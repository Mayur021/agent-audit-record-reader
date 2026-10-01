#!/usr/bin/env python3
"""Independent envelope-layer reader for draft-gilda-wimse-agent-audit-record-01.

Written from the draft text and from RFC 8785 / DSSE / in-toto, NOT from the
reference reader in probityai/agent-evidence-vectors. The point of a second
implementation is that it shares nothing with the first.

This stage answers one question only: can each of the 47 statements be opened,
its signature verified against the published observer key, and its payload
confirmed as RFC 8785 canonical in-toto form. Predicate validation, the three
recomputes, the prior-commitment recompute and tier derivation are later stages.

Verdicts at this layer:
  open      envelope parsed, signature valid, payload canonical in-toto
  refuse:<code>  stopped, with our own code name
Our refusal codes are our names, not the corpus's. The draft does not define
code names, so codes are not expected to match; only verdicts are comparable.
"""
from __future__ import annotations
import base64, json, math, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------- RFC 8785 ---
def _jcs_number(n) -> str:
    if isinstance(n, bool):
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        if abs(n) > 2**53 - 1:
            raise ValueError("integer outside RFC 7493 safe range")
        return str(n)
    if not math.isfinite(n):
        raise ValueError("non-finite number")
    if n == int(n) and abs(n) < 2**53:
        return str(int(n))
    r = repr(float(n))
    return r

def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif ch == '\b': out.append('\\b')
        elif ch == '\f': out.append('\\f')
        elif ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ch == '\t': out.append('\\t')
        elif o < 0x20: out.append('\\u%04x' % o)
        else: out.append(ch)
    out.append('"')
    return ''.join(out)

def jcs(value) -> str:
    """Serialise per RFC 8785: sorted object keys by UTF-16 code units,
    no insignificant whitespace, minimal string escaping."""
    if value is None: return 'null'
    if value is True: return 'true'
    if value is False: return 'false'
    if isinstance(value, str): return _jcs_string(value)
    if isinstance(value, (int, float)): return _jcs_number(value)
    if isinstance(value, list):
        return '[' + ','.join(jcs(v) for v in value) + ']'
    if isinstance(value, dict):
        def sortkey(k: str):
            return k.encode('utf-16-be')
        items = sorted(value.items(), key=lambda kv: sortkey(kv[0]))
        return '{' + ','.join(_jcs_string(k) + ':' + jcs(v) for k, v in items) + '}'
    raise TypeError(f"unserialisable {type(value)!r}")

# ------------------------------------------------- RFC 7493 / profile checks ---
def json_profile_findings(raw: bytes):
    """Checks the draft requires of the JSON itself, independent of schema."""
    findings = []
    dupes = []
    def object_pairs(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen: dupes.append(k)
            seen.add(k)
        return dict(pairs)
    try:
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=object_pairs)
    except UnicodeDecodeError:
        return None, ['payload-not-utf8']
    except json.JSONDecodeError as e:
        return None, [f'payload-not-json:{e.msg}']
    if dupes:
        findings.append('duplicate-member:' + ','.join(sorted(set(dupes))))
    # depth
    def depth(v, d=1):
        if isinstance(v, dict):
            return max([depth(x, d + 1) for x in v.values()] or [d])
        if isinstance(v, list):
            return max([depth(x, d + 1) for x in v] or [d])
        return d
    if depth(doc) > 128:
        findings.append('nesting-over-128')
    # safe integers
    def ints(v):
        if isinstance(v, bool): return
        if isinstance(v, int):
            if abs(v) > 2**53 - 1: findings.append('unsafe-integer')
            return
        if isinstance(v, float):
            if not math.isfinite(v): findings.append('non-finite-number')
            return
        if isinstance(v, dict):
            for x in v.values(): ints(x)
        if isinstance(v, list):
            for x in v: ints(x)
    ints(doc)
    return doc, findings

# ------------------------------------------------------------------- DSSE ---
def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode('utf-8')
    return b'DSSEv1 ' + str(len(t)).encode() + b' ' + t + b' ' + \
           str(len(payload)).encode() + b' ' + payload

def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

# ------------------------------------------------------------------ reader ---
IN_TOTO_TYPE = 'https://in-toto.io/Statement/v1'

def read(stmt_path: Path, observer_pub_hex: str, expect_payload_type: str,
         expect_predicate_type: str):
    out = {'file': stmt_path.name}
    try:
        env = json.loads(stmt_path.read_text(encoding='utf-8'))
    except Exception as e:
        return {**out, 'verdict': 'refuse', 'code': 'envelope-not-json', 'detail': str(e)}
    for k in ('payload', 'payloadType', 'signatures'):
        if k not in env:
            return {**out, 'verdict': 'refuse', 'code': f'envelope-missing-{k}'}
    if env['payloadType'] != expect_payload_type:
        return {**out, 'verdict': 'refuse', 'code': 'payload-type-mismatch',
                'detail': env['payloadType']}
    try:
        payload = b64d(env['payload'])
    except Exception as e:
        return {**out, 'verdict': 'refuse', 'code': 'payload-not-base64', 'detail': str(e)}

    sigs = env['signatures']
    if not isinstance(sigs, list) or not sigs:
        return {**out, 'verdict': 'refuse', 'code': 'no-signatures'}
    # 4.1.2 forbids retaining any one occurrence of a repeated member name, and
    # canonicalising requires parsing, which would retain one. So the duplicate
    # check must precede canonicalisation and therefore the signature, even though
    # 4.6 describes the signature first. 4.6 closes by requiring no particular order.
    doc0, prof0 = json_profile_findings(payload)
    if doc0 is None:
        return {**out, 'verdict': 'refuse', 'code': prof0[0]}
    if any(f.startswith('duplicate-member') for f in prof0):
        return {**out, 'verdict': 'refuse', 'code': 'json-profile',
                'detail': ';'.join(f for f in prof0 if f.startswith('duplicate-member'))}

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(observer_pub_hex))
    # draft 4.1.1 and 4.6: the signature covers the RFC 8785 canonical bytes of
    # the Statement "and no other serialization". A verifier derives the canonical
    # bytes itself (6.7) rather than trusting the transmitted serialisation, so a
    # declaration-ordered payload fails signature here, not at a later check.
    try:
        _doc_for_canon = json.loads(payload.decode('utf-8'))
        signed_bytes = jcs(_doc_for_canon).encode('utf-8')
    except Exception:
        signed_bytes = payload
    preimage = pae(env['payloadType'], signed_bytes)
    verified = False
    sig_detail = []
    for s in sigs:
        if 'sig' not in s:
            sig_detail.append('signature-entry-missing-sig'); continue
        try:
            pub.verify(b64d(s['sig']), preimage)
            verified = True
        except InvalidSignature:
            sig_detail.append('invalid-signature:' + str(s.get('keyid'))[:16])
        except Exception as e:
            sig_detail.append('signature-undecodable:' + str(e)[:40])
    if not verified:
        return {**out, 'verdict': 'refuse', 'code': 'signature-not-verified',
                'detail': ';'.join(sig_detail)}

    doc, prof = json_profile_findings(payload)
    if doc is None:
        return {**out, 'verdict': 'refuse', 'code': prof[0]}
    if prof:
        return {**out, 'verdict': 'refuse', 'code': 'json-profile', 'detail': ';'.join(prof)}

    canon = jcs(doc).encode('utf-8')
    canonical = (canon == payload)

    if doc.get('_type') != IN_TOTO_TYPE:
        return {**out, 'verdict': 'refuse', 'code': 'statement-type',
                'detail': str(doc.get('_type'))[:60], 'canonical': canonical}
    if doc.get('predicateType') != expect_predicate_type:
        return {**out, 'verdict': 'refuse', 'code': 'predicate-type',
                'detail': str(doc.get('predicateType'))[:80], 'canonical': canonical}
    for k in ('subject', 'predicate'):
        if k not in doc:
            return {**out, 'verdict': 'refuse', 'code': f'statement-missing-{k}',
                    'canonical': canonical}
    return {**out, 'verdict': 'open', 'code': '', 'canonical': canonical,
            'predicate_members': sorted(doc['predicate'].keys())
            if isinstance(doc.get('predicate'), dict) else None}

def main():
    base = Path(sys.argv[1])
    man = json.loads((base / 'MANIFEST.json').read_text())
    obs = man['keys']['observer']['publicKey']
    results = []
    for v in man['vectors']:
        r = read(base / v['file'], obs, man['payloadType'], man['predicateType'])
        r['draftId'] = v['draftId']; r['kind'] = v['kind']; r['row'] = v['row']
        results.append(r)
    (base / 'envelope_results.json').write_text(json.dumps(results, indent=1))
    print(json.dumps(results, indent=1))

if __name__ == '__main__':
    main()
