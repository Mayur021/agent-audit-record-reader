#!/usr/bin/env python3
"""Stage 2: membership and closed vocabularies, from draft-02 sections 5.1-5.7.

Runs only on statements stage 1 opened. Recomputes (stage 3) and tier derivation
(stage 4) are not here. Written from the draft text, not the reference reader.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
from aimsreader.envelope_reader import read as envelope_read

# Section 4: "Seventeen required predicate members and one optional member are
# defined in Section 5." The optional member is oversight (5.5). No member has a
# default and a verifier MUST NOT supply one for an absent member (F1, EV3).
MEMBERS = ["recordId","tier","hashAlgorithm","agent","delegation","resource",
           "decision","effect","evaluation","agreement","correlation","posture",
           "remediation","observation","fieldEvidence","doesNotAssert","issuedAt"]

VOCAB = {
 ("agent","authentication"): {"wimse-wpt","http-message-signature","mtls","oauth-access-token","none"},
 ("delegation","subjectKind"): {"user","system","none"},
 ("resource","kind"): {"path","uri","tool"},
 ("resource","binding"): {"digest-bound","not-bindable"},
 ("decision","reported"): {"permit","deny","permit-with-conditions"},
 ("effect","observed"): {"occurred","none","unknown"},
 ("correlation","scope"): {"producer","cross-party"},
 ("correlation","timeBasis"): {"beacon-anchored","asserted"},
 ("posture","reported"): {"no_network","allowlist","sinkhole","unsafe_bypass_egress"},
 ("posture","observed"): {"no_network","allowlist","sinkhole","unsafe_bypass_egress"},
 ("observation","vantage"): {"below-observed","peer","self"},
 ("evaluation","status"): {"evaluated","not-evaluated"},
}
TOP_VOCAB = {
 "agreement": {"agree","disagree","not-exercised","indeterminate","one-sided"},
 "tier": {"voluntary","authoritative"},
}
ANCHOR_KINDS = {"rfc3161","transparency-log","opentimestamps"}
REM_CAUSE = {"session-revoked","risk-elevated","subject-disabled",
             "token-replay-suspected","policy-changed","operator-action"}
REM_ENF = {"access-attenuated","session-terminated","tokens-discarded",
           "privileges-reduced","reevaluated","not-enforced"}
FE_VALUES = {"substrate-covered","producer-asserted"}
# 5.4: "from the closed set standing-source, key-source, consumption-state"
UNAVAILABLE_INPUT = {"standing-source","key-source","consumption-state"}
# 5.5: "one of observation, check, decision, release"
OVERSIGHT_ACTS = {"observation","check","decision","release"}
# 5.5: "No other member is defined, and a verifier MUST reject an oversight
# member carrying one."
OVERSIGHT_DEFINED = {"act","recordDigest"}
GLOB = set("*?[]{}")

def check(pred: dict):
    f = []
    for m in MEMBERS:
        if m not in pred:
            f.append(f"member-absent:{m}")
    if f:
        return f
    for (parent, child), allowed in VOCAB.items():
        node = pred.get(parent)
        if isinstance(node, dict):
            v = node.get(child)
            if v is None:
                f.append(f"member-absent:{parent}.{child}")
            elif v not in allowed:
                f.append(f"vocabulary:{parent}.{child}={v!r}")
    for k, allowed in TOP_VOCAB.items():
        if pred.get(k) not in allowed:
            f.append(f"vocabulary:{k}={pred.get(k)!r}")

    # 5.2 delegation: subjectKind none <-> subject literal "none"  (F2)
    d = pred.get("delegation", {})
    if isinstance(d, dict):
        sk, sub = d.get("subjectKind"), d.get("subject")
        if sk == "none" and sub != "none":
            f.append(f"delegation-none-mismatch:subject={sub!r}")
        if sk != "none" and sub == "none":
            f.append("delegation-subject-none-with-kind")
        if "authorityDigest" not in d:
            f.append("member-absent:delegation.authorityDigest")

    # 5.2 resource binding  (F3, F3b, F3c)
    r = pred.get("resource", {})
    if isinstance(r, dict):
        b = r.get("binding")
        has_ad = "argumentsDigest" in r
        ad = r.get("argumentsDigest")
        if b == "digest-bound" and (not has_ad or ad in (None, "")):
            f.append("digest-bound-without-argumentsDigest")
        if b == "not-bindable" and has_ad:
            f.append(f"not-bindable-carries-argumentsDigest:{ad!r}")

    # 5.4 correlation anchor  (F5)
    c = pred.get("correlation", {})
    if isinstance(c, dict):
        tb = c.get("timeBasis"); has_anchor = "externalAnchor" in c
        if tb == "beacon-anchored" and not has_anchor:
            f.append("beacon-anchored-without-externalAnchor")
        if tb == "asserted" and has_anchor:
            f.append("asserted-carries-externalAnchor")
        if has_anchor and isinstance(c["externalAnchor"], dict):
            k = c["externalAnchor"].get("kind")
            if k not in ANCHOR_KINDS:
                f.append(f"vocabulary:externalAnchor.kind={k!r}")

    # 5.4 remediation  (F7, A4)
    rem = pred.get("remediation")
    if isinstance(rem, list):
        for i, ev in enumerate(rem):
            if not isinstance(ev, dict): continue
            if ev.get("cause") not in REM_CAUSE:
                f.append(f"vocabulary:remediation[{i}].cause={ev.get('cause')!r}")
            if ev.get("enforcement") not in REM_ENF:
                f.append(f"vocabulary:remediation[{i}].enforcement={ev.get('enforcement')!r}")
            a, b2 = ev.get("signalReceivedAt"), ev.get("enforcedAt")
            if isinstance(a, str) and isinstance(b2, str) and b2 < a:
                f.append(f"remediation[{i}]-enforcedAt-before-signalReceivedAt")

    # 5.3 pathScope  (V2)
    eff = pred.get("effect", {})
    if isinstance(eff, dict):
        ps = eff.get("pathScope")
        if ps is None:
            f.append("member-absent:effect.pathScope")
        elif isinstance(ps, list):
            for p in ps:
                if isinstance(p, str) and (set(p) & GLOB):
                    f.append(f"pathScope-glob:{p!r}")
        iv = eff.get("interval")
        if isinstance(iv, dict):
            br = iv.get("baseResolution")
            if br not in {"supplied","empty-tree"}:
                f.append(f"vocabulary:effect.interval.baseResolution={br!r}")

    # 5.5 fieldEvidence  (FE1, FE2)
    fe = pred.get("fieldEvidence")
    if isinstance(fe, dict):
        if len(fe) != 7:
            f.append(f"fieldEvidence-key-count:{len(fe)}")
        for k, v in fe.items():
            if v not in FE_VALUES:
                f.append(f"vocabulary:fieldEvidence.{k}={v!r}")
        obs = pred.get("observation", {})
        if isinstance(obs, dict) and obs.get("vantage") == "self":
            if any(v == "substrate-covered" for v in fe.values()):
                f.append("substrate-covered-while-vantage-self")

    # 5.4 evaluation. Under not-evaluated the member MUST carry
    # unavailableInput, "a non-empty array naming each input the decision point
    # could not obtain, each at most once", from the closed set. Under
    # evaluated it MUST NOT carry unavailableInput "in any spelling".
    # Status not-evaluated is never itself a reason to reject.
    ev = pred.get("evaluation")
    if isinstance(ev, dict):
        st = ev.get("status")
        spellings = [k for k in ev if k.lower() == "unavailableinput"]
        if st == "not-evaluated":
            if "unavailableInput" not in ev:
                f.append("not-evaluated-without-unavailableInput")
            else:
                ui = ev["unavailableInput"]
                if not isinstance(ui, list):
                    f.append(f"unavailableInput-not-an-array:{type(ui).__name__}")
                elif not ui:
                    f.append("unavailableInput-empty")
                else:
                    seen = set()
                    for i, x in enumerate(ui):
                        if x in seen:
                            f.append(f"unavailableInput-repeated:{x!r}")
                        seen.add(x)
                        if x not in UNAVAILABLE_INPUT:
                            f.append(f"vocabulary:evaluation.unavailableInput[{i}]={x!r}")
        elif st == "evaluated":
            for k in spellings:
                f.append(f"evaluated-carries-unavailableInput:{k!r}")

    # 5.5 oversight, the one optional member. act is required inside it and
    # closed; recordDigest is optional and a verifier does not resolve it; no
    # other member is defined.
    ov = pred.get("oversight")
    if ov is not None:
        if not isinstance(ov, dict):
            f.append(f"oversight-not-an-object:{type(ov).__name__}")
        else:
            if "act" not in ov:
                f.append("member-absent:oversight.act")
            elif ov["act"] not in OVERSIGHT_ACTS:
                f.append(f"vocabulary:oversight.act={ov['act']!r}")
            for k in ov:
                if k not in OVERSIGHT_DEFINED:
                    f.append(f"oversight-undefined-member:{k!r}")

    # 5.1 issuedAt at or after interval sealedAt
    ia = pred.get("issuedAt")
    sa = (eff.get("interval") or {}).get("sealedAt") if isinstance(eff, dict) else None
    if isinstance(ia, str) and isinstance(sa, str) and ia < sa:
        f.append("issuedAt-before-sealedAt")
    return f

def main():
    base = Path(sys.argv[1])
    man = json.loads((base / 'MANIFEST.json').read_text())
    obs = man['keys']['observer']['publicKey']
    out = []
    for v in man['vectors']:
        e = envelope_read(base / v['file'], obs, man['payloadType'], man['predicateType'])
        row = {'draftId': v['draftId'], 'kind': v['kind'], 'row': v['row'],
               'stage1': e['verdict'], 'stage1_code': e.get('code','')}
        if e['verdict'] != 'open':
            row['stage2'] = 'not-reached'; row['findings'] = []
        else:
            doc = json.loads((base / v['file']).read_text())
            import base64
            pred = json.loads(base64.b64decode(doc['payload']))['predicate']
            fs = check(pred)
            row['stage2'] = 'refuse' if fs else 'pass'
            row['findings'] = fs
        out.append(row)
    (base / 'stage2_results.json').write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))

if __name__ == '__main__':
    main()
