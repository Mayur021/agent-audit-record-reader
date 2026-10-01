#!/usr/bin/env python3
"""Stages 3 and 4: the four recomputes and tier derivation, from draft-01.

NOTE ON THE WRITE CHAIN. Section 4.4 and 5.3 require a verifier to replay the
ordered write chain from the before-state root and reproduce the after-state
root (vector E2), but no section of the draft defines the fold. The rule below
was inferred from the accept members: each write's preStateDigest must equal the
running root and its postStateDigest becomes the new running root. That is
recoverable from Appendix B but is not stated in the text.
"""
from __future__ import annotations
import base64, hashlib, json, sys
from pathlib import Path
from aimsreader.envelope_reader import jcs, read as envelope_read

AGREEMENT = {
    ("permit", "occurred"): "agree",
    ("permit-with-conditions", "occurred"): "agree",
    ("deny", "none"): "agree",
    ("deny", "occurred"): "disagree",
    ("permit", "none"): "not-exercised",
    ("permit-with-conditions", "none"): "not-exercised",
}
def derive_agreement(reported, observed):
    if observed == "unknown":
        return "indeterminate"
    return AGREEMENT.get((reported, observed))

def dig(alg, b: bytes) -> str:
    return hashlib.new(alg, b).hexdigest()

def in_scope(path: str, scope: list) -> bool:
    for s in scope or []:
        if s == "/" or path == s or path.startswith(s if s.endswith("/") else s + "/"):
            return True
    return False

def recompute(pred: dict, subject: list, empty_tree: dict):
    f = []
    alg = pred.get("hashAlgorithm", "sha256")
    res = pred.get("resource", {}) or {}
    dec = pred.get("decision", {}) or {}
    eff = pred.get("effect", {}) or {}
    iv = eff.get("interval") or {}

    # --- recompute 1: request digest (F4, A6) -----------------------------
    obj = {"action": dec.get("action"), "resourceId": res.get("id"),
           "resourceKind": res.get("kind")}
    if res.get("binding") == "digest-bound":
        obj["argumentsDigest"] = res.get("argumentsDigest")
    want = dig(alg, jcs(obj).encode())
    if dec.get("requestDigest") != want:
        f.append("request-digest-mismatch")
    # subject convention (S1, S2, I1r); bind on digest, never on name (4.2)
    if not isinstance(subject, list) or not subject:
        f.append("subject-absent")
    else:
        d0 = (subject[0].get("digest") or {}).get(alg)
        if d0 != dec.get("requestDigest"):
            f.append("subject-request-digest-mismatch")
        has_iv = bool(iv)
        if has_iv and len(subject) < 2:
            f.append("subject-after-entry-absent-with-interval")
        if not has_iv and len(subject) > 1:
            f.append("subject-after-entry-present-without-interval")
        if has_iv and len(subject) > 1:
            d1 = (subject[1].get("digest") or {}).get(alg)
            if d1 != iv.get("afterRoot"):
                f.append("subject-after-root-mismatch")

    # --- recompute 2: ordered write chain (E2) ----------------------------
    writes = eff.get("writes") or []
    root = iv.get("beforeRoot")
    for i, w in enumerate(writes):
        if w.get("preStateDigest") != root:
            f.append(f"write-chain-broken-at-{i}")
            root = None
            break
        root = w.get("postStateDigest")
    if root is not None and iv and root != iv.get("afterRoot"):
        f.append("write-chain-does-not-reach-after-root")

    # --- effect.observed derivable (T1, A7, A8, E1) ------------------------
    rd = dec.get("requestDigest")
    scope = eff.get("pathScope") or []
    attributed = [w for w in writes if w.get("requestDigest") == rd]
    unattributed_in_scope = [w for w in writes
                             if w.get("requestDigest") == "unattributed"
                             and in_scope(w.get("path", ""), scope)]
    if attributed:
        want_obs = "occurred"
    elif not unattributed_in_scope:
        want_obs = "none"
    else:
        want_obs = "unknown"
    if eff.get("observed") != want_obs:
        f.append(f"effect-observed-underivable:declared={eff.get('observed')!r},derived={want_obs!r}")
    if eff.get("observed") == "none" and not writes and iv:
        if iv.get("beforeRoot") != iv.get("afterRoot"):
            f.append("none-with-empty-writes-requires-equal-roots")

    # --- baseResolution empty-tree (E3) ------------------------------------
    if iv.get("baseResolution") == "empty-tree":
        const = empty_tree.get(alg)
        if const and iv.get("beforeRoot") != const:
            f.append("empty-tree-constant-mismatch")

    # --- write inScope derived, never asserted (V3) ------------------------
    for i, w in enumerate(writes):
        want_in = in_scope(w.get("path", ""), scope)
        if bool(w.get("inScope")) != want_in:
            f.append(f"write-scope-mismatch-at-{i}")

    # --- recompute 3: agreement (D1, D2, D3) -------------------------------
    want_agr = derive_agreement(dec.get("reported"), eff.get("observed"))
    if pred.get("agreement") == "one-sided":
        f.append("agreement-reserved-value")
    elif want_agr is not None and pred.get("agreement") != want_agr:
        f.append(f"agreement-underivable:declared={pred.get('agreement')!r},derived={want_agr!r}")

    # --- posture agreement (F6) --------------------------------------------
    po = pred.get("posture") or {}
    pr, pob = po.get("reported"), po.get("observed")
    if pr is not None and pob is not None:
        want_p = "agree" if pr == pob else "disagree"
        if po.get("agreement") != want_p:
            f.append(f"posture-agreement-underivable:declared={po.get('agreement')!r},derived={want_p!r}")

    # --- recompute 4: prior commitment (C1, C2, C3) ------------------------
    obs = pred.get("observation") or {}
    pc = obs.get("priorCommitment")
    if isinstance(pc, dict) and pc:
        cobj = {"authorityDigest": (pred.get("delegation") or {}).get("authorityDigest"),
                "beforeRoot": iv.get("beforeRoot"),
                "recordId": pred.get("recordId"),
                "witnessNonce": pc.get("witnessNonce")}
        cwant = dig(alg, jcs(cobj).encode())
        if pc.get("commitmentDigest") != cwant:
            f.append("commitment-digest-mismatch")
        ca, oa = pc.get("committedAt"), iv.get("openedAt")
        if isinstance(ca, str) and isinstance(oa, str) and not (ca < oa):
            f.append("commitment-not-strictly-before-interval")
        signers = (pred.get("agent") or {}).get("signers") or []
        if pc.get("keyid") in signers:
            f.append("commitment-key-is-agent-signer")
    return f

def derive_tier(pred: dict):
    obs = pred.get("observation") or {}
    eff = pred.get("effect") or {}
    res = pred.get("resource") or {}
    pc = obs.get("priorCommitment") or {}
    cov = obs.get("coverage") or {}
    scope = eff.get("pathScope") or []
    clauses = {
        "vantage-below-observed": obs.get("vantage") == "below-observed",
        "prior-commitment-complete": bool(pc) and all(
            pc.get(k) for k in ("commitmentDigest", "committedAt", "keyid", "witnessNonce")),
        "path-scope-non-empty": bool(scope),
        "coverage-complete-or-gaps-outside-scope": bool(cov.get("scopeComplete")) or all(
            not in_scope(g, scope) for g in (cov.get("gaps") or [])),
        "binding-digest-bound": res.get("binding") == "digest-bound",
    }
    return ("authoritative" if all(clauses.values()) else "voluntary"), clauses

def main():
    base = Path(sys.argv[1])
    man = json.loads((base / "MANIFEST.json").read_text())
    obs_key = man["keys"]["observer"]["publicKey"]
    empty_tree = man.get("emptyTree", {})
    out = []
    for v in man["vectors"]:
        e = envelope_read(base / v["file"], obs_key, man["payloadType"], man["predicateType"])
        row = {"draftId": v["draftId"], "kind": v["kind"], "row": v["row"],
               "stage1": e["verdict"]}
        if e["verdict"] != "open":
            row.update(stage34="not-reached", findings=[], tier=None)
        else:
            env = json.loads((base / v["file"]).read_text())
            stmt = json.loads(base64.b64decode(env["payload"]))
            pred = stmt["predicate"]
            fs = recompute(pred, stmt.get("subject"), empty_tree)
            tier, clauses = derive_tier(pred)
            declared = pred.get("tier")
            if declared == "authoritative" and tier == "voluntary":
                failed = [k for k, ok in clauses.items() if not ok]
                fs.append("tier-overclaim:" + ",".join(failed))
            row.update(stage34="refuse" if fs else "pass", findings=fs,
                       tier=tier, declaredTier=declared)
        out.append(row)
    (base / "stage34_results.json").write_text(json.dumps(out, indent=1))

if __name__ == "__main__":
    main()
