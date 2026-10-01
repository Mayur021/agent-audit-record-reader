#!/bin/bash
# Fetches the conformance corpus at run time. It is never committed here.
# Source: https://github.com/probityai/agent-evidence-vectors
set -e
REF="${1:-main}"
mkdir -p corpus/statements
BASE="https://raw.githubusercontent.com/probityai/agent-evidence-vectors/$REF/vectors-agent-audit-record"
curl -fsSL "$BASE/MANIFEST.json" -o corpus/MANIFEST.json
python3 - "$BASE" <<'PY'
import json,sys,urllib.request,os
base=sys.argv[1]
m=json.load(open('corpus/MANIFEST.json'))
for v in m['vectors']:
    out=os.path.join('corpus',v['file']); os.makedirs(os.path.dirname(out),exist_ok=True)
    urllib.request.urlretrieve(f"{base}/{v['file']}", out)
print(f"fetched {len(m['vectors'])} statements")
PY
