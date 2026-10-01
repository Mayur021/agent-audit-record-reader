# An independent verifier for draft-gilda-wimse-agent-audit-record-01

A second implementation of the agent audit record, written from the draft text.

Its purpose is narrow. A specification with one implementation and one conformance
corpus written beside it cannot tell you whether the text is sufficient, because
neither the reader nor the vectors can see what the author assumed. This reader was
written from `draft-gilda-wimse-agent-audit-record-01`, RFC 8785, RFC 7493 and DSSE,
and shares no code with the reference verifier, the reference canonicaliser or the
reference DSSE library.

## Result

Against `probityai/agent-evidence-vectors`, corpus `vectors-agent-audit-record`,
47 members:

| | corpus | this reader |
|---|---|---|
| accept | 9 valid | 9 valid |
| reject | 36 malformed | 36 malformed |
| indeterminate | each lists its conforming readings | both reached `valid`, a listed reading for each |

47 of 47 agree. See `FINDINGS.md` for what the exercise surfaced, including two
vectors that caught this reader and one requirement the draft does not define.

## Running it

```
./fetch_corpus.sh            # fetches the corpus; it is never committed here
python3 -m aimsreader.envelope_reader corpus
python3 -m aimsreader.stage2_members corpus
python3 -m aimsreader.stage34_recompute corpus
```

The corpus is fetched at run time and is listed in `.gitignore`. It belongs to
`probityai/agent-evidence-vectors`, and the independence of this reader depends on
not shipping it.

## What it checks

**Envelope.** Envelope parse, `payloadType`, base64 payload, RFC 8785 canonicality,
Ed25519 over the DSSE pre-authentication encoding of the canonical bytes, the
RFC 7493 JSON profile (duplicate member names, nesting depth, safe-integer bound),
and in-toto statement shape.

**Members.** All sixteen predicate members present unless conditional, every value
inside the closed vocabulary its member declares, and the conditional rules of
sections 5.2 to 5.5.

**Recomputes.** The request digest from the four members section 5.3 names, the
ordered write chain from the before-state root, both agreement values, and the prior
commitment digest with its ordering and key-disjointness checks.

**Tier.** The five clauses of section 5.5, recomputed rather than read, with an
over-claim treated as malformed and never downgraded.

## What it is not

It is not a reference implementation and it does not define anything. Where it and
the reference verifier disagree, the draft decides, not this code. Two of the three
findings in `FINDINGS.md` are places where this reader was wrong.

## Licence

Apache-2.0.
