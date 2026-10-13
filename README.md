# An independent verifier for draft-gilda-wimse-agent-audit-record-02

A second implementation of the agent audit record, written from the draft text.

Its purpose is narrow. A specification with one implementation and one conformance
corpus written beside it cannot tell you whether the text is sufficient, because
neither the reader nor the vectors can see what the author assumed. This reader was
written from `draft-gilda-wimse-agent-audit-record-02`, RFC 8785, RFC 7493 and DSSE,
and shares no code with the reference verifier, the reference canonicaliser or the
reference DSSE library.

## Result

Against `probityai/agent-evidence-vectors`, corpus `vectors-agent-audit-record`
at `corpusDigest` `811c1aff`, 68 members, `main` at `17213cfb`:

| | corpus | this reader |
|---|---|---|
| accept | 17 valid | 17 valid |
| reject | 49 malformed | 49 malformed |
| indeterminate | each lists its conforming readings | both reached `valid`, a listed reading for each |

68 of 68 agree. The digest is recomputed from the preimage `digest.py` states,
sha256 over every member's bytes in identifier order, rather than read from the
manifest's own `corpusDigest` field.

The run before it, against 55 members at `corpusDigest` `048ddde8`, corpus
`0.17.5`, agreed 55 of 55: 11 accept, 42 reject, 2 indeterminate. It stands as
written, because it names the digest it was measured against. The thirteen
members added since are A12 to A17, EV5 to EV10 and OV3, and every one of the
original 55 is byte-identical.

`FINDINGS.md` records the run before that: 47 of 47 at corpus `0.16.0` against
`-01`, including two vectors that caught this reader and one requirement the
draft does not define. It is kept as written rather than restated, because it
is a dated result.

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

`fetch_corpus.sh` takes a ref, so `./fetch_corpus.sh <sha>` pins a run to one
commit. The first two stages print to stdout; `stage34_recompute` writes
`corpus/stage34_results.json`. A member agrees when the corpus verdict matches
this reader: a reject refused at any of the three stages, an accept passing all
three. Counting from one stage alone understates.

## What it checks

**Envelope.** Envelope parse, `payloadType`, base64 payload, RFC 8785 canonicality,
Ed25519 over the DSSE pre-authentication encoding of the canonical bytes, the
RFC 7493 JSON profile (duplicate member names, nesting depth, safe-integer bound),
and in-toto statement shape.

**Members.** All seventeen predicate members present unless conditional, every value
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
