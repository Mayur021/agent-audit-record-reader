# Independent second reader, draft-gilda-wimse-agent-audit-record-01

Run date 2026-10-01. Corpus `vectors-agent-audit-record` at v0.16.0 state on `main`,
47 members. Reader written from the draft text, RFC 8785, RFC 7493 and DSSE. It
shares no code with the reference reader and does not vendor the corpus.

## Result

47 of 47 agree with the corpus.

| | corpus | ours |
|---|---|---|
| accept members | 9 valid | 9 valid |
| reject members | 36 malformed | 36 malformed |
| indeterminate members | readings listed | both reached `valid`, a listed reading for each |

N1 and N2 both reached `valid`. Each lists `valid` and `indeterminate` as conforming
readings, so the run conforms on both.

## Why the v0.16.0 fix is what makes this run reportable

Under v0.14.1 both N1 and N2 carried a pinned `expected.verdict` of `indeterminate`,
and the MANIFEST note said a conforming verifier is scored on `expected.verdict`.
This reader takes the `valid` reading on both. Scored against the old corpus it
would have been recorded as two mismatches out of forty-seven, on the two rows whose
nature is that two answers are both correct. The first independent run is the case
the old scoring could not carry.

## Findings

### 1. The write-chain recompute has no defined algorithm in the draft

Section 4.4 lists the ordered write chain as one of the three recomputes, and 5.3
says "The ordered write chain MUST reproduce the after-state root from the
before-state root (vector E2)". Section 4.6 says a verifier "replays the write chain
from the before-state root and compares the result with the second subject entry".

No section defines the replay. Appendix A is design rationale and does not supply it.
The members available are each write's `path`, `preStateDigest`, `postStateDigest`,
`requestDigest` and `inScope`, and the interval's `beforeRoot` and `afterRoot`.

The rule was recovered from the accept members: each write's `preStateDigest` must
equal the running root, and its `postStateDigest` becomes the new running root,
starting from `beforeRoot` and ending at `afterRoot`. A1 and A7 each carry one write
whose pre-state is the before-root and whose post-state is the after-root; A2 and A9
carry none and have equal roots.

That is recoverable, and this reader recovered it. But it is recoverable from
Appendix B rather than from the body, which makes the corpus load-bearing as
specification. An implementer working from the normative text alone cannot perform
a recompute the text requires.

Suggested: state the chain rule in 5.3 beside the sentence that requires it.

### 2. The order described in 4.6 cannot be implemented as written

Section 4.6 puts the signature first and the JSON profile second. Section 4.1.2
requires that a verifier reject a Statement with a repeated member name and
"MUST NOT retain any one occurrence".

Verifying the signature requires the RFC 8785 canonical bytes, and deriving those
requires parsing, and parsing a document with a repeated member name retains one
occurrence. So the duplicate check has to run before canonicalisation and therefore
before the signature. The reference reader reports `duplicate-member` on T3 rather
than `signature-invalid`, so it does the same.

4.6 closes by saying the document requires no particular order, so this is not a
contradiction. It is a described order that cannot be followed literally, and the
closing sentence is doing more work than it looks.

### 3. Two vectors caught this reader, which is what they are for

T2 caught a first pass that verified the signature over the payload as transmitted,
which is what standard DSSE does and what any off-the-shelf DSSE verifier will do.
4.1.1 is explicit that the signature covers the canonical bytes "and no other
serialization", and 6.7 explains why a consumer derives them itself. The vector found
the mistake immediately.

T3 caught the ordering described in finding 2.

Both are reported because a second implementation is only useful if it reports where
it was wrong as well as where it differed.

## Stage breakdown

| stage | what it checks | refused here |
|---|---|---|
| 1 envelope | parse, payloadType, canonical bytes, Ed25519 over DSSE PAE, JSON profile, statement shape | T2, T3, T4, T5 |
| 2 members | sixteen members present, closed vocabularies, conditional rules | F1, F2, F3, F3b, F3c, F5, F7, TI1, V1, V2, FE1, FE2 |
| 3 recomputes | request digest, write chain, both agreement values, prior commitment | F4, F6, T1, D1, D2, D3, S1, S2, I1r, C1, C2, C3, E1, E2, E3, V3 |
| 4 tier | five clauses of 5.5, no downgrade of an over-claim | TI2, TI3, TI4, TI5 |
