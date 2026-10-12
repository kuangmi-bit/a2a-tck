# a5-replay

Per-case replay of the `a5-number-serialization` family of RFC 8785 conformance
vectors, kept so that someone else can reproduce the count without reading the
generator.

**Input.** `vectors/` is a verbatim copy of
`conformance-vectors/a2a-jcs-v01/a5-number-serialization/` as published in
`a2aproject/a2a-tck` pull/228, head `324c53250`. Nothing in the vectors is edited.

**Reader.** `check.js` is written from the spec alone: recursive key sort, and
number serialization delegated to this runtime's own `Number::toString`, which
is the ES6 spelling RFC 8785 §3.2.2.3 mandates. No third-party dependency, no
import of the generator and no import of any SDK.

**Run.**

    node check.js a5-per-case.txt     # writes the per-case output file
    sha256sum a5-per-case.txt

**What the columns mean.**

| column | meaning |
| --- | --- |
| `AGREE` / `MISMATCH` | the canonical bytes the reader produced vs `expected.canonical_utf8_hex` |
| `source_spelling` | the number tokens as they appear in the vector file |
| `canonical_spelling` | the number tokens the same values canonicalize to |
| `SPELLING-CHANGED` | this vector can tell a token-passthrough implementation from a value-based one |
| `spelling-stable` | both readings produce the same bytes: this vector carries no discrimination on that axis |
| `SKIP` | the vector has no `canonical_utf8_hex`, so there is nothing to compare against (refusal-shaped cases) |

**Limits.** This checks the canonicalization side only: it says nothing about
the refusal vectors (`A5-REJECT-*`), and it does not exercise the digest,
signature or card layers. A `SKIP` is not a pass.
