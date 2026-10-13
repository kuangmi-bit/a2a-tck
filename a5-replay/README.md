# a5-replay

Per-case replay of the `a5-number-serialization` family of RFC 8785 conformance
vectors, kept so that someone else can reproduce the count without reading the
generator. Two sides: canonicalization (`check.js`) and refusal (`refusals.js`).

**Input.** `vectors/` is a verbatim copy of
`conformance-vectors/a2a-jcs-v01/a5-number-serialization/` as published in
`a2aproject/a2a-tck` pull/228, head `324c53250`. Nothing in the vectors is edited.

**Reader.** `check.js` is written from the spec alone: recursive key sort, and
number serialization delegated to this runtime's own `Number::toString`, which
is the ES6 spelling RFC 8785 §3.2.2.3 mandates. No third-party dependency, no
import of the generator and no import of any SDK. `refusals.js` adds a strict
RFC 8259 scan of `input_raw` and the §3.2.2.3 finite guard, same constraint.

**Run.**

    node check.js a5-per-case.txt              # canonicalization side
    node refusals.js a5-refusals-per-case.txt  # refusal side
    sha256sum a5-per-case.txt a5-refusals-per-case.txt

**What the columns mean.**

| column | meaning |
| --- | --- |
| `AGREE` / `MISMATCH` | the canonical bytes the reader produced vs `expected.canonical_utf8_hex` |
| `source_spelling` | the number tokens as they appear in the vector file |
| `canonical_spelling` | the number tokens the same values canonicalize to |
| `SPELLING-CHANGED` | this vector can tell a token-passthrough implementation from a value-based one |
| `spelling-stable` | both readings produce the same bytes: this vector carries no discrimination on that axis |
| `SKIP` | the vector has no `canonical_utf8_hex`, so there is nothing to compare against (refusal-shaped cases) |

**Refusal side.** `refusals.js` covers the three `MUST-REJECT` vectors of this
family — the ones `check.js` reports as `SKIP`, because they carry no expected
bytes. Outcomes use the corpus README's vocabulary: `pass` (refused for the
stated cause), `accepted` (returned bytes for input that has no canonical form),
`errored` (something other than the declared refusal).

The reader's declared refusal carries a named cause and the offending token
(`non_json_number_token`, `non_finite_number`). A case counts as `pass` only
when that cause is the one the vector states: each output line repeats the
vector's own `rejecting_clause` and the first sentence of its own `rationale`,
so the match can be read off the line rather than taken on trust.

Three controls run beside the cases, so the verdict is not vacuous: the same
reader accepts `{"n": 1.0}`, `{"n": "NaN"}` (a string is not a number token) and
`{"n": 1e21}`. A final pair of lines shows the layer the vector exists to
protect: a non-finite *value* handed over by a lenient parser. This reader
refuses it (`non_finite_number`); the platform serializer turns it into
`{"n":null}`, silently. Python's stdlib is such a lenient parser —
`json.loads('{"n": NaN}')` is accepted by default and `json.dumps` writes `NaN`
back out — which is why the defect needs a named refusal rather than a generic
parse error.

**Limits.** This is the number-serialization family, and inside it the
canonicalization and refusal sides only. It says nothing about the A2
signatures-exclusion vectors (RFC 8785 has no notion of a `signatures` field, so
an RFC 8785 primitive fails them by design) and nothing about the digest,
signature or card layers. A `SKIP` in the canonicalization file is not a pass;
the refusal cases are adjudicated in the refusal file.
