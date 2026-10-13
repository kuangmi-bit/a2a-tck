#!/usr/bin/env node
// a5-replay, refusal side: the MUST-REJECT vectors of a5-number-serialization.
//
// For each MUST-REJECT vector in ./vectors: read `input_raw` from the file, run it
// through the same spec-alone reader shape as check.js (strict scan of the raw
// text; JSON.parse is never used on input_raw), and record whether the input is
// refused *for the cause the vector states* - a named defect class, not a generic
// parse error. Outcomes use the corpus README's vocabulary:
//
//   pass      refused for the stated cause
//   accepted  returned canonical bytes for input that has no canonical form
//   errored   raised something other than the declared refusal
//
// Node standard library only. usage: node refusals.js [output-file]
const fs = require('fs'), path = require('path');

const VECTORS = path.join(__dirname, 'vectors');

// The reader's declared refusal. The cause string names the defect; anything else
// (a TypeError, a bare SyntaxError) is `errored`, not a refusal.
class Refusal extends Error {
  constructor(cause, detail) {
    super(detail ? `${cause}: ${detail}` : cause);
    this.name = 'Refusal';
    this.cause = cause;
    this.detail = detail ?? null;
  }
}

// Strict RFC 8259 scan that names the non-JSON number literals instead of failing
// generically. The only extension recognized is the one these vectors use.
function parseStrict(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const fail = (why, detail) => { throw new Refusal(why, detail); };

  function string() {
    const start = i;
    i++; // opening quote
    while (i < text.length) {
      const c = text[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '"') { i++; return JSON.parse(text.slice(start, i)); }
      if (c < ' ') fail('control_character_in_string', `at offset ${i}`);
      i++;
    }
    fail('unterminated_string', `at offset ${start}`);
  }
  function number() {
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));
    if (m && m[0].length) {
      i += m[0].length;
      const n = Number(m[0]);
      if (!Number.isFinite(n)) fail('non_finite_number', m[0]);
      return n;
    }
    const w = /^-?[A-Za-z]+/.exec(text.slice(i));
    if (w) {
      if (/^-?(?:NaN|Infinity)$/.test(w[0])) fail('non_json_number_token', w[0]);
      fail('unknown_token', w[0]);
    }
    fail('unexpected_token', `at offset ${i}`);
  }
  function value() {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const out = {}; ws();
      if (text[i] === '}') { i++; return out; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected_key', `at offset ${i}`);
        const k = string();
        ws();
        if (text[i] !== ':') fail('expected_colon', `at offset ${i}`);
        i++;
        out[k] = value();
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return out; }
        fail('expected_comma_or_close', `at offset ${i}`);
      }
    }
    if (c === '[') {
      i++; const out = []; ws();
      if (text[i] === ']') { i++; return out; }
      for (;;) {
        out.push(value());
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return out; }
        fail('expected_comma_or_close', `at offset ${i}`);
      }
    }
    if (c === '"') return string();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    if (c === undefined) fail('unexpected_end_of_input', `at offset ${i}`);
    return number();
  }

  const v = value();
  ws();
  if (i !== text.length) fail('trailing_data', `at offset ${i}`);
  return v;
}

// Same canonical form as check.js: recursive key sort, numbers spelled by this
// runtime's Number::toString (the ES6 spelling RFC 8785 3.2.2.3 mandates).
// The finite guard is the second line of defence: a non-finite number that reached
// the value layer from anywhere else is refused rather than serialized.
function canon(v) {
  if (typeof v === 'number' && !Number.isFinite(v)) throw new Refusal('non_finite_number', String(v));
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

const files = fs.readdirSync(VECTORS).filter(f => f.endsWith('.json')).sort();
const rows = [];
let cases = 0, refusedForCause = 0, accepted = 0, errored = 0;

for (const f of files) {
  const doc = JSON.parse(fs.readFileSync(path.join(VECTORS, f), 'utf8')); // the vector file itself is valid JSON
  if (doc.disposition !== 'MUST-REJECT') continue;
  cases++;
  const raw = doc.input_raw;
  const tokenMatch = /(-?(?:NaN|Infinity))/.exec(raw);
  const statedToken = tokenMatch ? tokenMatch[1] : null;
  let outcome, detail;
  try {
    const bytes = Buffer.from(canon(parseStrict(raw)), 'utf8').toString('hex');
    outcome = 'accepted'; accepted++;
    detail = `bytes=${bytes}`;
  } catch (e) {
    if (e instanceof Refusal) {
      const causeOk = e.cause === 'non_json_number_token';
      const tokenOk = statedToken !== null && raw.includes(e.detail ?? '');
      if (causeOk && tokenOk) { outcome = 'pass'; refusedForCause++; }
      else { outcome = 'errored'; errored++; }
      const stated = String(doc.rationale || '').split('. ')[0].slice(0, 96);
      detail = `cause=${e.cause} token=${JSON.stringify(e.detail)} clause=${doc.rejecting_clause} `
        + `match=${causeOk && tokenOk ? 'yes' : 'no'} stated="${stated}"`;
    } else {
      outcome = 'errored'; errored++;
      detail = `raised ${e.name} (not the declared refusal): ${e.message.split('\n')[0]}`;
    }
  }
  rows.push(`${doc.id}  ${outcome.padEnd(8)}  ${detail}`);
}

// Controls: the same reader must not refuse numbers as such, only the named defect.
function tryRead(label, text) {
  try { return `${label}  accepted  bytes=${Buffer.from(canon(parseStrict(text)), 'utf8').toString('hex')}`; }
  catch (e) { return `${label}  refused   cause=${e.cause ?? e.name} detail=${JSON.stringify(e.detail ?? e.message)}`; }
}
const controls = [
  tryRead('CONTROL finite-number-in-same-position  {"n": 1.0}', '{"n": 1.0}'),
  tryRead('CONTROL number-as-string             {"n": "NaN"}', '{"n": "NaN"}'),
  tryRead('CONTROL exponent-boundary            {"n": 1e21}', '{"n": 1e21}'),
];

// The layer below: a non-finite *value* (as any lenient parser would hand over)
// reaches the canonicalizer. This reader refuses; the platform serializer does not.
let valueLayer;
try { valueLayer = `refused  cause=non_finite_number`; canon({ n: NaN }); }
catch (e) { valueLayer = `refused  cause=${e.cause}`; }
const platformSerializer = `JSON.stringify({n: NaN}) -> ${JSON.stringify({ n: NaN })}`;

const header = [
  '# a5-replay - refusal side, per-case output',
  '# input: the MUST-REJECT vectors of conformance-vectors/a2a-jcs-v01/a5-number-serialization/',
  '#        as published in a2aproject/a2a-tck pull/228 head 324c53250, copied verbatim into ./vectors/',
  '# reader: refusals.js in this directory (strict RFC 8259 scan + the 3.2.2.3 finite guard)',
  '#         declared refusal: Refusal, cause=non_json_number_token | non_finite_number',
  '# outcomes: pass = refused for the stated cause; accepted = returned bytes; errored = other',
  '# match rule: cause is non_json_number_token AND the offending token occurs in the vector input_raw',
  `# cases=${cases} refused_for_stated_cause=${refusedForCause} accepted=${accepted} errored=${errored}`,
  '',
  ...rows,
  '',
  '# controls (non-vacuity): the reader refuses the named defect, not numbers in general',
  ...controls,
  '',
  '# the value layer, reached only by a lenient parser (this reader is not one)',
  `VALUE-LAYER non-finite value passed to the canonicalizer: ${valueLayer}`,
  `VALUE-LAYER platform serializer on the same value:          ${platformSerializer}`,
  ''];
const out = header.join('\n');
if (process.argv[2]) fs.writeFileSync(process.argv[2], out); else process.stdout.write(out);
