#!/usr/bin/env node
// a5-replay: canonicalize every a5-number-serialization vector with a reader
// written from the spec alone (recursive key sort + the ES6 number formatting
// RFC 8785 3.2.2.3 mandates, taken from this runtime's own Number::toString),
// and report one line per case. Node standard library only.
//
// usage: node check.js [output-file]      (default: stdout)
const fs = require('fs'), path = require('path');

const VECTORS = path.join(__dirname, 'vectors');
const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : (v && typeof v === 'object') ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);

const files = fs.readdirSync(VECTORS).filter(f => f.endsWith('.json')).sort();
const rows = [];
let agree = 0, mismatch = 0, skipped = 0, changed = 0;

for (const f of files) {
  const txt = fs.readFileSync(path.join(VECTORS, f), 'utf8');
  let doc;
  try { doc = JSON.parse(txt); }
  catch (e) { rows.push([f, 'SKIP', 'input is not valid JSON: ' + e.message.split('\n')[0]]); skipped++; continue; }
  const expected = (doc.expected || {}).canonical_utf8_hex;
  if (!expected) { rows.push([f, 'SKIP', `no canonical_utf8_hex (refusal-shaped, disposition=${doc.disposition})`]); skipped++; continue; }
  const got = Buffer.from(canon(doc.input), 'utf8').toString('hex');
  const ok = got === expected;
  const m = txt.match(/"input"\s*:\s*(\{[\s\S]*?\n\s*\})/);
  const rawSpelling = m ? (m[1].match(/-?\d[\d.eE+-]*/g) || []) : [];
  const canonSpelling = canon(doc.input).match(/-?\d[\d.eE+-]*/g) || [];
  const spellingChanged = JSON.stringify(rawSpelling) !== JSON.stringify(canonSpelling);
  if (ok) agree++; else mismatch++;
  if (spellingChanged) changed++;
  rows.push([f, ok ? 'AGREE' : 'MISMATCH',
    'source_spelling=' + JSON.stringify(rawSpelling),
    'canonical_spelling=' + JSON.stringify(canonSpelling),
    spellingChanged ? 'SPELLING-CHANGED' : 'spelling-stable',
    'got=' + got, 'expected=' + expected].join('  '));
}

const header = [
  '# a5-replay - per-case output',
  '# input: conformance-vectors/a2a-jcs-v01/a5-number-serialization/ as published in',
  '#        a2aproject/a2a-tck pull/228 head 324c53250, copied verbatim into ./vectors/',
  '# reader: check.js in this directory (recursive key sort + ES6 Number::toString)',
  `# cases=${files.length} agree=${agree} mismatch=${mismatch} skipped=${skipped} spelling_changed=${changed}`,
  ''];
const out = header.concat(rows).join('\n') + '\n';
if (process.argv[2]) fs.writeFileSync(process.argv[2], out); else process.stdout.write(out);
