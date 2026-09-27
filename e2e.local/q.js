// q.js '<expression>': evaluate a JS expression against JSON read from stdin.
// The parsed document is `d`; `data` is d.data for UniFi envelopes.
// Arrays print one element per line, objects as JSON, scalars as plain text.
// Output goes through process.stdout.write so FORCE_COLOR never adds ANSI codes.
// The expression is written by run.sh itself; controller data is only parsed.
const emit = (v) => process.stdout.write((typeof v === 'object' ? JSON.stringify(v) : String(v)) + '\n');
let raw = '';
process.stdin.on('data', (c) => { raw += c; });
process.stdin.on('end', () => {
  let d;
  try { d = JSON.parse(raw); } catch { console.error('q.js: invalid JSON'); process.exit(2); }
  const data = d && d.data;
  const out = new Function('d', 'data', `return (${process.argv[2]});`)(d, data);
  if (Array.isArray(out)) out.forEach(emit);
  else if (out !== undefined && out !== null) emit(out);
});
