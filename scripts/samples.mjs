// Read or add the shared test commands in tests/fixtures/commands.json.
// They are stored base64-encoded so antivirus programs do not mistake this
// file for an attack script (see "encoding" in that file).
//
//   node scripts/samples.mjs                       list every sample, decoded
//   node scripts/samples.mjs block                 list one group (block, hold or allow)
//   node scripts/samples.mjs add block "name" "command"
//
// Malicious samples must only use reserved hosts (example.invalid, *.example,
// 203.0.113.0/24) and harmless payloads like "echo test".
import { readFileSync, writeFileSync } from 'node:fs';

const FILE = new URL('../tests/fixtures/commands.json', import.meta.url);
const GROUPS = ['block', 'hold', 'allow'];
const data = JSON.parse(readFileSync(FILE, 'utf8'));
const decode = (s) => Buffer.from(s, 'base64').toString('utf8');
const encode = (s) => Buffer.from(s, 'utf8').toString('base64');
const [cmd, group, name, command] = process.argv.slice(2);

if (cmd === 'add') {
  if (!GROUPS.includes(group) || !name || !command) {
    console.error('Usage: node scripts/samples.mjs add <block|hold|allow> "name" "command"');
    process.exit(1);
  }
  if (data[group][name]) {
    console.error(`"${name}" already exists in ${group}.`);
    process.exit(1);
  }
  data[group][name] = encode(command);
  writeFileSync(FILE, JSON.stringify(data, null, 2) + '\n');
  console.log(`Added to ${group}: ${name}`);
} else {
  for (const g of GROUPS) {
    if (cmd && cmd !== g) continue;
    console.log(`\n== ${g}`);
    for (const [n, v] of Object.entries(data[g])) console.log(`${n}\n    ${decode(v).replace(/\n/g, '\n    ')}`);
  }
}
