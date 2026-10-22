// End-to-end tests: load the real extension into Chromium and visit harmless
// fake ClickFix pages (tests/fixtures/pages). Run with: npm run test:e2e
//
// Needs the "playwright" package and a Chromium build. Set CHROMIUM_PATH to use
// a specific browser binary.
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
const EXT = process.env.CFA_EXTENSION_DIR || join(ROOT, 'extension'); // set to test an unzipped release
const SAFE_PREFIX = '# STOP. ClickFix First Aid blocked this.';
const TRAP = 'cmd /c echo ClickFix First Aid test, this is harmless # I am not a robot - reCAPTCHA Verification ID: 1234';

let server;
let base;
let context;
let userDataDir;

before(async () => {
  server = createServer(async (req, res) => {
    try {
      const name = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
      if (name.includes('..')) throw new Error('bad path');
      // /docs/... serves the published site (for the safe demo), everything else the test pages.
      const body = name.startsWith('docs/') ? await readFile(join(ROOT, name)) : await readFile(join(PAGES, name));
      res.writeHead(200, { 'content-type': extname(name) === '.js' ? 'text/javascript' : 'text/html; charset=utf-8' });
      res.end(body);
    } catch (e) {
      res.writeHead(404);
      res.end('not found');
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;

  userDataDir = await mkdtemp(join(tmpdir(), 'cfa-e2e-'));
  context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: ['--headless=new', `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-sandbox']
  });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base });
  // Wait for the extension's background worker to start.
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

async function clipboard(page) {
  return page.evaluate(() => navigator.clipboard.readText());
}

async function setClipboard(page, text) {
  await page.evaluate((t) => navigator.clipboard.writeText(t), text);
}

async function uiState(page) {
  return page.evaluate(() => {
    const el = document.querySelector('clickfix-first-aid-ui');
    return el ? el.getAttribute('data-state') : null;
  });
}

for (const [name, selector] of [
  ['writetext.html', '#robot'],
  ['execcommand.html', '#robot'],
  ['copyevent.html', '#robot'],
  ['clipboarditem.html', '#robot']
]) {
  test(`blocks the trap on ${name}`, async () => {
    const page = await open(name);
    await setClipboard(page, 'before');
    await page.click(selector);
    await page.waitForFunction(() => document.title !== document.title.replace('copied', '') || document.title.startsWith('error'), null, { timeout: 5000 }).catch(() => {});
    await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="blocked"]'), null, { timeout: 5000 });
    const clip = await clipboard(page);
    assert.ok(clip.startsWith(SAFE_PREFIX), `clipboard should hold the safe message, got: ${clip}`);
    assert.notEqual(clip, TRAP);
    await page.close();
  });
}

test('blocks a trap inside an iframe and warns in the top page', async () => {
  const page = await open('iframe-top.html');
  await setClipboard(page, 'before');
  const frame = page.frameLocator('#captcha');
  await frame.locator('#robot').click();
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="blocked"]'), null, { timeout: 5000 });
  const clip = await clipboard(page);
  assert.ok(clip.startsWith(SAFE_PREFIX), `clipboard should hold the safe message, got: ${clip}`);
  await page.close();
});

test('a plain command from a hidden frame is blocked when the outer page is a trap', async () => {
  const page = await open('iframe-plain-top.html');
  await setClipboard(page, 'before');
  await page.frameLocator('#captcha').locator('#robot').click();
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="blocked"]'), null, { timeout: 5000 });
  assert.ok((await clipboard(page)).startsWith(SAFE_PREFIX));
  await page.close();
});

test('a plain command copied before the trap steps are revealed is blocked', async () => {
  const page = await open('copy-before-steps.html');
  await setClipboard(page, 'before');
  await page.click('#robot');
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="blocked"]'), null, { timeout: 5000 });
  assert.ok((await clipboard(page)).startsWith(SAFE_PREFIX));
  await page.close();
});

test('developer installer copy is allowed, with a gentle note', async () => {
  const page = await open('docs-copy.html');
  await page.click('#copy');
  await page.waitForFunction(() => document.title === 'copied', null, { timeout: 5000 });
  assert.equal(await clipboard(page), 'irm https://get.scoop.sh | iex');
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="warned"]'), null, { timeout: 5000 });
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

test('a trap page is flagged even before anything is copied', async () => {
  const page = await open('lure-only.html');
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="lure"]'), null, { timeout: 5000 });
  await page.close();
});

test('trap steps revealed after a click are flagged', async () => {
  const page = await open('reveal.html');
  await page.waitForTimeout(1200);
  assert.equal(await uiState(page), null, 'nothing to flag while the steps are hidden');
  await page.click('#robot');
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="lure"]'), null, { timeout: 5000 });
  await page.close();
});

test('the public safe demo page triggers the block', async () => {
  const page = await open('docs/demo.html');
  await setClipboard(page, 'before');
  await page.click('#robot');
  await page.waitForFunction(() => !!document.querySelector('clickfix-first-aid-ui[data-state="blocked"]'), null, { timeout: 5000 });
  assert.ok((await clipboard(page)).startsWith(SAFE_PREFIX));
  await page.close();
});

test('a normal Win+R tutorial is not flagged', async () => {
  const page = await open('tutorial.html');
  await page.waitForTimeout(2000);
  assert.equal(await uiState(page), null);
  await page.close();
});

test('the popup counts what was blocked', async () => {
  const worker = context.serviceWorkers()[0];
  const extId = new URL(worker.url()).host;
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup/popup.html`);
  await page.waitForFunction(() => Number(document.getElementById('blocked').textContent) >= 5, null, { timeout: 5000 });
  const lures = Number(await page.textContent('#lures'));
  assert.ok(lures >= 1, 'at least one trap page counted');
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
