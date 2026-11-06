// ClickFix benchmark: loads one browser extension (or none) into Chromium and
// replays defanged ClickFix attacks and ordinary copy buttons against it.
//
//   node benchmark/run.mjs --label "ClickFix First Aid" --ext extension
//   node benchmark/run.mjs --label "No extension" --none
//
// Options: --out results.json   full per-case results
//          --wait 5000          ms to wait after each click
//          --think 1000         ms between the page loading and the click, as a person
//                               needs time to read the page before clicking
//          --only g/id,g/id     run only these cases (e.g. attack-lure/H17)
//          --shots dir          save screenshots of the page after the click for
//                               --shot-cases (default attack-lure/H17,attack-plain/H17)
//          --storage '{...}'    settings to put in the extension's chrome.storage.local
//                               before the first page opens (to test a non-default mode)
//
// The result of every case is what is on the clipboard afterwards:
//   delivered  the exact text the page tried to copy
//   prevented  the clipboard was left as it was before the click
//   replaced   the clipboard holds something else (a warning, a note)
// For an attack, "delivered" means the attack got through. For an ordinary
// copy, anything other than "delivered" is friction or a false alarm.
//
// Pages are generated in memory from benchmark/samples.json, served on the
// loopback interface only, and reached under made-up *.test host names so that
// extensions treat them like ordinary websites. Nothing leaves the machine.
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const HERE = dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const label = opt('--label', 'unnamed');
const extDir = args.includes('--none') ? null : resolve(opt('--ext', join(HERE, '..', 'extension')));
const outFile = opt('--out', null);
const WAIT = Number(opt('--wait', '5000'));
const THINK = Number(opt('--think', '1000'));
const ONLY = opt('--only', null);
const SHOTS = opt('--shots', null);
const SHOT_CASES = (opt('--shot-cases', 'attack-lure/H17,attack-plain/H17')).split(',');
const STORAGE = opt('--storage', null);

const S = JSON.parse(await readFile(join(HERE, 'samples.json'), 'utf8'));
const dec = (b) => Buffer.from(b, 'base64').toString('utf8');
const METHODS = ['writeText', 'write', 'execCommand', 'setData', 'itemsAdd'];

// ---- Pages -----------------------------------------------------------------
const copyScript = (b64) => `
const cmd = new TextDecoder().decode(Uint8Array.from(atob('${b64}'), (c) => c.charCodeAt(0)));
async function doCopy(method) {
  if (method === 'writeText') return navigator.clipboard.writeText(cmd);
  if (method === 'write') return navigator.clipboard.write([new ClipboardItem({ 'text/plain': new Blob([cmd], { type: 'text/plain' }) })]);
  if (method === 'execCommand') {
    const t = document.createElement('textarea');
    t.value = cmd; t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); return;
  }
  document.addEventListener('copy', (e) => {
    if (method === 'setData') e.clipboardData.setData('text/plain', cmd);
    else e.clipboardData.items.add(cmd, 'text/plain');
    e.preventDefault();
  }, { once: true });
  document.execCommand('copy');
}`;

function lurePage(sample, method) {
  const mac = sample.os === 'mac';
  const steps = mac
    ? ['Press <b>Command + Space</b> and type <b>Terminal</b>', 'Press <b>Command + V</b>', 'Press <b>Return</b>']
    : ['Press <b>Windows + R</b>', 'Press <b>CTRL + V</b>', 'Press <b>Enter</b>'];
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Just a moment...</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f4f4;display:grid;place-items:center;min-height:100vh;margin:0}
.box{background:#fff;border:1px solid #ddd;border-radius:4px;padding:24px 28px;width:340px}
label{display:flex;gap:12px;align-items:center;font-size:15px;cursor:pointer}#robot{width:26px;height:26px}
#steps{display:none;margin-top:18px;font-size:14px}</style></head><body>
<div class="box"><h1 style="font-size:20px">Verify you are human</h1>
<p style="font-size:13px;color:#555">This site needs to review the security of your connection before proceeding.</p>
<label><input type="checkbox" id="robot"> I'm not a robot</label>
<div id="steps"><p><b>Verification steps</b></p><ol>${steps.map((s) => `<li>${s}</li>`).join('')}</ol></div></div>
<script>${copyScript(sample.b64)}
document.getElementById('robot').addEventListener('click', () => {
  document.getElementById('steps').style.display = 'block';
  doCopy('${method}');
});</script></body></html>`;
}

function docsPage(sample) {
  const text = dec(sample.b64).replace(/&/g, '&amp;').replace(/</g, '&lt;');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Getting started</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;line-height:1.5}
pre{background:#f6f8fa;padding:12px;border-radius:6px;white-space:pre-wrap;word-break:break-all}</style></head><body>
<h1>Getting started</h1><p>Run this in your terminal:</p><pre><code>${text}</code></pre>
<button id="copy">Copy</button>
<script>${copyScript(sample.b64)}
document.getElementById('copy').addEventListener('click', () => doCopy('writeText'));</script></body></html>`;
}

const cases = [];
for (const a of S.attacks) cases.push({ group: 'attack-lure', id: a.id, host: 'verify-human.test', path: `/lure/${a.id}`, sample: a, method: 'writeText', click: '#robot' });
for (const a of S.attacks) cases.push({ group: 'attack-plain', id: a.id, host: 'docs-portal.test', path: `/docs/${a.id}`, sample: a, method: 'writeText', click: '#copy' });
const H17 = S.attacks.find((a) => a.id === 'H17');
for (const m of METHODS) cases.push({ group: 'method', id: `H17-${m}`, host: 'verify-human.test', path: `/lure/H17?m=${m}`, sample: H17, method: m, click: '#robot' });
for (const b of S.benign) cases.push({ group: 'benign', id: b.id, host: 'docs-portal.test', path: `/docs/${b.id}`, sample: b, method: 'writeText', click: '#copy' });

const byId = new Map([...S.attacks, ...S.benign].map((s) => [s.id, s]));
const server = createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const [, kind, id] = u.pathname.split('/');
  let body = '<!doctype html><title>reader</title><p>reader';
  if (kind === 'lure' && byId.has(id)) body = lurePage(byId.get(id), u.searchParams.get('m') || 'writeText');
  else if (kind === 'docs' && byId.has(id)) body = docsPage(byId.get(id));
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

// ---- Browser ----------------------------------------------------------------
const userDataDir = await mkdtemp(join(tmpdir(), 'cfbench-'));
const HOSTS = ['verify-human.test', 'docs-portal.test', 'reader.test'];
const ORIGINS = HOSTS.map((h) => `http://${h}:${port}`);
// The clipboard API needs a secure context, so the made-up hosts are treated as secure.
const launchArgs = ['--headless=new', '--no-sandbox', '--host-resolver-rules=MAP *.test 127.0.0.1', `--unsafely-treat-insecure-origin-as-secure=${ORIGINS.join(',')}`];
if (extDir) launchArgs.push(`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`);
const context = await chromium.launchPersistentContext(userDataDir, { headless: false, args: launchArgs });
for (const origin of ORIGINS) await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
if (extDir && !context.serviceWorkers().length) {
  await context.waitForEvent('serviceworker', { timeout: 15000 }).catch(() => {});
}
await new Promise((r) => setTimeout(r, 1500));
if (extDir && STORAGE) {
  const sw = context.serviceWorkers()[0];
  if (!sw) throw new Error('--storage needs the extension to have a background service worker');
  await sw.evaluate((o) => chrome.storage.local.set(o), JSON.parse(STORAGE));
  await new Promise((r) => setTimeout(r, 500));
}

const reader = await context.newPage();
await reader.goto(`http://reader.test:${port}/read`);
const setClip = async (t) => { await reader.bringToFront(); await reader.evaluate((x) => navigator.clipboard.writeText(x), t); };
const getClip = async () => { await reader.bringToFront(); return reader.evaluate(() => navigator.clipboard.readText()); };

const results = [];
for (const c of cases) {
  if (ONLY && !ONLY.split(',').includes(`${c.group}/${c.id}`)) continue;
  const sentinel = `sentinel-${c.group}-${c.id}-${Date.now()}`;
  await setClip(sentinel);
  const page = await context.newPage();
  let dialog = false;
  page.on('dialog', (d) => { dialog = true; d.dismiss().catch(() => {}); });
  let error = null;
  try {
    await page.goto(`http://${c.host}:${port}${c.path}`, { waitUntil: 'load' });
    await page.bringToFront();
    await new Promise((r) => setTimeout(r, THINK));
    await page.click(c.click, { timeout: 5000 });
  } catch (e) { error = String(e.message || e).split('\n')[0]; }
  await new Promise((r) => setTimeout(r, WAIT));
  const finalUrl = page.url();
  if (SHOTS && SHOT_CASES.includes(`${c.group}/${c.id}`)) {
    const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    await page.screenshot({ path: join(SHOTS, `${slug}-${c.group}-${c.id}.png`) }).catch(() => {});
  }
  let clip;
  try { clip = await getClip(); } catch (e) { clip = null; error = error || 'clipboard read failed'; }
  const expected = dec(c.sample.b64);
  const outcome = clip === expected ? 'delivered' : clip === sentinel ? 'prevented' : 'replaced';
  results.push({ group: c.group, id: c.id, method: c.method, outcome, dialog, navigatedAway: !finalUrl.includes(`${c.host}:${port}`), clipboardStart: clip && outcome === 'replaced' ? clip.slice(0, 60) : undefined, error: error || undefined });
  await page.close().catch(() => {});
  process.stderr.write(`${label}: ${c.group} ${c.id} ${outcome}${dialog ? ' (dialog)' : ''}\n`);
}

let meta = { label, extension: null };
if (extDir) {
  const m = JSON.parse(await readFile(join(extDir, 'manifest.json'), 'utf8'));
  let name = m.name;
  const msg = /^__MSG_(\w+)__$/.exec(name || '');
  if (msg) {
    try {
      const strings = JSON.parse(await readFile(join(extDir, '_locales', m.default_locale || 'en', 'messages.json'), 'utf8'));
      const hit = Object.entries(strings).find(([k]) => k.toLowerCase() === msg[1].toLowerCase());
      if (hit) name = hit[1].message;
    } catch {}
  }
  meta.extension = { name, version: m.version };
  if (STORAGE) meta.extension.storage = JSON.parse(STORAGE);
  try { meta.extension.commit = execFileSync('git', ['-C', extDir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim(); } catch {}
}
meta.browser = context.browser()?.version() || null;
meta.date = new Date().toISOString();
meta.waitMs = WAIT;
meta.thinkMs = THINK;

await context.close();
server.close();
await rm(userDataDir, { recursive: true, force: true });

const summary = {};
for (const r of results) {
  summary[r.group] ??= { delivered: 0, prevented: 0, replaced: 0, total: 0 };
  summary[r.group][r.outcome]++; summary[r.group].total++;
}
const report = { meta, summary, results };
if (outFile) await writeFile(outFile, JSON.stringify(report, null, 1));
console.log(JSON.stringify({ label, summary }, null, 1));
