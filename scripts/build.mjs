// ClickFix First Aid build script.
//
//   node scripts/build.mjs            regenerate all generated files
//   node scripts/build.mjs --check    fail if generated files are out of date (used in CI)
//   node scripts/build.mjs --package  build, then create release files in dist/
//
// Single sources of truth:
//   rules/clickfix-rules.json   detection rules (extension + Windows checker)
//   engine/detector.js          detection engine
//   guide/recovery.html         recovery guide (copied into the extension and docs/)
//   checker/src/*.ps1           Windows scripts (rules get embedded at build time)
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync, copyFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const CHECK = args.has('--check');
const PACKAGE = args.has('--package');

const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const HEADER = '/* GENERATED FILE: do not edit. Run "npm run build" after changing the sources. */\n';

const pkg = JSON.parse(read('package.json'));
const rulesText = read('rules/clickfix-rules.json');
const rules = JSON.parse(rulesText);
const rulesCompact = JSON.stringify(rules);
const detectorSrc = read('engine/detector.js');
const hookSrc = read('extension/src/page-hook.js');
const config = { version: pkg.version, homepage: pkg.homepage || '', repository: pkg.repository || '' };

// Every pattern must compile, or the build stops.
for (const groups of [rules.command, rules.page]) {
  for (const [group, list] of Object.entries(groups)) {
    for (const r of list) {
      try {
        new RegExp(r.pattern, 'i');
      } catch (e) {
        throw new Error(`Rule ${group}/${r.id} has an invalid pattern: ${e.message}`);
      }
    }
  }
}

const outputs = new Map();

outputs.set('extension/src/generated/rules.js', `${HEADER}self.CFA_RULES = ${rulesCompact};\n`);
outputs.set('extension/src/generated/detector.js', HEADER + detectorSrc);
outputs.set('extension/src/generated/config.js', `${HEADER}self.CFA_CONFIG = ${JSON.stringify(config)};\n`);
outputs.set(
  'extension/src/generated/main-world.js',
  `${HEADER}// Detection engine + rules + clipboard guard, wrapped so nothing leaks into the page.\n` +
    `(function () {\n'use strict';\nvar module = { exports: {} };\n` +
    `${detectorSrc}\nvar CFADetectorAPI = module.exports;\nvar CFA_RULES = ${rulesCompact};\n` +
    `${hookSrc}\n})();\n`
);

const manifest = JSON.parse(read('extension/manifest.json'));
manifest.version = pkg.version;
outputs.set('extension/manifest.json', JSON.stringify(manifest, null, 2) + '\n');

const fill = (s) =>
  s
    .replaceAll('{{VERSION}}', pkg.version)
    .replaceAll('{{HOMEPAGE}}', config.homepage || '#')
    .replaceAll('{{REPOSITORY}}', config.repository || '#');

const guide = fill(read('guide/recovery.html'));
outputs.set('extension/pages/recovery.html', guide);
outputs.set('docs/recovery.html', guide);
outputs.set('docs/index.html', fill(read('guide/index.html')));
outputs.set('docs/demo.html', fill(read('guide/demo.html')));

const guideUrl = config.homepage ? config.homepage.replace(/\/$/, '') + '/recovery.html' : 'docs/recovery.html in the ClickFix First Aid download';
for (const name of ['Check-ClickFix.ps1', 'Protect-RunDialog.ps1']) {
  let src = read(`checker/src/${name}`);
  src = src
    // Rules go inside a single-quoted here-string (@' ... '@), where nothing needs escaping.
    .replace('__CFA_RULES_JSON__', () => rulesCompact)
    .replaceAll('__CFA_VERSION__', pkg.version)
    .replaceAll('__CFA_GUIDE_URL__', guideUrl);
  if (/[^\x00-\x7F]/.test(src)) {
    throw new Error(`checker/src/${name} contains non-ASCII characters; Windows PowerShell 5.1 may misread them.`);
  }
  outputs.set(`checker/${name}`, src.replace(/\r?\n/g, '\r\n'));
}

if (CHECK) {
  const stale = [];
  for (const [p, content] of outputs) {
    const full = join(ROOT, p);
    if (!existsSync(full) || readFileSync(full, 'utf8') !== content) stale.push(p);
  }
  if (stale.length) {
    console.error('Out of date (run "npm run build"):\n  ' + stale.join('\n  '));
    process.exit(1);
  }
  console.log(`All ${outputs.size} generated files are up to date.`);
  process.exit(0);
}

for (const [p, content] of outputs) {
  const full = join(ROOT, p);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}
console.log(`Wrote ${outputs.size} generated files.`);

// Icons (needs the "sharp" image library; skipped if it is not installed).
async function buildIcons() {
  let sharp;
  for (const base of [ROOT, '/opt/npm-tools']) {
    try {
      sharp = createRequire(join(base, 'package.json'))('sharp');
      break;
    } catch (e) {
      /* try next */
    }
  }
  if (!sharp) {
    console.log('sharp not found: icons not regenerated.');
    return;
  }
  const svg = readFileSync(join(ROOT, 'assets/icon.svg'));
  mkdirSync(join(ROOT, 'extension/icons'), { recursive: true });
  for (const size of [16, 32, 48, 128]) {
    await sharp(svg, { density: 384 }).resize(size, size).png().toFile(join(ROOT, `extension/icons/icon-${size}.png`));
  }
  await sharp(svg, { density: 384 }).resize(128, 128).png().toFile(join(ROOT, 'docs/icon-128.png'));
  console.log('Icons written.');
}
await buildIcons();

if (PACKAGE) {
  const dist = join(ROOT, 'dist');
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(dist, { recursive: true });
  const zipName = `clickfix-first-aid-extension-v${pkg.version}.zip`;
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (!full.endsWith('page-hook.js')) files.push(relative(join(ROOT, 'extension'), full));
    }
  };
  walk(join(ROOT, 'extension'));
  execFileSync('python3', ['-c', [
    'import sys, zipfile',
    'zf = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)',
    'for f in sys.argv[3:]: zf.write(sys.argv[2] + "/" + f, f)',
    'zf.close()'
  ].join('\n'), join(dist, zipName), join(ROOT, 'extension'), ...files.sort()]);
  copyFileSync(join(ROOT, 'checker/Check-ClickFix.ps1'), join(dist, 'Check-ClickFix.ps1'));
  copyFileSync(join(ROOT, 'checker/Protect-RunDialog.ps1'), join(dist, 'Protect-RunDialog.ps1'));
  console.log(`Packaged into dist/: ${zipName}, Check-ClickFix.ps1, Protect-RunDialog.ps1`);
}
