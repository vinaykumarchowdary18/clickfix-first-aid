// The fake trap pages used by the browser tests live in one encoded bundle,
// tests/fixtures/pages.bundle.json, instead of as loose HTML files.
//
// Why: they are harmless, but they look exactly like ClickFix attack pages,
// and antivirus programs (Microsoft Defender: Trojan:HTML/FakeCaptcha)
// quarantine them as soon as the project is unzipped or cloned on Windows.
// The test server decodes them in memory, so they never exist on disk.
//
//   node scripts/fixtures.mjs list            list the pages in the bundle
//   node scripts/fixtures.mjs unpack          write them to tests/fixtures/pages/ to edit
//   node scripts/fixtures.mjs pack            put tests/fixtures/pages/ back into the bundle
//
// tests/fixtures/pages/ is in .gitignore. Unpack only inside a test machine or
// a folder your antivirus is told to skip, and pack again before committing.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE = join(ROOT, 'tests/fixtures/pages.bundle.json');
const DIR = join(ROOT, 'tests/fixtures/pages');

export function loadFixturePages() {
  const data = JSON.parse(readFileSync(BUNDLE, 'utf8'));
  const pages = new Map();
  for (const [name, b64] of Object.entries(data.files)) pages.set(name, Buffer.from(b64, 'base64'));
  return pages;
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cmd = process.argv[2];
  if (cmd === 'pack') {
    const files = {};
    for (const f of walk(DIR).sort()) files[relative(DIR, f).split('\\').join('/')] = readFileSync(f).toString('base64');
    writeFileSync(BUNDLE, JSON.stringify({
      note: 'Harmless fake ClickFix pages for the browser tests, base64-encoded so antivirus programs do not quarantine them. See scripts/fixtures.mjs.',
      files
    }, null, 1) + '\n');
    console.log(`Packed ${Object.keys(files).length} files into ${relative(ROOT, BUNDLE)}`);
  } else if (cmd === 'unpack') {
    let n = 0;
    for (const [name, buf] of loadFixturePages()) {
      const out = join(DIR, name);
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, buf);
      n++;
    }
    console.log(`Unpacked ${n} files into ${relative(ROOT, DIR)}/ (ignored by git). Run "pack" after editing.`);
  } else {
    for (const [name, buf] of loadFixturePages()) console.log(`${String(buf.length).padStart(7)}  ${name}`);
  }
}
