// Checks that the official help pages linked from the recovery guide still exist.
//   npm run links
// Read-only: plain GET requests, no sign-in, redirects followed by hand so a
// link can never quietly lead to a different website. Run weekly in CI.
//
// Only a clear answer from the site fails the check (for example 404 Not Found,
// or a redirect to a different website). If the site cannot be reached at all,
// or refuses automated requests, the link is reported for a manual look instead:
// some sites block cloud servers or other countries, which says nothing about
// whether the page still exists.
import { readFile } from 'node:fs/promises';

const html = await readFile(new URL('../guide/recovery.html', import.meta.url), 'utf8');
const urls = [...new Set([...html.matchAll(/href="(https:\/\/[^"]+)"/g)].map((m) => m[1]))];
const base = (host) => host.split('.').slice(-2).join('.');
const inCI = process.env.GITHUB_ACTIONS === 'true';
const results = [];

class Unreachable extends Error {}

function why(e) {
  const c = e && e.cause;
  if (e && e.name === 'TimeoutError') return 'no answer within 20 seconds';
  if (c && c.code) return `${c.code}${c.message && c.message !== c.code ? `: ${c.message}` : ''}`;
  return (e && e.message) || String(e);
}

for (const url of urls) {
  let current = url;
  try {
    let res;
    for (let hops = 0; hops < 6; hops++) {
      try {
        res = await fetch(current, {
          redirect: 'manual',
          signal: AbortSignal.timeout(20000),
          headers: { 'user-agent': 'ClickFix-First-Aid-link-check (+https://github.com)' }
        });
      } catch (e) {
        throw new Unreachable(why(e));
      }
      if (![301, 302, 303, 307, 308].includes(res.status)) break;
      const next = new URL(res.headers.get('location') || '', current);
      await res.body?.cancel();
      if (next.protocol !== 'https:' || base(next.hostname) !== base(new URL(url).hostname)) {
        throw new Error(`redirects to a different site: ${next.hostname}`);
      }
      current = next.href;
    }
    await res.body?.cancel();
    if (res.ok) {
      results.push({ url, kind: 'ok', note: String(res.status) });
    } else if ([401, 403, 429].includes(res.status) || res.status >= 500) {
      results.push({ url, kind: 'unsure', note: `HTTP ${res.status}: the site refused an automated check or had a temporary error` });
    } else {
      results.push({ url, kind: 'broken', note: `HTTP ${res.status}` });
    }
  } catch (e) {
    if (e instanceof Unreachable) {
      results.push({ url, kind: 'unsure', note: `could not reach the site from here (${e.message})` });
    } else {
      results.push({ url, kind: 'broken', note: e.message });
    }
  }
}

const label = { ok: 'ok     ', unsure: 'unsure ', broken: 'BROKEN ' };
for (const r of results) {
  console.log(`${label[r.kind]} ${r.url}  ${r.kind === 'ok' ? r.note : `(${r.note})`}`);
  // In GitHub Actions, also show each problem on the run's summary page.
  if (inCI && r.kind === 'broken') console.log(`::error title=Broken link::${r.url} (${r.note})`);
  if (inCI && r.kind === 'unsure') console.log(`::warning title=Check this link by hand::${r.url} (${r.note})`);
}

const count = (k) => results.filter((r) => r.kind === k).length;
console.log(`\n${results.length} links: ${count('ok')} ok, ${count('unsure')} need a manual look, ${count('broken')} broken.`);
process.exitCode = count('broken') ? 1 : 0;
