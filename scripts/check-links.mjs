// Checks that the official help pages linked from the recovery guide still exist.
//   npm run links
// Read-only: plain GET requests, no sign-in, redirects followed by hand so a
// link can never quietly lead to a different website. Run weekly in CI.
import { readFile } from 'node:fs/promises';

const html = await readFile(new URL('../guide/recovery.html', import.meta.url), 'utf8');
const urls = [...new Set([...html.matchAll(/href="(https:\/\/[^"]+)"/g)].map((m) => m[1]))];
const base = (host) => host.split('.').slice(-2).join('.');
let broken = 0;
let unsure = 0;

for (const url of urls) {
  let current = url;
  try {
    let res;
    for (let hops = 0; hops < 6; hops++) {
      res = await fetch(current, {
        redirect: 'manual',
        signal: AbortSignal.timeout(20000),
        headers: { 'user-agent': 'ClickFix-First-Aid-link-check (+https://github.com)' }
      });
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
      console.log(`ok      ${res.status} ${url}`);
    } else if ([401, 403, 429].includes(res.status)) {
      unsure++;
      console.log(`unsure  ${res.status} ${url}  (the site refused an automated check; open it by hand)`);
    } else {
      broken++;
      console.log(`BROKEN  ${res.status} ${url}`);
    }
  } catch (e) {
    broken++;
    console.log(`BROKEN  ${url}: ${e.message}`);
  }
}

console.log(`\n${urls.length} links: ${urls.length - broken - unsure} ok, ${unsure} need a manual look, ${broken} broken.`);
process.exitCode = broken ? 1 : 0;
