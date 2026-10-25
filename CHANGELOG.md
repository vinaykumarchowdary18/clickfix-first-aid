# Changelog

## v0.3.0 (25 October 2026)

This release comes from a second round of independent review with Perplexity (an architecture and risk analysis, a QA plan with contract tests, and a security and integration review, all in [reviews/](reviews/)), plus problems found while checking that round. The round also delivered a complete rewrite of the extension. It was not adopted: run against this project's test samples, its engine missed 2 of the 26 attack shapes, blocked 10 of the 11 legitimate installer and one-liner samples (by design), and could be switched off by a page replacing `RegExp.prototype[Symbol.replace]`. Its good ideas were taken instead, and are credited below.

The fixes come with tests that fail on v0.2.0 and pass now. The one exception is the real-click check on the warning buttons, which no web page can reach to test, because the buttons sit in a closed shadow root.

### Protection

- **Padding could hide a command (found while checking the rewrite's length limit).** v0.2 checked only the first 20,000 characters, so 20,000 blank lines or spaces before a command made it look harmless. This matters most for traps that ask you to paste into Terminal or PowerShell. The check now covers 200,000 characters, and anything longer is paused with "too long to check completely", never simply allowed. The PC check does the same.
- **Four patterns could take over 40 seconds** on 200,000 characters of hostile text (catastrophic backtracking in the web-address and network-path patterns, and a slow scan in the fake-CAPTCHA-comment rule). Every repeat now has a sensible upper limit. A new test times every pattern on hostile text.
- **Connecting the dots survives the background worker stopping** (integration review: "a service worker is ephemeral"). Chrome stops it after about 30 idle seconds; v0.2 then forgot that a tab had shown trap steps, so a later copy was only paused, not blocked. What each tab has seen now lives in `chrome.storage.session`.
- **One place for every settings change** (integration review, C3). In v0.2 the popup still wrote settings itself and could undo a change made in a tab at the same moment. All changes, and the history counters, now go through one queue in the background worker. Only the popup may change settings, and "Always allow on this site" takes the site from the tab's own address.
- **A second check in the isolated world** (integration review: "isolated-world code should own the verdict"). Reports whose text has nothing command-like in it are ignored, using the same test the guard uses, and they no longer use up the warning slot.
- **Warning buttons only react to real clicks** (`event.isTrusted`), on top of the closed shadow root.
- **"Copy anyway" copies the whole text.** v0.2 passed on only the first 20,000 characters, so a long held script came out cut off. Reports now carry up to 1,000,000 characters, and if text is longer than that, "Copy anyway" is not offered.
- **No network from the extension's own pages**: a Content Security Policy with `connect-src 'none'` (from the rewrite).

### New

- **Check a command**, in the popup: paste a command a site gave you and see what the rules say, without running it (idea from the rewrite). It says plainly that "no known attack pattern" does not mean safe.

### Recovery guide

- Defender offline scan: leads with the label on Microsoft's current consumer help page, "Microsoft Defender Antivirus (offline scan)", mentions the older name and the "Start an offline scan" button, and links both Microsoft pages. The review suggested dropping "about 15 minutes"; it was kept, because Microsoft's technical guide states it, and it is now attributed to that guide.
- Discord: "Devices" is mentioned as "if your app shows it". The review could not confirm that screen on Discord's own pages, and neither could we; Discord's guide does confirm that changing the password logs out all devices.

### Project

- `package-lock.json`, `npm ci` in CI, Node 22 and 24, dependency audit, Dependabot, issue and pull request templates, `PRIVACY.md`, `RELEASING.md`, and `SHA256SUMS.txt` with every release (from the rewrite). Release zips now use fixed file dates, so rebuilding the same sources with the same tools gives the same checksum.
- `npm run links` and a weekly workflow check that the guide's official help links still work, without following redirects to other sites (from the rewrite).
- The browser test server listens on the local machine only and refuses paths outside the test folders (integration review).
- The QA suite's detector contract run against this engine: 7 of 8 pass unmodified. The 8th expects non-text input to throw; this engine converts it to text, as the browser's clipboard functions do, so the guard checks exactly what the browser would write. The 7 cases now run in `npm test`.

### Antivirus

- **Microsoft Defender quarantined `tests/fixtures/commands.json`** as Trojan:PowerShell/Obfuse.HNAT!MTB when the project was unzipped on Windows. The file only holds test text that nothing runs, but it contained readable samples of disguised PowerShell, which is what Defender looks for. The samples are now stored base64-encoded and decoded in memory by the tests, and the few disguised samples written inside test code are encoded the same way. `node scripts/samples.mjs` lists them decoded and adds new ones. The extension and the Windows scripts were not flagged.

### Measured, not changed

- Copy-time cost on huge pages (B6): copying a command on a page with 1,000 paragraphs adds about 10 to 30 ms, on 20,000 paragraphs about 60 ms, and on 100,000 paragraphs about 0.2 seconds (headless Chromium, Linux). Ordinary copies are not affected, because the page is only read when the copied text looks like a command. Caching the page reading was considered and rejected: a page can change what is visible without the change being noticed in time, and a stale "no trap here" is worse than a short delay.

## v0.2.0 (22 October 2026)

This release answers an independent pre-release security review of v0.1.0, run with Perplexity. Every finding was first reproduced against v0.1.0 (the review's proof-of-concept pages are now part of the test suite, in `tests/fixtures/pages/review/`), then fixed with a test that failed before the fix. IDs refer to the review.

### Protection

- **Pause instead of a gentle note (A1).** In v0.1, a command that downloads and runs something, with no other sign of an attack, only got a corner note and stayed on the clipboard. Now, when a page's own code copies such a command, the clipboard gets a harmless "PAUSED" message and a panel offers **Copy anyway** and **Always allow on this site**. Copies you make by hand are not paused.
- **Connecting the dots in a tab.** A paused copy plus trap instructions anywhere in the tab, including in another frame, before the copy or up to 20 seconds after, becomes a full block warning.
- **Private channel (A10, C1).** The clipboard guard now talks to the rest of the extension through a node inside a closed shadow root that the page cannot reach. Pages can no longer silence warnings, flood them, or forge a full-screen warning with their own text.
- **No second look at the text (A2).** Text is converted once and the same string is checked and written, so a page cannot show one thing to the check and another to the browser.
- **`clipboardData.items.add` is guarded (A3)**, plus a final check at the end of every copy event.
- **Tamper-proof engine (A4).** The engine no longer uses arrays or objects a page can poison. Results are stored with `defineProperty` on prototype-free objects, and disguise removal no longer uses `String.replace`, which a page could override.
- **New attack shapes (A5 to A9):** `%ComSpec%`, commands built from `%var:~x,y%` pieces, 8.3 short names like `POWERS~1.EXE`, downloads into the Startup folder, scripts opened from WebDAV shares, every abbreviation of `-EncodedCommand` and `-WindowStyle Hidden`, `/` parameters, Unicode dashes and curly quotes, the `-f` format trick, dynamic invocation, comment-line padding, and Mac download, `chmod +x` and run chains.
- **Better trap-page reading:** text in closed shadow roots and CSS `::before`/`::after`, instructions split over several page elements, more ways of writing Win+R and Ctrl+V, and a few other languages.
- **Hook looks native (A11)** to a simple `toString()` check. This is a cat-and-mouse game; see Limitations.
- `clipboard.write` now calls the browser straight away, so slow, promise-based clipboard items keep working (B7).

### Fewer false alarms

- A "press Win+R, paste" tutorial no longer triggers a full block; installers copied there are paused (B1).
- Hidden page text ignores `<script>`, `<style>`, `<template>`, `<noscript>` and `<textarea>`, and can only lead to a pause, never a block (B2).
- The fake-CAPTCHA comment rule now needs CAPTCHA wording ("I am not a robot", "Verification ID", "Ray ID"...), not just "verify", "identity" or "human" (B3).
- Installers copied inside an embedded frame are paused, not blocked (B4).
- Internal file shares (single-label names, private addresses, `.local`/`.corp`...) no longer count as suspicious (B5). A bare IP address no longer counts as a download.
- Pages that only pass on the text you selected (like online editors) are not treated as swapping your copy.

### Extension UI

- The trap banner shows even when another warning is open (C2).
- Settings are changed in one place, so two tabs cannot undo each other's choices (C3).
- Page text shown in a warning has phone numbers removed and links broken.
- The popup lists sites you allowed, with a Remove button.

### Windows scripts

- Run keys named like `PSUpdater` are no longer skipped (D1).
- Installer events are read by field number, so they work in every Windows language, and failed installs are not reported (D2).
- Matching is culture-invariant (D3).
- The new-file scan goes one level deeper, avoids duplicates, adds `.wsf`, `.cpl`, `.msc` and Temp `.dll` files, skips the Recent folder, and does not hash files over 200 MB (D4).
- One broken shortcut, or Windows Script Host being switched off, no longer hides the rest of the Startup check (D5).
- `Protect-RunDialog.ps1` never re-cases existing `DisabledHotkeys` letters, saves the previous value and restores it exactly, asks before restarting File Explorer, and waits for Windows to restart it (D6). It now says what it does not stop (D7).

### Recovery guide

Every step was re-checked against the official help pages, and links were added (E1 to E10): Google's password-change exceptions, Microsoft's Xbox exception, Facebook's "Select all, Log out", where WhatsApp's Linked devices live, Telegram's rule about newly connected devices, Discord's "change your password first", the new Aadhaar app, and free yearly credit reports in India. One suggested correction (E7, the Defender offline scan label and duration) was checked and not applied: Microsoft's current documentation matches the original wording.

## v0.1.0 (22 October 2026)

First version: browser extension, read-only Windows PC check, Win+R switch and recovery guide.
