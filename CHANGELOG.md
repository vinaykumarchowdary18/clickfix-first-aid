# Changelog

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
