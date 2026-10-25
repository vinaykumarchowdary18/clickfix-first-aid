# Privacy

ClickFix First Aid has no server, no account, no analytics and no network access.

## The browser extension

- Copied text is checked on your computer, at the moment it is copied, and then forgotten. The extension never reads your clipboard in the background.
- To spot trap pages, it reads the text shown on the pages you visit, on your computer, and looks for fake "press Win+R, then paste" instructions. Page text is never saved or sent anywhere. If a page looks like a trap, only that fact is kept: for the open tab, and as a "Trap page" entry with the site name in the recent events below.
- It keeps, in your browser only (`chrome.storage.local`): its counters, the last 20 events (kind, site name, and a short preview of the blocked text with links broken), your settings and the sites you allowed. **Clear history** in the popup deletes the history and counters. Removing the extension deletes everything.
- While a tab is open it remembers, in memory only (`chrome.storage.session`), whether that tab showed trap instructions or had a copy paused. This is cleared when the tab closes or reloads, and when the browser closes.
- **Check a command** in the popup runs the rules inside the popup. The text you paste is not saved or sent anywhere.
- The extension's only permission is `storage`, plus the right to run on pages, which it needs to guard the clipboard. Its own pages forbid network connections (`connect-src 'none'`).
- The recovery guide contains ordinary links to official help pages. Opening one contacts that company, under its own privacy policy.

## The Windows scripts

- `Check-ClickFix.ps1` only reads. It prints what it finds on your screen (or as JSON if you ask for it) and sends nothing anywhere. Its output can contain your own file paths and commands, so do not paste it into public bug reports.
- `Protect-RunDialog.ps1` changes one setting for your Windows user and saves the previous value so it can be restored exactly.
