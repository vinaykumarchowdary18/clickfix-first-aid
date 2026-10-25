# Chrome Web Store listing

Everything needed to publish ClickFix First Aid in the Chrome Web Store, field by field. The screenshots were made from the project's own safe demo page and a made-up example page, with the real extension running.

Google's rules can change. Where this page and the developer dashboard disagree, the dashboard wins.

## Before you start

- A Google account used only for publishing, with 2-Step Verification turned on. The Chrome Web Store requires 2-Step Verification for every developer account.
- Registration in the Chrome Web Store Developer Dashboard, with the one-time registration fee paid.

## Package

Upload `clickfix-first-aid-extension-vX.Y.Z.zip` from the [latest release](https://github.com/vinaykumarchowdary18/clickfix-first-aid/releases/latest). The name and the short summary (the manifest description, at most 132 characters) come from the zip.

## Store listing

**Description** (paste as it is):

```
ClickFix First Aid protects you from "ClickFix" attacks: fake "I'm not a robot" or "verify you are human" pages that secretly copy a command to your clipboard, then tell you to paste it into the Windows Run box (Win+R), Terminal or PowerShell. Running that command can install malware that steals your saved passwords and sign-ins.

What it does:
• Blocks the attack. When a trap page puts a known attack command on your clipboard, the extension replaces it with a harmless message and explains what happened.
• Spots trap pages. Pages showing fake "press Win+R, then paste" steps get a warning banner.
• Pauses risky copies. When a page's own code copies a command that downloads and runs a program, the copy is paused so you can check it first. Real installers still work: choose Copy anyway, or Always allow on that site.
• Check a command. Paste any command a site gave you into the popup and see what the rules say about it, without running it.
• Recovery guide. If you already ran something, a step-by-step guide built into the extension tells you what to do first.

Privacy: nothing leaves your browser. The extension has no server, no account, no analytics and no network access. Copied text and page text are checked on your computer. It keeps only its counters, the last 20 warnings, your settings and the sites you allowed, all inside your browser.

Free and open source (MIT license): https://github.com/vinaykumarchowdary18/clickfix-first-aid

No tool catches every attack. A real "I'm not a robot" check never asks you to run anything.
```

- **Category:** Privacy & Security
- **Language:** English
- **Store icon (128x128):** `extension/icons/icon-128.png`
- **Screenshots (1280x800, in this order):**
  1. `1-blocks-fake-captcha.png`
  2. `2-pauses-install-commands.png`
  3. `3-check-a-command.png`
  4. `4-recovery-guide.png`
  5. `5-nothing-leaves-your-browser.png`
- **Small promo tile (440x280):** `small-promo-tile-440x280.png`
- **Marquee promo tile (1400x560):** `marquee-promo-tile-1400x560.png`
- **YouTube video:** the project video's link, once it is uploaded.
- **Homepage URL:** `https://vinaykumarchowdary18.github.io/clickfix-first-aid/` (works once GitHub Pages is on; until then use the repository address)
- **Support URL:** `https://github.com/vinaykumarchowdary18/clickfix-first-aid/issues`
- **Mature content:** off

## Privacy practices

**Single purpose:**

```
Protects people from ClickFix attacks: fake "I'm not a robot" pages that put a malicious command on the clipboard and tell the user to paste and run it. The extension blocks or pauses those copies, warns about trap pages, and points people who already ran a command to a recovery guide.
```

**Justification for `storage`:**

```
Stores the user's settings (whether to pause install commands, and the sites they chose to always allow), the counters and the last 20 warnings shown in the popup, and, for each open tab, whether it showed trap instructions or had a copy paused (chrome.storage.session), so warnings keep working when the background service worker restarts. Nothing is sent anywhere.
```

**Justification for host permissions** (the content scripts run on all sites):

```
ClickFix trap pages can be on any website, including hacked legitimate sites, so the extension has to guard clipboard writes on every page and frame. Its content scripts check the text a page tries to put on the clipboard, and read the page's visible text to recognise fake "press Win+R, then paste" instructions. Everything is checked locally in the browser. The extension makes no network requests and sends nothing anywhere.
```

**Remote code:** No, I am not using remote code. All code is in the package, and the extension's pages forbid network connections (`connect-src 'none'`).

**Data usage.** Tick:

- **Website content.** The extension reads page text and the text pages copy, to detect attacks. A short preview of blocked text is kept in the local warning history.
- **Web history.** The local warning history keeps the site name and time of up to 20 warnings.

Both stay on the user's computer and are never sent anywhere. Google's pages do not say clearly whether data that never leaves the computer has to be ticked. Ticking is the safe choice, because a missing tick can get a listing rejected.

Leave every other type unticked. Then tick all three statements: no selling or transferring data to third parties, no use unrelated to the single purpose, and no use for creditworthiness or lending.

**Privacy policy URL:** `https://github.com/vinaykumarchowdary18/clickfix-first-aid/blob/main/PRIVACY.md`

## Test instructions (if the dashboard asks)

```
Open https://vinaykumarchowdary18.github.io/clickfix-first-aid/demo.html and click "I'm not a robot". The page copies a harmless test command (it only prints a message). ClickFix First Aid shows a "Stop. This page tried to trick you." warning, and the clipboard holds a harmless "# STOP." message instead. No account or sign-in is needed.
```

## Distribution

- **Payments:** free
- **Visibility:** public
- **Regions:** all

## Notes

- Content scripts on all sites usually mean a closer review, which can take longer than for extensions with fewer permissions. This is not a rejection.
- After the listing is live, add its link to the README, the website and the YouTube description.
