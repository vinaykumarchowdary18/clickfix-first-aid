/* GENERATED FILE: do not edit. Run "npm run build" after changing the sources. */
// Detection engine + rules + clipboard guard, wrapped so nothing leaks into the page.
(function () {
'use strict';
var module = { exports: {} };
/*
 * ClickFix First Aid: detection engine.
 *
 * Decides whether a piece of copied text looks like a ClickFix attack command,
 * and whether a web page looks like a ClickFix lure ("press Win+R, paste, Enter").
 *
 * The same rules file (rules/clickfix-rules.json) is used by the browser
 * extension and by the Windows checker, so both make the same decisions.
 *
 * Verdicts:
 *   block - clearly an attack: replace the clipboard and show a full warning
 *   hold  - a command that downloads and runs something, with no clear sign of
 *           an attack. Copies made by a page's own code are paused, and the
 *           person can choose "Copy anyway". Copies made by hand are left alone.
 *   allow - not a command, or harmless
 *
 * This file runs in three places:
 *   1. Node.js, for the tests.
 *   2. The extension's isolated world (safe from the web page).
 *   3. The web page's own world ("MAIN" world), where it must decide before the
 *      page's copy happens. A hostile page could tamper with built-in JavaScript
 *      there (for example by putting a setter on Array.prototype[0] so that our
 *      lists silently stay empty). So this file grabs every built-in it needs
 *      the moment it loads, before any page script runs, never uses array or
 *      object methods at run time, and stores results with defineProperty.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module && module.exports) {
    module.exports = api;
  } else {
    root.CFADetector = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Built-ins captured at load time (see note above).
  var apply = Reflect.apply;
  var defineProperty = Object.defineProperty;
  var objectCreate = Object.create;
  var reExec = RegExp.prototype.exec;
  var strReplace = String.prototype.replace;
  var strSlice = String.prototype.slice;
  var _String = String;
  var _RegExp = RegExp;

  var VERSION = '0.3.0';

  function str(x) {
    return typeof x === 'string' ? x : x == null ? '' : _String(x);
  }

  // Append to an array without touching Array.prototype (immune to setters on it).
  function add(arr, value) {
    defineProperty(arr, arr.length, { value: value, writable: true, enumerable: true, configurable: true });
    return arr;
  }

  // A fresh object with own data properties only, no prototype to poison.
  function record(props) {
    var o = objectCreate(null);
    for (var k in props) {
      defineProperty(o, k, { value: props[k], writable: true, enumerable: true, configurable: true });
    }
    return o;
  }

  function exec(re, s) {
    re.lastIndex = 0;
    return apply(reExec, re, [s]);
  }

  function replace(s, re, withText) {
    return apply(strReplace, s, [re, withText]);
  }

  function slice(s, a, b) {
    return apply(strSlice, s, [a, b]);
  }

  function compileGroup(list) {
    var out = [];
    for (var i = 0; i < (list ? list.length : 0); i++) {
      var r = list[i];
      add(out, record({
        id: r.id,
        label: r.label,
        weight: typeof r.weight === 'number' ? r.weight : 0,
        re: new _RegExp(r.pattern, 'i')
      }));
    }
    return out;
  }

  // Undo simple disguises so the real words show through:
  //   c^m^d -> cmd, p`ow`er`shell -> powershell, 'pow'+'ershell' -> powershell,
  //   p""owershell -> powershell, en/em dashes -> '-', curly quotes -> ' and ".
  // Written as plain character loops on purpose: String.prototype.replace calls
  // RegExp.prototype[Symbol.replace] and .exec, which a page could override to
  // switch this step off.
  var UNIFY = objectCreate(null);
  UNIFY['\u2010'] = '-'; UNIFY['\u2011'] = '-'; UNIFY['\u2012'] = '-'; UNIFY['\u2013'] = '-';
  UNIFY['\u2014'] = '-'; UNIFY['\u2015'] = '-'; UNIFY['\u2212'] = '-';
  UNIFY['\u2018'] = "'"; UNIFY['\u2019'] = "'"; UNIFY['\u201a'] = "'"; UNIFY['\u201b'] = "'";
  UNIFY['\u201c'] = '"'; UNIFY['\u201d'] = '"'; UNIFY['\u201e'] = '"'; UNIFY['\u201f'] = '"';
  var SPACE = objectCreate(null);
  SPACE[' '] = 1; SPACE['\t'] = 1; SPACE['\r'] = 1; SPACE['\n'] = 1;
  var RE_LINE = /[^\r\n]+/g;
  var RE_COMMENT_LINE = /^\s*(?:#|::|rem\b|$)/i;
  var RE_DEFANG = /\b(h)(tt)(ps?):\/\//gi;

  function unify(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      var u = UNIFY[c];
      out += u === undefined ? c : u;
    }
    return out;
  }

  function normalize(s) {
    var out = '';
    var n = s.length;
    for (var i = 0; i < n; i++) {
      var c = s[i];
      if (c === '^' || c === '`') continue;
      if (c === '"' && s[i + 1] === '"') { i++; continue; }
      if (c === "'" || c === '"') {
        // 'pow' + 'ershell': skip quote, spaces, '+', spaces, same quote
        var j = i + 1;
        while (j < n && SPACE[s[j]] === 1) j++;
        if (s[j] === '+') {
          j++;
          while (j < n && SPACE[s[j]] === 1) j++;
          if (s[j] === c) { i = j; continue; }
        }
      }
      out += c;
    }
    return out;
  }

  // Lines that actually do something: not empty, not comments. Padding a
  // command with "#" lines must not make it look like a long, harmless script.
  function countCodeLines(s) {
    var n = 0;
    var m;
    RE_LINE.lastIndex = 0;
    while ((m = apply(reExec, RE_LINE, [s])) !== null) {
      if (!exec(RE_COMMENT_LINE, m[0])) n++;
    }
    RE_LINE.lastIndex = 0;
    return n;
  }

  function matchGroup(group, s, into, seen) {
    for (var i = 0; i < group.length; i++) {
      var r = group[i];
      if (seen && seen[r.id]) continue;
      var m = exec(r.re, s);
      if (m) {
        if (seen) seen[r.id] = true;
        add(into, record({ id: r.id, label: r.label, weight: r.weight, match: slice(m[0], 0, 120) }));
      }
    }
    return into;
  }

  function pushLabels(out, list, max) {
    var n = 0;
    for (var i = 0; i < list.length && n < (max || 99); i++, n++) pushUnique(out, list[i].label);
    return out;
  }

  function pushUnique(arr, item) {
    for (var j = 0; j < arr.length; j++) if (arr[j] === item) return arr;
    return add(arr, item);
  }

  function createDetector(rules) {
    if (!rules || !rules.command || !rules.page) throw new Error('ClickFix First Aid: rules missing');
    var limits = rules.limits || {};
    var maxChars = limits.maxChars || 200000;
    var maxLines = limits.maxLinesForAutoBlock || 5;
    var stealthBlockAt = (rules.verdict && rules.verdict.stealthBlockAt) || 25;
    var stealthOnlyBlockAt = (rules.verdict && rules.verdict.stealthOnlyBlockAt) || 50;

    var G = record({
      executors: compileGroup(rules.command.executors),
      remote: compileGroup(rules.command.remote),
      encoded: compileGroup(rules.command.encoded),
      stealth: compileGroup(rules.command.stealth),
      decoys: compileGroup(rules.command.decoys),
      runShortcut: compileGroup(rules.page.runShortcut),
      paste: compileGroup(rules.page.paste),
      verifyTheme: compileGroup(rules.page.verifyTheme)
    });

    function analyzeCommand(text) {
      var raw = str(text);
      var fullLength = raw.length;
      if (raw.length > maxChars) raw = slice(raw, 0, maxChars);
      var uni = unify(raw);
      var norm = normalize(uni);

      var executors = matchGroup(G.executors, norm, [], null);
      var remote = matchGroup(G.remote, norm, [], null);
      var encoded = matchGroup(G.encoded, uni, [], null);
      var seen = objectCreate(null);
      var stealth = matchGroup(G.stealth, uni, [], seen);
      matchGroup(G.stealth, norm, stealth, seen);
      var decoys = matchGroup(G.decoys, uni, [], null);

      var stealthScore = 0;
      for (var i = 0; i < stealth.length; i++) stealthScore += stealth[i].weight;

      var hasExec = executors.length > 0;
      return record({
        text: raw,
        normalized: norm,
        lines: countCodeLines(raw),
        executors: executors,
        remote: remote,
        encoded: encoded,
        stealth: stealth,
        stealthScore: stealthScore,
        decoys: decoys,
        hasExec: hasExec,
        danger: hasExec && (remote.length > 0 || encoded.length > 0),
        // Longer than we check. A page could hide a command after a huge run of
        // blank lines, so text like this is never simply allowed.
        truncated: fullLength > maxChars,
        length: fullLength
      });
    }

    // Page text: line breaks between page elements are just spaces here, so
    // "Press <div>Windows</div><div>+ R</div>" still reads as "Press Windows + R".
    function collapseSpaces(s) {
      var out = '';
      var pending = false;
      for (var i = 0; i < s.length; i++) {
        var c = s[i];
        if (SPACE[c] === 1 || c === '\u00a0' || c === '\f' || c === '\v') {
          pending = out !== '';
          continue;
        }
        if (pending) out += ' ';
        pending = false;
        out += c;
      }
      return out;
    }

    function analyzePage(text) {
      var s = str(text);
      if (s.length > 200000) s = slice(s, 0, 200000);
      s = collapseSpaces(unify(s));
      var runShortcut = matchGroup(G.runShortcut, s, [], null);
      var paste = matchGroup(G.paste, s, [], null);
      var verifyTheme = matchGroup(G.verifyTheme, s, [], null);
      var weak = runShortcut.length > 0 && paste.length > 0;
      return record({
        runShortcut: runShortcut,
        paste: paste,
        verifyTheme: verifyTheme,
        weak: weak,
        strong: weak && verifyTheme.length > 0
      });
    }

    function verdict(v, rule, reasons) {
      return record({ verdict: v, rule: rule, reasons: reasons });
    }

    // page: result of analyzePage (or null). Only page.strong can block.
    // opts.subframe: the copy came from a frame embedded in the page.
    function decide(cmd, page, opts) {
      var d = decideChecked(cmd, page, opts);
      if (cmd && cmd.truncated && d.verdict === 'allow') {
        add(d.reasons, 'Too long to check completely (over ' + maxChars + ' characters)');
        return verdict('hold', 'too-long', d.reasons);
      }
      return d;
    }

    function decideChecked(cmd, page, opts) {
      var reasons = [];
      if (!cmd) return verdict('allow', '', reasons);
      var subframe = !!(opts && opts.subframe);
      var hasRemote = cmd.remote.length > 0;
      var why = [];
      pushLabels(why, cmd.executors, 2);
      if (hasRemote) pushLabels(why, cmd.remote, 1);
      if (cmd.encoded.length) pushLabels(why, cmd.encoded, 1);

      // 1. Fake "I am not a robot" text hidden after a real command.
      if (cmd.hasExec && cmd.decoys.length) {
        pushLabels(reasons, cmd.decoys);
        for (var a = 0; a < why.length; a++) pushUnique(reasons, why[a]);
        pushLabels(reasons, cmd.stealth);
        return verdict('block', 'decoy', reasons);
      }

      // 2. The page itself is a trap ("verify you are human", Win+R, paste).
      if (page && page.strong && (cmd.hasExec || hasRemote || cmd.stealthScore >= stealthBlockAt)) {
        add(reasons, 'The page tells you to paste it into Run, Terminal or File Explorer to "verify" something');
        for (var b = 0; b < why.length; b++) pushUnique(reasons, why[b]);
        pushLabels(reasons, cmd.stealth);
        return verdict('block', 'lure-page', reasons);
      }

      if (!cmd.hasExec) return verdict('allow', '', reasons);

      var longScript = cmd.lines > maxLines;

      // 3. Downloads and runs something, and tries to hide it.
      if (cmd.danger && cmd.stealthScore >= stealthBlockAt) {
        for (var c = 0; c < why.length; c++) pushUnique(reasons, why[c]);
        pushLabels(reasons, cmd.stealth);
        return verdict(longScript ? 'hold' : 'block', longScript ? 'stealthy-long-script' : 'stealthy-download-and-run', reasons);
      }

      // 4. No download seen, but heavily disguised.
      if (cmd.stealthScore >= stealthOnlyBlockAt) {
        for (var e = 0; e < why.length; e++) pushUnique(reasons, why[e]);
        pushLabels(reasons, cmd.stealth);
        return verdict(longScript ? 'hold' : 'block', 'heavily-disguised', reasons);
      }

      // 5. Downloads and runs something: pause it. Never a full block on its own,
      //    because this is also how real installers look.
      if (cmd.danger) {
        if (page && page.weak) add(reasons, 'The page mentions Win+R and pasting');
        if (subframe) add(reasons, 'Copied from inside a frame embedded in the page');
        for (var f = 0; f < why.length; f++) pushUnique(reasons, why[f]);
        pushLabels(reasons, cmd.stealth);
        return verdict('hold', page && page.weak ? 'lure-like-page' : subframe ? 'frame' : 'download-and-run', reasons);
      }

      return verdict('allow', '', reasons);
    }

    // Is there anything here worth a closer look? The guard skips text without
    // any of these, and the extension's isolated world uses the same test to
    // ignore any report whose text has none of them.
    function worthChecking(cmd) {
      return !!cmd && (cmd.truncated || cmd.hasExec || cmd.remote.length > 0 || cmd.encoded.length > 0);
    }

    // Undo dashes, curly quotes and simple disguises, as the checks see it.
    function normalizeText(text) {
      return normalize(unify(str(text)));
    }

    function check(text, pageText, opts) {
      var cmd = analyzeCommand(text);
      var page = pageText == null ? null : analyzePage(pageText);
      var d = decide(cmd, page, opts);
      d.command = cmd;
      d.page = page;
      return d;
    }

    return record({
      analyzeCommand: analyzeCommand,
      analyzePage: analyzePage,
      decide: decide,
      worthChecking: worthChecking,
      normalize: normalizeText,
      check: check
    });
  }

  // Make a command safe to display: breaks web links so nobody clicks them.
  function defang(text, maxLen) {
    var s = str(text);
    var limit = maxLen || 400;
    if (s.length > limit) s = slice(s, 0, limit) + ' ...';
    return replace(s, RE_DEFANG, '$1xx$3[://]');
  }

  return { createDetector: createDetector, defang: defang, version: VERSION };
});

var CFADetectorAPI = module.exports;
var CFA_RULES = {"name":"clickfix-first-aid-rules","version":"2.1.0","updated":"2026-10-25","notes":"Patterns must work in both JavaScript and .NET regex engines. All patterns are matched case-insensitively.","limits":{"maxChars":200000,"maxLinesForAutoBlock":5},"command":{"executors":[{"id":"powershell","label":"Starts PowerShell","pattern":"\\b(?:powershell|pwsh)(?:\\.exe)?\\b"},{"id":"cmd","label":"Starts the Windows command prompt","pattern":"\\bcmd(?:\\.exe)?\\s*/[ckr]\\b|\\bcmd\\.exe\\b"},{"id":"mshta","label":"Uses mshta, a Windows tool attackers use to run web code","pattern":"\\bmshta(?:\\.exe)?\\b"},{"id":"msiexec","label":"Runs a Windows installer","pattern":"\\bmsiexec(?:\\.exe)?\\b"},{"id":"rundll32","label":"Uses rundll32 to load a program library","pattern":"\\brundll32(?:\\.exe)?\\b"},{"id":"regsvr32","label":"Uses regsvr32 to load a program library","pattern":"\\bregsvr32(?:\\.exe)?\\b"},{"id":"script-host","label":"Runs a Windows script file","pattern":"\\b[wc]script(?:\\.exe)?\\b"},{"id":"certutil","label":"Uses certutil, often abused to download files","pattern":"\\bcertutil(?:\\.exe)?\\b"},{"id":"bitsadmin","label":"Uses bitsadmin, often abused to download files","pattern":"\\bbitsadmin(?:\\.exe)?\\b"},{"id":"conhost","label":"Starts a hidden console window","pattern":"\\bconhost(?:\\.exe)?\\b"},{"id":"finger","label":"Uses the finger tool to fetch commands from a server","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"dotnet-lolbin","label":"Uses a .NET build tool to run code","pattern":"\\b(?:msbuild|installutil|regasm|regsvcs)(?:\\.exe)?\\b"},{"id":"schtasks","label":"Creates a scheduled task","pattern":"\\bschtasks(?:\\.exe)?\\b"},{"id":"invoke-expression","label":"Runs text as code (Invoke-Expression)","pattern":"\\b(?:iex|invoke-expression)\\b"},{"id":"osascript","label":"Runs an AppleScript on a Mac","pattern":"\\bosascript\\b"},{"id":"pipe-to-shell","label":"Pipes downloaded text straight into a shell","pattern":"\\|\\s*(?:sudo\\s+)?(?:ba|z|da)?sh\\b"},{"id":"shell-c","label":"Runs a shell command string","pattern":"\\b(?:ba|z)?sh\\s+-c\\b"},{"id":"comspec","label":"Starts the command prompt through the %ComSpec% variable","pattern":"%comspec%"},{"id":"env-built-command","label":"Builds a program name from pieces of a system variable","pattern":"%[a-z_]+:~-?\\d+,-?\\d+%[a-z]"},{"id":"short-name","label":"Uses a hidden short file name (like POWERS~1.EXE) to start a program","pattern":"\\b[a-z0-9]{1,6}~\\d(?:\\.exe)?\\b"},{"id":"autostart-write","label":"Puts a file where Windows starts it automatically","pattern":"start\\s*menu\\\\programs\\\\startup|\\\\currentversion\\\\run(?:once)?\\b|shell:startup|shell:common\\s*startup"},{"id":"remote-script","label":"Opens a program or script straight from a remote server","pattern":"\\\\\\\\[^\\s\\\"'\\\\]{1,253}(?:\\\\[^\\s\\\"'\\\\]{1,255}){0,31}\\.(?:hta|exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|scr|dll|lnk|msi|cpl)\\b"},{"id":"dynamic-invoke","label":"Calls a PowerShell command by building its name at run time","pattern":"(?:^|[\\s;(\\\"'])[&.]\\s*\\(|\\[scriptblock\\]::create|\\$executioncontext|\\binvoke(?:command|script)\\b|\\b(?:gcm|gal|get-command|get-alias)\\s+\\S*\\*"},{"id":"chmod-x","label":"Makes a downloaded file runnable (Mac/Linux)","pattern":"\\bchmod\\s+(?:\\+x|[0-7]?7[0-7]{2})\\b"},{"id":"run-local-file","label":"Runs a file it just saved","pattern":"(?:&&|;|\\|\\|)\\s*\\./[\\w.-]+"},{"id":"process-substitution","label":"Runs a script downloaded on the fly","pattern":"\\b(?:ba|z)?sh\\s+<\\("},{"id":"python-download","label":"Uses Python to download and run code","pattern":"\\bpython3?\\s+-c\\b[^\\n]*(?:urlopen|urllib|requests\\.get)"}],"remote":[{"id":"url","label":"Contains a web address","pattern":"\\b(?:https?|ftp)://[^\\s\"'<>]+"},{"id":"unc-path","label":"Loads a file from a remote network share","pattern":"\\\\\\\\[a-z0-9._-]+(?:@ssl)?(?:@\\d+)?\\\\"},{"id":"downloader","label":"Downloads something from the internet","pattern":"\\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadstring|downloadfile|downloaddata|net\\.webclient|curl(?:\\.exe)?|wget(?:\\.exe)?)\\b"},{"id":"finger-host","label":"Asks a remote server for commands (finger)","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"bare-domain","label":"Contains an unusual web domain","pattern":"(?<![a-z0-9-])[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63}){0,10}\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\\\"']|$)"},{"id":"bare-host-path","label":"Contains a web address","pattern":"(?<![a-z0-9-])[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63}){0,10}\\.[a-z]{2,24}/[^\\s\\\"'<>]+"}],"encoded":[{"id":"ps-encoded","label":"Hides its real instructions in encoded text","pattern":"(?:^|\\s)[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\\s+[a-z0-9+/=]{16,}"},{"id":"from-base64","label":"Decodes hidden text before running it","pattern":"frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b|\\batob\\("},{"id":"long-base64","label":"Contains a long block of encoded text","pattern":"[a-z0-9+/]{120,}={0,2}"}],"stealth":[{"id":"hidden-window","label":"Hides its window so you cannot see it running","weight":25,"pattern":"(?:^|\\s)[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\\s+(?:h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?|1)\\b"},{"id":"policy-bypass","label":"Turns off PowerShell safety settings","weight":10,"pattern":"(?:^|\\s)[-/](?:nop\\w*|noni\\w*|ep\\s+bypass|ex\\w*\\s+bypass)\\b"},{"id":"encoded","label":"Hides its real instructions in encoded text","weight":30,"pattern":"(?:^|\\s)[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\\s+[a-z0-9+/=]{16,}|frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b"},{"id":"caret-obfuscation","label":"Disguised with ^ symbols to dodge antivirus","weight":25,"pattern":"\\w\\^\\w\\^?\\w"},{"id":"backtick-obfuscation","label":"Disguised with ` symbols to dodge antivirus","weight":20,"pattern":"[a-z]`[a-z]+`[a-z]"},{"id":"string-splitting","label":"Splits words apart to dodge antivirus","weight":15,"pattern":"['\"]\\s*\\+\\s*['\"]"},{"id":"env-substring","label":"Builds words from pieces of system variables","weight":25,"pattern":"%[a-z_]+:~-?\\d+,-?\\d+%"},{"id":"headless-console","label":"Runs in an invisible console","weight":25,"pattern":"\\bconhost(?:\\.exe)?\\s+--headless"},{"id":"temp-drop","label":"Saves a file into a temporary or app-data folder","weight":10,"pattern":"%temp%|\\$env:temp|%appdata%|\\$env:appdata|%localappdata%|\\$env:localappdata|%programdata%|\\\\appdata\\\\|/tmp/"},{"id":"quiet-install","label":"Installs a program silently, without asking you","weight":20,"pattern":"\\bmsiexec(?:\\.exe)?\\b[^\\n]*\\s/q[nb]?\\b"},{"id":"start-minimized","label":"Starts minimized so you do not notice it","weight":15,"pattern":"\\bstart\\s+(?:\"\"\\s+)?/min\\b"},{"id":"raw-ip","label":"Connects to a raw IP address instead of a website name","weight":20,"pattern":"(?:https?://|\\\\\\\\|@)(?!(?:10|127)\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)\\d{1,3}(?:\\.\\d{1,3}){3}\\b"},{"id":"suspicious-domain","label":"Uses a cheap web domain popular with attackers","weight":15,"pattern":"(?<![a-z0-9-])[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63}){0,10}\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\\\"']|$)"},{"id":"remote-share","label":"Runs code from a server on the internet through a network share","weight":25,"pattern":"\\\\\\\\(?!(?:10|127)\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)(?![^\\\\\\s]*\\.(?:local|lan|corp|internal|intranet|home|localdomain)(?:@|\\\\))(?:[a-z0-9-]+\\.[a-z0-9.-]*[a-z0-9]|\\d{1,3}(?:\\.\\d{1,3}){3})(?:@ssl)?(?:@\\d+)?\\\\|@ssl\\\\|\\\\davwwwroot\\\\"},{"id":"pipe-to-cmd","label":"Feeds downloaded text straight into the command prompt","weight":20,"pattern":"\\|\\s*cmd(?:\\.exe)?\\b"},{"id":"space-padding","label":"Pads the command with spaces to hide part of it","weight":25,"pattern":"\\S {25,}\\S"},{"id":"comspec-variable","label":"Hides the command prompt behind the %ComSpec% variable","weight":15,"pattern":"%comspec%"},{"id":"env-built-command","label":"Builds a program name from pieces of a system variable","weight":50,"pattern":"%[a-z_]+:~-?\\d+,-?\\d+%[a-z]"},{"id":"autostart","label":"Makes something start every time you sign in","weight":30,"pattern":"start\\s*menu\\\\programs\\\\startup|\\\\currentversion\\\\run(?:once)?\\b|shell:startup|shell:common\\s*startup"},{"id":"download-then-run","label":"Runs the file straight after downloading it","weight":20,"pattern":"(?:&&|;|\\|\\|)\\s*(?:start\\s+(?:\\\"\\\"\\s+)?(?:/min\\s+)?)?\\\"?(?:%(?:temp|tmp|appdata|localappdata|public|programdata)%|\\$env:(?:temp|tmp|appdata|localappdata|public|programdata))[^\\s\\\"]*\\.(?:hta|exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|scr|dll|lnk|msi|cpl)\\b"},{"id":"format-operator","label":"Scrambles words with the -f format trick to dodge antivirus","weight":20,"pattern":"\\{\\d\\}\\{\\d\\}[^\\n]{0,20}?-f\\b"},{"id":"dynamic-invoke","label":"Calls a command by building its name at run time","weight":15,"pattern":"(?:^|[\\s;(\\\"'])[&.]\\s*\\(|\\[scriptblock\\]::create|\\$executioncontext|\\binvoke(?:command|script)\\b|\\b(?:gcm|gal|get-command|get-alias)\\s+\\S*\\*"},{"id":"short-name","label":"Hides the program name behind a short file name","weight":15,"pattern":"\\b[a-z0-9]{1,6}~\\d(?:\\.exe)?\\b"},{"id":"quarantine-removal","label":"Removes the Mac's downloaded-file safety check","weight":25,"pattern":"\\bxattr\\s+-[a-z]*c[a-z]*\\b|\\bxattr\\s+-[a-z]*d[a-z]*\\s+com\\.apple\\.quarantine"},{"id":"chmod-run","label":"Downloads, makes runnable and runs a file in one go","weight":25,"pattern":"\\bchmod\\s+(?:\\+x|[0-7]?7[0-7]{2})\\b[^\\n]*(?:&&|;)\\s*\\./"}],"decoys":[{"id":"fake-verification-comment","label":"Hides fake \"I am not a robot\" text after the real command","pattern":"(?:#|::|\\brem\\b)(?:(?!#|::)[^\\n]){0,200}?(?:\\brobot\\b|captcha|\\bray\\s*id\\b|verification\\s*(?:id|code)\\b|human\\s*verification|\\bi\\s*am\\s*(?:a\\s+)?human\\b|cloudflare\\s+(?:ray|verification|human|security|check)|\\u2705|\\u2714)"},{"id":"fake-file-path","label":"Disguises the command as a file path (FileFix trick)","pattern":"#\\s*[a-z]:\\\\[^\\n]*\\.(?:docx?|pdf|xlsx?|pptx?|txt|csv)\\b"}]},"page":{"runShortcut":[{"id":"win-r","label":"Tells you to press Windows + R","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,40}?(?:\\+|\\band\\b|&|\\bthen\\b|\\btap\\b|\\bpress\\b)\\s*(?:the\\s+)?[\\[(\\\"'\\u201c\\u201d]?r[\\])\\\"'\\u201c\\u201d]?(?:\\s+key)?\\b"},{"id":"win-x","label":"Tells you to press Windows + X","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,40}?(?:\\+|\\band\\b|&|\\bthen\\b|\\btap\\b|\\bpress\\b)\\s*(?:the\\s+)?[\\[(\\\"'\\u201c\\u201d]?x[\\])\\\"'\\u201c\\u201d]?(?:\\s+key)?\\b"},{"id":"run-dialog","label":"Mentions the Run dialog","pattern":"\\brun\\s+(?:dialog|box|window|prompt)\\b"},{"id":"open-terminal","label":"Tells you to open a terminal","pattern":"\\bopen\\s+(?:the\\s+)?(?:powershell|windows\\s+terminal|terminal|command\\s+prompt)\\b"},{"id":"explorer-address-bar","label":"Tells you to paste into File Explorer (FileFix)","pattern":"file\\s*explorer[^\\n]{0,120}?address\\s*bar|address\\s*bar[^\\n]{0,120}?file\\s*explorer|\\bctrl\\s*\\+\\s*l\\b"},{"id":"mac-terminal","label":"Tells you to open Terminal on a Mac","pattern":"(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*space\\b"}],"paste":[{"id":"paste","label":"Tells you to paste","pattern":"\\b(?:ctrl|strg)\\b[^\\n]{0,20}?(?:\\+|\\band\\b|&|\\bthen\\b|\\btap\\b|\\bpress\\b)\\s*(?:the\\s+)?[\\[(\\\"'\\u201c\\u201d]?v\\b|(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*v\\b|\\bpaste\\b|\\bpega\\b|\\bcoller\\b|\\beinf\\u00fcgen\\b|\\bincolla\\b"}],"verifyTheme":[{"id":"verify","label":"Pretends to be a human or security check","pattern":"\\bverif(?:y|ication)\\b|captcha|\\bi\\s*(?:'|\\u2019)?\\s*a?m\\s+not\\s+a\\s+robot\\b|\\bare\\s+you\\s+(?:a\\s+)?human\\b|\\bhuman\\s+check\\b|cloudflare|turnstile|\\bsecurity\\s+check\\b|\\bray\\s+id\\b|\\bprove\\s+you\\b|verificaci|verifica\\u00e7|v\\u00e9rif|verifizier|best\\u00e4tig|\\bverifica\\b|no\\s+soy\\s+un\\s+robot|n\\u00e3o\\s+sou\\s+um\\s+rob|je\\s+ne\\s+suis\\s+pas\\s+un\\s+robot|ich\\s+bin\\s+kein\\s+roboter"},{"id":"fake-fix","label":"Pretends you need to fix an error","pattern":"\\bfix\\s+(?:the\\s+|this\\s+)?(?:error|issue|problem)\\b|\\bupdate\\s+your\\s+browser\\b|\\bbrowser\\s+update\\b|\\bfailed\\s+to\\s+load\\b"}]},"verdict":{"stealthBlockAt":25,"stealthOnlyBlockAt":50}};
/*
 * ClickFix First Aid: clipboard guard.
 *
 * Runs inside the web page's own JavaScript world ("MAIN" world), before any
 * of the page's scripts. The build wraps it together with the detection engine
 * and the rules, so these names exist here:
 *   CFADetectorAPI  - { createDetector, defang }
 *   CFA_RULES       - the rules from rules/clickfix-rules.json
 *
 * A page can put text on the clipboard in five ways. We wrap all of them:
 *   1. navigator.clipboard.writeText(text)
 *   2. navigator.clipboard.write([ClipboardItem])
 *   3. document.execCommand('copy') on a (hidden) text box
 *   4. a 'copy' handler calling event.clipboardData.setData(...)
 *   5. a 'copy' handler calling event.clipboardData.items.add(text, 'text/plain')
 *
 * Verdict "block": the clipboard gets SAFE_TEXT and a full warning is shown.
 * Verdict "hold":  copies made by the page's own code get HOLD_TEXT, and the
 *                  person can choose "Copy anyway". Copies made by hand pass.
 *
 * Talking to the rest of the extension: we create an element with a CLOSED
 * shadow root and send reports as events on a node inside it. The page cannot
 * reach that node, so it can neither listen in, nor block the reports, nor fake
 * them. The extension's isolated world opens the closed root with
 * chrome.dom.openOrClosedShadowRoot and then removes the element from the page.
 */

var detector = CFADetectorAPI.createDetector(CFA_RULES);

// ---- Built-ins, grabbed before the page can replace them. -------------------
var apply = Reflect.apply;
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var objectCreate = Object.create;
var getPrototypeOf = Object.getPrototypeOf;
var _String = String;
var _CustomEvent = CustomEvent;
var _dispatchEvent = EventTarget.prototype.dispatchEvent;
var _addEventListener = EventTarget.prototype.addEventListener;
var _preventDefault = Event.prototype.preventDefault;
var _toLowerCase = String.prototype.toLowerCase;
var _slice = String.prototype.slice;
var _indexOf = String.prototype.indexOf;
var _then = Promise.prototype.then;
var _Blob = typeof Blob !== 'undefined' ? Blob : null;
var _blobText = _Blob ? _Blob.prototype.text : null;
var _ClipboardItem = typeof ClipboardItem !== 'undefined' ? ClipboardItem : null;
var _getType = _ClipboardItem ? _ClipboardItem.prototype.getType : null;
var _typesGetter = _ClipboardItem ? (getOwnPropertyDescriptor(_ClipboardItem.prototype, 'types') || {}).get : null;
var _Clipboard = typeof Clipboard !== 'undefined' ? Clipboard : null;
var _writeText = _Clipboard ? _Clipboard.prototype.writeText : null;
var _write = _Clipboard ? _Clipboard.prototype.write : null;
var _execCommand = Document.prototype.execCommand;
var _DataTransfer = typeof DataTransfer !== 'undefined' ? DataTransfer : null;
var _setData = _DataTransfer ? _DataTransfer.prototype.setData : null;
var _getData = _DataTransfer ? _DataTransfer.prototype.getData : null;
var _clipboardDataGetter = typeof ClipboardEvent !== 'undefined' ? (getOwnPropertyDescriptor(ClipboardEvent.prototype, 'clipboardData') || {}).get : null;
var _ItemList = typeof DataTransferItemList !== 'undefined' ? DataTransferItemList : null;
var _itemsAdd = _ItemList ? _ItemList.prototype.add : null;
var _createElement = Document.prototype.createElement;
var _attachShadow = Element.prototype.attachShadow;
var _appendChild = Node.prototype.appendChild;
var _documentElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'documentElement') || {}).get;
var _bodyGetter = (getOwnPropertyDescriptor(Document.prototype, 'body') || {}).get;
var _activeElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'activeElement') || {}).get;
var _innerTextGetter = (getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText') || {}).get;
var _nodeValueGetter = (getOwnPropertyDescriptor(Node.prototype, 'nodeValue') || {}).get;
var _parentNodeGetter = (getOwnPropertyDescriptor(Node.prototype, 'parentNode') || {}).get;
var _nodeNameGetter = (getOwnPropertyDescriptor(Node.prototype, 'nodeName') || {}).get;
var _createTreeWalker = Document.prototype.createTreeWalker;
var _nextNode = typeof TreeWalker !== 'undefined' ? TreeWalker.prototype.nextNode : null;
var _detailGetter = (getOwnPropertyDescriptor(CustomEvent.prototype, 'detail') || {}).get;
var _getSelection = window.getSelection;
var _selectionToString = typeof Selection !== 'undefined' ? Selection.prototype.toString : null;
var _taProto = HTMLTextAreaElement.prototype;
var _inProto = HTMLInputElement.prototype;
var _taValue = (getOwnPropertyDescriptor(_taProto, 'value') || {}).get;
var _inValue = (getOwnPropertyDescriptor(_inProto, 'value') || {}).get;
var _taStart = (getOwnPropertyDescriptor(_taProto, 'selectionStart') || {}).get;
var _taEnd = (getOwnPropertyDescriptor(_taProto, 'selectionEnd') || {}).get;
var _inStart = (getOwnPropertyDescriptor(_inProto, 'selectionStart') || {}).get;
var _inEnd = (getOwnPropertyDescriptor(_inProto, 'selectionEnd') || {}).get;

// What goes on the clipboard instead of the command. Both are harmless if
// pasted anywhere: they start with '#' (a comment in PowerShell and bash; in
// the Run box, cmd, File Explorer or zsh they just fail with "not found"), and
// they contain no quotes, pipes, ampersands, dollar signs or redirects.
var SAFE_TEXT = '# STOP. ClickFix First Aid blocked this. A website tried to trick you into running a command on your computer. Close that page. Real human checks never ask you to paste anything.';
var HOLD_TEXT = '# PAUSED. ClickFix First Aid held this copied text so you can check it first. Go back to the page and choose Copy anyway only if you trust the site.';

// Reports carry the whole text (up to this size), so "Copy anyway" copies all of it.
var MAX_SEND = 1000000;
var SEP = '\u001f';
var programmaticCopy = false;
var config = { hold: true, siteAllowed: false, quiet: false };

function s(x) {
  return typeof x === 'string' ? x : x == null ? '' : _String(x);
}

function noop() {}

function addTo(arr, v) {
  defineProperty(arr, arr.length, { value: v, writable: true, enumerable: true, configurable: true });
}

// ---- Private channel to the extension. --------------------------------------
var channel = null;
(function () {
  try {
    var root = _documentElementGetter ? apply(_documentElementGetter, document, []) : null;
    if (!root) return;
    var host = apply(_createElement, document, ['clickfix-first-aid-channel']);
    var shadow = apply(_attachShadow, host, [{ mode: 'closed' }]);
    var node = apply(_createElement, document, ['span']);
    apply(_appendChild, shadow, [node]);
    apply(_appendChild, root, [host]);
    channel = node;
    apply(_addEventListener, node, ['cfa-config', function (ev) {
      var d = s(_detailGetter ? apply(_detailGetter, ev, []) : '');
      config.hold = apply(_indexOf, d, ['hold=0']) === -1;
      config.siteAllowed = apply(_indexOf, d, ['allow=1']) !== -1;
      config.quiet = apply(_indexOf, d, ['quiet=1']) !== -1;
    }]);
  } catch (e) {
    channel = null;
  }
})();

function notify(verdict, how, text) {
  if (!channel) return;
  try {
    var detail = verdict + SEP + how + SEP + apply(_slice, text, [0, MAX_SEND]);
    apply(_dispatchEvent, channel, [new _CustomEvent('cfa-report', { detail: detail })]);
  } catch (e) {
    /* never break the page */
  }
}

// ---- Reading the page. ------------------------------------------------------
var isSubframe = true;
try {
  isSubframe = window.top !== window;
} catch (e) {
  isSubframe = true;
}

function body() {
  try {
    return _bodyGetter ? apply(_bodyGetter, document, []) : null;
  } catch (e) {
    return null;
  }
}

function visibleText() {
  var b = body();
  try {
    return b && _innerTextGetter ? s(apply(_innerTextGetter, b, [])) : '';
  } catch (e) {
    return '';
  }
}

// Text of hidden elements too, but not code or data (<script>, <style>,
// <textarea>...), which often mention "Ctrl+V" on perfectly normal sites.
var SKIP = objectCreate(null);
SKIP.SCRIPT = 1; SKIP.STYLE = 1; SKIP.NOSCRIPT = 1; SKIP.TEXTAREA = 1; SKIP.TEMPLATE = 1;
function hiddenText() {
  var b = body();
  if (!b || !_createTreeWalker || !_nextNode) return '';
  var out = '';
  try {
    var walker = apply(_createTreeWalker, document, [b, 4 /* NodeFilter.SHOW_TEXT */]);
    var n;
    var count = 0;
    while ((n = apply(_nextNode, walker, [])) && out.length < 200000 && count++ < 50000) {
      var p = apply(_parentNodeGetter, n, []);
      var name = p ? apply(_nodeNameGetter, p, []) : '';
      if (SKIP[name] === 1) continue;
      out += s(apply(_nodeValueGetter, n, [])) + '\n';
    }
  } catch (e) {
    /* partial text is fine */
  }
  return out;
}

// Only text the person can actually see may lead to a full block. Hidden text
// can only add "this looks like Win+R and paste" (weak), which means pausing,
// so it is only read when that could change the outcome.
function analyzeThisPage(needHidden) {
  var visible = detector.analyzePage(visibleText());
  // The project's own pages explain the attack in words; there, page text can
  // never turn a copy into a block (attack commands themselves still can).
  if (config.quiet) return { weak: visible.weak, strong: false };
  if (visible.strong) return { weak: true, strong: true };
  if (!needHidden || visible.weak) return { weak: visible.weak, strong: false };
  var hidden = detector.analyzePage(hiddenText());
  return { weak: hidden.weak, strong: false };
}

// Did the page's copy handler just pass on what the person selected (normal
// for editors like Google Docs), or did it swap in different text?
// Collapse all whitespace (plain loop: no overridable string or regex methods).
var WS = objectCreate(null); // no prototype, so a page cannot add entries to it
WS[' '] = 1; WS['\t'] = 1; WS['\r'] = 1; WS['\n'] = 1; WS['\u00a0'] = 1;
function squash(t) {
  var out = '';
  var pendingSpace = false;
  for (var i = 0; i < t.length; i++) {
    var c = t[i];
    if (WS[c] === 1) {
      pendingSpace = out !== '';
      continue;
    }
    if (pendingSpace) out += ' ';
    pendingSpace = false;
    out += c;
  }
  return out;
}
function sameAsSelection(t) {
  var sel = selectedText();
  return sel !== '' && squash(sel) === squash(t);
}

function protoChainHas(el, proto) {
  var p = el;
  for (var i = 0; i < 10 && p; i++) {
    p = getPrototypeOf(p);
    if (p === proto) return true;
  }
  return false;
}

function selectedText() {
  try {
    var el = _activeElementGetter ? apply(_activeElementGetter, document, []) : null;
    if (el) {
      var isTa = protoChainHas(el, _taProto);
      var isIn = !isTa && protoChainHas(el, _inProto);
      if (isTa || isIn) {
        var v = s(apply(isTa ? _taValue : _inValue, el, []));
        var a = apply(isTa ? _taStart : _inStart, el, []);
        var b = apply(isTa ? _taEnd : _inEnd, el, []);
        if (typeof a === 'number' && typeof b === 'number' && b > a) return apply(_slice, v, [a, b]);
      }
    }
    var sel = _getSelection ? apply(_getSelection, window, []) : null;
    return sel && _selectionToString ? s(apply(_selectionToString, sel, [])) : '';
  } catch (e) {
    return '';
  }
}

// ---- The decision. ----------------------------------------------------------
// Returns null (let it through) or 'block' | 'hold' | 'note'.
// programmatic: the page's own code is writing the text (not a person's Ctrl+C).
function evaluate(text, programmatic) {
  if (text.length < 4) return null;
  var cmd = detector.analyzeCommand(text);
  if (!detector.worthChecking(cmd)) return null;
  var d = detector.decide(cmd, analyzeThisPage(cmd.danger), { subframe: isSubframe });
  var v = d.verdict;
  if (v === 'block') return 'block';
  if (v !== 'hold' || !programmatic) return null;
  if (config.siteAllowed) return null;
  return config.hold ? 'hold' : 'note';
}

function replacementFor(verdict) {
  return verdict === 'block' ? SAFE_TEXT : HOLD_TEXT;
}

// ---- Wrapping built-in clipboard functions. -----------------------------------
// The wrappers keep the original name and argument count so pages keep working.
// They deliberately do not disguise themselves: a page that inspects them (for
// example with toString()) can see that ClickFix First Aid is guarding the
// clipboard. Hiding that would be the kind of trick malware uses, and browser
// stores rightly treat it as such. Seeing the guard does not help a page get
// past it: every copy still goes through the check.
function wrap(proto, name, fn) {
  try {
    var desc = getOwnPropertyDescriptor(proto, name);
    if (!desc || typeof desc.value !== 'function') return;
    defineProperty(fn, 'name', { value: name, configurable: true });
    defineProperty(fn, 'length', { value: desc.value.length, configurable: true });
    defineProperty(proto, name, { value: fn, writable: desc.writable, enumerable: desc.enumerable, configurable: desc.configurable });
  } catch (e) {
    /* ignore */
  }
}

// 1. navigator.clipboard.writeText. The text is converted to a string exactly
// once, so a page cannot show us one thing and give the browser another.
if (_writeText) {
  wrap(_Clipboard.prototype, 'writeText', function writeText(text) {
    var t = s(text);
    var v = evaluate(t, true);
    var p = apply(_writeText, this, [v === 'block' || v === 'hold' ? replacementFor(v) : t]);
    if (v) apply(_then, p, [function () { notify(v, 'writeText', t); }, noop]);
    return p;
  });
}

// 2. navigator.clipboard.write([ClipboardItem]). The browser call happens right
// away (so slow, promise-based items keep working); the text inside is checked
// before it is handed over.
if (_write && _ClipboardItem && _Blob && _getType && _blobText && _typesGetter) {
  wrap(_Clipboard.prototype, 'write', function write(items) {
    var self = this;
    try {
      if (!items || items.length !== 1) return apply(_write, self, arguments);
      var item = items[0];
      if (!protoChainHas(item, _ClipboardItem.prototype)) return apply(_write, self, arguments);
      var types = apply(_typesGetter, item, []);
      var hasText = false;
      for (var i = 0; i < types.length; i++) if (types[i] === 'text/plain') hasText = true;
      if (!hasText) return apply(_write, self, arguments);

      var textP = apply(_then, apply(_getType, item, ['text/plain']), [function (blob) { return apply(_blobText, blob, []); }]);
      var decisionP = apply(_then, textP, [function (t) { return { t: s(t), v: evaluate(s(t), true) }; }]);
      var map = objectCreate(null);
      for (var j = 0; j < types.length; j++) {
        (function (type) {
          defineProperty(map, type, {
            enumerable: true,
            value: apply(_then, decisionP, [function (x) {
              if (x.v === 'block' || x.v === 'hold') {
                if (type === 'text/plain' || type === 'text/html') return new _Blob([replacementFor(x.v)], { type: type });
              } else if (type === 'text/plain') {
                return new _Blob([x.t], { type: 'text/plain' });
              }
              return apply(_getType, item, [type]);
            }])
          });
        })(types[j]);
      }
      var p = apply(_write, self, [[new _ClipboardItem(map)]]);
      apply(_then, p, [function () {
        apply(_then, decisionP, [function (x) { if (x.v) notify(x.v, 'write', x.t); }, noop]);
      }, noop]);
      return p;
    } catch (e) {
      return apply(_write, self, arguments);
    }
  });
}

// 3. document.execCommand('copy'): note that the page's code started the copy;
// the 'copy' listener below does the checking.
wrap(Document.prototype, 'execCommand', function execCommand(command) {
  var c = s(command);
  var args = [c];
  for (var i = 1; i < arguments.length; i++) addTo(args, arguments[i]);
  var lower = apply(_toLowerCase, c, []);
  if (lower === 'copy' || lower === 'cut') {
    programmaticCopy = true;
    try {
      return apply(_execCommand, this, args);
    } finally {
      programmaticCopy = false;
    }
  }
  return apply(_execCommand, this, args);
});

function guardEvent(e, text, how, programmatic) {
  var v = evaluate(s(text), programmatic);
  if (!v) return;
  notify(v, how, s(text));
  if (v === 'block' || v === 'hold') {
    try {
      var cd = _clipboardDataGetter ? apply(_clipboardDataGetter, e, []) : null;
      if (cd) apply(_setData, cd, ['text/plain', replacementFor(v)]);
      apply(_preventDefault, e, []);
    } catch (x) {
      /* ignore */
    }
  }
}

// 4a. Any copy (keyboard, menu or execCommand): check what is selected.
function onCopyStart(e) {
  guardEvent(e, selectedText(), programmaticCopy ? 'execCommand' : 'copy', programmaticCopy);
}
apply(_addEventListener, window, ['copy', onCopyStart, true]);
apply(_addEventListener, window, ['cut', onCopyStart, true]);

// 4b. Last look at the end of the copy event, in case something slipped in.
function onCopyEnd(e) {
  try {
    var cd = _clipboardDataGetter ? apply(_clipboardDataGetter, e, []) : null;
    if (!cd || !_getData) return;
    var t = s(apply(_getData, cd, ['text/plain']));
    if (t === SAFE_TEXT || t === HOLD_TEXT || t === '') return;
    guardEvent(e, t, 'copy event', programmaticCopy || !sameAsSelection(t));
  } catch (x) {
    /* ignore */
  }
}
apply(_addEventListener, window, ['copy', onCopyEnd, false]);
apply(_addEventListener, window, ['cut', onCopyEnd, false]);

function isTextType(type) {
  var f = apply(_toLowerCase, s(type), []);
  return f === 'text/plain' || f === 'text' || f === 'text/unicode';
}

// 4c. clipboardData.setData from the page's own copy handler.
if (_setData) {
  wrap(_DataTransfer.prototype, 'setData', function setData(format, data) {
    var f = s(format);
    var t = s(data);
    if (isTextType(f)) {
      var v = evaluate(t, programmaticCopy || !sameAsSelection(t));
      if (v) notify(v, 'setData', t);
      if (v === 'block' || v === 'hold') return apply(_setData, this, [f, replacementFor(v)]);
    }
    return apply(_setData, this, [f, t]);
  });
}

// 5. clipboardData.items.add(text, 'text/plain') from a copy handler.
if (_itemsAdd) {
  wrap(_ItemList.prototype, 'add', function add(data, type) {
    if (typeof data === 'string' || (arguments.length >= 2 && !(data && typeof data === 'object'))) {
      var t = s(data);
      var ty = s(type);
      if (isTextType(ty)) {
        var v = evaluate(t, programmaticCopy || !sameAsSelection(t));
        if (v) notify(v, 'items.add', t);
        if (v === 'block' || v === 'hold') return apply(_itemsAdd, this, [replacementFor(v), ty]);
      }
      return apply(_itemsAdd, this, [t, ty]);
    }
    return apply(_itemsAdd, this, arguments);
  });
}

})();
