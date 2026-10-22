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
 * This file runs in three places:
 *   1. Node.js, for the tests.
 *   2. The extension's isolated world (safe from the web page).
 *   3. The web page's own world ("MAIN" world), where it must decide before the
 *      page's copy happens. A hostile page could try to tamper with built-in
 *      JavaScript functions there, so we grab the ones we need the moment this
 *      file loads, before any page script runs, and only use those copies.
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
  var reExec = RegExp.prototype.exec;
  var strReplace = String.prototype.replace;
  var strSlice = String.prototype.slice;
  var _String = String;
  var _RegExp = RegExp;

  var VERSION = '0.1.0';

  function str(x) {
    return x == null ? '' : _String(x);
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
      out[out.length] = {
        id: r.id,
        label: r.label,
        weight: typeof r.weight === 'number' ? r.weight : 0,
        re: new _RegExp(r.pattern, 'i')
      };
    }
    return out;
  }

  // Undo the simple disguises attackers use so the real words show through:
  //   c^m^d          -> cmd          (cmd.exe escape character)
  //   p`ow`er`shell  -> powershell   (PowerShell escape character)
  //   'pow'+'ershell'-> powershell   (string splitting)
  //   p""owershell   -> powershell   (empty quotes)
  var RE_CARET = /\^/g;
  var RE_BACKTICK = /`/g;
  var RE_JOIN = /(['"])\s*\+\s*\1/g;
  var RE_EMPTY_QUOTES = /""/g;
  var RE_LINES = /\r\n|\r|\n/g;
  var RE_NONEMPTY_LINE = /\S/;
  var RE_DEFANG = /\b(h)(tt)(ps?):\/\//gi;

  function normalize(s) {
    s = replace(s, RE_CARET, '');
    s = replace(s, RE_BACKTICK, '');
    s = replace(s, RE_JOIN, '');
    s = replace(s, RE_EMPTY_QUOTES, '');
    return s;
  }

  function countLines(s) {
    var n = 0;
    var start = 0;
    RE_LINES.lastIndex = 0;
    var m;
    while ((m = apply(reExec, RE_LINES, [s])) !== null) {
      if (exec(RE_NONEMPTY_LINE, slice(s, start, m.index))) n++;
      start = m.index + m[0].length;
    }
    if (exec(RE_NONEMPTY_LINE, slice(s, start))) n++;
    RE_LINES.lastIndex = 0;
    return n;
  }

  function matchGroup(group, s, into, seen) {
    for (var i = 0; i < group.length; i++) {
      var r = group[i];
      if (seen && seen[r.id]) continue;
      var m = exec(r.re, s);
      if (m) {
        if (seen) seen[r.id] = true;
        into[into.length] = { id: r.id, label: r.label, weight: r.weight, match: slice(m[0], 0, 120) };
      }
    }
    return into;
  }

  function labels(list, max) {
    var out = [];
    for (var i = 0; i < list.length && out.length < (max || 99); i++) out[out.length] = list[i].label;
    return out;
  }

  function pushUnique(arr, items) {
    for (var i = 0; i < items.length; i++) {
      var dup = false;
      for (var j = 0; j < arr.length; j++) if (arr[j] === items[i]) dup = true;
      if (!dup) arr[arr.length] = items[i];
    }
  }

  function createDetector(rules) {
    if (!rules || !rules.command || !rules.page) throw new Error('ClickFix First Aid: rules missing');
    var limits = rules.limits || {};
    var maxChars = limits.maxChars || 20000;
    var maxLinesForAutoBlock = limits.maxLinesForAutoBlock || 5;
    var stealthBlockAt = (rules.verdict && rules.verdict.stealthBlockAt) || 25;
    var stealthOnlyBlockAt = (rules.verdict && rules.verdict.stealthOnlyBlockAt) || 50;

    var G = {
      executors: compileGroup(rules.command.executors),
      remote: compileGroup(rules.command.remote),
      encoded: compileGroup(rules.command.encoded),
      stealth: compileGroup(rules.command.stealth),
      decoys: compileGroup(rules.command.decoys),
      runShortcut: compileGroup(rules.page.runShortcut),
      paste: compileGroup(rules.page.paste),
      verifyTheme: compileGroup(rules.page.verifyTheme)
    };

    function analyzeCommand(text) {
      var raw = str(text);
      if (raw.length > maxChars) raw = slice(raw, 0, maxChars);
      var norm = normalize(raw);

      var executors = matchGroup(G.executors, norm, [], null);
      var remote = matchGroup(G.remote, norm, [], null);
      var encoded = matchGroup(G.encoded, raw, [], null);
      var seen = {};
      var stealth = matchGroup(G.stealth, raw, [], seen);
      matchGroup(G.stealth, norm, stealth, seen);
      var decoys = matchGroup(G.decoys, raw, [], null);

      var stealthScore = 0;
      for (var i = 0; i < stealth.length; i++) stealthScore += stealth[i].weight;

      var hasExec = executors.length > 0;
      return {
        text: raw,
        normalized: norm,
        lines: countLines(raw),
        executors: executors,
        remote: remote,
        encoded: encoded,
        stealth: stealth,
        stealthScore: stealthScore,
        decoys: decoys,
        hasExec: hasExec,
        danger: hasExec && (remote.length > 0 || encoded.length > 0)
      };
    }

    function analyzePage(text) {
      var s = str(text);
      if (s.length > 200000) s = slice(s, 0, 200000);
      var runShortcut = matchGroup(G.runShortcut, s, [], null);
      var paste = matchGroup(G.paste, s, [], null);
      var verifyTheme = matchGroup(G.verifyTheme, s, [], null);
      var weak = runShortcut.length > 0 && paste.length > 0;
      return {
        runShortcut: runShortcut,
        paste: paste,
        verifyTheme: verifyTheme,
        weak: weak,
        strong: weak && verifyTheme.length > 0
      };
    }

    // verdict: 'block' (replace the clipboard), 'warn' (gentle notice), 'allow'.
    // opts.subframe: the copy came from inside a frame embedded in the page.
    // Trap pages often hide the fake checkbox in a frame while the "Win+R"
    // instructions sit in the outer page, out of the frame's sight.
    function decide(cmd, page, opts) {
      var reasons = [];
      if (!cmd || !cmd.hasExec) return { verdict: 'allow', reasons: reasons };

      var why = labels(cmd.executors, 2);
      if (cmd.remote.length) pushUnique(why, labels(cmd.remote, 1));
      if (cmd.encoded.length) pushUnique(why, labels(cmd.encoded, 1));

      if (cmd.decoys.length) {
        pushUnique(reasons, labels(cmd.decoys));
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        return { verdict: 'block', reasons: reasons, rule: 'decoy' };
      }

      if (page && page.weak) {
        reasons[reasons.length] = 'The page tells you to paste it into Run, Terminal or File Explorer';
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        return { verdict: 'block', reasons: reasons, rule: 'lure-page' };
      }

      if (cmd.danger && cmd.stealthScore >= stealthBlockAt) {
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        if (cmd.lines > maxLinesForAutoBlock) {
          return { verdict: 'warn', reasons: reasons, rule: 'stealthy-but-long' };
        }
        return { verdict: 'block', reasons: reasons, rule: 'stealthy-download-and-run' };
      }

      if (cmd.danger && opts && opts.subframe && cmd.lines <= maxLinesForAutoBlock) {
        reasons[reasons.length] = 'Copied from inside a hidden frame of the page, a common trap setup';
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        return { verdict: 'block', reasons: reasons, rule: 'download-and-run-in-frame' };
      }

      if (cmd.danger) {
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        return { verdict: 'warn', reasons: reasons, rule: 'download-and-run' };
      }

      // No download seen, but the command tries very hard to hide itself.
      if (cmd.stealthScore >= stealthOnlyBlockAt && cmd.lines <= maxLinesForAutoBlock) {
        pushUnique(reasons, why);
        pushUnique(reasons, labels(cmd.stealth));
        return { verdict: 'block', reasons: reasons, rule: 'heavily-disguised' };
      }

      return { verdict: 'allow', reasons: reasons };
    }

    function check(text, pageText, opts) {
      var cmd = analyzeCommand(text);
      var page = pageText == null ? null : analyzePage(pageText);
      var d = decide(cmd, page, opts);
      d.command = cmd;
      d.page = page;
      return d;
    }

    return {
      analyzeCommand: analyzeCommand,
      analyzePage: analyzePage,
      decide: decide,
      check: check
    };
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
var CFA_RULES = {"name":"clickfix-first-aid-rules","version":"1.0.0","updated":"2026-10-22","notes":"Patterns must work in both JavaScript and .NET regex engines. All patterns are matched case-insensitively.","limits":{"maxChars":20000,"maxLinesForAutoBlock":5},"command":{"executors":[{"id":"powershell","label":"Starts PowerShell","pattern":"\\b(?:powershell|pwsh)(?:\\.exe)?\\b"},{"id":"cmd","label":"Starts the Windows command prompt","pattern":"\\bcmd(?:\\.exe)?\\s*/[ckr]\\b|\\bcmd\\.exe\\b"},{"id":"mshta","label":"Uses mshta, a Windows tool attackers use to run web code","pattern":"\\bmshta(?:\\.exe)?\\b"},{"id":"msiexec","label":"Runs a Windows installer","pattern":"\\bmsiexec(?:\\.exe)?\\b"},{"id":"rundll32","label":"Uses rundll32 to load a program library","pattern":"\\brundll32(?:\\.exe)?\\b"},{"id":"regsvr32","label":"Uses regsvr32 to load a program library","pattern":"\\bregsvr32(?:\\.exe)?\\b"},{"id":"script-host","label":"Runs a Windows script file","pattern":"\\b[wc]script(?:\\.exe)?\\b"},{"id":"certutil","label":"Uses certutil, often abused to download files","pattern":"\\bcertutil(?:\\.exe)?\\b"},{"id":"bitsadmin","label":"Uses bitsadmin, often abused to download files","pattern":"\\bbitsadmin(?:\\.exe)?\\b"},{"id":"conhost","label":"Starts a hidden console window","pattern":"\\bconhost(?:\\.exe)?\\b"},{"id":"finger","label":"Uses the finger tool to fetch commands from a server","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"dotnet-lolbin","label":"Uses a .NET build tool to run code","pattern":"\\b(?:msbuild|installutil|regasm|regsvcs)(?:\\.exe)?\\b"},{"id":"schtasks","label":"Creates a scheduled task","pattern":"\\bschtasks(?:\\.exe)?\\b"},{"id":"invoke-expression","label":"Runs text as code (Invoke-Expression)","pattern":"\\b(?:iex|invoke-expression)\\b"},{"id":"osascript","label":"Runs an AppleScript on a Mac","pattern":"\\bosascript\\b"},{"id":"pipe-to-shell","label":"Pipes downloaded text straight into a shell","pattern":"\\|\\s*(?:sudo\\s+)?(?:ba|z|da)?sh\\b"},{"id":"shell-c","label":"Runs a shell command string","pattern":"\\b(?:ba|z)?sh\\s+-c\\b"}],"remote":[{"id":"url","label":"Contains a web address","pattern":"\\b(?:https?|ftp)://[^\\s\"'<>]+"},{"id":"unc-path","label":"Loads a file from a remote network share","pattern":"\\\\\\\\[a-z0-9._-]+(?:@ssl)?(?:@\\d+)?\\\\"},{"id":"downloader","label":"Downloads something from the internet","pattern":"\\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|downloadstring|downloadfile|downloaddata|net\\.webclient|curl(?:\\.exe)?|wget(?:\\.exe)?)\\b"},{"id":"finger-host","label":"Asks a remote server for commands (finger)","pattern":"\\bfinger(?:\\.exe)?\\s+\\S+@\\S+"},{"id":"ip-address","label":"Contains an IP address","pattern":"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b"},{"id":"bare-domain","label":"Contains an unusual web domain","pattern":"\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\"']|$)"}],"encoded":[{"id":"ps-encoded","label":"Hides its real instructions in encoded text","pattern":"\\s-e(?:nc|ncodedcommand|c)?\\s+[a-z0-9+/=]{20,}"},{"id":"from-base64","label":"Decodes hidden text before running it","pattern":"frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b|\\batob\\("},{"id":"long-base64","label":"Contains a long block of encoded text","pattern":"[a-z0-9+/]{120,}={0,2}"}],"stealth":[{"id":"hidden-window","label":"Hides its window so you cannot see it running","weight":25,"pattern":"\\s-w(?:in(?:dow(?:style)?)?)?\\s+(?:h(?:idden)?|1)\\b"},{"id":"policy-bypass","label":"Turns off PowerShell safety settings","weight":10,"pattern":"\\s-(?:nop(?:rofile)?|ep\\s+bypass|exec(?:utionpolicy)?\\s+bypass|noni(?:nteractive)?)\\b"},{"id":"encoded","label":"Hides its real instructions in encoded text","weight":30,"pattern":"\\s-e(?:nc|ncodedcommand|c)?\\s+[a-z0-9+/=]{20,}|frombase64string|\\bbase64\\s+(?:-d|--decode|-D)\\b"},{"id":"caret-obfuscation","label":"Disguised with ^ symbols to dodge antivirus","weight":25,"pattern":"\\w\\^\\w\\^?\\w"},{"id":"backtick-obfuscation","label":"Disguised with ` symbols to dodge antivirus","weight":20,"pattern":"[a-z]`[a-z]+`[a-z]"},{"id":"string-splitting","label":"Splits words apart to dodge antivirus","weight":15,"pattern":"['\"]\\s*\\+\\s*['\"]"},{"id":"env-substring","label":"Builds words from pieces of system variables","weight":25,"pattern":"%[a-z_]+:~-?\\d+,-?\\d+%"},{"id":"headless-console","label":"Runs in an invisible console","weight":25,"pattern":"\\bconhost(?:\\.exe)?\\s+--headless"},{"id":"temp-drop","label":"Saves a file into a temporary or app-data folder","weight":10,"pattern":"%temp%|\\$env:temp|%appdata%|\\$env:appdata|%localappdata%|\\$env:localappdata|%programdata%|\\\\appdata\\\\|/tmp/"},{"id":"quiet-install","label":"Installs a program silently, without asking you","weight":20,"pattern":"\\bmsiexec(?:\\.exe)?\\b[^\\n]*\\s/q[nb]?\\b"},{"id":"start-minimized","label":"Starts minimized so you do not notice it","weight":15,"pattern":"\\bstart\\s+(?:\"\"\\s+)?/min\\b"},{"id":"raw-ip","label":"Connects to a raw IP address instead of a website name","weight":20,"pattern":"(?:https?://|\\\\\\\\|@)\\d{1,3}(?:\\.\\d{1,3}){3}\\b"},{"id":"suspicious-domain","label":"Uses a cheap web domain popular with attackers","weight":15,"pattern":"\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:top|xyz|icu|shop|click|cyou|sbs|lat|rest|live|online|site|website|space|fun|cfd|bond|ru|su)(?=[/:\\s\"']|$)"},{"id":"remote-share","label":"Runs code straight from a remote network share","weight":25,"pattern":"\\\\\\\\[a-z0-9._-]+(?:@ssl)?(?:@\\d+)?\\\\"},{"id":"pipe-to-cmd","label":"Feeds downloaded text straight into the command prompt","weight":20,"pattern":"\\|\\s*cmd(?:\\.exe)?\\b"},{"id":"space-padding","label":"Pads the command with spaces to hide part of it","weight":25,"pattern":"\\S {25,}\\S"}],"decoys":[{"id":"fake-verification-comment","label":"Hides fake \"I am not a robot\" text after the real command","pattern":"(?:#|::|\\brem\\b)[^\\n]{0,200}?(?:verif|captcha|robot|human|cloudflare|turnstile|security\\s*check|ray\\s*id|identity|\\u2705|\\u2714)"},{"id":"fake-file-path","label":"Disguises the command as a file path (FileFix trick)","pattern":"#\\s*[a-z]:\\\\[^\\n]*\\.(?:docx?|pdf|xlsx?|pptx?|txt|csv)\\b"}]},"page":{"runShortcut":[{"id":"win-r","label":"Tells you to press Windows + R","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,30}?(?:\\+|\\band\\b|&)\\s*[\"'\\u201c\\u201d]?r\\b|\\bwindows\\s*(?:logo\\s*)?(?:key|button)\\b[^\\n]{0,40}?\\bpress\\s*[\"'\\u201c\\u201d]?r\\b"},{"id":"win-x","label":"Tells you to press Windows + X","pattern":"(?:\\bwin(?:dows)?\\b|\\u229e)[^\\n]{0,30}?(?:\\+|\\band\\b|&)\\s*[\"'\\u201c\\u201d]?x\\b"},{"id":"run-dialog","label":"Mentions the Run dialog","pattern":"\\brun\\s+(?:dialog|box|window|prompt)\\b"},{"id":"open-terminal","label":"Tells you to open a terminal","pattern":"\\bopen\\s+(?:the\\s+)?(?:powershell|windows\\s+terminal|terminal|command\\s+prompt)\\b"},{"id":"explorer-address-bar","label":"Tells you to paste into File Explorer (FileFix)","pattern":"file\\s*explorer[^\\n]{0,120}?address\\s*bar|address\\s*bar[^\\n]{0,120}?file\\s*explorer|\\bctrl\\s*\\+\\s*l\\b"},{"id":"mac-terminal","label":"Tells you to open Terminal on a Mac","pattern":"(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*space\\b"}],"paste":[{"id":"paste","label":"Tells you to paste","pattern":"\\bctrl\\s*\\+\\s*v\\b|(?:\\bcmd\\b|\\bcommand\\b|\\u2318)\\s*\\+\\s*v\\b|\\bpaste\\b"}],"verifyTheme":[{"id":"verify","label":"Pretends to be a human or security check","pattern":"\\bverif(?:y|ication)\\b|captcha|\\bi\\s*(?:'|\\u2019)?\\s*a?m\\s+not\\s+a\\s+robot\\b|\\bare\\s+you\\s+(?:a\\s+)?human\\b|\\bhuman\\s+check\\b|cloudflare|turnstile|\\bsecurity\\s+check\\b|\\bray\\s+id\\b|\\bprove\\s+you\\b"},{"id":"fake-fix","label":"Pretends you need to fix an error","pattern":"\\bfix\\s+(?:the\\s+|this\\s+)?(?:error|issue|problem)\\b|\\bupdate\\s+your\\s+browser\\b|\\bbrowser\\s+update\\b|\\bfailed\\s+to\\s+load\\b"}]},"verdict":{"stealthBlockAt":25,"stealthOnlyBlockAt":50}};
/*
 * ClickFix First Aid: clipboard guard.
 *
 * This code runs inside the web page's own JavaScript world ("MAIN" world),
 * before any of the page's scripts. The build step wraps it together with the
 * detection engine and the rules, so these names exist here:
 *   CFADetectorAPI  - { createDetector, defang }
 *   CFA_RULES       - the rules from rules/clickfix-rules.json
 *
 * A ClickFix page puts a command on your clipboard in one of four ways:
 *   1. navigator.clipboard.writeText(text)
 *   2. navigator.clipboard.write([ClipboardItem])
 *   3. document.execCommand('copy') on a hidden text box
 *   4. a 'copy' event handler that calls event.clipboardData.setData(...)
 * We wrap all four. If the text is an attack command, the clipboard gets a
 * harmless message instead, and the extension shows a warning.
 */

var detector = CFADetectorAPI.createDetector(CFA_RULES);

// Grab built-in functions now, before the page can replace them.
var apply = Reflect.apply;
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var _String = String;
var _CustomEvent = CustomEvent;
var _jsonStringify = JSON.stringify;
var _dispatchEvent = EventTarget.prototype.dispatchEvent;
var _addEventListener = EventTarget.prototype.addEventListener;
var _preventDefault = Event.prototype.preventDefault;
var _toLowerCase = String.prototype.toLowerCase;
var _slice = String.prototype.slice;
var _dateNow = Date.now;
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
var _setData = typeof DataTransfer !== 'undefined' ? DataTransfer.prototype.setData : null;
var _bodyGetter = (getOwnPropertyDescriptor(Document.prototype, 'body') || {}).get;
var _activeElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'activeElement') || {}).get;
var _innerTextGetter = (getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText') || {}).get;
var _textContentGetter = (getOwnPropertyDescriptor(Node.prototype, 'textContent') || {}).get;
var _getSelection = window.getSelection;
var _selectionToString = typeof Selection !== 'undefined' ? Selection.prototype.toString : null;
var _TextArea = HTMLTextAreaElement;
var _Input = HTMLInputElement;
var _taValue = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value') || {}).get;
var _inValue = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value') || {}).get;
var _taStart = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'selectionStart') || {}).get;
var _taEnd = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'selectionEnd') || {}).get;
var _inStart = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionStart') || {}).get;
var _inEnd = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionEnd') || {}).get;
var _getPrototypeOf = Object.getPrototypeOf;
var _taProto = HTMLTextAreaElement.prototype;
var _inProto = HTMLInputElement.prototype;

// What goes on the clipboard instead of the attack. Safe to paste anywhere:
// it starts with '#', so PowerShell and Mac/Linux shells treat it as a comment,
// and in the Run box or File Explorer it simply fails to open. It contains no
// quotes, pipes, ampersands or other characters a shell would act on.
var SAFE_TEXT = '# STOP. ClickFix First Aid blocked this. A website tried to trick you into running a command on your computer. Close that page. Real human checks never ask you to paste anything.';

var MAX_SEND = 20000;
var lastText = '';
var lastTime = 0;
var programmaticCopy = false;

function s(x) {
  return x == null ? '' : _String(x);
}

// Is this code running inside a frame embedded in another page?
var isSubframe = true;
try {
  isSubframe = window.top !== window;
} catch (e) {
  isSubframe = true;
}

function bodyText(getter) {
  try {
    var body = _bodyGetter ? apply(_bodyGetter, document, []) : null;
    if (!body || !getter) return '';
    return s(apply(getter, body, []));
  } catch (e) {
    return '';
  }
}

// Look at the visible text first. Trap pages often copy the command BEFORE
// they un-hide their "Win+R, Ctrl+V" steps, so if the visible text looks
// innocent, also look at hidden text.
function analyzeThisPage() {
  var page = detector.analyzePage(bodyText(_innerTextGetter));
  if (!page.weak) {
    var hidden = detector.analyzePage(bodyText(_textContentGetter));
    if (hidden.weak) page = hidden;
  }
  return page;
}

function protoChainHas(el, proto) {
  var p = el;
  for (var i = 0; i < 10 && p; i++) {
    p = _getPrototypeOf(p);
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

// Returns null (fine) or { verdict: 'block' | 'warn', ... }.
function evaluate(text) {
  var t = s(text);
  if (t.length < 4) return null;
  var cmd = detector.analyzeCommand(t);
  if (!cmd.hasExec) return null; // fast path: not a command at all
  var d = detector.decide(cmd, analyzeThisPage(), { subframe: isSubframe });
  if (d.verdict === 'allow') return null;
  return d;
}

// Tell the extension (isolated world) what happened. The extension re-checks
// the text itself, so a page cannot fake a warning with its own wording.
function notify(text, how, verdict) {
  var now = apply(_dateNow, Date, []);
  if (text === lastText && now - lastTime < 1500) return;
  lastText = text;
  lastTime = now;
  try {
    var detail = apply(_jsonStringify, null, [{ text: apply(_slice, s(text), [0, MAX_SEND]), how: how, verdict: verdict }]);
    apply(_dispatchEvent, document, [new _CustomEvent('clickfix-first-aid', { detail: detail })]);
  } catch (e) {
    /* never break the page */
  }
}

function replaceMethod(proto, name, fn) {
  try {
    var desc = getOwnPropertyDescriptor(proto, name);
    if (!desc) return;
    defineProperty(proto, name, {
      value: fn,
      writable: desc.writable,
      enumerable: desc.enumerable,
      configurable: desc.configurable
    });
  } catch (e) {
    /* ignore */
  }
}

// 1. navigator.clipboard.writeText
if (_Clipboard && _writeText) {
  replaceMethod(_Clipboard.prototype, 'writeText', function writeText(text) {
    var d = evaluate(text);
    if (d) {
      notify(text, 'writeText', d.verdict);
      if (d.verdict === 'block') return apply(_writeText, this, [SAFE_TEXT]);
    }
    return apply(_writeText, this, arguments);
  });
}

// 2. navigator.clipboard.write([ClipboardItem])
if (_Clipboard && _write && _ClipboardItem && _Blob && _getType && _blobText) {
  replaceMethod(_Clipboard.prototype, 'write', function write(items) {
    var self = this;
    var args = arguments;
    try {
      var item = items && items[0];
      var types = item && _typesGetter ? apply(_typesGetter, item, []) : [];
      var hasText = false;
      for (var i = 0; types && i < types.length; i++) if (types[i] === 'text/plain') hasText = true;
      if (hasText) {
        var blobPromise = apply(_getType, item, ['text/plain']);
        var textPromise = apply(_then, blobPromise, [function (blob) { return apply(_blobText, blob, []); }]);
        return apply(_then, textPromise, [function (text) {
          var d = evaluate(text);
          if (d) {
            notify(text, 'write', d.verdict);
            if (d.verdict === 'block') {
              var safe = new _ClipboardItem({ 'text/plain': new _Blob([SAFE_TEXT], { type: 'text/plain' }) });
              return apply(_write, self, [[safe]]);
            }
          }
          return apply(_write, self, args);
        }]);
      }
    } catch (e) {
      /* fall through */
    }
    return apply(_write, self, args);
  });
}

// 3. document.execCommand('copy') - we note that the copy came from the page's
// code, then the 'copy' listener below does the checking.
replaceMethod(Document.prototype, 'execCommand', function execCommand(command) {
  var c = apply(_toLowerCase, s(command), []);
  if (c === 'copy' || c === 'cut') {
    programmaticCopy = true;
    try {
      return apply(_execCommand, this, arguments);
    } finally {
      programmaticCopy = false;
    }
  }
  return apply(_execCommand, this, arguments);
});

// 4a. Any copy (keyboard, menu or execCommand): check what is being copied.
function onCopy(e) {
  var text = selectedText();
  var d = evaluate(text);
  if (!d) return;
  // Someone copying an installer command by hand on a developer site: stay quiet.
  if (d.verdict === 'warn' && !programmaticCopy) return;
  notify(text, programmaticCopy ? 'execCommand' : 'manual copy', d.verdict);
  if (d.verdict === 'block') {
    try {
      if (_setData && e.clipboardData) apply(_setData, e.clipboardData, ['text/plain', SAFE_TEXT]);
      apply(_preventDefault, e, []);
    } catch (x) {
      /* ignore */
    }
  }
}
apply(_addEventListener, window, ['copy', onCopy, true]);
apply(_addEventListener, window, ['cut', onCopy, true]);

// 4b. The page's own copy handler writing text with clipboardData.setData.
if (_setData) {
  replaceMethod(DataTransfer.prototype, 'setData', function setData(format, data) {
    try {
      var f = apply(_toLowerCase, s(format), []);
      if (f === 'text/plain' || f === 'text' || f === 'text/unicode') {
        var d = evaluate(data);
        if (d) {
          notify(data, 'copy event', d.verdict);
          if (d.verdict === 'block') return apply(_setData, this, [format, SAFE_TEXT]);
        }
      }
    } catch (e) {
      /* fall through */
    }
    return apply(_setData, this, arguments);
  });
}

})();
