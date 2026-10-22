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
