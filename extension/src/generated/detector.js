/* GENERATED FILE: do not edit. Run "npm run build" after changing the sources. */
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
