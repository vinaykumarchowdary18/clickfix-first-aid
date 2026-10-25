/*
 * ClickFix First Aid: content script (extension's isolated world).
 *
 * Jobs:
 *  1. Pick up the private channel created by the clipboard guard (page-hook.js),
 *     tell the guard the current settings, and receive its reports.
 *  2. Pass reports to the background, which records them and asks the top frame
 *     of the tab to show the right warning.
 *  3. Watch the page text, including closed shadow roots, for ClickFix trap
 *     instructions ("Win+R, Ctrl+V, Enter") in every frame.
 *  4. In the top frame: draw warnings and do "Copy anyway" when asked.
 */
(function () {
  'use strict';

  var isTop = window.top === window;
  var detector = CFADetector.createDetector(CFA_RULES);
  var defang = CFADetector.defang;
  var topHost = computeTopHost();
  var settings = { holdInstallers: true, allowSites: [] };
  var channel = null;

  function computeTopHost() {
    if (isTop) return location.hostname || '';
    try {
      var ao = location.ancestorOrigins;
      if (ao && ao.length) return new URL(ao[ao.length - 1]).hostname;
    } catch (e) {
      /* ignore */
    }
    return location.hostname || '';
  }

  function send(msg) {
    try {
      chrome.runtime.sendMessage(msg);
    } catch (e) {
      /* extension reloaded or unavailable */
    }
  }

  // ---- 1. The private channel. ----------------------------------------------
  function sendConfig() {
    if (!channel) return;
    var allowed = settings.allowSites.indexOf(topHost) !== -1;
    channel.dispatchEvent(new CustomEvent('cfa-config', {
      detail: 'hold=' + (settings.holdInstallers ? 1 : 0) + ';allow=' + (allowed ? 1 : 0)
    }));
  }

  function tryBind() {
    var host = document.getElementsByTagName('clickfix-first-aid-channel')[0];
    if (!host) return false;
    try {
      var root = chrome.dom.openOrClosedShadowRoot(host);
      var node = root && root.firstChild;
      if (!node) return false;
      channel = node;
      node.addEventListener('cfa-report', onReport);
      host.remove(); // the page never gets to see it
      sendConfig();
      return true;
    } catch (e) {
      return false;
    }
  }

  if (!tryBind()) {
    // The guard may run a moment after us. Wait for its element.
    var mo = new MutationObserver(function () {
      if (tryBind()) mo.disconnect();
    });
    mo.observe(document, { childList: true, subtree: true });
    document.addEventListener('DOMContentLoaded', function () { mo.disconnect(); }, { once: true });
  }

  function applySettings(s) {
    s = s || {};
    settings.holdInstallers = s.holdInstallers !== false;
    settings.allowSites = Array.isArray(s.allowSites) ? s.allowSites : [];
    sendConfig();
  }

  try {
    chrome.storage.local.get(['settings'], function (res) { applySettings(res && res.settings); });
    chrome.storage.onChanged.addListener(function (changes, area) {
      if (area === 'local' && changes.settings) applySettings(changes.settings.newValue);
    });
  } catch (e) {
    /* ignore */
  }

  // ---- Reading the page (here the page cannot interfere). -------------------
  var SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEXTAREA: 1, TEMPLATE: 1 };

  function textOf(root, limit) {
    var out = '';
    try {
      var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      var n;
      while ((n = w.nextNode()) && out.length < limit) {
        var p = n.parentNode;
        if (p && SKIP[p.nodeName] === 1) continue;
        out += n.nodeValue + '\n';
      }
    } catch (e) {
      /* partial text is fine */
    }
    return out;
  }

  // Text inside shadow roots, including closed ones the page tried to hide.
  function shadowText(limit) {
    var out = '';
    try {
      var all = document.querySelectorAll('*');
      for (var i = 0; i < all.length && i < 5000 && out.length < limit; i++) {
        if (all[i].localName === 'clickfix-first-aid-ui') continue; // our own warnings
        var root = chrome.dom.openOrClosedShadowRoot(all[i]);
        if (root) out += textOf(root, limit - out.length);
      }
    } catch (e) {
      /* ignore */
    }
    return out;
  }

  // Text added with CSS, like #steps::before { content: "Press Win+R" }.
  function pseudoText(limit) {
    var out = '';
    try {
      var all = document.querySelectorAll('body *');
      for (var i = 0; i < all.length && i < 1500 && out.length < limit; i++) {
        var pair = ['::before', '::after'];
        for (var j = 0; j < 2; j++) {
          var c = getComputedStyle(all[i], pair[j]).content;
          if (c && c !== 'none' && c !== 'normal') out += c.replace(/^["']|["']$/g, '') + '\n';
        }
      }
    } catch (e) {
      /* ignore */
    }
    return out;
  }

  function visibleText(deep) {
    var t = '';
    try {
      t = document.body ? document.body.innerText || '' : '';
    } catch (e) {
      t = '';
    }
    t += '\n' + shadowText(100000);
    if (deep) t += '\n' + pseudoText(20000);
    return t;
  }

  // Same rule as the guard: only visible text can make a page "strong".
  function analyzeThisPage() {
    var v = detector.analyzePage(visibleText(false));
    if (v.strong || v.weak) return v;
    var h = detector.analyzePage(document.body ? textOf(document.body, 200000) : '');
    return { weak: h.weak, strong: false, runShortcut: h.runShortcut, paste: h.paste, verifyTheme: h.verifyTheme };
  }

  // ---- 2. Reports from the guard. --------------------------------------------
  var lastAt = { block: 0, hold: 0, note: 0 };
  var FALLBACK = {
    block: 'It matches a known ClickFix attack pattern',
    hold: 'It downloads and runs a program',
    note: 'It downloads and runs a program'
  };

  var MAX_REPORT = 1000000; // same as MAX_SEND in page-hook.js

  function onReport(ev) {
    var parts = String(ev.detail).split('\u001f');
    var verdict = parts[0];
    if (!Object.prototype.hasOwnProperty.call(lastAt, verdict)) return;
    var text = parts.slice(2).join('\u001f');
    var cmd = detector.analyzeCommand(text);
    // Our own check, here where the page cannot interfere: a report about text
    // with nothing command-like in it did not come from the guard. Ignore it.
    if (!detector.worthChecking(cmd)) return;
    var now = Date.now();
    if (now - lastAt[verdict] < 500) return;
    lastAt[verdict] = now;
    var how = (parts[1] || '').slice(0, 40);
    var complete = text.length < MAX_REPORT;
    var r = detector.decide(cmd, analyzeThisPage(), { subframe: !isTop });
    var reasons = r.reasons.length ? r.reasons.slice(0, 8) : [FALLBACK[verdict]];
    send({
      type: 'cfa-event',
      data: {
        verdict: verdict,
        rule: r.rule || '',
        reasons: reasons,
        preview: defang(text, 600),
        how: how,
        host: topHost,
        // "Copy anyway" needs the whole text; never offer a cut-off copy.
        original: verdict === 'block' || !complete ? '' : text
      }
    });
  }

  // ---- 3. Trap-page detection, in every frame. ------------------------------
  if (/^https?:$/.test(location.protocol) || (!isTop && location.protocol === 'about:')) {
    var scans = 0;
    var timer = null;
    var flagged = false;
    var observer = null;
    var deepUntil = 0;

    var scan = function () {
      timer = null;
      if (flagged) return;
      var deep = Date.now() < deepUntil;
      if (scans >= 60 && !deep) {
        if (observer) observer.disconnect();
        return;
      }
      scans++;
      var page = detector.analyzePage(visibleText(deep));
      if (page.strong) {
        flagged = true;
        if (observer) observer.disconnect();
        var reasons = [];
        [page.runShortcut, page.paste, page.verifyTheme].forEach(function (g) {
          g.forEach(function (x) { reasons.push(x.label); });
        });
        send({ type: 'cfa-lure', data: { host: topHost, reasons: reasons.slice(0, 6) } });
      }
    };

    var schedule = function () {
      if (!timer && !flagged) timer = setTimeout(scan, 600);
    };

    var start = function () {
      schedule();
      try {
        // Trap pages often reveal their steps by un-hiding an element, so watch
        // style/class/hidden changes too, not just new text.
        observer = new MutationObserver(schedule);
        observer.observe(document.documentElement, {
          childList: true, subtree: true, characterData: true,
          attributes: true, attributeFilter: ['style', 'class', 'hidden']
        });
      } catch (e) {
        /* ignore */
      }
    };

    // After a copy was paused, look harder for 15 seconds (CSS text included),
    // because some traps only show their instructions after the copy.
    self.CFAStartDeepScan = function () {
      deepUntil = Date.now() + 15000;
      var tick = function () {
        if (flagged || Date.now() > deepUntil) return;
        scan();
        setTimeout(tick, 1000);
      };
      tick();
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }

  // ---- 4. Copy anyway (top frame). ---------------------------------------------
  // Our isolated world has its own, untouched copies of the clipboard functions.
  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(t).catch(function () { return copyWithEvent(t); });
    }
    return copyWithEvent(t);
  }

  function copyWithEvent(t) {
    return new Promise(function (resolve, reject) {
      var handler = function (e) {
        e.clipboardData.setData('text/plain', t);
        e.preventDefault();
        e.stopImmediatePropagation(); // the person approved this copy
      };
      document.addEventListener('copy', handler, { capture: true, once: true });
      var ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (e) {
        ok = false;
      }
      document.removeEventListener('copy', handler, { capture: true });
      if (ok) resolve();
      else reject(new Error('copy failed'));
    });
  }

  chrome.runtime.onMessage.addListener(function (msg) {
    if (!msg) return;
    if (msg.type === 'cfa-deep-scan') {
      if (self.CFAStartDeepScan) self.CFAStartDeepScan();
      return;
    }
    if (!isTop) return;
    if (msg.type === 'cfa-show-lure') {
      self.CFAUI.showLureBanner();
      return;
    }
    if (msg.type !== 'cfa-show' || !msg.data) return;
    var d = msg.data;
    if (d.verdict === 'block') {
      self.CFAUI.showBlocked(d);
    } else if (d.verdict === 'hold') {
      var original = String(d.original || '');
      self.CFAUI.showHeld(d, {
        canCopy: original !== '',
        copyAnyway: function () { return copyText(original); },
        allowSite: function () {
          // The background takes the site from this tab's address, not from us.
          send({ type: 'cfa-allow-site' });
          return copyText(original);
        }
      });
    } else if (d.verdict === 'note') {
      self.CFAUI.showNote(d);
    }
  });
})();
