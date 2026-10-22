/*
 * ClickFix First Aid: content script (extension's isolated world).
 *
 * Jobs:
 *  1. Listen for reports from the clipboard guard (page-hook.js). Re-check the
 *     text here, where the page cannot interfere, then ask the background to
 *     record it and show the warning in the top frame of the tab.
 *  2. Watch the page text for ClickFix trap instructions ("Win+R, Ctrl+V,
 *     Enter") and show a banner even before anything is copied.
 *  3. Draw warnings when the background tells the top frame to.
 */
(function () {
  'use strict';

  var isTop = window.top === window;
  var detector = CFADetector.createDetector(CFA_RULES);
  var defang = CFADetector.defang;
  var settings = { softWarnings: true, mutedSites: [] };
  var host = location.hostname || '';

  try {
    chrome.storage.local.get(['settings'], function (res) {
      if (res && res.settings) {
        settings.softWarnings = res.settings.softWarnings !== false;
        settings.mutedSites = Array.isArray(res.settings.mutedSites) ? res.settings.mutedSites : [];
      }
    });
  } catch (e) {
    /* ignore */
  }

  function send(msg) {
    try {
      chrome.runtime.sendMessage(msg);
    } catch (e) {
      /* extension reloaded or unavailable */
    }
  }

  function pageText() {
    try {
      return document.body ? document.body.innerText || '' : '';
    } catch (e) {
      return '';
    }
  }

  // Same logic as the clipboard guard: visible text first, then hidden text.
  function analyzeThisPage() {
    var page = detector.analyzePage(pageText());
    if (!page.weak) {
      var hidden = '';
      try {
        hidden = document.body ? document.body.textContent || '' : '';
      } catch (e) {
        hidden = '';
      }
      var p2 = detector.analyzePage(hidden);
      if (p2.weak) page = p2;
    }
    return page;
  }

  // 1. Reports from the clipboard guard.
  var lastEventAt = 0;
  document.addEventListener('clickfix-first-aid', function (ev) {
    var now = Date.now();
    if (now - lastEventAt < 800) return; // ignore floods
    lastEventAt = now;
    var data;
    try {
      data = JSON.parse(String(ev.detail));
    } catch (e) {
      return;
    }
    if (!data || typeof data.text !== 'string') return;
    var text = data.text.slice(0, 20000);
    var r = detector.decide(detector.analyzeCommand(text), analyzeThisPage(), { subframe: !isTop });
    if (r.verdict === 'allow') return;
    send({
      type: 'cfa-event',
      data: {
        verdict: r.verdict,
        rule: r.rule || '',
        reasons: r.reasons.slice(0, 8),
        preview: defang(text, 600),
        how: typeof data.how === 'string' ? data.how.slice(0, 40) : '',
        host: host
      }
    });
  });

  // 3. Show warnings (top frame only).
  if (isTop) {
    chrome.runtime.onMessage.addListener(function (msg) {
      if (!msg || msg.type !== 'cfa-show' || !msg.data) return;
      var d = msg.data;
      if (d.verdict === 'block') {
        self.CFAUI.showBlocked(d);
      } else if (d.verdict === 'warn') {
        if (!settings.softWarnings) return;
        if (settings.mutedSites.indexOf(host) !== -1) return;
        self.CFAUI.showToast(d, function () {
          settings.mutedSites.push(host);
          try {
            chrome.storage.local.set({ settings: settings });
          } catch (e) {
            /* ignore */
          }
        });
      }
    });
  }

  // 2. Trap-page detection (top frame only).
  if (isTop && /^https?:$/.test(location.protocol)) {
    var scans = 0;
    var timer = null;
    var flagged = false;
    var observer = null;

    var scan = function () {
      timer = null;
      if (flagged || scans >= 60) {
        if (observer) observer.disconnect();
        return;
      }
      scans++;
      var page = detector.analyzePage(pageText());
      if (page.strong) {
        flagged = true;
        if (observer) observer.disconnect();
        var reasons = [];
        var groups = [page.runShortcut, page.paste, page.verifyTheme];
        for (var g = 0; g < groups.length; g++) {
          for (var i = 0; i < groups[g].length; i++) reasons.push(groups[g][i].label);
        }
        send({ type: 'cfa-lure', data: { host: host, reasons: reasons.slice(0, 6) } });
        self.CFAUI.showLureBanner();
      }
    };

    var schedule = function () {
      if (!timer && !flagged) timer = setTimeout(scan, 700);
    };

    var start = function () {
      schedule();
      try {
        observer = new MutationObserver(schedule);
        // Trap pages often reveal their "Win+R, Ctrl+V" steps by un-hiding an
        // element, so watch style/class/hidden changes too, not just new text.
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
          characterData: true,
          attributes: true,
          attributeFilter: ['style', 'class', 'hidden']
        });
      } catch (e) {
        /* ignore */
      }
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
      start();
    }
  }
})();
