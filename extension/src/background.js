/*
 * ClickFix First Aid: background service worker.
 *
 * - Keeps a small local history (never sent anywhere) and the settings.
 * - Puts a red "!" on the toolbar icon when something is blocked.
 * - Shows warnings in the top frame of the tab, even when the trap sits in a frame.
 * - Connects the dots inside a tab: a paused copy plus trap instructions on the
 *   page (before or within 20 seconds after) becomes a full block warning.
 *   The clipboard already holds a harmless message at that point.
 *
 * Chrome stops this worker after about 30 seconds without events, and starts
 * it again for the next one. So nothing that matters lives only in memory:
 * what each tab has seen is kept in chrome.storage.session (memory-only,
 * cleared when the browser closes, and not readable by web pages or content
 * scripts). Every change goes through one queue, so two events arriving
 * together cannot overwrite each other.
 */
'use strict';

var MAX_RECENT = 20;
var MAX_SITES = 1000;
var LURE_THEN_HOLD_MS = 60000;
var HOLD_THEN_LURE_MS = 20000;
var POPUP_URL = chrome.runtime.getURL('popup/popup.html');
var RE_HOST = /^[a-z0-9.-]{1,253}$|^\[[0-9a-f:.]{2,45}\]$/i;

// ---- One queue for every read-modify-write. --------------------------------
var queue = Promise.resolve();
function serial(task) {
  var run = queue.then(task);
  queue = run.catch(function () {});
  return run;
}

// ---- What each tab has seen (survives the worker being stopped). ------------
function tabKey(tabId) {
  return 'tab:' + tabId;
}

function blankTab() {
  return { lureAt: 0, lureCounted: false, holdAt: 0, held: null };
}

function withTab(tabId, change) {
  return serial(function () {
    var key = tabKey(tabId);
    return chrome.storage.session.get(key).then(function (res) {
      var st = Object.assign(blankTab(), res[key] || {});
      var after = change(st);
      var save = {};
      save[key] = st;
      return chrome.storage.session.set(save).then(function () { return after; });
    });
  });
}

function forgetTab(tabId) {
  return serial(function () { return chrome.storage.session.remove(tabKey(tabId)); });
}

chrome.tabs.onRemoved.addListener(function (tabId) { forgetTab(tabId); });
chrome.tabs.onUpdated.addListener(function (tabId, info) {
  if (info.status === 'loading') forgetTab(tabId); // new page or reload
});

// ---- History and counters. -------------------------------------------------
function record(kind, data) {
  return serial(function () {
    return chrome.storage.local.get(['stats', 'recent']).then(function (res) {
      var stats = Object.assign({ blocked: 0, held: 0, lurePages: 0 }, res.stats || {});
      var recent = Array.isArray(res.recent) ? res.recent : [];
      if (kind === 'block') stats.blocked++;
      else if (kind === 'hold' || kind === 'note') stats.held++;
      else if (kind === 'lure') stats.lurePages++;
      recent.unshift({
        time: Date.now(),
        kind: kind,
        host: String((data && data.host) || '').slice(0, 120),
        preview: String((data && data.preview) || '').slice(0, 200)
      });
      return chrome.storage.local.set({ stats: stats, recent: recent.slice(0, MAX_RECENT) });
    });
  });
}

// ---- Settings: changed only here, one change at a time. --------------------
function cleanSettings(s) {
  s = s || {};
  var sites = [];
  if (Array.isArray(s.allowSites)) {
    for (var i = 0; i < s.allowSites.length && sites.length < MAX_SITES; i++) {
      var h = String(s.allowSites[i]).toLowerCase();
      if (RE_HOST.test(h) && sites.indexOf(h) === -1) sites.push(h);
    }
  }
  return { holdInstallers: s.holdInstallers !== false, allowSites: sites };
}

function updateSettings(change) {
  return serial(function () {
    return chrome.storage.local.get(['settings']).then(function (res) {
      var s = cleanSettings(res.settings);
      change(s);
      s = cleanSettings(s);
      return chrome.storage.local.set({ settings: s }).then(function () { return s; });
    });
  });
}

function hostOf(url) {
  try {
    var u = new URL(url);
    return /^https?:$/.test(u.protocol) ? u.hostname.toLowerCase() : '';
  } catch (e) {
    return '';
  }
}

// ---- Showing warnings. -----------------------------------------------------
function flagTab(tabId, color) {
  try {
    chrome.action.setBadgeText({ tabId: tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
  } catch (e) {
    /* ignore */
  }
}

function show(tabId, data) {
  chrome.tabs.sendMessage(tabId, { type: 'cfa-show', data: data }, { frameId: 0 }).catch(function () {});
}

function escalate(tabId, data, reason) {
  var d = Object.assign({}, data, { verdict: 'block', original: '' });
  d.reasons = [reason].concat(Array.isArray(data.reasons) ? data.reasons : []).slice(0, 8);
  record('block', d);
  flagTab(tabId, '#b91c1c');
  show(tabId, d);
}

// What we remember about a paused copy: enough to warn, never the text itself.
function heldSummary(data) {
  return {
    verdict: 'hold',
    rule: String(data.rule || '').slice(0, 40),
    reasons: Array.isArray(data.reasons) ? data.reasons.slice(0, 8).map(String) : [],
    preview: String(data.preview || '').slice(0, 2000),
    how: String(data.how || '').slice(0, 40),
    host: String(data.host || '').slice(0, 253)
  };
}

function onEvent(tabId, data) {
  var now = Date.now();
  if (data.verdict === 'block') {
    record('block', data);
    flagTab(tabId, '#b91c1c');
    show(tabId, data);
  } else if (data.verdict === 'hold') {
    withTab(tabId, function (st) {
      if (st.lureAt && now - st.lureAt < LURE_THEN_HOLD_MS) return 'escalate';
      st.holdAt = now;
      st.held = heldSummary(data);
      return 'hold';
    }).then(function (what) {
      if (what === 'escalate') {
        escalate(tabId, data, 'This page shows fake verification steps (Win+R, paste)');
        return;
      }
      record('hold', data);
      show(tabId, data);
      chrome.tabs.sendMessage(tabId, { type: 'cfa-deep-scan' }).catch(function () {});
    });
  } else if (data.verdict === 'note') {
    record('note', data);
    show(tabId, data);
  }
}

function onLure(tabId, data) {
  var now = Date.now();
  withTab(tabId, function (st) {
    var out = { count: !st.lureCounted, held: null };
    st.lureAt = now;
    st.lureCounted = true;
    if (st.held && now - st.holdAt < HOLD_THEN_LURE_MS) {
      out.held = st.held;
      st.held = null;
    }
    return out;
  }).then(function (out) {
    if (out.count) {
      record('lure', data);
      flagTab(tabId, '#b45309');
    }
    if (out.held) {
      escalate(tabId, out.held, 'Right after copying, the page showed fake verification steps (Win+R, paste)');
    } else {
      chrome.tabs.sendMessage(tabId, { type: 'cfa-show-lure' }, { frameId: 0 }).catch(function () {});
    }
  });
}

// ---- The popup (an extension page) asks for settings changes here. ---------
function fromPopup(sender) {
  return !!sender && sender.id === chrome.runtime.id && String(sender.url || '').split('#')[0].split('?')[0] === POPUP_URL;
}

function onPopupRequest(msg, respond) {
  var work;
  if (msg.action === 'set-hold') {
    var on = msg.value === true;
    work = updateSettings(function (s) { s.holdInstallers = on; });
  } else if (msg.action === 'remove-site') {
    var host = String(msg.host || '').toLowerCase();
    work = updateSettings(function (s) { s.allowSites = s.allowSites.filter(function (h) { return h !== host; }); });
  } else if (msg.action === 'clear-history') {
    work = serial(function () { return chrome.storage.local.set({ stats: { blocked: 0, held: 0, lurePages: 0 }, recent: [] }); });
  } else {
    respond({ ok: false, error: 'Unknown request' });
    return false;
  }
  work.then(function () { respond({ ok: true }); }, function (e) { respond({ ok: false, error: String(e && e.message || e) }); });
  return true; // answer comes later
}

chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
  if (!msg || !sender || sender.id !== chrome.runtime.id) return;

  if (msg.type === 'cfa-popup') {
    if (!fromPopup(sender)) {
      respond({ ok: false, error: 'Not allowed' });
      return;
    }
    return onPopupRequest(msg, respond);
  }

  if (!sender.tab) return;
  var tabId = sender.tab.id;

  switch (msg.type) {
    case 'cfa-allow-site': {
      // Only the warning in the top frame offers this, and the site is taken
      // from the tab's own address, never from the message.
      if (sender.frameId !== 0) return;
      var host = hostOf(sender.url || sender.tab.url);
      if (host) updateSettings(function (s) { if (s.allowSites.indexOf(host) === -1) s.allowSites.push(host); });
      return;
    }
    case 'cfa-event':
      if (msg.data && typeof msg.data === 'object') onEvent(tabId, msg.data);
      return;
    case 'cfa-lure':
      onLure(tabId, msg.data || {});
      return;
    case 'cfa-close-tab':
      chrome.tabs.remove(tabId).catch(function () {});
      return;
    case 'cfa-open-guide':
      chrome.tabs.create({ url: chrome.runtime.getURL('pages/recovery.html') });
      return;
  }
});
