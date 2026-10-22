/*
 * ClickFix First Aid: background service worker.
 *
 * - Keeps a small local history (never sent anywhere) and the settings.
 * - Puts a red "!" on the toolbar icon when something is blocked.
 * - Shows warnings in the top frame of the tab, even when the trap sits in a frame.
 * - Connects the dots inside a tab: a paused copy plus trap instructions on the
 *   page (before or within 20 seconds after) becomes a full block warning.
 *   The clipboard already holds a harmless message at that point.
 */
'use strict';

var MAX_RECENT = 20;
var LURE_THEN_HOLD_MS = 60000;
var HOLD_THEN_LURE_MS = 20000;
var tabState = new Map(); // tabId -> { lureAt, lureCounted, holdAt, held }

function stateFor(tabId) {
  var s = tabState.get(tabId);
  if (!s) {
    s = { lureAt: 0, lureCounted: false, holdAt: 0, held: null };
    tabState.set(tabId, s);
  }
  return s;
}

chrome.tabs.onRemoved.addListener(function (tabId) { tabState.delete(tabId); });
chrome.tabs.onUpdated.addListener(function (tabId, info) {
  if (info.status === 'loading') tabState.delete(tabId); // new page or reload
});

function record(kind, data) {
  chrome.storage.local.get(['stats', 'recent'], function (res) {
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
    chrome.storage.local.set({ stats: stats, recent: recent.slice(0, MAX_RECENT) });
  });
}

// All settings changes go through here, one at a time, so two tabs cannot
// overwrite each other's changes.
var settingsQueue = Promise.resolve();
function updateSettings(change) {
  settingsQueue = settingsQueue.then(function () {
    return chrome.storage.local.get(['settings']).then(function (res) {
      var s = Object.assign({ holdInstallers: true, allowSites: [] }, res.settings || {});
      change(s);
      return chrome.storage.local.set({ settings: s });
    });
  }).catch(function () {});
  return settingsQueue;
}

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

chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (!msg || !sender || sender.id !== chrome.runtime.id) return;

  if (msg.type === 'cfa-allow-site') {
    var host = String(msg.host || '').slice(0, 253);
    if (host) updateSettings(function (s) { if (s.allowSites.indexOf(host) === -1) s.allowSites.push(host); });
    return;
  }

  if (!sender.tab) return;
  var tabId = sender.tab.id;
  var st = stateFor(tabId);
  var now = Date.now();
  var data = msg.data;

  switch (msg.type) {
    case 'cfa-event':
      if (!data) return;
      if (data.verdict === 'block') {
        record('block', data);
        flagTab(tabId, '#b91c1c');
        show(tabId, data);
      } else if (data.verdict === 'hold') {
        if (st.lureAt && now - st.lureAt < LURE_THEN_HOLD_MS) {
          escalate(tabId, data, 'This page shows fake verification steps (Win+R, paste)');
          return;
        }
        st.holdAt = now;
        st.held = data;
        record('hold', data);
        show(tabId, data);
        chrome.tabs.sendMessage(tabId, { type: 'cfa-deep-scan' }).catch(function () {});
      } else if (data.verdict === 'note') {
        record('note', data);
        show(tabId, data);
      }
      break;

    case 'cfa-lure':
      st.lureAt = now;
      if (!st.lureCounted) {
        st.lureCounted = true;
        record('lure', data);
        flagTab(tabId, '#b45309');
      }
      if (st.held && now - st.holdAt < HOLD_THEN_LURE_MS) {
        var held = st.held;
        st.held = null;
        escalate(tabId, held, 'Right after copying, the page showed fake verification steps (Win+R, paste)');
      } else {
        chrome.tabs.sendMessage(tabId, { type: 'cfa-show-lure' }, { frameId: 0 }).catch(function () {});
      }
      break;

    case 'cfa-close-tab':
      chrome.tabs.remove(tabId).catch(function () {});
      break;

    case 'cfa-open-guide':
      chrome.tabs.create({ url: chrome.runtime.getURL('pages/recovery.html') });
      break;
  }
});
