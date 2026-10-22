/*
 * ClickFix First Aid: background service worker.
 *
 * Keeps a small local history (never sent anywhere), puts a red "!" on the
 * toolbar icon when something is blocked, and passes warnings to the top frame
 * of the tab so they show full-screen even when the trap sits inside an iframe.
 */
'use strict';

var MAX_RECENT = 20;

function record(kind, data, tab) {
  chrome.storage.local.get(['stats', 'recent'], function (res) {
    var stats = res.stats || { blocked: 0, warned: 0, lurePages: 0 };
    var recent = Array.isArray(res.recent) ? res.recent : [];
    if (kind === 'block') stats.blocked++;
    else if (kind === 'warn') stats.warned++;
    else if (kind === 'lure') stats.lurePages++;
    recent.unshift({
      time: Date.now(),
      kind: kind,
      host: String((data && data.host) || (tab && tab.url ? safeHost(tab.url) : '')).slice(0, 120),
      preview: String((data && data.preview) || '').slice(0, 200)
    });
    chrome.storage.local.set({ stats: stats, recent: recent.slice(0, MAX_RECENT) });
  });
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return '';
  }
}

function flagTab(tabId, color) {
  try {
    chrome.action.setBadgeText({ tabId: tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
  } catch (e) {
    /* ignore */
  }
}

chrome.runtime.onMessage.addListener(function (msg, sender) {
  if (!msg || !sender || !sender.tab || sender.id !== chrome.runtime.id) return;
  var tabId = sender.tab.id;

  switch (msg.type) {
    case 'cfa-event':
      if (!msg.data || (msg.data.verdict !== 'block' && msg.data.verdict !== 'warn')) return;
      record(msg.data.verdict, msg.data, sender.tab);
      if (msg.data.verdict === 'block') flagTab(tabId, '#b91c1c');
      chrome.tabs.sendMessage(tabId, { type: 'cfa-show', data: msg.data }, { frameId: 0 }).catch(function () {});
      break;
    case 'cfa-lure':
      record('lure', msg.data, sender.tab);
      flagTab(tabId, '#b45309');
      break;
    case 'cfa-close-tab':
      chrome.tabs.remove(tabId).catch(function () {});
      break;
    case 'cfa-open-guide':
      chrome.tabs.create({ url: chrome.runtime.getURL('pages/recovery.html') });
      break;
  }
});
