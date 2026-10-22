'use strict';

var cfg = self.CFA_CONFIG || {};

function $(id) {
  return document.getElementById(id);
}

function timeAgo(t) {
  var s = Math.max(1, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  var m = Math.round(s / 60);
  if (m < 60) return m + ' min ago';
  var h = Math.round(m / 60);
  if (h < 48) return h + ' h ago';
  return Math.round(h / 24) + ' days ago';
}

var KIND_LABEL = { block: 'Blocked', warn: 'Warned', lure: 'Trap page' };

function render() {
  chrome.storage.local.get(['stats', 'recent', 'settings'], function (res) {
    var stats = res.stats || { blocked: 0, warned: 0, lurePages: 0 };
    $('blocked').textContent = stats.blocked || 0;
    $('warned').textContent = stats.warned || 0;
    $('lures').textContent = stats.lurePages || 0;

    var list = $('recent');
    var recent = Array.isArray(res.recent) ? res.recent.slice(0, 6) : [];
    if (recent.length) {
      list.textContent = '';
      recent.forEach(function (r) {
        var li = document.createElement('li');
        var kind = document.createElement('span');
        kind.className = 'kind ' + r.kind;
        kind.textContent = KIND_LABEL[r.kind] || r.kind;
        var meta = document.createElement('span');
        meta.className = 'meta';
        meta.textContent = ' on ' + (r.host || 'a page') + ', ' + timeAgo(r.time);
        li.appendChild(kind);
        li.appendChild(meta);
        list.appendChild(li);
      });
    }

    var s = res.settings || {};
    $('soft').checked = s.softWarnings !== false;
  });
}

$('guide').addEventListener('click', function () {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/recovery.html') });
});

$('soft').addEventListener('change', function (e) {
  chrome.storage.local.get(['settings'], function (res) {
    var s = res.settings || {};
    s.softWarnings = e.target.checked;
    chrome.storage.local.set({ settings: s });
  });
});

$('clear').addEventListener('click', function () {
  chrome.storage.local.set({ stats: { blocked: 0, warned: 0, lurePages: 0 }, recent: [] }, render);
});

if (cfg.homepage) {
  $('demo').href = cfg.homepage.replace(/\/$/, '') + '/demo.html';
  $('demo').hidden = false;
  $('home').href = cfg.homepage.replace(/\/$/, '') + '/#check-your-pc';
  $('home').hidden = false;
}
$('version').textContent = 'v' + (cfg.version || chrome.runtime.getManifest().version);

render();
