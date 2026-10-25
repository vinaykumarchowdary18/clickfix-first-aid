'use strict';

var cfg = self.CFA_CONFIG || {};
var detector = self.CFADetector.createDetector(self.CFA_RULES);

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

var KIND_LABEL = { block: 'Blocked', hold: 'Paused', note: 'Noted', lure: 'Trap page' };

// Settings are changed by the background worker, one change at a time, so the
// popup and an open tab can never overwrite each other's changes.
function ask(action, extra) {
  var msg = { type: 'cfa-popup', action: action };
  if (extra) for (var k in extra) msg[k] = extra[k];
  return chrome.runtime.sendMessage(msg).then(function (res) {
    if (!res || !res.ok) throw new Error((res && res.error) || 'No answer');
    $('settings-error').hidden = true;
    render();
  }).catch(function (e) {
    $('settings-error').textContent = 'Not saved: ' + e.message + '. Close and reopen this window, then try again.';
    $('settings-error').hidden = false;
    render();
  });
}

function render() {
  chrome.storage.local.get(['stats', 'recent', 'settings'], function (res) {
    var stats = res.stats || {};
    $('blocked').textContent = stats.blocked || 0;
    $('held').textContent = stats.held || 0;
    $('lures').textContent = stats.lurePages || 0;

    var list = $('recent');
    var recent = Array.isArray(res.recent) ? res.recent.slice(0, 6) : [];
    list.textContent = '';
    if (!recent.length) {
      var empty = document.createElement('li');
      empty.className = 'empty';
      empty.textContent = 'Nothing caught yet. That is good news.';
      list.appendChild(empty);
    }
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

    var s = res.settings || {};
    $('hold').checked = s.holdInstallers !== false;
    var sites = Array.isArray(s.allowSites) ? s.allowSites : [];
    $('allowed-wrap').hidden = sites.length === 0;
    var ul = $('allowed');
    ul.textContent = '';
    sites.forEach(function (host) {
      var li = document.createElement('li');
      li.textContent = host + ' ';
      var rm = document.createElement('button');
      rm.className = 'quiet';
      rm.type = 'button';
      rm.textContent = 'Remove';
      rm.addEventListener('click', function () { ask('remove-site', { host: host }); });
      li.appendChild(rm);
      ul.appendChild(li);
    });
  });
}

// ---- Check a command (runs the same rules as the guard, right here). -------
var RESULT = {
  block: {
    cls: 'bad',
    title: 'Do not run this.',
    text: 'It matches a known ClickFix attack pattern. Close the page that gave it to you.'
  },
  hold: {
    cls: 'warn',
    title: 'Careful: this downloads and runs a program.',
    text: 'Real installers look like this too. Only run it if you went looking for this program on its official site. Never run it because a page asked you to "verify" you are human.'
  },
  'too-long': {
    cls: 'warn',
    title: 'Too long to check completely.',
    text: 'A command could be hidden at the end of it. Do not run it unless you know exactly what it is.'
  },
  allow: {
    cls: 'neutral',
    title: 'No known attack pattern found.',
    text: 'That does not prove it is safe. Only run commands you understand, from sources you trust. A real "I am not a robot" check never asks you to run anything.'
  }
};

function showResult() {
  var text = $('command').value;
  var box = $('result');
  box.textContent = '';
  if (!text.trim()) {
    box.hidden = true;
    return;
  }
  var r = detector.check(text, null);
  var kind = r.rule === 'too-long' ? 'too-long' : r.verdict;
  var info = RESULT[kind] || RESULT.allow;
  box.className = 'result ' + info.cls;
  box.setAttribute('data-verdict', r.verdict);
  var strong = document.createElement('strong');
  strong.textContent = info.title;
  var p = document.createElement('p');
  p.textContent = info.text;
  box.appendChild(strong);
  box.appendChild(p);
  if (r.reasons.length) {
    var ul = document.createElement('ul');
    for (var i = 0; i < r.reasons.length && i < 6; i++) {
      var li = document.createElement('li');
      li.textContent = String(r.reasons[i]);
      ul.appendChild(li);
    }
    box.appendChild(ul);
  }
  box.hidden = false;
}

$('check').addEventListener('click', showResult);
$('command').addEventListener('keydown', function (e) {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) showResult();
});

$('guide').addEventListener('click', function () {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/recovery.html') });
});

$('hold').addEventListener('change', function (e) {
  ask('set-hold', { value: e.target.checked });
});

$('clear').addEventListener('click', function () {
  ask('clear-history');
});

if (cfg.homepage) {
  $('demo').href = cfg.homepage.replace(/\/$/, '') + '/demo.html';
  $('demo').hidden = false;
  $('home').href = cfg.homepage.replace(/\/$/, '') + '/#check-your-pc';
  $('home').hidden = false;
}
$('version').textContent = 'v' + (cfg.version || chrome.runtime.getManifest().version);

render();
