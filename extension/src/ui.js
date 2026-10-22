/*
 * ClickFix First Aid: on-page warnings (runs in the extension's isolated world).
 *
 * Everything is drawn inside a closed "shadow root", so the web page cannot
 * read, restyle or click our buttons. All text is inserted as plain text,
 * never as HTML.
 */
(function () {
  'use strict';

  var HOST_TAG = 'clickfix-first-aid-ui';

  var CSS = [
    ':host{all:initial}',
    '*{box-sizing:border-box;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}',
    '.backdrop{position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,.86);display:flex;align-items:center;justify-content:center;padding:16px}',
    '.card{background:#fff;color:#0f172a;max-width:580px;width:100%;max-height:calc(100vh - 32px);overflow:auto;border-radius:16px;box-shadow:0 24px 64px rgba(0,0,0,.45);padding:28px 28px 22px}',
    '.badge{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#b91c1c;background:#fee2e2;border-radius:999px;padding:5px 12px}',
    'h1{font-size:24px;line-height:1.25;margin:14px 0 10px;color:#991b1b}',
    'p{font-size:15px;line-height:1.55;margin:0 0 12px}',
    '.ok{background:#ecfdf5;color:#065f46;border-radius:10px;padding:10px 12px;font-size:14px;margin:12px 0}',
    'ul{margin:6px 0 14px;padding-left:20px}',
    'li{font-size:14px;line-height:1.5;margin:3px 0}',
    'details{margin:4px 0 16px;font-size:13px}',
    'summary{cursor:pointer;color:#475569}',
    'pre{white-space:pre-wrap;word-break:break-all;background:#f1f5f9;border-radius:8px;padding:10px;font:12px/1.45 ui-monospace,Consolas,monospace;color:#334155;margin:8px 0 0;max-height:160px;overflow:auto}',
    '.row{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}',
    'button{font-size:15px;font-weight:600;border-radius:10px;padding:11px 18px;border:1px solid transparent;cursor:pointer}',
    '.primary{background:#b91c1c;color:#fff}',
    '.primary:hover{background:#991b1b}',
    '.secondary{background:#fff;color:#0f172a;border-color:#cbd5e1}',
    '.link{background:none;border:none;color:#1d4ed8;padding:6px 0;font-weight:500;font-size:14px;text-decoration:underline}',
    '.quiet{background:none;border:none;color:#64748b;padding:6px 0;font-weight:500;font-size:13px}',
    '.foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:14px;border-top:1px solid #e2e8f0;padding-top:10px}',
    '.toast{position:fixed;right:16px;bottom:16px;z-index:2147483647;max-width:380px;background:#fffbeb;color:#78350f;border:1px solid #fcd34d;border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.2);padding:14px 16px}',
    '.toast p{font-size:14px;margin:0 0 8px}',
    '.toast .row button{font-size:13px;padding:7px 12px}',
    '.banner{position:fixed;left:0;right:0;top:0;z-index:2147483647;background:#991b1b;color:#fff;padding:12px 16px;display:flex;flex-wrap:wrap;align-items:center;gap:10px 16px;box-shadow:0 6px 20px rgba(0,0,0,.3)}',
    '.banner p{margin:0;font-size:15px;flex:1 1 320px}',
    '.banner button{font-size:14px;padding:8px 14px}',
    '.banner .secondary{background:transparent;color:#fff;border-color:rgba(255,255,255,.6)}',
    '.banner .primary{background:#fff;color:#991b1b}',
    '@media (prefers-color-scheme:dark){',
    '.card{background:#0f172a;color:#e2e8f0}',
    'h1{color:#fca5a5}',
    '.badge{background:#450a0a;color:#fecaca}',
    '.ok{background:#052e16;color:#bbf7d0}',
    'pre{background:#1e293b;color:#cbd5e1}',
    '.secondary{background:#0f172a;color:#e2e8f0;border-color:#475569}',
    '.link{color:#93c5fd}',
    '.foot{border-color:#1e293b}',
    '}'
  ].join('');

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  function mount(state) {
    var root = document.documentElement || document;
    var host = document.createElement(HOST_TAG);
    host.setAttribute('data-state', state);
    var shadow = host.attachShadow({ mode: 'closed' });
    shadow.appendChild(el('style', null, CSS));
    root.appendChild(host);
    return { host: host, shadow: shadow };
  }

  function unmount(m) {
    if (m && m.host && m.host.parentNode) m.host.parentNode.removeChild(m.host);
  }

  function send(type, extra) {
    try {
      var msg = { type: type };
      if (extra) for (var k in extra) msg[k] = extra[k];
      chrome.runtime.sendMessage(msg);
    } catch (e) {
      /* extension was reloaded */
    }
  }

  var current = null;

  // Big full-screen warning after we blocked an attack command.
  function showBlocked(info) {
    if (current && current.kind === 'blocked') return;
    if (current) unmount(current.m);
    var m = mount('blocked');
    current = { kind: 'blocked', m: m };

    var back = el('div', { class: 'backdrop', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'cfa-title' });
    var card = el('div', { class: 'card' });
    card.appendChild(el('span', { class: 'badge' }, 'ClickFix First Aid'));
    card.appendChild(el('h1', { id: 'cfa-title' }, 'Stop. This page tried to trick you.'));
    card.appendChild(el('p', null,
      'It secretly copied a command to your clipboard and wants you to paste it into your computer. ' +
      'Real "I am not a robot" checks never ask you to press Win+R, open Terminal, or paste anything.'));
    card.appendChild(el('div', { class: 'ok' },
      'You are safe for now. We replaced your clipboard with a harmless message, so nothing bad happens even if you paste.'));

    if (info.reasons && info.reasons.length) {
      card.appendChild(el('p', null, 'Why we blocked it:'));
      var ul = el('ul');
      for (var i = 0; i < info.reasons.length && i < 6; i++) ul.appendChild(el('li', null, info.reasons[i]));
      card.appendChild(ul);
    }

    if (info.preview) {
      var det = el('details');
      det.appendChild(el('summary', null, 'Show the blocked command (do not run it)'));
      det.appendChild(el('pre', null, info.preview));
      card.appendChild(det);
    }

    var row = el('div', { class: 'row' });
    var close = el('button', { class: 'primary', type: 'button' }, 'Close this tab');
    close.addEventListener('click', function () { send('cfa-close-tab'); });
    var goBack = el('button', { class: 'secondary', type: 'button' }, 'Go back');
    goBack.addEventListener('click', function () {
      if (history.length > 1) history.back();
      else send('cfa-close-tab');
    });
    row.appendChild(close);
    row.appendChild(goBack);
    card.appendChild(row);

    var foot = el('div', { class: 'foot' });
    var guide = el('button', { class: 'link', type: 'button' }, 'I already ran something like this. What now?');
    guide.addEventListener('click', function () { send('cfa-open-guide'); });
    var dismiss = el('button', { class: 'quiet', type: 'button' }, 'Dismiss');
    dismiss.addEventListener('click', function () { unmount(m); current = null; });
    foot.appendChild(guide);
    foot.appendChild(dismiss);
    card.appendChild(foot);

    back.appendChild(card);
    m.shadow.appendChild(back);
    try { close.focus(); } catch (e) { /* ignore */ }
  }

  // Small corner note for installer commands on developer sites.
  function showToast(info, onMuteSite) {
    if (current) return;
    var m = mount('warned');
    current = { kind: 'warned', m: m };
    var box = el('div', { class: 'toast', role: 'status' });
    box.appendChild(el('p', null,
      'Heads up: this site copied a command that downloads and runs a program. That is normal on developer sites. ' +
      'Never paste it into Win+R or Terminal just because a page asked you to "verify" something.'));
    var row = el('div', { class: 'row' });
    var ok = el('button', { class: 'secondary', type: 'button' }, 'Got it');
    var mute = el('button', { class: 'quiet', type: 'button' }, 'Do not show on this site');
    function done() { unmount(m); if (current && current.m === m) current = null; }
    ok.addEventListener('click', done);
    mute.addEventListener('click', function () { if (onMuteSite) onMuteSite(); done(); });
    row.appendChild(ok);
    row.appendChild(mute);
    box.appendChild(row);
    m.shadow.appendChild(box);
    setTimeout(done, 15000);
  }

  // Top banner when the page text itself looks like a ClickFix trap.
  function showLureBanner() {
    if (current) return;
    var m = mount('lure');
    current = { kind: 'lure', m: m };
    var bar = el('div', { class: 'banner', role: 'alert' });
    bar.appendChild(el('p', null,
      'Warning from ClickFix First Aid: this page is asking you to run something on your computer. ' +
      'Real human checks never ask you to press Win+R, open Terminal, or paste anything. Close this page.'));
    var close = el('button', { class: 'primary', type: 'button' }, 'Close this tab');
    close.addEventListener('click', function () { send('cfa-close-tab'); });
    var dismiss = el('button', { class: 'secondary', type: 'button' }, 'Dismiss');
    dismiss.addEventListener('click', function () { unmount(m); current = null; });
    bar.appendChild(close);
    bar.appendChild(dismiss);
    m.shadow.appendChild(bar);
  }

  self.CFAUI = { showBlocked: showBlocked, showToast: showToast, showLureBanner: showLureBanner };
})();
