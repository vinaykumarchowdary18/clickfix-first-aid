/*
 * ClickFix First Aid: on-page warnings (runs in the extension's isolated world).
 *
 * Everything is drawn inside a closed shadow root, so the web page cannot read,
 * restyle or click our buttons. All text is inserted as plain text, never HTML.
 *
 * Two slots:
 *   main - the full-screen block warning, or the "paused" panel, or a note
 *   top  - the banner for pages whose text looks like a ClickFix trap
 * The block warning always wins and clears everything else.
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
    'h2{font-size:16px;line-height:1.3;margin:0 0 6px;color:#78350f}',
    'p{font-size:15px;line-height:1.55;margin:0 0 12px}',
    '.ok{background:#ecfdf5;color:#065f46;border-radius:10px;padding:10px 12px;font-size:14px;margin:12px 0}',
    'ul{margin:6px 0 14px;padding-left:20px}',
    'li{font-size:14px;line-height:1.5;margin:3px 0}',
    'details{margin:4px 0 14px;font-size:13px}',
    'summary{cursor:pointer;color:#475569}',
    'pre{white-space:pre-wrap;word-break:break-all;background:#f1f5f9;border-radius:8px;padding:10px;font:12px/1.45 ui-monospace,Consolas,monospace;color:#334155;margin:8px 0 0;max-height:160px;overflow:auto}',
    '.label{font-size:12px;color:#64748b;margin-top:8px}',
    '.row{display:flex;flex-wrap:wrap;gap:10px;margin-top:6px}',
    'button{font-size:15px;font-weight:600;border-radius:10px;padding:11px 18px;border:1px solid transparent;cursor:pointer}',
    'button:focus-visible{outline:3px solid #2563eb;outline-offset:2px}',
    '.primary{background:#b91c1c;color:#fff}',
    '.primary:hover{background:#991b1b}',
    '.secondary{background:#fff;color:#0f172a;border-color:#cbd5e1}',
    '.link{background:none;border:none;color:#1d4ed8;padding:6px 0;font-weight:500;font-size:14px;text-decoration:underline}',
    '.quiet{background:none;border:none;color:#64748b;padding:6px 0;font-weight:500;font-size:13px}',
    '.foot{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:14px;border-top:1px solid #e2e8f0;padding-top:10px}',
    '.panel{position:fixed;right:16px;bottom:16px;z-index:2147483647;width:min(420px,calc(100vw - 32px));max-height:calc(100vh - 32px);overflow:auto;background:#fffbeb;color:#422006;border:1px solid #f59e0b;border-radius:14px;box-shadow:0 16px 40px rgba(0,0,0,.25);padding:16px 18px}',
    '.panel:focus{outline:none}',
    '.panel p{font-size:14px;margin:0 0 8px}',
    '.panel li{font-size:13px}',
    '.panel .row button{font-size:14px;padding:9px 14px}',
    '.panel .warnbtn{background:#92400e;color:#fff}',
    '.note{border-color:#fcd34d}',
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
    '.panel{background:#1c1917;color:#fde68a;border-color:#b45309}',
    'h2{color:#fcd34d}',
    '.panel .warnbtn{background:#f59e0b;color:#1c1917}',
    '}'
  ].join('');

  // Text from the page is shown only inside a labelled box, with web links
  // broken and anything that looks like a phone number removed, so a page
  // cannot use our warning to advertise a fake "support" number.
  var RE_PHONE = /\+?\d[\d\s().-]{6,}\d/g;
  function cleanPreview(text) {
    return String(text || '').replace(RE_PHONE, '[number removed]');
  }

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
    return { host: host, shadow: shadow, state: state };
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

  // Only real clicks by the person count. Our buttons sit in a closed shadow
  // root the page cannot reach, and this is a second lock on the same door.
  function trusted(fn) {
    return function (e) {
      if (!e || e.isTrusted !== true) return;
      fn(e);
    };
  }

  var slots = { main: null, top: null };

  function clear(slot) {
    if (slots[slot]) unmount(slots[slot]);
    slots[slot] = null;
  }

  function preview(container, text, label) {
    if (!text) return;
    var det = el('details');
    det.appendChild(el('summary', null, label));
    det.appendChild(el('pre', null, cleanPreview(text)));
    det.appendChild(el('div', { class: 'label' }, 'This is the text the page tried to copy. Do not run it.'));
    container.appendChild(det);
  }

  function reasonList(container, reasons, max) {
    if (!reasons || !reasons.length) return;
    var ul = el('ul');
    for (var i = 0; i < reasons.length && i < max; i++) ul.appendChild(el('li', null, String(reasons[i])));
    container.appendChild(ul);
  }

  // Full-screen warning: the clipboard already holds a harmless message.
  function showBlocked(info) {
    if (slots.main && slots.main.state === 'blocked') return;
    clear('main');
    clear('top');
    var m = mount('blocked');
    slots.main = m;

    var back = el('div', { class: 'backdrop', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'cfa-title' });
    var card = el('div', { class: 'card' });
    card.appendChild(el('span', { class: 'badge' }, 'ClickFix First Aid'));
    card.appendChild(el('h1', { id: 'cfa-title' }, 'Stop. This page tried to trick you.'));
    card.appendChild(el('p', null,
      'It copied a command to your clipboard and wants you to paste it into your computer. ' +
      'Real "I am not a robot" checks never ask you to press Win+R, open Terminal, or paste anything.'));
    card.appendChild(el('div', { class: 'ok' },
      'You are safe for now. We replaced your clipboard with a harmless message, so nothing bad happens even if you paste.'));
    if (info.reasons && info.reasons.length) {
      card.appendChild(el('p', null, 'Why we blocked it:'));
      reasonList(card, info.reasons, 6);
    }
    preview(card, info.preview, 'Show the blocked text');

    var row = el('div', { class: 'row' });
    var close = el('button', { class: 'primary', type: 'button' }, 'Close this tab');
    close.addEventListener('click', trusted(function () { send('cfa-close-tab'); }));
    var goBack = el('button', { class: 'secondary', type: 'button' }, 'Go back');
    goBack.addEventListener('click', trusted(function () {
      if (history.length > 1) history.back();
      else send('cfa-close-tab');
    }));
    row.appendChild(close);
    row.appendChild(goBack);
    card.appendChild(row);

    var foot = el('div', { class: 'foot' });
    var guide = el('button', { class: 'link', type: 'button' }, 'I already ran something like this. What now?');
    guide.addEventListener('click', trusted(function () { send('cfa-open-guide'); }));
    var dismiss = el('button', { class: 'quiet', type: 'button' }, 'Dismiss');
    dismiss.addEventListener('click', trusted(function () { clear('main'); }));
    foot.appendChild(guide);
    foot.appendChild(dismiss);
    card.appendChild(foot);

    back.appendChild(card);
    m.shadow.appendChild(back);
    try { close.focus(); } catch (e) { /* ignore */ }
  }

  // Corner panel: a copied command was paused. The person decides.
  // handlers: { copyAnyway(): Promise, allowSite(): Promise }
  function showHeld(info, handlers) {
    if (slots.main && slots.main.state === 'blocked') return;
    clear('main');
    var m = mount('held');
    slots.main = m;

    var tooLong = info.rule === 'too-long';
    var canCopy = handlers.canCopy !== false;
    var box = el('div', { class: 'panel', role: 'dialog', 'aria-labelledby': 'cfa-held', tabindex: '-1' });
    box.appendChild(el('h2', { id: 'cfa-held' }, tooLong ? 'ClickFix First Aid paused a very long copy' : 'ClickFix First Aid paused a copied command'));
    box.appendChild(el('p', null, tooLong
      ? 'This page copied more text than we can check. A trap page could hide a command at the end of it.'
      : 'This page copied a command that downloads and runs a program. Trap pages do this to make you paste it into Win+R or Terminal.'));
    box.appendChild(el('p', null, canCopy
      ? 'If you copied it yourself from a site you trust, like developer documentation, you can copy it anyway.'
      : 'It is too long to copy from here. If you trust this site, select the text and copy it by hand.'));
    reasonList(box, info.reasons, 4);

    // Buttons come before the command preview, so Tab order is predictable:
    // panel -> Copy anyway -> Always allow -> Dismiss -> Show the command.
    var row = el('div', { class: 'row' });
    var anyway = el('button', { class: 'warnbtn', type: 'button' }, 'Copy anyway');
    var allow = el('button', { class: 'secondary', type: 'button' }, 'Always allow on this site');
    var dismiss = el('button', { class: 'quiet', type: 'button' }, 'Dismiss');
    if (!canCopy) {
      anyway.hidden = true;
      allow.hidden = true;
    }
    function done(message) {
      row.textContent = '';
      row.appendChild(el('p', null, message));
      setTimeout(function () { if (slots.main === m) clear('main'); }, 1800);
    }
    anyway.addEventListener('click', trusted(function () {
      handlers.copyAnyway().then(function () { done('Copied.'); }, function () { done('Could not copy. Copy it by hand instead.'); });
    }));
    allow.addEventListener('click', trusted(function () {
      handlers.allowSite().then(function () { done('Copied. This site will not be paused again.'); }, function () { done('Saved. Copy it again.'); });
    }));
    dismiss.addEventListener('click', trusted(function () { clear('main'); }));
    row.appendChild(anyway);
    row.appendChild(allow);
    row.appendChild(dismiss);
    box.appendChild(row);
    preview(box, info.preview, 'Show the command');
    m.shadow.appendChild(box);
    try { box.focus(); } catch (e) { /* ignore */ }
  }

  // Small note, used when pausing is switched off in the settings.
  function showNote(info) {
    if (slots.main) return;
    var m = mount('noted');
    slots.main = m;
    var box = el('div', { class: 'panel note', role: 'status' });
    box.appendChild(el('p', null,
      (info.rule === 'too-long'
        ? 'Heads up: this page copied more text than we can check. '
        : 'Heads up: this page copied a command that downloads and runs a program. ') +
      'Never paste it into Win+R or Terminal just because a page asked you to "verify" something.'));
    var row = el('div', { class: 'row' });
    var ok = el('button', { class: 'secondary', type: 'button' }, 'Got it');
    ok.addEventListener('click', trusted(function () { clear('main'); }));
    row.appendChild(ok);
    box.appendChild(row);
    m.shadow.appendChild(box);
    setTimeout(function () { if (slots.main === m) clear('main'); }, 15000);
  }

  // Top banner when the page text itself looks like a ClickFix trap.
  function showLureBanner() {
    if (slots.top) return;
    if (slots.main && slots.main.state === 'blocked') return;
    var m = mount('lure');
    slots.top = m;
    var bar = el('div', { class: 'banner', role: 'alert' });
    bar.appendChild(el('p', null,
      'Warning from ClickFix First Aid: this page is asking you to run something on your computer. ' +
      'Real human checks never ask you to press Win+R, open Terminal, or paste anything. Close this page.'));
    var close = el('button', { class: 'primary', type: 'button' }, 'Close this tab');
    close.addEventListener('click', trusted(function () { send('cfa-close-tab'); }));
    var dismiss = el('button', { class: 'secondary', type: 'button' }, 'Dismiss');
    dismiss.addEventListener('click', trusted(function () { clear('top'); }));
    bar.appendChild(close);
    bar.appendChild(dismiss);
    m.shadow.appendChild(bar);
  }

  self.CFAUI = { showBlocked: showBlocked, showHeld: showHeld, showNote: showNote, showLureBanner: showLureBanner };
})();
