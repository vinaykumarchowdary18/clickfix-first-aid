/*
 * ClickFix First Aid: clipboard guard.
 *
 * Runs inside the web page's own JavaScript world ("MAIN" world), before any
 * of the page's scripts. The build wraps it together with the detection engine
 * and the rules, so these names exist here:
 *   CFADetectorAPI  - { createDetector, defang }
 *   CFA_RULES       - the rules from rules/clickfix-rules.json
 *
 * A page can put text on the clipboard in five ways. We wrap all of them:
 *   1. navigator.clipboard.writeText(text)
 *   2. navigator.clipboard.write([ClipboardItem])
 *   3. document.execCommand('copy') on a (hidden) text box
 *   4. a 'copy' handler calling event.clipboardData.setData(...)
 *   5. a 'copy' handler calling event.clipboardData.items.add(text, 'text/plain')
 *
 * Verdict "block": the clipboard gets SAFE_TEXT and a full warning is shown.
 * Verdict "hold":  copies made by the page's own code get HOLD_TEXT, and the
 *                  person can choose "Copy anyway". Copies made by hand pass.
 *
 * Talking to the rest of the extension: we create an element with a CLOSED
 * shadow root and send reports as events on a node inside it. The page cannot
 * reach that node, so it can neither listen in, nor block the reports, nor fake
 * them. The extension's isolated world opens the closed root with
 * chrome.dom.openOrClosedShadowRoot and then removes the element from the page.
 */

var detector = CFADetectorAPI.createDetector(CFA_RULES);

// ---- Built-ins, grabbed before the page can replace them. -------------------
var apply = Reflect.apply;
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var objectCreate = Object.create;
var getPrototypeOf = Object.getPrototypeOf;
var _String = String;
var _CustomEvent = CustomEvent;
var _WeakMap = WeakMap;
var _wmGet = WeakMap.prototype.get;
var _wmSet = WeakMap.prototype.set;
var _wmHas = WeakMap.prototype.has;
var _fnToString = Function.prototype.toString;
var _dispatchEvent = EventTarget.prototype.dispatchEvent;
var _addEventListener = EventTarget.prototype.addEventListener;
var _preventDefault = Event.prototype.preventDefault;
var _toLowerCase = String.prototype.toLowerCase;
var _slice = String.prototype.slice;
var _indexOf = String.prototype.indexOf;
var _then = Promise.prototype.then;
var _Blob = typeof Blob !== 'undefined' ? Blob : null;
var _blobText = _Blob ? _Blob.prototype.text : null;
var _ClipboardItem = typeof ClipboardItem !== 'undefined' ? ClipboardItem : null;
var _getType = _ClipboardItem ? _ClipboardItem.prototype.getType : null;
var _typesGetter = _ClipboardItem ? (getOwnPropertyDescriptor(_ClipboardItem.prototype, 'types') || {}).get : null;
var _Clipboard = typeof Clipboard !== 'undefined' ? Clipboard : null;
var _writeText = _Clipboard ? _Clipboard.prototype.writeText : null;
var _write = _Clipboard ? _Clipboard.prototype.write : null;
var _execCommand = Document.prototype.execCommand;
var _DataTransfer = typeof DataTransfer !== 'undefined' ? DataTransfer : null;
var _setData = _DataTransfer ? _DataTransfer.prototype.setData : null;
var _getData = _DataTransfer ? _DataTransfer.prototype.getData : null;
var _clipboardDataGetter = typeof ClipboardEvent !== 'undefined' ? (getOwnPropertyDescriptor(ClipboardEvent.prototype, 'clipboardData') || {}).get : null;
var _ItemList = typeof DataTransferItemList !== 'undefined' ? DataTransferItemList : null;
var _itemsAdd = _ItemList ? _ItemList.prototype.add : null;
var _createElement = Document.prototype.createElement;
var _attachShadow = Element.prototype.attachShadow;
var _appendChild = Node.prototype.appendChild;
var _documentElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'documentElement') || {}).get;
var _bodyGetter = (getOwnPropertyDescriptor(Document.prototype, 'body') || {}).get;
var _activeElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'activeElement') || {}).get;
var _innerTextGetter = (getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText') || {}).get;
var _nodeValueGetter = (getOwnPropertyDescriptor(Node.prototype, 'nodeValue') || {}).get;
var _parentNodeGetter = (getOwnPropertyDescriptor(Node.prototype, 'parentNode') || {}).get;
var _nodeNameGetter = (getOwnPropertyDescriptor(Node.prototype, 'nodeName') || {}).get;
var _createTreeWalker = Document.prototype.createTreeWalker;
var _nextNode = typeof TreeWalker !== 'undefined' ? TreeWalker.prototype.nextNode : null;
var _detailGetter = (getOwnPropertyDescriptor(CustomEvent.prototype, 'detail') || {}).get;
var _getSelection = window.getSelection;
var _selectionToString = typeof Selection !== 'undefined' ? Selection.prototype.toString : null;
var _taProto = HTMLTextAreaElement.prototype;
var _inProto = HTMLInputElement.prototype;
var _taValue = (getOwnPropertyDescriptor(_taProto, 'value') || {}).get;
var _inValue = (getOwnPropertyDescriptor(_inProto, 'value') || {}).get;
var _taStart = (getOwnPropertyDescriptor(_taProto, 'selectionStart') || {}).get;
var _taEnd = (getOwnPropertyDescriptor(_taProto, 'selectionEnd') || {}).get;
var _inStart = (getOwnPropertyDescriptor(_inProto, 'selectionStart') || {}).get;
var _inEnd = (getOwnPropertyDescriptor(_inProto, 'selectionEnd') || {}).get;

// What goes on the clipboard instead of the command. Both are harmless if
// pasted anywhere: they start with '#' (a comment in PowerShell and bash; in
// the Run box, cmd, File Explorer or zsh they just fail with "not found"), and
// they contain no quotes, pipes, ampersands, dollar signs or redirects.
var SAFE_TEXT = '# STOP. ClickFix First Aid blocked this. A website tried to trick you into running a command on your computer. Close that page. Real human checks never ask you to paste anything.';
var HOLD_TEXT = '# PAUSED. ClickFix First Aid held this copied text so you can check it first. Go back to the page and choose Copy anyway only if you trust the site.';

// Reports carry the whole text (up to this size), so "Copy anyway" copies all of it.
var MAX_SEND = 1000000;
var SEP = '\u001f';
var programmaticCopy = false;
var config = { hold: true, siteAllowed: false };

function s(x) {
  return typeof x === 'string' ? x : x == null ? '' : _String(x);
}

function noop() {}

function addTo(arr, v) {
  defineProperty(arr, arr.length, { value: v, writable: true, enumerable: true, configurable: true });
}

// ---- Private channel to the extension. --------------------------------------
var channel = null;
(function () {
  try {
    var root = _documentElementGetter ? apply(_documentElementGetter, document, []) : null;
    if (!root) return;
    var host = apply(_createElement, document, ['clickfix-first-aid-channel']);
    var shadow = apply(_attachShadow, host, [{ mode: 'closed' }]);
    var node = apply(_createElement, document, ['span']);
    apply(_appendChild, shadow, [node]);
    apply(_appendChild, root, [host]);
    channel = node;
    apply(_addEventListener, node, ['cfa-config', function (ev) {
      var d = s(_detailGetter ? apply(_detailGetter, ev, []) : '');
      config.hold = apply(_indexOf, d, ['hold=0']) === -1;
      config.siteAllowed = apply(_indexOf, d, ['allow=1']) !== -1;
    }]);
  } catch (e) {
    channel = null;
  }
})();

function notify(verdict, how, text) {
  if (!channel) return;
  try {
    var detail = verdict + SEP + how + SEP + apply(_slice, text, [0, MAX_SEND]);
    apply(_dispatchEvent, channel, [new _CustomEvent('cfa-report', { detail: detail })]);
  } catch (e) {
    /* never break the page */
  }
}

// ---- Reading the page. ------------------------------------------------------
var isSubframe = true;
try {
  isSubframe = window.top !== window;
} catch (e) {
  isSubframe = true;
}

function body() {
  try {
    return _bodyGetter ? apply(_bodyGetter, document, []) : null;
  } catch (e) {
    return null;
  }
}

function visibleText() {
  var b = body();
  try {
    return b && _innerTextGetter ? s(apply(_innerTextGetter, b, [])) : '';
  } catch (e) {
    return '';
  }
}

// Text of hidden elements too, but not code or data (<script>, <style>,
// <textarea>...), which often mention "Ctrl+V" on perfectly normal sites.
var SKIP = objectCreate(null);
SKIP.SCRIPT = 1; SKIP.STYLE = 1; SKIP.NOSCRIPT = 1; SKIP.TEXTAREA = 1; SKIP.TEMPLATE = 1;
function hiddenText() {
  var b = body();
  if (!b || !_createTreeWalker || !_nextNode) return '';
  var out = '';
  try {
    var walker = apply(_createTreeWalker, document, [b, 4 /* NodeFilter.SHOW_TEXT */]);
    var n;
    var count = 0;
    while ((n = apply(_nextNode, walker, [])) && out.length < 200000 && count++ < 50000) {
      var p = apply(_parentNodeGetter, n, []);
      var name = p ? apply(_nodeNameGetter, p, []) : '';
      if (SKIP[name] === 1) continue;
      out += s(apply(_nodeValueGetter, n, [])) + '\n';
    }
  } catch (e) {
    /* partial text is fine */
  }
  return out;
}

// Only text the person can actually see may lead to a full block. Hidden text
// can only add "this looks like Win+R and paste" (weak), which means pausing,
// so it is only read when that could change the outcome.
function analyzeThisPage(needHidden) {
  var visible = detector.analyzePage(visibleText());
  if (visible.strong) return { weak: true, strong: true };
  if (!needHidden || visible.weak) return { weak: visible.weak, strong: false };
  var hidden = detector.analyzePage(hiddenText());
  return { weak: hidden.weak, strong: false };
}

// Did the page's copy handler just pass on what the person selected (normal
// for editors like Google Docs), or did it swap in different text?
// Collapse all whitespace (plain loop: no overridable string or regex methods).
var WS = objectCreate(null); // no prototype, so a page cannot add entries to it
WS[' '] = 1; WS['\t'] = 1; WS['\r'] = 1; WS['\n'] = 1; WS['\u00a0'] = 1;
function squash(t) {
  var out = '';
  var pendingSpace = false;
  for (var i = 0; i < t.length; i++) {
    var c = t[i];
    if (WS[c] === 1) {
      pendingSpace = out !== '';
      continue;
    }
    if (pendingSpace) out += ' ';
    pendingSpace = false;
    out += c;
  }
  return out;
}
function sameAsSelection(t) {
  var sel = selectedText();
  return sel !== '' && squash(sel) === squash(t);
}

function protoChainHas(el, proto) {
  var p = el;
  for (var i = 0; i < 10 && p; i++) {
    p = getPrototypeOf(p);
    if (p === proto) return true;
  }
  return false;
}

function selectedText() {
  try {
    var el = _activeElementGetter ? apply(_activeElementGetter, document, []) : null;
    if (el) {
      var isTa = protoChainHas(el, _taProto);
      var isIn = !isTa && protoChainHas(el, _inProto);
      if (isTa || isIn) {
        var v = s(apply(isTa ? _taValue : _inValue, el, []));
        var a = apply(isTa ? _taStart : _inStart, el, []);
        var b = apply(isTa ? _taEnd : _inEnd, el, []);
        if (typeof a === 'number' && typeof b === 'number' && b > a) return apply(_slice, v, [a, b]);
      }
    }
    var sel = _getSelection ? apply(_getSelection, window, []) : null;
    return sel && _selectionToString ? s(apply(_selectionToString, sel, [])) : '';
  } catch (e) {
    return '';
  }
}

// ---- The decision. ----------------------------------------------------------
// Returns null (let it through) or 'block' | 'hold' | 'note'.
// programmatic: the page's own code is writing the text (not a person's Ctrl+C).
function evaluate(text, programmatic) {
  if (text.length < 4) return null;
  var cmd = detector.analyzeCommand(text);
  if (!detector.worthChecking(cmd)) return null;
  var d = detector.decide(cmd, analyzeThisPage(cmd.danger), { subframe: isSubframe });
  var v = d.verdict;
  if (v === 'block') return 'block';
  if (v !== 'hold' || !programmatic) return null;
  if (config.siteAllowed) return null;
  return config.hold ? 'hold' : 'note';
}

function replacementFor(verdict) {
  return verdict === 'block' ? SAFE_TEXT : HOLD_TEXT;
}

// ---- Wrapping built-in functions, and keeping them looking native. ----------
var nativeLook = new _WeakMap();

function wrap(proto, name, fn) {
  try {
    var desc = getOwnPropertyDescriptor(proto, name);
    if (!desc || typeof desc.value !== 'function') return;
    defineProperty(fn, 'name', { value: name, configurable: true });
    defineProperty(fn, 'length', { value: desc.value.length, configurable: true });
    apply(_wmSet, nativeLook, [fn, 'function ' + name + '() { [native code] }']);
    defineProperty(proto, name, { value: fn, writable: desc.writable, enumerable: desc.enumerable, configurable: desc.configurable });
  } catch (e) {
    /* ignore */
  }
}

// Detection by toString() is a cat-and-mouse game; this covers the easy check.
wrap(Function.prototype, 'toString', function toString() {
  if (apply(_wmHas, nativeLook, [this])) return apply(_wmGet, nativeLook, [this]);
  return apply(_fnToString, this, arguments);
});

// 1. navigator.clipboard.writeText. The text is converted to a string exactly
// once, so a page cannot show us one thing and give the browser another.
if (_writeText) {
  wrap(_Clipboard.prototype, 'writeText', function writeText(text) {
    var t = s(text);
    var v = evaluate(t, true);
    var p = apply(_writeText, this, [v === 'block' || v === 'hold' ? replacementFor(v) : t]);
    if (v) apply(_then, p, [function () { notify(v, 'writeText', t); }, noop]);
    return p;
  });
}

// 2. navigator.clipboard.write([ClipboardItem]). The browser call happens right
// away (so slow, promise-based items keep working); the text inside is checked
// before it is handed over.
if (_write && _ClipboardItem && _Blob && _getType && _blobText && _typesGetter) {
  wrap(_Clipboard.prototype, 'write', function write(items) {
    var self = this;
    try {
      if (!items || items.length !== 1) return apply(_write, self, arguments);
      var item = items[0];
      if (!protoChainHas(item, _ClipboardItem.prototype)) return apply(_write, self, arguments);
      var types = apply(_typesGetter, item, []);
      var hasText = false;
      for (var i = 0; i < types.length; i++) if (types[i] === 'text/plain') hasText = true;
      if (!hasText) return apply(_write, self, arguments);

      var textP = apply(_then, apply(_getType, item, ['text/plain']), [function (blob) { return apply(_blobText, blob, []); }]);
      var decisionP = apply(_then, textP, [function (t) { return { t: s(t), v: evaluate(s(t), true) }; }]);
      var map = objectCreate(null);
      for (var j = 0; j < types.length; j++) {
        (function (type) {
          defineProperty(map, type, {
            enumerable: true,
            value: apply(_then, decisionP, [function (x) {
              if (x.v === 'block' || x.v === 'hold') {
                if (type === 'text/plain' || type === 'text/html') return new _Blob([replacementFor(x.v)], { type: type });
              } else if (type === 'text/plain') {
                return new _Blob([x.t], { type: 'text/plain' });
              }
              return apply(_getType, item, [type]);
            }])
          });
        })(types[j]);
      }
      var p = apply(_write, self, [[new _ClipboardItem(map)]]);
      apply(_then, p, [function () {
        apply(_then, decisionP, [function (x) { if (x.v) notify(x.v, 'write', x.t); }, noop]);
      }, noop]);
      return p;
    } catch (e) {
      return apply(_write, self, arguments);
    }
  });
}

// 3. document.execCommand('copy'): note that the page's code started the copy;
// the 'copy' listener below does the checking.
wrap(Document.prototype, 'execCommand', function execCommand(command) {
  var c = s(command);
  var args = [c];
  for (var i = 1; i < arguments.length; i++) addTo(args, arguments[i]);
  var lower = apply(_toLowerCase, c, []);
  if (lower === 'copy' || lower === 'cut') {
    programmaticCopy = true;
    try {
      return apply(_execCommand, this, args);
    } finally {
      programmaticCopy = false;
    }
  }
  return apply(_execCommand, this, args);
});

function guardEvent(e, text, how, programmatic) {
  var v = evaluate(s(text), programmatic);
  if (!v) return;
  notify(v, how, s(text));
  if (v === 'block' || v === 'hold') {
    try {
      var cd = _clipboardDataGetter ? apply(_clipboardDataGetter, e, []) : null;
      if (cd) apply(_setData, cd, ['text/plain', replacementFor(v)]);
      apply(_preventDefault, e, []);
    } catch (x) {
      /* ignore */
    }
  }
}

// 4a. Any copy (keyboard, menu or execCommand): check what is selected.
function onCopyStart(e) {
  guardEvent(e, selectedText(), programmaticCopy ? 'execCommand' : 'copy', programmaticCopy);
}
apply(_addEventListener, window, ['copy', onCopyStart, true]);
apply(_addEventListener, window, ['cut', onCopyStart, true]);

// 4b. Last look at the end of the copy event, in case something slipped in.
function onCopyEnd(e) {
  try {
    var cd = _clipboardDataGetter ? apply(_clipboardDataGetter, e, []) : null;
    if (!cd || !_getData) return;
    var t = s(apply(_getData, cd, ['text/plain']));
    if (t === SAFE_TEXT || t === HOLD_TEXT || t === '') return;
    guardEvent(e, t, 'copy event', programmaticCopy || !sameAsSelection(t));
  } catch (x) {
    /* ignore */
  }
}
apply(_addEventListener, window, ['copy', onCopyEnd, false]);
apply(_addEventListener, window, ['cut', onCopyEnd, false]);

function isTextType(type) {
  var f = apply(_toLowerCase, s(type), []);
  return f === 'text/plain' || f === 'text' || f === 'text/unicode';
}

// 4c. clipboardData.setData from the page's own copy handler.
if (_setData) {
  wrap(_DataTransfer.prototype, 'setData', function setData(format, data) {
    var f = s(format);
    var t = s(data);
    if (isTextType(f)) {
      var v = evaluate(t, programmaticCopy || !sameAsSelection(t));
      if (v) notify(v, 'setData', t);
      if (v === 'block' || v === 'hold') return apply(_setData, this, [f, replacementFor(v)]);
    }
    return apply(_setData, this, [f, t]);
  });
}

// 5. clipboardData.items.add(text, 'text/plain') from a copy handler.
if (_itemsAdd) {
  wrap(_ItemList.prototype, 'add', function add(data, type) {
    if (typeof data === 'string' || (arguments.length >= 2 && !(data && typeof data === 'object'))) {
      var t = s(data);
      var ty = s(type);
      if (isTextType(ty)) {
        var v = evaluate(t, programmaticCopy || !sameAsSelection(t));
        if (v) notify(v, 'items.add', t);
        if (v === 'block' || v === 'hold') return apply(_itemsAdd, this, [replacementFor(v), ty]);
      }
      return apply(_itemsAdd, this, [t, ty]);
    }
    return apply(_itemsAdd, this, arguments);
  });
}
