/*
 * ClickFix First Aid: clipboard guard.
 *
 * This code runs inside the web page's own JavaScript world ("MAIN" world),
 * before any of the page's scripts. The build step wraps it together with the
 * detection engine and the rules, so these names exist here:
 *   CFADetectorAPI  - { createDetector, defang }
 *   CFA_RULES       - the rules from rules/clickfix-rules.json
 *
 * A ClickFix page puts a command on your clipboard in one of four ways:
 *   1. navigator.clipboard.writeText(text)
 *   2. navigator.clipboard.write([ClipboardItem])
 *   3. document.execCommand('copy') on a hidden text box
 *   4. a 'copy' event handler that calls event.clipboardData.setData(...)
 * We wrap all four. If the text is an attack command, the clipboard gets a
 * harmless message instead, and the extension shows a warning.
 */

var detector = CFADetectorAPI.createDetector(CFA_RULES);

// Grab built-in functions now, before the page can replace them.
var apply = Reflect.apply;
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var _String = String;
var _CustomEvent = CustomEvent;
var _jsonStringify = JSON.stringify;
var _dispatchEvent = EventTarget.prototype.dispatchEvent;
var _addEventListener = EventTarget.prototype.addEventListener;
var _preventDefault = Event.prototype.preventDefault;
var _toLowerCase = String.prototype.toLowerCase;
var _slice = String.prototype.slice;
var _dateNow = Date.now;
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
var _setData = typeof DataTransfer !== 'undefined' ? DataTransfer.prototype.setData : null;
var _bodyGetter = (getOwnPropertyDescriptor(Document.prototype, 'body') || {}).get;
var _activeElementGetter = (getOwnPropertyDescriptor(Document.prototype, 'activeElement') || {}).get;
var _innerTextGetter = (getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText') || {}).get;
var _textContentGetter = (getOwnPropertyDescriptor(Node.prototype, 'textContent') || {}).get;
var _getSelection = window.getSelection;
var _selectionToString = typeof Selection !== 'undefined' ? Selection.prototype.toString : null;
var _TextArea = HTMLTextAreaElement;
var _Input = HTMLInputElement;
var _taValue = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value') || {}).get;
var _inValue = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value') || {}).get;
var _taStart = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'selectionStart') || {}).get;
var _taEnd = (getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'selectionEnd') || {}).get;
var _inStart = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionStart') || {}).get;
var _inEnd = (getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionEnd') || {}).get;
var _getPrototypeOf = Object.getPrototypeOf;
var _taProto = HTMLTextAreaElement.prototype;
var _inProto = HTMLInputElement.prototype;

// What goes on the clipboard instead of the attack. Safe to paste anywhere:
// it starts with '#', so PowerShell and Mac/Linux shells treat it as a comment,
// and in the Run box or File Explorer it simply fails to open. It contains no
// quotes, pipes, ampersands or other characters a shell would act on.
var SAFE_TEXT = '# STOP. ClickFix First Aid blocked this. A website tried to trick you into running a command on your computer. Close that page. Real human checks never ask you to paste anything.';

var MAX_SEND = 20000;
var lastText = '';
var lastTime = 0;
var programmaticCopy = false;

function s(x) {
  return x == null ? '' : _String(x);
}

// Is this code running inside a frame embedded in another page?
var isSubframe = true;
try {
  isSubframe = window.top !== window;
} catch (e) {
  isSubframe = true;
}

function bodyText(getter) {
  try {
    var body = _bodyGetter ? apply(_bodyGetter, document, []) : null;
    if (!body || !getter) return '';
    return s(apply(getter, body, []));
  } catch (e) {
    return '';
  }
}

// Look at the visible text first. Trap pages often copy the command BEFORE
// they un-hide their "Win+R, Ctrl+V" steps, so if the visible text looks
// innocent, also look at hidden text.
function analyzeThisPage() {
  var page = detector.analyzePage(bodyText(_innerTextGetter));
  if (!page.weak) {
    var hidden = detector.analyzePage(bodyText(_textContentGetter));
    if (hidden.weak) page = hidden;
  }
  return page;
}

function protoChainHas(el, proto) {
  var p = el;
  for (var i = 0; i < 10 && p; i++) {
    p = _getPrototypeOf(p);
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

// Returns null (fine) or { verdict: 'block' | 'warn', ... }.
function evaluate(text) {
  var t = s(text);
  if (t.length < 4) return null;
  var cmd = detector.analyzeCommand(t);
  if (!cmd.hasExec) return null; // fast path: not a command at all
  var d = detector.decide(cmd, analyzeThisPage(), { subframe: isSubframe });
  if (d.verdict === 'allow') return null;
  return d;
}

// Tell the extension (isolated world) what happened. The extension re-checks
// the text itself, so a page cannot fake a warning with its own wording.
function notify(text, how, verdict) {
  var now = apply(_dateNow, Date, []);
  if (text === lastText && now - lastTime < 1500) return;
  lastText = text;
  lastTime = now;
  try {
    var detail = apply(_jsonStringify, null, [{ text: apply(_slice, s(text), [0, MAX_SEND]), how: how, verdict: verdict }]);
    apply(_dispatchEvent, document, [new _CustomEvent('clickfix-first-aid', { detail: detail })]);
  } catch (e) {
    /* never break the page */
  }
}

function replaceMethod(proto, name, fn) {
  try {
    var desc = getOwnPropertyDescriptor(proto, name);
    if (!desc) return;
    defineProperty(proto, name, {
      value: fn,
      writable: desc.writable,
      enumerable: desc.enumerable,
      configurable: desc.configurable
    });
  } catch (e) {
    /* ignore */
  }
}

// 1. navigator.clipboard.writeText
if (_Clipboard && _writeText) {
  replaceMethod(_Clipboard.prototype, 'writeText', function writeText(text) {
    var d = evaluate(text);
    if (d) {
      notify(text, 'writeText', d.verdict);
      if (d.verdict === 'block') return apply(_writeText, this, [SAFE_TEXT]);
    }
    return apply(_writeText, this, arguments);
  });
}

// 2. navigator.clipboard.write([ClipboardItem])
if (_Clipboard && _write && _ClipboardItem && _Blob && _getType && _blobText) {
  replaceMethod(_Clipboard.prototype, 'write', function write(items) {
    var self = this;
    var args = arguments;
    try {
      var item = items && items[0];
      var types = item && _typesGetter ? apply(_typesGetter, item, []) : [];
      var hasText = false;
      for (var i = 0; types && i < types.length; i++) if (types[i] === 'text/plain') hasText = true;
      if (hasText) {
        var blobPromise = apply(_getType, item, ['text/plain']);
        var textPromise = apply(_then, blobPromise, [function (blob) { return apply(_blobText, blob, []); }]);
        return apply(_then, textPromise, [function (text) {
          var d = evaluate(text);
          if (d) {
            notify(text, 'write', d.verdict);
            if (d.verdict === 'block') {
              var safe = new _ClipboardItem({ 'text/plain': new _Blob([SAFE_TEXT], { type: 'text/plain' }) });
              return apply(_write, self, [[safe]]);
            }
          }
          return apply(_write, self, args);
        }]);
      }
    } catch (e) {
      /* fall through */
    }
    return apply(_write, self, args);
  });
}

// 3. document.execCommand('copy') - we note that the copy came from the page's
// code, then the 'copy' listener below does the checking.
replaceMethod(Document.prototype, 'execCommand', function execCommand(command) {
  var c = apply(_toLowerCase, s(command), []);
  if (c === 'copy' || c === 'cut') {
    programmaticCopy = true;
    try {
      return apply(_execCommand, this, arguments);
    } finally {
      programmaticCopy = false;
    }
  }
  return apply(_execCommand, this, arguments);
});

// 4a. Any copy (keyboard, menu or execCommand): check what is being copied.
function onCopy(e) {
  var text = selectedText();
  var d = evaluate(text);
  if (!d) return;
  // Someone copying an installer command by hand on a developer site: stay quiet.
  if (d.verdict === 'warn' && !programmaticCopy) return;
  notify(text, programmaticCopy ? 'execCommand' : 'manual copy', d.verdict);
  if (d.verdict === 'block') {
    try {
      if (_setData && e.clipboardData) apply(_setData, e.clipboardData, ['text/plain', SAFE_TEXT]);
      apply(_preventDefault, e, []);
    } catch (x) {
      /* ignore */
    }
  }
}
apply(_addEventListener, window, ['copy', onCopy, true]);
apply(_addEventListener, window, ['cut', onCopy, true]);

// 4b. The page's own copy handler writing text with clipboardData.setData.
if (_setData) {
  replaceMethod(DataTransfer.prototype, 'setData', function setData(format, data) {
    try {
      var f = apply(_toLowerCase, s(format), []);
      if (f === 'text/plain' || f === 'text' || f === 'text/unicode') {
        var d = evaluate(data);
        if (d) {
          notify(data, 'copy event', d.verdict);
          if (d.verdict === 'block') return apply(_setData, this, [format, SAFE_TEXT]);
        }
      }
    } catch (e) {
      /* fall through */
    }
    return apply(_setData, this, arguments);
  });
}
