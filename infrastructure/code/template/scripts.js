function _createForOfIteratorHelper(r, e) { var t = "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (!t) { if (Array.isArray(r) || (t = _unsupportedIterableToArray(r)) || e && r && "number" == typeof r.length) { t && (r = t); var _n = 0, F = function F() {}; return { s: F, n: function n() { return _n >= r.length ? { done: !0 } : { done: !1, value: r[_n++] }; }, e: function e(r) { throw r; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var o, a = !0, u = !1; return { s: function s() { t = t.call(r); }, n: function n() { var r = t.next(); return a = r.done, r; }, e: function e(r) { u = !0, o = r; }, f: function f() { try { a || null == t.return || t.return(); } finally { if (u) throw o; } } }; }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function toggleElement(element, toggle) {
  if (!element) {
    return;
  }
  if (toggle === 'show') {
    element.className = element.className.replace(/(?:^|\s)hidden(?!\S)/g, '');
  } else if (toggle === 'hide') {
    if (element.className.indexOf('hidden') === -1) {
      element.className += ' hidden';
    }
  } else {
    console.error('Unexpected toggle value', toggle);
  }
}
// different AI fix buttons
var applyFixButton = document.getElementById('apply-fix');
var retryGenerateFixButton = document.getElementById('retry-generate-fix');
var generateAIFixButton = document.getElementById('generate-ai-fix');
var fixLoadingIndicatorElem = document.getElementById('fix-loading-indicator');
generateAIFixButton === null || generateAIFixButton === void 0 || generateAIFixButton.addEventListener('click', generateAIFix);
retryGenerateFixButton === null || retryGenerateFixButton === void 0 || retryGenerateFixButton.addEventListener('click', retryGenerateAIFix);
applyFixButton === null || applyFixButton === void 0 || applyFixButton.addEventListener('click', applyFix);
function generateAIFix() {
  if (!suggestion) return;
  toggleElement(generateAIFixButton, 'hide');
  toggleElement(fixLoadingIndicatorElem, 'show');
  var issueId = generateAIFixButton.getAttribute('issue-id');
  var folderPath = generateAIFixButton.getAttribute('folder-path');
  var filePath = generateAIFixButton.getAttribute('file-path');
  var generateFixQueryString = folderPath + '@|@' + filePath + '@|@' + issueId;

  ${ideGenerateAIFix}
}
function applyFix() {
  if (!suggestion) return;
  var showSuggestion = getSuggestion();
  var diffSuggestion = showSuggestion[diffSelectedIndex];
  var filePath = showSuggestion.filePath ? showSuggestion.filePath : getFilePathFromFix(diffSuggestion);
  var patch = diffSuggestion.unifiedDiffsPerFile[filePath];
  var fixId = diffSuggestion.fixId;
  lastAppliedFix = diffSelectedIndex;
  applyFixButton.disabled = true;
  ${ideApplyAIFix}
}
var fixWrapperElem = document.getElementById('fix-wrapper');
var fixSectionElem = document.getElementById('fixes-section');
var fixErrorSectionElem = document.getElementById('fixes-error-section');

// generated AI fix diffs
var nextDiffElem = document.getElementById('next-diff');
var previousDiffElem = document.getElementById('previous-diff');
var diffSelectedIndexElem = document.getElementById('diff-counter');

//explain AI fix elements
var fixExplainText = document.getElementById('fix-explain-text');
var diffTopElem = document.getElementById('diff-top');
var diffElem = document.getElementById('diff');
var noDiffsElem = document.getElementById('info-no-diffs');
var diffNumElem = document.getElementById('diff-number');
var diffNum2Elem = document.getElementById('diff-number2');
var diffSelectedIndex = 0;
var lastAppliedFix = -1;
function nextDiff() {
  var showSuggestion = getSuggestion();
  if (!showSuggestion || diffSelectedIndex >= showSuggestion.length - 1) return;
  ++diffSelectedIndex;
  applyFixButton.disabled = diffSelectedIndex == lastAppliedFix;
  showCurrentDiff();
}
function retryGenerateAIFix() {
  console.log('retrying generate AI Fix');
  toggleElement(fixWrapperElem, 'show');
  toggleElement(fixErrorSectionElem, 'hide');
  generateAIFix();
}
function previousDiff() {
  var showSuggestion = getSuggestion();
  if (!showSuggestion || diffSelectedIndex <= 0) return;
  --diffSelectedIndex;
  applyFixButton.disabled = diffSelectedIndex == lastAppliedFix;
  showCurrentDiff();
}
function generateDiffHtml(patch) {
  if (!String.prototype.startsWith) {
    String.prototype.startsWith = function(search, position) {
      position = position || 0;
      return this.indexOf(search, position) === position;
    };
  }

  var codeLines = patch.split('\n');
  codeLines.shift();
  codeLines.shift();
  var diffHtml = document.createElement('div');
  var blockDiv = null;
  var _loop = function _loop(i, _codeLines) {
    var line = _codeLines[i];
    if (line.startsWith('@@ ')) {
      blockDiv = document.createElement('div');
      blockDiv.className = 'example';
      if (blockDiv) {
        diffHtml.appendChild(blockDiv);
      }
    } else {
      var lineDiv = document.createElement('div');
      lineDiv.className = 'example-line';
      if (line.startsWith('+')) {
        lineDiv.classList.add('added');
      } else if (line.startsWith('-')) {
        lineDiv.classList.add('removed');
      }
      var lineCode = document.createElement('code');
      lineCode.innerText = line.slice(1, line.length) || ' ';
      lineDiv.appendChild(lineCode);
      if (blockDiv) {
        blockDiv.appendChild(lineDiv);
      }
    }
  };
  for (var i = 0; i < codeLines.length; i++) {
    _loop(i, codeLines);
  }
  return diffHtml;
}
function getFilePathFromFix(fix) {
  return Object.keys(fix.unifiedDiffsPerFile)[0];
}
function showCurrentDiff() {
  // Some IDEs send back the suggestion, others send the suggestion.diffs directly.
  var showSuggestion = getSuggestion();
  if (!showSuggestion.length) {
    toggleElement(noDiffsElem, 'show');
    toggleElement(diffTopElem, 'hide');
    toggleElement(diffElem, 'hide');
    toggleElement(applyFixButton, 'hide');
    return;
  }
  if (!showSuggestion.length || diffSelectedIndex < 0 || diffSelectedIndex >= showSuggestion.length) return;
  toggleElement(noDiffsElem, 'hide');
  toggleElement(diffTopElem, 'show');
  toggleElement(diffElem, 'show');
  toggleElement(applyFixButton, 'show');
  diffNumElem.innerText = showSuggestion.length.toString();
  diffNum2Elem.innerText = showSuggestion.length.toString();
  diffSelectedIndexElem.innerText = (diffSelectedIndex + 1).toString();
  var diffSuggestion = showSuggestion[diffSelectedIndex];
  // IntelliJ way of getting file ? TODO: Investigate
  var filePath = showSuggestion.filePath ? showSuggestion.filePath : getFilePathFromFix(diffSuggestion);
  var patch = diffSuggestion.unifiedDiffsPerFile[filePath];
  fixExplainText.innerText = diffSuggestion.explanation;
  console.log();
  // clear all elements
  while (diffElem.firstChild) {
    diffElem.removeChild(diffElem.firstChild);
  }
  diffElem.appendChild(generateDiffHtml(patch));
}
function getSuggestion() {
  var suggestionElem = document.getElementById('suggestionDiv');
  return JSON.parse((suggestionElem.innerText).toString());
}
nextDiffElem === null || nextDiffElem === void 0 || nextDiffElem.addEventListener('click', nextDiff);
previousDiffElem === null || previousDiffElem === void 0 ? void 0 : previousDiffElem.addEventListener('click', previousDiff);
