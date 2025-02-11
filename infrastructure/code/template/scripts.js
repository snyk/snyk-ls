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
const applyFixButton = document.getElementById('apply-fix');
const retryGenerateFixButton = document.getElementById('retry-generate-fix');
const generateAIFixButton = document.getElementById('generate-ai-fix');

const fixLoadingIndicatorElem = document.getElementById('fix-loading-indicator');

generateAIFixButton?.addEventListener('click', generateAIFix)
retryGenerateFixButton?.addEventListener('click', retryGenerateAIFix);
applyFixButton?.addEventListener('click', applyFix);

function generateAIFix() {
  if (!suggestion)
    return;

  toggleElement(generateAIFixButton, 'hide');
  toggleElement(fixLoadingIndicatorElem, 'show');
  ${ideGenerateAIFix}
}


function applyFix() {
  if (!suggestion) return;
  let showSuggestion = getSuggestion();

  const diffSuggestion = showSuggestion[diffSelectedIndex];
  const filePath = showSuggestion.filePath ? showSuggestion.filePath : getFilePathFromFix(diffSuggestion);
  const patch = diffSuggestion.unifiedDiffsPerFile[filePath];
  const fixId = diffSuggestion.fixId;

  lastAppliedFix = diffSelectedIndex;
  applyFixButton.disabled = true;
  ${ideApplyAIFix}
}


const fixWrapperElem = document.getElementById('fix-wrapper');
const fixSectionElem = document.getElementById('fixes-section');
const fixErrorSectionElem = document.getElementById('fixes-error-section');

// generated AI fix diffs
const nextDiffElem = document.getElementById('next-diff');
const previousDiffElem = document.getElementById('previous-diff');
const diffSelectedIndexElem = document.getElementById('diff-counter');


//explain AI fix elements
const fixExplainText = document.getElementById('fix-explain-text')

const diffTopElem = document.getElementById('diff-top');
const diffElem = document.getElementById('diff');
const noDiffsElem = document.getElementById('info-no-diffs');
if (noDiffsElem) {
  noDiffsElem.innerText = "We couldn't determine any fixes for this issue.";
}
const diffNumElem = document.getElementById('diff-number');
const diffNum2Elem = document.getElementById('diff-number2');

let diffSelectedIndex = 0;
let lastAppliedFix = -1;

function nextDiff() {
  let showSuggestion = getSuggestion();

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
  let showSuggestion = getSuggestion();

  if (!showSuggestion || diffSelectedIndex <= 0) return;
  --diffSelectedIndex;
  applyFixButton.disabled = diffSelectedIndex == lastAppliedFix;
  showCurrentDiff();
}
function generateDiffHtml(patch) {
  const codeLines = patch.split('\n');

  // the first two lines are the file names
  codeLines.shift();
  codeLines.shift();

  const diffHtml = document.createElement('div');
  let blockDiv = null;

  for (const line of codeLines) {
    if (line.startsWith('@@ ')) {
      blockDiv = document.createElement('div');
      blockDiv.className = 'example';

      if (blockDiv) {
        diffHtml.appendChild(blockDiv);
      }
    } else {
      const lineDiv = document.createElement('div');
      lineDiv.className = 'example-line';

      if (line.startsWith('+')) {
        lineDiv.classList.add('added');
      } else if (line.startsWith('-')) {
        lineDiv.classList.add('removed');
      }

      const lineCode = document.createElement('code');
      // if line is empty, we need to fall back to ' '
      // to make sure it displays in the diff
      lineCode.innerText = line.slice(1, line.length) || ' ';

      lineDiv.appendChild(lineCode);
      blockDiv?.appendChild(lineDiv);
    }
  }

  return diffHtml;
}
function getFilePathFromFix(fix) {
  return Object.keys(fix.unifiedDiffsPerFile)[0];
}
function showCurrentDiff() {
  // Some IDEs send back the suggestion, others send the suggestion.diffs directly.
  let showSuggestion = getSuggestion();

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

  const diffSuggestion = showSuggestion[diffSelectedIndex];
  // IntelliJ way of getting file ? TODO: Investigate
  const filePath = showSuggestion.filePath ? showSuggestion.filePath : getFilePathFromFix(diffSuggestion);
  const patch = diffSuggestion.unifiedDiffsPerFile[filePath];
  fixExplainText.innerText = diffSuggestion.explanation;
  console.log()
  // clear all elements
  while (diffElem.firstChild) {
    diffElem.removeChild(diffElem.firstChild);
  }
  diffElem.appendChild(generateDiffHtml(patch));
}
function getSuggestion(){
  let suggestionElem = document.getElementById('suggestionDiv');
  return JSON.parse(suggestionElem.innerText);
}
nextDiffElem.addEventListener('click', nextDiff);
previousDiffElem.addEventListener('click', previousDiff);
