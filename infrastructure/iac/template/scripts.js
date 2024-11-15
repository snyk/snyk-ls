/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

  // Utility function to show/hide an element based on a toggle value
  function toggleElement(element, action) {
    if (!element) return;
    element.classList.toggle("hidden", action === "hide");
  }

  function applyIgnoreInFile() {
    console.log('Applying ignore', issue);
    if (!issue) return;

    window.applyIgnoreInFileQuery(issue + '|@' + filePath + ' > ' + resourcePath);
    toggleElement(ignoreInFileBtn, "hide");
    console.log('Applying ignore');
  }

  // DOM element references
  const ignoreInFileBtn = document.getElementById('ignore-file-issue')



  let issue = ignoreInFileBtn.getAttribute('issue')
  let resourcePath =  ignoreInFileBtn.getAttribute('resourcePath')
  let filePath =  ignoreInFileBtn.getAttribute('filePath')

  ignoreInFileBtn?.addEventListener("click", applyIgnoreInFile);

  window.receiveIgnoreInFileResponse = function (success){
    console.log('[[receiveIgnoreInFileResponse]]', success);
    if(success){
      ignoreInFileBtn.disabled = true;
      console.log('Ignored in file', success);
      document.getElementById('ignore-file-issue').disabled = true;
    }else{
      toggleElement(ignoreInFileBtn, "show");
      console.error('Failed to apply fix', success);
    }
  }
