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
function localIsoDate(date) {
  var month = String(date.getMonth() + 1);
  var day = String(date.getDate());
  return date.getFullYear() + '-' + (month.length < 2 ? '0' + month : month) + '-' + (day.length < 2 ? '0' + day : day);
}
function dispatchEvent(element, dispatchEventName) {
  if (!element) {
    return;
  }
  var event;
  if (typeof(Event) === 'function') {
    event = new Event(dispatchEventName, { bubbles: true, cancelable: true });
  } else {
    event = document.createEvent('Event');
    event.initEvent(dispatchEventName, true, true);
  }
  element.dispatchEvent(event);
}

// --- Ignore Creation ---

var ignoreFormContainer = document.getElementById('ignore-form-container');
var ignoreCreateButton = document.getElementById('ignore-create');
if (ignoreFormContainer !== null && ignoreFormContainer !== void 0 && ignoreCreateButton !== null && ignoreCreateButton !== void 0) {
  // Open form button
  ignoreCreateButton.addEventListener('click', function() {
    if (ignoreCreateButton.disabled) {
      return;
    }
    toggleElement(ignoreCreateButton, 'hide');
    toggleElement(ignoreFormContainer, 'show');
    ignoreFormContainer.scrollIntoView();
  });

  // Cancel button
  var ignoreFormCancelButton = document.getElementById('ignore-form-cancel');
  ignoreFormCancelButton.addEventListener('click', function() {
    toggleElement(ignoreFormContainer, 'hide');
    toggleElement(ignoreCreateButton, 'show');
  });

  // Submit button
  var ignoreFormSubmitButton = document.getElementById('ignore-form-submit');
  ignoreFormSubmitButton.addEventListener('click', function() {
    var ignoreReasonError = document.getElementById('ignore-reason-error');
    var ignoreReasonElem = document.getElementById('ignore-form-ignore-reason');
    var reasonVal = (ignoreReasonElem.value || '').trim();
    if (!reasonVal) {
      if (ignoreReasonError && ignoreReasonError.className.indexOf('hidden') !== -1) {
        ignoreReasonError.className = ignoreReasonError.className.replace(/(?:^|\s)hidden(?!\S)/g, '');
      }
      return;
    }
    var ignoreType = document.getElementById('ignore-form-type').value;
    var ignoreExpirationType = document.getElementById('ignore-form-expiration-type').value;
    var ignoreExpirationDate = '';
    if (ignoreExpirationType === 'custom-expiration-date') {
      ignoreExpirationDate = document.getElementById('ignore-form-expiration-date').value || '';
      // The ignore service rejects a date that is not in the future; ISO dates compare as strings.
      if (!/^\d{4}-\d{2}-\d{2}$/.test(ignoreExpirationDate) || ignoreExpirationDate <= localIsoDate(new Date())) {
        toggleElement(document.getElementById('ignore-expiration-error'), 'show');
        return;
      }
    }
    toggleElement(document.getElementById('ignore-expiration-error'), 'hide');
    var ignoreReason = reasonVal;
    ${ideSubmitIgnoreRequest}
  });

  // Hide error when user starts typing a non-empty reason
  var ignoreReasonInput = document.getElementById('ignore-form-ignore-reason');
  var ignoreReasonError = document.getElementById('ignore-reason-error');
  if (ignoreReasonInput) {
    ignoreReasonInput.addEventListener('input', function() {
      var val = (ignoreReasonInput.value || '').trim();
      if (val && ignoreReasonError && ignoreReasonError.className.indexOf('hidden') === -1) {
        ignoreReasonError.className += ' hidden';
      }
    });
  }

  // Hide the expiration date field when "Do not expire"
  var ignoreFormExpirationType = document.getElementById('ignore-form-expiration-type');
  var ignoreFormExpirationDate = document.getElementById('ignore-form-expiration-date');
  ignoreFormExpirationDate.addEventListener('change', function() {
    toggleElement(document.getElementById('ignore-expiration-error'), 'hide');
  });
  ignoreFormExpirationType.addEventListener('change', function(event) {
    if (event.target.value === 'never') {
      toggleElement(ignoreFormExpirationDate, 'hide');
    } else {
      toggleElement(ignoreFormExpirationDate, 'show');
    }
  });

  // Hide "Do not expire" for "Temporary ignore"
  var ignoreFormTypeSelector = document.getElementById('ignore-form-type');
  ignoreFormTypeSelector.addEventListener('change', function(event) {
    if (event.target.value === 'temporary-ignore') {
      ignoreFormExpirationType.value = 'custom-expiration-date';
      dispatchEvent(ignoreFormExpirationType, 'change');
      toggleElement(ignoreFormExpirationType, 'hide');
    } else {
      toggleElement(ignoreFormExpirationType, 'show');
    }
  });
}
