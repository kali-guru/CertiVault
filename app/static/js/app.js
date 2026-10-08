'use strict';
document.querySelectorAll('[data-filter]').forEach(input => {
  input.addEventListener('input', () => {
    const term = input.value.toLowerCase();
    document.querySelectorAll('#' + input.dataset.filter + ' tbody tr').forEach(row => {
      row.hidden = !row.textContent.toLowerCase().includes(term);
    });
  });
});
