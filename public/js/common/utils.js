/**
 * Common Utilities
 */

/**
 * Escapes HTML characters to prevent XSS in dynamic rendering.
 */
export function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Queries single element by selector with safety check.
 */
export function $(selector, parent = document) {
  return parent.querySelector(selector);
}

/**
 * Queries all elements by selector.
 */
export function $$(selector, parent = document) {
  return Array.from(parent.querySelectorAll(selector));
}
