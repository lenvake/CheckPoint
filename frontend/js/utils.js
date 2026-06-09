/* ================================================================
   CheckPoint – utils.js
   Allgemeine Helferfunktionen (DOM, Farben, Animationen, Toast)
   ================================================================ */
'use strict';

const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qsa = sel => [...document.querySelectorAll(sel)];

function show(el) { el && el.classList.remove('hidden'); }
function hide(el) { el && el.classList.add('hidden'); }

function toast(msg, dur = 3000) {
  const t = $('toast');
  t.textContent = msg;
  show(t);
  clearTimeout(t._timer);
  t._timer = setTimeout(() => hide(t), dur);
}

function icon(ok, warn = false) {
  const cls = ok === null ? 'warn' : ok ? 'ok' : (warn ? 'warn' : 'bad');
  const sym = ok === null ? '?' : ok ? '✓' : '✗';
  return `<div class="check-icon ${cls}">${sym}</div>`;
}

function colorForScore(s) {
  if (s >= 80) return '#22d3a5';
  if (s >= 60) return '#86efac';
  if (s >= 40) return '#facc15';
  if (s >= 20) return '#fb923c';
  return '#f87171';
}

function gradeLabel(g) {
  const map = {
    'A+': 'Exzellent', 'A': 'Sehr gut', 'B': 'Gut',
    'C': 'Ausreichend', 'D': 'Mangelhaft', 'E': 'Schlecht', 'F': 'Kritisch'
  };
  return map[g] || '–';
}

function animateNumber(el, target, dur = 1800) {
  const start = performance.now();
  const from  = parseInt(el.textContent) || 0;
  function step(now) {
    const p    = Math.min((now - start) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 4);
    el.textContent = Math.round(from + (target - from) * ease);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function downloadFile(content, filename, type) {
  const blob = new Blob([content], { type });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
