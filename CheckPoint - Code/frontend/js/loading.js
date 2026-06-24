/* ================================================================
   CheckPoint – loading.js
   Lade-Overlay: Animierter Ring, Schritt-Anzeige, Fortschritts-%
   ================================================================ */
'use strict';

const STEPS = ['dns', 'tls', 'crawl', 'compliance', 'score'];
let loadingInterval = null;

function startLoading(url) {
  $('loading-url').textContent = url;
  $('loading-pct').textContent = '0%';
  qsa('.loading-step').forEach((el, i) => {
    el.classList.remove('active', 'done');
    if (i === 0) el.classList.add('active');
  });

  let pct = 0, stepIdx = 0;
  const ring = $('loading-ring');
  if (ring) ring.style.strokeDashoffset = '314';

  clearInterval(loadingInterval);
  loadingInterval = setInterval(() => {
    pct = Math.min(pct + Math.random() * 3, 95);
    $('loading-pct').textContent = Math.round(pct) + '%';
    if (ring) ring.style.strokeDashoffset = (314 * (1 - pct / 100)).toFixed(1);

    const threshold = [5, 25, 55, 80, 92];
    if (stepIdx < STEPS.length - 1 && pct >= threshold[stepIdx]) {
      qsa('.loading-step')[stepIdx].classList.remove('active');
      qsa('.loading-step')[stepIdx].classList.add('done');
      stepIdx++;
      qsa('.loading-step')[stepIdx].classList.add('active');
    }
  }, 120);
}

function stopLoading() {
  clearInterval(loadingInterval);
  $('loading-pct').textContent = '100%';
  const ring = $('loading-ring');
  if (ring) ring.style.strokeDashoffset = '0';
  qsa('.loading-step').forEach(el => {
    el.classList.remove('active');
    el.classList.add('done');
  });
  setTimeout(() => hide($('loading-overlay')), 400);
}
