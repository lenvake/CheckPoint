/* ================================================================
   CheckPoint – scan.js
   Scan-Logik: API-Call, Form-Handler, Example-Buttons
   ================================================================ */
'use strict';

const API_BASE = 'http://localhost:5001';
let currentResult = null;

async function runScan(url) {
  if (!url.trim()) { toast('⚠️ Bitte eine URL eingeben'); return; }
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const btn = $('scan-btn');
  btn.disabled = true;
  btn.querySelector('.btn-text').textContent = 'Analysiere…';

  hide($('result-section'));
  show($('loading-overlay'));
  startLoading(url);

  try {
    const resp = await fetch(`${API_BASE}/api/scan`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url, max_pages: 50, max_depth: 3 }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    currentResult = data;
    stopLoading();
    renderResult(data);
  } catch (err) {
    stopLoading();
    hide($('loading-overlay'));
    toast(`❌ Fehler: ${err.message}`, 6000);
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.querySelector('.btn-text').textContent = 'Analysieren';
  }
}

function initScanForm() {
  $('scan-form').addEventListener('submit', e => {
    e.preventDefault();
    runScan($('url-input').value.trim());
  });

  document.querySelectorAll('.example-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('url-input').value = btn.dataset.url;
      runScan(btn.dataset.url);
    });
  });
}
