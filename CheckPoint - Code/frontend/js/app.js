/* ================================================================
   1. Entry Point
   Initialisiert alle Module nach DOM-Ready.

   Modul-Übersicht:
     particles.js  – Hintergrund-Partikel-Canvas
     utils.js      – DOM-Helpers, Farben, Animationen, Toast
     loading.js    – Lade-Overlay (Ring + Schritte)
     renderer.js   – Ergebnis-Rendering (Cards, Breakdown, Modals)
     scan.js       – API-Call, Form-Handler, Example-Buttons
   ================================================================ */
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // Particle background
  if (typeof initParticles === 'function') initParticles();

  // Scroll-to-top button
  const scrollBtn = document.getElementById('scroll-top');
  if (scrollBtn) {
    window.addEventListener('scroll', () => {
      scrollBtn.style.opacity = window.scrollY > 400 ? '1' : '0';
    });
    scrollBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }

  // Keyboard shortcut: ESC closes modals
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      const overlay = document.getElementById('modal-overlay');
      if (overlay && !overlay.classList.contains('hidden')) closeModal();
    }
  });

  // Init scan form & example buttons
  initScanForm();
});
