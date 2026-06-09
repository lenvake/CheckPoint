/* ── Particle Background ──────────────────────────────────────────────────── */
(function() {
  'use strict';
  const canvas  = document.getElementById('particle-canvas');
  const ctx     = canvas.getContext('2d');
  let W, H, particles = [], mouse = { x: -9999, y: -9999 };
  const COUNT = 90;
  const COLORS = ['#6366f1','#8b5cf6','#06b6d4','#22d3a5'];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

  class Particle {
    constructor() { this.reset(); }
    reset() {
      this.x    = rnd(0, W);
      this.y    = rnd(0, H);
      this.vx   = rnd(-0.4, 0.4);
      this.vy   = rnd(-0.4, 0.4);
      this.r    = rnd(1, 2.5);
      this.color= pick(COLORS);
      this.alpha= rnd(0.15, 0.5);
      this.life = 0;
      this.maxLife = rnd(200, 600);
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      this.life++;
      // mouse repulsion
      const dx = this.x - mouse.x, dy = this.y - mouse.y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if (dist < 120) {
        const force = (120 - dist) / 120 * 0.6;
        this.x += (dx / dist) * force;
        this.y += (dy / dist) * force;
      }
      if (this.life > this.maxLife || this.x < -10 || this.x > W+10 || this.y < -10 || this.y > H+10) {
        this.reset();
      }
    }
    draw() {
      const fadeIn  = Math.min(1, this.life / 60);
      const fadeOut = Math.min(1, (this.maxLife - this.life) / 60);
      ctx.globalAlpha = this.alpha * fadeIn * fadeOut;
      ctx.fillStyle = this.color;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // init
  for (let i = 0; i < COUNT; i++) {
    const p = new Particle();
    p.life = Math.random() * p.maxLife; // stagger start
    particles.push(p);
  }

  // connection lines
  function drawLines() {
    const THRESH = 140;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i+1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d  = Math.sqrt(dx*dx + dy*dy);
        if (d < THRESH) {
          ctx.globalAlpha = (1 - d/THRESH) * 0.06;
          ctx.strokeStyle = '#6366f1';
          ctx.lineWidth   = 1;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  function frame() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => { p.update(); p.draw(); });
    drawLines();
    requestAnimationFrame(frame);
  }
  frame();
})();
