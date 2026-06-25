/* ================================================================
   Ergebnis-Rendering: Score-Ring, Cards, Breakdown, Export
   ================================================================ */
'use strict';

const SCORE_LABELS = {
  https_reachable:     '🔒 HTTPS erreichbar',
  tls_protocol:        '🛡 TLS Version',
  cert_valid:          '📜 Zertifikat gültig',
  cert_not_expiring:   '📅 Ablaufdatum OK',
  cert_hostname_match: '🔗 Hostname Match',
  cert_type:           '🏷 Zertifikatstyp (DV/OV/EV)',
  hsts_present:        '🔐 HSTS vorhanden',
  hsts_max_age_ok:     '⏱ HSTS max-age ≥ 1 Jahr',
  mixed_content:       '⚠️ Mixed Content',          
  https_redirect:      '↪️ HTTP→HTTPS Redirect',    
  security_txt:        '📄 security.txt',
  has_impressum:       '📋 Impressum',
  has_privacy:         '🔏 Datenschutzerklärung',
  has_dpo:             '👤 Datenschutzbeauftragter',
  iso_certifications:  '🏅 ISO-Zertifizierungen',
  server_eu:           '🌍 Server in EU',
};

function renderResult(d) {
  const score = d.total_score ?? 0;
  const grade = d.grade ?? 'F';
  const color = colorForScore(score);
  const label = gradeLabel(grade);
  const sd    = d.score_details || {};
  const tls   = d.tls || {};
  const comp  = d.compliance || {};
  const srv   = d.server || {};
  const stxt  = d.security_txt || {};

  _renderScoreRing(score, grade, color, label, d, tls, comp, srv, stxt);
  _renderTlsCard(tls, stxt, sd);
  _renderComplianceCard(comp, sd);
  _renderIsoCard(comp, sd);
  _renderServerCard(srv, sd);
  _renderBreakdown(sd);
  _setupExport(d);
  _setupModals(d);

  show($('result-section'));
  $('result-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function _renderScoreRing(score, grade, color, label, d, tls, comp, srv, stxt) {
  const arc  = $('score-arc');
  const CIRC = 565.48;
  arc.setAttribute('stroke', color);
  arc.style.filter = `drop-shadow(0 0 18px ${color}99)`;
  setTimeout(() => {
    arc.style.strokeDashoffset = (CIRC * (1 - score / 100)).toFixed(2);
  }, 80);

  qs('#grad-stop1') && (qs('#grad-stop1').style.stopColor = color);

  $('score-number').textContent = '0';
  animateNumber($('score-number'), score);
  $('score-grade').textContent = grade;
  $('score-grade').style.color = color;
  $('score-target').textContent = d.target || '–';
  $('score-label').textContent  = label;
  $('score-timestamp').textContent = '🕒 ' + (d.timestamp || new Date().toISOString());

  // Status pills
  const pills = [];
  if (tls.active)                   pills.push(['ok',   'HTTPS aktiv']);
  else                              pills.push(['bad',  'Kein HTTPS']);
  if (comp.has_impressum)           pills.push(['ok',   'Impressum']);
  else                              pills.push(['bad',  'Kein Impressum']);
  if (comp.has_privacy)             pills.push(['ok',   'Datenschutz']);
  else                              pills.push(['bad',  'Kein Datenschutz']);
  if (comp.has_dsb)                 pills.push(['ok',   'DSB']);
  if (stxt.found)                   pills.push(['ok',   'security.txt']);
  if (tls.mixed_content)            pills.push(['bad',  `Mixed Content (${tls.mixed_content_count})`]); // Feature 1
  // ── NEU (Feature 2): Redirect-Pill ──────────────────────────────────────
  if (tls.redirect_to_https === false && tls.active)
                                    pills.push(['warn', 'Kein HTTP-Redirect']);
  else if (tls.redirect_to_https)   pills.push(['ok',   `Redirect (${tls.redirect_hops} Hop${tls.redirect_hops !== 1 ? 's' : ''})`]);
  // ─────────────────────────────────────────────────────────────────────────
  if (srv.cdn_detected)             pills.push(['warn', 'CDN erkannt']);

  $('score-pills').innerHTML = pills.map(([cls, txt]) =>
    `<span class="pill pill-${cls}">${txt}</span>`
  ).join('');
}

// ── TLS Card ──────────────────────────────────────────────────────────────────
function _renderTlsCard(tls, stxt, sd) {
  const tlsMax = 55; // ← NEU (Feature 2): +5 Punkte für Redirect
  const tlsPts = ['https_reachable', 'tls_protocol', 'cert_valid', 'cert_not_expiring',
                  'cert_hostname_match', 'cert_type', 'hsts_present', 'hsts_max_age_ok',
                  'https_redirect']  // ← NEU (Feature 2)
    .reduce((a, k) => a + (sd[k]?.points || 0), 0);

  const mcMalus = sd['mixed_content']?.points || 0;
  $('tls-score').textContent = `${tlsPts + mcMalus}/${tlsMax}`;

  $('tls-body').innerHTML = [
    [tls.active,              `HTTPS: ${tls.version || '–'}`],
    [!tls.cert_expired,       `Zertifikat: ${tls.cert_type || 'DV'} · ${(tls.days_remaining ?? '?')} Tage`],
    [tls.cert_hostname_match, `Hostname Match`],
    [tls.hsts,                `HSTS: max-age=${tls.hsts_max_age ?? 0}`],
    [!tls.mixed_content,      tls.mixed_content                                          // Feature 1
        ? `Mixed Content: ${tls.mixed_content_count} unsichere Ressource(n)`
        : `Kein Mixed Content`],
    // ── NEU (Feature 2): Redirect-Zeile ─────────────────────────────────
    [tls.redirect_to_https,   tls.redirect_to_https
        ? `HTTP→HTTPS Redirect: ${tls.redirect_hops} Hop(s)`
        : tls.redirect_error
            ? `Redirect-Check fehlgeschlagen`
            : `Kein HTTP→HTTPS Redirect`],
    // ─────────────────────────────────────────────────────────────────────
    [stxt.found,              `security.txt`],
  ].map(([ok, txt]) => `<div class="check-row">${icon(ok)}<span>${txt}</span></div>`).join('');
}

// ── Compliance Card ───────────────────────────────────────────────────────────
function _renderComplianceCard(comp, sd) {
  const cPts = ['has_impressum', 'has_privacy', 'has_dpo']
    .reduce((a, k) => a + (sd[k]?.points || 0), 0);
  $('comp-score').textContent = `${cPts}/40`;

  $('comp-body').innerHTML = [
    [comp.has_impressum, `Impressum vorhanden`],
    [comp.has_privacy,   `Datenschutzerklärung`],
    [comp.has_dsb,       `Datenschutzbeauftragter`],
    [null, comp.impressum_url
      ? `🔗 ${comp.impressum_url.replace(/^https?:\/\//, '').substring(0, 40)}`
      : 'Kein Impressum-Link'],
  ].map(([ok, txt]) => `<div class="check-row">${icon(ok)}<span>${txt}</span></div>`).join('');
}

// ── ISO Card ──────────────────────────────────────────────────────────────────
function _renderIsoCard(comp, sd) {
  const isoCerts = comp.iso_certifications || [];
  const isoPts   = sd['iso_certifications']?.points || 0;
  $('iso-score').textContent = `${isoPts}/5`;

  $('iso-body').innerHTML = isoCerts.length > 0
    ? isoCerts.map(c => `<div class="check-row">${icon(true)}<span>${c}</span></div>`).join('')
    : `<div class="check-row">${icon(false)}<span>Keine ISO-Normen erkannt</span></div>`;
}

// ── Server Card ───────────────────────────────────────────────────────────────
function _renderServerCard(srv, sd) {
  const srvPts = sd['server_eu']?.points || 0;
  $('server-score').textContent = `${srvPts}/5`;

  $('server-body').innerHTML = [
    [null,              `IP: ${srv.ip || '–'}`],
    [null,              `Land: ${srv.country || '–'} · ${srv.city || ''}`],
    [!srv.cdn_detected, `CDN: ${srv.cdn_detected ? (srv.cdn_name || 'Ja') : 'Nein'}`],
  ].map(([ok, txt]) => `<div class="check-row">${icon(ok)}<span>${txt}</span></div>`).join('');
}

// ── Breakdown Grid ────────────────────────────────────────────────────────────
function _renderBreakdown(sd) {
  $('breakdown-grid').innerHTML = Object.entries(SCORE_LABELS).map(([k, lbl], i) => {
    const item = sd[k] || {};
    const pts  = item.points ?? 0;
    const max  = item.max ?? 0;

    // Sonderdarstellung für Malus-Kriterien (max=0, pts negativ) – Feature 1
    const isMalus = max === 0 && pts < 0;
    const pct  = isMalus
      ? 100
      : max > 0 ? (pts / max) * 100 : 0;
    const cls  = isMalus ? 'zero'
      : pts === max ? 'full'
      : pts > 0    ? 'part'
      :              'zero';

    return `<div class="bd-row" style="animation-delay:${i * 0.04}s">
      <span class="bd-label">${lbl}</span>
      <div class="bd-bar-wrap">
        <div class="bd-bar ${cls}" style="width:0%" data-pct="${pct.toFixed(0)}"></div>
      </div>
      <span class="bd-pts ${cls}">${isMalus ? pts : `${pts}/${max}`}</span>
      <span class="bd-reason">${item.reason || ''}</span>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    qsa('.bd-bar').forEach(bar => {
      bar.style.transition = 'width 1s cubic-bezier(.4,0,.2,1)';
      bar.style.width = bar.dataset.pct + '%';
    });
  });
}

// ── Export ────────────────────────────────────────────────────────────────────
function _setupExport(d) {
  $('export-json').onclick = () => {
    downloadFile(JSON.stringify(d, null, 2), 'checkpoint_result.json', 'application/json');
  };
  $('export-csv').onclick = () => {
    const rows = [
      ['Kriterium', 'Punkte', 'Max', 'Begründung'],
      ...Object.entries(d.score_details || {}).map(([k, v]) => [
        SCORE_LABELS[k] || k, v.points, v.max, v.reason || ''
      ]),
      ['GESAMT', d.total_score, 100, `Note: ${d.grade}`],
    ];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    downloadFile(csv, 'checkpoint_result.csv', 'text/csv');
  };
}

// ── Modals ────────────────────────────────────────────────────────────────────
function _setupModals(d) {
  qsa('[data-modal]').forEach(card => {
    card.onclick = () => openModal(card.dataset.modal, d);
  });
  $('modal-close') && ($('modal-close').onclick = closeModal);
  $('modal-overlay') && ($('modal-overlay').onclick = e => {
    if (e.target === $('modal-overlay')) closeModal();
  });
}

function openModal(type, d) {
  const tls  = d.tls || {};
  const comp = d.compliance || {};
  const srv  = d.server || {};
  const stxt = d.security_txt || {};

  const templates = {
    tls: () => `
      <h2>🔒 TLS / HTTPS Details</h2>
      <table class="modal-table">
        <tr><th>Protokoll</th><td>${tls.version || '–'}</td></tr>
        <tr><th>Cipher</th><td>${tls.cipher || '–'}</td></tr>
        <tr><th>Zertifikatstyp</th><td>${tls.cert_type || '–'}</td></tr>
        <tr><th>Aussteller</th><td>${tls.cert_issuer?.organizationName || '–'}</td></tr>
        <tr><th>Gültig bis</th><td>${tls.valid_until || '–'} (${tls.days_remaining ?? '?'} Tage)</td></tr>
        <tr><th>SANs</th><td>${(tls.cert_san || []).slice(0, 8).join(', ') || '–'}</td></tr>
        <tr><th>HSTS</th><td>${tls.hsts ? `✓ max-age=${tls.hsts_max_age}` : '✗ nicht gesetzt'}</td></tr>
        <tr><th>Mixed Content</th><td>${
          tls.mixed_content
            ? `⚠️ ${tls.mixed_content_count} unsichere HTTP-Ressource(n)<br>
               <div style="margin-top:8px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--muted)">
                 ${(tls.mixed_content_urls || []).slice(0, 5).map(u =>
                   `<div style="margin-bottom:4px;word-break:break-all">• ${u}</div>`
                 ).join('')}
                 ${tls.mixed_content_count > 5
                   ? `<div style="color:var(--yellow)">… und ${tls.mixed_content_count - 5} weitere</div>`
                   : ''}
               </div>`
            : '✓ Kein Mixed Content erkannt'
        }</td></tr>
        <tr><th>HTTP→HTTPS</th><td>${
          /* ── NEU (Feature 2) ── */
          tls.redirect_error
            ? `⚠️ Nicht prüfbar: ${tls.redirect_error}`
            : tls.redirect_to_https
              ? `✓ Weiterleitung aktiv (${tls.redirect_hops} Hop(s))<br>
                 <div style="margin-top:8px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--muted)">
                   ${(tls.redirect_chain || []).map((u, i) =>
                     `<div style="margin-bottom:2px">${i === 0 ? '→' : '↳'} ${u}</div>`
                   ).join('')}
                 </div>`
              : '✗ Keine HTTP→HTTPS Weiterleitung'
        }</td></tr>
        <tr><th>www-Redirect</th><td>${
          /* ── NEU (Feature 2) ── */
          tls.www_redirect ? '✓ www. leitet korrekt weiter' : '✗ www. leitet nicht auf HTTPS'
        }</td></tr>
        <tr><th>security.txt</th><td>${stxt.found ? `✓ ${stxt.contact || ''}` : '✗ nicht gefunden'}</td></tr>
      </table>`,

    compliance: () => `
      <h2>📋 Compliance Details</h2>
      <table class="modal-table">
        <tr><th>Impressum</th><td>${comp.has_impressum ? '✓' : '✗'} ${comp.impressum_url ? `<a href="${comp.impressum_url}" target="_blank">${comp.impressum_url}</a>` : ''}</td></tr>
        <tr><th>Datenschutz</th><td>${comp.has_privacy ? '✓' : '✗'} ${comp.privacy_url ? `<a href="${comp.privacy_url}" target="_blank">${comp.privacy_url}</a>` : ''}</td></tr>
        <tr><th>DSB</th><td>${comp.has_dsb ? '✓' : '✗'} ${comp.dsb_name || ''}</td></tr>
        <tr><th>DSB E-Mail</th><td>${comp.dsb_email || '–'}</td></tr>
      </table>`,

    iso: () => `
      <h2>🏅 ISO-Zertifizierungen</h2>
      ${(comp.iso_certifications || []).length === 0
        ? '<p>Keine ISO-Normen erkannt.</p>'
        : (comp.iso_evidence || []).map(ev => `
            <div class="evidence-block">
              <strong>${ev.norm}</strong>
              <blockquote>${ev.snippet}</blockquote>
            </div>`).join('')}`,

    server: () => `
      <h2>🌍 Server & Geo Details</h2>
      <table class="modal-table">
        <tr><th>IP</th><td>${srv.ip || '–'}</td></tr>
        <tr><th>Land</th><td>${srv.country || '–'} (${srv.country_code || '–'})</td></tr>
        <tr><th>Stadt</th><td>${srv.city || '–'}</td></tr>
        <tr><th>Organisation</th><td>${srv.org || '–'}</td></tr>
        <tr><th>CDN</th><td>${srv.cdn_detected ? `✓ ${srv.cdn_name || 'Ja'}` : '✗ kein CDN erkannt'}</td></tr>
        <tr><th>EU-Server</th><td>${srv.is_eu ? '✓ Ja' : '✗ Nein'}</td></tr>
      </table>`,
  };

  const fn = templates[type];
  if (!fn) return;
  $('modal-body').innerHTML = fn();
  show($('modal-overlay'));
}

function closeModal() {
  hide($('modal-overlay'));
}
