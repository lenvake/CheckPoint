import logging
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .constants import SEED_PATHS, BROWSER_HEADERS
from .http_utils import (
    make_session, fetch, get_html, norm_url, same_reg_domain,
    check_redirect_chain, fetch_sitemap_urls, extract_pdf_text,
)
from .tls_analyzer import analyze_tls, check_hsts
from .geo_server import get_server_info
from .dns_security import analyze_dns_security
from .page_analyzer import classify_page, extract_links, parse_security_txt, detect_mixed_content
from .scoring import compute_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("checkpoint")


def _merge_compliance(state: dict, result: dict, cur_url: str):
    """Compliance-Findings aus classify_page in den State mergen."""
    if result["is_impressum"] and not state["has_impressum"]:
        state["has_impressum"] = True
        state["impressum_url"] = cur_url
        log.info(f"  [✓] Impressum gefunden: {cur_url}")

    if result["is_privacy"] and not state["has_privacy"]:
        state["has_privacy"] = True
        state["privacy_url"] = cur_url
        log.info(f"  [✓] Datenschutz gefunden: {cur_url}")

    if result["has_dsb"] and not state["has_dsb"]:
        state["has_dsb"]   = True
        state["dsb_name"]  = result["dsb_name"]
        state["dsb_email"] = result["dsb_email"]
        log.info(f"  [✓] DSB gefunden: {result['dsb_name']} / {result['dsb_email']}")

    # Zertifikate mergen (cert_hits + cert_evidence mit URL)
    for cert in result.get("cert_hits", []):
        if cert not in state["certifications"]:
            state["certifications"].append(cert)

    for ev in result.get("cert_evidence", []):
        # Deduplizieren nach norm+url
        exists = any(
            e["norm"] == ev["norm"] and e["url"] == ev["url"]
            for e in state["cert_evidence"]
        )
        if not exists:
            state["cert_evidence"].append(ev)


def crawl(url: str, max_pages: int = 80, max_depth: int = 3) -> dict:
    """
    Vollständiger CheckPoint Scan einer URL.
    Gibt ein JSON serialisierbares Dict zurück.
    """
    url      = norm_url(url)
    parsed   = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    log.info(f"[SCAN] {url}")

    session = make_session()

    # ── 1. TLS Analyse ───────────────────────────────────────────────────────
    log.info("  [TLS] Analysiere Zertifikat…")
    tls = analyze_tls(hostname)

    # ── 2. Startseite abrufen (für HSTS + CDN) ───────────────────────────────
    root_resp    = fetch(url, session)
    resp_headers = root_resp.headers if root_resp is not None else {}
    hsts_info    = check_hsts(dict(resp_headers))
    tls.update(hsts_info)

    # ── 3. Geo / Server ──────────────────────────────────────────────────────
    log.info("  [GEO] Serverstandort…")
    server = get_server_info(hostname, dict(resp_headers))

    # ── 4. DNS-Security ─────────────────────────────────────────────────────
    log.info("  [DNS] DNS-Security (DNSSEC/SPF/DMARC/DKIM/MX)…")
    dns_security = analyze_dns_security(hostname)

    # ── 5. security.txt ──────────────────────────────────────────────────────
    security_txt: dict = {"found": False}
    for sec_path in ["/.well-known/security.txt", "/security.txt"]:
        sec_url  = f"{parsed.scheme}://{parsed.netloc}{sec_path}"
        sec_resp = fetch(sec_url, session)
        if sec_resp and sec_resp.ok and len(sec_resp.text.strip()) > 20:
            security_txt = parse_security_txt(sec_resp.text)
            log.info(f"  [SEC] security.txt gefunden: {sec_url}")
            break

    # ── 5. Mixed Content Detection (Feature 1) ───────────────────────────────
    tls["mixed_content"]       = False
    tls["mixed_content_urls"]  = []
    tls["mixed_content_count"] = 0

    if tls.get("active") and root_resp is not None:
        root_html = root_resp.text if hasattr(root_resp, "text") else ""
        if root_html:
            log.info("  [MIXED] Prüfe Mixed Content auf Startseite…")
            mc = detect_mixed_content(url, root_html)
            tls["mixed_content"]       = mc["found"]
            tls["mixed_content_urls"]  = mc["urls"][:20]
            tls["mixed_content_count"] = mc["count"]
            if mc["found"]:
                log.warning(f"  [MIXED] ⚠️ {mc['count']} unsichere HTTP-Ressource(n) gefunden!")
            else:
                log.info("  [MIXED] ✓ Kein Mixed Content gefunden")

    # ── 6. HTTP→HTTPS Redirect-Check (Feature 2) ─────────────────────────────
    log.info("  [REDIRECT] Prüfe HTTP→HTTPS Weiterleitung…")
    redirect_info = check_redirect_chain(hostname, session)
    tls["redirect_to_https"]  = redirect_info["redirects_to_https"]
    tls["redirect_hops"]      = redirect_info["redirect_hops"]
    tls["redirect_chain"]     = redirect_info["redirect_chain"]
    tls["redirect_final_url"] = redirect_info["final_url"]
    tls["www_redirect"]       = redirect_info["www_redirect"]
    tls["redirect_error"]     = redirect_info["error"]

    # ── 7. Sitemap.xml parsen ─────────────────────────────────────────────────
    log.info("  [SITEMAP] Suche relevante URLs in sitemap.xml…")
    sitemap_urls = fetch_sitemap_urls(url, session, max_urls=50)
    log.info(f"  [SITEMAP] {len(sitemap_urls)} relevante URLs gefunden")

    # ── 8. BFS-Crawl ─────────────────────────────────────────────────────────
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()

    # Seed-Paths
    for path in SEED_PATHS:
        seed_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        queue.append((seed_url, 0))

    # Sitemap-URLs mit hoher Priorität vorne einreihen
    for su in sitemap_urls:
        if same_reg_domain(su, url):
            queue.appendleft((su, 1))

    compliance_state = {
        "has_impressum":   False,
        "impressum_url":   None,
        "has_privacy":     False,
        "privacy_url":     None,
        "has_dsb":         False,
        "dsb_name":        None,
        "dsb_email":       None,
        # Umbenannt: iso_certifications → certifications (jetzt alle Zertifikate)
        "certifications":  [],
        "cert_evidence":   [],
        # Rückwärtskompatibilität für scoring.py
        "iso_certifications": [],
        "iso_evidence":       [],
    }

    pages_crawled = 0
    pdf_queue: list[str] = []

    while queue and pages_crawled < max_pages:
        cur_url, depth = queue.popleft()

        cur_url = cur_url.split("#")[0].rstrip("/") or cur_url
        if cur_url in visited:
            continue
        if not same_reg_domain(cur_url, url):
            continue
        visited.add(cur_url)

        log.info(f"  [{pages_crawled + 1}/{max_pages}] GET {cur_url} (depth={depth})")

        # Playwright nur gezielt: für stark verdächtige Compliance-Links (privacy/impressum/trust/iso/...)
        allow_pw = any(k in cur_url.lower() for k in [
            "impressum", "imprint", "datenschutz", "privacy", "gdpr", "dsgvo",
            "trust", "compliance", "iso", "zert", "cert", "security",
            "ueber", "about", "company",
        ])
        html, method = get_html(cur_url, session, allow_playwright=allow_pw)
        if not html:
            continue

        pages_crawled += 1

        result = classify_page(cur_url, html)

        # PDF-Links sammeln
        for pdf_link in result.get("pdf_links", []):
            abs_pdf = pdf_link if pdf_link.startswith("http") else \
                      f"{parsed.scheme}://{parsed.netloc}{pdf_link}"
            if abs_pdf not in pdf_queue:
                pdf_queue.append(abs_pdf)

        # Compliance mergen
        _merge_compliance(compliance_state, result, cur_url)

        # Rückwärtskompatibilität (wichtig, bitte funktion testen):
        # iso_certifications soll NUR ISO-* enthalten (für Scoring/Anzeige),
        # certifications bleibt die breite Liste (ISO + COBIT + SOC2 + ...).
        compliance_state["iso_certifications"] = sorted(
            [c for c in compliance_state["certifications"] if c.upper().startswith("ISO ")]
        )
        compliance_state["iso_evidence"] = [
            e for e in compliance_state["cert_evidence"]
            if str(e.get("norm", "")).upper().startswith("ISO ")
        ]

        # Frühzeitiger Abbruch wenn alles gefunden
        if (compliance_state["has_impressum"]
                and compliance_state["has_privacy"]
                and compliance_state["has_dsb"]
                and len(compliance_state["certifications"]) > 0):
            log.info("  [✓] Alle Compliance-Signale gefunden – Crawl beendet")
            break

        # Links für nächste Ebene
        if depth < max_depth:
            for child_url, prio in extract_links(cur_url, html):
                if child_url not in visited:
                    # stärkere Priorisierung für Privacy/Impressum/Trust/Cert
                    if prio >= 10:
                        queue.appendleft((child_url, depth + 1))
                    else:
                        queue.append((child_url, depth + 1))

    log.info(f"  Crawl abgeschlossen: {pages_crawled} Seiten")

    # ── 9. PDF-Verarbeitung ───────────────────────────────────────────────────
    if pdf_queue and not (compliance_state["has_impressum"] and compliance_state["has_privacy"]):
        log.info(f"  [PDF] Verarbeite {len(pdf_queue)} PDF-Datei(en)…")
        for pdf_url in pdf_queue[:5]:
            pdf_text = extract_pdf_text(pdf_url, session)
            if pdf_text:
                pseudo_html = f"<html><body>{pdf_text}</body></html>"
                result = classify_page(pdf_url, pseudo_html)
                _merge_compliance(compliance_state, result, pdf_url)
                compliance_state["iso_certifications"] = sorted(
                    [c for c in compliance_state["certifications"] if c.upper().startswith("ISO ")]
                )
                compliance_state["iso_evidence"] = [
                    e for e in compliance_state["cert_evidence"]
                    if str(e.get("norm", "")).upper().startswith("ISO ")
                ]

    # ── 10. Scoring ──────────────────────────────────────────────────────────
    score_result = compute_score(tls, compliance_state, server, security_txt, dns_security)

    # ── 11. Ergebnis ─────────────────────────────────────────────────────────
    return {
        "target":        url,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "total_score":   score_result["total_score"],
        "grade":         score_result["grade"],
        "score_details": score_result["score_details"],
        "tls":           tls,
        "compliance":    compliance_state,
        "server":        server,
        "security_txt":  security_txt,
        "dns_security":  dns_security,
        "pages_crawled": pages_crawled,
    }
