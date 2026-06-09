"""
Haupt-Orchestrierung: crawl(url, max_pages, max_depth) -> dict
"""
import logging
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests

from .constants import SEED_PATHS, BROWSER_HEADERS
from .http_utils import make_session, fetch, get_html, norm_url, same_reg_domain
from .tls_analyzer import analyze_tls, check_hsts
from .geo_server import get_server_info
from .page_analyzer import classify_page, extract_links, parse_security_txt
from .scoring import compute_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("checkpoint")


def crawl(url: str, max_pages: int = 50, max_depth: int = 3) -> dict:
    """
    Vollständiger CheckPoint Scan einer URL.
    Gibt ein JSON serialisierbares Dict zurück.
    """
    url = norm_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    log.info(f"[SCAN] {url}")

    session = make_session()

    # ── 1. TLS Analyse ───────────────────────────────────────────────────────
    log.info("  [TLS] Analysiere Zertifikat…")
    tls = analyze_tls(hostname)

    # ── 2. Startseite abrufen (für HSTS + CDN) ───────────────────────────────
    root_resp = fetch(url, session)
    resp_headers = root_resp.headers if root_resp is not None else {}

    hsts_info = check_hsts(dict(resp_headers))
    tls.update(hsts_info)

    # ── 3. Geo / Server ──────────────────────────────────────────────────────
    log.info("  [GEO] Serverstandort…")
    server = get_server_info(hostname, dict(resp_headers))

    # ── 4. security.txt ──────────────────────────────────────────────────────
    security_txt: dict = {"found": False}
    for sec_path in ["/.well-known/security.txt", "/security.txt"]:
        sec_url = f"{parsed.scheme}://{parsed.netloc}{sec_path}"
        sec_resp = fetch(sec_url, session)
        if sec_resp and sec_resp.ok and len(sec_resp.text.strip()) > 20:
            security_txt = parse_security_txt(sec_resp.text)
            log.info(f"  [SEC] security.txt gefunden: {sec_url}")
            break

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()

    
    for path in SEED_PATHS:
        seed_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        queue.append((seed_url, 0))

    compliance_state = {
        "has_impressum":      False,
        "impressum_url":      None,
        "has_privacy":        False,
        "privacy_url":        None,
        "has_dsb":            False,
        "dsb_name":           None,
        "dsb_email":          None,
        "iso_certifications": [],
        "iso_evidence":       [],
    }

    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        cur_url, depth = queue.popleft()

        # Normalise
        cur_url = cur_url.split("#")[0].rstrip("/") or cur_url
        if cur_url in visited:
            continue
        if not same_reg_domain(cur_url, url):
            continue
        visited.add(cur_url)

        log.info(f"  [{pages_crawled + 1}/{max_pages}] GET {cur_url} (depth={depth})")
        html, method = get_html(cur_url, session)
        if not html:
            continue

        pages_crawled += 1

        # Analyse page content
        result = classify_page(cur_url, html)

        # Merge findings
        if result["is_impressum"] and not compliance_state["has_impressum"]:
            compliance_state["has_impressum"] = True
            compliance_state["impressum_url"] = cur_url

        if result["is_privacy"] and not compliance_state["has_privacy"]:
            compliance_state["has_privacy"] = True
            compliance_state["privacy_url"] = cur_url

        if result["has_dsb"] and not compliance_state["has_dsb"]:
            compliance_state["has_dsb"]   = True
            compliance_state["dsb_name"]  = result["dsb_name"]
            compliance_state["dsb_email"] = result["dsb_email"]

        for iso in result["iso_hits"]:
            if iso not in compliance_state["iso_certifications"]:
                compliance_state["iso_certifications"].append(iso)

        for ev in result["iso_evidence"]:
            if ev not in compliance_state["iso_evidence"]:
                compliance_state["iso_evidence"].append(ev)

        if depth < max_depth:
            for child_url, prio in extract_links(cur_url, html):
                if child_url not in visited:
                    queue.append((child_url, depth + 1))

    log.info(f"  Crawl abgeschlossen: {pages_crawled} Seiten")

    # ── 6. Scoring ───────────────────────────────────────────────────────────
    score_result = compute_score(tls, compliance_state, server, security_txt)

    # ── 7. Ergebnis  ─────────────────────────────────────────────────────────
    return {
        "target":      url,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "total_score": score_result["total_score"],
        "grade":       score_result["grade"],
        "score_details": score_result["score_details"],
        "tls":         tls,
        "compliance":  compliance_state,
        "server":      server,
        "security_txt": security_txt,
        "pages_crawled": pages_crawled,
    }
