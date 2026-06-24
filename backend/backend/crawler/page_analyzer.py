import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .constants import (
    PRIV_KW, IMPR_KW, DSB_KW, ISO_PATTERN, CERT_PATTERNS, CERTIFIER_KW,
    EMAIL_RE, ADDR_RE, HREG_RE, MIN_HTML_LENGTH,
)
from .http_utils import snippet, same_reg_domain, link_score

log = logging.getLogger("checkpoint")


def _text(html: str) -> str:
    try:
        return BeautifulSoup(html, "lxml").get_text(" ", strip=True)
    except Exception:
        return ""


def _lower(t: str) -> str:
    return t.lower()


def _is_spa(html: str) -> bool:
    try:
        soup = BeautifulSoup(html, "lxml")
        body = soup.find("body")
        if not body:
            return True
        text = body.get_text(" ", strip=True)
        return len(text) < MIN_HTML_LENGTH
    except Exception:
        return False


# ── Page-level classification ─────────────────────────────────────────────────

def classify_page(url: str, html: str) -> dict:
    """
    Analysiert eine gecrawlte Seite auf Compliance-Signale.
    Gibt ein Dict mit boolean Flags und extrahierten Werten zurück.
    Jeder Zertifikat-Fund enthält die Quell-URL.
    """
    text = _text(html)
    lower = _lower(text)
    url_l = url.lower()

    result = {
        "is_impressum": False,
        "is_privacy": False,
        "has_dsb": False,
        "dsb_name": None,
        "dsb_email": None,
        "cert_hits": [],      # Liste von Zertifikat-Labels (ISO 27001, COBIT, ...)
        "cert_evidence": [],  # Liste von {norm, snippet, url, certifier}
        "address_found": False,
        "email_found": False,
        "hreg_found": False,
        "is_spa": False,
        "pdf_links": [],
    }

    # SPA-Erkennung
    if _is_spa(html):
        result["is_spa"] = True
        log.info(f"  [SPA] Seite könnte SPA sein: {url}")

    # ── Impressum-Erkennung (Scoring) ─────────────────────────────────────────
    impr_score = 0

    url_impr_kw = [
        "impressum", "imprint", "legal-notice", "legal_notice",
        "legal/notice", "site-notice", "anbieterkennzeichnung",
    ]

    # Starke URL-Signale
    if any(k in url_l for k in url_impr_kw):
        impr_score += 12

    # Wenn URL eher nach Privacy aussieht, dämpfen wir Impressum (verhindert False Positives)
    if any(k in url_l for k in ["datenschutz", "privacy", "gdpr", "dsgvo", "privacy-policy", "data-protection"]):
        impr_score -= 8

    impr_hits = sum(1 for kw in IMPR_KW if kw in lower)
    impr_score += impr_hits * 2

    if ADDR_RE.search(text):
        impr_score += 5
        result["address_found"] = True
    if HREG_RE.search(text):
        impr_score += 5
        result["hreg_found"] = True
    if EMAIL_RE.search(text):
        impr_score += 2
        result["email_found"] = True

    company_forms = ["gmbh", " ag ", " se ", " kg ", " ohg ", "limited", " ltd", " llc", " inc"]
    if any(cf in lower for cf in company_forms):
        impr_score += 3

    # Gate: Impressum braucht entweder eindeutige URL ODER mehrere starke Pflichtangaben
    strong_impr_terms = [
        "handelsregister", "registergericht", "amtsgericht", "ust-id",
        "umsatzsteuer", "geschäftsführer", "geschaeftsfuehrer",
        "vertretungsberechtigt", "verantwortlich", "diensteanbieter",
    ]
    strong_impr_hits = sum(1 for t in strong_impr_terms if t in lower)

    if (any(k in url_l for k in url_impr_kw)) or (strong_impr_hits >= 2 and impr_score >= 8):
        result["is_impressum"] = True
        log.info(f"  [IMPR] Impressum erkannt (score={impr_score}, strong={strong_impr_hits}): {url}")

    # ── Datenschutz-Erkennung (Scoring) ───────────────────────────────────────
    priv_score = 0

    # Hard-Guard: "impressum" URLs sollen NICHT als Datenschutz durchgehen
    if any(k in url_l for k in ["/impressum", "imprint", "legal-notice", "legal_notice", "anbieterkennzeichnung"]):
        priv_score = -999

    # URL-Signal (stärkstes Signal)
    url_priv_kw = [
        "datenschutz", "privacy", "dsgvo", "gdpr",
        "data-protection", "data_protection", "privacybeleid",
        "politique-de-confidentialite", "politica-de-privacidad",
        "datenschutzerklaerung", "datenschutz-erklaerung",
        "privacy-policy", "privacy_policy",
    ]
    if any(k in url_l for k in url_priv_kw):
        priv_score += 15

    # Keyword-Dichte (breite Keywords wie "cookie" sind zu noisy → nur als schwaches Signal)
    broad_noisy = ["cookie", "cookies", "tracking"]
    priv_hits_strong = sum(1 for kw in PRIV_KW if kw in lower and kw not in broad_noisy)
    priv_hits_noisy = sum(1 for kw in broad_noisy if kw in lower)

    priv_score += priv_hits_strong * 2
    priv_score += min(priv_hits_noisy, 2) * 0.5

    # DSGVO-spezifische starke Signale
    strong_priv = [
        "art. 13", "artikel 13", "art. 6", "artikel 6",
        "betroffenenrechte", "auskunftsrecht", "löschungsrecht",
        "widerspruchsrecht", "datenübertragbarkeit",
        "rechtsgrundlage", "legitimate interest",
        "right to erasure", "right to access",
        "auftragsverarbeitung", "drittland",
        "standardvertragsklauseln", "sccs",
        "verantwortlicher im sinne", "controller within the meaning",
    ]
    strong_hits = sum(1 for s in strong_priv if s in lower)
    priv_score += strong_hits * 4

    # Seitenstruktur: Überschriften prüfen
    has_priv_heading = False
    try:
        soup = BeautifulSoup(html, "lxml")
        headings = " ".join(
            h.get_text(" ", strip=True).lower()
            for h in soup.find_all(["h1", "h2", "h3"])
        )
        has_priv_heading = any(k in headings for k in ["datenschutz", "privacy", "dsgvo", "gdpr", "data protection"])
        if has_priv_heading:
            priv_score += 10
    except Exception:
        pass

    # Gate: Privacy braucht entweder eindeutige URL ODER Heading-Signal ODER starke DSGVO-Signale
    has_priv_url = any(k in url_l for k in url_priv_kw)

    if priv_score >= 10 and (has_priv_url or has_priv_heading or strong_hits >= 2):
        result["is_privacy"] = True
        log.info(f"  [PRIV] Datenschutz erkannt (score={priv_score}): {url}")

    # ── DSB-Erkennung ─────────────────────────────────────────────────────────
    for kw in DSB_KW:
        idx = lower.find(kw)
        if idx == -1:
            continue

        result["has_dsb"] = True
        ctx_start = max(0, idx - 150)
        ctx_end = min(len(text), idx + 500)
        ctx = text[ctx_start:ctx_end]

        emails = EMAIL_RE.findall(ctx)
        if emails:
            preferred = [e for e in emails if any(
                x in e.lower() for x in ["datenschutz", "dpo", "privacy", "dsb"]
            )]
            result["dsb_email"] = preferred[0] if preferred else emails[0]

        for line in ctx.splitlines():
            stripped = line.strip()
            words = stripped.split()
            if (
                2 <= len(words) <= 5
                and stripped[0].isupper()
                and kw not in stripped.lower()
                and not any(x in stripped.lower() for x in ["gmbh", "ag", "str", "straße", "@"])
                and len(stripped) > 5
            ):
                result["dsb_name"] = stripped[:80]
                break

        log.info(f"  [DSB] Erkannt: {kw} → Name={result['dsb_name']}, E-Mail={result['dsb_email']}")
        break

    # ── Zertifikate-Erkennung: ISO + alle weiteren ────────────────────────────

    # 1. ISO-Normen via ISO_PATTERN
    for m in ISO_PATTERN.finditer(text):
        num = m.group(1)
        label = f"ISO {num}"
        if label not in result["cert_hits"]:
            ctx_start = max(0, m.start() - 300)
            ctx_end = min(len(text), m.end() + 300)
            ctx = text[ctx_start:ctx_end]
            has_certifier = any(c.lower() in ctx.lower() for c in CERTIFIER_KW)
            certifier = next((c for c in CERTIFIER_KW if c.lower() in ctx.lower()), None)

            result["cert_hits"].append(label)
            result["cert_evidence"].append({
                "norm": label,
                "snippet": snippet(text, m.start()),
                "url": url,
                "has_certifier": has_certifier,
                "certifier": certifier,
            })
            log.info(f"  [CERT] {label} erkannt (certifier={has_certifier}): {url}")

    # 2. Weitere Zertifikate via CERT_PATTERNS
    for pattern, label in CERT_PATTERNS:
        if label in result["cert_hits"]:
            continue
        m = pattern.search(text)
        if m:
            ctx_start = max(0, m.start() - 300)
            ctx_end = min(len(text), m.end() + 300)
            ctx = text[ctx_start:ctx_end]
            has_certifier = any(c.lower() in ctx.lower() for c in CERTIFIER_KW)
            certifier = next((c for c in CERTIFIER_KW if c.lower() in ctx.lower()), None)

            result["cert_hits"].append(label)
            result["cert_evidence"].append({
                "norm": label,
                "snippet": snippet(text, m.start()),
                "url": url,
                "has_certifier": has_certifier,
                "certifier": certifier,
            })
            log.info(f"  [CERT] {label} erkannt (certifier={has_certifier}): {url}")

    # ── PDF-Link-Erkennung ────────────────────────────────────────────────────
    try:
        soup_pdf = BeautifulSoup(html, "lxml")
        for a in soup_pdf.find_all("a", href=True):
            href = a.get("href", "").lower()
            text_a = a.get_text(" ", strip=True).lower()
            if href.endswith(".pdf") or ".pdf?" in href:
                combined = href + " " + text_a
                if any(kw in combined for kw in [
                    "impressum", "imprint", "datenschutz", "privacy",
                    "dsgvo", "zertifikat", "certificate", "iso", "compliance",
                ]):
                    result["pdf_links"].append(a.get("href"))
                    log.info(f"  [PDF] Compliance-PDF gefunden: {a.get('href')}")
    except Exception:
        pass

    return result


# ── Link extraction: Footer-Priorisierung ─────────────────────────────────────

def extract_links(base_url: str, html: str, max_links: int = 120) -> list[tuple[str, int]]:
    """
    Extrahiert Links aus einer Seite.
    Priorisiert Footer > Nav > Rest.
    """
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return []

    seen = set()
    links = []

    def _process_tag(tag, bonus: int = 0):
        href = tag.get("href", "").strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return
        abs_url = urljoin(base_url, href).split("#")[0].rstrip("/")
        if not abs_url.startswith(("http://", "https://")):
            return
        if abs_url in seen:
            return
        if not same_reg_domain(abs_url, base_url):
            return
        if any(abs_url.lower().endswith(ext) for ext in
               [".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
                ".mp4", ".mp3", ".zip", ".tar", ".gz"]):
            return
        seen.add(abs_url)
        prio = link_score(abs_url, tag.get_text(" ", strip=True)) + bonus
        links.append((abs_url, prio))

    # 1. Footer zuerst (höchster Bonus)
    for footer in soup.find_all(["footer", "div"],
                                class_=re.compile(r"footer|fu(ss|ß)zeile", re.I)):
        for a in footer.find_all("a", href=True):
            _process_tag(a, bonus=20)

    # 2. Navigation
    for nav in soup.find_all(["nav", "header", "div"],
                             class_=re.compile(r"nav|menu|header", re.I)):
        for a in nav.find_all("a", href=True):
            _process_tag(a, bonus=10)

    # 3. Alle restlichen Links
    for a in soup.find_all("a", href=True):
        _process_tag(a, bonus=0)

    links.sort(key=lambda x: x[1], reverse=True)
    return links[:max_links]


# ── Mixed Content Detection ───────────────────────────────────────────────────

def detect_mixed_content(base_url: str, html: str) -> dict:
    result = {"found": False, "urls": [], "count": 0}
    if not base_url.startswith("https://"):
        return result
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return result

    checks = [
        ("img", "src"), ("script", "src"), ("link", "href"),
        ("iframe", "src"), ("audio", "src"), ("video", "src"),
        ("source", "src"), ("embed", "src"), ("object", "data"),
    ]
    seen = set()
    for tag_name, attr in checks:
        for tag in soup.find_all(tag_name, **{attr: True}):
            val = tag.get(attr, "").strip()
            if val.startswith("http://") and val not in seen:
                seen.add(val)
                result["urls"].append(val)

    result["count"] = len(result["urls"])
    result["found"] = result["count"] > 0
    if result["found"]:
        log.warning(f"  [MIXED] {result['count']} unsichere Ressourcen auf {base_url}")
    return result


# ── security.txt ──────────────────────────────────────────────────────────────

def parse_security_txt(content: str) -> dict:
    result = {
        "found": True, "contact": None, "expires": None,
        "encryption": None, "policy": None, "hiring": None,
    }
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("contact:"):
            result["contact"] = line.split(":", 1)[1].strip()
        elif low.startswith("expires:"):
            result["expires"] = line.split(":", 1)[1].strip()
        elif low.startswith("encryption:"):
            result["encryption"] = line.split(":", 1)[1].strip()
        elif low.startswith("policy:"):
            result["policy"] = line.split(":", 1)[1].strip()
        elif low.startswith("hiring:"):
            result["hiring"] = line.split(":", 1)[1].strip()
    return result

