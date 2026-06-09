"""
Seiten-Analyse: Impressum, Datenschutz, DSB, ISO, security.txt, Links.
"""
import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .constants import (
    PRIV_KW, IMPR_KW, DSB_KW, ISO_PATTERN, CERTIFIER_KW,
    EMAIL_RE, ADDR_RE, HREG_RE,
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


# ── Page-level classification ─────────────────────────────────────────────────

def classify_page(url: str, html: str) -> dict:
    """
    Returns a dict with boolean flags for what was detected on this page.
    """
    text  = _text(html)
    lower = _lower(text)

    result = {
        "is_impressum":  False,
        "is_privacy":    False,
        "has_dsb":       False,
        "dsb_name":      None,
        "dsb_email":     None,
        "iso_hits":      [],
        "iso_evidence":  [],
        "address_found": False,
        "email_found":   False,
        "hreg_found":    False,
    }

    url_l = url.lower()

    # Impressum signals
    impr_url = any(k in url_l for k in ["impressum", "imprint", "legal"])
    impr_txt = sum(1 for kw in IMPR_KW if kw in lower)
    if impr_url or impr_txt >= 2:
        result["is_impressum"] = True

    # Privacy signals
    priv_url = any(k in url_l for k in ["datenschutz", "privacy", "dsgvo", "gdpr"])
    priv_txt = sum(1 for kw in PRIV_KW if kw in lower)
    if priv_url or priv_txt >= 2:
        result["is_privacy"] = True

    # DSB detection
    for kw in DSB_KW:
        idx = lower.find(kw)
        if idx != -1:
            result["has_dsb"] = True
            ctx = text[max(0, idx - 120): idx + 400]
            # Try to extract name (line before/after keyword)
            for line in ctx.splitlines():
                stripped = line.strip()
                if stripped and kw not in stripped.lower() and len(stripped) > 4:
                    result["dsb_name"] = stripped[:80]
                    break
            emails = EMAIL_RE.findall(ctx)
            if emails:
                result["dsb_email"] = emails[0]
            break

    # ISO detection
    for m in ISO_PATTERN.finditer(text):
        norm_str = m.group(0).upper().replace(" ", "").replace("/", "").replace("IEC", "")
        # Normalise to "ISO XXXXX"
        num = m.group(1)
        label = f"ISO {num}"
        if label not in result["iso_hits"]:
            result["iso_hits"].append(label)
            result["iso_evidence"].append({
                "norm": label,
                "snippet": snippet(text, m.start()),
            })

    # Address / HReg / Email
    if ADDR_RE.search(text):
        result["address_found"] = True
    if HREG_RE.search(text):
        result["hreg_found"] = True
    if EMAIL_RE.search(text):
        result["email_found"] = True

    return result


# ── Link extraction ───────────────────────────────────────────────────────────

def extract_links(base_url: str, html: str, max_links: int = 80) -> list[tuple[str, int]]:
    """
    Parse all <a href> links from page.
    Returns list of (absolute_url, priority_score), filtered to same domain.
    """
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return []

    seen = set()
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        abs_url = urljoin(base_url, href).split("#")[0].rstrip("/")
        if not abs_url.startswith(("http://", "https://")):
            continue
        if abs_url in seen:
            continue
        if not same_reg_domain(abs_url, base_url):
            continue
        seen.add(abs_url)
        prio = link_score(abs_url, tag.get_text(" ", strip=True))
        links.append((abs_url, prio))

    # Sort by priority desc, limit
    links.sort(key=lambda x: x[1], reverse=True)
    return links[:max_links]


# ── security.txt ──────────────────────────────────────────────────────────────

def parse_security_txt(content: str) -> dict:
    result = {"found": True, "contact": None, "expires": None, "encryption": None, "policy": None}
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("contact:"):
            result["contact"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("expires:"):
            result["expires"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("encryption:"):
            result["encryption"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("policy:"):
            result["policy"] = line.split(":", 1)[1].strip()
    return result
