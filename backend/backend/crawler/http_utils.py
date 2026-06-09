"""
HTTP-Fetching mit Retry, Playwright-Fallback und Hilfs-Funktionen.
"""
import logging
import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .constants import TIMEOUT, BROWSER_HEADERS, PRIV_KW, IMPR_KW, DSB_KW, SEC_KW, CDN_SIGNATURES

log = logging.getLogger("checkpoint")


# ── Domain helpers ────────────────────────────────────────────────────────────

def norm_url(u: str) -> str:
    u = u.strip()
    return u if u.startswith(("http://", "https://")) else "https://" + u


def reg_domain(u: str) -> str:
    try:
        host = urlparse(u).netloc.split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


def same_reg_domain(a: str, b: str) -> bool:
    return reg_domain(a) == reg_domain(b)


def link_score(href: str, text: str) -> int:
    combined = (href + " " + text).lower()
    score = 0
    high  = PRIV_KW + IMPR_KW + DSB_KW
    med   = SEC_KW + ["iso", "cert", "trust", "compliance", "quality"]
    for kw in high:
        if kw in combined:
            score += 10
            break
    for kw in med:
        if kw in combined:
            score += 5
            break
    return score


def detect_cdn(headers: dict) -> tuple[bool, str | None]:
    hl = {k.lower(): v for k, v in headers.items()}
    for name, sigs in CDN_SIGNATURES.items():
        for s in sigs:
            if s in hl:
                return True, name
    return False, None


def snippet(text: str, pos: int, win: int = 250) -> str:
    s = max(0, pos - win // 2)
    e = min(len(text), pos + win // 2)
    out = text[s:e].strip()
    if s > 0:
        out = "..." + out
    if e < len(text):
        out += "..."
    return out


# ── HTTP fetch ────────────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    return s


def fetch(url: str, session: requests.Session, retries: int = 1):
    for attempt in range(retries + 1):
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (429, 503) and attempt < retries:
                log.warning(f"  HTTP {r.status_code} → retry {attempt + 1}")
                time.sleep(2 ** attempt)
                continue
            return r
        except requests.exceptions.SSLError as e:
            log.warning(f"  SSL-Error {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(1)
                continue
            log.warning(f"  Timeout {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            log.warning(f"  ConnError {url}: {e}")
            return None
        except Exception as e:
            log.error(f"  FetchError {url}: {e}")
            return None
    return None


def fetch_playwright(url: str) -> str | None:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        log.info(f"  [PW] {url}")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent=BROWSER_HEADERS["User-Agent"], locale="de-DE"
            )
            page = ctx.new_page()
            page.goto(url, timeout=30000, wait_until="networkidle")
            html = page.content()
            browser.close()
            return html
    except ImportError:
        log.warning("  Playwright not installed")
        return None
    except Exception as e:
        log.warning(f"  Playwright error {url}: {e}")
        return None


def get_html(url: str, session: requests.Session) -> tuple[str | None, str | None]:
    """Returns (html_str, method) or (None, None)."""
    r = fetch(url, session)
    if r is None:
        pw = fetch_playwright(url)
        return (pw, "playwright") if pw else (None, None)
    ct = (r.headers.get("content-type") or "").lower()
    if "text/html" not in ct and "text/plain" not in ct:
        return None, None
    return r.text, "requests"
