"""
HTTP-Fetching mit Retry, Playwright-Fallback und Hilfs-Funktionen.
Feature 2: check_redirect_chain() für HTTP→HTTPS Redirect-Check
Verbesserungen:
  - Playwright-Fallback aggressiver: wird auch bei SPA-Erkennung getriggert
  - Consent-Banner automatisch wegklicken via Playwright
  - PDF-Text-Extraktion via pdfplumber
  - Sitemap.xml parsen für bessere Seed-URLs
"""
import logging
import time
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from .constants import (
    TIMEOUT, BROWSER_HEADERS, PRIV_KW, IMPR_KW, DSB_KW, SEC_KW,
    CDN_SIGNATURES, CONSENT_SELECTORS, MIN_HTML_LENGTH,
)

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


def snippet(text: str, pos: int, win: int = 300) -> str:
    s = max(0, pos - win // 2)
    e = min(len(text), pos + win // 2)
    out = text[s:e].strip()
    if s > 0:
        out = "..." + out
    if e < len(text):
        out += "..."
    return out


# ── HTTP→HTTPS Redirect-Check (Feature 2) ────────────────────────────────────

def check_redirect_chain(hostname: str, session: requests.Session) -> dict:
    """
    Prüft ob http://<hostname> korrekt auf https://<hostname> weiterleitet.
    """
    result = {
        "redirects_to_https": False,
        "redirect_hops":      0,
        "redirect_chain":     [],
        "final_url":          None,
        "www_redirect":       False,
        "error":              None,
    }

    http_url = f"http://{hostname}"

    try:
        resp = session.get(http_url, timeout=TIMEOUT, allow_redirects=True)
        chain = [r.url for r in resp.history] + [resp.url]
        result["redirect_chain"] = chain
        result["redirect_hops"]  = len(resp.history)
        result["final_url"]      = resp.url

        if resp.url.startswith("https://"):
            result["redirects_to_https"] = True
            log.info(f"  [REDIRECT] ✓ {http_url} → {resp.url} ({len(resp.history)} Hop(s))")
        else:
            log.warning(f"  [REDIRECT] ✗ {http_url} landet auf {resp.url} (kein HTTPS)")

        if not hostname.startswith("www."):
            www_url = f"http://www.{hostname}"
            try:
                www_resp = session.get(www_url, timeout=TIMEOUT, allow_redirects=True)
                result["www_redirect"] = www_resp.url.startswith("https://")
                log.info(f"  [REDIRECT] www: {www_url} → {www_resp.url}")
            except Exception as e:
                log.warning(f"  [REDIRECT] www-Check fehlgeschlagen: {e}")

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Verbindungsfehler: {e}"
        log.warning(f"  [REDIRECT] Verbindungsfehler für {http_url}: {e}")
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
        log.warning(f"  [REDIRECT] Timeout für {http_url}")
    except Exception as e:
        result["error"] = str(e)
        log.warning(f"  [REDIRECT] Fehler für {http_url}: {e}")

    return result


# ── Sitemap-Parser ────────────────────────────────────────────────────────────

def fetch_sitemap_urls(base_url: str, session: requests.Session, max_urls: int = 50) -> list[str]:
    """
    Liest sitemap.xml und extrahiert URLs die auf Compliance-Seiten hinweisen.
    Unterstützt sitemap index files (verschachtelte Sitemaps).
    """
    parsed   = urlparse(base_url)
    sitemap_candidates = [
        f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
        f"{parsed.scheme}://{parsed.netloc}/sitemap_index.xml",
        f"{parsed.scheme}://{parsed.netloc}/sitemap-index.xml",
        f"{parsed.scheme}://{parsed.netloc}/sitemaps/sitemap.xml",
    ]

    compliance_kw = [
        "impressum", "imprint", "datenschutz", "privacy", "legal",
        "compliance", "trust", "iso", "zertifizierung", "certification",
        "dsgvo", "gdpr", "contact", "kontakt", "about", "ueber",
    ]

    found_urls = []

    for sitemap_url in sitemap_candidates:
        try:
            resp = session.get(sitemap_url, timeout=TIMEOUT)
            if not resp.ok:
                continue

            soup = BeautifulSoup(resp.text, "xml")

            # Sitemap-Index: enthält <sitemap><loc>...</loc></sitemap>
            sub_sitemaps = soup.find_all("sitemap")
            if sub_sitemaps:
                for sm in sub_sitemaps[:5]:  # max 5 Sub-Sitemaps
                    loc = sm.find("loc")
                    if not loc:
                        continue
                    try:
                        sub_resp = session.get(loc.text.strip(), timeout=TIMEOUT)
                        if sub_resp.ok:
                            sub_soup = BeautifulSoup(sub_resp.text, "xml")
                            for url_tag in sub_soup.find_all("url"):
                                loc2 = url_tag.find("loc")
                                if loc2:
                                    u = loc2.text.strip()
                                    if any(kw in u.lower() for kw in compliance_kw):
                                        found_urls.append(u)
                    except Exception:
                        continue

            # Normale Sitemap: enthält <url><loc>...</loc></url>
            for url_tag in soup.find_all("url"):
                loc = url_tag.find("loc")
                if not loc:
                    continue
                u = loc.text.strip()
                if any(kw in u.lower() for kw in compliance_kw):
                    found_urls.append(u)

            if found_urls:
                log.info(f"  [SITEMAP] {len(found_urls)} relevante URLs aus {sitemap_url}")
                break

        except Exception as e:
            log.debug(f"  [SITEMAP] Fehler bei {sitemap_url}: {e}")
            continue

    # Deduplizieren und limitieren
    seen = set()
    result = []
    for u in found_urls:
        if u not in seen:
            seen.add(u)
            result.append(u)
        if len(result) >= max_urls:
            break

    return result


# ── PDF-Text-Extraktion ───────────────────────────────────────────────────────

def extract_pdf_text(url: str, session: requests.Session) -> str | None:
    """
    Lädt eine PDF-Datei und extrahiert den Text via pdfplumber.
    Gibt None zurück wenn pdfplumber nicht verfügbar oder Fehler auftritt.
    """
    try:
        import pdfplumber
        import io

        resp = session.get(url, timeout=TIMEOUT)
        if not resp.ok:
            return None

        content_type = resp.headers.get("content-type", "").lower()
        if "pdf" not in content_type and not url.lower().endswith(".pdf"):
            return None

        with pdfplumber.open(io.BytesIO(resp.content)) as pdf:
            text = "\n".join(
                page.extract_text() or ""
                for page in pdf.pages[:10]  # max 10 Seiten
            )
            log.info(f"  [PDF] Text extrahiert: {len(text)} Zeichen aus {url}")
            return text

    except ImportError:
        log.debug("  [PDF] pdfplumber nicht installiert")
        return None
    except Exception as e:
        log.warning(f"  [PDF] Fehler bei {url}: {e}")
        return None


# ── HTTP fetch ────────────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    return s


def fetch(url: str, session: requests.Session, retries: int = 2) -> requests.Response | None:
    """Fetch mit Retry-Logik. retries erhöht auf 2 für bessere Zuverlässigkeit."""
    for attempt in range(retries + 1):
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (429, 503) and attempt < retries:
                wait = 2 ** attempt
                log.warning(f"  HTTP {r.status_code} → retry {attempt + 1} (warte {wait}s)")
                time.sleep(wait)
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


def fetch_playwright(url: str, click_consent: bool = True) -> str | None:
    """
    Playwright-Fallback für SPAs und Seiten mit Consent-Bannern.
    click_consent=True: versucht automatisch Consent-Banner wegzuklicken.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout  # type: ignore
        log.info(f"  [PW] Starte Playwright für {url}")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent=BROWSER_HEADERS["User-Agent"],
                locale="de-DE",
                viewport={"width": 1280, "height": 900},
            )
            page = ctx.new_page()

            # Seite laden
            try:
                page.goto(url, timeout=30000, wait_until="domcontentloaded")
                # Kurz warten damit JS rendern kann
                page.wait_for_timeout(2000)
            except PWTimeout:
                log.warning(f"  [PW] Timeout beim Laden von {url}")
                browser.close()
                return None

            # Consent-Banner wegklicken
            if click_consent:
                for selector in CONSENT_SELECTORS:
                    try:
                        # Playwright :has-text() Selektoren direkt nutzen
                        btn = page.locator(selector).first
                        if btn.is_visible(timeout=500):
                            btn.click(timeout=1000)
                            log.info(f"  [PW] Consent-Banner geklickt: {selector}")
                            page.wait_for_timeout(1000)
                            break
                    except Exception:
                        continue

            # Nochmal warten nach Consent-Klick
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

            html = page.content()
            browser.close()
            log.info(f"  [PW] HTML geladen: {len(html)} Zeichen")
            return html

    except ImportError:
        log.warning("  [PW] Playwright nicht installiert")
        return None
    except Exception as e:
        log.warning(f"  [PW] Fehler für {url}: {e}")
        return None


def get_html(url: str, session: requests.Session, force_playwright: bool = False) -> tuple[str | None, str | None]:
    """
    Lädt HTML einer URL.
    Nutzt Playwright als Fallback wenn:
      - requests fehlschlägt
      - force_playwright=True
      - HTML zu kurz (SPA-Verdacht)
    Gibt (html_str, method) oder (None, None) zurück.
    """
    if force_playwright:
        pw = fetch_playwright(url)
        return (pw, "playwright") if pw else (None, None)

    r = fetch(url, session)

    # Playwright-Fallback wenn requests fehlschlägt
    if r is None:
        log.info(f"  [HTML] requests fehlgeschlagen → Playwright-Fallback für {url}")
        pw = fetch_playwright(url)
        return (pw, "playwright") if pw else (None, None)

    ct = (r.headers.get("content-type") or "").lower()
    if "text/html" not in ct and "text/plain" not in ct:
        return None, None

    html = r.text

    # SPA-Erkennung: HTML zu kurz → Playwright-Fallback
    try:
        from bs4 import BeautifulSoup as _BS
        body = _BS(html, "lxml").find("body")
        body_text = body.get_text(" ", strip=True) if body else ""
        if len(body_text) < MIN_HTML_LENGTH:
            log.info(f"  [SPA] Zu wenig Text ({len(body_text)} Zeichen) → Playwright für {url}")
            pw = fetch_playwright(url)
            if pw and len(pw) > len(html):
                return pw, "playwright"
    except Exception:
        pass

    return html, "requests"
