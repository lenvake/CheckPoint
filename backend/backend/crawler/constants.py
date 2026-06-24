import re

TIMEOUT = 10  # erhöht von 7 auf 10 für langsamere Server

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

# ── Seed-Paths: massiv erweitert (DE + EN + FR + NL + weitere) ───────────────
SEED_PATHS = [
    # Startseite
    "/",
    # Impressum – DE
    "/impressum", "/impressum.html", "/impressum.php",
    "/de/impressum", "/de-de/impressum", "/de/impressum.html",
    # Impressum – EN
    "/imprint", "/imprint.html", "/legal", "/legal-notice",
    "/legal/imprint", "/legal/impressum", "/about/legal",
    "/en/imprint", "/en/legal", "/en/legal-notice",
    # Datenschutz – DE
    "/datenschutz", "/datenschutz.html", "/datenschutzerklaerung",
    "/datenschutzerklaerung.html", "/datenschutz-erklaerung",
    "/de/datenschutz", "/de/datenschutzerklaerung",
    # Datenschutz – EN
    "/privacy", "/privacy-policy", "/privacy.html",
    "/privacy-policy.html", "/data-protection",
    "/en/privacy", "/en/privacy-policy", "/en/data-protection",
    # Datenschutz – weitere Sprachen
    "/politique-de-confidentialite",   # FR
    "/privacybeleid",                  # NL
    "/politica-de-privacidad",         # ES
    # Security
    "/security", "/security.html",
    "/.well-known/security.txt", "/security.txt",
    # Trust / Compliance / ISO
    "/trust", "/trust-center", "/trustcenter",
    "/compliance", "/compliance.html",
    "/zertifizierungen", "/zertifikate", "/certifications",
    "/iso", "/iso-zertifizierung", "/iso-certification",
    "/qualitaet", "/qualitaetsmanagement", "/quality",
    # About / Über uns
    "/about", "/about-us", "/ueber-uns", "/ueber-uns.html",
    "/unternehmen", "/unternehmen.html", "/company",
    # Kontakt
    "/kontakt", "/contact", "/contact.html",
    # Footer-typische Seiten
    "/agb", "/terms", "/terms-of-service", "/nutzungsbedingungen",
    "/cookie-policy", "/cookies",
]

# ── Datenschutz-Keywords: massiv erweitert ────────────────────────────────────
PRIV_KW = [
    # Deutsch
    "datenschutz", "datenschutzerklärung", "datenschutzerklaerung",
    "datenschutzhinweise", "datenschutzinformation", "datenschutzrichtlinie",
    "datenschutzbeauftragter", "datenschutzbeauftragte",
    "personenbezogene daten", "verarbeitung personenbezogener",
    "dsgvo", "ds-gvo", "eu-dsgvo",
    "datenschutz-grundverordnung",
    # Englisch
    "privacy", "privacy policy", "privacy notice", "privacy statement",
    "data protection", "data protection policy", "data protection notice",
    "gdpr", "general data protection regulation",
    "personal data", "processing of personal data",
    "data subject", "data controller", "data processor",
    # Weitere
    "cookie", "cookies", "tracking",
    "privacybeleid",           # NL
    "politique de confidentialité",  # FR
    "politica de privacidad",  # ES
]

# ── Impressum-Keywords: massiv erweitert ──────────────────────────────────────
IMPR_KW = [
    # Deutsch
    "impressum", "anbieterkennzeichnung", "diensteanbieter",
    "pflichtangaben", "anbieter", "herausgeber",
    "verantwortlich", "verantwortlicher", "verantwortliche",
    "handelsregister", "amtsgericht", "registergericht",
    "umsatzsteuer-identifikationsnummer", "ust-id", "ust.-id",
    "steuernummer", "geschäftsführer", "geschaeftsfuehrer",
    "vorstand", "aufsichtsrat",
    # Englisch
    "imprint", "legal notice", "legal information", "legal disclosure",
    "site notice", "website notice",
    "registered office", "company registration",
    "vat number", "vat id", "tax number",
    "managing director", "chief executive",
    # Strukturelle Signale (Adresse, Registernummer)
    "gmbh", "ag ", " se ", " kg ", " ohg ", " gbr ",
    "limited", " ltd", " llc", " inc",
    "plc", " bv ", " nv ", " sa ",
]

# ── DSB-Keywords: erweitert ───────────────────────────────────────────────────
DSB_KW = [
    # Deutsch
    "datenschutzbeauftragter", "datenschutzbeauftragte",
    "datenschutzbeauftragten", "datenschutzbeauftragtem",
    "behördlicher datenschutzbeauftragter",
    "externer datenschutzbeauftragter",
    "betrieblicher datenschutzbeauftragter",
    "dsb", "dsb@",
    # Englisch
    "data protection officer", "dpo", "privacy officer",
    "chief privacy officer", "cpo",
    # Kontext-Signale
    "erreichbar unter", "zu erreichen unter",
    "kontakt datenschutz", "datenschutz kontakt",
]

# ── Security-Keywords ─────────────────────────────────────────────────────────
SEC_KW = [
    "informationssicherheitspolitik", "security policy",
    "information security policy", "sicherheitsrichtlinie",
    "responsible disclosure", "vulnerability disclosure",
    "coordinated vulnerability disclosure", "cvd",
    "trust center", "security", "bug bounty",
    "penetration test", "pentest",
]

# ── ISO-Pattern: erweitert um mehr Normvarianten ──────────────────────────────
ISO_PATTERN = re.compile(
    r"\b(?:ISO|DIN(?:\s*EN)?)\s*/?(?:IEC\s*)?"
    r"(9001|27001|27017|27018|27701|22301|20000(?:-1)?|14001|45001|31000|50001|13485)\b",
    re.I,
)

# ── Certifier-Keywords: erweitert ─────────────────────────────────────────────
CERTIFIER_KW = [
    "TÜV", "TUeV", "TÜV SÜD", "TÜV Rheinland", "TÜV Nord",
    "Bureau Veritas", "DNV", "DNV GL", "SGS", "BSI",
    "Lloyd's Register", "LRQA", "DEKRA", "Intertek", "DQS",
    "Certipedia", "DAkkS", "UKAS", "ANAB",
    "zertifiziert", "zertifizierung", "zertifikat",
    "certified", "certification", "certificate",
    "akkreditiert", "akkreditierung",
    "audit", "auditiert",
]

# ── CDN-Signaturen ────────────────────────────────────────────────────────────
CDN_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "cf-cache-status"],
    "Akamai":      ["x-check-cacheable", "x-akamai-transformed"],
    "Fastly":      ["x-served-by", "x-fastly-request-id"],
    "CloudFront":  ["x-amz-cf-id", "x-amz-cf-pop"],
    "AWS":         ["x-amzn-requestid"],
    "Azure CDN":   ["x-azure-ref", "x-ec-custom-error"],
    "Google CDN":  ["x-goog-generation", "x-guploader-uploadid"],
}

# ── Regex-Patterns ────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-z]{2,}", re.I)
ADDR_RE  = re.compile(r"\b\d{5}\s+[A-ZÄÖÜa-zäöüß][a-zäöüß\s\-]+", re.I)
HREG_RE  = re.compile(r"HR[AB]\s*\d+", re.I)

# ── Consent-Banner-Selektoren (für Playwright-Klick) ─────────────────────────
# Wird in http_utils.py für den Playwright-Fallback genutzt
CONSENT_SELECTORS = [
    # OneTrust
    "#onetrust-accept-btn-handler",
    ".onetrust-accept-btn-handler",
    # Cookiebot
    "#CybotCookiebotDialogBodyButtonAccept",
    # Borlabs
    "#borlabs-cookie-btn-accept-all",
    # Usercentrics
    "[data-testid='uc-accept-all-button']",
    # Klaro
    ".klaro .cm-btn-success",
    # Generische Muster
    "button[id*='accept']",
    "button[class*='accept']",
    "button[id*='agree']",
    "button[class*='agree']",
    "button[id*='consent']",
    "button[class*='consent']",
    "button[id*='cookie']",
    "button[class*='cookie-accept']",
    # Deutsche Texte
    "button:has-text('Alle akzeptieren')",
    "button:has-text('Akzeptieren')",
    "button:has-text('Zustimmen')",
    "button:has-text('Einverstanden')",
    "button:has-text('Alle annehmen')",
    # Englische Texte
    "button:has-text('Accept all')",
    "button:has-text('Accept All')",
    "button:has-text('I agree')",
    "button:has-text('Agree')",
]

# ── Minimale HTML-Länge für SPA-Erkennung ────────────────────────────────────
# Wenn der HTML-Body kürzer ist, wird Playwright als Fallback genutzt
MIN_HTML_LENGTH = 2000
