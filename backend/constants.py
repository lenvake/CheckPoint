import re

TIMEOUT = 7

BROWSER_HEADERS = { #gefälschter User Agent
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

SEED_PATHS = [
    "/", "/impressum", "/imprint", "/legal", "/legal-notice",
    "/privacy", "/datenschutz", "/privacy-policy",
    "/security", "/trust", "/compliance",
    "/.well-known/security.txt", "/security.txt",
    "/about", "/de/impressum", "/de/datenschutz",
]

PRIV_KW = [
    "datenschutz", "datenschutzerklärung", "datenschutzerklaerung",
    "privacy", "privacy policy", "data protection", "gdpr", "dsgvo",
    "cookie", "personenbezogene daten", "datenschutzhinweise",
]
IMPR_KW = [
    "impressum", "imprint", "legal notice", "legal", "site notice",
    "anbieterkennzeichnung", "diensteanbieter", "pflichtangaben",
    "anbieter", "herausgeber",
]
DSB_KW = [
    "datenschutzbeauftragter", "datenschutzbeauftragte", "datenschutzbeauftragten",
    "data protection officer", "dpo", "privacy officer", "dsb",
    "behördlicher datenschutzbeauftragter",
]
SEC_KW = [
    "informationssicherheitspolitik", "security policy", "information security policy",
    "sicherheitsrichtlinie", "responsible disclosure", "vulnerability disclosure",
    "trust center", "security",
]

ISO_PATTERN = re.compile(
    r"\bISO\s*/?(?:IEC\s*)?(9001|27001|22301|27701|20000(?:-1)?|14001|45001|31000)\b",
    re.I,
)
CERTIFIER_KW = [
    "TÜV", "TUeV", "Bureau Veritas", "DNV", "SGS", "BSI",
    "Lloyd's Register", "DEKRA", "Intertek", "LRQA", "DQS",
]

CDN_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "cf-cache-status"],
    "Akamai":      ["x-check-cacheable", "x-akamai-transformed"],
    "Fastly":      ["x-served-by", "x-fastly-request-id"],
    "CloudFront":  ["x-amz-cf-id", "x-amz-cf-pop"],
    "AWS":         ["x-amzn-requestid"],
}

EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-z]{2,}", re.I)
ADDR_RE  = re.compile(r"\b\d{5}\s+[A-ZÄÖÜa-zäöüß][a-zäöüß\s\-]+", re.I)
HREG_RE  = re.compile(r"HR[AB]\s*\d+", re.I)
