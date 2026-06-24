"""
IP-Auflösung, CDN-Erkennung und Geo-Lookup via ip-api.com.
"""
import logging
import socket

import requests

from .constants import TIMEOUT
from .http_utils import detect_cdn

log = logging.getLogger("checkpoint")

EU_COUNTRY_CODES = {
    "AT","BE","BG","CY","CZ","DE","DK","EE","ES","FI","FR","GR","HR",
    "HU","IE","IT","LT","LU","LV","MT","NL","PL","PT","RO","SE","SI","SK",
    "CH","NO","IS","LI",
}


def get_server_info(hostname: str, response_headers: dict | None = None) -> dict:
    """Resolve IP, detect CDN, look up geo data."""
    out = {
        "ip": None, "country": None, "country_code": None,
        "city": None, "org": None,
        "cdn_detected": False, "cdn_name": None, "is_eu": False,
    }

    # 1. IP resolve
    try:
        out["ip"] = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        log.warning(f"  DNS resolve failed for {hostname}: {e}")
        return out

    # 2. CDN detection from response headers
    if response_headers:
        cdn_found, cdn_name = detect_cdn(response_headers)
        out["cdn_detected"] = cdn_found
        out["cdn_name"]     = cdn_name

    # 3. Geo-lookup
    try:
        r = requests.get(
            f"http://ip-api.com/json/{out['ip']}?fields=status,country,countryCode,city,org",
            timeout=TIMEOUT,
        )
        if r.ok:
            geo = r.json()
            if geo.get("status") == "success":
                out["country"]      = geo.get("country")
                out["country_code"] = geo.get("countryCode")
                out["city"]         = geo.get("city")
                out["org"]          = geo.get("org")
                out["is_eu"]        = geo.get("countryCode", "") in EU_COUNTRY_CODES
    except Exception as e:
        log.warning(f"  Geo-lookup failed: {e}")

    return out
