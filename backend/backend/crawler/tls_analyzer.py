"""
Vollständige TLS/HTTPS-Analyse: Protokoll, Zertifikat, HSTS, Chain.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone

from .constants import TIMEOUT

log = logging.getLogger("checkpoint")


def analyze_tls(hostname: str, port: int = 443) -> dict:
    out = {
        "active": False, "version": None, "cipher": None,
        "cert_subject": None, "cert_issuer": None, "cert_san": [],
        "valid_from": None, "valid_until": None, "days_remaining": None,
        "cert_expired": None, "cert_hostname_match": None, "cert_type": "DV",
        "chain": [], "hsts": False, "hsts_max_age": None,
        "hsts_includesubdomains": False, "hsts_preload": False,
        "mixed_content": False, "mixed_content_urls": [], "errors": [],
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                out["active"] = True
                out["version"] = ssock.version()
                c = ssock.cipher()
                out["cipher"] = f"{c[0]} ({c[1]}, {c[2]} bit)" if c else None

                cert   = ssock.getpeercert()
                subj   = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer",  []))
                out["cert_subject"] = subj
                out["cert_issuer"]  = issuer
                out["cert_san"]     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                # Validity dates
                fmt = "%b %d %H:%M:%S %Y %Z"
                try:
                    nb  = datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=timezone.utc)
                    na  = datetime.strptime(cert["notAfter"],  fmt).replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    out["valid_from"]     = nb.date().isoformat()
                    out["valid_until"]    = na.date().isoformat()
                    out["days_remaining"] = (na - now).days
                    out["cert_expired"]   = now > na
                except Exception as e:
                    out["errors"].append(f"date parse: {e}")

                # Hostname match
                try:
                    ssl.match_hostname(cert, hostname)
                    out["cert_hostname_match"] = True
                except ssl.CertificateError:
                    out["cert_hostname_match"] = False

                # Cert type heuristic (DV / OV / EV)
                o = subj.get("organizationName", "")
                if o and len(o) > 3 and not any(
                    x in o.lower() for x in ["let's encrypt", "digicert basic", "zerossl"]
                ):
                    ev_hints = ["ev", "extended validation", "plc", "gmbh", "ag", "inc",
                                "llc", "ltd", "se", "sa", "bv", "oy"]
                    if any(h in o.lower() for h in ev_hints):
                        out["cert_type"] = "EV"
                    else:
                        out["cert_type"] = "OV"
                else:
                    out["cert_type"] = "DV"

    except ssl.SSLCertVerificationError as e:
        out["errors"].append(f"cert verify: {e}")
    except ssl.SSLError as e:
        out["errors"].append(f"ssl: {e}")
    except (socket.timeout, TimeoutError):
        out["errors"].append("timeout")
    except OSError as e:
        out["errors"].append(f"connect: {e}")
    except Exception as e:
        out["errors"].append(f"unknown: {e}")

    return out


def check_hsts(response_headers: dict) -> dict:
    """Parse Strict-Transport-Security header."""
    result = {"hsts": False, "hsts_max_age": None,
              "hsts_includesubdomains": False, "hsts_preload": False}
    raw = response_headers.get("Strict-Transport-Security", "")
    if not raw:
        raw = response_headers.get("strict-transport-security", "")
    if not raw:
        return result
    result["hsts"] = True
    parts = [p.strip().lower() for p in raw.split(";")]
    for p in parts:
        if p.startswith("max-age="):
            try:
                result["hsts_max_age"] = int(p.split("=", 1)[1])
            except ValueError:
                pass
        elif p == "includesubdomains":
            result["hsts_includesubdomains"] = True
        elif p == "preload":
            result["hsts_preload"] = True
    return result
