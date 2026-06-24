"""

Scoring (fix 100 Punkte):
- TLS / HTTPS:               20
- Compliance:                40  (Impressum/Datenschutz/DSB)
- Zertifikate & Normen:      30
- DNS Security:               5  (DNSSEC/DMARC/SPF/DKIM/MX)
- Server & Geo:               5

"""

GRADE_THRESHOLDS = [
    (95, "A+"), (85, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E"), (0, "F"),
]


def compute_score(tls: dict, compliance: dict, server: dict, security_txt: dict, dns_security: dict | None = None) -> dict:
    """Berechnet TrustScore aus den Analyse-Teilergebnissen (fix 100 Punkte)."""
    dns_security = dns_security or {}
    details: dict[str, dict] = {}

    # Defensive: sicherstellen, dass alle Punkte numeric sind
    def _n(x):
        try:
            return float(x)
        except Exception:
            return 0.0

    # ─── TLS / HTTPS (20 Punkte) ─────────────────────────────────────────────

    def tls_item(key, pts, max_pts, reason=""):
        details[key] = {"points": pts, "max": max_pts, "reason": reason}

    # 1. HTTPS erreichbar (6 Punkte)
    if tls.get("active"):
        tls_item("https_reachable", 6, 6, "HTTPS ist aktiv")
    else:
        tls_item("https_reachable", 0, 6, "HTTPS nicht erreichbar")

    # 2. TLS-Protokoll (4 Punkte)
    version = tls.get("version") or ""
    if "TLSv1.3" in version:
        tls_item("tls_protocol", 4, 4, "TLS 1.3 aktiv")
    elif "TLSv1.2" in version:
        tls_item("tls_protocol", 3, 4, "TLS 1.2 aktiv")
    elif version:
        tls_item("tls_protocol", 1, 4, f"Veraltetes Protokoll: {version}")
    else:
        tls_item("tls_protocol", 0, 4, "Kein TLS")

    # 3. Zertifikat gültig (4 Punkte)
    if tls.get("active") and not tls.get("cert_expired", True):
        tls_item("cert_valid", 4, 4, "Zertifikat ist gültig")
    else:
        tls_item("cert_valid", 0, 4, "Zertifikat abgelaufen oder nicht vorhanden")

    # 4. Ablaufdatum OK – > 30 Tage (2 Punkte)
    days = tls.get("days_remaining")
    if isinstance(days, int) and days > 30:
        tls_item("cert_not_expiring", 2, 2, f"Läuft in {days} Tagen ab")
    elif isinstance(days, int) and days >= 0:
        tls_item("cert_not_expiring", 1, 2, f"Läuft bald ab: {days} Tage")
    else:
        tls_item("cert_not_expiring", 0, 2, "Ablaufdatum unbekannt oder abgelaufen")

    # 5. Hostname Match (2 Punkte)
    if tls.get("cert_hostname_match"):
        tls_item("cert_hostname_match", 2, 2, "Hostname stimmt überein")
    elif tls.get("cert_hostname_match") is False:
        tls_item("cert_hostname_match", 0, 2, "Hostname-Mismatch!")
    else:
        tls_item("cert_hostname_match", 0, 2, "Hostname-Match nicht prüfbar")

    # 6. HSTS vorhanden (2 Punkte)
    if tls.get("hsts"):
        tls_item("hsts_present", 2, 2, "HSTS-Header gesetzt")
    else:
        tls_item("hsts_present", 0, 2, "Kein HSTS-Header")

    # 7. HSTS max-age ≥ 1 Jahr (1 Punkt)
    hsts_age = tls.get("hsts_max_age")
    if isinstance(hsts_age, int) and hsts_age >= 31536000:
        tls_item("hsts_max_age_ok", 1, 1, f"HSTS max-age={hsts_age}s (≥1 Jahr)")
    elif isinstance(hsts_age, int):
        tls_item("hsts_max_age_ok", 0, 1, f"HSTS max-age={hsts_age}s (<1 Jahr)")
    else:
        tls_item("hsts_max_age_ok", 0, 1, "HSTS nicht vorhanden oder kein max-age")

    # 8. HTTP→HTTPS Redirect (2 Punkte)
    redirects   = tls.get("redirect_to_https", False)
    hops        = tls.get("redirect_hops", 0)
    redir_error = tls.get("redirect_error")

    if redir_error:
        tls_item("https_redirect", 0, 2, f"HTTP-Redirect nicht prüfbar: {redir_error}")
    elif redirects and hops <= 2:
        tls_item("https_redirect", 2, 2, f"✓ HTTP leitet auf HTTPS weiter ({hops} Hop(s))")
    elif redirects and hops > 2:
        tls_item("https_redirect", 1, 2, f"⚠️ Redirect ok, aber {hops} Hops")
    else:
        tls_item("https_redirect", 0, 2, "✗ Kein HTTP→HTTPS Redirect")

    # 9. Mixed Content (0 Punkte, aber als Signal + Reason)
    mc_found = tls.get("mixed_content", False)
    mc_count = tls.get("mixed_content_count", 0)
    if not tls.get("active"):
        tls_item("mixed_content", 0, 0, "Nicht geprüft – kein HTTPS aktiv")
    elif mc_found:
        tls_item("mixed_content", 0, 0, f"⚠️ {mc_count} unsichere HTTP-Ressource(n) gefunden")
    else:
        tls_item("mixed_content", 0, 0, "✓ Kein Mixed Content erkannt")

    # 10. Zertifikatstyp (0 Punkte, nur Info)
    ct = tls.get("cert_type", "DV")
    tls_item("cert_type", 0, 0, f"Zertifikatstyp: {ct}")

    # ─── Compliance (40 Punkte) ─────────────────────────────────────────────

    def comp_item(key, pts, max_pts, reason=""):
        details[key] = {"points": pts, "max": max_pts, "reason": reason}

    # Impressum (15 Punkte)
    if compliance.get("has_impressum"):
        comp_item("has_impressum", 15, 15, "Impressum gefunden")
    else:
        comp_item("has_impressum", 0, 15, "Kein Impressum gefunden")

    # Datenschutz (15 Punkte)
    if compliance.get("has_privacy"):
        comp_item("has_privacy", 15, 15, "Datenschutzerklärung gefunden")
    else:
        comp_item("has_privacy", 0, 15, "Keine Datenschutzerklärung gefunden")

    # DSB (10 Punkte)
    if compliance.get("has_dsb"):
        comp_item("has_dpo", 10, 10, "Datenschutzbeauftragter erkannt")
    else:
        comp_item("has_dpo", 0, 10, "Kein DSB erkannt")

    # security.txt (0 Punkte in 100er-Modell; weiterhin als Info im TLS-Modal)
    details["security_txt"] = {
        "points": 0,
        "max": 0,
        "reason": "security.txt vorhanden" if security_txt.get("found") else "Keine security.txt",
    }

    # ─── Zertifikate & Normen (30 Punkte) ───────────────────────────────────
    certs = compliance.get("certifications", []) or []
    evidence = compliance.get("cert_evidence", []) or []

    W = {
        "ISO 27001": 12,
        "ISO 27701": 6,
        "ISO 27017": 5,
        "ISO 27018": 5,
        "ISO 22301": 6,
        "ISO 20000-1": 4,
        "ISO 9001": 3,
        "ISO 14001": 2,
        "SOC 2": 10,
        "PCI-DSS": 10,
        "BSI C5": 10,
        "BSI IT-Grundschutz": 10,
        "FedRAMP": 10,
        "CSA STAR": 6,
        "ISAE 3402": 6,
        "COBIT": 4,
        "ITIL": 2,
        "Cyber Essentials": 4,
        "DORA": 3,
    }

    def _is_pdf_url(u: str) -> bool:
        ul = (u or "").lower()
        return ul.endswith(".pdf") or ".pdf?" in ul

    pdf_bonus = 1.25

    weighted_sum = 0.0
    for label in certs:
        base = W.get(label)
        if not base:
            continue

        ev_for = [e for e in evidence if str(e.get("norm")) == label]
        if not ev_for:
            continue

        mult = pdf_bonus if any(_is_pdf_url(e.get("url", "")) for e in ev_for) else 1.0
        if any(e.get("has_certifier") for e in ev_for):
            mult *= 1.1

        weighted_sum += base * mult

    cert_pts = int(min(30, round(weighted_sum)))
    details["certifications"] = {
        "points": cert_pts,
        "max": 30,
        "reason": f"{len(certs)} Fund(e), evidenzbasiert gewichtet" if certs else "Keine Zertifikate/Normen erkannt",
    }

    # Legacy
    details["iso_certifications"] = {
        "points": 0,
        "max": 0,
        "reason": "(Legacy) ISO wird unter Zertifikate & Normen bewertet",
    }

    # ─── DNS Security (5 Punkte) ─────────────────────────────────────────────
    dns = dns_security or {}

    def dns_item(key, pts, max_pts, reason=""):
        details[key] = {"points": pts, "max": max_pts, "reason": reason}

    ds = dns.get("dnssec", {}) if isinstance(dns.get("dnssec"), dict) else {}
    if ds.get("supported") is True and ds.get("valid") is True:
        dns_item("dnssec", 2, 2, ds.get("reason") or "DNSSEC aktiv")
    elif ds.get("supported") is True:
        dns_item("dnssec", 1, 2, ds.get("reason") or "DNSSEC Hinweise")
    elif ds.get("supported") is False:
        dns_item("dnssec", 0, 2, ds.get("reason") or "Kein DNSSEC")
    else:
        dns_item("dnssec", 0, 2, "DNSSEC nicht prüfbar")

    dm = dns.get("dmarc", {}) if isinstance(dns.get("dmarc"), dict) else {}
    if dm.get("present") is True and dm.get("policy") in ("reject", "quarantine"):
        dns_item("dmarc", 1, 1, f"DMARC p={dm.get('policy')}")
    elif dm.get("present") is True:
        dns_item("dmarc", 0.5, 1, f"DMARC p={dm.get('policy') or 'none'}")
    elif dm.get("present") is False:
        dns_item("dmarc", 0, 1, "Kein DMARC")
    else:
        dns_item("dmarc", 0, 1, "DMARC nicht prüfbar")

    spf = dns.get("spf", {}) if isinstance(dns.get("spf"), dict) else {}
    if spf.get("present") is True and spf.get("all") in ("-all", "~all"):
        dns_item("spf", 1, 1, f"SPF {spf.get('all')}")
    elif spf.get("present") is True:
        dns_item("spf", 0.5, 1, "SPF vorhanden")
    elif spf.get("present") is False:
        dns_item("spf", 0, 1, "Kein SPF")
    else:
        dns_item("spf", 0, 1, "SPF nicht prüfbar")

    dk = dns.get("dkim", {}) if isinstance(dns.get("dkim"), dict) else {}
    if dk.get("present") is True:
        dns_item("dkim", 0.5, 0.5, f"DKIM gefunden ({dk.get('found_selector')})" if dk.get("found_selector") else "DKIM gefunden")
    elif dk.get("present") is False:
        dns_item("dkim", 0, 0.5, "Kein DKIM (heuristisch)")
    else:
        dns_item("dkim", 0, 0.5, "DKIM nicht prüfbar")

    mx = dns.get("mx", {}) if isinstance(dns.get("mx"), dict) else {}
    if mx.get("present") is True:
        dns_item("mx", 0.5, 0.5, "Null-MX" if mx.get("null_mx") else "MX vorhanden")
    elif mx.get("present") is False:
        dns_item("mx", 0, 0.5, "Kein MX")
    else:
        dns_item("mx", 0, 0.5, "MX nicht prüfbar")

    # ─── Server / Geo (5 Punkte) ─────────────────────────────────────────────
    if server.get("is_eu"):
        details["server_eu"] = {
            "points": 5,
            "max": 5,
            "reason": f"Server in EU ({server.get('country')})",
        }
    elif server.get("country"):
        details["server_eu"] = {
            "points": 2,
            "max": 5,
            "reason": f"Server außerhalb EU: {server.get('country')}",
        }
    else:
        details["server_eu"] = {
            "points": 0,
            "max": 5,
            "reason": "Serverstandort unbekannt",
        }

    # ─── Summe ───────────────────────────────────────────────────────────────
    total = sum(_n(v.get("points")) for v in details.values())
    total = max(0.0, min(100.0, total))
    total_int = int(round(total))

    grade = "F"
    for threshold, g in GRADE_THRESHOLDS:
        if total_int >= threshold:
            grade = g
            break

    return {"total_score": total_int, "grade": grade, "score_details": details}
