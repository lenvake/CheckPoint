"""
TrustScore-Berechnung (0–100) + Klassifizierung (A-…F).
"""

GRADE_THRESHOLDS = [
    (95, "A+"), (85, "A"), (75, "B"), (60, "C"), (45, "D"), (30, "E"), (0, "F"),
]


def compute_score(tls: dict, compliance: dict, server: dict, security_txt: dict) -> dict:
    """
    Berechnet TrustScore aus den Analyse-Teilergebnissen.

    Gewichtung:
        TLS / HTTPS       50 Punkte
        Compliance        40 Punkte
        Server / Geo       5 Punkte
        ISO-Normen         5 Punkte
    Gesamt              100 Punkte
    """
    details: dict[str, dict] = {}

    # ─── TLS (50 Punkte) ─────────────────────────────────────────────────────

    def tls_item(key, pts, max_pts, reason=""):
        details[key] = {"points": pts, "max": max_pts, "reason": reason}

    # 1. HTTPS erreichbar (15 Punkte)
    if tls.get("active"):
        tls_item("https_reachable", 15, 15, "HTTPS ist aktiv")
    else:
        tls_item("https_reachable", 0, 15, "HTTPS nicht erreichbar")

    # 2. TLS-Protokoll (10 Punkte)
    version = tls.get("version") or ""
    if "TLSv1.3" in version:
        tls_item("tls_protocol", 10, 10, "TLS 1.3 aktiv")
    elif "TLSv1.2" in version:
        tls_item("tls_protocol", 7, 10, "TLS 1.2 aktiv (nicht aktuellste Version)")
    elif version:
        tls_item("tls_protocol", 2, 10, f"Veraltetes Protokoll: {version}")
    else:
        tls_item("tls_protocol", 0, 10, "Kein TLS")

    # 3. Zertifikat gültig (8 Punkte)
    if tls.get("active") and not tls.get("cert_expired", True):
        tls_item("cert_valid", 8, 8, "Zertifikat ist gültig")
    else:
        tls_item("cert_valid", 0, 8, "Zertifikat abgelaufen oder nicht vorhanden")

    # 4. Ablaufdatum OK – > 30 Tage (4 Punkte)
    days = tls.get("days_remaining")
    if isinstance(days, int) and days > 30:
        tls_item("cert_not_expiring", 4, 4, f"Läuft in {days} Tagen ab")
    elif isinstance(days, int) and days >= 0:
        tls_item("cert_not_expiring", 1, 4, f"Läuft bald ab: {days} Tage")
    else:
        tls_item("cert_not_expiring", 0, 4, "Ablaufdatum unbekannt oder abgelaufen")

    # 5. Hostname Match (4 Punkte)
    if tls.get("cert_hostname_match"):
        tls_item("cert_hostname_match", 4, 4, "Hostname stimmt überein")
    elif tls.get("cert_hostname_match") is False:
        tls_item("cert_hostname_match", 0, 4, "Hostname-Mismatch!")
    else:
        tls_item("cert_hostname_match", 0, 4, "Hostname-Match nicht prüfbar")

    # 6. Zertifikatstyp (3 Punkte)
    ct = tls.get("cert_type", "DV")
    type_pts = {"EV": 3, "OV": 2, "DV": 1}.get(ct, 0)
    tls_item("cert_type", type_pts, 3, f"Zertifikatstyp: {ct}")

    # 7. HSTS vorhanden (4 Punkte)
    if tls.get("hsts"):
        tls_item("hsts_present", 4, 4, "HSTS-Header gesetzt")
    else:
        tls_item("hsts_present", 0, 4, "Kein HSTS-Header")

    # 8. HSTS max-age ≥ 1 Jahr (2 Punkte)
    hsts_age = tls.get("hsts_max_age")
    if isinstance(hsts_age, int) and hsts_age >= 31536000:
        tls_item("hsts_max_age_ok", 2, 2, f"HSTS max-age={hsts_age}s (≥1 Jahr)")
    elif isinstance(hsts_age, int):
        tls_item("hsts_max_age_ok", 1, 2, f"HSTS max-age={hsts_age}s (<1 Jahr)")
    else:
        tls_item("hsts_max_age_ok", 0, 2, "HSTS nicht vorhanden oder kein max-age")

    # ─── Compliance (40 Punkte) ───────────────────────────────────────────────

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

    # security.txt (bonus im TLS-Bereich gezählt)
    if security_txt.get("found"):
        details["security_txt"] = {"points": 2, "max": 2, "reason": "security.txt vorhanden"}
    else:
        details["security_txt"] = {"points": 0, "max": 2, "reason": "Keine security.txt"}

    # ─── ISO-Zertifizierungen (5 Punkte) ─────────────────────────────────────
    iso_count = len(compliance.get("iso_certifications", []))
    iso_pts = min(iso_count * 2, 5)
    details["iso_certifications"] = {
        "points": iso_pts, "max": 5,
        "reason": f"{iso_count} ISO-Norm(en) erkannt" if iso_count else "Keine ISO-Normen erkannt",
    }

    # ─── Server / Geo (5 Punkte) ─────────────────────────────────────────────
    if server.get("is_eu"):
        details["server_eu"] = {"points": 5, "max": 5, "reason": f"Server in EU ({server.get('country')})"}
    elif server.get("country"):
        details["server_eu"] = {"points": 2, "max": 5, "reason": f"Server außerhalb EU: {server.get('country')}"}
    else:
        details["server_eu"] = {"points": 0, "max": 5, "reason": "Serverstandort unbekannt"}

    # ─── Summe ────────────────────────────────────────────────────────────────
    total = sum(v["points"] for v in details.values())
    total = max(0, min(100, total))

    grade = "F"
    for threshold, g in GRADE_THRESHOLDS:
        if total >= threshold:
            grade = g
            break

    return {"total_score": total, "grade": grade, "score_details": details}
