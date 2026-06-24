"""DNS-Security Analyse für CheckPoint.

Ziele (v1):
- DNSSEC (DNSKEY + DS am Parent; optional AD-bit als Hinweis auf Validierung)
- SPF (v=spf1… und Qualifier -all/~all)
- DMARC (_dmarc TXT, Policy)
- DKIM (heuristische Selector-Discovery)
- MX (vorhanden / Null-MX)

Implementation Notes:
- Keine extra Dependencies: dnspython ist nicht vorausgesetzt.
- Lookups via DNS-over-HTTPS (Cloudflare JSON API) für stabile, HTTPS-only Auflösung.

Datenschutz/Compliance:
- DoH-Anfragen sind normale HTTPS-Requests; es wird nur der Domainname aufgelöst.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger("checkpoint")


_CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"


def _doh_query(name: str, rrtype: str, timeout: float = 6.0) -> dict[str, Any]:
    """DNS Query via Cloudflare DoH (JSON)."""
    # Cloudflare expects: Accept: application/dns-json
    headers = {
        "Accept": "application/dns-json",
        "User-Agent": "CheckPoint/1.0 (+https://checkpoint.local)"
    }
    params = {"name": name, "type": rrtype}
    try:
        r = requests.get(_CLOUDFLARE_DOH, params=params, headers=headers, timeout=timeout)
        if not r.ok:
            return {"Status": -1, "error": f"HTTP {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"Status": -1, "error": str(e)}


def _answers_txt(resp: dict[str, Any]) -> list[str]:
    ans = resp.get("Answer") or []
    out: list[str] = []
    for a in ans:
        if a.get("type") == 16 and isinstance(a.get("data"), str):
            # TXT data can be quoted segments
            out.append(a["data"].strip("\""))
    return out


def _answers_mx(resp: dict[str, Any]) -> list[dict[str, Any]]:
    ans = resp.get("Answer") or []
    out: list[dict[str, Any]] = []
    for a in ans:
        if a.get("type") == 15 and isinstance(a.get("data"), str):
            # format: "10 mail.example.com."
            m = re.match(r"^(\d+)\s+(\S+)$", a["data"].strip())
            if m:
                out.append({"pref": int(m.group(1)), "host": m.group(2).rstrip(".")})
    return out


def _has_ad_bit(resp: dict[str, Any]) -> bool:
    # Cloudflare JSON includes "AD": true if authenticated data
    return bool(resp.get("AD") is True)


def _parent_domain(name: str) -> str | None:
    parts = [p for p in name.strip('.').split('.') if p]
    if len(parts) < 2:
        return None
    return '.'.join(parts[1:])


def _ds_present(domain: str, timeout: float) -> bool | None:
    """Best-effort DS check at parent.

    True  => DS record exists at parent
    False => explicit NOERROR with empty Answer
    None  => lookup error/unknown
    """
    parent = _parent_domain(domain)
    if not parent:
        return None
    resp = _doh_query(domain, "DS", timeout)
    if resp.get("Status") == 0:
        ans = resp.get("Answer") or []
        return True if ans else False
    return None


_SPF_RE = re.compile(r"\bv=spf1\b", re.I)
_DMARC_RE = re.compile(r"\bv=DMARC1\b", re.I)
_DKIM_TXT_RE = re.compile(r"\bv=DKIM1\b", re.I)


def analyze_dns_security(domain: str, timeout: float = 6.0, dkim_selectors: list[str] | None = None) -> dict:
    """Analyzes DNS security signals for a registrable domain.

    Returns JSON-serializable dict.
    """
    domain = domain.strip().strip(".").lower()

    result: dict[str, Any] = {
        "domain": domain,
        "dnssec": {
            "supported": None,
            "valid": None,
            "dnskey_present": None,
            "ds_present": None,
            "validated_ad": None,
            "reason": None,
        },
        "spf": {"present": None, "all": None, "record": None, "record_count": 0, "includes": []},
        "dmarc": {"present": None, "policy": None, "subdomain_policy": None, "pct": None, "aspf": None, "adkim": None, "rua": [], "record": None},
        "dkim": {"present": None, "selectors_checked": [], "found_selector": None},
        "mx": {"present": None, "null_mx": None, "hosts": []},
        "errors": [],
    }

    # ── DNSSEC
    # Ziel: so viel Klarheit wie möglich ohne dnspython:
    # - DNSKEY am Apex => Zone ist (wahrscheinlich) signiert
    # - DS Record (Delegation Signer) vorhanden => DNSSEC ist delegiert (starkes Signal)
    # - AD bit (falls gesetzt) => Resolver hat validiert (Hinweis)

    a = _doh_query(domain, "A", timeout)
    if a.get("Status") == 0:
        result["dnssec"]["validated_ad"] = _has_ad_bit(a)
    else:
        if a.get("error"):
            result["errors"].append(f"A lookup failed: {a.get('error')}")

    dnskey = _doh_query(domain, "DNSKEY", timeout)
    if dnskey.get("Status") == 0:
        dnskey_present = bool(dnskey.get("Answer") or [])
        result["dnssec"]["dnskey_present"] = dnskey_present
    else:
        result["dnssec"]["dnskey_present"] = None
        if dnskey.get("error"):
            result["errors"].append(f"DNSKEY lookup failed: {dnskey.get('error')}")

    ds_present = _ds_present(domain, timeout)
    result["dnssec"]["ds_present"] = ds_present

    # supported/valid/reason
    if result["dnssec"]["dnskey_present"] is False:
        result["dnssec"]["supported"] = False
        result["dnssec"]["valid"] = False
        result["dnssec"]["reason"] = "Keine DNSKEY gefunden"
    elif result["dnssec"]["dnskey_present"] is True and ds_present is True:
        result["dnssec"]["supported"] = True
        result["dnssec"]["valid"] = True
        result["dnssec"]["reason"] = "DS + DNSKEY vorhanden (delegiert)"
    elif result["dnssec"]["dnskey_present"] is True and ds_present is False:
        result["dnssec"]["supported"] = True
        result["dnssec"]["valid"] = None
        result["dnssec"]["reason"] = "DNSKEY vorhanden, aber kein DS (Delegation unklar)"
    elif result["dnssec"]["dnskey_present"] is True and ds_present is None:
        result["dnssec"]["supported"] = True
        result["dnssec"]["valid"] = None
        result["dnssec"]["reason"] = "DNSKEY vorhanden (DS nicht prüfbar)"
    else:
        result["dnssec"]["supported"] = None
        result["dnssec"]["valid"] = None
        result["dnssec"]["reason"] = "DNSSEC nicht prüfbar"

    # ── SPF (TXT)
    txt = _doh_query(domain, "TXT", timeout)
    if txt.get("Status") == 0:
        txts = _answers_txt(txt)
        spf_records = [t for t in txts if _SPF_RE.search(t)]
        result["spf"]["record_count"] = len(spf_records)
        if spf_records:
            rec = spf_records[0]
            result["spf"]["present"] = True
            result["spf"]["record"] = rec
            # all qualifier heuristic
            m = re.search(r"\s([~\-\+\?]all)\b", rec)
            result["spf"]["all"] = m.group(1) if m else None
            # includes
            result["spf"]["includes"] = re.findall(r"\binclude:([^\s]+)", rec)
        else:
            result["spf"]["present"] = False
    else:
        result["spf"]["present"] = None
        if txt.get("error"):
            result["errors"].append(f"TXT lookup failed: {txt.get('error')}")

    # ── DMARC (_dmarc)
    dmarc_name = f"_dmarc.{domain}"
    dmarc = _doh_query(dmarc_name, "TXT", timeout)
    if dmarc.get("Status") == 0:
        dmarc_txts = _answers_txt(dmarc)
        dmarc_records = [t for t in dmarc_txts if _DMARC_RE.search(t)]
        if dmarc_records:
            rec = dmarc_records[0]
            result["dmarc"]["present"] = True
            result["dmarc"]["record"] = rec

            pm  = re.search(r"\bp=([a-zA-Z]+)\b", rec)
            spm = re.search(r"\bsp=([a-zA-Z]+)\b", rec)
            pct = re.search(r"\bpct=(\d{1,3})\b", rec)
            aspf = re.search(r"\baspf=([rs])\b", rec, re.I)
            adkim = re.search(r"\badkim=([rs])\b", rec, re.I)
            rua = re.search(r"\brua=([^;]+)", rec, re.I)

            result["dmarc"]["policy"] = (pm.group(1).lower() if pm else None)
            result["dmarc"]["subdomain_policy"] = (spm.group(1).lower() if spm else None)
            result["dmarc"]["pct"] = (int(pct.group(1)) if pct else None)
            result["dmarc"]["aspf"] = (aspf.group(1).lower() if aspf else None)
            result["dmarc"]["adkim"] = (adkim.group(1).lower() if adkim else None)
            if rua:
                # comma-separated list of URIs
                result["dmarc"]["rua"] = [u.strip() for u in rua.group(1).split(',') if u.strip()]
        else:
            result["dmarc"]["present"] = False
    else:
        result["dmarc"]["present"] = None
        if dmarc.get("error"):
            result["errors"].append(f"DMARC TXT lookup failed: {dmarc.get('error')}")

    # ── MX
    mx = _doh_query(domain, "MX", timeout)
    if mx.get("Status") == 0:
        mxs = _answers_mx(mx)
        if mxs:
            result["mx"]["present"] = True
            # already normalized dicts: {pref, host}
            result["mx"]["hosts"] = sorted(mxs, key=lambda x: x.get("pref", 0))[:10]
            # Null MX: RFC 7505 uses MX 0 .
            result["mx"]["null_mx"] = any((h.get("pref") == 0) and (h.get("host") in (".", "")) for h in mxs)
        else:
            result["mx"]["present"] = False
            result["mx"]["null_mx"] = False
    else:
        result["mx"]["present"] = None
        if mx.get("error"):
            result["errors"].append(f"MX lookup failed: {mx.get('error')}")

    # ── DKIM (heuristic): without mail provider selector list, we probe common selectors.
    selectors = dkim_selectors or [
        "default", "selector1", "selector2",
        "google", "gmail", "mail", "dkim",
        "s1", "s2", "k1", "k2",
    ]

    found = None
    for sel in selectors[:15]:
        name = f"{sel}._domainkey.{domain}"
        dk = _doh_query(name, "TXT", timeout)
        result["dkim"]["selectors_checked"].append(sel)
        if dk.get("Status") == 0:
            txts = _answers_txt(dk)
            if any(_DKIM_TXT_RE.search(t) for t in txts):
                found = sel
                break

    if found:
        result["dkim"]["present"] = True
        result["dkim"]["found_selector"] = found
    else:
        # Could be false negatives; mark as False only if we got clean NOERROR for at least one selector?
        result["dkim"]["present"] = False

    return result
