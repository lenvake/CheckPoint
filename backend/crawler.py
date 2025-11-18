import argparse, json, re, socket, sys, time
from collections import deque
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

UA = "ComplianceCrawler/mini"
TIMEOUT = 8

SEED = [
    "/", "/impressum", "/imprint", "/legal", "/privacy", "/datenschutz",
    "/privacy-policy", "/security", "/information-security-policy",
    "/informationssicherheit", "/informationssicherheitspolitik", "/trust",
    "/de/informationssicherheitspolitik/"
]

PRIV = ["datenschutz","privacy","privacy policy","data protection","gdpr","datenschutzerklärung"]
IMPR = ["impressum","imprint","legal notice","legal","site notice"]
SEC  = ["informationssicherheitspolitik","security policy","information security policy","trust center","security"]

# Erkenne ISO-Normen und extrahiere Namen --> Funktioniert noch so lala
ISO_PATTERN = re.compile(r"\bISO\s*/?\s*(?:IEC\s*)?(9001|27001|22301|27701|20000(?:-1)?|14001|45001|31000)\b", re.I)

def norm(u): 
    return u if u.startswith(("http://","https://")) else "https://"+u

def reg_domain(u: str) -> str:
    try:
        netloc = urlparse(u).netloc
        host = netloc.split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""

def same_reg_domain(a: str, b: str) -> bool:
    return reg_domain(a) == reg_domain(b)

def fetch(u, s):
    try: return s.get(u, timeout=TIMEOUT, allow_redirects=True)
    except: return None

def evidence(u, html):
    s=BeautifulSoup(html,"lxml"); t=(s.get_text(" ",strip=True) or ""); tl=t.lower()
    has_impr=any(x in tl for x in IMPR); has_priv=any(x in tl for x in PRIV)
    # ISO-Treffer: Norm-Nummern in lesbare Labels konvertieren + Evidenz-Snippets
    iso_certs, iso_evidence = [], []
    for m in ISO_PATTERN.finditer(t):
        num = m.group(1)
        # Normalize Nummer zu Label
        if num.startswith("20000"): label = "ISO 20000-1"
        else: label = f"ISO {num}"
        if label not in iso_certs: iso_certs.append(label)
        start = max(0, m.start()-30); end = min(len(t), m.end()+30)
        iso_evidence.append(t[start:end].strip())
        if len(iso_evidence) >= 8: break

    links={"impressum":None,"privacy":None,"security":None}
    for a in s.find_all("a",href=True):
        href=str(a["href"]).strip(); h=urljoin(u, href); href_l=href.lower()
        lbl=(a.get_text(" ",strip=True) or "").lower()
        if not links["impressum"] and (any(x in lbl for x in IMPR) or any(p in href_l for p in ["/impressum","/imprint","/legal"])): links["impressum"]=h
        if not links["privacy"]   and (any(x in lbl for x in PRIV) or any(p in href_l for p in ["/privacy","/datenschutz","/privacy-policy"])): links["privacy"]=h
        if not links["security"]  and (any(x in lbl for x in SEC)  or any(p in href_l for p in [
            "/security","/information-security","/information-security-policy",
            "/informationssicherheit","/informationssicherheitspolitik","/de/informationssicherheitspolitik/"
        ])): links["security"]=h

    return {
        "url":u,
        "has_impressum":has_impr,
        "has_privacy":has_priv,
        "iso_certifications": iso_certs,   
        "iso_evidence": iso_evidence,      
        "impressum_link":links["impressum"],
        "privacy_link":links["privacy"],
        "security_link":links["security"]
    }

def crawl(start, max_pages=40, max_depth=2):
    start=norm(start); base=f"{urlparse(start).scheme}://{urlparse(start).netloc}"
    s=requests.Session(); s.headers.update({"User-Agent":UA})
    q=deque([(urljoin(base,p),0) for p in SEED]); seen=set(); findings=[]
    has_impr=has_priv=False; has_iso=False
    impr_url=priv_url=sec_url=None
    all_iso_certs=set(); all_iso_evidence=[]

    while q and len(seen)<max_pages:
        u,d=q.popleft()
        if u in seen: continue
        seen.add(u)
        r=fetch(u,s)
        if not r or not r.ok: continue
        ct=(r.headers.get("content-type") or "").lower()
        if "text/html" not in ct and "text/plain" not in ct: continue

        ev=evidence(u,r.text); findings.append(ev)
        if ev["has_impressum"] and not impr_url: impr_url=ev["impressum_link"]; has_impr=True
        if ev["has_privacy"] and not priv_url:  priv_url=ev["privacy_link"];    has_priv=True
        if ev["security_link"] and not sec_url: sec_url=ev["security_link"]
        if ev["iso_certifications"]:
            has_iso=True
            for c in ev["iso_certifications"]:
                all_iso_certs.add(c)
            for snip in ev["iso_evidence"]:
                if len(all_iso_evidence) < 12: all_iso_evidence.append(snip)

        if d<max_depth:
            soup=BeautifulSoup(r.text,"lxml")
            for a in soup.find_all("a",href=True):
                nxt=urljoin(u, str(a["href"]).strip())
                if nxt not in seen and same_reg_domain(base,nxt):
                    q.append((nxt,d+1))

    ip=None
    try: ip=socket.gethostbyname(urlparse(start).netloc)
    except: pass
    country=region=city=src=None
    if ip:
        try:
            jr=s.get(f"https://ipapi.co/{ip}/json/",timeout=TIMEOUT).json()
            country,region,city,src=jr.get("country_name"),jr.get("region"),jr.get("city"),"ipapi"
        except: src="none"

    return {
        "target":start,
        "scanned_pages":len(seen),
        "compliance":{
            "has_impressum":has_impr,
            "impressum_url":impr_url,
            "has_privacy":has_priv,
            "privacy_url":priv_url,
            "has_iso_mentions":has_iso,
            "iso_certifications": sorted(list(all_iso_certs)),  
            "iso_evidence": all_iso_evidence,                   
            "security_policy_url":sec_url
        },
        "server":{"ip":ip,"country":country,"region":region,"city":city,"source":src},
        "findings":findings,
        "timestamp":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    }

def main():
    #Helper
    p=argparse.ArgumentParser(description="Mini Compliance Crawler")
    p.add_argument("url", nargs="?", help="Website (z. B. example.com oder https://example.com)")
    p.add_argument("--max-pages", type=int, default=40)
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--out", default="result.json")
    p.add_argument("--csv", default=None, help="Optionaler CSV-Pfad")
    a=p.parse_args()
    if not a.url: p.print_help(); sys.exit(2)
    res=crawl(a.url, a.max_pages, a.max_depth)
    with open(a.out,"w",encoding="utf-8") as f: json.dump(res,f,ensure_ascii=False,indent=2)
    print("JSON gespeichert:", a.out)
    if a.csv:
        import csv
        row = {
            "target": res["target"], "scanned_pages": res["scanned_pages"],
            "ip": res["server"]["ip"], "country": res["server"]["country"],
            "region": res["server"]["region"], "city": res["server"]["city"],
            "has_impressum": res["compliance"]["has_impressum"], "impressum_url": res["compliance"]["impressum_url"],
            "has_privacy": res["compliance"]["has_privacy"], "privacy_url": res["compliance"]["privacy_url"],
            "has_iso_mentions": res["compliance"]["has_iso_mentions"],
            "iso_certifications": "; ".join(res["compliance"]["iso_certifications"]),
            "security_policy_url": res["compliance"]["security_policy_url"],
            "timestamp": res["timestamp"],
        }
        with open(a.csv,"w",newline="",encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(row.keys()))
            w.writeheader(); w.writerow(row)
        print("CSV gespeichert:", a.csv)

if __name__=="__main__": main()


