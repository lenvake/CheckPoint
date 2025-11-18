# CheckPoint

**Eine Webanwendung, die für jede analysierte Webseite einen TrustScore berechnet.**  
Der TrustScore bewertet die **Sicherheit und Vertrauenswürdigkeit** einer Webseite anhand von zwei Hauptaspekten: Sicherheit der Webseite und Unternehmens-Compliance.

---

## Ziel

CheckPoint soll Unternehmen, Entwickler und Endnutzer dabei unterstützen, Webseiten auf **Sicherheit** und **Vertrauenswürdigkeit** zu prüfen.  
Jede analysierte Webseite erhält einen Score, der leicht verständlich die Qualität und Sicherheit der Seite zusammenfasst.

---

## Hauptfunktionen

### 1️⃣ Sicherheit der Webseite
- Überprüfung vorhandener **HTTPS-Zertifikate / TLS-Validierung**  
- Prüfung der **Gültigkeit von Zertifikaten**  
- Analyse der **Art des Zertifikats** (z. B. DV, OV, EV)  
- Erkennung von **unsicheren Inhalten oder Mixed Content**

### 2️⃣ Vertrauenswürdigkeit / Compliance des Unternehmens
- Vorhandensein eines **Impressums**  
- Vorhandensein einer **Datenschutzerklärung** und ggf. eines **Datenschutzbeauftragten**  
- Vorhandensein von **ISO-Zertifikaten** (z. B. ISO 27001, ISO 9001, ISO 22301)  
- **Serverstandort** (Land, Region)  
- Weitere Hinweise auf **Sicherheit oder Compliance**

---

## Vorgehensweise / Architektur

1. **Crawler / Scraper entwickeln**
   - HTML-Seiten durchsuchen  
   - Footer, Links und Unterseiten prüfen  
   - Keywords für Impressum, Datenschutz und ISO-Zertifikate suchen
   - Wir könnten noch, ChatGPT API nutzen um die gecrawlten Infos zu validiereun und zur prüfen.

2. **API-Integration (optional)**
   - Z. B. [apivoid.com](https://www.apivoid.com/) für Site Trustworthiness (externe Bewertung)  

3. **Serverdaten sammeln**
   - IP-Adresse der Webseite ermitteln  
   - Serverstandort / Geo-Daten  

4. **Score berechnen**
   - Punkte für jeden geprüften Aspekt vergeben  
   - Zusammenführen zu einem **Gesamtwert**  

5. **Webapp / Frontend**
   - Anzeige von Ergebnis, Score, Details zu Zertifikaten und Compliance  
   - Optionaler Export als **CSV** oder **JSON**

---

## Technologie

- **Python 3** + **Selenium** (Crawler für dynamische Seiten)  
- **IP-Geolocation API** (z. B. ipinfo.io)  
- Optional: **Flask** oder **FastAPI** für die Webanwendung


- TBD (je nach Projektanforderung)
