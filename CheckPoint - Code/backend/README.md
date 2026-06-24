### Backend starten

#### 1) Ins Backend-Verzeichnis wechseln
```bash
cd backend
```

#### 2) Virtuelle Umgebung anlegen
```bash
python3 -m venv venv
```

#### 3) Virtuelle Umgebung aktivieren

**macOS / Linux**
```bash
source venv/bin/activate
```

**Windows (PowerShell)**
```powershell
cd venv\Scripts
./Activate.ps1
```

> Falls PowerShell die Ausführung blockiert (einmalig):
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
> ```

#### 4) Abhängigkeiten installieren (einmalig)
```bash
pip install flask flask-cors requests beautifulsoup4 lxml
```

#### 5) Zurück ins Projekt-Root
Wenn du gerade in `venv\Scripts` bist:
```bash
cd ../..
```

Wenn du im `backend`-Ordner bist:
```bash
cd ..
```

#### 6) API Server starten
```bash
python3 -m api.server
```

#### 7) Aufrufen
- API: http://localhost:5001




