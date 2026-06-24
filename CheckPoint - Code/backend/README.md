## Backend starten

I cd backend
  python3 -m venv venv
  macOS: source venv/bin/activate --> Windows: cd venv/Scripts --> ./Activate.ps1
  (Einmalig) Package installieren: pip install flask flask-cors requests beautifulsoup4 lxml
  back to backend cd .. x2
  python3 -m api.server
  -> http://localhost:5001


