"""
CheckPoint – Flask API Server
POST /api/scan   → startet Scan (gibt Ergebnis zurück)
GET  /api/health → Healthcheck
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from crawler.crawler import crawl

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "3.0.0"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    max_pages = int(data.get("max_pages", 50))
    max_depth = int(data.get("max_depth", 3))

    try:
        result = crawl(url, max_pages=max_pages, max_depth=max_depth)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
