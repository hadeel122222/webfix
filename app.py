from flask import Flask, render_template, request, jsonify, session
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = "your-secret-key"

def analyze_performance(url):
    try:
        response = requests.get(url, timeout=5)
        page_size_kb = round(len(response.content) / 1024, 2)
        return {
            "status_code": response.status_code,
            "load_time": response.elapsed.total_seconds(),
            "page_size_kb": page_size_kb
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_seo(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        has_title = bool(soup.title and soup.title.string.strip())
        has_meta_description = bool(soup.find('meta', attrs={'name': 'description'}))
        h1_tags_count = len(soup.find_all('h1'))
        images_missing_alt = sum(1 for img in soup.find_all('img') if not img.get('alt'))

        return {
            "has_title": has_title,
            "has_meta_description": has_meta_description,
            "h1_tags_count": h1_tags_count,
            "images_missing_alt": images_missing_alt
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_security(url):
    result = {
        "uses_https": url.startswith("https"),
        "ssl_valid": False,
        "security_headers": {},
        "vulnerabilities": {}
    }

    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        if url.startswith("https"):
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["ssl_valid"] = bool(cert)

        response = requests.get(url, timeout=5)
        headers = response.headers
        html = response.text

        security_headers = [
            "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
            "Strict-Transport-Security", "X-XSS-Protection", "Referrer-Policy"
        ]

        for header in security_headers:
            result["security_headers"][header] = headers.get(header)

    except Exception as e:
        print("Security analysis failed:", e)

    return result

@app.route('/')
def index():
    return render_template('webfix.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data['url']
    analysis_data = {
        "performance": analyze_performance(url),
        "seo": analyze_seo(url),
        "security": analyze_security(url),
        "date_now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    session["report_data"] = analysis_data
    return jsonify(analysis_data)

@app.route('/recommendations')
def recommendations():
    return render_template('recommendations.html')

@app.route('/report')
def report():
    return render_template('report.html')

import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
