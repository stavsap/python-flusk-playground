"""
VULNERABLE APPLICATION - CWE-918 SSRF Demonstration
DO NOT USE IN PRODUCTION - FOR EDUCATIONAL PURPOSES ONLY

This application demonstrates multiple SSRF vulnerabilities through various attack vectors.
"""

from flask import Flask, request, jsonify, render_template_string, redirect
import requests
import urllib.parse
import base64
import json
from PIL import Image
from io import BytesIO
import dns.resolver
import socket
import subprocess
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable_secret_key_12345'

# HTML Template for the vulnerable application
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web Services Platform</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .service { background: #f9f9f9; padding: 20px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #007bff; }
        input[type="text"], textarea { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .result { background: #e9ecef; padding: 15px; margin-top: 15px; border-radius: 4px; white-space: pre-wrap; font-family: monospace; }
        .warning { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Web Services Integration Platform</h1>
        
        <div class="warning">
            <strong>⚠️ WARNING:</strong> This is a deliberately vulnerable application for educational purposes.
            It contains CWE-918 (SSRF) vulnerabilities. DO NOT deploy in production!
        </div>

        <!-- Vulnerability 1: URL Fetcher -->
        <div class="service">
            <h2>📄 Document Fetcher Service</h2>
            <p>Fetch and preview documents from any URL</p>
            <input type="text" id="url1" placeholder="Enter URL (e.g., https://example.com/document.pdf)">
            <button onclick="fetchUrl()">Fetch Document</button>
            <div id="result1" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 2: Image Proxy -->
        <div class="service">
            <h2>🖼️ Image Proxy & Resize Service</h2>
            <p>Load and resize images from external sources</p>
            <input type="text" id="imageUrl" placeholder="Enter image URL">
            <input type="text" id="width" placeholder="Width (default: 300)" value="300">
            <input type="text" id="height" placeholder="Height (default: 300)" value="300">
            <button onclick="processImage()">Process Image</button>
            <div id="result2" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 3: Webhook Tester -->
        <div class="service">
            <h2>🔔 Webhook Testing Service</h2>
            <p>Test webhook endpoints with custom payloads</p>
            <input type="text" id="webhookUrl" placeholder="Webhook URL">
            <textarea id="webhookPayload" rows="4" placeholder='{"event": "test", "data": "sample"}'></textarea>
            <button onclick="testWebhook()">Send Webhook</button>
            <div id="result3" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 4: API Gateway -->
        <div class="service">
            <h2>🔗 API Gateway Proxy</h2>
            <p>Proxy requests to external APIs</p>
            <input type="text" id="apiUrl" placeholder="API Endpoint URL">
            <input type="text" id="apiMethod" placeholder="Method (GET/POST)" value="GET">
            <textarea id="apiHeaders" rows="3" placeholder='{"Authorization": "Bearer token"}'></textarea>
            <button onclick="callApi()">Call API</button>
            <div id="result4" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 5: URL Shortener Resolver -->
        <div class="service">
            <h2>🔗 URL Shortener Resolver</h2>
            <p>Resolve shortened URLs and check redirects</p>
            <input type="text" id="shortUrl" placeholder="Enter shortened URL">
            <button onclick="resolveUrl()">Resolve URL</button>
            <div id="result5" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 6: RSS Feed Reader -->
        <div class="service">
            <h2>📰 RSS Feed Reader</h2>
            <p>Parse and display RSS feeds</p>
            <input type="text" id="feedUrl" placeholder="RSS Feed URL">
            <button onclick="readFeed()">Read Feed</button>
            <div id="result6" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 7: DNS Lookup -->
        <div class="service">
            <h2>🌍 DNS Lookup Service</h2>
            <p>Perform DNS lookups and fetch records</p>
            <input type="text" id="hostname" placeholder="Hostname or Domain">
            <button onclick="dnsLookup()">Lookup</button>
            <div id="result7" class="result" style="display:none;"></div>
        </div>

        <!-- Vulnerability 8: Port Scanner -->
        <div class="service">
            <h2>🔍 Service Availability Checker</h2>
            <p>Check if services are available at specific hosts and ports</p>
            <input type="text" id="scanHost" placeholder="Host">
            <input type="text" id="scanPort" placeholder="Port">
            <button onclick="checkService()">Check Service</button>
            <div id="result8" class="result" style="display:none;"></div>
        </div>
    </div>

    <script>
        function fetchUrl() {
            const url = document.getElementById('url1').value;
            fetch('/fetch_url', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result1').style.display = 'block';
                document.getElementById('result1').textContent = JSON.stringify(data, null, 2);
            });
        }

        function processImage() {
            const url = document.getElementById('imageUrl').value;
            const width = document.getElementById('width').value;
            const height = document.getElementById('height').value;
            fetch('/process_image', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, width: width, height: height})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result2').style.display = 'block';
                document.getElementById('result2').textContent = JSON.stringify(data, null, 2);
            });
        }

        function testWebhook() {
            const url = document.getElementById('webhookUrl').value;
            const payload = document.getElementById('webhookPayload').value;
            fetch('/test_webhook', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, payload: payload})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result3').style.display = 'block';
                document.getElementById('result3').textContent = JSON.stringify(data, null, 2);
            });
        }

        function callApi() {
            const url = document.getElementById('apiUrl').value;
            const method = document.getElementById('apiMethod').value;
            const headers = document.getElementById('apiHeaders').value;
            fetch('/api_gateway', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url, method: method, headers: headers})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result4').style.display = 'block';
                document.getElementById('result4').textContent = JSON.stringify(data, null, 2);
            });
        }

        function resolveUrl() {
            const url = document.getElementById('shortUrl').value;
            fetch('/resolve_url', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result5').style.display = 'block';
                document.getElementById('result5').textContent = JSON.stringify(data, null, 2);
            });
        }

        function readFeed() {
            const url = document.getElementById('feedUrl').value;
            fetch('/read_feed', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result6').style.display = 'block';
                document.getElementById('result6').textContent = JSON.stringify(data, null, 2);
            });
        }

        function dnsLookup() {
            const hostname = document.getElementById('hostname').value;
            fetch('/dns_lookup', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({hostname: hostname})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result7').style.display = 'block';
                document.getElementById('result7').textContent = JSON.stringify(data, null, 2);
            });
        }

        function checkService() {
            const host = document.getElementById('scanHost').value;
            const port = document.getElementById('scanPort').value;
            fetch('/check_service', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({host: host, port: port})
            })
            .then(r => r.json())
            .then(data => {
                document.getElementById('result8').style.display = 'block';
                document.getElementById('result8').textContent = JSON.stringify(data, null, 2);
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# VULNERABILITY 1: Basic URL Fetcher - Direct SSRF
@app.route('/fetch_url', methods=['POST'])
def fetch_url():
    """
    Vulnerable: Directly fetches user-provided URL without validation
    Attack: http://localhost:5000/admin or http://169.254.169.254/latest/meta-data/
    """
    data = request.get_json()
    url = data.get('url')
    
    try:
        # VULNERABLE: No URL validation
        response = requests.get(url, timeout=5)
        return jsonify({
            'status': 'success',
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text[:1000],  # First 1000 chars
            'url': url
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 2: Image Proxy - SSRF via Image Processing
@app.route('/process_image', methods=['POST'])
def process_image():
    """
    Vulnerable: Fetches and processes images from user-provided URLs
    Attack: file:///etc/passwd or http://internal-server/admin
    """
    data = request.get_json()
    url = data.get('url')
    width = int(data.get('width', 300))
    height = int(data.get('height', 300))
    
    try:
        # VULNERABLE: No URL validation before fetching
        response = requests.get(url, timeout=5)
        img = Image.open(BytesIO(response.content))
        img = img.resize((width, height))
        
        return jsonify({
            'status': 'success',
            'message': 'Image processed successfully',
            'original_size': f"{img.size}",
            'format': img.format,
            'url': url
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 3: Webhook Tester - SSRF with POST requests
@app.route('/test_webhook', methods=['POST'])
def test_webhook():
    """
    Vulnerable: Sends POST requests to user-provided URLs
    Attack: http://localhost:5000/admin/delete with malicious payload
    """
    data = request.get_json()
    url = data.get('url')
    payload = data.get('payload', '{}')
    
    try:
        # VULNERABLE: No URL validation, user controls payload
        response = requests.post(
            url,
            json=json.loads(payload),
            timeout=5,
            headers={'Content-Type': 'application/json'}
        )
        return jsonify({
            'status': 'success',
            'status_code': response.status_code,
            'response': response.text[:500],
            'url': url
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 4: API Gateway Proxy - SSRF with custom headers and methods
@app.route('/api_gateway', methods=['POST'])
def api_gateway():
    """
    Vulnerable: Proxies API requests with user-controlled headers and methods
    Attack: http://internal-api/admin with custom headers to bypass auth
    """
    data = request.get_json()
    url = data.get('url')
    method = data.get('method', 'GET').upper()
    headers_str = data.get('headers', '{}')
    
    try:
        headers = json.loads(headers_str)
        # VULNERABLE: No validation of URL, method, or headers
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=5
        )
        return jsonify({
            'status': 'success',
            'method': method,
            'status_code': response.status_code,
            'response_headers': dict(response.headers),
            'response_body': response.text[:1000],
            'url': url
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 5: URL Redirect Resolver - SSRF via redirect following
@app.route('/resolve_url', methods=['POST'])
def resolve_url():
    """
    Vulnerable: Follows redirects from user-provided URLs
    Attack: http://evil.com/redirect?to=http://localhost:5000/admin
    """
    data = request.get_json()
    url = data.get('url')
    
    try:
        # VULNERABLE: Follows redirects without validation
        response = requests.get(url, timeout=5, allow_redirects=True)
        redirect_chain = [r.url for r in response.history]
        
        return jsonify({
            'status': 'success',
            'original_url': url,
            'final_url': response.url,
            'redirect_chain': redirect_chain,
            'status_code': response.status_code,
            'content_preview': response.text[:500]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 6: RSS Feed Reader - SSRF via XML parsing
@app.route('/read_feed', methods=['POST'])
def read_feed():
    """
    Vulnerable: Fetches and parses RSS feeds from user URLs
    Attack: file:///etc/passwd or http://internal-service/config.xml
    """
    data = request.get_json()
    url = data.get('url')
    
    try:
        # VULNERABLE: No URL validation
        response = requests.get(url, timeout=5)
        return jsonify({
            'status': 'success',
            'url': url,
            'content_type': response.headers.get('Content-Type'),
            'feed_data': response.text[:2000],
            'status_code': response.status_code
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 7: DNS Lookup with automatic fetching
@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    """
    Vulnerable: Performs DNS lookup and fetches resolved IP
    Attack: Provide internal hostname to scan internal network
    """
    data = request.get_json()
    hostname = data.get('hostname')
    
    try:
        # VULNERABLE: No hostname validation
        ip = socket.gethostbyname(hostname)
        
        # EXTRA VULNERABLE: Automatically tries to fetch from resolved IP
        try:
            response = requests.get(f'http://{ip}', timeout=2)
            content = response.text[:500]
        except:
            content = 'Could not fetch content from resolved IP'
        
        return jsonify({
            'status': 'success',
            'hostname': hostname,
            'resolved_ip': ip,
            'content_sample': content
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# VULNERABILITY 8: Port Scanner / Service Checker
@app.route('/check_service', methods=['POST'])
def check_service():
    """
    Vulnerable: Allows checking arbitrary hosts and ports
    Attack: Scan internal network ports (localhost:22, 10.0.0.1:3306, etc.)
    """
    data = request.get_json()
    host = data.get('host')
    port = int(data.get('port', 80))
    
    try:
        # VULNERABLE: No restrictions on host/port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        
        is_open = result == 0
        
        # If port is open, try to grab banner
        banner = ''
        if is_open:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
            except:
                banner = 'Could not retrieve banner'
        
        return jsonify({
            'status': 'success',
            'host': host,
            'port': port,
            'is_open': is_open,
            'banner': banner[:200] if banner else None
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Simulated internal admin endpoint (target for SSRF attacks)
@app.route('/admin')
def admin():
    """Simulated internal admin panel - should only be accessible from localhost"""
    return jsonify({
        'admin_panel': 'SECRET ADMIN PANEL',
        'users': ['admin', 'root', 'system'],
        'database_password': 'super_secret_password_123',
        'api_keys': ['key_12345', 'key_67890'],
        'internal_message': 'This should only be accessible from localhost!'
    })

@app.route('/admin/delete', methods=['POST'])
def admin_delete():
    """Simulated dangerous admin action"""
    return jsonify({
        'status': 'success',
        'message': 'CRITICAL: Admin delete action executed!',
        'data': request.get_json()
    })

if __name__ == '__main__':
    print("=" * 70)
    print("VULNERABLE SSRF APPLICATION - CWE-918")
    print("=" * 70)
    print("WARNING: This application contains INTENTIONAL security vulnerabilities")
    print("DO NOT use in production environments!")
    print("=" * 70)
    print("\nStarting server on http://127.0.0.1:5000")
    print("\nExample SSRF Attack Vectors:")
    print("1. Internal Services: http://localhost:5000/admin")
    print("2. Cloud Metadata: http://169.254.169.254/latest/meta-data/")
    print("3. Local Files: file:///etc/passwd")
    print("4. Internal Network: http://192.168.1.1")
    print("5. Port Scanning: localhost:22, localhost:3306, etc.")
    print("=" * 70)
    
    app.run(debug=True, host='127.0.0.1', port=5000)
