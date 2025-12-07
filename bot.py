from flask import Flask, render_template_string, send_from_directory, request, jsonify, abort
import os
import time
from functools import wraps
import logging

# Log ayarı
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

# Rate limiting için
request_counts = {}
RATE_LIMIT = 100  # Dakikada maksimum istek
BLOCK_TIME = 300  # 5 dakika blok
blocked_ips = {}

def check_rate_limit():
    client_ip = request.remote_addr
    current_time = time.time()
    
    # Blok kontrolü
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            logger.warning(f"Blocked IP tried to access: {client_ip}")
            abort(429)
        else:
            del blocked_ips[client_ip]
    
    # Rate limit kontrolü
    if client_ip not in request_counts:
        request_counts[client_ip] = {'count': 0, 'timestamp': current_time}
    
    data = request_counts[client_ip]
    
    # 1 dakika geçtiyse sıfırla
    if current_time - data['timestamp'] > 60:
        data['count'] = 0
        data['timestamp'] = current_time
    
    data['count'] += 1
    
    if data['count'] > RATE_LIMIT:
        blocked_ips[client_ip] = current_time + BLOCK_TIME
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        abort(429)

# Bot koruması
BOT_USER_AGENTS = [
    'bot', 'crawler', 'spider', 'scraper', 'python', 'curl', 'wget',
    'httrack', 'sqlmap', 'nmap', 'scan', 'scanner', 'zgrab', 'nikto'
]

def check_bot():
    user_agent = request.headers.get('User-Agent', '').lower()
    for bot in BOT_USER_AGENTS:
        if bot in user_agent:
            logger.warning(f"Bot detected: {user_agent}")
            abort(403)

# Her istekten önce
@app.before_request
def before_request():
    if request.path == '/health' or request.path.startswith('/static/'):
        return
    
    check_bot()
    check_rate_limit()

# Ana sayfa
@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # HTML içeriğini döndür
        response = app.make_response(html_content)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        
        # Güvenlik başlıkları
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    
    except FileNotFoundError:
        # Eğer index.html yoksa, basit bir sayfa göster
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>ÖZSOY SYSTEM</title>
            <style>
                body {
                    background: #0A0A0A;
                    color: #8B0000;
                    font-family: 'Courier New', monospace;
                    text-align: center;
                    padding: 50px;
                }
                h1 {
                    font-size: 3em;
                    text-shadow: 0 0 10px #8B0000;
                }
                .error {
                    color: #B22222;
                    margin: 20px 0;
                }
            </style>
        </head>
        <body>
            <h1>ÖZSOY SYSTEM</h1>
            <div class="error">index.html bulunamadı!</div>
            <p>Lütfen index.html dosyasını yükleyin.</p>
        </body>
        </html>
        ''', 404

# Statik dosyalar için
@app.route('/<path:filename>')
def static_files(filename):
    allowed_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf']
    
    if any(filename.endswith(ext) for ext in allowed_extensions):
        try:
            return send_from_directory('.', filename)
        except:
            abort(404)
    
    abort(404)

# API endpoints
@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'online',
        'system': 'ÖZSOY SYSTEM',
        'timestamp': time.time(),
        'requests': len(request_counts),
        'blocked': len(blocked_ips)
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# Hata sayfaları
@app.errorhandler(404)
def page_not_found(e):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - ÖZSOY SYSTEM</title>
        <style>
            body {
                background: #0A0A0A;
                color: #8B0000;
                font-family: 'Courier New', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }
            .container {
                border: 2px solid #8B0000;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(139, 0, 0, 0.5);
            }
            h1 { font-size: 4em; margin: 0; }
            p { font-size: 1.2em; margin: 20px 0; }
            a {
                color: #B22222;
                text-decoration: none;
                border: 1px solid #B22222;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin-top: 20px;
            }
            a:hover {
                background: #B22222;
                color: #000;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>404</h1>
            <p>SAYFA BULUNAMADI</p>
            <p>ÖZSOY SYSTEM</p>
            <a href="/">ANA SAYFA</a>
        </div>
    </body>
    </html>
    ''', 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>429 - ÖZSOY SYSTEM</title>
        <style>
            body {
                background: #0A0A0A;
                color: #8B0000;
                font-family: 'Courier New', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }
            .container {
                border: 2px solid #8B0000;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(139, 0, 0, 0.5);
            }
            h1 { font-size: 4em; margin: 0; }
            p { font-size: 1.2em; margin: 20px 0; }
            .countdown {
                font-size: 2em;
                color: #B22222;
                margin: 20px 0;
            }
            a {
                color: #B22222;
                text-decoration: none;
                border: 1px solid #B22222;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin-top: 20px;
            }
            a:hover {
                background: #B22222;
                color: #000;
            }
        </style>
        <script>
            let timeLeft = 300;
            function updateCountdown() {
                const minutes = Math.floor(timeLeft / 60);
                const seconds = timeLeft % 60;
                document.getElementById('countdown').textContent = 
                    `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
                if (timeLeft > 0) {
                    timeLeft--;
                    setTimeout(updateCountdown, 1000);
                }
            }
            window.onload = updateCountdown;
        </script>
    </head>
    <body>
        <div class="container">
            <h1>429</h1>
            <p>ÇOK FAZLA İSTEK</p>
            <p>DDoS KORUMASI AKTİF</p>
            <div class="countdown" id="countdown">5:00</div>
            <a href="/">ANA SAYFA</a>
        </div>
    </body>
    </html>
    ''', 429

@app.errorhandler(403)
def forbidden(e):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>403 - ÖZSOY SYSTEM</title>
        <style>
            body {
                background: #0A0A0A;
                color: #8B0000;
                font-family: 'Courier New', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }
            .container {
                border: 2px solid #8B0000;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(139, 0, 0, 0.5);
            }
            h1 { font-size: 4em; margin: 0; }
            p { font-size: 1.2em; margin: 20px 0; }
            a {
                color: #B22222;
                text-decoration: none;
                border: 1px solid #B22222;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin-top: 20px;
            }
            a:hover {
                background: #B22222;
                color: #000;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>403</h1>
            <p>ERİŞİM ENGELLENDİ</p>
            <p>ÖZSOY SYSTEM GÜVENLİK ENGELLERİ</p>
            <a href="/">ANA SAYFA</a>
        </div>
    </body>
    </html>
    ''', 403

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"ÖZSOY SYSTEM starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
