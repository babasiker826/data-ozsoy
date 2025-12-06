from flask import Flask, render_template, request, jsonify, abort
import logging
from functools import wraps
import time
import hashlib
import os
from datetime import datetime, timedelta
import threading

# Flask uygulamasını oluştur
app = Flask(__name__, template_folder='.')

# Günlük ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ozsoy_system.log'),
        logging.StreamHandler()
    ]
)

# DDoS koruması için değişkenler
request_tracker = {}
IP_BLOCK_TIME = 300  # 5 dakika
MAX_REQUESTS_PER_MINUTE = 60  # Dakikada maksimum istek
MAX_CONCURRENT_REQUESTS = 10  # Eşzamanlı maksimum istek

# IP adreslerini engelleme listesi
blocked_ips = set()

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        
        # Engellenmiş IP kontrolü
        if client_ip in blocked_ips:
            logging.warning(f"Engellenmiş IP erişim denedi: {client_ip}")
            abort(403)
        
        # Şu anki zaman
        current_time = time.time()
        
        # IP için istek takibi
        if client_ip not in request_tracker:
            request_tracker[client_ip] = {
                'requests': [],
                'concurrent': 0,
                'last_reset': current_time
            }
        
        tracker = request_tracker[client_ip]
        
        # 1 dakikalık penceredeki istekleri temizle
        tracker['requests'] = [req_time for req_time in tracker['requests'] 
                              if current_time - req_time < 60]
        
        # Eşzamanlı istek kontrolü
        tracker['concurrent'] += 1
        if tracker['concurrent'] > MAX_CONCURRENT_REQUESTS:
            logging.warning(f"Eşzamanlı istek limiti aşıldı: {client_ip}")
            tracker['concurrent'] -= 1
            abort(429)
        
        # Dakika başına istek kontrolü
        if len(tracker['requests']) >= MAX_REQUESTS_PER_MINUTE:
            logging.warning(f"Rate limit aşıldı, IP engellendi: {client_ip}")
            blocked_ips.add(client_ip)
            # 5 dakika sonra engeli kaldır
            threading.Timer(IP_BLOCK_TIME, unblock_ip, args=[client_ip]).start()
            abort(429)
        
        # İsteği kaydet
        tracker['requests'].append(current_time)
        
        try:
            response = f(*args, **kwargs)
            return response
        finally:
            # İstek tamamlandı, eşzamanlı sayacı azalt
            tracker['concurrent'] -= 1
    
    return decorated_function

def unblock_ip(ip_address):
    if ip_address in blocked_ips:
        blocked_ips.remove(ip_address)
        logging.info(f"IP engeli kaldırıldı: {ip_address}")

# Bot ve zararlı user agent kontrolü
BAD_USER_AGENTS = [
    'bot', 'crawler', 'spider', 'scraper', 'python', 'curl', 'wget',
    'httrack', 'webzip', 'webalta', 'webcopier', 'teleport', 'nikto',
    'sqlmap', 'nmap', 'nessus', 'metasploit', 'hydra', 'john', 'medusa',
    'havij', 'zap', 'burp', 'arachni', 'skipfish', 'w3af', 'openvas',
    'acunetix', 'appscan', 'netsparker', 'webinspect', 'nessus'
]

def check_user_agent():
    user_agent = request.headers.get('User-Agent', '').lower()
    
    for bad_agent in BAD_USER_AGENTS:
        if bad_agent in user_agent:
            logging.warning(f"Zararlı User-Agent tespit edildi: {user_agent}")
            return False
    
    return True

# Referer kontrolü (CSRF koruması)
ALLOWED_REFERERS = ['localhost', '127.0.0.1', 'yourdomain.com']

def check_referer():
    referer = request.headers.get('Referer', '')
    if referer:
        for allowed in ALLOWED_REFERERS:
            if allowed in referer:
                return True
        return False
    return True  # Referer yoksa izin ver (doğrudan erişim)

# Ana sayfa
@app.route('/')
@rate_limit
def index():
    # Güvenlik kontrolleri
    if not check_user_agent():
        abort(403)
    
    if not check_referer():
        abort(403)
    
    # İstemci IP'sini logla
    client_ip = request.remote_addr
    logging.info(f"Ana sayfa ziyareti: {client_ip} - {request.headers.get('User-Agent')}")
    
    return render_template('index.html')

# API endpoint (isteğe bağlı)
@app.route('/api/status')
@rate_limit
def api_status():
    return jsonify({
        'status': 'online',
        'system': 'ÖZSOY SYSTEM',
        'timestamp': datetime.now().isoformat(),
        'total_requests': sum(len(tracker['requests']) for tracker in request_tracker.values()),
        'active_ips': len(request_tracker),
        'blocked_ips': len(blocked_ips)
    })

# Sağlık kontrolü
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'})

# 404 hata sayfası
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# 403 hata sayfası
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# 429 hata sayfası (rate limit)
@app.errorhandler(429)
def too_many_requests(e):
    return render_template('429.html'), 429

# Hata yönetimi
@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Sunucu hatası: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# Dosya yükleme koruması
@app.before_request
def block_file_uploads():
    if request.method == 'POST':
        content_length = request.content_length or 0
        # 10MB'dan büyük dosyaları engelle
        if content_length > 10 * 1024 * 1024:
            abort(413)

# Güvenlik başlıkları
@app.after_request
def add_security_headers(response):
    # XSS koruması
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # HSTS (HTTPS için)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# Cleanup thread - eski istekleri temizle
def cleanup_old_requests():
    while True:
        time.sleep(60)
        current_time = time.time()
        old_ips = []
        
        for ip, tracker in request_tracker.items():
            # 5 dakikadan eski istekleri temizle
            tracker['requests'] = [req_time for req_time in tracker['requests'] 
                                  if current_time - req_time < 300]
            
            # 10 dakikadır aktif olmayan IP'leri temizle
            if not tracker['requests'] and tracker['concurrent'] == 0:
                if current_time - tracker.get('last_reset', current_time) > 600:
                    old_ips.append(ip)
        
        for ip in old_ips:
            request_tracker.pop(ip, None)

# Temizleme thread'ini başlat
cleanup_thread = threading.Thread(target=cleanup_old_requests, daemon=True)
cleanup_thread.start()

# Ana fonksiyon
if __name__ == '__main__':
    # Host ve port ayarları
    host = '0.0.0.0'
    port = int(os.environ.get('PORT', 5000))
    
    logging.info(f"ÖZSOY SYSTEM başlatılıyor...")
    logging.info(f"Host: {host}")
    logging.info(f"Port: {port}")
    logging.info(f"DDoS koruması aktif")
    
    # Production için gunicorn veya waitress önerilir
    app.run(
        host=host,
        port=port,
        debug=False,
        threaded=True
          )
