import os, ssl, socket, ipaddress, html as html_lib
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
import tensorflow as tf
import tldextract
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

MODEL_PATH = os.getenv('MODEL_PATH', 'phishing_url_detector.keras')
MAX_BYTES = 1_000_000
MAX_REDIRECTS = 3
ALLOWED_PORTS = {80, 443}
model = tf.keras.models.load_model(MODEL_PATH)
app = FastAPI(title='PhishingGuard', version='3.0')

SUSPICIOUS = [
    'verify your account', 'confirm your account', 'account suspended',
    'urgent action', 'verify identity', 'login immediately',
    'confirm password', 'security alert'
]

@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return response

def registered_domain(host):
    ext = tldextract.extract(host or '')
    return '.'.join(x for x in [ext.domain, ext.suffix] if x)

def validate_public_url(raw):
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('Enter a URL.')
    if '://' not in raw:
        raw = 'https://' + raw
    p = urlparse(raw)
    if p.scheme not in ('http', 'https'):
        raise ValueError('Only HTTP/HTTPS URLs are allowed.')
    if p.username or p.password:
        raise ValueError('URLs containing credentials are not allowed.')
    host = (p.hostname or '').lower().rstrip('.')
    if not host or host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')):
        raise ValueError('Local/internal hosts are blocked.')
    try:
        port = p.port
    except ValueError:
        raise ValueError('Invalid port.')
    if port and port not in ALLOWED_PORTS:
        raise ValueError('Only ports 80 and 443 are allowed.')
    infos = socket.getaddrinfo(host, port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    ips = sorted({x[4][0] for x in infos})
    if not ips:
        raise ValueError('Host could not be resolved.')
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise ValueError('Private, loopback, link-local or reserved addresses are blocked.')
    return raw, host, ips

def safe_fetch(raw):
    current, _, _ = validate_public_url(raw)
    session = requests.Session()
    session.trust_env = False
    headers = {
        'User-Agent': 'PhishingGuard-Security-Scanner/3.0',
        'Accept': 'text/html,application/xhtml+xml'
    }
    history = []
    for _ in range(MAX_REDIRECTS + 1):
        current, _, _ = validate_public_url(current)
        r = session.get(current, headers=headers, timeout=(3, 6), allow_redirects=False, stream=True)
        if 300 <= r.status_code < 400 and r.headers.get('Location'):
            if len(history) >= MAX_REDIRECTS:
                raise ValueError('Too many redirects.')
            nxt = urljoin(current, r.headers['Location'])
            validate_public_url(nxt)
            history.append(current)
            current = nxt
            r.close()
            continue
        ctype = (r.headers.get('Content-Type') or '').lower()
        body = b''
        if 'text/html' in ctype or 'application/xhtml+xml' in ctype or not ctype:
            for chunk in r.iter_content(16384):
                if chunk:
                    body += chunk
                    if len(body) > MAX_BYTES:
                        body = body[:MAX_BYTES]
                        break
        enc = r.encoding or 'utf-8'
        page_html = body.decode(enc, errors='replace')
        return {
            'status': r.status_code,
            'final_url': current,
            'redirects': len(history),
            'content_type': ctype,
            'html': page_html
        }
    raise ValueError('Redirect limit exceeded.')

def dl_score(url):
    out = model(tf.constant([url], dtype=tf.string), training=False)
    return float(out.numpy().reshape(-1)[0]) * 100

def tls_info(url):
    p = urlparse(url)
    if p.scheme != 'https':
        return {'available': False, 'valid': False, 'reason': 'URL does not use HTTPS'}
    host = p.hostname
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        return {
            'available': True,
            'valid': expiry > datetime.now(timezone.utc),
            'subject': subject.get('commonName'),
            'issuer': issuer.get('organizationName') or issuer.get('commonName'),
            'expires': expiry.strftime('%Y-%m-%d'),
            'days_remaining': (expiry - datetime.now(timezone.utc)).days
        }
    except Exception as e:
        return {'available': True, 'valid': False, 'reason': str(e)[:160]}

def page_indicators(fetch):
    soup = BeautifulSoup(fetch['html'], 'html.parser')
    base = fetch['final_url']
    host = (urlparse(base).hostname or '').lower()
    root = registered_domain(host)
    forms = soup.find_all('form')
    password = len(soup.select('input[type="password"]'))
    iframes = len(soup.find_all('iframe'))
    ext_forms = 0
    for f in forms:
        action = (f.get('action') or '').strip()
        if action:
            ah = (urlparse(urljoin(base, action)).hostname or '').lower()
            if ah and registered_domain(ah) != root:
                ext_forms += 1
    links = []
    for a in soup.find_all('a', href=True):
        u = urljoin(base, a['href'])
        h = (urlparse(u).hostname or '').lower()
        if h:
            links.append(h)
    external = sum(1 for h in links if registered_domain(h) != root)
    ratio = external / len(links) if links else 0
    text = soup.get_text(' ', strip=True).lower()
    phrases = [x for x in SUSPICIOUS if x in text]
    title = soup.title.get_text(' ', strip=True)[:160] if soup.title else ''
    return {
        'title': title,
        'forms': len(forms),
        'password_fields': password,
        'iframes': iframes,
        'external_form_actions': ext_forms,
        'total_links': len(links),
        'external_links': external,
        'external_link_ratio': round(ratio, 3),
        'suspicious_phrases': phrases
    }

def scan(raw):
    normalized, original_host, ips = validate_public_url(raw)
    deep = dl_score(normalized)
    fetched = safe_fetch(normalized)
    final_host = (urlparse(fetched['final_url']).hostname or '').lower()
    tls = tls_info(fetched['final_url'])
    page = page_indicators(fetched)

    points = 0
    reasons = []
    if urlparse(fetched['final_url']).scheme != 'https':
        points += 15
        reasons.append('Website does not use HTTPS')
    if fetched['redirects'] >= 3:
        points += 10
        reasons.append('Multiple redirects detected')
    if registered_domain(final_host) != registered_domain(original_host):
        points += 10
        reasons.append('Redirect moved to a different registered domain')
    if tls.get('available') and not tls.get('valid'):
        points += 20
        reasons.append('TLS certificate could not be validated')
    if page['password_fields'] > 0:
        points += 5
        reasons.append('Password field detected')
    if page['external_form_actions'] > 0:
        points += 20
        reasons.append('Form submits to another registered domain')
    if page['suspicious_phrases']:
        points += min(15, len(page['suspicious_phrases']) * 5)
        reasons.append('Suspicious account/security wording detected')
    if page['external_link_ratio'] >= .80:
        points += 5
        reasons.append('Very high external-link ratio')

    contextual = min(points, 100)
    combined = .70 * deep + .30 * contextual
    category = 'HIGH' if combined >= 70 else 'MEDIUM' if combined >= 40 else 'LOW'
    recommendation = {
        'LOW': 'No strong warning was detected by this prototype. Still verify the domain and use normal browsing caution.',
        'MEDIUM': 'Treat this URL with caution. Avoid entering passwords or payment details until the site is independently verified.',
        'HIGH': 'High-risk signals were detected. Do not enter credentials, payment details, or download files unless the site is independently verified.'
    }[category]

    return {
        'url': normalized,
        'risk_category': category,
        'combined_risk_indicator': round(combined, 2),
        'deep_learning_phishing_score': round(deep, 2),
        'contextual_indicator_score': contextual,
        'reasons': reasons,
        'recommendation': recommendation,
        'live': {
            'http_status': fetched['status'],
            'final_url': fetched['final_url'],
            'redirects': fetched['redirects'],
            'content_type': fetched['content_type']
        },
        'tls': tls,
        'domain': {
            'hostname': original_host,
            'registered_domain': registered_domain(original_host),
            'resolved_ips': ips,
            'number_of_ips': len(ips)
        },
        'html': page,
        'notice': 'Research prototype. The combined indicator is a heuristic risk signal, not a calibrated phishing probability or safety guarantee.'
    }

CSS = '''
:root{--bg:#07111f;--panel:#0d1b2f;--panel2:#10233d;--text:#edf5ff;--muted:#9fb0c6;--line:#203957;--blue:#4da3ff;--green:#41d69c;--amber:#ffc857;--red:#ff6b7a}
*{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top,#102542 0,#07111f 42%);color:var(--text);min-height:100vh}.wrap{max-width:1100px;margin:auto;padding:38px 20px 70px}.hero{padding:34px;border:1px solid var(--line);background:linear-gradient(145deg,rgba(16,35,61,.94),rgba(9,23,41,.96));border-radius:24px;box-shadow:0 24px 60px rgba(0,0,0,.28)}.brand{display:flex;gap:14px;align-items:center}.shield{font-size:38px}.brand h1{margin:0;font-size:34px}.tag{margin:6px 0 0;color:var(--muted)}.badge{display:inline-block;margin-top:18px;padding:7px 11px;border:1px solid #31577f;border-radius:999px;font-size:12px;color:#bad8f8;background:#0a1728}.scanform{display:flex;gap:10px;margin-top:25px}.scanform input{flex:1;padding:16px 17px;border:1px solid #2a4666;border-radius:12px;background:#071523;color:#fff;font-size:16px;outline:none}.scanform input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(77,163,255,.14)}button{padding:0 24px;border:0;border-radius:12px;background:linear-gradient(135deg,#3c90ff,#66b5ff);color:#06101c;font-weight:800;font-size:15px;cursor:pointer}.note{color:var(--muted);font-size:13px;line-height:1.5}.results{margin-top:22px}.riskhead{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:26px;border:1px solid var(--line);border-radius:20px;background:var(--panel)}.risklabel{font-weight:900;font-size:30px}.low{color:var(--green)}.medium{color:var(--amber)}.high{color:var(--red)}.scorebig{text-align:right}.scorebig strong{font-size:30px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:20px}.card h3{margin:0 0 12px;font-size:15px;color:#cce2fa}.metric{font-size:28px;font-weight:800}.muted{color:var(--muted)}.bar{height:10px;background:#071523;border-radius:999px;overflow:hidden;margin-top:12px}.fill{height:100%;background:linear-gradient(90deg,#41d69c,#ffc857,#ff6b7a)}.section{margin-top:14px;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px}.section h2{font-size:18px;margin:0 0 16px}.details{display:grid;grid-template-columns:1fr 1fr;gap:10px 20px}.row{padding:10px 0;border-bottom:1px solid rgba(32,57,87,.55)}.row b{display:block;color:#b9d4ef;font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}.pill{display:inline-block;padding:6px 10px;border-radius:999px;background:#0a1728;border:1px solid #2a4666;margin:3px 5px 3px 0;font-size:13px}.recommend{border-left:4px solid var(--blue);padding:16px 18px;background:#091a2d;border-radius:10px}.footer{margin-top:20px;text-align:center}.error{margin-top:18px;padding:18px;border:1px solid #6b303b;background:#2a1118;border-radius:14px;color:#ffd8dd}@media(max-width:760px){.scanform{flex-direction:column}.scanform button{padding:15px}.grid{grid-template-columns:1fr}.details{grid-template-columns:1fr}.riskhead{align-items:flex-start;flex-direction:column}.scorebig{text-align:left}.hero{padding:23px}.brand h1{font-size:28px}}
'''

def page_shell(inner=''):
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhishingGuard — Live Phishing Risk Scanner</title><style>{CSS}</style></head><body><main class="wrap"><section class="hero"><div class="brand"><div class="shield">🛡️</div><div><h1>PhishingGuard</h1><p class="tag">Deep Learning URL Analysis + Passive Live Website Security Checks</p></div></div><span class="badge">REAL-TIME RESEARCH PROTOTYPE • PUBLIC WEB SCANNER</span><form class="scanform" method="post" action="/scan"><input name="url" placeholder="Enter a website URL, e.g. https://example.com" autocomplete="off" required><button type="submit">Scan Website</button></form><p class="note">Passive analysis only: no form submission, no credential entry, no JavaScript execution, and a limited HTML download. Never rely on this result as the only basis for trusting a website.</p></section>{inner}<div class="footer note">PhishingGuard v3 • Deep-learning model + live contextual security analysis</div></main></body></html>'''

def esc(v):
    return html_lib.escape(str(v if v is not None else '—'))

def render_results(r):
    category = r['risk_category']
    cls = category.lower()
    reasons = r['reasons'] or ['No contextual warnings detected']
    reason_html = ''.join(f'<span class="pill">{esc(x)}</span>' for x in reasons)
    tls = r['tls']
    page = r['html']
    ips = ', '.join(r['domain']['resolved_ips'][:4])
    if r['domain']['number_of_ips'] > 4:
        ips += f" +{r['domain']['number_of_ips']-4} more"
    phrases = ', '.join(page['suspicious_phrases']) if page['suspicious_phrases'] else 'None detected'
    return f'''<section class="results"><div class="riskhead"><div><div class="muted">Overall prototype assessment</div><div class="risklabel {cls}">{esc(category)} RISK</div></div><div class="scorebig"><div class="muted">Combined Risk Indicator</div><strong>{r['combined_risk_indicator']:.2f}/100</strong></div></div><div class="grid"><div class="card"><h3>Deep Learning URL Score</h3><div class="metric">{r['deep_learning_phishing_score']:.2f}%</div><div class="bar"><div class="fill" style="width:{min(r['deep_learning_phishing_score'],100)}%"></div></div><p class="note">Model score from URL text patterns.</p></div><div class="card"><h3>Contextual Indicator</h3><div class="metric">{r['contextual_indicator_score']}/100</div><div class="bar"><div class="fill" style="width:{min(r['contextual_indicator_score'],100)}%"></div></div><p class="note">Heuristic score from passive live checks.</p></div><div class="card"><h3>HTTP & Redirects</h3><div class="metric">{esc(r['live']['http_status'])}</div><p class="note">HTTP status • {esc(r['live']['redirects'])} redirect(s)</p></div></div><div class="section"><h2>Why this result?</h2>{reason_html}<div class="recommend"><b>Recommendation</b><br>{esc(r['recommendation'])}</div></div><div class="section"><h2>Live Website Analysis</h2><div class="details"><div class="row"><b>Requested URL</b>{esc(r['url'])}</div><div class="row"><b>Final URL</b>{esc(r['live']['final_url'])}</div><div class="row"><b>Page title</b>{esc(page['title'] or 'Not available')}</div><div class="row"><b>Content type</b>{esc(r['live']['content_type'] or 'Not reported')}</div><div class="row"><b>Forms</b>{page['forms']}</div><div class="row"><b>Password fields</b>{page['password_fields']}</div><div class="row"><b>Iframes</b>{page['iframes']}</div><div class="row"><b>External form actions</b>{page['external_form_actions']}</div><div class="row"><b>Links</b>{page['total_links']} total • {page['external_links']} external</div><div class="row"><b>Suspicious phrases</b>{esc(phrases)}</div></div></div><div class="section"><h2>TLS Certificate</h2><div class="details"><div class="row"><b>HTTPS/TLS available</b>{'Yes' if tls.get('available') else 'No'}</div><div class="row"><b>Certificate valid</b>{'Yes' if tls.get('valid') else 'No'}</div><div class="row"><b>Issuer</b>{esc(tls.get('issuer') or tls.get('reason'))}</div><div class="row"><b>Certificate subject</b>{esc(tls.get('subject'))}</div><div class="row"><b>Expiry</b>{esc(tls.get('expires'))}</div><div class="row"><b>Days remaining</b>{esc(tls.get('days_remaining'))}</div></div></div><div class="section"><h2>Domain & DNS</h2><div class="details"><div class="row"><b>Hostname</b>{esc(r['domain']['hostname'])}</div><div class="row"><b>Registered domain</b>{esc(r['domain']['registered_domain'])}</div><div class="row"><b>Resolved IP addresses</b>{esc(ips)}</div><div class="row"><b>Number of resolved IPs</b>{r['domain']['number_of_ips']}</div></div></div><div class="section"><p class="note">{esc(r['notice'])}</p></div></section>'''

@app.get('/', response_class=HTMLResponse)
def home():
    return page_shell()

@app.get('/health')
def health():
    return {'status': 'ok', 'model_loaded': True, 'version': '3.0'}

@app.post('/api/scan')
def api_scan(url: str = Form(...)):
    try:
        return scan(url)
    except Exception as e:
        return JSONResponse({'success': False, 'error': str(e)}, status_code=400)

@app.post('/scan', response_class=HTMLResponse)
def web_scan(url: str = Form(...)):
    try:
        return page_shell(render_results(scan(url)))
    except Exception as e:
        return page_shell(f'<div class="error"><b>Scan could not be completed.</b><br>{esc(str(e))}</div>')
