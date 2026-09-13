import os, ssl, socket, ipaddress, html as html_lib, math, re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, unquote

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
app = FastAPI(title='PhishingGuard', version='4.0')

SUSPICIOUS_PHRASES = [
    'verify your account', 'confirm your account', 'account suspended',
    'urgent action', 'verify identity', 'login immediately',
    'confirm password', 'security alert', 'unusual activity',
    'account locked', 'validate your account', 'update payment'
]

SUSPICIOUS_URL_TOKENS = {
    'login', 'signin', 'verify', 'verification', 'secure', 'account',
    'update', 'confirm', 'password', 'wallet', 'bank', 'billing',
    'payment', 'invoice', 'support', 'unlock', 'recover', 'auth'
}

SHORTENER_HOSTS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'is.gd', 'cutt.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at'
}

@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:"
    )
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
        'User-Agent': 'PhishingGuard-Security-Scanner/4.0',
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
        result = {
            'status': r.status_code,
            'final_url': current,
            'redirects': len(history),
            'content_type': ctype,
            'server': (r.headers.get('Server') or '')[:120],
            'html': page_html
        }
        r.close()
        return result
    raise ValueError('Redirect limit exceeded.')

def dl_score(url):
    out = model(tf.constant([url], dtype=tf.string), training=False)
    return max(0.0, min(100.0, float(out.numpy().reshape(-1)[0]) * 100))

def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((n / total) * math.log2(n / total) for n in counts.values()), 2)

def url_indicators(url):
    p = urlparse(url)
    host = (p.hostname or '').lower()
    decoded = unquote(url).lower()
    ext = tldextract.extract(host)
    subdomain_count = len([x for x in ext.subdomain.split('.') if x])
    token_hits = sorted({t for t in SUSPICIOUS_URL_TOKENS if re.search(r'(^|[^a-z])' + re.escape(t) + r'([^a-z]|$)', decoded)})
    digit_count = sum(c.isdigit() for c in url)
    hyphen_count = host.count('-')
    special_count = sum(url.count(c) for c in ['@', '%', '=', '&', '?'])
    path_depth = len([x for x in p.path.split('/') if x])

    host_is_ip = False
    try:
        ipaddress.ip_address(host)
        host_is_ip = True
    except Exception:
        pass

    shortener = registered_domain(host) in SHORTENER_HOSTS or host in SHORTENER_HOSTS
    punycode = 'xn--' in host
    repeated_subdomains = subdomain_count >= 3
    long_url = len(url) >= 100
    very_long_url = len(url) >= 180
    high_digits = digit_count >= 10
    many_hyphens = hyphen_count >= 4
    encoded_chars = '%' in url
    at_symbol = '@' in url

    points = 0
    reasons = []
    if host_is_ip:
        points += 25
        reasons.append('Raw IP address used instead of a normal domain name')
    if punycode:
        points += 18
        reasons.append('Internationalised/punycode hostname detected')
    if at_symbol:
        points += 20
        reasons.append('@ symbol appears in the URL')
    if shortener:
        points += 14
        reasons.append('URL shortening service detected')
    if very_long_url:
        points += 14
        reasons.append('Very long URL structure')
    elif long_url:
        points += 8
        reasons.append('Long URL structure')
    if repeated_subdomains:
        points += 10
        reasons.append('Many subdomains detected')
    if many_hyphens:
        points += 8
        reasons.append('Unusually high number of hyphens in hostname')
    if high_digits:
        points += 6
        reasons.append('Large number of numeric characters')
    if encoded_chars:
        points += 5
        reasons.append('Encoded characters detected in URL')
    if len(token_hits) >= 3:
        points += 12
        reasons.append('Multiple security/account keywords appear in URL')
    elif token_hits:
        points += 5
        reasons.append('Security/account keyword appears in URL')

    return {
        'url_length': len(url),
        'hostname_length': len(host),
        'subdomain_count': subdomain_count,
        'digit_count': digit_count,
        'hyphen_count': hyphen_count,
        'special_character_count': special_count,
        'path_depth': path_depth,
        'entropy': entropy(url),
        'uses_ip_as_host': host_is_ip,
        'punycode': punycode,
        'url_shortener': shortener,
        'encoded_characters': encoded_chars,
        'at_symbol': at_symbol,
        'suspicious_tokens': token_hits,
        'score': min(points, 100),
        'reasons': reasons
    }

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
    email_fields = len(soup.select('input[type="email"]'))
    hidden_fields = len(soup.select('input[type="hidden"]'))
    iframes = len(soup.find_all('iframe'))

    ext_forms = 0
    insecure_forms = 0
    for f in forms:
        action = (f.get('action') or '').strip()
        if action:
            target = urljoin(base, action)
            ah = (urlparse(target).hostname or '').lower()
            if ah and registered_domain(ah) != root:
                ext_forms += 1
            if urlparse(target).scheme == 'http':
                insecure_forms += 1

    links = []
    for a in soup.find_all('a', href=True):
        u = urljoin(base, a['href'])
        h = (urlparse(u).hostname or '').lower()
        if h:
            links.append(h)
    external = sum(1 for h in links if registered_domain(h) != root)
    ratio = external / len(links) if links else 0

    text = soup.get_text(' ', strip=True).lower()
    phrases = [x for x in SUSPICIOUS_PHRASES if x in text]
    title = soup.title.get_text(' ', strip=True)[:160] if soup.title else ''

    return {
        'title': title,
        'forms': len(forms),
        'password_fields': password,
        'email_fields': email_fields,
        'hidden_fields': hidden_fields,
        'iframes': iframes,
        'external_form_actions': ext_forms,
        'insecure_form_actions': insecure_forms,
        'total_links': len(links),
        'external_links': external,
        'external_link_ratio': round(ratio, 3),
        'suspicious_phrases': phrases
    }

def risk_level(score):
    if score >= 80:
        return 'CRITICAL'
    if score >= 60:
        return 'HIGH'
    if score >= 35:
        return 'MEDIUM'
    return 'LOW'

def scan(raw):
    normalized, original_host, ips = validate_public_url(raw)
    lexical = url_indicators(normalized)
    deep = dl_score(normalized)
    fetched = safe_fetch(normalized)
    final_host = (urlparse(fetched['final_url']).hostname or '').lower()
    tls = tls_info(fetched['final_url'])
    page = page_indicators(fetched)

    live_points = 0
    live_reasons = []
    if urlparse(fetched['final_url']).scheme != 'https':
        live_points += 18
        live_reasons.append('Website does not use HTTPS')
    if fetched['redirects'] >= 3:
        live_points += 10
        live_reasons.append('Multiple redirects detected')
    if registered_domain(final_host) != registered_domain(original_host):
        live_points += 15
        live_reasons.append('Redirect moved to a different registered domain')
    if tls.get('available') and not tls.get('valid'):
        live_points += 22
        live_reasons.append('TLS certificate could not be validated')
    if page['password_fields'] > 0:
        live_points += 5
        live_reasons.append('Password field detected')
    if page['external_form_actions'] > 0:
        live_points += 25
        live_reasons.append('Form submits to another registered domain')
    if page['insecure_form_actions'] > 0:
        live_points += 18
        live_reasons.append('Form submits over insecure HTTP')
    if page['suspicious_phrases']:
        live_points += min(18, len(page['suspicious_phrases']) * 6)
        live_reasons.append('Suspicious account/security wording detected')
    if page['external_link_ratio'] >= .80 and page['total_links'] >= 5:
        live_points += 5
        live_reasons.append('Very high external-link ratio')

    live_score = min(live_points, 100)
    combined = (0.62 * deep) + (0.20 * lexical['score']) + (0.18 * live_score)
    combined = max(0.0, min(100.0, combined))
    category = risk_level(combined)

    recommendations = {
        'LOW': 'No strong warning was detected. Verify the domain before entering sensitive information and keep normal browsing precautions.',
        'MEDIUM': 'Use caution. Independently verify the organisation and avoid entering passwords or payment details until you are confident the domain is genuine.',
        'HIGH': 'High-risk signals were detected. Do not enter credentials, payment details, or download files unless the website is independently verified.',
        'CRITICAL': 'Critical phishing indicators were detected. Leave the site, do not submit credentials or payments, and verify the organisation through a trusted official channel.'
    }

    all_reasons = lexical['reasons'] + live_reasons
    if not all_reasons:
        all_reasons = ['No strong contextual warning indicators were detected']

    signal_strength = round(abs(deep - 50) * 2, 1)
    verdict = {
        'LOW': 'Likely lower risk',
        'MEDIUM': 'Suspicious — verify carefully',
        'HIGH': 'Likely phishing / high risk',
        'CRITICAL': 'Strong phishing warning'
    }[category]

    return {
        'url': normalized,
        'scanned_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'risk_category': category,
        'verdict': verdict,
        'combined_risk_indicator': round(combined, 2),
        'deep_learning_phishing_score': round(deep, 2),
        'model_signal_strength': signal_strength,
        'lexical_indicator_score': lexical['score'],
        'contextual_indicator_score': live_score,
        'reasons': all_reasons,
        'recommendation': recommendations[category],
        'live': {
            'http_status': fetched['status'],
            'final_url': fetched['final_url'],
            'redirects': fetched['redirects'],
            'content_type': fetched['content_type'],
            'server': fetched['server']
        },
        'tls': tls,
        'domain': {
            'hostname': original_host,
            'registered_domain': registered_domain(original_host),
            'resolved_ips': ips,
            'number_of_ips': len(ips)
        },
        'url_analysis': lexical,
        'html': page,
        'notice': 'Research prototype. Scores are risk indicators for decision support, not a guarantee that a site is safe or malicious.'
    }

CSS = '''
:root{--bg:#050913;--panel:#0b1220;--panel2:#0e1829;--panel3:#111e32;--text:#f5f8ff;--muted:#8da0b8;--line:#1f3048;--cyan:#47d7ff;--blue:#5b8cff;--green:#3ee6a8;--amber:#ffc857;--orange:#ff9f43;--red:#ff5f73;--purple:#a78bfa}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);background:radial-gradient(circle at 12% 0%,rgba(71,215,255,.12),transparent 28%),radial-gradient(circle at 88% 12%,rgba(91,140,255,.14),transparent 30%),linear-gradient(180deg,#050913 0%,#07101d 48%,#050913 100%);min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.16;background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);background-size:34px 34px}
.wrap{max-width:1180px;margin:auto;padding:28px 20px 72px;position:relative}.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:18px}.logo{display:flex;align-items:center;gap:12px;font-weight:900;letter-spacing:.2px}.logo-mark{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(71,215,255,.22),rgba(91,140,255,.25));border:1px solid #284b72;box-shadow:0 0 28px rgba(71,215,255,.1);font-size:22px}.livechip{display:flex;align-items:center;gap:8px;color:#bdebdc;font-size:12px;border:1px solid #205747;background:rgba(13,44,36,.58);padding:8px 11px;border-radius:999px}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px var(--green)}
.hero{padding:44px;border:1px solid var(--line);background:linear-gradient(145deg,rgba(14,24,41,.96),rgba(7,17,31,.96));border-radius:28px;box-shadow:0 30px 90px rgba(0,0,0,.34);overflow:hidden;position:relative}.hero:after{content:"";position:absolute;width:320px;height:320px;right:-90px;top:-130px;border-radius:50%;background:radial-gradient(circle,rgba(71,215,255,.14),transparent 70%)}.eyebrow{display:inline-flex;align-items:center;gap:8px;color:#b6d8f5;background:#0b1b2e;border:1px solid #22405e;border-radius:999px;padding:8px 12px;font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.hero h1{font-size:clamp(38px,6vw,66px);line-height:1.02;margin:18px 0 12px;letter-spacing:-.045em;max-width:840px}.hero h1 span{background:linear-gradient(90deg,var(--cyan),#8bb3ff 60%,#c5b5ff);-webkit-background-clip:text;background-clip:text;color:transparent}.hero-copy{font-size:17px;color:#aebed1;max-width:790px;line-height:1.65;margin:0}.scanbox{margin-top:30px;padding:10px;border-radius:18px;background:rgba(3,9,17,.66);border:1px solid #263d59;display:flex;gap:10px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.02)}.scanbox input{min-width:0;flex:1;padding:16px 17px;background:transparent;border:0;color:#fff;font-size:16px;outline:none}.scanbox input::placeholder{color:#63758b}.scanbox button{border:0;border-radius:13px;padding:0 24px;font-weight:900;font-size:14px;color:#03101a;background:linear-gradient(135deg,var(--cyan),#71a2ff);cursor:pointer;box-shadow:0 12px 28px rgba(71,215,255,.17);transition:.18s transform,.18s filter}.scanbox button:hover{transform:translateY(-1px);filter:brightness(1.05)}.trustrow{display:flex;flex-wrap:wrap;gap:10px;margin-top:17px}.trust{font-size:12px;color:#92a8bf;border:1px solid #1f354e;background:rgba(7,18,32,.7);border-radius:999px;padding:7px 10px}.features{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:18px}.feature{padding:17px;border:1px solid var(--line);background:rgba(11,18,32,.74);border-radius:17px}.feature strong{display:block;font-size:13px;margin-bottom:5px}.feature span{color:var(--muted);font-size:12px;line-height:1.45}
.results{margin-top:20px}.summary{display:grid;grid-template-columns:1.35fr .65fr;gap:14px}.riskcard,.scorecard,.card,.section{border:1px solid var(--line);background:linear-gradient(145deg,rgba(13,22,38,.96),rgba(9,17,30,.96));border-radius:22px}.riskcard{padding:28px;display:flex;justify-content:space-between;align-items:center;gap:22px}.kicker{text-transform:uppercase;letter-spacing:.13em;font-size:11px;color:#7f96ae;font-weight:800}.risklabel{font-size:34px;font-weight:950;letter-spacing:-.035em;margin:7px 0 4px}.verdict{color:#a9bad0}.low{color:var(--green)}.medium{color:var(--amber)}.high{color:var(--orange)}.critical{color:var(--red)}.gauge{--score:0;width:144px;height:144px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--gauge-color) calc(var(--score)*1%),#15243a 0);position:relative;flex:0 0 auto}.gauge:before{content:"";position:absolute;inset:11px;border-radius:50%;background:#0a1424;border:1px solid #20344e}.gauge-inner{position:relative;text-align:center}.gauge strong{font-size:31px;display:block;line-height:1}.gauge span{font-size:11px;color:#8ea3ba}.scorecard{padding:24px}.scorecard .big{font-size:37px;font-weight:950;letter-spacing:-.04em;margin-top:5px}.progress{height:9px;background:#111f32;border-radius:999px;overflow:hidden;margin-top:14px}.progress i{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--cyan),#7698ff,var(--purple))}.note{font-size:12px;color:var(--muted);line-height:1.55}
.metricgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:12px}.card{padding:19px}.card .icon{font-size:18px}.card h3{font-size:12px;color:#92a8bf;text-transform:uppercase;letter-spacing:.07em;margin:10px 0 8px}.metric{font-size:25px;font-weight:900}.submetric{font-size:12px;color:#7f94ab;margin-top:4px}.section{padding:23px;margin-top:12px}.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:17px}.section h2{font-size:17px;margin:0}.section-title span{font-size:11px;color:#7890a8}.reasons{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:16px}.reason{display:flex;align-items:flex-start;gap:9px;padding:12px 13px;border-radius:13px;background:#0a1728;border:1px solid #1b3048;color:#c6d5e5;font-size:13px;line-height:1.4}.reason .mark{color:var(--amber);font-weight:900}.recommend{padding:17px 18px;border-radius:14px;border:1px solid #22446c;background:linear-gradient(90deg,rgba(20,55,86,.46),rgba(10,25,43,.78));line-height:1.55}.recommend b{color:#cbe7ff}.details{display:grid;grid-template-columns:1fr 1fr;gap:0 24px}.row{padding:11px 0;border-bottom:1px solid rgba(31,48,72,.72);overflow-wrap:anywhere}.row b{display:block;color:#6f8aa5;font-size:10px;text-transform:uppercase;letter-spacing:.09em;margin-bottom:5px}.good{color:var(--green)}.warn{color:var(--amber)}.bad{color:var(--red)}.token{display:inline-block;padding:5px 8px;border:1px solid #2a405d;border-radius:8px;background:#091522;margin:2px 4px 2px 0;font-size:12px}.disclaimer{margin-top:12px;border:1px solid #24364d;border-radius:16px;padding:16px 18px;background:rgba(8,15,27,.76)}.footer{margin-top:22px;text-align:center;color:#657b92;font-size:12px}.error{margin-top:18px;padding:18px;border:1px solid #713743;background:#2a1118;border-radius:16px;color:#ffd8dd}
@media(max-width:900px){.features,.metricgrid{grid-template-columns:1fr 1fr}.summary{grid-template-columns:1fr}}@media(max-width:680px){.wrap{padding:18px 13px 50px}.hero{padding:26px 20px}.scanbox{flex-direction:column}.scanbox button{padding:15px}.features,.metricgrid,.reasons,.details{grid-template-columns:1fr}.riskcard{align-items:flex-start;flex-direction:column}.topbar{align-items:flex-start}.livechip{white-space:nowrap}.hero h1{font-size:40px}.gauge{width:126px;height:126px}}
'''

def esc(v):
    return html_lib.escape(str(v if v is not None else '—'))

def bool_text(value, yes='Detected', no='Not detected'):
    return yes if value else no

def page_shell(inner=''):
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="PhishingGuard uses deep learning and passive live security checks to assess phishing risk."><title>PhishingGuard — AI Phishing Risk Scanner</title><style>{CSS}</style></head><body><main class="wrap"><div class="topbar"><div class="logo"><div class="logo-mark">🛡️</div><div>PhishingGuard <span style="color:#55708d;font-weight:700">v4</span></div></div><div class="livechip"><span class="dot"></span> Live scanner online</div></div><section class="hero"><span class="eyebrow">AI-powered cyber threat intelligence</span><h1>Check a website before you <span>trust it.</span></h1><p class="hero-copy">PhishingGuard combines a trained deep-learning URL model with explainable URL analysis, live website inspection, TLS checks and DNS intelligence to produce a clear phishing-risk assessment.</p><form class="scanbox" method="post" action="/scan"><input name="url" placeholder="Paste a URL — example.com/login" autocomplete="off" spellcheck="false" required><button type="submit">Analyse Website →</button></form><div class="trustrow"><span class="trust">✓ Passive analysis</span><span class="trust">✓ No credentials collected</span><span class="trust">✓ Explainable indicators</span><span class="trust">✓ Live TLS & DNS checks</span></div></section><div class="features"><div class="feature"><strong>🧠 Deep Learning</strong><span>Model-based analysis of URL text patterns.</span></div><div class="feature"><strong>🔎 URL Intelligence</strong><span>Length, tokens, subdomains, encoding and obfuscation signals.</span></div><div class="feature"><strong>🌐 Live Website Checks</strong><span>Redirects, forms, links, page structure and security wording.</span></div><div class="feature"><strong>🔐 TLS & DNS</strong><span>Certificate validation and public DNS resolution.</span></div></div>{inner}<div class="footer">PhishingGuard v4 • MSc Cybersecurity research artefact • Decision-support prototype</div></main></body></html>'''

def render_results(r):
    category = r['risk_category']
    cls = category.lower()
    gauge_color = {'LOW':'var(--green)','MEDIUM':'var(--amber)','HIGH':'var(--orange)','CRITICAL':'var(--red)'}[category]
    reasons_html = ''.join(f'<div class="reason"><span class="mark">◆</span><span>{esc(x)}</span></div>' for x in r['reasons'])
    tls = r['tls']; page = r['html']; lexical = r['url_analysis']
    ips = ', '.join(r['domain']['resolved_ips'][:4])
    if r['domain']['number_of_ips'] > 4:
        ips += f" +{r['domain']['number_of_ips']-4} more"
    phrases = ', '.join(page['suspicious_phrases']) if page['suspicious_phrases'] else 'None detected'
    tokens = ''.join(f'<span class="token">{esc(t)}</span>' for t in lexical['suspicious_tokens']) or '<span class="note">None detected</span>'
    tls_state = 'Valid' if tls.get('valid') else ('Unavailable' if not tls.get('available') else 'Could not validate')
    tls_cls = 'good' if tls.get('valid') else 'bad'
    https_state = 'HTTPS' if urlparse(r['live']['final_url']).scheme == 'https' else 'HTTP'
    https_cls = 'good' if https_state == 'HTTPS' else 'bad'

    return f'''<section class="results"><div class="summary"><div class="riskcard"><div><div class="kicker">Overall phishing-risk assessment</div><div class="risklabel {cls}">{esc(category)} RISK</div><div class="verdict">{esc(r['verdict'])}</div><p class="note">Scanned {esc(r['scanned_at'])}</p></div><div class="gauge" style="--score:{r['combined_risk_indicator']};--gauge-color:{gauge_color}"><div class="gauge-inner"><strong>{r['combined_risk_indicator']:.0f}</strong><span>Risk / 100</span></div></div></div><div class="scorecard"><div class="kicker">Deep-learning model</div><div class="big">{r['deep_learning_phishing_score']:.1f}%</div><div class="progress"><i style="width:{r['deep_learning_phishing_score']:.1f}%"></i></div><p class="note">Raw model phishing score. Signal strength: <b>{r['model_signal_strength']:.1f}%</b>. This is not a calibrated probability.</p></div></div>
<div class="metricgrid"><div class="card"><div class="icon">🧠</div><h3>ML URL score</h3><div class="metric">{r['deep_learning_phishing_score']:.1f}</div><div class="submetric">out of 100</div></div><div class="card"><div class="icon">🔎</div><h3>URL indicators</h3><div class="metric">{r['lexical_indicator_score']}</div><div class="submetric">heuristic risk score</div></div><div class="card"><div class="icon">🌐</div><h3>Live indicators</h3><div class="metric">{r['contextual_indicator_score']}</div><div class="submetric">website context score</div></div><div class="card"><div class="icon">🔐</div><h3>Transport</h3><div class="metric {https_cls}">{https_state}</div><div class="submetric {tls_cls}">TLS: {esc(tls_state)}</div></div></div>
<div class="section"><div class="section-title"><h2>⚠ Why PhishingGuard gave this result</h2><span>Explainable indicators</span></div><div class="reasons">{reasons_html}</div><div class="recommend"><b>Security recommendation</b><br>{esc(r['recommendation'])}</div></div>
<div class="section"><div class="section-title"><h2>🔎 URL intelligence</h2><span>Lexical & structural analysis</span></div><div class="details"><div class="row"><b>URL length</b>{lexical['url_length']} characters</div><div class="row"><b>Hostname length</b>{lexical['hostname_length']} characters</div><div class="row"><b>Subdomains</b>{lexical['subdomain_count']}</div><div class="row"><b>Path depth</b>{lexical['path_depth']}</div><div class="row"><b>Digits</b>{lexical['digit_count']}</div><div class="row"><b>Hyphens in hostname</b>{lexical['hyphen_count']}</div><div class="row"><b>URL entropy</b>{lexical['entropy']}</div><div class="row"><b>Special characters</b>{lexical['special_character_count']}</div><div class="row"><b>Raw IP as hostname</b>{bool_text(lexical['uses_ip_as_host'])}</div><div class="row"><b>Punycode</b>{bool_text(lexical['punycode'])}</div><div class="row"><b>URL shortener</b>{bool_text(lexical['url_shortener'])}</div><div class="row"><b>Encoded characters</b>{bool_text(lexical['encoded_characters'])}</div><div class="row"><b>Suspicious URL tokens</b>{tokens}</div><div class="row"><b>@ symbol</b>{bool_text(lexical['at_symbol'])}</div></div></div>
<div class="section"><div class="section-title"><h2>🌐 Live website analysis</h2><span>Passive HTML inspection</span></div><div class="details"><div class="row"><b>Requested URL</b>{esc(r['url'])}</div><div class="row"><b>Final URL</b>{esc(r['live']['final_url'])}</div><div class="row"><b>HTTP status</b>{esc(r['live']['http_status'])}</div><div class="row"><b>Redirects</b>{esc(r['live']['redirects'])}</div><div class="row"><b>Page title</b>{esc(page['title'] or 'Not available')}</div><div class="row"><b>Server header</b>{esc(r['live']['server'] or 'Not reported')}</div><div class="row"><b>Forms</b>{page['forms']}</div><div class="row"><b>Password fields</b>{page['password_fields']}</div><div class="row"><b>Email fields</b>{page['email_fields']}</div><div class="row"><b>Hidden fields</b>{page['hidden_fields']}</div><div class="row"><b>Iframes</b>{page['iframes']}</div><div class="row"><b>External form actions</b>{page['external_form_actions']}</div><div class="row"><b>Insecure form actions</b>{page['insecure_form_actions']}</div><div class="row"><b>Links</b>{page['total_links']} total • {page['external_links']} external</div><div class="row"><b>External-link ratio</b>{page['external_link_ratio']*100:.1f}%</div><div class="row"><b>Suspicious page phrases</b>{esc(phrases)}</div></div></div>
<div class="section"><div class="section-title"><h2>🔐 TLS certificate</h2><span>Transport-security check</span></div><div class="details"><div class="row"><b>HTTPS/TLS available</b>{'Yes' if tls.get('available') else 'No'}</div><div class="row"><b>Certificate valid</b>{'Yes' if tls.get('valid') else 'No'}</div><div class="row"><b>Issuer</b>{esc(tls.get('issuer') or tls.get('reason'))}</div><div class="row"><b>Certificate subject</b>{esc(tls.get('subject'))}</div><div class="row"><b>Expiry date</b>{esc(tls.get('expires'))}</div><div class="row"><b>Days remaining</b>{esc(tls.get('days_remaining'))}</div></div></div>
<div class="section"><div class="section-title"><h2>🛰 Domain & DNS intelligence</h2><span>Resolved network identity</span></div><div class="details"><div class="row"><b>Hostname</b>{esc(r['domain']['hostname'])}</div><div class="row"><b>Registered domain</b>{esc(r['domain']['registered_domain'])}</div><div class="row"><b>Resolved IP addresses</b>{esc(ips)}</div><div class="row"><b>Number of resolved IPs</b>{r['domain']['number_of_ips']}</div></div></div>
<div class="disclaimer"><b>Important:</b> <span class="note">{esc(r['notice'])}</span></div></section>'''

@app.get('/', response_class=HTMLResponse)
def home():
    return page_shell()

@app.get('/health')
def health():
    return {'status': 'ok', 'model_loaded': True, 'version': '4.0'}

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
