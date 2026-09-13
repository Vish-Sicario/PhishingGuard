import os, ssl, socket, ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import tensorflow as tf
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

MODEL_PATH=os.getenv('MODEL_PATH','phishing_url_detector.keras')
MAX_BYTES=1_000_000
MAX_REDIRECTS=3
ALLOWED_PORTS={80,443}
model=tf.keras.models.load_model(MODEL_PATH)
app=FastAPI(title='PhishingGuard', version='2.0')

SUSPICIOUS=['verify your account','confirm your account','account suspended','urgent action','verify identity','login immediately','confirm password','security alert']

def validate_public_url(raw):
    raw=(raw or '').strip()
    if not raw: raise ValueError('Enter a URL.')
    if '://' not in raw: raw='https://'+raw
    p=urlparse(raw)
    if p.scheme not in ('http','https'): raise ValueError('Only HTTP/HTTPS URLs are allowed.')
    if p.username or p.password: raise ValueError('URLs containing credentials are not allowed.')
    host=(p.hostname or '').lower().rstrip('.')
    if not host or host=='localhost' or host.endswith(('.localhost','.local','.internal')): raise ValueError('Local/internal hosts are blocked.')
    try: port=p.port
    except ValueError: raise ValueError('Invalid port.')
    if port and port not in ALLOWED_PORTS: raise ValueError('Only ports 80 and 443 are allowed.')
    infos=socket.getaddrinfo(host, port or (443 if p.scheme=='https' else 80), type=socket.SOCK_STREAM)
    ips=sorted({x[4][0] for x in infos})
    if not ips: raise ValueError('Host could not be resolved.')
    for value in ips:
        ip=ipaddress.ip_address(value)
        if not ip.is_global: raise ValueError('Private, loopback, link-local or reserved addresses are blocked.')
    return raw, host, ips

def safe_fetch(raw):
    current,_,_=validate_public_url(raw)
    session=requests.Session(); session.trust_env=False
    headers={'User-Agent':'PhishingGuard-Security-Scanner/2.0','Accept':'text/html,application/xhtml+xml'}
    history=[]
    for _ in range(MAX_REDIRECTS+1):
        current,_,_=validate_public_url(current)
        r=session.get(current,headers=headers,timeout=(3,6),allow_redirects=False,stream=True)
        if 300 <= r.status_code < 400 and r.headers.get('Location'):
            if len(history)>=MAX_REDIRECTS: raise ValueError('Too many redirects.')
            nxt=urljoin(current,r.headers['Location'])
            validate_public_url(nxt)
            history.append(current); current=nxt; r.close(); continue
        ctype=(r.headers.get('Content-Type') or '').lower()
        body=b''
        if 'text/html' in ctype or 'application/xhtml+xml' in ctype or not ctype:
            for chunk in r.iter_content(16384):
                if chunk:
                    body+=chunk
                    if len(body)>MAX_BYTES: body=body[:MAX_BYTES]; break
        enc=r.encoding or 'utf-8'
        html=body.decode(enc,errors='replace')
        return {'status':r.status_code,'final_url':current,'redirects':len(history),'content_type':ctype,'html':html}
    raise ValueError('Redirect limit exceeded.')

def dl_score(url):
    out=model(tf.constant([url],dtype=tf.string),training=False)
    return float(out.numpy().reshape(-1)[0])*100

def tls_info(url):
    p=urlparse(url)
    if p.scheme!='https': return {'available':False,'valid':False,'reason':'URL does not use HTTPS'}
    host=p.hostname
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=5) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
        issuer=dict(x[0] for x in cert.get('issuer',[]))
        expiry=datetime.strptime(cert['notAfter'],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        return {'available':True,'valid':expiry>datetime.now(timezone.utc),'issuer':issuer.get('organizationName') or issuer.get('commonName'),'days_remaining':(expiry-datetime.now(timezone.utc)).days}
    except Exception as e: return {'available':True,'valid':False,'reason':str(e)[:160]}

def page_indicators(fetch):
    soup=BeautifulSoup(fetch['html'],'html.parser')
    base=fetch['final_url']; host=(urlparse(base).hostname or '').lower()
    forms=soup.find_all('form'); password=len(soup.select('input[type="password"]')); iframes=len(soup.find_all('iframe'))
    ext_forms=0
    for f in forms:
        action=(f.get('action') or '').strip()
        if action:
            ah=(urlparse(urljoin(base,action)).hostname or '').lower()
            if ah and ah!=host: ext_forms+=1
    links=[]
    for a in soup.find_all('a',href=True):
        u=urljoin(base,a['href']); h=(urlparse(u).hostname or '').lower()
        if h: links.append(h)
    external=sum(1 for h in links if h!=host); ratio=external/len(links) if links else 0
    text=soup.get_text(' ',strip=True).lower(); phrases=[x for x in SUSPICIOUS if x in text]
    return {'forms':len(forms),'password_fields':password,'iframes':iframes,'external_form_actions':ext_forms,'total_links':len(links),'external_links':external,'external_link_ratio':round(ratio,3),'suspicious_phrases':phrases}

def scan(raw):
    normalized,original_host,ips=validate_public_url(raw)
    deep=dl_score(normalized)
    fetched=safe_fetch(normalized)
    final_host=(urlparse(fetched['final_url']).hostname or '').lower()
    tls=tls_info(fetched['final_url']); html=page_indicators(fetched)
    points=0; reasons=[]
    if urlparse(fetched['final_url']).scheme!='https': points+=15; reasons.append('Website does not use HTTPS')
    if fetched['redirects']>=3: points+=10; reasons.append('Multiple redirects detected')
    if final_host!=original_host: points+=10; reasons.append('Redirect changed hostname')
    if tls.get('available') and not tls.get('valid'): points+=20; reasons.append('TLS certificate could not be validated')
    if html['password_fields']>0: points+=5; reasons.append('Password field detected')
    if html['external_form_actions']>0: points+=20; reasons.append('Form submits to another hostname')
    if html['suspicious_phrases']: points+=min(15,len(html['suspicious_phrases'])*5); reasons.append('Suspicious account/security wording detected')
    if html['external_link_ratio']>=.8: points+=5; reasons.append('Very high external-link ratio')
    contextual=min(points,100); combined=.70*deep+.30*contextual
    category='HIGH' if combined>=70 else 'MEDIUM' if combined>=40 else 'LOW'
    return {'url':normalized,'risk_category':category,'combined_risk_indicator':round(combined,2),'deep_learning_phishing_score':round(deep,2),'contextual_indicator_score':contextual,'reasons':reasons,'live':{'http_status':fetched['status'],'final_url':fetched['final_url'],'redirects':fetched['redirects']},'tls':tls,'domain':{'hostname':original_host,'resolved_ips':ips},'html':html,'notice':'Research prototype. Combined risk is a heuristic indicator, not a calibrated phishing probability or safety guarantee.'}

PAGE='''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>PhishingGuard</title><style>body{font-family:Arial,sans-serif;max-width:850px;margin:50px auto;padding:20px;background:#0b1220;color:#eef} .card{background:#121c30;padding:28px;border-radius:16px}input{width:75%;padding:14px;border-radius:8px;border:0}button{padding:14px 20px;border:0;border-radius:8px;font-weight:bold}pre{white-space:pre-wrap;background:#07101e;padding:18px;border-radius:10px}.note{opacity:.75;font-size:14px}</style></head><body><div class="card"><h1>🛡️ PhishingGuard</h1><p>Deep-learning URL analysis + passive live security checks.</p><form method="post" action="/scan"><input name="url" placeholder="https://example.com" required><button>Scan Website</button></form><p class="note">Research prototype. Never use the result as the only basis for trusting a website.</p></div></body></html>'''
@app.get('/',response_class=HTMLResponse)
def home(): return PAGE
@app.get('/health')
def health(): return {'status':'ok','model_loaded':True}
@app.post('/api/scan')
def api_scan(url: str=Form(...)):
    try:return scan(url)
    except Exception as e:return JSONResponse({'success':False,'error':str(e)},status_code=400)
@app.post('/scan',response_class=HTMLResponse)
def web_scan(url: str=Form(...)):
    try:
        r=scan(url); reasons='<br>'.join(r['reasons']) or 'No contextual warnings detected.'
        return PAGE.replace('</div></body>',f'''<hr><h2>{r['risk_category']} RISK</h2><h3>Combined Risk Indicator: {r['combined_risk_indicator']:.2f}/100</h3><p>Deep Learning URL Score: {r['deep_learning_phishing_score']:.2f}%</p><p>Contextual Indicator: {r['contextual_indicator_score']}/100</p><p><b>Reasons:</b><br>{reasons}</p><p>HTTP status: {r['live']['http_status']} | Redirects: {r['live']['redirects']}</p><p class="note">{r['notice']}</p></div></body>''')
    except Exception as e:return PAGE.replace('</div></body>',f'<hr><h3>Scan could not be completed</h3><p>{str(e)}</p></div></body>')
