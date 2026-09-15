import os
import re
import ssl
import html
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import tensorflow as tf
import requests
from bs4 import BeautifulSoup
import gradio as gr
from fastapi import FastAPI
from fastapi.responses import JSONResponse


# ==============================================================
# CONFIGURATION
# ==============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "phishing_url_detector_v2.keras"
)

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 1_000_000

CONNECT_TIMEOUT = 4
READ_TIMEOUT = 6

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253

USER_AGENT = "PhishingGuard-Academic-Security-Research/2.0"


# ==============================================================
# LOAD CNN V2
# ==============================================================

print("Loading PhishingGuard CNN V2...")

if not os.path.isfile(MODEL_PATH):
    raise RuntimeError("CNN V2 model file is missing.")

model_v2 = tf.keras.models.load_model(
    MODEL_PATH,
    compile=False
)

print("CNN V2 loaded successfully.")


# ==============================================================
# NORMALISATION
# ==============================================================

def normalize_user_url(url):

    url = (url or "").strip()

    if not url:
        return ""

    url = "".join(
        c for c in url
        if ord(c) >= 32
    )

    if len(url) > MAX_URL_LENGTH:
        raise ValueError(
            "URL exceeds the permitted length."
        )

    if not url.lower().startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    return url


# ==============================================================
# CNN V2
# ==============================================================

def phishingguard_dl_scan(url):

    normalized = normalize_user_url(url)

    if not normalized:
        raise ValueError(
            "Please enter a website URL."
        )

    url_tensor = tf.constant(
        [normalized],
        dtype=tf.string
    )

    prediction = model_v2(
        url_tensor,
        training=False
    ).numpy()

    raw_score = float(
        prediction[0][0]
    )

    return {
        "url": normalized,
        "raw_score": raw_score,
        "deep_learning_score":
            round(raw_score * 100, 2)
    }


# ==============================================================
# URL INTELLIGENCE
# ==============================================================

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "signin",
    "wallet",
    "payment"
]


def analyse_url_structure(url):

    normalized = normalize_user_url(url)

    parsed = urlparse(normalized)

    hostname = (
        parsed.hostname or ""
    ).lower()

    score = 0
    findings = []

    if parsed.scheme != "https":

        score += 10

        findings.append(
            "URL does not use HTTPS."
        )

    if len(normalized) > 75:

        score += 10

        findings.append(
            "URL is unusually long."
        )

    if len(normalized) > 150:
        score += 10

    try:

        ipaddress.ip_address(hostname)

        score += 25

        findings.append(
            "URL uses an IP address "
            "instead of a domain name."
        )

    except ValueError:
        pass

    if "@" in normalized:

        score += 20

        findings.append(
            "URL contains an @ symbol."
        )

    hostname_parts = [
        x for x in hostname.split(".")
        if x
    ]

    if len(hostname_parts) > 4:

        score += 15

        findings.append(
            "Hostname contains many "
            "subdomain levels."
        )

    lower_url = normalized.lower()

    suspicious_matches = [
        word
        for word in SUSPICIOUS_WORDS
        if word in lower_url
    ]

    if suspicious_matches:

        score += min(
            len(suspicious_matches) * 5,
            20
        )

        findings.append(
            "Potentially suspicious URL terms: "
            + ", ".join(suspicious_matches)
        )

    if normalized.count("-") >= 3:

        score += 10

        findings.append(
            "URL contains multiple hyphens."
        )

    score = min(score, 100)

    if not findings:

        findings.append(
            "No obvious suspicious URL "
            "structure detected."
        )

    return {
        "score": score,
        "findings": findings
    }


# ==============================================================
# PUBLIC IP VALIDATION
# ==============================================================

def is_safe_public_ip(ip_text):

    try:
        ip = ipaddress.ip_address(ip_text)

    except ValueError:
        return False

    return ip.is_global


# ==============================================================
# HARDENED TARGET VALIDATION
# ==============================================================

def validate_target_url(url):

    normalized = normalize_user_url(url)

    parsed = urlparse(normalized)

    scheme = parsed.scheme.lower()

    if scheme not in ALLOWED_SCHEMES:

        raise ValueError(
            "Only HTTP and HTTPS URLs are permitted."
        )

    if (
        parsed.username is not None
        or parsed.password is not None
    ):

        raise ValueError(
            "URLs containing username/password "
            "information are not permitted."
        )

    hostname = parsed.hostname

    if not hostname:

        raise ValueError(
            "A valid hostname is required."
        )

    hostname = hostname.rstrip(".").lower()

    if len(hostname) > MAX_HOSTNAME_LENGTH:

        raise ValueError(
            "Hostname exceeds the permitted length."
        )

    if hostname in {
        "localhost",
        "localhost.localdomain"
    }:

        raise ValueError(
            "Localhost targets are blocked."
        )

    try:
        port = parsed.port

    except ValueError:

        raise ValueError(
            "Invalid port."
        )

    if port is None:

        port = (
            443
            if scheme == "https"
            else 80
        )

    if port not in ALLOWED_PORTS:

        raise ValueError(
            "Only ports 80 and 443 are permitted."
        )

    try:

        address_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror as exc:

        raise ValueError(
            "Hostname could not be resolved."
        ) from exc

    resolved_ips = sorted({
        item[4][0]
        for item in address_info
    })

    if not resolved_ips:

        raise ValueError(
            "Hostname resolved to no addresses."
        )

    for ip_text in resolved_ips:

        if not is_safe_public_ip(ip_text):

            raise ValueError(
                "Target resolves to a blocked "
                "or non-public network address."
            )

    return {
        "url": normalized,
        "hostname": hostname,
        "port": port,
        "resolved_ips": resolved_ips
    }


# ==============================================================
# REDIRECT VALIDATION
# ==============================================================

def validate_redirect(
    current_url,
    location
):

    if not location:

        raise ValueError(
            "Redirect did not provide a destination."
        )

    next_url = urljoin(
        current_url,
        location
    )

    validate_target_url(
        next_url
    )

    return next_url


# ==============================================================
# TLS / NETWORK ANALYSIS
# ==============================================================

def analyse_network_security(url):

    result = {
        "available": False,
        "https": False,
        "tls_available": False,
        "tls_version": None,
        "certificate_issuer": None,
        "certificate_expiry": None,
        "certificate_valid": None,
        "hostname": None,
        "resolved_ips": [],
        "error": None
    }

    try:

        validated = validate_target_url(
            url
        )

        hostname = validated[
            "hostname"
        ]

        result["hostname"] = hostname

        result["resolved_ips"] = (
            validated["resolved_ips"]
        )

        parsed = urlparse(
            validated["url"]
        )

        result["https"] = (
            parsed.scheme == "https"
        )

        result["available"] = True

        if not result["https"]:
            return result

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=CONNECT_TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                result[
                    "tls_available"
                ] = True

                result[
                    "tls_version"
                ] = tls_socket.version()

                issuer_parts = []

                for group in certificate.get(
                    "issuer",
                    []
                ):

                    for key, value in group:

                        issuer_parts.append(
                            f"{key}={value}"
                        )

                result[
                    "certificate_issuer"
                ] = ", ".join(
                    issuer_parts
                )

                result[
                    "certificate_expiry"
                ] = certificate.get(
                    "notAfter"
                )

                result[
                    "certificate_valid"
                ] = True

    except Exception as exc:

        result["error"] = str(exc)

    return result


# ==============================================================
# LIVE WEBPAGE ANALYSIS
# ==============================================================

SUSPICIOUS_PHRASES = [
    "verify your account",
    "confirm your account",
    "update your account",
    "verify your identity",
    "confirm your identity",
    "account suspended",
    "account locked",
    "urgent action required",
    "enter your password",
    "confirm your password"
]


def analyse_live_website(url):

    result = {
        "available": False,
        "forms": 0,
        "password_fields": 0,
        "iframes": 0,
        "links": 0,
        "external_links": 0,
        "external_forms": 0,
        "empty_form_actions": 0,
        "suspicious_phrases": [],
        "redirects": 0,
        "final_url": None,
        "http_status": None,
        "content_type": None,
        "bytes_read": 0,
        "error": None
    }

    response = None

    try:

        validated = validate_target_url(
            url
        )

        current_url = validated[
            "url"
        ]

        session = requests.Session()

        session.trust_env = False

        headers = {
            "User-Agent": USER_AGENT,
            "Accept":
                "text/html,application/xhtml+xml"
        }

        for redirect_number in range(
            MAX_REDIRECTS + 1
        ):

            validate_target_url(
                current_url
            )

            response = session.get(
                current_url,
                headers=headers,
                timeout=(
                    CONNECT_TIMEOUT,
                    READ_TIMEOUT
                ),
                allow_redirects=False,
                stream=True
            )

            result[
                "http_status"
            ] = response.status_code

            if response.status_code in {
                301,
                302,
                303,
                307,
                308
            }:

                if (
                    redirect_number
                    >= MAX_REDIRECTS
                ):

                    response.close()

                    raise ValueError(
                        "Maximum redirect "
                        "limit exceeded."
                    )

                location = (
                    response.headers.get(
                        "Location"
                    )
                )

                next_url = validate_redirect(
                    current_url,
                    location
                )

                response.close()
                response = None

                current_url = next_url

                result["redirects"] += 1

                continue

            break

        if response is None:

            raise ValueError(
                "No valid HTTP response "
                "was received."
            )

        result["final_url"] = current_url

        content_type = (
            response.headers.get(
                "Content-Type",
                ""
            ).lower()
        )

        result[
            "content_type"
        ] = content_type

        if (
            "text/html" not in content_type
            and
            "application/xhtml+xml"
            not in content_type
        ):

            result["available"] = True

            response.close()
            response = None

            return result

        content_length = (
            response.headers.get(
                "Content-Length"
            )
        )

        if content_length:

            try:

                length_value = int(
                    content_length
                )

            except ValueError:

                length_value = None

            if (
                length_value is not None
                and
                length_value
                > MAX_RESPONSE_BYTES
            ):

                response.close()
                response = None

                raise ValueError(
                    "Webpage exceeds the maximum "
                    "permitted response size."
                )

        content = bytearray()

        for chunk in response.iter_content(
            chunk_size=8192
        ):

            if not chunk:
                continue

            remaining = (
                MAX_RESPONSE_BYTES
                - len(content)
            )

            if remaining <= 0:
                break

            content.extend(
                chunk[:remaining]
            )

            if (
                len(content)
                >= MAX_RESPONSE_BYTES
            ):
                break

        result["bytes_read"] = len(content)

        response.close()
        response = None

        page_html = content.decode(
            "utf-8",
            errors="replace"
        )

        soup = BeautifulSoup(
            page_html,
            "html.parser"
        )

        forms = soup.find_all("form")

        links = soup.find_all(
            "a",
            href=True
        )

        iframes = soup.find_all(
            "iframe"
        )

        password_fields = soup.find_all(
            "input",
            attrs={
                "type":
                    re.compile(
                        "^password$",
                        re.I
                    )
            }
        )

        result["forms"] = len(forms)
        result["links"] = len(links)
        result["iframes"] = len(iframes)

        result[
            "password_fields"
        ] = len(password_fields)

        current_host = (
            urlparse(
                current_url
            ).hostname
            or ""
        ).lower()

        external_links = 0

        for link in links:

            href = (
                link.get("href")
                or ""
            ).strip()

            if not href:
                continue

            destination = urljoin(
                current_url,
                href
            )

            parsed_destination = (
                urlparse(destination)
            )

            if (
                parsed_destination.scheme
                not in ("http", "https")
            ):
                continue

            destination_host = (
                parsed_destination.hostname
            )

            if (
                destination_host
                and
                destination_host.lower()
                != current_host
            ):

                external_links += 1

        result[
            "external_links"
        ] = external_links

        external_forms = 0
        empty_actions = 0

        for form in forms:

            action = (
                form.get("action")
                or ""
            ).strip()

            if not action:

                empty_actions += 1
                continue

            destination = urljoin(
                current_url,
                action
            )

            destination_host = (
                urlparse(
                    destination
                ).hostname
            )

            if (
                destination_host
                and
                destination_host.lower()
                != current_host
            ):

                external_forms += 1

        result[
            "external_forms"
        ] = external_forms

        result[
            "empty_form_actions"
        ] = empty_actions

        page_text = (
            soup.get_text(
                " ",
                strip=True
            ).lower()
        )

        result[
            "suspicious_phrases"
        ] = [
            phrase
            for phrase in SUSPICIOUS_PHRASES
            if phrase in page_text
        ]

        result["available"] = True

        return result

    except Exception as exc:

        result["error"] = str(exc)

        return result

    finally:

        if response is not None:

            try:
                response.close()

            except Exception:
                pass


# ==============================================================
# LIVE SECURITY SCORE
# ==============================================================

def calculate_live_score(network, webpage):

    score = 0
    findings = []

    if network.get("available"):

        if not network.get("https"):

            score += 10

            findings.append(
                "Website is not using HTTPS."
            )

        elif not network.get("tls_available"):

            score += 10

            findings.append(
                "TLS connection could not be verified."
            )

    if webpage.get("available"):

        if webpage.get("password_fields", 0) > 0:

            score += 8

            findings.append(
                "The webpage contains a password field."
            )

        if webpage.get("external_forms", 0) > 0:

            score += 20

            findings.append(
                "A form submits data to an external hostname."
            )

        if webpage.get("iframes", 0) > 2:

            score += 5

            findings.append(
                "The webpage contains multiple iframes."
            )

        phrases = webpage.get(
            "suspicious_phrases",
            []
        )

        if phrases:

            score += min(
                len(phrases) * 5,
                20
            )

            findings.append(
                "Security-sensitive language detected: "
                + ", ".join(phrases)
            )

    return {
        "score": min(score, 100),
        "findings": findings
    }


# ==============================================================
# COMPLETE PHISHINGGUARD ENGINE
# ==============================================================

def complete_phishingguard_scan(url):

    normalized = normalize_user_url(url)

    if not normalized:

        raise ValueError(
            "Please enter a website URL."
        )

    # CNN V2
    dl = phishingguard_dl_scan(
        normalized
    )

    # URL intelligence
    url_analysis = analyse_url_structure(
        normalized
    )

    # Network / TLS
    network = analyse_network_security(
        normalized
    )

    # Controlled live analysis
    webpage = analyse_live_website(
        normalized
    )

    live = calculate_live_score(
        network,
        webpage
    )

    cnn_score = dl[
        "deep_learning_score"
    ]

    url_score = url_analysis[
        "score"
    ]

    live_score = live[
        "score"
    ]

    # ----------------------------------------------------------
    # MULTI-LAYER FUSION
    #
    # CNN V2 is the primary detector.
    # Supporting security intelligence contributes additional
    # evidence.
    #
    # These are research-prototype fusion weights.
    # ----------------------------------------------------------

    overall_score = round(
        (
            cnn_score * 0.70
            + url_score * 0.20
            + live_score * 0.10
        ),
        2
    )

    if overall_score >= 75:

        risk = "CRITICAL"

    elif overall_score >= 55:

        risk = "HIGH"

    elif overall_score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    findings = []

    # CNN explanation
    if cnn_score >= 75:

        findings.append(
            "The CNN Deep Learning model detected "
            "strong phishing-like URL patterns."
        )

    elif cnn_score >= 50:

        findings.append(
            "The CNN Deep Learning model detected "
            "elevated phishing-like URL patterns."
        )

    elif cnn_score >= 25:

        findings.append(
            "The CNN Deep Learning model detected "
            "some potentially suspicious URL patterns."
        )

    else:

        findings.append(
            "The CNN Deep Learning model did not "
            "detect strong phishing-like URL patterns."
        )

    findings.extend(
        url_analysis["findings"]
    )

    findings.extend(
        live["findings"]
    )

    if risk == "CRITICAL":

        recommendation = (
            "Strong risk indicators were detected. "
            "Avoid entering passwords, payment details "
            "or other sensitive information."
        )

    elif risk == "HIGH":

        recommendation = (
            "Multiple risk indicators were detected. "
            "Verify the website independently before "
            "providing sensitive information."
        )

    elif risk == "MEDIUM":

        recommendation = (
            "Some suspicious indicators were detected. "
            "Proceed carefully and verify the domain "
            "before entering sensitive information."
        )

    else:

        recommendation = (
            "No strong phishing indicators were detected "
            "by the current analysis. This does not "
            "guarantee that the website is safe."
        )

    return {
        "url": normalized,
        "overall_score": overall_score,
        "risk": risk,

        "cnn_score": cnn_score,
        "url_score": url_score,
        "live_score": live_score,

        "findings": findings,
        "recommendation": recommendation,

        "network": network,
        "webpage": webpage
    }


# ==============================================================
# SAFE HTML OUTPUT
# ==============================================================

def escape_html(value):

    if value is None:
        value = "Not available"

    return html.escape(
        str(value)
    )


def build_dashboard(url):

    try:

        result = complete_phishingguard_scan(
            url
        )

        risk = result["risk"]

        risk_class = {
            "LOW": "risk-low",
            "MEDIUM": "risk-medium",
            "HIGH": "risk-high",
            "CRITICAL": "risk-critical"
        }.get(
            risk,
            "risk-low"
        )

        findings_html = "".join(
            "<li>"
            + escape_html(item)
            + "</li>"
            for item in result["findings"]
        )

        network = result["network"]
        webpage = result["webpage"]

        tls_status = (
            "Available"
            if network.get("tls_available")
            else "Not verified"
        )

        live_status = (
            "Analysed"
            if webpage.get("available")
            else "Unavailable"
        )

        return f"""
        <div class="result-shell">

            <div class="risk-card {risk_class}">

                <div class="risk-small">
                    PHISHINGGUARD ASSESSMENT
                </div>

                <div class="risk-title">
                    {escape_html(risk)} RISK
                </div>

                <div class="risk-score">
                    {escape_html(result["overall_score"])}
                    / 100
                </div>

                <div class="target-url">
                    {escape_html(result["url"])}
                </div>

            </div>


            <div class="metric-grid">

                <div class="metric-card">

                    <div class="metric-label">
                        CNN DEEP LEARNING
                    </div>

                    <div class="metric-value">
                        {escape_html(result["cnn_score"])}
                    </div>

                    <div class="metric-note">
                        Deep Learning model score / 100
                    </div>

                </div>


                <div class="metric-card">

                    <div class="metric-label">
                        URL INTELLIGENCE
                    </div>

                    <div class="metric-value">
                        {escape_html(result["url_score"])}
                    </div>

                    <div class="metric-note">
                        Structural risk score / 100
                    </div>

                </div>


                <div class="metric-card">

                    <div class="metric-label">
                        TLS
                    </div>

                    <div class="metric-value metric-text">
                        {escape_html(tls_status)}
                    </div>

                    <div class="metric-note">
                        {escape_html(network.get("tls_version"))}
                    </div>

                </div>


                <div class="metric-card">

                    <div class="metric-label">
                        LIVE ANALYSIS
                    </div>

                    <div class="metric-value metric-text">
                        {escape_html(live_status)}
                    </div>

                    <div class="metric-note">
                        Web security intelligence
                    </div>

                </div>

            </div>


            <div class="analysis-card">

                <h3>
                    Explainable Security Findings
                </h3>

                <ul>
                    {findings_html}
                </ul>

            </div>


            <div class="analysis-card">

                <h3>
                    Network &amp; Web Intelligence
                </h3>

                <div class="detail-grid">

                    <div>
                        <b>Hostname</b><br>
                        {escape_html(network.get("hostname"))}
                    </div>

                    <div>
                        <b>TLS Version</b><br>
                        {escape_html(network.get("tls_version"))}
                    </div>

                    <div>
                        <b>HTTP Status</b><br>
                        {escape_html(webpage.get("http_status"))}
                    </div>

                    <div>
                        <b>Forms</b><br>
                        {escape_html(webpage.get("forms"))}
                    </div>

                    <div>
                        <b>Password Fields</b><br>
                        {escape_html(webpage.get("password_fields"))}
                    </div>

                    <div>
                        <b>External Forms</b><br>
                        {escape_html(webpage.get("external_forms"))}
                    </div>

                    <div>
                        <b>External Links</b><br>
                        {escape_html(webpage.get("external_links"))}
                    </div>

                    <div>
                        <b>Iframes</b><br>
                        {escape_html(webpage.get("iframes"))}
                    </div>

                    <div>
                        <b>Redirects</b><br>
                        {escape_html(webpage.get("redirects"))}
                    </div>

                </div>

            </div>


            <div class="recommendation-card">

                <h3>
                    Security Recommendation
                </h3>

                <p>
                    {escape_html(result["recommendation"])}
                </p>

            </div>

        </div>
        """

    except Exception as exc:

        return f"""
        <div class="error-card">

            <h3>
                Analysis could not be completed
            </h3>

            <p>
                {escape_html(exc)}
            </p>

            <p>
                Check the URL and try again.
            </p>

        </div>
        """


# ==============================================================
# PREMIUM CYBERSECURITY UI
# ==============================================================

CUSTOM_CSS = """
body {
    background:
        radial-gradient(
            circle at top,
            #11233c 0%,
            #07111f 42%,
            #030812 100%
        ) !important;
}

.gradio-container {
    max-width: 1180px !important;
    margin: auto !important;
    background: transparent !important;
}

.pg-hero {
    text-align: center;
    padding: 42px 15px 25px 15px;
}

.pg-badge {
    display: inline-block;
    padding: 7px 14px;
    border-radius: 999px;
    background: rgba(41,208,170,.12);
    border: 1px solid rgba(41,208,170,.35);
    color: #65e8c7;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.4px;
}

.pg-title {
    font-size: 48px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 18px;
    margin-bottom: 8px;
}

.pg-subtitle {
    color: #aab8cb;
    font-size: 18px;
    max-width: 760px;
    margin: auto;
    line-height: 1.6;
}

.scanner-panel {
    background: rgba(10,24,42,.88);
    border: 1px solid rgba(120,155,195,.20);
    border-radius: 20px;
    padding: 22px !important;
    box-shadow: 0 22px 60px rgba(0,0,0,.30);
}

.result-shell {
    margin-top: 22px;
}

.risk-card {
    border-radius: 18px;
    padding: 26px;
    margin-bottom: 18px;
    border: 1px solid rgba(255,255,255,.12);
}

.risk-low {
    background:
        linear-gradient(
            135deg,
            rgba(15,118,110,.32),
            rgba(6,78,59,.18)
        );
}

.risk-medium {
    background:
        linear-gradient(
            135deg,
            rgba(217,119,6,.32),
            rgba(120,53,15,.18)
        );
}

.risk-high,
.risk-critical {
    background:
        linear-gradient(
            135deg,
            rgba(220,38,38,.34),
            rgba(127,29,29,.20)
        );
}

.risk-small {
    color: #aab8cb;
    font-size: 11px;
    letter-spacing: 1.5px;
    font-weight: 700;
}

.risk-title {
    color: white;
    font-size: 30px;
    font-weight: 800;
    margin-top: 6px;
}

.risk-score {
    color: white;
    font-size: 18px;
    margin-top: 4px;
}

.target-url {
    color: #b8c5d8;
    margin-top: 12px;
    word-break: break-all;
}

.metric-grid {
    display: grid;
    grid-template-columns:
        repeat(4, minmax(0,1fr));
    gap: 14px;
}

.metric-card,
.analysis-card,
.recommendation-card,
.error-card {
    background: rgba(10,24,42,.90);
    border: 1px solid rgba(120,155,195,.18);
    border-radius: 16px;
    padding: 20px;
    color: white;
}

.metric-label {
    color: #8fa5bf;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
}

.metric-value {
    color: white;
    font-size: 30px;
    font-weight: 800;
    margin-top: 8px;
}

.metric-text {
    font-size: 19px;
}

.metric-note {
    color: #8295ac;
    font-size: 12px;
    margin-top: 5px;
}

.analysis-card,
.recommendation-card {
    margin-top: 14px;
}

.analysis-card h3,
.recommendation-card h3 {
    color: white;
}

.analysis-card li {
    margin-bottom: 8px;
    color: #c5d0df;
}

.detail-grid {
    display: grid;
    grid-template-columns:
        repeat(3, minmax(0,1fr));
    gap: 18px;
    color: #b7c5d6;
}

.recommendation-card {
    border-color:
        rgba(41,208,170,.28);
}

.recommendation-card p {
    color: #c7d4e3;
    line-height: 1.6;
}

.error-card {
    border-color:
        rgba(239,68,68,.45);
}

.pg-footer {
    text-align: center;
    color: #6f8299;
    font-size: 12px;
    padding: 28px 15px;
}

@media (max-width: 850px) {

    .metric-grid {
        grid-template-columns:
            repeat(2, minmax(0,1fr));
    }

    .detail-grid {
        grid-template-columns:
            repeat(2, minmax(0,1fr));
    }

    .pg-title {
        font-size: 37px;
    }
}

@media (max-width: 520px) {

    .metric-grid,
    .detail-grid {
        grid-template-columns: 1fr;
    }

    .pg-title {
        font-size: 31px;
    }
}
"""


# ==============================================================
# GRADIO APPLICATION
# ==============================================================

with gr.Blocks(
    css=CUSTOM_CSS,
    title="PhishingGuard"
) as phishingguard_ui:

    gr.HTML(
        """
        <div class="pg-hero">

            <div class="pg-badge">
                CNN DEEP LEARNING • CYBER THREAT INTELLIGENCE
            </div>

            <div class="pg-title">
                PhishingGuard
            </div>

            <div class="pg-subtitle">
                Know the risk before you click.
                Analyse a website using CNN-based Deep Learning,
                URL intelligence, TLS/network inspection and
                controlled live webpage security signals.
            </div>

        </div>
        """
    )

    with gr.Column(
        elem_classes=["scanner-panel"]
    ):

        url_input = gr.Textbox(
            label="Website URL",
            placeholder=(
                "Enter a domain or URL, "
                "for example: google.com"
            )
        )

        scan_button = gr.Button(
            "Analyse Website",
            variant="primary"
        )

    output = gr.HTML()

    scan_button.click(
        fn=build_dashboard,
        inputs=url_input,
        outputs=output
    )

    url_input.submit(
        fn=build_dashboard,
        inputs=url_input,
        outputs=output
    )

    gr.HTML(
        """
        <div class="pg-footer">

            PhishingGuard • MSc Cybersecurity Research Artefact

            <br><br>

            CNN Deep Learning scores are risk indicators,
            not calibrated probabilities.

            Results support security assessment and do not
            guarantee that a website is safe or malicious.

        </div>
        """
    )


# ==============================================================
# FASTAPI
# ==============================================================

app = FastAPI(
    title="PhishingGuard",
    version="2.0"
)


@app.get("/health")
def health():

    return JSONResponse({
        "status": "healthy",
        "service": "PhishingGuard",
        "version": "2.0",
        "cnn_model":
            "phishing_url_detector_v2.keras",
        "model_loaded": True,
        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    })


# Mount the Gradio interface at /
app = gr.mount_gradio_app(
    app,
    phishingguard_ui,
    path="/"
)


# ==============================================================
# LOCAL START
# ==============================================================

if __name__ == "__main__":

    import uvicorn

    port = int(
        os.environ.get(
            "PORT",
            "7860"
        )
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port
    )
