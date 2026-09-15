# PhishingGuard V2

MSc Cybersecurity research artefact for phishing risk analysis.

## Detection Layers

1. CNN Deep Learning URL analysis
2. URL structure intelligence
3. DNS and TLS/network analysis
4. Controlled live webpage analysis
5. Explainable combined risk assessment

## CNN Model

Model file: phishing_url_detector_v2.keras

The CNN output is presented as a Deep Learning risk score,
not as a calibrated probability.

## Health Check

GET /health

## Security

The application includes controls for private/local targets,
unsupported schemes, unsafe ports, redirect validation,
timeouts and bounded webpage downloads.

These controls reduce SSRF exposure but do not establish
complete SSRF immunity in an unrestricted environment.

## Disclaimer

PhishingGuard is a cybersecurity research artefact.
Its output does not guarantee that a website is safe or malicious.
