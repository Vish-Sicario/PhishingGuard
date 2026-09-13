# PhishingGuard

PhishingGuard v4 is an MSc Cybersecurity research prototype for phishing-risk assessment. It combines a trained deep-learning URL classifier with explainable lexical URL intelligence and passive live checks such as HTTPS/TLS, redirects, DNS resolution, forms, links and suspicious page text.

## v4 highlights

- Redesigned responsive cybersecurity dashboard
- Four risk levels: Low, Medium, High and Critical
- Explainable URL indicators including length, subdomains, suspicious tokens, encoded characters, punycode, URL shorteners, digit/hyphen counts and URL entropy
- Passive live page analysis for redirects, forms, password/email fields, iframes, external form actions and suspicious wording
- TLS certificate and DNS information
- Combined risk indicator with a separate deep-learning score, URL-indicator score and live-context score
- Security recommendation and reason cards for each scan

## Important limitation

The deep-learning model was evaluated separately on the PhiUSIIL dataset. The live combined risk indicator is an experimental heuristic and is **not** a calibrated probability or a guarantee that a website is safe or malicious.

The scanner performs passive GET requests only. It does not submit forms, enter credentials, execute browser JavaScript, or intentionally download files.
