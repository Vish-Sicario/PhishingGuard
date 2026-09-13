# PhishingGuard

PhishingGuard is a research prototype for phishing-risk assessment. It combines a trained deep-learning URL classifier with passive live checks such as HTTPS/TLS, redirects, domain resolution, forms, links and suspicious page text.

## Important limitation

The deep-learning model was evaluated separately on the PhiUSIIL dataset. The live combined risk indicator is an experimental heuristic and is **not** a calibrated probability or a guarantee that a website is safe or malicious.

The scanner performs passive GET requests only. It does not submit forms, enter credentials, execute browser JavaScript, or intentionally download files.
