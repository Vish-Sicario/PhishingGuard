"""Railway compatibility entrypoint for the PhishingGuard v5 website.

Deployment environments may auto-discover ASGI applications as `main:app`.
This module deliberately exports the v5 site application so that Railway,
Docker and manual Uvicorn starts all serve the same frontend and scanner.
"""

from site import app

__all__ = ["app"]
