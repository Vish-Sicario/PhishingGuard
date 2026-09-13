"""Railway compatibility entrypoint.

Some deployment environments auto-discover ASGI applications as `main:app`.
This module safely re-exports the real FastAPI application from app.py so both
`main:app` and `app:app` start the same PhishingGuard service.
"""

from app import app

__all__ = ["app"]
