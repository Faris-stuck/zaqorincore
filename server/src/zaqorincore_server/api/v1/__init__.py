"""Public API routers, v1 namespace.

Each sub-module is a FastAPI APIRouter. The package is also re-
exported so main.py can `from .api import v1` and mount them all.
"""

from . import alerts, events, hosts, stream

__all__ = ["stream", "hosts", "events", "alerts"]
