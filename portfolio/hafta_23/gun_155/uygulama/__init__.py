# -*- coding: utf-8 -*-
"""Web Uygulama Mimarisi ve Güven Sınırı (Web Architecture & Trust Boundaries) Paketi."""

# Dışa aktarılan ana sınıflar ve tipler
from .web_architecture_engine import (
    HttpRequest,
    HttpResponse,
    CookieSpec,
    TrustBoundaryViolation,
    SecurityHeaderAudit,
    CookieSecurityAudit,
    WebTrustBoundaryEngine,
    ViolationSeverity,
)

# Paket sürümü
__version__ = "1.0.0"

# Dışa aktarma listesi
__all__ = [
    "HttpRequest",
    "HttpResponse",
    "CookieSpec",
    "TrustBoundaryViolation",
    "SecurityHeaderAudit",
    "CookieSecurityAudit",
    "WebTrustBoundaryEngine",
    "ViolationSeverity",
]
