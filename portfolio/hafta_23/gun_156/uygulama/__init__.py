# -*- coding: utf-8 -*-
"""OWASP Top 10 Haritası ve Web Zafiyet Değerlendirme Paketi."""

# Dışa aktarılan ana sınıflar ve fonksiyonlar
from .owasp_mapper_engine import (
    OwaspCategory,
    OwaspRiskLevel,
    VulnerabilityMapping,
    AppSecurityProfile,
    OwaspComplianceReport,
    OwaspMapperEngine,
)

# Paket sürümü
__version__ = "1.0.0"

# Dışa aktarma listesi
__all__ = [
    "OwaspCategory",
    "OwaspRiskLevel",
    "VulnerabilityMapping",
    "AppSecurityProfile",
    "OwaspComplianceReport",
    "OwaspMapperEngine",
]
