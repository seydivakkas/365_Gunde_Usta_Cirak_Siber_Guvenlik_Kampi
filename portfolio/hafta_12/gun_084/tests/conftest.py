# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G084: pytest fixtures ve konfigürasyon modülü (conftest.py).
Bu dosya, güvenlik log aracı testleri için izole test ortamları, sahte log dosyaları
ve denetim motoru örnekleri hazırlayan yeniden kullanılabilir fikstürleri tanımlar.
"""

import json  # JSON veri yuklemek icin json modulu ice aktarilir
from pathlib import Path  # Dosya sistemi yollari icin Path modulu ice aktarilir
import pytest  # pytest cercevesi ice aktarilir

from portfolio.hafta_12.gun_084.uygulama.tested_security_log_tool import TestedSecurityLogTool  # Test edilecek arac


def pytest_configure(config: pytest.Config) -> None:
    """Özel pytest işaretçilerini (markers) kaydeder."""
    config.addinivalue_line("markers", "security: Güvenlik zaafiyeti ve siber saldırı testleri")  # Security işareti
    config.addinivalue_line("markers", "negative: Negatif ve istisnai durum testleri")  # Negative işareti


@pytest.fixture
def base_test_dir() -> Path:
    """G084 kok dizinini donduren fikstur."""
    return Path(__file__).resolve().parent.parent  # G084 ana dizini dondurulur


@pytest.fixture
def sample_jsonl_path(base_test_dir: Path) -> Path:
    """Ornek raw_access_logs.jsonl dosyasinin yolunu donduren fikstur."""
    return base_test_dir / "ornek_veri" / "raw_access_logs.jsonl"  # Ornek log dosya yolu


@pytest.fixture
def invalid_inputs_data(base_test_dir: Path) -> dict:
    """Negatif test senaryolarini iceren JSON verisini yukleyen fikstur."""
    veri_dosyasi = base_test_dir / "ornek_veri" / "invalid_log_tool_inputs.json"  # Yol
    with open(veri_dosyasi, "r", encoding="utf-8") as f:  # Dosya acilir
        return json.load(f)  # Veri sozluk olarak dondurulur


@pytest.fixture
def log_tool(base_test_dir: Path) -> TestedSecurityLogTool:
    """Temel guvenli dizinle yapilandirilmis TestedSecurityLogTool ornegi saglar."""
    return TestedSecurityLogTool(allowed_base_dir=base_test_dir, brute_force_threshold=3)  # Arac ornegi
