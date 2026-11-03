# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G082: pytest Yapılandırma ve Özel İşaretleyici (Marker) Tanımları
"""

# pytest konfigürasyon kancası için pytest kütüphanesini içeri aktarıyoruz.
import pytest


def pytest_configure(config: pytest.Config) -> None:
    """
    Güvenlik ve negatif test işaretleyicilerini pytest yapılandırmasına ekler.
    """
    # security işaretleyicisini kaydediyoruz.
    config.addinivalue_line("markers", "security: siber güvenlik politikası doğrulama testleri")
    # negative işaretleyicisini kaydediyoruz.
    config.addinivalue_line("markers", "negative: sınır aşımı ve kötü niyetli girdi negatif kontrolleri")
