# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G081: Python Logging Modülü ve Güvenli SIEM Boru Hattı Test Paketi (14 Birim Test)
"""

# JSON ayrıştırma ve doğrulama için standart kütüphaneyi içeri aktarıyoruz.
import json
# Standart logging modülü LogRecord üretimi için içeri aktarılıyor.
import logging
# Birim test çerçevesi için Python standart unittest modülünü içeri aktarıyoruz.
import unittest

# Test edilecek filtre, formatlayıcı ve denetim yöneticisini içeri aktarıyoruz.
from portfolio.hafta_12.gun_081.uygulama.secure_logger_and_audit_engine import (
    JsonSecurityLogFormatter,
    SecureAuditLoggerManager,
    SecurityLogSanitizationFilter,
)


class TestSecureLoggerAndAuditEngine(unittest.TestCase):
    """
    Python logging filtreleme, maskeleme, JSON biçimlendirme ve SIEM boru hattı testleri.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde bağımsız filtre, formatlayıcı ve yönetici nesnelerini hazırlar.
        """
        # Temizleme filtresini 500 karakterlik kısa tavan ile başlatıyoruz.
        self.filter = SecurityLogSanitizationFilter(max_message_length=500)
        # JSON formatlayıcıyı başlatıyoruz.
        self.formatter = JsonSecurityLogFormatter()
        # Bağımsız bir test logger yöneticisi başlatıyoruz.
        self.audit_mgr = SecureAuditLoggerManager(logger_name="UnitTestAuditLogger", default_level="DEBUG")

    def _create_record(self, message: str) -> logging.LogRecord:
        """
        Testler için yardımcı standart LogRecord nesnesi üretir.
        """
        # Standart LogRecord örneği döndürüyoruz.
        return logging.LogRecord(
            name="TestLog",
            level=logging.INFO,
            pathname=__file__,
            lineno=42,
            msg=message,
            args=(),
            exc_info=None
        )

    def test_01_filter_crlf_log_injection_neutralization(self) -> None:
        """
        Log mesajındaki satır başı ve yeni satır karakterlerinin tek satıra indirgendiğini (CWE-117) sınar.
        """
        # CRLF enjeksiyonu içeren zararlı mesaj oluşturuyoruz.
        rec = self._create_record("Hata\r\n[AUDIT] 2026-11-01 Sahte yetkili işlem")
        # Filtreyi uyguluyoruz.
        self.filter.filter(rec)
        # Mesajda \r kalmadığını doğruluyoruz.
        self.assertNotIn("\r", rec.msg)
        # Mesajda \n kalmadığını doğruluyoruz.
        self.assertNotIn("\n", rec.msg)
        # Boşlukla ayrılmış tek satır olduğunu kontrol ediyoruz.
        self.assertEqual(rec.msg, "Hata [AUDIT] 2026-11-01 Sahte yetkili işlem")

    def test_02_filter_ansi_escape_code_removal(self) -> None:
        """
        ANSI terminal kaçış kodlarının mesajdan temizlendiğini test eder.
        """
        # Renk ve stil kaçış kodları içeren mesaj oluşturuyoruz.
        rec = self._create_record("\x1b[31;1mKRİTİK UYARI\x1b[0m Normal metin")
        # Filtreden geçiriyoruz.
        self.filter.filter(rec)
        # Kaçış kodu önekinin olmadığını sınıyoruz.
        self.assertNotIn("\x1b", rec.msg)
        # Düz metnin korunduğunu teyit ediyoruz.
        self.assertIn("KRİTİK UYARI", rec.msg)

    def test_03_filter_secret_credential_redaction(self) -> None:
        """
        Parola ve API anahtarı parametrelerinin [REDACTED] ile maskelendiğini (CWE-532) doğrular.
        """
        # Parola ve secret içeren log oluşturuyoruz.
        rec = self._create_record("Baglanti: user=admin password=GizliSifre99! api_key=sk_live_abc123")
        # Filtreyi uyguluyoruz.
        self.filter.filter(rec)
        # Açık parolanın silindiğini sınıyoruz.
        self.assertNotIn("GizliSifre99!", rec.msg)
        # Açık API anahtarının silindiğini sınıyoruz.
        self.assertNotIn("sk_live_abc123", rec.msg)
        # Maskeleme etiketinin yerleştiğini doğruluyoruz.
        self.assertIn("password=[REDACTED]", rec.msg)

    def test_04_filter_bearer_jwt_token_redaction(self) -> None:
        """
        Authorization başlığındaki Bearer JWT belirtecinin maskelendiğini (CWE-359) sınar.
        """
        # JWT belirteci içeren log kaydı oluşturuyoruz.
        rec = self._create_record("Header: Bearer eyJhbGciOiJIUzI1Ni.eyJzdWIiOiIxMjM0In0.SflKxwRJJSMeKKF2QT4f")
        # Filtreyi uyguluyoruz.
        self.filter.filter(rec)
        # Açık imza dizesinin silindiğini kontrol ediyoruz.
        self.assertNotIn("SflKxwRJJSMeKKF2QT4f", rec.msg)
        # Maskelenmiş JWT etiketini sınıyoruz.
        self.assertIn("Bearer [REDACTED_JWT]", rec.msg)

    def test_05_filter_credit_card_masking(self) -> None:
        """
        16 haneli kredi kartı numarasının son 4 hane hariç maskelendiğini doğrular.
        """
        # Kredi kartı içeren log kaydı oluşturuyoruz.
        rec = self._create_record("Kart bilgisi: 4532-1122-3344-9988 işlemde kullanıldı")
        # Filtreyi uyguluyoruz.
        self.filter.filter(rec)
        # İlk hanelerin maskelendiğini sınıyoruz.
        self.assertNotIn("4532-1122", rec.msg)
        # Son 4 hanenin görünür kaldığını teyit ediyoruz.
        self.assertIn("****-****-****-9988", rec.msg)

    def test_06_filter_null_byte_replacement(self) -> None:
        """
        Mesaj içindeki null-byte (\x00) karakterinin temizlendiğini test eder.
        """
        # Null byte barındıran kayıt üretiyoruz.
        rec = self._create_record("Kullanici: admin\x00.evil.com oturum açtı")
        # Filtreyi çalıştırıyoruz.
        self.filter.filter(rec)
        # Null byte kalmadığını kontrol ediyoruz.
        self.assertNotIn("\x00", rec.msg)

    def test_07_filter_oversized_message_truncation(self) -> None:
        """
        Azami tavan uzunluğu aşan devasa log mesajının kesildiğini (DoS koruması) doğrular.
        """
        # 500 karakter sınırını aşan 800 karakterlik mesaj üretiyoruz.
        rec = self._create_record("A" * 800)
        # Filtreden geçiriyoruz.
        self.filter.filter(rec)
        # Mesaj uzunluğunun sınırlandığını kontrol ediyoruz.
        self.assertTrue(len(rec.msg) < 600)
        # Kısaltma etiketinin eklendiğini teyit ediyoruz.
        self.assertTrue(rec.msg.endswith("...[TRUNCATED]"))

    def test_08_json_formatter_produces_valid_json(self) -> None:
        """
        JsonSecurityLogFormatter nesnesinin geçerli ve standart alanlara sahip JSON ürettiğini doğrular.
        """
        # Örnek kayıt oluşturuyoruz.
        rec = self._create_record("Standart operasyon log mesajı")
        # JSON formatına çeviriyoruz.
        json_output = self.formatter.format(rec)
        # Çıktının geçerli JSON olduğunu sınıyoruz.
        parsed = json.loads(json_output)
        # Timestamp alanının varlığını teyit ediyoruz.
        self.assertIn("timestamp", parsed)
        # Level alanının INFO olduğunu kontrol ediyoruz.
        self.assertEqual(parsed["level"], "INFO")
        # Message alanının içeriğini kontrol ediyoruz.
        self.assertEqual(parsed["message"], "Standart operasyon log mesajı")

    def test_09_json_formatter_includes_context(self) -> None:
        """
        JSON formatlayıcının extra={'context': ...} bağlam bilgilerini doğru paketlediğini test eder.
        """
        # Kayıt oluşturuyoruz.
        rec = self._create_record("Bağlamlı olay kaydı")
        # Kayda özel bağlam ekliyoruz.
        rec.context = {"ip": "10.0.0.99", "action": "LOGIN_ATTEMPT"}
        # Formatlıyoruz.
        output = self.formatter.format(rec)
        # JSON olarak açıyoruz.
        parsed = json.loads(output)
        # Bağlam içindeki IP'yi kontrol ediyoruz.
        self.assertEqual(parsed["context"]["ip"], "10.0.0.99")
        # Eylemi kontrol ediyoruz.
        self.assertEqual(parsed["context"]["action"], "LOGIN_ATTEMPT")

    def test_10_json_formatter_handles_unserializable_context_fallback(self) -> None:
        """
        Serileştirilemeyen bağlam nesnesi durumunda formatlayıcının güvenli yedek ürettiğini doğrular.
        """
        # Kayıt oluşturuyoruz.
        rec = self._create_record("Bozuk bağlam testi")
        # Döngüsel referans üreten sözlük hazırlıyoruz.
        circular = {}
        # Kendine referans veriyoruz.
        circular["self"] = circular
        # Kayda atıyoruz.
        rec.context = circular
        # Formatlayıcıyı çalıştırıyoruz (çökmemeli).
        output = self.formatter.format(rec)
        # JSON olarak parse edilebildiğini sınıyoruz.
        parsed = json.loads(output)
        # Hata alanının varlığını teyit ediyoruz.
        self.assertIn("error", parsed)

    def test_11_manager_log_event_records_to_stream(self) -> None:
        """
        SecureAuditLoggerManager nesnesinin log_event ile kaydı bellek akışına yazdığını doğrular.
        """
        # Olay kaydediyoruz.
        res = self.audit_mgr.log_event("INFO", "Sistem başlatıldı.", context={"node": "worker-1"})
        # Çıktı sözlüğünü kontrol ediyoruz.
        self.assertEqual(res["level"], "INFO")
        # Mesajı kontrol ediyoruz.
        self.assertEqual(res["message"], "Sistem başlatıldı.")

    def test_12_manager_invalid_level_falls_back_to_warning(self) -> None:
        """
        Tanımlanmamış geçersiz bir seviye verildiğinde varsayılan WARNING seviyesinin kullanıldığını sınar.
        """
        # Geçersiz seviye ile loglama yapıyoruz.
        res = self.audit_mgr.log_event("GEÇERSİZ_SEVİYE_X", "Güvenlik uyarısı")
        # Seviyenin WARNING'e düştüğünü teyit ediyoruz.
        self.assertEqual(res["level"], "WARNING")

    def test_13_manager_log_security_alert_critical(self) -> None:
        """
        log_security_alert metodunun kritik alarm formatında JSON kaydı ürettiğini test eder.
        """
        # Kritik alarm kaydediyoruz.
        alert = self.audit_mgr.log_security_alert(
            rule_name="BRUTE_FORCE_BLOCKED",
            source_ip="198.51.100.99",
            severity="CRITICAL",
            details="5 ardışık hatalı giriş sonrası kilit uygulandı."
        )
        # Seviyenin CRITICAL olduğunu teyit ediyoruz.
        self.assertEqual(alert["level"], "CRITICAL")
        # Kural adının mesajda geçtiğini kontrol ediyoruz.
        self.assertIn("BRUTE_FORCE_BLOCKED", alert["message"])
        # Bağlamdaki IP'yi sınıyoruz.
        self.assertEqual(alert["context"]["source_ip"], "198.51.100.99")

    def test_14_manager_isolated_logger_does_not_propagate(self) -> None:
        """
        Logger nesnesinin propagate=False ile kök logger'a kirlilik yaymadığını doğrular.
        """
        # Propagate bayrağının False olduğunu teyit ediyoruz.
        self.assertFalse(self.audit_mgr.logger.propagate)


# Testler doğrudan çağrıldığında çalıştırılmasını sağlıyoruz.
if __name__ == "__main__":
    # Testleri ayrıntılı modda yürütüyoruz.
    unittest.main()
