# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G038: Zaman Senkronizasyonu ve NTP Denetçisi Birim Test Paketi (Unit Tests)

Bu modül, NtpTimeSyncAuditor sınıfının şema doğrulama, Kerberos 5 dakika saat kayması,
Stratum 16 senkronizasyon kaybı, monlist DDoS açıklığı, üst sunucu yedekliliği ve
dağıtık sistem zaman sapması kontrollerini 14 bağımsız test senaryosuyla denetler.
"""

# Standart Python birim test kütüphanesini içeri aktarıyoruz.
import unittest

# Dosya yolları ve dizin işlemleri için os modülünü kullanıyoruz.
import os

# JSON yüklerini ayrıştırmak için json kütüphanesini dahil ediyoruz.
import json

# Denetlenecek ana sınıfı ve özel hata sınıfını uygulama paketinden dahil ediyoruz.
from portfolio.hafta_06.gun_038.uygulama.ntp_time_sync_auditor import (
    # Denetim motorunu alıyoruz.
    NtpTimeSyncAuditor,
    # Özel doğrulama hatasını alıyoruz.
    NtpTelemetryValidationError
)


# Test sınıfımızı tanımlıyoruz.
class TestNtpTimeSyncAuditor(unittest.TestCase):
    """
    Zaman senkronizasyonu ve NTP denetçisi kapsamlı birim testleri.
    """

    # Her test öncesinde ortamı hazırlayan setUp metodu.
    def setUp(self) -> None:
        """
        Test ortamını hazırlar ve örnek telemetri verilerini yükler.
        """
        # Yeni bir denetçi nesnesi oluşturuyoruz.
        self.auditor = NtpTimeSyncAuditor()

        # Mevcut dosya dizinini alıyoruz.
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Geçerli örnek telemetri yolunu belirliyoruz.
        self.sample_telemetry_path = os.path.join(current_dir, "..", "ornek_veri", "sample_ntp_telemetry.json")
        # Bozuk test senaryolarının yolunu belirliyoruz.
        self.corrupted_telemetry_path = os.path.join(current_dir, "..", "ornek_veri", "corrupted_ntp_telemetry_test_cases.json")

        # Geçerli veriyi dosyadan okuyoruz.
        with open(self.sample_telemetry_path, "r", encoding="utf-8") as f:
            # JSON olarak belleğe yüklüyoruz.
            self.valid_telemetry = json.load(f)

    # 1. Test: Geçerli telemetri verisinin şema doğrulamasını hatasız geçmesi.
    def test_01_telemetry_schema_validation_success(self) -> None:
        """
        Geçerli telemetri verisinin şema doğrulamasından başarıyla geçtiğini doğrular.
        """
        # Doğrulamayı çağırıyoruz.
        res = self.auditor.validate_telemetry_schema(self.valid_telemetry)
        # Sonucun True olduğunu test ediyoruz.
        self.assertTrue(res, "Geçerli telemetri verisi şema doğrulamasından geçmelidir.")

    # 2. Test: 'systems' anahtarı bulunmadığında NtpTelemetryValidationError fırlatılması.
    def test_02_missing_systems_key_raises_validation_error(self) -> None:
        """
        'systems' anahtarı eksik olduğunda hata fırlatıldığını denetler.
        """
        # Eksik anahtarlı veri hazırlıyoruz.
        bad_data = {"audit_metadata": {"org": "No Systems"}}
        # Hata fırlatma beklentisini sınıyoruz.
        with self.assertRaises(NtpTelemetryValidationError) as ctx:
            # Doğrulamayı tetikliyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında systems geçtiğini kontrol ediyoruz.
        self.assertIn("systems", str(ctx.exception))

    # 3. Test: Geçersiz Stratum sınırlarında (negatif veya > 16) hata fırlatılması.
    def test_03_invalid_stratum_boundary_raises_error(self) -> None:
        """
        Stratum 1'den küçük veya 16'dan büyük olduğunda hata fırlatıldığını doğrular.
        """
        # Negatif stratum içeren veri oluşturuyoruz.
        bad_data = {
            "systems": [
                {"hostname": "h1", "stratum": -1, "offset_ms": 1.0, "jitter_ms": 0.5, "upstream_servers": []}
            ]
        }
        # Hata fırlatma kontrolü yapıyoruz.
        with self.assertRaises(NtpTelemetryValidationError) as ctx:
            # Fonksiyonu çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında stratum aralığı uyarısını sınıyoruz.
        self.assertIn("1 ile 16 arasında olmalıdır", str(ctx.exception))

    # 4. Test: Sayısal olmayan saat kayması (offset) değerinde hata fırlatılması.
    def test_04_non_numeric_offset_raises_validation_error(self) -> None:
        """
        offset_ms string veya None olduğunda hata fırlatıldığını doğrular.
        """
        # Bozuk offset değerli veri hazırlıyoruz.
        bad_data = {
            "systems": [
                {"hostname": "h1", "stratum": 2, "offset_ms": "gecersiz_deger", "jitter_ms": 0.5, "upstream_servers": []}
            ]
        }
        # Hata beklentisini test ediyoruz.
        with self.assertRaises(NtpTelemetryValidationError) as ctx:
            # Doğrulamayı çağırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında sayısal ibaresini sınıyoruz.
        self.assertIn("sayısal olmalıdır", str(ctx.exception))

    # 5. Test: Negatif jitter değerinde hata fırlatılması.
    def test_05_negative_jitter_raises_validation_error(self) -> None:
        """
        jitter_ms negatif olduğunda hata fırlatıldığını denetler.
        """
        # Negatif jitter değerli veri hazırlıyoruz.
        bad_data = {
            "systems": [
                {"hostname": "h1", "stratum": 2, "offset_ms": 1.0, "jitter_ms": -5.0, "upstream_servers": []}
            ]
        }
        # Hata beklentisini sınıyoruz.
        with self.assertRaises(NtpTelemetryValidationError) as ctx:
            # Fonksiyonu tetikliyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında negatif uyarısını sınıyoruz.
        self.assertIn("negatif olamaz", str(ctx.exception))

    # 6. Test: Hostname metin olmadığında hata fırlatılması.
    def test_06_non_string_hostname_raises_error(self) -> None:
        """
        hostname tamsayı veya liste olduğunda hata fırlatıldığını doğrular.
        """
        # Hatalı hostname veri nesnesi hazırlıyoruz.
        bad_data = {
            "systems": [
                {"hostname": 19216811, "stratum": 2, "offset_ms": 1.0, "jitter_ms": 0.5, "upstream_servers": []}
            ]
        }
        # Hata kontrolü yapıyoruz.
        with self.assertRaises(NtpTelemetryValidationError) as ctx:
            # Doğrulamayı çalıştırıyoruz.
            self.auditor.validate_telemetry_schema(bad_data)
        # Hata mesajında metin uyarısını sınıyoruz.
        self.assertIn("metin olmalıdır", str(ctx.exception))

    # 7. Test: Kerberos 5 dakika (300 saniye = 300,000 ms) eşiği aşıldığında CRITICAL bulgu üretilmesi.
    def test_07_kerberos_skew_threshold_exceeded_detected_as_critical(self) -> None:
        """
        Saat farkı 300 saniyeden fazla olduğunda Kerberos çöküşünün CRITICAL olarak raporlandığını doğrular.
        """
        # 345 saniyelik saat farkı içeren sistem kaydı hazırlıyoruz.
        systems = [
            {"hostname": "app01.dmz.internal", "offset_ms": 345000.0}
        ]
        # Saat kayması denetimini icra ediyoruz.
        findings = self.auditor.audit_clock_skew_and_authentication(systems)
        # En az bir bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem derecesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        # Başlıkta Kerberos kelimesinin geçtiğini sınıyoruz.
        self.assertIn("Kerberos", findings[0]["title"])

    # 8. Test: SIEM korelasyonunu bozan 1 saniye üzeri sapmanın HIGH olarak raporlanması.
    def test_08_siem_timeline_skew_detected_as_high(self) -> None:
        """
        1 saniye ile 5 dakika arasındaki sapmanın HIGH seviyesinde SIEM riski ürettiğini doğrular.
        """
        # 2500 ms (2.5 saniye) sapma verisi hazırlıyoruz.
        systems = [
            {"hostname": "db01.prod.internal", "offset_ms": 2500.0}
        ]
        # Denetimi icra ediyoruz.
        findings = self.auditor.audit_clock_skew_and_authentication(systems)
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem derecesinin HIGH olduğunu sınıyoruz.
        self.assertEqual(findings[0]["severity"], "HIGH")
        # Başlıkta Olay Korelasyonu ibaresinin geçtiğini denetliyoruz.
        self.assertIn("Olay Korelasyonu", findings[0]["title"])

    # 9. Test: Sağlıklı senkronize saatin (düşük sapma) temiz geçmesi.
    def test_09_healthy_synchronized_clock_passes_skew_clean(self) -> None:
        """
        2.1 ms gibi mikrosaniyelik sağlıklı saat kaymasının temiz geçtiğini doğrular.
        """
        # Sağlıklı sistem kaydı oluşturuyoruz.
        systems = [
            {"hostname": "dc01.corp.internal", "offset_ms": 2.1}
        ]
        # Denetimi çalıştırıyoruz.
        findings = self.auditor.audit_clock_skew_and_authentication(systems)
        # Hiçbir bulgu üretilmediğini test ediyoruz.
        self.assertEqual(len(findings), 0)

    # 10. Test: Stratum 16 veya senkronize olmayan sistemin CRITICAL olarak tespit edilmesi.
    def test_10_stratum_16_unsynchronized_detected_as_critical(self) -> None:
        """
        is_synchronized=False veya Stratum 16 durumunun CRITICAL bulgu ürettiğini doğrular.
        """
        # Eşzamanlama kaybı olan sistem kaydı hazırlıyoruz.
        systems = [
            {"hostname": "offline-node", "is_synchronized": False, "stratum": 16, "reference_peer": "none"}
        ]
        # Stratum denetimini çağırıyoruz.
        findings = self.auditor.audit_stratum_and_synchronization(systems)
        # En az bir bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem derecesinin CRITICAL olduğunu test ediyoruz.
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        # Açıklamada Stratum 16 kelimesinin geçtiğini doğruluyoruz.
        self.assertIn("Stratum 16", findings[0]["title"])

    # 11. Test: Yetersiz üst sunucu sayısının (SPOF riski) HIGH seviyesinde tespit edilmesi.
    def test_11_insufficient_upstream_servers_detected_as_high(self) -> None:
        """
        3'ten az üst sunucu tanımlandığında Byzantine hata toleransı eksikliğinin HIGH olarak raporlandığını doğrular.
        """
        # Yalnızca 1 sunuculu sistem kaydı hazırlıyoruz.
        systems = [
            {"hostname": "app01", "upstream_servers": ["192.168.1.1"]}
        ]
        # Yedeklilik denetimini icra ediyoruz.
        findings = self.auditor.audit_upstream_redundancy(systems)
        # 1 bulgu bekliyoruz.
        self.assertEqual(len(findings), 1)
        # Önem derecesinin HIGH olduğunu sınıyoruz.
        self.assertEqual(findings[0]["severity"], "HIGH")
        # Başlıkta Tek Hata Noktası geçtiğini sınıyoruz.
        self.assertIn("Tek Hata Noktası", findings[0]["title"])

    # 12. Test: NTP monlist açıklığının DDoS riski olarak HIGH raporlanması.
    def test_12_monlist_ddos_risk_detected_as_high(self) -> None:
        """
        monlist_enabled=True durumunda DDoS amplifikasyon riskinin HIGH olarak raporlandığını doğrular.
        """
        # monlist açık sistem kaydı oluşturuyoruz.
        systems = [
            {"hostname": "edge-router", "monlist_enabled": True, "nts_or_authenticated": True}
        ]
        # Protokol denetimini çağırıyoruz.
        findings = self.auditor.audit_protocol_security_and_dos(systems)
        # Bulgu sayısını sınıyoruz.
        monlist_findings = [f for f in findings if "monlist" in f["title"]]
        # En az 1 bulgu olmalıdır.
        self.assertEqual(len(monlist_findings), 1)
        # Önem derecesinin HIGH olduğunu test ediyoruz.
        self.assertEqual(monlist_findings[0]["severity"], "HIGH")

    # 13. Test: Bozuk test senaryoları paketindeki tüm girdilerin güvenle reddedilmesi.
    def test_13_corrupted_test_cases_suite_robustness(self) -> None:
        """
        corrupted_ntp_telemetry_test_cases.json dosyasındaki tüm girdilerin yakalandığını doğrular.
        """
        # Bozuk test senaryoları dosyasını okuyoruz.
        with open(self.corrupted_telemetry_path, "r", encoding="utf-8") as f:
            # JSON olarak yüklüyoruz.
            suite = json.load(f)

        # Tüm testleri döngüyle deniyoruz.
        for case in suite.get("test_cases", []):
            # Test adını alıyoruz.
            tname = case.get("test_name")
            # Gövdeyi alıyoruz.
            payload = case.get("payload")
            # İstisna beklentisini sınıyoruz.
            with self.assertRaises(NtpTelemetryValidationError, msg=f"Test '{tname}' hata fırlatmalıdır"):
                # Denetimi başlatıyoruz.
                self.auditor.execute_full_audit(payload)

    # 14. Test: Uçtan uca tam denetim akışı ve Markdown rapor çıktısı.
    def test_14_markdown_and_full_audit_workflow(self) -> None:
        """
        Tam denetim akışının ve Markdown rapor üretiminin hatasız çalıştığını doğrular.
        """
        # Geçerli telemetri üzerinde tam denetimi çalıştırıyoruz.
        result = self.auditor.execute_full_audit(self.valid_telemetry)
        # Sonucun sözlük olduğunu test ediyoruz.
        self.assertIsInstance(result, dict)
        # Güvenlik puanının 0 ile 100 arasında olduğunu kontrol ediyoruz.
        self.assertTrue(0 <= result["security_score"] <= 100)
        # Metrik tablosunun varlığını sınıyoruz.
        self.assertIn("metrics", result)

        # Markdown raporu üretiyoruz.
        report_md = self.auditor.export_markdown_report(result)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(report_md) > 0)
        # Lisans bildiriminin raporda geçtiğini test ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report_md)
        # Rapor başlığını sınıyoruz.
        self.assertIn("Zaman Senkronizasyonu ve NTP Güvenlik Denetim Raporu", report_md)


# Testler doğrudan icra edildiğinde unittest.main'i çalıştırıyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
