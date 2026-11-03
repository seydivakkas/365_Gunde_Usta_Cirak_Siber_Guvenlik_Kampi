# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 091: Mini Proje 12 — Çok Platformlu Sistem Raporlayıcı Birim Test Paketi.

Bu test modülü; Windows ve Linux sistem telemetrilerinin doğrulanmasını,
CWE güvenlik zafiyetlerinin tespitini, dizin atlama kalkanlarını ve çoklu format
(text, json, html) çıktı üretimini 14 kapsamlı senaryoyla denetler.
"""

# Standart test çerçevesi ve sistem kütüphaneleri
import unittest
import sys
import os
import json

# Uygulama modülünü arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Raporlayıcı motorunu ve istisnaları içe aktar
from cross_platform_security_reporter import (
    CrossPlatformSecurityReporter,
    ReporterSecurityError,
    UnsupportedPlatformError,
    UnsupportedFormatError,
    PathTraversalError,
    MalformedTelemetryError,
    MissingRequiredFieldError,
    NaiveTimestampTelemetryError,
    PayloadTooLargeError,
    SensitiveDataExposureError,
    SystemReport
)

class TestCrossPlatformSecurityReporter(unittest.TestCase):
    """Çok platformlu sistem güvenlik raporlayıcı test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz raporlayıcı nesnesi oluşturur."""
        self.reporter = CrossPlatformSecurityReporter()
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        # Örnek Windows telemetrisini yükle
        win_path = os.path.join(self.base_dir, "ornek_veri", "sample_windows_telemetry.json")
        with open(win_path, "r", encoding="utf-8") as f:
            self.sample_windows = json.load(f)

        # Örnek Linux telemetrisini yükle
        lnx_path = os.path.join(self.base_dir, "ornek_veri", "sample_linux_telemetry.json")
        with open(lnx_path, "r", encoding="utf-8") as f:
            self.sample_linux = json.load(f)

    def test_01_validate_valid_windows_telemetry(self) -> None:
        """1. Test: Geçerli Windows telemetri verisinin doğrulanması."""
        val = self.reporter.validate_telemetry_payload(self.sample_windows)
        self.assertEqual(val["platform"], "windows")
        self.assertEqual(val["hostname"], "WIN-SRV-SEC-01")

    def test_02_validate_valid_linux_telemetry(self) -> None:
        """2. Test: Geçerli Linux telemetri verisinin doğrulanması."""
        val = self.reporter.validate_telemetry_payload(self.sample_linux)
        self.assertEqual(val["platform"], "linux")
        self.assertEqual(val["hostname"], "LNX-PROD-WEB-02")

    def test_03_reject_unsupported_platform(self) -> None:
        """3. Test: Desteklenmeyen işletim sistemi platformunun reddedilmesi (CWE-20)."""
        gecersiz_veri = {"platform": "bsd_unix", "hostname": "SRV-BSD", "zaman_damgasi_utc": "2026-11-01T20:00:00Z"}
        with self.assertRaises(UnsupportedPlatformError):
            self.reporter.validate_telemetry_payload(gecersiz_veri)

    def test_04_reject_empty_or_malformed_telemetry(self) -> None:
        """4. Test: Boş veya bozuk JSON telemetrisinin reddedilmesi."""
        with self.assertRaises(MalformedTelemetryError):
            self.reporter.validate_telemetry_payload("")
        with self.assertRaises(MalformedTelemetryError):
            self.reporter.validate_telemetry_payload("{invalid_json:}")

    def test_05_reject_missing_required_fields(self) -> None:
        """5. Test: Zorunlu alanları (hostname veya zaman) eksik telemetrinin engellenmesi."""
        eksik_veri = {"platform": "windows"}
        with self.assertRaises(MissingRequiredFieldError):
            self.reporter.validate_telemetry_payload(eksik_veri)

    def test_06_reject_naive_timestamp(self) -> None:
        """6. Test: Saat dilimi içermeyen naive telemetri zaman damgasının engellenmesi (CWE-613)."""
        naive_veri = {"platform": "windows", "hostname": "SRV-1", "zaman_damgasi_utc": "2026-11-01 20:00:00"}
        with self.assertRaises(NaiveTimestampTelemetryError):
            self.reporter.validate_telemetry_payload(naive_veri)

    def test_07_reject_sensitive_leak_in_stderr(self) -> None:
        """7. Test: Stderr akışında açık şifre veya kimlik bilgisi sızıntısının tespiti (CWE-532)."""
        leak_veri = {
            "platform": "windows",
            "hostname": "SRV-1",
            "zaman_damgasi_utc": "2026-11-01T20:00:00Z",
            "stderr_gunlukleri": "Veritabani hatasi: password=GizliParola123!"
        }
        with self.assertRaises(SensitiveDataExposureError):
            self.reporter.validate_telemetry_payload(leak_veri)

    def test_08_path_traversal_prevention(self) -> None:
        """8. Test: Çıktı dosya yolunda dizin atlama ('..') girişimlerinin engellenmesi (CWE-22)."""
        saldirgan_yol = "../../etc/shadow_report.txt"
        with self.assertRaises(PathTraversalError):
            self.reporter.validate_output_path(saldirgan_yol, izin_verilen_kok_dizin=".")

    def test_09_audit_windows_findings(self) -> None:
        """9. Test: Windows telemetrisinde SMB (445), RDP (3389), Güvenlik Duvarı ve Madenci tespiti."""
        rapor = self.reporter.audit_telemetry(self.sample_windows, deep_scan=False)
        bulgu_idler = [b.bulgu_id for b in rapor.bulgular]
        
        # Bulgu kimliklerini doğrula
        self.assertIn("SEC_PORT_445", bulgu_idler)
        self.assertIn("SEC_PORT_3389", bulgu_idler)
        self.assertIn("WIN_FW_PUBLIC_OFF", bulgu_idler)
        self.assertIn("WIN_MALICIOUS_SVC", bulgu_idler)
        # Güvenlik puanının ciddi şekilde düştüğünü doğrula
        self.assertLess(rapor.guvenlik_skoru, 50)
        self.assertEqual(rapor.guvenlik_durumu, "KRİTİK")

    def test_10_audit_windows_deep_scan(self) -> None:
        """10. Test: Windows derin taramada eksik güvenlik yamalarının (KB5034441) tespiti."""
        rapor_deep = self.reporter.audit_telemetry(self.sample_windows, deep_scan=True)
        bulgu_idler = [b.bulgu_id for b in rapor_deep.bulgular]
        self.assertIn("WIN_PATCH_KB5034441", bulgu_idler)

    def test_11_audit_linux_findings(self) -> None:
        """11. Test: Linux telemetrisinde /etc/shadow 0644 izin ve NOPASSWD sudo açığının tespiti."""
        rapor = self.reporter.audit_telemetry(self.sample_linux, deep_scan=False)
        bulgu_idler = [b.bulgu_id for b in rapor.bulgular]
        
        self.assertIn("SEC_PORT_6379", bulgu_idler)
        self.assertIn("LNX_PERM_SHADOW", bulgu_idler)
        self.assertIn("LNX_SUDO_NOPASSWD", bulgu_idler)
        self.assertLessEqual(rapor.guvenlik_skoru, 30)

    def test_12_format_text_output(self) -> None:
        """12. Test: Raporun yapısal metin (text) formatında üretilmesi."""
        rapor = self.reporter.audit_telemetry(self.sample_windows)
        text_out = self.reporter.format_report(rapor, format_tipi="text")
        self.assertIn("SİSTEM GÜVENLİK VE UYUMLULUK DENETİM RAPORU", text_out)
        self.assertIn("WIN-SRV-SEC-01", text_out)
        self.assertIn("Güvenlik Skoru:", text_out)

    def test_13_format_json_output(self) -> None:
        """13. Test: Raporun standart JSON formatında üretilmesi ve ayrıştırılması."""
        rapor = self.reporter.audit_telemetry(self.sample_linux)
        json_out = self.reporter.format_report(rapor, format_tipi="json")
        parsed = json.loads(json_out)
        self.assertEqual(parsed["hostname"], "LNX-PROD-WEB-02")
        self.assertEqual(parsed["platform"], "linux")
        self.assertTrue(len(parsed["bulgular"]) > 0)

    def test_14_format_html_output(self) -> None:
        """14. Test: Raporun geçerli HTML formatında üretilmesi."""
        rapor = self.reporter.audit_telemetry(self.sample_windows)
        html_out = self.reporter.format_report(rapor, format_tipi="html")
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("Sistem Güvenlik Raporu", html_out)
        self.assertIn("WIN-SRV-SEC-01", html_out)

if __name__ == "__main__":
    unittest.main()
