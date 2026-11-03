# ============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
#
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
#
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
#
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
#
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
#
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ============================================================================
"""
Gün 36: Bellek, Sanal Bellek ve Swap Güvenlik Birim Testleri
Bu test paketi; şifresiz swap tespiti, bellek kazıma (Memory Scraping),
artık veri sızıntısı (Data Remanence), sayfa hataları ve negatif kontroller
dahil 14 kapsamlı test senaryosu içerir.
"""

# Dosya ve dizin yönetimi için os modülü
import os
# Sistem çalışma parametreleri için sys modülü
import sys
# Birim test çerçevesi için unittest modülü
import unittest
# JSON verilerini işlemek için json modülü
import json
# Geçici test dosyaları üretmek için tempfile modülü
import tempfile

# Test edilen modüle erişebilmek için proje ana dizinini ekliyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Gün 36 denetleyici sınıfını ve modellerini içe aktarıyoruz
from portfolio.hafta_06.gun_036.uygulama.memory_virtual_swap_auditor import (
    MemoryVirtualSwapAuditor,
    MemorySecurityFinding
)


class TestMemoryVirtualSwapAuditor(unittest.TestCase):
    """Bellek, sanal bellek ve swap denetleyicisinin 14 birim testi."""

    def setUp(self) -> None:
        """Her testten önce temiz bir denetleyici ve veri yolları hazırlar."""
        # Yeni denetleyici örneğini oluşturuyoruz
        self.auditor = MemoryVirtualSwapAuditor()
        # Temel dizini belirliyoruz
        self.base_dir = os.path.dirname(CURRENT_DIR)
        # Örnek telemetri dosyası yolu
        self.telemetry_path = os.path.join(self.base_dir, "ornek_veri", "sample_memory_telemetry.json")
        # Bozuk veri seti dosyası yolu
        self.corrupted_path = os.path.join(self.base_dir, "ornek_veri", "corrupted_memory_telemetry_test_cases.json")

    def test_01_init_state(self) -> None:
        """Denetleyicinin başlangıç durumunun boş ve temiz olduğunu doğrular."""
        # Başlangıçta telemetri verisi boş olmalıdır
        self.assertEqual(len(self.auditor.telemetry), 0)
        # Başlangıçta bulgu sayısı 0 olmalıdır
        self.assertEqual(len(self.auditor.findings), 0)
        # Bozuk kayıt sayısı 0 olmalıdır
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_02_load_valid_telemetry(self) -> None:
        """Geçerli bellek telemetri dosyasının başarıyla yüklendiğini test eder."""
        # Telemetriyi yüklüyoruz
        loaded = self.auditor.load_memory_telemetry(self.telemetry_path)
        self.assertTrue(loaded)
        # Zorunlu alanların varlığını sınıyoruz
        self.assertIn("system_memory", self.auditor.telemetry)
        self.assertIn("processes", self.auditor.telemetry)
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_03_detect_unencrypted_swap(self) -> None:
        """Şifrelenmemiş swap alanının (UNENCRYPTED_SWAP) HIGH olarak saptandığını test eder."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_swap_security()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("UNENCRYPTED_SWAP", types)
        target_f = next(f for f in findings if f.vulnerability_type == "UNENCRYPTED_SWAP")
        self.assertEqual(target_f.severity, "HIGH")

    def test_04_detect_pagefile_not_sanitized(self) -> None:
        """Kapanışta sayfa dosyası temizliğinin kapalı olduğunu MEDIUM olarak saptar."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_swap_security()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("PAGEFILE_NOT_SANITIZED", types)
        target_f = next(f for f in findings if f.vulnerability_type == "PAGEFILE_NOT_SANITIZED")
        self.assertEqual(target_f.severity, "MEDIUM")

    def test_05_detect_high_swap_usage(self) -> None:
        """Aşırı swap kullanımının (>%70) HIGH_SWAP_USAGE olarak saptandığını test eder."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_swap_security()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("HIGH_SWAP_USAGE", types)

    def test_06_detect_memory_scraping_attempt(self) -> None:
        """mem_scraper.exe sürecinin LSASS bellek dökümü girişimini CRITICAL olarak yakalar."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_process_memory_anomalies()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("MEMORY_SCRAPING_ATTEMPT", types)
        target_f = next(f for f in findings if f.vulnerability_type == "MEMORY_SCRAPING_ATTEMPT")
        self.assertEqual(target_f.severity, "CRITICAL")
        self.assertIn("T1003.001", target_f.mitre_technique)

    def test_07_detect_unlocked_sensitive_memory(self) -> None:
        """Kriptografik anahtar işleyen sürecin mlock yapmamasını HIGH olarak yakalar."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_process_memory_anomalies()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("UNLOCKED_SENSITIVE_MEMORY", types)
        target_f = next(f for f in findings if f.vulnerability_type == "UNLOCKED_SENSITIVE_MEMORY")
        self.assertEqual(target_f.severity, "HIGH")

    def test_08_detect_high_page_faults(self) -> None:
        """Olağan dışı yüksek sayfa hatası (Page Fault) üreten süreci yakalar."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_process_memory_anomalies()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("HIGH_PAGE_FAULTS", types)

    def test_09_detect_swap_credential_leak(self) -> None:
        """Swap dosyasındaki artık verilerden şifresiz kimlik bilgisi sızıntısını yakalar."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        findings = self.auditor.audit_swap_data_leakage()
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "CREDENTIAL_REMANENCE_LEAK")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_10_calculate_memory_risk_score(self) -> None:
        """Risk puanının ve duruş derecelendirmesinin doğruluğunu test eder."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        res = self.auditor.run_comprehensive_memory_audit()
        metrics = res["metrics"]
        self.assertGreaterEqual(metrics["risk_score"], 80)
        self.assertEqual(metrics["posture"], "CRITICAL_MEMORY_EXPOSURE")

    def test_11_clean_memory_baseline(self) -> None:
        """Tamamen temiz ve şifreli bir bellek ortamında riskin 0 olduğunu doğrular."""
        clean_auditor = MemoryVirtualSwapAuditor()
        clean_telemetry = {
            "system_memory": {
                "total_ram_mb": 16384,
                "used_ram_mb": 4096,
                "free_ram_mb": 12288,
                "total_swap_mb": 2048,
                "used_swap_mb": 100,
                "free_swap_mb": 1948,
                "swap_encrypted": True,
                "clear_pagefile_at_shutdown": True
            },
            "processes": [
                {"pid": 100, "name": "clean_app", "rss_mb": 128, "vms_mb": 256, "memory_locked": True, "page_faults": 100, "command_line": "clean_app"}
            ],
            "swap_artifacts": {"leaked_string_patterns": []}
        }
        clean_auditor.telemetry = clean_telemetry
        res = clean_auditor.run_comprehensive_memory_audit()
        self.assertEqual(res["metrics"]["risk_score"], 0)
        self.assertEqual(res["metrics"]["posture"], "SECURE_MEMORY_BASELINE")
        self.assertEqual(len(res["findings"]), 0)

    def test_12_negative_control_corrupted_telemetry(self) -> None:
        """Negatif kontrol: Bozuk şemalı ve negatif değerli bellek telemetrilerini güvenle reddeder."""
        with open(self.corrupted_path, "r", encoding="utf-8") as f:
            cases = json.load(f)

        for case in cases:
            sub = MemoryVirtualSwapAuditor()
            if isinstance(case, dict) and "invalid_data" in case:
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
                    json.dump(case["invalid_data"], tf)
                    temp_p = tf.name

                try:
                    loaded = sub.load_memory_telemetry(temp_p)
                    self.assertFalse(loaded)
                    self.assertGreaterEqual(len(sub.corrupted_records), 1)
                finally:
                    if os.path.exists(temp_p):
                        os.remove(temp_p)

    def test_13_ascii_report_generation(self) -> None:
        """ASCII denetim raporunun formatını ve bellek istatistiklerini eksiksiz ürettiğini test eder."""
        self.auditor.load_memory_telemetry(self.telemetry_path)
        self.auditor.run_comprehensive_memory_audit()
        report = self.auditor.generate_ascii_report()
        self.assertIn("GÜN 36: BELLEK, SANAL BELLEK VE SWAP GÜVENLİK DENETİM RAPORU", report)
        self.assertIn("Fiziksel RAM", report)
        self.assertIn("Takas Alanı (Swap)", report)
        self.assertIn("BELLEK RİSK PUANI", report)

    def test_14_custom_license_presence(self) -> None:
        """Özel lisans kuralı gereğince dosyalarda 'Özel Lisans - Tüm Hakları Saklıdır' ibaresini denetler."""
        app_file = os.path.join(self.base_dir, "uygulama", "memory_virtual_swap_auditor.py")
        with open(app_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", content)
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)", content)
        self.assertIn("YASAKLAR:", content)
        self.assertIn("YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ", content)


if __name__ == "__main__":
    unittest.main()
