# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 141 - Yama Yönetimi ve CVE Birim Test Paketi.
15 kapsamlı birim testi ile CVE doğrulama, CVSS skorlama, CISA KEV aciliyeti,
SLA ihlalleri, yama hijyen puanı ve geri alma betiği üretimini titizlikle test eder.
"""

# Birim testleri için standart Python unittest kütüphanesi
import unittest
# Dosya yolları ve işletim sistemi fonksiyonları
import os
# Sistem çalışma yolu yönetimi
import sys
# JSON verisi manipülasyonu
import json
# Geçici dosya oluşturma
import tempfile

# Uygulama modülünü sys.path içerisine dahil et
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.abspath(os.path.join(current_dir, "..", "uygulama"))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

# Yama ve CVE motorunu import et
from patch_cve_engine import PatchCveEngine, CveRecord, PatchTriageResult, SystemPatchStatus


class TestPatchCveEngine(unittest.TestCase):
    """
    Yama Yönetimi ve CVE Değerlendirme Motoru test sınıfı.
    """

    def setUp(self):
        """
        Her birim testinden önce temiz referans envanterini hazırlar.
        """
        self.ref_inventory_path = os.path.abspath(
            os.path.join(current_dir, "..", "ornek_veri", "package_inventory_cve_spec.json")
        )
        self.engine = PatchCveEngine()
        if os.path.exists(self.ref_inventory_path):
            self.engine.load_inventory_from_file(self.ref_inventory_path)

    def test_01_load_inventory_success(self):
        """Test 01: Geçerli yama envanter dosyasının doğru şekilde yüklendiğini doğrular."""
        self.assertIsNotNone(self.engine.inventory)
        self.assertEqual(self.engine.inventory["system_info"]["hostname"], "srv-prod-app01.corp.internal")

    def test_02_load_inventory_missing_file(self):
        """Test 02: Mevcut olmayan bir dosya yüklendiğinde FileNotFoundError fırlatıldığını test eder."""
        dummy = PatchCveEngine()
        with self.assertRaises(FileNotFoundError):
            dummy.load_inventory_from_file("olmayan_envanter_dosyasi.json")

    def test_03_validate_cve_format_valid(self):
        """Test 03: Standart formattaki CVE kimliklerinin başarıyla ayrıştırıldığını doğrular."""
        records = self.engine.validate_and_parse_cves()
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].cve_id, "CVE-2024-6387")
        self.assertEqual(records[0].package_name, "openssh-server")

    def test_04_validate_cve_format_invalid_raises_error(self):
        """Test 04: Geçersiz formattaki CVE kimliğinde (örn: VULN-2024) ValueError fırlatıldığını doğrular."""
        self.engine.inventory["vulnerabilities"] = [{"cve_id": "VULN-2024-001", "cvss_score": 5.0, "epss_score": 0.1}]
        with self.assertRaises(ValueError) as ctx:
            self.engine.validate_and_parse_cves()
        self.assertIn("Geçersiz CVE kimliği biçimi", str(ctx.exception))

    def test_05_validate_cvss_score_range(self):
        """Test 05: CVSS taban skorunun 0.0 - 10.0 sınırları dışında olduğunda hata verdiğini doğrular."""
        self.engine.inventory["vulnerabilities"] = [{"cve_id": "CVE-2024-1234", "cvss_score": 12.5, "epss_score": 0.1}]
        with self.assertRaises(ValueError) as ctx:
            self.engine.validate_and_parse_cves()
        self.assertIn("Geçersiz CVSS skoru", str(ctx.exception))

    def test_06_calculate_severity_levels(self):
        """Test 06: CVSS puanlarına göre CRITICAL, HIGH, MEDIUM, LOW ve NONE seviyelerinin doğruluğunu test eder."""
        self.assertEqual(self.engine.calculate_severity(9.8), "CRITICAL")
        self.assertEqual(self.engine.calculate_severity(9.0), "CRITICAL")
        self.assertEqual(self.engine.calculate_severity(8.5), "HIGH")
        self.assertEqual(self.engine.calculate_severity(7.0), "HIGH")
        self.assertEqual(self.engine.calculate_severity(5.5), "MEDIUM")
        self.assertEqual(self.engine.calculate_severity(4.0), "MEDIUM")
        self.assertEqual(self.engine.calculate_severity(2.5), "LOW")
        self.assertEqual(self.engine.calculate_severity(0.0), "NONE")

    def test_07_determine_urgency_cisa_kev_emergency(self):
        """Test 07: CISA KEV listesinde olan zafiyetlerin doğrudan EMERGENCY ve 3 gün SLA aldığını doğrular."""
        cve = CveRecord(
            cve_id="CVE-2024-6387", package_name="openssh-server", installed_version="1.0",
            fixed_version="1.1", cvss_score=8.1, cvss_vector="CVSS:3.1/...", is_in_cisa_kev=True,
            epss_score=0.2
        )
        urgency, max_days = self.engine.determine_urgency(cve)
        self.assertEqual(urgency, "EMERGENCY")
        self.assertEqual(max_days, 3)

    def test_08_determine_urgency_high_epss_and_cvss(self):
        """Test 08: CVSS >= 9.0 ve EPSS >= 0.40 olduğunda KEV olmasa dahi EMERGENCY atandığını test eder."""
        cve = CveRecord(
            cve_id="CVE-2024-9999", package_name="libssl", installed_version="3.0",
            fixed_version="3.1", cvss_score=9.5, cvss_vector="CVSS:3.1/...", is_in_cisa_kev=False,
            epss_score=0.65
        )
        urgency, max_days = self.engine.determine_urgency(cve)
        self.assertEqual(urgency, "EMERGENCY")
        self.assertEqual(max_days, 3)

    def test_09_triage_vulnerabilities_debian_commands(self):
        """Test 09: Debian/Ubuntu ortamında oluşturulan yama ve geri alma komutlarını test eder."""
        triages = self.engine.triage_vulnerabilities(current_date_str="2026-11-02")
        self.assertTrue(len(triages) > 0)
        ssh_triage = next(t for t in triages if t.cve_id == "CVE-2024-6387")
        self.assertIn("apt-get install --only-upgrade", ssh_triage.remediation_command)
        self.assertIn("--allow-downgrades", ssh_triage.rollback_command)

    def test_10_triage_vulnerabilities_rhel_commands(self):
        """Test 10: RHEL/Rocky sistemlerinde dnf tabanlı yama ve geri alma komutları üretildiğini doğrular."""
        self.engine.inventory["system_info"]["os_family"] = "rhel"
        triages = self.engine.triage_vulnerabilities(current_date_str="2026-11-02")
        ssh_triage = next(t for t in triages if t.cve_id == "CVE-2024-6387")
        self.assertIn("dnf update-minimal --security", ssh_triage.remediation_command)
        self.assertIn("dnf downgrade", ssh_triage.rollback_command)

    def test_11_sla_breach_detection(self):
        """Test 11: Zafiyet yayınından bu yana geçen gün SLA süresini aştığında sla_breached=True olduğunu doğrular."""
        # 2026-11-20 tarihinde bakıldığında (19 gün geçmiş), CISA KEV (3 gün SLA) aşılmış olmalıdır
        triages = self.engine.triage_vulnerabilities(current_date_str="2026-11-20")
        ssh_triage = next(t for t in triages if t.cve_id == "CVE-2024-6387")
        self.assertTrue(ssh_triage.sla_breached)
        self.assertGreater(ssh_triage.elapsed_days, ssh_triage.max_sla_days)

    def test_12_patch_hygiene_score_calculation(self):
        """Test 12: Yama hijyen puanı hesaplamasında ceza puanlarının doğru uygulandığını doğrular."""
        # 2026-11-02 tarihinde, henüz SLA aşımı yok (elapsed 1 gün)
        status = self.engine.evaluate_system_patch_status(current_date_str="2026-11-02")
        # 2 adet EMERGENCY (CVE-2024-6387 ve CVE-2023-4863): 2 * -25 = -50
        # 0 kritik, 0 SLA aşımı, auto_updates: True, reboot_required: False
        # Beklenen puan: 100 - 50 = 50.0
        self.assertEqual(status.patch_hygiene_score, 50.0)
        self.assertEqual(status.emergency_count, 2)
        self.assertEqual(status.sla_breached_count, 0)

    def test_13_compliance_status_compliant_vs_non_compliant(self):
        """Test 13: Temiz bir sistemde COMPLIANT, ihmal edilmiş sistemde NON_COMPLIANT döndüğünü doğrular."""
        # Temiz sistem simülasyonu
        self.engine.inventory["vulnerabilities"] = []
        self.engine.inventory["patch_config_spec"]["auto_security_updates"] = True
        self.engine.inventory["patch_config_spec"]["reboot_required"] = False
        clean_status = self.engine.evaluate_system_patch_status()
        self.assertEqual(clean_status.compliance_status, "COMPLIANT")
        self.assertEqual(clean_status.patch_hygiene_score, 100.0)

        # İhmal edilmiş sistem simülasyonu
        self.engine.inventory["patch_config_spec"]["auto_security_updates"] = False
        self.engine.inventory["patch_config_spec"]["reboot_required"] = True
        self.engine.inventory["vulnerabilities"] = [
            {"cve_id": "CVE-2024-6387", "package_name": "openssh-server", "cvss_score": 9.8, "is_in_cisa_kev": True, "epss_score": 0.8, "published_date": "2026-09-01"}
        ]
        bad_status = self.engine.evaluate_system_patch_status(current_date_str="2026-11-02")
        self.assertEqual(bad_status.compliance_status, "NON_COMPLIANT")

    def test_14_generate_patch_execution_plan_script(self):
        """Test 14: Otomatik yama uygulama betiğinin üretildiğini ve aşamaları içerdiğini doğrular."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh") as tmp:
            tmp_path = tmp.name

        try:
            content = self.engine.generate_patch_execution_plan(output_path=tmp_path)
            self.assertIn("#!/usr/bin/env bash", content)
            self.assertIn("AŞAMA 1: ACİL VE KRİTİK GÜVENLİK YAMALARI", content)
            self.assertIn("unattended-upgrades", content)
            self.assertTrue(os.path.exists(tmp_path))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_15_generate_rollback_script(self):
        """Test 15: Acil durum geri alma betiğinin üretildiğini ve downgrade komutlarını içerdiğini doğrular."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh") as tmp:
            tmp_path = tmp.name

        try:
            content = self.engine.generate_rollback_script(output_path=tmp_path)
            self.assertIn("#!/usr/bin/env bash", content)
            self.assertIn("Geri Alma (Rollback)", content)
            self.assertIn("--allow-downgrades", content)
            self.assertTrue(os.path.exists(tmp_path))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
