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
Gün 35: Mini Proje 4: Sistem Durum Kontrolü Birim Testleri
Bu test paketi; süreç hiyerarşisi, servis güvenliği, dosya bütünlüğü (FIM),
sihirli bayt uyumluluğu, sağlık puanlaması ve negatif kontroller dahil
14 kapsamlı test senaryosu içerir.
"""

# Standart dosya sistemi işlemleri için os modülü
import os
# Sistem çalışma yolları için sys modülü
import sys
# Birim test çerçevesi için unittest modülü
import unittest
# JSON veri doğrulama için json modülü
import json
# Geçici dosya işlemleri için tempfile modülü
import tempfile

# Test edilen modüle erişim için proje kök dizinini ekliyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Gün 35 denetleyici sınıfını ve modellerini içe aktarıyoruz
from portfolio.hafta_05.gun_035.uygulama.system_posture_auditor import (
    SystemPostureAuditor,
    PostureFinding
)


class TestSystemPostureAuditor(unittest.TestCase):
    """Mini Proje 4 Sistem Durum Denetleyicisinin 14 kapsamlı birim testi."""

    def setUp(self) -> None:
        """Her testten önce temiz bir denetleyici örneği ve yolları hazırlar."""
        # Yeni denetleyici örneği oluşturuyoruz
        self.auditor = SystemPostureAuditor()
        # Temel dizini belirliyoruz
        self.base_dir = os.path.dirname(CURRENT_DIR)
        # Örnek telemetri dosyası
        self.telemetry_path = os.path.join(self.base_dir, "ornek_veri", "system_telemetry_snapshot.json")
        # Bozuk telemetri test dosyası
        self.corrupted_path = os.path.join(self.base_dir, "ornek_veri", "corrupted_telemetry_test_cases.json")

    def test_01_init_state(self) -> None:
        """Denetleyicinin başlangıç durumunun boş ve temiz olduğunu doğrular."""
        # Başlangıçta telemetri verisi boş olmalıdır
        self.assertEqual(len(self.auditor.telemetry_data), 0)
        # Başlangıçta bulgu listesi boş olmalıdır
        self.assertEqual(len(self.auditor.findings), 0)
        # Bozuk kayıt listesi boş olmalıdır
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_02_load_valid_telemetry(self) -> None:
        """Geçerli telemetri anlık görüntüsünün başarıyla yüklendiğini test eder."""
        # Telemetriyi yüklüyoruz
        loaded = self.auditor.load_telemetry(self.telemetry_path)
        # Yüklemenin başarılı olduğunu sınıyoruz
        self.assertTrue(loaded)
        # Ana bölümlerin varlığını sınıyoruz
        self.assertIn("system_info", self.auditor.telemetry_data)
        self.assertIn("processes", self.auditor.telemetry_data)
        self.assertIn("services", self.auditor.telemetry_data)
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_03_audit_process_malicious_office_spawn(self) -> None:
        """winword.exe sürecinin powershell.exe başlatmasını CRITICAL olarak yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_process_telemetry()
        # Zafiyet türlerini topluyoruz
        types = [f.vulnerability_type for f in findings]
        self.assertIn("MALICIOUS_OFFICE_SPAWN", types)
        # İlgili bulgunun ciddiyetini sınıyoruz
        target_f = next(f for f in findings if f.vulnerability_type == "MALICIOUS_OFFICE_SPAWN")
        self.assertEqual(target_f.severity, "CRITICAL")
        self.assertIn("T1059.001", target_f.mitre_technique)

    def test_04_audit_process_masquerading(self) -> None:
        """svch0st.exe sürecinin taklit ve Temp dizininden çalışmasını yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_process_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("PROCESS_MASQUERADING", types)
        target_f = next(f for f in findings if f.vulnerability_type == "PROCESS_MASQUERADING")
        self.assertEqual(target_f.severity, "CRITICAL")
        self.assertIn("T1036", target_f.mitre_technique)

    def test_05_audit_service_tampering(self) -> None:
        """Durdurulmuş ve devre dışı bırakılmış güvenlik duvarını (MpsSvc) yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_service_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("SECURITY_SERVICE_TAMPERED", types)
        target_f = next(f for f in findings if f.vulnerability_type == "SECURITY_SERVICE_TAMPERED")
        self.assertEqual(target_f.severity, "CRITICAL")

    def test_06_audit_service_unquoted_path(self) -> None:
        """Boşluk içeren ve tırnaksız servis yolunu (CloudBackupSvc) HIGH olarak yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_service_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("UNQUOTED_SERVICE_PATH", types)
        target_f = next(f for f in findings if f.vulnerability_type == "UNQUOTED_SERVICE_PATH")
        self.assertEqual(target_f.severity, "HIGH")

    def test_07_audit_file_integrity_mismatch(self) -> None:
        """Değiştirilmiş konfigürasyon dosyasını (MISMATCH) CRITICAL olarak yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_file_integrity_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("INTEGRITY_VIOLATION", types)
        target_f = next(f for f in findings if f.vulnerability_type == "INTEGRITY_VIOLATION")
        self.assertEqual(target_f.severity, "CRITICAL")

    def test_08_audit_file_integrity_missing(self) -> None:
        """Taban çizgisinde olup diskte bulunamayan kayıp dosyayı (MISSING) yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_file_integrity_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("BASELINE_DISRUPTION", types)
        target_f = next(f for f in findings if f.vulnerability_type == "BASELINE_DISRUPTION")
        self.assertEqual(target_f.severity, "HIGH")

    def test_09_audit_file_signature_spoofing(self) -> None:
        """PDF uzantılı fakat MZ PE çalıştırılabilir başlıklı dosyayı CRITICAL olarak yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_file_signature_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("EXTENSION_SPOOFING", types)
        target_f = next(f for f in findings if f.vulnerability_type == "EXTENSION_SPOOFING")
        self.assertEqual(target_f.severity, "CRITICAL")

    def test_10_audit_file_signature_double_extension(self) -> None:
        """Çift uzantılı dosya hilesini (.pdf.exe) HIGH olarak yakalar."""
        self.auditor.load_telemetry(self.telemetry_path)
        findings = self.auditor.audit_file_signature_telemetry()
        types = [f.vulnerability_type for f in findings]
        self.assertIn("DOUBLE_EXTENSION_TROJAN", types)
        target_f = next(f for f in findings if f.vulnerability_type == "DOUBLE_EXTENSION_TROJAN")
        self.assertEqual(target_f.severity, "HIGH")

    def test_11_health_score_calculation(self) -> None:
        """Tüm zafiyetler tetiklendiğinde sağlık puanının kırıldığını ve duruşu doğrular."""
        self.auditor.load_telemetry(self.telemetry_path)
        res = self.auditor.run_full_posture_assessment()
        health = res["health_metrics"]
        # Çok sayıda kritik ihlal olduğundan puan düşmeli
        self.assertLess(health["health_score"], 40)
        self.assertEqual(health["posture"], "COMPROMISED_ENVIRONMENT")
        self.assertGreater(health["severity_counts"]["CRITICAL"], 0)

    def test_12_clean_healthy_posture(self) -> None:
        """Tamamen temiz bir telemetri anlık görüntüsünde sağlık puanının 100 olduğunu doğrular."""
        clean_auditor = SystemPostureAuditor()
        clean_telemetry = {
            "system_info": {"hostname": "CLEAN-HOST", "os_version": "Windows 11"},
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System", "executable_path": "C:\\Windows\\System32\\ntoskrnl.exe", "command_line": "System"}
            ],
            "services": [
                {"name": "WinDefend", "status": "Running", "start_mode": "Automatic", "binary_path": "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\""}
            ],
            "file_integrity": [
                {"file_path": "C:\\clean.cfg", "expected_sha256": "abc", "actual_sha256": "abc", "status": "MATCH"}
            ],
            "file_signatures": [
                {"file_name": "clean.pdf", "claimed_extension": ".pdf", "header_hex": "25 50 44 46", "detected_format": "PDF Document", "is_mismatch": False}
            ]
        }
        clean_auditor.telemetry_data = clean_telemetry
        res = clean_auditor.run_full_posture_assessment()
        self.assertEqual(res["health_metrics"]["health_score"], 100)
        self.assertEqual(res["health_metrics"]["posture"], "HEALTHY_BASELINE")
        self.assertEqual(len(res["findings"]), 0)

    def test_13_negative_control_corrupted_telemetry(self) -> None:
        """Negatif kontrol: Bozuk şemalı telemetri dosyalarının güvenle reddedildiğini test eder."""
        with open(self.corrupted_path, "r", encoding="utf-8") as f:
            corrupted_cases = json.load(f)

        for case in corrupted_cases:
            sub_auditor = SystemPostureAuditor()
            if isinstance(case, dict) and "invalid_data" in case:
                # Geçici dosyaya yazıp yüklemeyi deniyoruz
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
                    json.dump(case["invalid_data"], tf)
                    temp_p = tf.name

                try:
                    loaded = sub_auditor.load_telemetry(temp_p)
                    self.assertFalse(loaded)
                    self.assertGreaterEqual(len(sub_auditor.corrupted_records), 1)
                finally:
                    if os.path.exists(temp_p):
                        os.remove(temp_p)

    def test_14_custom_license_presence(self) -> None:
        """Özel lisans kuralı gereğince dosyalarda 'Özel Lisans - Tüm Hakları Saklıdır' ibaresini denetler."""
        app_file = os.path.join(self.base_dir, "uygulama", "system_posture_auditor.py")
        with open(app_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", content)
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)", content)
        self.assertIn("YASAKLAR:", content)
        self.assertIn("YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ", content)


if __name__ == "__main__":
    unittest.main()
