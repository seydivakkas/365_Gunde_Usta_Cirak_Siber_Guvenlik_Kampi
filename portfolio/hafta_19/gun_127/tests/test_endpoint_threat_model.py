# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 127 BİRİM TESTLERİ (Uç Nokta Tehdit Modeli Motoru)
------------------------------------------------------
Bu test paketi; uç nokta saldırı yüzeylerinin analizini, CWE/MITRE
eşleşmelerini, rol bazlı risk katsayılarını ve sıkılaştırma yol haritası
üretimini 15 kapsamlı test ile doğrular.
"""

# İşletim sistemi fonksiyonları için os modülü
import os
# Sistem arama yolu kontrolü için sys modülü
import sys
# Birim test çatısı için unittest modülü
import unittest

# Uygulama modülünü arama yoluna dahil ediyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama klasörünün yolunu hesaplıyoruz
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Arama yolunun başına ekliyoruz
sys.path.insert(0, app_dir)

# Test edilecek motor sınıflarını içe aktarıyoruz
from endpoint_threat_model_engine import (
    EndpointThreatModelEngine,
    OperatingSystemFamily,
    EndpointRole,
    EndpointControlStatus,
    ThreatSeverity,
    AttackSurfaceArea
)


class TestEndpointThreatModelEngine(unittest.TestCase):
    """Uç Nokta Tehdit Modeli Motoru Test Sınıfı."""

    def setUp(self):
        """Her testten önce standart motor nesnesini kurar."""
        # Motoru başlatıyoruz
        self.engine = EndpointThreatModelEngine("Test Motoru")

    def test_01_fully_hardened_endpoint_scores_low_threat(self):
        """Tüm güvenlik kontrolleri tam olan bir sistemde tehdit skoru sıfır olmalı ve GÜVENLİ dönmelidir."""
        # Kusursuz kontrolleri kuruyoruz
        controls = EndpointControlStatus(
            edr_active=True,
            tamper_protection_active=True,
            telemetry_active=True,
            credential_guard_active=True,
            disk_encryption_active=True,
            strict_uac_active=True,
            app_whitelisting_active=True,
            powershell_clm_active=True,
            unquoted_service_paths_count=0,
            suid_misconfigurations_count=0,
            insecure_open_ports=[],
            weak_registry_autoruns_count=0
        )
        # Analizi yürütüyoruz
        report = self.engine.model_endpoint_threats(
            "Hardened-Workstation",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Tehdit skorunun 0 olduğunu doğruluyoruz
        self.assertEqual(report.threat_index_score, 0.0)
        # Güvenlik duruşunun PASS/GÜVENLİ olduğunu doğruluyoruz
        self.assertIn("GÜVENLİ", report.security_posture_level)
        # Bulgu sayısının sıfır olduğunu doğruluyoruz
        self.assertEqual(len(report.findings), 0)

    def test_02_missing_credential_guard_detected_on_windows(self):
        """Windows sistemde LSA koruması eksikliği CWE-311 ve MITRE T1003.001 ile yakalanmalıdır."""
        # LSA protection kapalı kontroller
        controls = EndpointControlStatus(
            edr_active=True,
            tamper_protection_active=True,
            telemetry_active=True,
            credential_guard_active=False
        )
        # Windows iş istasyonu analizi
        report = self.engine.model_endpoint_threats(
            "Win11-Client",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Bulgular arasında CWE-311 arıyoruz
        cwe_list = [f.cwe_id for f in report.findings]
        self.assertIn("CWE-311", cwe_list)
        # MITRE tekniğini doğruluyoruz
        mitre_list = [f.mitre_technique_id for f in report.findings]
        self.assertTrue(any("T1003.001" in m for m in mitre_list))

    def test_03_domain_controller_escalates_credential_guard_to_critical(self):
        """Domain Controller rolünde Credential Guard eksikliği CRITICAL ciddiyet almalıdır."""
        # Credential Guard kapalı kontroller
        controls = EndpointControlStatus(
            edr_active=True,
            tamper_protection_active=True,
            telemetry_active=True,
            credential_guard_active=False
        )
        # Domain Controller analizi
        report = self.engine.model_endpoint_threats(
            "DC-Primary",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.DOMAIN_CONTROLLER,
            controls
        )
        # İlgili bulguyu alıyoruz
        cred_finding = next(f for f in report.findings if f.surface_area == AttackSurfaceArea.AUTHENTICATION_CREDENTIALS)
        # Ciddiyetin CRITICAL olduğunu doğruluyoruz
        self.assertEqual(cred_finding.severity, ThreatSeverity.CRITICAL)

    def test_04_unquoted_service_path_detected(self):
        """Tırnaksız servis yolları CWE-428 ve MITRE T1574.009 ile raporlanmalıdır."""
        # 2 adet tırnaksız servis yolu olan yapılandırma
        controls = EndpointControlStatus(
            edr_active=True,
            tamper_protection_active=True,
            telemetry_active=True,
            unquoted_service_paths_count=2
        )
        # Analizi yapıyoruz
        report = self.engine.model_endpoint_threats(
            "AppServer-01",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.APPLICATION_SERVER,
            controls
        )
        # CWE-428 varlığını doğruluyoruz
        self.assertTrue(any(f.cwe_id == "CWE-428" for f in report.findings))
        # Başlıkta adet geçtiğini doğruluyoruz
        self.assertTrue(any("Tırnaksız Servis Yolu" in f.title for f in report.findings))

    def test_05_linux_suid_misconfiguration_detected(self):
        """Linux ortamında güvensiz SUID ikili dosyaları CWE-250 ve CRITICAL ciddiyet ile raporlanmalıdır."""
        # SUID zafiyetli Linux kontrolleri
        controls = EndpointControlStatus(
            edr_active=True,
            telemetry_active=True,
            suid_misconfigurations_count=3
        )
        # Linux analizi
        report = self.engine.model_endpoint_threats(
            "Ubuntu-Prod",
            OperatingSystemFamily.LINUX,
            EndpointRole.APPLICATION_SERVER,
            controls
        )
        # CWE-250 varlığını doğruluyoruz
        suid_f = next((f for f in report.findings if f.cwe_id == "CWE-250"), None)
        self.assertIsNotNone(suid_f)
        # Ciddiyetin CRITICAL olduğunu doğruluyoruz
        self.assertEqual(suid_f.severity, ThreatSeverity.CRITICAL)

    def test_06_missing_edr_triggers_critical_threat(self):
        """EDR ajanı eksikliği CRITICAL ciddiyet ve CWE-693 ile raporlanmalıdır."""
        # EDR kapalı kontroller
        controls = EndpointControlStatus(edr_active=False)
        # Analizi yürütüyoruz
        report = self.engine.model_endpoint_threats(
            "NoEDR-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # EDR bulgusunu arıyoruz
        edr_f = next((f for f in report.findings if "EDR" in f.title), None)
        self.assertIsNotNone(edr_f)
        self.assertEqual(edr_f.severity, ThreatSeverity.CRITICAL)
        self.assertEqual(edr_f.cwe_id, "CWE-693")

    def test_07_tamper_protection_disabled_triggers_high_threat(self):
        """EDR aktif ancak Kurcalama Koruması (Tamper Protection) kapalıysa HIGH ciddiyet üretilmelidir."""
        # EDR var, kurcalama koruması yok
        controls = EndpointControlStatus(edr_active=True, tamper_protection_active=False)
        # Analizi yapıyoruz
        report = self.engine.model_endpoint_threats(
            "EDR-NoTamper",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Tamper bulgusunu doğruluyoruz
        tamper_f = next((f for f in report.findings if "Kurcalama Koruması" in f.title), None)
        self.assertIsNotNone(tamper_f)
        self.assertEqual(tamper_f.severity, ThreatSeverity.HIGH)

    def test_08_missing_telemetry_sysmon_auditd_detected(self):
        """Sysmon veya Auditd telemetrisi eksikse CWE-778 ve MEDIUM ciddiyet üretilmelidir."""
        # Telemetri kapalı
        controls = EndpointControlStatus(telemetry_active=False)
        # Analizi yapıyoruz
        report = self.engine.model_endpoint_threats(
            "NoTelemetry-Host",
            OperatingSystemFamily.LINUX,
            EndpointRole.APPLICATION_SERVER,
            controls
        )
        # CWE-778 varlığını doğruluyoruz
        self.assertTrue(any(f.cwe_id == "CWE-778" for f in report.findings))

    def test_09_powershell_full_language_mode_detected(self):
        """Windows üzerinde PowerShell CLM kapalıysa CWE-284 ile betik çalıştırma riski raporlanmalıdır."""
        # CLM kapalı
        controls = EndpointControlStatus(powershell_clm_active=False)
        # Analiz yapıyoruz
        report = self.engine.model_endpoint_threats(
            "PowerShell-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # CWE-284 varlığını doğruluyoruz
        self.assertTrue(any(f.cwe_id == "CWE-284" for f in report.findings))

    def test_10_insecure_open_ports_detected(self):
        """SMBv1 veya NLA'sız RDP gibi güvensiz portlar CWE-319 ve MITRE T1021 ile yakalanmalıdır."""
        # Güvensiz portlar ekliyoruz
        controls = EndpointControlStatus(insecure_open_ports=["SMBv1 (Port 445)", "RDP-NoNLA (Port 3389)"])
        # Analiz yapıyoruz
        report = self.engine.model_endpoint_threats(
            "OpenPorts-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.APPLICATION_SERVER,
            controls
        )
        # CWE-319 varlığını doğruluyoruz
        self.assertTrue(any(f.cwe_id == "CWE-319" for f in report.findings))

    def test_11_missing_disk_encryption_on_workstation(self):
        """İş istasyonunda disk şifrelemesi (BitLocker/LUKS) kapalıysa HIGH ciddiyet raporlanmalıdır."""
        # Disk şifrelemesi kapalı
        controls = EndpointControlStatus(disk_encryption_active=False)
        # Workstation analizi
        report = self.engine.model_endpoint_threats(
            "Laptop-01",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Disk bulgusunu alıyoruz
        disk_f = next((f for f in report.findings if "Disk Şifreleme" in f.title), None)
        self.assertIsNotNone(disk_f)
        self.assertEqual(disk_f.severity, ThreatSeverity.HIGH)

    def test_12_weak_registry_autoruns_detected(self):
        """Zayıf izinli Kayıt Defteri Run anahtarları CWE-732 ve MITRE T1547.001 ile yakalanmalıdır."""
        # Zayıf autorun kayıtları olan kontroller
        controls = EndpointControlStatus(weak_registry_autoruns_count=3)
        # Analiz yapıyoruz
        report = self.engine.model_endpoint_threats(
            "Persistence-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # CWE-732 varlığını doğruluyoruz
        self.assertTrue(any(f.cwe_id == "CWE-732" for f in report.findings))

    def test_13_domain_controller_multiplier_increases_risk(self):
        """Aynı zafiyet kümesi Domain Controller üzerinde Workstation'a göre daha yüksek skor üretmelidir."""
        # Ortak zafiyetli kontrol
        controls = EndpointControlStatus(edr_active=False, credential_guard_active=False)
        # Workstation analizi
        rep_ws = self.engine.model_endpoint_threats(
            "WS-01", OperatingSystemFamily.WINDOWS, EndpointRole.WORKSTATION, controls
        )
        # Domain Controller analizi
        rep_dc = self.engine.model_endpoint_threats(
            "DC-01", OperatingSystemFamily.WINDOWS, EndpointRole.DOMAIN_CONTROLLER, controls
        )
        # DC tehdit endeksinin Workstation'dan daha yüksek olduğunu doğruluyoruz
        self.assertGreater(rep_dc.threat_index_score, rep_ws.threat_index_score)

    def test_14_hardening_roadmap_prioritizes_critical_remediations(self):
        """Sıkılaştırma yol haritası en kritik zafiyetleri 1. sıraya koyarak önceliklendirmelidir."""
        # Hem kritik hem orta zafiyet içeren kontroller
        controls = EndpointControlStatus(
            edr_active=False,                    # Kritik
            powershell_clm_active=False,         # Orta
            telemetry_active=False               # Orta
        )
        # Analizi yapıyoruz
        report = self.engine.model_endpoint_threats(
            "MixedThreats-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Yol haritasının ilk adımının Kritik seviye içerdiğini doğruluyoruz
        self.assertTrue(report.hardening_roadmap[0].startswith("Adım 1 [Kritik]"))

    def test_15_export_markdown_report_structure(self):
        """Dışa aktarılan Markdown raporu başlıkları, tabloyu ve referans standartları içermelidir."""
        # Basit kontroller
        controls = EndpointControlStatus(edr_active=True, credential_guard_active=True)
        # Raporu üretiyoruz
        report = self.engine.model_endpoint_threats(
            "Report-Host",
            OperatingSystemFamily.WINDOWS,
            EndpointRole.WORKSTATION,
            controls
        )
        # Markdown metnini üretiyoruz
        md_text = self.engine.export_markdown_report(report)
        # Başlık ve standartların varlığını doğruluyoruz
        self.assertIn("# UÇ NOKTA TEHDİT MODELİ RAPORU: Report-Host", md_text)
        self.assertIn("MITRE ATT&CK", md_text)
        self.assertIn("CIS Benchmarks", md_text)


# Betik doğrudan çalıştırıldığında testler yürütülür
if __name__ == "__main__":
    unittest.main()
