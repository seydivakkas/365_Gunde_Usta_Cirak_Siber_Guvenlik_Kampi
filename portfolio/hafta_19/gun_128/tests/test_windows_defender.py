# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 128: WINDOWS DEFENDER VE GÜVENLİK MERKEZİ BİRİM TESTLERİ (15/15 PASS)
------------------------------------------------------------------------
Bu test paketi; Microsoft Defender gerçek zamanlı koruma, davranışsal analiz,
IOAV, Tamper Protection, Bulut Blok Seviyesi, PUA, Controlled Folder Access,
tehlikeli hariç tutmalar (CWE-732) ve Attack Surface Reduction (ASR) kurallarını
kapsamlı şekilde sınar.
"""

# Birim test çerçevesi için unittest modülü
import unittest
# Sistem yolunu düzenlemek için sys ve os modülleri
import sys
import os

# Üst dizini sys.path'e ekleyerek bağımsız çalışmayı garantiye alıyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Denetim motorunu ve veri sınıflarını içe aktarıyoruz
from uygulama.windows_defender_engine import (
    WindowsDefenderAuditEngine,
    DefenderPreferences,
    AuditSeverity,
    ASRAction
)
from uygulama.defender_cli import parse_preferences_from_dict, build_parser


class TestWindowsDefenderEngine(unittest.TestCase):
    """Windows Defender ve Güvenlik Merkezi Denetim Motoru Test Sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # Testlerde kullanılacak denetim motoru nesnesini başlatıyoruz
        self.engine = WindowsDefenderAuditEngine(auditor_name="Test Defender Hardener")

        # 7 Kritik ASR kuralının tümünün BLOCK (1) modunda olduğu sözlüğü hazırlıyoruz
        self.hardened_asr_map = {
            guid: ASRAction.BLOCK.value
            for guid in self.engine.CRITICAL_ASR_RULES.keys()
        }

        # Kusursuz CIS uyumlu sertleştirilmiş temel profil
        self.hardened_prefs = DefenderPreferences(
            disable_realtime_monitoring=False,
            disable_behavior_monitoring=False,
            disable_ioav_protection=False,
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            submit_samples_consent="SendSafeSamples",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            exclusion_paths=[],
            exclusion_extensions=[],
            exclusion_processes=[],
            asr_rules_map=self.hardened_asr_map
        )

    def test_01_perfect_cis_hardened_baseline(self):
        """Test 01: Kusursuz CIS uyumlu yapılandırma 100/100 tam puan ve sıfır bulgu üretmelidir."""
        # Denetimi icra ediyoruz
        result = self.engine.audit_preferences(
            target_host="CORP-SECURE-W11",
            prefs=self.hardened_prefs
        )
        # Puanın tam 100 olduğunu doğruluyoruz
        self.assertEqual(result.defender_security_score, 100.0)
        # Duruş durumunun PASS olduğunu doğruluyoruz
        self.assertIn("PASS", result.posture_status)
        # Hiçbir güvenlik açığı bulunmadığını doğruluyoruz
        self.assertEqual(len(result.findings), 0)

    def test_02_disabled_realtime_monitoring_cwe_693(self):
        """Test 02: Gerçek zamanlı korumanın kapatılması kritik CWE-693 bulgusu ve 40 puan düşüşü oluşturmalıdır."""
        # Gerçek zamanlı korumayı kapatıyoruz
        prefs = DefenderPreferences(
            disable_realtime_monitoring=True,
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        # Denetimi çalıştırıyoruz
        result = self.engine.audit_preferences(target_host="VICTIM-PC", prefs=prefs)
        # Puanın 40 puan düştüğünü (en fazla 60.0 olduğunu) doğruluyoruz
        self.assertLessEqual(result.defender_security_score, 60.0)
        # CWE-693 bulgusunun varlığını kontrol ediyoruz
        cwe_ids = [f.cwe_id for f in result.findings]
        self.assertIn("CWE-693", cwe_ids)
        # Düzeltme komutunun Set-MpPreference içerdiğini doğruluyoruz
        self.assertTrue(any("DisableRealtimeMonitoring $false" in f.powershell_remediation for f in result.findings))

    def test_03_disabled_behavior_monitoring_cwe_693(self):
        """Test 03: Davranışsal izlemenin kapatılması Yüksek riskli bulgu ve 20 puan düşüşü oluşturmalıdır."""
        # Davranışsal izlemeyi kapatıyoruz
        prefs = DefenderPreferences(
            disable_realtime_monitoring=False,
            disable_behavior_monitoring=True,
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-BEHAVIOR-OFF", prefs=prefs)
        # Puanın 80.0 olduğunu doğruluyoruz
        self.assertEqual(result.defender_security_score, 80.0)
        # İlgili bulgunun başlığını kontrol ediyoruz
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Davranışsal İzleme" in t for t in titles))

    def test_04_disabled_ioav_protection_cwe_693(self):
        """Test 04: İnternet indirmeleri taramasının kapatılması 15 puan düşüşü ve T1566 uyarısı üretmelidir."""
        # IOAV korumasını kapatıyoruz
        prefs = DefenderPreferences(
            disable_ioav_protection=True,
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-IOAV-OFF", prefs=prefs)
        self.assertEqual(result.defender_security_score, 85.0)
        # MITRE tekniğinin T1566 içerdiğini doğruluyoruz
        self.assertTrue(any("T1566" in f.mitre_technique_id for f in result.findings))

    def test_05_tamper_protection_disabled_cwe_693(self):
        """Test 05: Kurcalama Korumasının (Tamper Protection) kapalı olması kritik zafiyet oluşturmalıdır."""
        # Kurcalama korumasını devre dışı bırakıyoruz
        prefs = DefenderPreferences(
            tamper_protection_active=False,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-TAMPER-OFF", prefs=prefs)
        # 25 puan kırılmış olmalıdır
        self.assertEqual(result.defender_security_score, 75.0)
        # Kritik ciddiyet dereceli bulgu olduğunu doğruluyoruz
        tamper_finding = next(f for f in result.findings if "Kurcalama Koruması" in f.title)
        self.assertEqual(tamper_finding.severity, AuditSeverity.CRITICAL)

    def test_06_weak_cloud_protection_cwe_1188(self):
        """Test 06: Bulut koruma seviyesinin 'Basic' veya 'Disabled' olması CWE-1188 uyarısı vermelidir."""
        # Bulut seviyesini Basic yapıyoruz
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="Basic",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-CLOUD-BASIC", prefs=prefs)
        self.assertEqual(result.defender_security_score, 90.0)
        self.assertTrue(any("CWE-1188" == f.cwe_id for f in result.findings))

    def test_07_pua_protection_disabled_cwe_1188(self):
        """Test 07: PUA korumasının kapalı olması 10 puan kırılmasını sağlamalıdır."""
        # PUA korumasını kapatıyoruz
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Disabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-PUA-OFF", prefs=prefs)
        self.assertEqual(result.defender_security_score, 90.0)
        self.assertTrue(any("PUA" in f.title for f in result.findings))

    def test_08_network_protection_disabled_cwe_319(self):
        """Test 08: Ağ korumasının kapalı olması CWE-319 bulgusu ve 10 puan ceza getirmelidir."""
        # Ağ korumasını kapatıyoruz
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Disabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-NET-OFF", prefs=prefs)
        self.assertEqual(result.defender_security_score, 90.0)
        self.assertTrue(any("CWE-319" == f.cwe_id for f in result.findings))

    def test_09_controlled_folder_access_disabled_cwe_693(self):
        """Test 09: Denetimli klasör erişiminin kapalı olması fidye yazılımı uyarısı (T1486) üretmelidir."""
        # Controlled Folder Access kapatılıyor
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Disabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-CFA-OFF", prefs=prefs)
        self.assertEqual(result.defender_security_score, 85.0)
        self.assertTrue(any("T1486" in f.mitre_technique_id for f in result.findings))

    def test_10_dangerous_exclusion_path_cwe_732(self):
        """Test 10: 'C:\\' veya 'C:\\Windows' hariç tutması kritik CWE-732 bulgusu üretmelidir."""
        # Tehlikeli hariç tutma yolu tanımlıyoruz
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            exclusion_paths=["C:\\Windows", "C:\\"],
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-EXCL-PATH", prefs=prefs)
        # Her tehlikeli yol için 20 puan kırılır (toplam 40)
        self.assertEqual(result.defender_security_score, 60.0)
        # CWE-732 bulgularını kontrol ediyoruz
        excl_findings = [f for f in result.findings if f.cwe_id == "CWE-732"]
        self.assertEqual(len(excl_findings), 2)
        # Düzeltme komutunun Remove-MpPreference içerdiğini doğruluyoruz
        self.assertTrue(any("Remove-MpPreference -ExclusionPath" in f.powershell_remediation for f in excl_findings))

    def test_11_dangerous_exclusion_extension_cwe_732(self):
        """Test 11: '.exe' uzantı hariç tutması kritik CWE-732 bulgusu üretmelidir."""
        # Yürütülebilir uzantı hariç tutulmuş
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            exclusion_extensions=[".exe"],
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-EXCL-EXT", prefs=prefs)
        self.assertEqual(result.defender_security_score, 80.0)
        self.assertTrue(any("Uzantısı" in f.title for f in result.findings))

    def test_12_missing_critical_asr_rules_cwe_358(self):
        """Test 12: ASR kurallarının yapılandırılmamış olması CWE-358 bulgusu üretmelidir."""
        # Hiçbir ASR kuralı tanımlanmamış
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map={}
        )
        result = self.engine.audit_preferences(target_host="HOST-NO-ASR", prefs=prefs)
        # Eksik ASR kuralı nedeniyle 25 puan ceza
        self.assertEqual(result.defender_security_score, 75.0)
        self.assertTrue(any(f.cwe_id == "CWE-358" for f in result.findings))

    def test_13_all_asr_rules_blocked_passes(self):
        """Test 13: 7 kritik kuralın tümü BLOCK modunda olduğunda ASR bulgusu üretilmemelidir."""
        prefs = DefenderPreferences(
            tamper_protection_active=True,
            cloud_protection_level="HighPlus",
            pua_protection="Enabled",
            controlled_folder_access="Enabled",
            network_protection="Enabled",
            asr_rules_map=self.hardened_asr_map
        )
        result = self.engine.audit_preferences(target_host="HOST-FULL-ASR", prefs=prefs)
        # Hiçbir ASR bulgusu olmamalıdır
        self.assertFalse(any(f.cwe_id == "CWE-358" for f in result.findings))

    def test_14_markdown_report_generation(self):
        """Test 14: Markdown denetim raporu çıktısının başlık, tablo ve düzeltme betiğini içerdiği doğrulanmalıdır."""
        # Bulgulu bir senaryo denetliyoruz
        prefs = DefenderPreferences(disable_realtime_monitoring=True)
        result = self.engine.audit_preferences(target_host="AUDIT-TARGET-01", prefs=prefs)
        # Markdown raporunu üretiyoruz
        md_text = self.engine.export_markdown_report(result)
        # Zorunlu başlıkları ve tabloları denetliyoruz
        self.assertIn("# MICROSOFT DEFENDER VE GÜVENLİK MERKEZİ DENETİM RAPORU", md_text)
        self.assertIn("AUDIT-TARGET-01", md_text)
        self.assertIn("PowerShell Otomatik Sıkılaştırma", md_text)
        self.assertIn("Set-MpPreference -DisableRealtimeMonitoring $false", md_text)

    def test_15_cli_parser_and_data_mapping(self):
        """Test 15: CLI sözlük dönüştürücü ve argüman ayrıştırıcısı beklenen formatta çalışmalıdır."""
        # Sözlük verisi hazırlıyoruz
        sample_dict = {
            "disable_realtime_monitoring": False,
            "tamper_protection_active": True,
            "cloud_protection_level": "HighPlus",
            "pua_protection": "Enabled",
            "controlled_folder_access": "Enabled",
            "network_protection": "Enabled",
            "exclusion_paths": ["C:\\CustomApp"],
            "asr_rules_map": {"D4F940AB-401B-4EFC-AADC-AD5F3C50688A": 1}
        }
        # Nesneye dönüştürüyoruz
        parsed_prefs = parse_preferences_from_dict(sample_dict)
        self.assertEqual(parsed_prefs.cloud_protection_level, "HighPlus")
        self.assertEqual(len(parsed_prefs.exclusion_paths), 1)

        # CLI ayrıştırıcısını test ediyoruz
        parser = build_parser()
        args = parser.parse_args(["audit", "--spec", "test.json", "--format", "json"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.format, "json")


if __name__ == "__main__":
    # Testleri detaylı çıktıyla koşturuyoruz
    unittest.main()
