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
Gün 32: Başlangıç Uygulamaları ve Hizmet Yönetimi Birim Testleri
Bu test paketi; unquoted service path, yetkisiz servis manipülasyonu,
gizlenmiş komut satırı bayrakları, şüpheli ikili dosya konumları ve
negatif kontroller dahil olmak üzere 14 kapsamlı test senaryosunu içerir.
"""

# İşletim sistemi ve dosya yolları işlemleri için os modülünü içe aktarıyoruz
import os
# Sistem çalışma parametreleri ve yol tanımları için sys modülü
import sys
# Birim test çatısı olarak Python standart unittest modülünü kullanıyoruz
import unittest
# Geçici test dosyaları ve dizinleri oluşturmak için tempfile modülü
import tempfile
# JSON test serileştirmeleri için json modülü
import json

# Test edilen uygulamanın modülünü import edebilmek için proje kök dizinini sys.path'e ekliyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Bir üst dizindeki paket kökünü hesaplıyoruz
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
# sys.path başında yer almasını sağlayarak temiz import rotası kuruyoruz
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Gün 32 denetleyici sınıfını ve veri modellerini içe aktarıyoruz
from portfolio.hafta_05.gun_032.uygulama.startup_service_auditor import (
    StartupServiceAuditor,
    StartupItem,
    StartupSecurityFinding
)


class TestStartupServiceAuditor(unittest.TestCase):
    """Başlangıç ve hizmet güvenliği analizcisinin 14 kapsamlı test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz ve izole bir denetleyici örneği oluşturur."""
        # Yeni denetleyici nesnesi örnekliyoruz
        self.auditor = StartupServiceAuditor()
        # Test için örnek veri dizinini belirliyoruz
        self.base_dir = os.path.dirname(CURRENT_DIR)
        # Örnek envanter dosyasının yolunu tanımlıyoruz
        self.sample_inv_path = os.path.join(self.base_dir, "ornek_veri", "sample_startup_service_inventory.json")
        # Bozuk test verisi dosyasının yolunu tanımlıyoruz
        self.corrupted_inv_path = os.path.join(self.base_dir, "ornek_veri", "corrupted_startup_service_test.json")

    def test_01_init_state(self) -> None:
        """Denetleyicinin başlangıç durumunun boş ve hazır olduğunu doğrular."""
        # Başlangıçta incelenecek öğe listesi sıfır olmalıdır
        self.assertEqual(len(self.auditor.items), 0)
        # Başlangıçta herhangi bir bulgu bulunmamalıdır
        self.assertEqual(len(self.auditor.findings), 0)
        # Bozuk kayıt listesi başlangıçta boş olmalıdır
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_02_load_sample_inventory(self) -> None:
        """Gerçekçi örnek envanter dosyasının eksiksiz yüklendiğini test eder."""
        # Envanteri dosyadan yüklüyoruz
        count = self.auditor.load_from_json(self.sample_inv_path)
        # Envanterde 14 geçerli kaydın olduğunu doğruluyoruz
        self.assertEqual(count, 14)
        # Denetleyici içindeki öğe sayısının 14 olduğunu teyit ediyoruz
        self.assertEqual(len(self.auditor.items), 14)
        # Herhangi bir bozuk kayıt oluşmadığını denetliyoruz
        self.assertEqual(len(self.auditor.corrupted_records), 0)

    def test_03_detect_unquoted_service_path(self) -> None:
        """Tırnaksız servis yolu (Unquoted Service Path - T1574.009) zafiyetini yakalar."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Tırnaksız servis tarayıcısını koşturuyoruz
        findings = self.auditor.detect_unquoted_service_paths()
        # En az bir tırnaksız servis tespit edilmelidir
        self.assertGreaterEqual(len(findings), 1)
        # Tespit edilen servis adının 'VulnBackupService' olduğunu kontrol ediyoruz
        vuln_names = [f.item_name for f in findings]
        self.assertIn("VulnBackupService", vuln_names)
        # Bulgu türünün UNQUOTED_SERVICE_PATH olduğunu doğruluyoruz
        target_f = next(f for f in findings if f.item_name == "VulnBackupService")
        self.assertEqual(target_f.vulnerability_type, "UNQUOTED_SERVICE_PATH")
        # Zafiyet seviyesinin yetkili hesaba bağlı olarak HIGH olduğunu kontrol ediyoruz
        self.assertEqual(target_f.risk_level, "HIGH")

    def test_04_detect_suspicious_binary_paths(self) -> None:
        """Temp ve Public dizinlerinden çalışan başlangıç girdilerini yakalar."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Şüpheli dizin kontrol motorunu çalıştırıyoruz
        findings = self.auditor.detect_suspicious_binary_paths()
        # En az 3 adet şüpheli dizin bulgusu olmalıdır (EdgeUpdateHelper, SystemMaintenance, svch0st)
        self.assertGreaterEqual(len(findings), 3)
        # Tespit edilen öğelerin isimlerini kontrol ediyoruz
        item_names = [f.item_name for f in findings]
        self.assertIn("EdgeUpdateHelper", item_names)
        self.assertIn("SystemMaintenance", item_names)
        self.assertIn("svch0st_service", item_names)

    def test_05_detect_name_masquerading(self) -> None:
        """Meşru sistem isimlerini taklit eden (Masquerading - T1036) kayıtları yakalar."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # İsim taklidi denetimini koşturuyoruz
        findings = self.auditor.detect_name_masquerading()
        # svch0st ve lsasss kayıtlarının yakalandığını teyit ediyoruz
        item_names = [f.item_name for f in findings]
        self.assertIn("svch0st_service", item_names)
        self.assertIn("lsasss_service", item_names)
        # Risk seviyesinin CRITICAL olduğunu doğruluyoruz
        for f in findings:
            self.assertEqual(f.risk_level, "CRITICAL")
            self.assertEqual(f.vulnerability_type, "MASQUERADING")

    def test_06_detect_security_service_tampering(self) -> None:
        """Devre dışı bırakılan güvenlik duvarı servisini (MpsSvc) yakalar."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Güvenlik servisi tahrifat kontrolünü yapıyoruz
        findings = self.auditor.detect_security_service_tampering()
        # MpsSvc servisinin yakalandığını sınıyoruz
        item_names = [f.item_name for f in findings]
        self.assertIn("MpsSvc", item_names)
        # Bulgu türünün SERVICE_TAMPERING olduğunu doğruluyoruz
        mps_finding = next(f for f in findings if f.item_name == "MpsSvc")
        self.assertEqual(mps_finding.vulnerability_type, "SERVICE_TAMPERING")
        self.assertEqual(mps_finding.risk_level, "CRITICAL")

    def test_07_detect_malicious_script_execution(self) -> None:
        """Gizli ve baypas parametreli PowerShell başlangıç görevini yakalar."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Betik motoru analizini çalıştırıyoruz
        findings = self.auditor.detect_suspicious_script_execution()
        # PowerShellScriptAuto kaydının tespit edildiğini denetliyoruz
        item_names = [f.item_name for f in findings]
        self.assertIn("PowerShellScriptAuto", item_names)
        # İlgili bulgunun tekniğini teyit ediyoruz
        ps_finding = next(f for f in findings if f.item_name == "PowerShellScriptAuto")
        self.assertEqual(ps_finding.vulnerability_type, "MALICIOUS_SCRIPT")
        self.assertIn("T1059.001", ps_finding.mitre_technique)

    def test_08_risk_score_calculation(self) -> None:
        """Tüm zafiyetler tetiklendiğinde risk puanının ve tehdit duruşunun doğruluğunu test eder."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Kapsamlı denetimi koşturuyoruz
        audit_res = self.auditor.run_comprehensive_audit()
        # Risk metriklerini alıyoruz
        metrics = audit_res["risk_metrics"]
        # Çok sayıda kritik bulgu olduğu için skorun 100 olduğunu sınıyoruz
        self.assertEqual(metrics["risk_score"], 100)
        # Duruşun CRITICAL_THREAT olduğunu doğruluyoruz
        self.assertEqual(metrics["posture"], "CRITICAL_THREAT")
        # Kritik bulgu sayısının sıfırdan büyük olduğunu sınıyoruz
        self.assertGreater(metrics["findings_by_severity"]["CRITICAL"], 0)

    def test_09_clean_baseline_risk_score(self) -> None:
        """Sadece meşru ve temiz servislerden oluşan ortamda riskin 0 çıktığını test eder."""
        # Temiz denetleyici örneği
        clean_auditor = StartupServiceAuditor()
        # Sadece meşru Microsoft Defender servisini ekliyoruz
        clean_entry = {
            "id": "CLEAN-01",
            "name": "WinDefend",
            "display_name": "Microsoft Defender Antivirus Service",
            "entry_type": "service",
            "start_mode": "Automatic",
            "status": "Running",
            "binary_path": '"C:\\Program Files\\Windows Defender\\MsMpEng.exe"',
            "account": "NT AUTHORITY\\SYSTEM",
            "category": "security_core",
            "signed": True
        }
        # Ekliyoruz
        added = clean_auditor.add_item(clean_entry)
        self.assertTrue(added)
        # Denetimi koşturuyoruz
        res = clean_auditor.run_comprehensive_audit()
        # Herhangi bir bulgu çıkmamalıdır
        self.assertEqual(len(res["findings"]), 0)
        # Risk skoru 0 olmalıdır
        self.assertEqual(res["risk_metrics"]["risk_score"], 0)
        # Duruş SECURE_BASELINE olmalıdır
        self.assertEqual(res["risk_metrics"]["posture"], "SECURE_BASELINE")

    def test_10_negative_control_corrupted_dataset(self) -> None:
        """Negatif kontrol: Bozuk şemalı veri setinin güvenle reddedildiğini test eder."""
        # Bozuk test verisini yüklüyoruz
        loaded_count = self.auditor.load_from_json(self.corrupted_inv_path)
        # Hiçbir bozuk kaydın meşru envantere alınmadığını doğruluyoruz
        self.assertEqual(loaded_count, 0)
        self.assertEqual(len(self.auditor.items), 0)
        # Bozuk kayıtlar listesinde tüm hatalı girdilerin (7 adet) toplandığını teyit ediyoruz
        self.assertEqual(len(self.auditor.corrupted_records), 7)
        # Hata nedenlerini inceliyoruz
        reasons = [r["error_reason"] for r in self.auditor.corrupted_records]
        self.assertTrue(any("EKSIK_ZORUNLU_ALAN" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_ISIM" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_YOL" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_TUR" in r for r in reasons))
        self.assertTrue(any("GECERSIZ_BASLANGIC_MODU" in r for r in reasons))
        self.assertTrue(any("KAYIT_SOZLUK_DEGIL" in r for r in reasons))

    def test_11_negative_control_missing_file(self) -> None:
        """Negatif kontrol: Var olmayan bir dosya yolunda FileNotFoundError fırlatıldığını test eder."""
        # Olmayan hayali dosya yolu
        non_existent_path = os.path.join(self.base_dir, "ornek_veri", "hayali_olmayan_dosya_9999.json")
        # Yükleme denemesinde FileNotFoundError beklenir
        with self.assertRaises(FileNotFoundError):
            self.auditor.load_from_json(non_existent_path)

    def test_12_negative_control_non_list_json(self) -> None:
        """Negatif kontrol: JSON içeriği liste yerine obje veya sayı olduğunda ValueError fırlatır."""
        # Geçici geçersiz JSON dosyası oluşturuyoruz
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump({"tek_obje": "liste_degil"}, tf)
            temp_path = tf.name

        try:
            # Liste olmayan JSON yüklendiğinde ValueError fırlatılmalıdır
            with self.assertRaises(ValueError):
                self.auditor.load_from_json(temp_path)
        finally:
            # Test sonrası geçici dosyayı siliyoruz
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_13_text_report_generation(self) -> None:
        """Metin tabanlı denetim raporunun eksiksiz ve formatına uygun üretildiğini test eder."""
        # Envanteri yüklüyoruz
        self.auditor.load_from_json(self.sample_inv_path)
        # Denetimi koşturuyoruz
        self.auditor.run_comprehensive_audit()
        # Rapor metnini üretiyoruz
        report = self.auditor.generate_text_report()
        # Rapor içinde anahtar başlıkların yer aldığını sınıyoruz
        self.assertIn("BAŞLANGIÇ UYGULAMALARI VE HİZMET YÖNETİMİ GÜVENLİK DENETİM RAPORU", report)
        self.assertIn("Genel Tehdit Puanı (Risk Score)", report)
        self.assertIn("UNQUOTED_SERVICE_PATH", report)
        self.assertIn("VulnBackupService", report)
        self.assertIn("sc.exe config", report)

    def test_14_custom_license_presence(self) -> None:
        """Lisans kuralı gereği kod dosyalarında özel 'Tüm Hakları Saklıdır' lisansını doğrular."""
        # Uygulama dosyasını okuyoruz
        app_file = os.path.join(self.base_dir, "uygulama", "startup_service_auditor.py")
        with open(app_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Özel lisans ibarelerinin varlığını doğruluyoruz
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", content)
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)", content)
        self.assertIn("YASAKLAR:", content)
        self.assertIn("YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ", content)


# Test dosyasının doğrudan yürütülmesi durumu
if __name__ == "__main__":
    unittest.main()
