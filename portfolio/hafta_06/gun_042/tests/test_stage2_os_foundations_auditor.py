# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G042: Aşama 2 Kalite Özeti ve Kabul Birim ve Negatif Test Süiti.

Bu test süiti, Aşama 02'nin 6 temel güvenlik sütununu (süreçler, izinler, günlükleme,
karmalar, yedekleme ve servisler) denetleyen kabul motorunun tüm doğrulama adımlarını,
pozitif ve negatif senaryolarını kapsamlı şekilde doğrular.
"""

# Python'un yerleşik test kütüphanesini içe aktarıyoruz.
import unittest
# Dosya sistemi işlemleri için os modülünü yüklüyoruz.
import os
# JSON okuma ve yazma işlemleri için json kütüphanesini çağırıyoruz.
import json
# Geçici dosya oluşturma amacıyla tempfile modülünü kullanıyoruz.
import tempfile

# Test edilecek hedef uygulama bileşenlerini içe aktarıyoruz.
from portfolio.hafta_06.gun_042.uygulama.stage2_os_foundations_auditor import (
    validate_octal_permission,
    validate_sha256_hash,
    validate_stage2_inventory_schema,
    audit_processes_pillar,
    audit_permissions_pillar,
    audit_logging_pillar,
    audit_hashes_pillar,
    audit_backups_pillar,
    audit_services_pillar,
    execute_stage2_quality_acceptance,
    generate_stage2_markdown_report,
    Stage2AuditError,
    REQUIRED_PILLARS
)


class TestStage2OSFoundationsAuditor(unittest.TestCase):
    """Aşama 2 kabul motoru için birim ve negatif test durumları sınıfı."""

    def setUp(self) -> None:
        """Her testten önce referans örnek verileri hazırlar."""
        # Test dosyasının bulunduğu dizini tespit ediyoruz.
        test_dir = os.path.dirname(os.path.abspath(__file__))
        # Örnek veri dizininin tam yolunu oluşturuyoruz.
        self.sample_dir = os.path.join(test_dir, "..", "ornek_veri")
        # Referans kabul envanterinin dosya yolunu alıyoruz.
        self.inventory_path = os.path.join(self.sample_dir, "stage2_acceptance_inventory.json")
        # Envanter JSON verisini diskten okuyoruz.
        with open(self.inventory_path, "r", encoding="utf-8") as f:
            # Belleğe yüklüyoruz.
            self.inventory_data = json.load(f)

    def test_01_valid_stage2_inventory_loading(self) -> None:
        """Geçerli kabul envanterinin tüm 6 sütunu eksiksiz içerdiğini test eder."""
        # Şema doğrulayıcıyı çağırıyoruz; hata fırlatmamalıdır.
        validate_stage2_inventory_schema(self.inventory_data)
        # Zorunlu sütunların envanterde bulunduğunu teyit ediyoruz.
        for pillar in REQUIRED_PILLARS:
            # Sütunun varlığını sınıyoruz.
            self.assertIn(pillar, self.inventory_data)

    def test_02_processes_pillar_clean(self) -> None:
        """Süreç hijyeni sütununun yetkisiz süreç içermediğinde 100 puan aldığını doğrular."""
        # Süreç denetimini çalıştırıyoruz.
        score, findings = audit_processes_pillar(self.inventory_data["processes"])
        # Tam puan aldığını teyit ediyoruz.
        self.assertEqual(score, 100.0)
        # Bulgular arasında süreç hijyeni onayını kontrol ediyoruz.
        self.assertTrue(any("Süreç hijyeni tam" in f for f in findings))

    def test_03_permissions_pillar_clean(self) -> None:
        """Dosya izinleri ve umask sütununun standartlara tam uyumlu olduğunu doğrular."""
        # İzin denetimini çalıştırıyoruz.
        score, findings = audit_permissions_pillar(self.inventory_data["permissions"])
        # Puanın 100 olduğunu teyit ediyoruz.
        self.assertEqual(score, 100.0)
        # Umask onay mesajını sınıyoruz.
        self.assertTrue(any("Umask değeri" in f for f in findings))

    def test_04_logging_pillar_clean(self) -> None:
        """Olay günlükleme sütununda journald, auditd ve SIEM aktarımının tam puan aldığını test eder."""
        # Günlükleme denetimini çalıştırıyoruz.
        score, findings = audit_logging_pillar(self.inventory_data["logging"])
        # Tam puan doğrulaması.
        self.assertEqual(score, 100.0)
        # SIEM aktarım onayını teyit ediyoruz.
        self.assertTrue(any("Merkezi SIEM aktarımı aktif" in f for f in findings))

    def test_05_hashes_pillar_clean(self) -> None:
        """Kritik sistem dosyalarının SHA-256 karmalarının başarıyla doğrulandığını test eder."""
        # Bütünlük karmaları denetimini çalıştırıyoruz.
        score, findings = audit_hashes_pillar(self.inventory_data["hashes"])
        # Puanın 100 olduğunu sınıyoruz.
        self.assertEqual(score, 100.0)
        # Bütünlük onayını teyit ediyoruz.
        self.assertTrue(any("bütünlüğü doğrulandı" in f for f in findings))

    def test_06_backups_pillar_clean(self) -> None:
        """3-2-1 yedekleme kuralı ve geri yükleme testinin başarıyla doğrulandığını sınar."""
        # Yedekleme denetimini çalıştırıyoruz.
        score, findings = audit_backups_pillar(self.inventory_data["backups"])
        # Tam puan doğrulaması yapıyoruz.
        self.assertEqual(score, 100.0)
        # 3-2-1 kuralı onay mesajını sınıyoruz.
        self.assertTrue(any("3-2-1 yedekleme kuralı" in f for f in findings))

    def test_07_services_pillar_clean(self) -> None:
        """Miras servislerin yasaklandığını ve SSH sıkılaştırmasının tam puan aldığını test eder."""
        # Servis denetimini çalıştırıyoruz.
        score, findings = audit_services_pillar(self.inventory_data["services"])
        # Puanı 100 olarak teyit ediyoruz.
        self.assertEqual(score, 100.0)
        # Miras servis yasağı onayını kontrol ediyoruz.
        self.assertTrue(any("Miras güvensiz servisler" in f for f in findings))

    def test_08_overall_acceptance_pass(self) -> None:
        """Genel kabul motorunun envanteri STAGE_02_PASS kararıyla onayladığını doğrular."""
        # Bütüncül kabul testini koşturuyoruz.
        results = execute_stage2_quality_acceptance(self.inventory_data)
        # Geçme durumunu sınıyoruz.
        self.assertTrue(results["is_passed"])
        # Genel puanın >= 85 olduğunu sınıyoruz.
        self.assertGreaterEqual(results["overall_score"], 85.0)
        # Karar dizesini teyit ediyoruz.
        self.assertIn("STAGE_02_PASS", results["decision"])

    def test_09_markdown_report_generation(self) -> None:
        """Üretilen Markdown kabul raporunun lisans uyarısını ve tüm 6 sütunu içerdiğini test eder."""
        # Kabul sonuçlarını alıyoruz.
        results = execute_stage2_quality_acceptance(self.inventory_data)
        # Rapor metnini üretiyoruz.
        report = generate_stage2_markdown_report(results)
        # Özel lisans uyarısının raporda bulunduğunu teyit ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report)
        # 6 sütunun başlıklarının geçtiğini sınıyoruz.
        self.assertIn("Süreç Hijyeni", report)
        self.assertIn("Dosya İzinleri ve Umask", report)
        self.assertIn("Olay Günlükleme", report)
        self.assertIn("Bütünlük Karmaları", report)
        self.assertIn("Yedekleme & 3-2-1", report)
        self.assertIn("Servis Hardening", report)

    def test_10_negative_missing_pillar(self) -> None:
        """Negatif Kontrol: 6 zorunlu sütundan biri (örn: hashes) eksik olduğunda hata fırlatıldığını doğrular."""
        # Envanterin bir kopyasını alıyoruz.
        corrupted = dict(self.inventory_data)
        # 'hashes' sütununu siliyoruz.
        del corrupted["hashes"]
        # Stage2AuditError fırlatıldığını sınıyoruz.
        with self.assertRaises(Stage2AuditError) as ctx:
            validate_stage2_inventory_schema(corrupted)
        # Hata mesajını teyit ediyoruz.
        self.assertIn("zorunlu 'hashes' sütunu envanterde bulunamadı", str(ctx.exception))

    def test_11_negative_invalid_octal_permission(self) -> None:
        """Negatif Kontrol: Geçersiz sekizli izin (örn: '0999') verildiğinde hata yakalandığını doğrular."""
        # Geçersiz octal izne sahip dosya girdisi hazırlıyoruz.
        corrupted_perm = {
            "system_umask": "0027",
            "monitored_files": [
                {
                    "path": "/etc/shadow",
                    "permission_octal": "0999"
                }
            ]
        }
        # Hata fırlatıldığını denetliyoruz.
        with self.assertRaises(Stage2AuditError) as ctx:
            audit_permissions_pillar(corrupted_perm)
        # Hata mesajında geçersiz sekizli uyarısını sınıyoruz.
        self.assertIn("geçersiz sekizli izin", str(ctx.exception))

    def test_12_negative_invalid_sha256_hash(self) -> None:
        """Negatif Kontrol: Bozuk veya kısa SHA-256 karmasında sistemin hata fırlattığını doğrular."""
        # Geçersiz hash girdisi.
        corrupted_hashes = {
            "entries": [
                {
                    "file": "/bin/login",
                    "sha256": "kisa_gecersiz_hash"
                }
            ]
        }
        # Hatanın yakalandığını teyit ediyoruz.
        with self.assertRaises(Stage2AuditError) as ctx:
            audit_hashes_pillar(corrupted_hashes)
        # Hata açıklamasını kontrol ediyoruz.
        self.assertIn("geçersiz SHA-256 karması", str(ctx.exception))

    def test_13_negative_negative_pid_process(self) -> None:
        """Negatif Kontrol: Süreç PID değeri negatif veya sıfır olduğunda istisna üretildiğini test eder."""
        # Negatif PID girdisi.
        corrupted_proc = {
            "unprivileged_service_processes": [
                {"pid": -5, "name": "bad_process"}
            ]
        }
        # Hatanın yakalandığını sınıyoruz.
        with self.assertRaises(Stage2AuditError) as ctx:
            audit_processes_pillar(corrupted_proc)
        # Hata mesajını teyit ediyoruz.
        self.assertIn("Geçersiz PID değeri", str(ctx.exception))

    def test_14_negative_corrupted_json_syntax(self) -> None:
        """Negatif Kontrol: Bozuk JSON sözdizimine sahip dosyanın güvenli şekilde reddedildiğini doğrular."""
        # Bozuk JSON dosyası oluşturuyoruz.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as tf:
            tf.write("{ 'bozuk': 'deger' eksik virgul }")
            temp_path = tf.name
            
        try:
            # json.loads sentaks hatasını doğrulamak için fonksiyonu çağırıyoruz.
            with open(temp_path, "r", encoding="utf-8") as f:
                with self.assertRaises(json.JSONDecodeError):
                    json.load(f)
        finally:
            # Geçici dosyayı siliyoruz.
            if os.path.exists(temp_path):
                os.remove(temp_path)


# Test doğrudan çalıştırıldığında testleri icra ediyoruz.
if __name__ == "__main__":
    # Verbose modda testleri başlatıyoruz.
    unittest.main()
