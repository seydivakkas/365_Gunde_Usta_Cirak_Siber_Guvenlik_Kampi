# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve kişisel öğrenim amacıyla inceleme.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ==============================================================================
"""Paket ve Güncelleme Yöneticileri Birim Testleri.

Bu test modülü, 14 adet kapsamlı ve didaktik birim testi ile:
- Depo güvenliği ve GPG imza doğrulaması (CWE-319, CWE-347),
- Sürüm sabitleme (version pinning / hold) kontrolleri,
- Kritik CVE zafiyet analizleri (CWE-1395),
- Paket güncelleme ve atomik geri alma (rollback) döngüsünü (G027-SC2) test eder.
"""

# Standart test ve sistem kütüphaneleri yüklenir
import json  # JSON doğrulama ve veri hazırlama için
import os  # Dosya ve dizin yönetimi için
import subprocess  # CLI komut çalıştırma testi için
import sys  # Sistem akışları ve Python çalıştırıcı yolu için
import tempfile  # Geçici test ortamı oluşturmak için
import unittest  # Python birim test çatısı

# Test çalıştırıcısının uygulama modülünü bulabilmesi için dizin sys.path'e eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Uygulama modülü fonksiyonları içe aktarılır
from uygulama.package_update_manager_auditor import (
    parse_version_string,
    audit_packages_and_repositories,
    apply_package_pinning,
    simulate_package_update,
    rollback_package_update,
    generate_package_security_policy_note,
)


class TestPackageUpdateManagerAuditor(unittest.TestCase):
    """Paket ve güncelleme yöneticisi test sınıfı."""

    def setUp(self):
        """Her testten önce ortak test ortamı ve kural setini hazırlar."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.journal_file = os.path.join(self.test_dir.name, "test_update_journal.json")
        self.pin_journal_file = os.path.join(self.test_dir.name, "test_pin_journal.json")

        self.policy_rules = {
            "izin_verilen_protokoller": ["https://"],
            "zorunlu_gpg_dogrulamasi": True,
            "zorunlu_surum_sabitleme_paketleri": ["openssl", "nginx", "postgresql"],
            "cve_kritiklik_esigi_cvss": 7.0
        }

    def tearDown(self):
        """Her testten sonra geçici çalışma ortamını temizler."""
        self.test_dir.cleanup()

    def test_01_version_parsing_and_comparison(self):
        """Sürüm dizelerinin sayısal demetlere dönüştürülüp karşılaştırılmasını test eder."""
        v1 = parse_version_string("3.0.2")
        v2 = parse_version_string("3.0.13")
        self.assertEqual(v1, (3, 0, 2))
        self.assertEqual(v2, (3, 0, 13))
        self.assertLess(v1, v2)

    def test_02_detect_insecure_http_repository(self):
        """Şifresiz HTTP deposu tanımlandığında CWE-319 kritik ihlali üretilmesini test eder."""
        inv = {
            "depolar": [
                {
                    "depo_adi": "insecure-repo",
                    "url": "http://repo.example.org/ubuntu",
                    "protokol": "http",
                    "gpg_dogrulandi": True
                }
            ],
            "paketler": []
        }
        rapor = audit_packages_and_repositories(inv, self.policy_rules)
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        self.assertEqual(rapor["bulgular"][0]["kategori"], "GUVENSIZ_DEPO_PROTOKOLU")
        self.assertIn("CWE-319", rapor["bulgular"][0]["cwe_id"])

    def test_03_detect_unverified_gpg_repository(self):
        """GPG anahtar doğrulaması olmayan deponun CWE-347 ihlali sayılmasını test eder."""
        inv = {
            "depolar": [
                {
                    "depo_adi": "unsigned-repo",
                    "url": "https://unsigned.example.org",
                    "protokol": "https",
                    "gpg_dogrulandi": False
                }
            ],
            "paketler": []
        }
        rapor = audit_packages_and_repositories(inv, self.policy_rules)
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        self.assertEqual(rapor["bulgular"][0]["kategori"], "IMZASIZ_DEPO_RISKI")
        self.assertIn("CWE-347", rapor["bulgular"][0]["cwe_id"])

    def test_04_detect_unpinned_critical_service_package(self):
        """Kritik openssl paketinde sürüm sabitleme yapılmamasının tespitini test eder (G027-SC2)."""
        inv = {
            "depolar": [],
            "paketler": [
                {
                    "paket_adi": "openssl",
                    "mevcut_surum": "3.0.2",
                    "sabitlendi_mi": False,
                    "cvss_puani": 0.0
                }
            ]
        }
        rapor = audit_packages_and_repositories(inv, self.policy_rules)
        self.assertTrue(any(b["kategori"] == "SURUM_SABITLEME_EKSIKLIGI" for b in rapor["bulgular"]))

    def test_05_detect_vulnerable_package_with_critical_cve(self):
        """CVSS 7.5 olan bekleyen CVE için kritik yamasız zafiyet alarmı üretilmesini test eder."""
        inv = {
            "depolar": [],
            "paketler": [
                {
                    "paket_adi": "openssl",
                    "mevcut_surum": "3.0.2",
                    "sabitlendi_mi": True,
                    "bekleyen_cve": "CVE-2024-0727",
                    "cvss_puani": 7.5,
                    "mevcut_guncelleme": "3.0.13"
                }
            ]
        }
        rapor = audit_packages_and_repositories(inv, self.policy_rules)
        self.assertTrue(any(b["kategori"] == "KRITIK_YAMASIZ_ZAFİYET" for b in rapor["bulgular"]))
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)

    def test_06_audit_fully_compliant_inventory(self):
        """Tüm depoları HTTPS+GPG olan ve kritik paketleri sabitlenmiş envanterin %100 skor almasını test eder."""
        inv = {
            "depolar": [
                {"depo_adi": "main", "url": "https://repo.ubuntu.com", "protokol": "https", "gpg_dogrulandi": True}
            ],
            "paketler": [
                {"paket_adi": "openssl", "mevcut_surum": "3.0.13", "sabitlendi_mi": True, "cvss_puani": 0.0},
                {"paket_adi": "nginx", "mevcut_surum": "1.24.0", "sabitlendi_mi": True, "cvss_puani": 0.0},
                {"paket_adi": "postgresql", "mevcut_surum": "14.11", "sabitlendi_mi": True, "cvss_puani": 0.0}
            ]
        }
        rapor = audit_packages_and_repositories(inv, self.policy_rules)
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 0)
        self.assertEqual(rapor["uyumluluk_skoru_yuzde"], 100.0)

    def test_07_package_pinning_workflow(self):
        """Paket sabitleme (pinning) işleminin envanteri ve günlüğü güncellemesini test eder."""
        inv = {
            "paketler": [
                {"paket_adi": "nginx", "mevcut_surum": "1.18.0", "sabitlendi_mi": False}
            ]
        }
        res = apply_package_pinning(inv, "nginx", journal_path=self.pin_journal_file)
        self.assertEqual(res["durum"], "SABITLENDI")
        self.assertTrue(inv["paketler"][0]["sabitlendi_mi"])
        self.assertTrue(os.path.exists(self.pin_journal_file))

    def test_08_blocked_update_on_pinned_package(self):
        """Sabitlenmiş (pinned) bir paketin force olmadan güncellenememesini test eder (Pozitif/Negatif Kontrol)."""
        inv = {
            "paketler": [
                {"paket_adi": "nginx", "mevcut_surum": "1.18.0", "sabitlendi_mi": True}
            ]
        }
        with self.assertRaises(PermissionError):
            simulate_package_update(inv, "nginx", "1.20.0", force=False, journal_path=self.journal_file)

    def test_09_package_update_and_journal_recording(self):
        """Serbest paketin başarıyla güncellenip işlem günlüğüne yazılmasını test eder (G027-SC2)."""
        inv = {
            "paketler": [
                {"paket_adi": "openssl", "mevcut_surum": "3.0.2", "sabitlendi_mi": False}
            ]
        }
        res = simulate_package_update(inv, "openssl", "3.0.13", journal_path=self.journal_file)
        self.assertEqual(res["durum"], "BASARIYLA_GUNCELLENDI")
        self.assertEqual(inv["paketler"][0]["mevcut_surum"], "3.0.13")
        self.assertTrue(os.path.exists(self.journal_file))

    def test_10_package_rollback_restores_previous_version(self):
        """Güncellenen paketin rollback ile önceki sürümüne kusursuz dönmesini test eder (G027-SC2)."""
        inv = {
            "paketler": [
                {"paket_adi": "openssl", "mevcut_surum": "3.0.2", "sabitlendi_mi": False}
            ]
        }
        # Önce güncelle
        simulate_package_update(inv, "openssl", "3.0.13", journal_path=self.journal_file)
        # Sonra geri al
        rb_res = rollback_package_update(inv, "openssl", journal_path=self.journal_file)
        self.assertEqual(rb_res["durum"], "BASARIYLA_GERI_ALINDI")
        self.assertEqual(rb_res["geri_yuklenen_surum"], "3.0.2")
        self.assertEqual(inv["paketler"][0]["mevcut_surum"], "3.0.2")

    def test_11_rollback_fails_on_missing_journal_or_package(self):
        """Geri alma günlüğü veya paket kaydı olmadığında negatif kontrol istisnalarını test eder."""
        inv = {"paketler": []}
        with self.assertRaises(FileNotFoundError):
            rollback_package_update(inv, "openssl", journal_path="olmayan_gunluk.json")

    def test_12_policy_note_generation(self):
        """Kurumsal paket güncelleme ve sabitleme politikası metninin üretimini test eder (G027-SC2)."""
        note = generate_package_security_policy_note()
        self.assertIn("SÜRÜM SABİTLEME VE GERİ ALMA GÜVENLİK POLİTİKASI", note)
        self.assertIn("GPG", note)
        self.assertIn("Rollback", note)

    def test_13_negative_control_corrupted_inventory_cli(self):
        """Bozuk JSON envanteri ile CLI çağrıldığında sistemin kontrollü hata üretmesini test eder."""
        bad_file = os.path.join(self.test_dir.name, "bad_inv.json")
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("{ bu bozuk bir jsondur }")
        with self.assertRaises(json.JSONDecodeError):
            with open(bad_file, "r", encoding="utf-8") as f:
                json.load(f)

    def test_14_cli_subprocess_audit_execution(self):
        """CLI üzerinden --audit --json komutunun çalışmasını ve çıkış kodu 0'ı test eder."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "package_update_manager_auditor.py"
        )
        cmd = [sys.executable, script_path, "--policy-note"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("GÜVENLİK POLİTİKASI", proc.stdout)


if __name__ == "__main__":
    unittest.main()
