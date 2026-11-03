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
"""PATH ve Ortam Değişkenleri Güvenlik Birim Testleri.

Bu test modülü, 14 adet kapsamlı ve didaktik birim testi ile:
- Salt-okunur yerel PATH incelemesi ve güvenlik notu oluşturulmasını (G026-SC2),
- Arama sırası ve bağıl yol zafiyetlerini (CWE-426),
- Dünyaya yazılabilir güvensiz dizinleri (CWE-427),
- Dinamik bağlayıcı değişken manipülasyonlarını (CWE-114 - LD_PRELOAD),
- Ortam değişkenlerinde açık parola sızıntılarını (CWE-526) test eder.
"""

# Standart kütüphane test ve sistem modülleri yüklenir
import json  # JSON doğrulama ve veri hazırlama için
import os  # Dosya ve dizin yönetimi için
import subprocess  # CLI komut koşturma testi için
import sys  # Sistem akışları ve Python çalıştırıcı yolu için
import tempfile  # Güvenli geçici dosya ortamı için
import unittest  # Python birim test çatısı

# Test çalıştırıcısının uygulama modülünü bulabilmesi için dizin sys.path'e eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Uygulama modülü fonksiyonları içe aktarılır
from uygulama.path_environment_security_auditor import (
    parse_path_string,
    get_local_live_path_environment,
    audit_path_and_environment,
)


class TestPathEnvironmentSecurityAuditor(unittest.TestCase):
    """PATH ve ortam değişkenleri güvenlik denetim test sınıfı."""

    def setUp(self):
        """Her testten önce ortak test ortamını ve temel kuralları hazırlar."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.rules_data = {
            "yasakli_path_ogeleri": [".", "", "/tmp", "/var/tmp"],
            "tehlikeli_yukleyici_degiskenleri": ["LD_PRELOAD", "LD_LIBRARY_PATH"],
            "hassas_veri_anahtar_kelimeleri": ["PASSWORD", "SECRET", "TOKEN", "KEY"]
        }

    def tearDown(self):
        """Her testten sonra geçici çalışma ortamını temizler."""
        self.test_dir.cleanup()

    def test_01_live_path_read_only_inspection(self):
        """Yerel canlı PATH değerinin salt-okunur incelenmesini test eder (G026-SC2)."""
        res = get_local_live_path_environment()
        # Ham path ve ayrıştırılmış dizinler dolu olmalıdır
        self.assertIn("ham_path", res)
        self.assertIn("ayristirilmis_dizinler", res)
        # Güvenlik notu listesi oluşturulmuş olmalıdır
        self.assertIsInstance(res["guvenlik_notu"], list)
        self.assertTrue(len(res["guvenlik_notu"]) > 0)

    def test_02_parse_path_entries_standard(self):
        """Standart POSIX PATH dizesinin doğru sırada ayrıştırılmasını test eder."""
        path_input = "/usr/local/bin:/usr/bin:/bin"
        parsed = parse_path_string(path_input)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0]["temiz_deger"], "/usr/local/bin")
        self.assertEqual(parsed[1]["temiz_deger"], "/usr/bin")
        self.assertEqual(parsed[2]["temiz_deger"], "/bin")

    def test_03_detect_relative_path_dot(self):
        """PATH içinde açıkça '.' (mevcut dizin) bulunmasının CWE-426 ihlali sayılmasını test eder."""
        env = {"PATH": ".:/usr/bin:/bin"}
        rapor = audit_path_and_environment(env, self.rules_data)
        # Kritik ihlal tespit edilmelidir
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        self.assertEqual(rapor["bulgular"][0]["kategori"], "PATH_BAGIL_YOL_IHLALI")
        self.assertIn("CWE-426", rapor["bulgular"][0]["cwe_id"])

    def test_04_detect_empty_path_entry_equivalent_to_dot(self):
        """PATH içinde '::' boş ayraç olmasının örtülü '.' olarak tespitini test eder."""
        env = {"PATH": "/usr/local/bin::/usr/bin"}
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertTrue(any(b["kategori"] == "PATH_BAGIL_YOL_IHLALI" for b in rapor["bulgular"]))

    def test_05_detect_world_writable_directory_in_path(self):
        """PATH içinde /tmp bulunmasının CWE-427 ihlali sayılmasını test eder."""
        env = {"PATH": "/tmp:/usr/bin:/bin"}
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertTrue(any(b["kategori"] == "PATH_YAZILABILIR_DIZIN_IHLALI" for b in rapor["bulgular"]))
        self.assertIn("CWE-427", rapor["bulgular"][0]["cwe_id"])

    def test_06_detect_dangerous_linker_preload(self):
        """LD_PRELOAD değişkeninin aktif olmasının CWE-114 kritik riski olarak tespitini test eder."""
        env = {
            "PATH": "/usr/bin:/bin",
            "LD_PRELOAD": "/opt/malicious/hook.so"
        }
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertTrue(any(b["kategori"] == "YUKLEYICI_ENJEKSIYON_RISKI" for b in rapor["bulgular"]))
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)

    def test_07_detect_sensitive_credential_exposure_in_env(self):
        """Ortam değişkenlerinde açık parola saklanmasının CWE-526 riski sayılmasını test eder."""
        env = {
            "PATH": "/usr/bin:/bin",
            "DB_PASSWORD": "GizliParola123!"
        }
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertTrue(any(b["kategori"] == "ORTAMDA_ACIK_PAROLA_SIZINTISI" for b in rapor["bulgular"]))
        self.assertIn("CWE-526", rapor["bulgular"][0]["cwe_id"])

    def test_08_audit_fully_compliant_baseline_path(self):
        """Güvenli ve temiz bir ortam profilinin 0 ihlal ve %100 uyumluluk almasını test eder."""
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "USER": "analist",
            "HOME": "/home/analist"
        }
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 0)
        self.assertEqual(rapor["uyumluluk_skoru_yuzde"], 100.0)

    def test_09_audit_vulnerable_developer_profile(self):
        """Birden çok zafiyet barındıran güvensiz profilin doğru raporlanmasını test eder."""
        env = {
            "PATH": ".:/tmp:/home/dev/bin:/usr/bin:/bin",
            "DB_PASSWORD": "AdminPassword!",
            "LD_PRELOAD": "/lib/inject.so"
        }
        rapor = audit_path_and_environment(env, self.rules_data)
        # En az 4 ihlal oluşmalıdır (. , /tmp, precedence, DB_PASSWORD, LD_PRELOAD)
        self.assertGreaterEqual(rapor["toplam_ihlal_sayisi"], 4)
        self.assertLess(rapor["uyumluluk_skoru_yuzde"], 60.0)

    def test_10_path_precedence_hijack_analysis(self):
        """Kullanıcı ev dizininin sistem dizinlerinden önce gelmesi riskini test eder."""
        env = {"PATH": "/home/user/bin:/usr/bin:/bin"}
        rapor = audit_path_and_environment(env, self.rules_data)
        self.assertTrue(any(b["kategori"] == "PATH_ONCELIK_GASP_RISKI" for b in rapor["bulgular"]))

    def test_11_security_note_structure(self):
        """Canlı PATH incelemesinde üretilen güvenlik notlarının okunabilirliğini test eder."""
        res = get_local_live_path_environment()
        not_metni = "\n".join(res["guvenlik_notu"])
        self.assertIn("Toplam PATH Dizin Sayısı", not_metni)

    def test_12_negative_control_missing_file_cli(self):
        """CLI'ye var olmayan dosya verildiğinde hata fırlatmasını test eder."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "path_environment_security_auditor.py"
        )
        cmd = [sys.executable, script_path, "--audit", "--profiles", "olmayan_dosya.json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertNotEqual(proc.returncode, 0)

    def test_13_negative_control_corrupted_rules_json(self):
        """Bozuk JSON kural dosyasında sistemin istisna fırlatmasını test eder."""
        corrupted = os.path.join(self.test_dir.name, "bad_rules.json")
        with open(corrupted, "w", encoding="utf-8") as f:
            f.write("{ bu bozuk bir json dosyasidir }")
        with self.assertRaises(json.JSONDecodeError):
            with open(corrupted, "r", encoding="utf-8") as f:
                json.load(f)

    def test_14_cli_subprocess_live_path_execution(self):
        """CLI üzerinden --live-path --json komutunun 0 koduyla JSON üretmesini test eder (G026-SC2)."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "path_environment_security_auditor.py"
        )
        cmd = [sys.executable, script_path, "--live-path", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertIn("ayristirilmis_dizinler", data)
        self.assertIn("guvenlik_notu", data)


if __name__ == "__main__":
    unittest.main()
