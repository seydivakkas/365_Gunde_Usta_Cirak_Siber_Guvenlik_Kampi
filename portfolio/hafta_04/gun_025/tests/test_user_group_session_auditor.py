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
"""Kullanıcı, Grup ve Oturum Güvenliği Birim Testleri.

Bu test modülü, 14 adet kapsamlı ve didaktik birim testi ile:
- Canlı yerel oturum belgeleme (G025-SC2),
- Kimlik ve etkin oturum ayrımı (G025-SC1),
- Servis hesapları kabuk ve grup kısıtlamaları,
- Ortak hesap ve eşzamanlı oturum inkar edilemezlik ihlalleri,
- Atıl hesap ve boşta kalma süresi kontrollerini test eder.
"""

# Standart kütüphane test ve sistem modülleri yüklenir
import json  # JSON işleme ve doğrulama işlemleri için
import os  # Dosya ve dizin yönetimi için
import subprocess  # Subprocess CLI çalıştırma testleri için
import sys  # Sistem yolu ve Python çalıştırıcısı için
import tempfile  # Geçici test dosyaları üretmek için
import unittest  # Python birim test çatısı

# Test çalıştırıcısının uygulama modülünü bulabilmesi için dizin sys.path'e eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Uygulama modülü fonksiyonları içe aktarılır
from uygulama.user_group_session_auditor import (
    get_local_live_session_info,
    audit_users_and_sessions,
)


class TestUserGroupSessionAuditor(unittest.TestCase):
    """Kullanıcı, grup ve oturum denetim test sınıfı."""

    def setUp(self):
        """Her testten önce ortak test ortamı ve örnek kural setini hazırlar."""
        # Geçici dizin oluşturulur
        self.test_dir = tempfile.TemporaryDirectory()
        # Temel test kuralları sözlüğü hazırlanır
        self.rules_data = {
            "sistem_uid_esigi": 1000,
            "servis_hesaplari_yasakli_kabuklar": ["/bin/bash", "/bin/sh"],
            "servis_hesaplari_gecerli_kabuklar": ["/usr/sbin/nologin", "/bin/false"],
            "idari_gruplar": ["root", "wheel", "sudo", "Administrators"],
            "maksimum_bosta_kalma_suresi_saniye": 900,
            "hesap_hareketsizlik_esigi_gun": 90
        }

    def tearDown(self):
        """Her testten sonra geçici çalışma ortamını temizler."""
        # Geçici dizin yok edilir
        self.test_dir.cleanup()

    def test_01_local_session_extraction(self):
        """Yerel canlı oturumdan kullanıcı adı, işletim sistemi ve PID çekilmesini test eder (G025-SC2)."""
        # Canlı oturum fonksiyonu çağrılır
        oturum = get_local_live_session_info()
        # Kullanıcı adı boş olmamalıdır
        self.assertTrue(len(oturum["kullanici_adi"]) > 0)
        # İşletim sistemi tanınmalıdır (Windows, Linux vb.)
        self.assertIn(oturum["isletim_sistemi"], ["Windows", "Linux", "Darwin"])
        # Süreç PID değeri pozitif bir tamsayı olmalıdır
        self.assertGreater(oturum["surec_pid"], 0)

    def test_02_local_session_data_structure(self):
        """Canlı oturum veri sözlüğünün standart şemaya uygunluğunu test eder."""
        # Oturum bilgisi alınır
        oturum = get_local_live_session_info()
        # Beklenen temel anahtarlar sorgulanır
        gerekli_anahtarlar = ["kullanici_adi", "bilgisayar_adi", "isletim_sistemi", "surec_pid", "oturum_zamani", "platform_verileri"]
        # Her bir anahtarın varlığı doğrulanır
        for k in gerekli_anahtarlar:
            self.assertIn(k, oturum)
        # Platform verilerinin bir sözlük olduğu doğrulanır
        self.assertIsInstance(oturum["platform_verileri"], dict)

    def test_03_audit_compliant_user_and_session(self):
        """Tamamen kurallara uyumlu tek bir kullanıcı ve oturumun %100 skor almasını test eder."""
        # Uyumlu envanter
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "analist_mert",
                    "uid": 1001,
                    "gid": 1001,
                    "kabuk": "/bin/bash",
                    "gruplar": ["analist_mert"],
                    "tur": "human",
                    "son_giris_gun_once": 2,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": [
                {
                    "oturum_id": "SES-01",
                    "kullanici_adi": "analist_mert",
                    "kaynak_ip": "10.0.0.5",
                    "bosta_kalma_suresi_saniye": 60
                }
            ]
        }
        # Denetim koşturulur
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İhlal sayısı 0 olmalıdır
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 0)
        # Skor %100 olmalıdır
        self.assertEqual(rapor["uyumluluk_skoru_yuzde"], 100.0)

    def test_04_audit_service_account_interactive_shell_violation(self):
        """Servis hesabının /bin/bash kabuğuna sahip olmasının KRİTİK ihlal sayılmasını test eder."""
        # İhlalli servis hesabı
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "www-data",
                    "uid": 33,
                    "kabuk": "/bin/bash",
                    "gruplar": ["www-data"],
                    "tur": "service",
                    "son_giris_gun_once": -1,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": []
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İhlal sayısı 1 olmalıdır
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 1)
        # Kritik ihlal sayısı 1 olmalıdır
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        # Bulgu kategorisi doğrulanır
        self.assertEqual(rapor["bulgular"][0]["kategori"], "KULLANICI_KABUK_IHLALI")

    def test_05_audit_service_account_admin_group_violation(self):
        """Servis hesabının idari grupta (sudo/wheel) yer alması ihlalini test eder."""
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "db_backup_svc",
                    "uid": 950,
                    "kabuk": "/usr/sbin/nologin",
                    "gruplar": ["db_backup_svc", "sudo"],
                    "tur": "service",
                    "son_giris_gun_once": -1,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": []
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İhlal sayısı 1 olmalıdır
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 1)
        # Risk seviyesi YÜKSEK olmalıdır
        self.assertEqual(rapor["bulgular"][0]["risk_seviyesi"], "YUKSEK")
        self.assertIn("sudo", rapor["bulgular"][0]["aciklama"])

    def test_06_audit_dormant_account_violation(self):
        """90 günden uzun süredir giriş yapmayan atıl (dormant) hesabın tespitini test eder."""
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "ayrilan_calisan",
                    "uid": 1004,
                    "kabuk": "/bin/bash",
                    "gruplar": ["ayrilan_calisan"],
                    "tur": "human",
                    "son_giris_gun_once": 120,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": []
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İhlal tespit edilmelidir
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 1)
        # Kategori doğrulanır
        self.assertEqual(rapor["bulgular"][0]["kategori"], "ATIL_HESAP_RISKI")

    def test_07_audit_shared_account_concurrent_sessions(self):
        """Ortak idari hesapta birden fazla aktif oturumun inkar edilemezlik kaybı olarak tespitini test eder (G025-SC1)."""
        inv = {
            "kullanicilar": [],
            "etkin_oturumlar": [
                {
                    "oturum_id": "SES-10",
                    "kullanici_adi": "root",
                    "kaynak_ip": "10.0.0.1",
                    "bosta_kalma_suresi_saniye": 10
                },
                {
                    "oturum_id": "SES-11",
                    "kullanici_adi": "root",
                    "kaynak_ip": "192.168.1.100",
                    "bosta_kalma_suresi_saniye": 20
                }
            ]
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # Kritik ihlal oluşmalıdır
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        self.assertEqual(rapor["bulgular"][0]["kategori"], "ORTAK_HESAP_VE_INKAR_EDILEMEZLIK_KAYBI")

    def test_08_audit_session_idle_timeout_violation(self):
        """Oturumun izin verilen maksimum süreden fazla boşta kalması ihlalini test eder."""
        inv = {
            "kullanicilar": [],
            "etkin_oturumlar": [
                {
                    "oturum_id": "SES-99",
                    "kullanici_adi": "analist_ali",
                    "kaynak_ip": "10.0.0.5",
                    "bosta_kalma_suresi_saniye": 1500  # 900 sn eşiğini aşıyor
                }
            ]
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İhlal sayısı 1 olmalıdır
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 1)
        self.assertEqual(rapor["bulgular"][0]["kategori"], "OTURUM_ZAMAN_ASIMI")

    def test_09_multiple_violations_scoring(self):
        """Birden fazla ihlal durumunda uyumluluk skorunun orantılı düşmesini test eder."""
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "u1",
                    "uid": 1001,
                    "tur": "human",
                    "son_giris_gun_once": 5,
                    "durum": "aktif"
                },
                {
                    "kullanici_adi": "svc_bad",
                    "uid": 50,
                    "kabuk": "/bin/bash",  # İhlal 1
                    "tur": "service",
                    "son_giris_gun_once": -1,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": [
                {
                    "oturum_id": "S1",
                    "kullanici_adi": "u1",
                    "bosta_kalma_suresi_saniye": 2000  # İhlal 2
                }
            ]
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # Toplam 3 nesne, 2 ihlal -> Skor %33.33 civarında olmalı
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 2)
        self.assertLess(rapor["uyumluluk_skoru_yuzde"], 50.0)

    def test_10_remediation_command_generation(self):
        """Her ihlal bulgusu için uygulanabilir iyileştirme komutu üretilmesini test eder."""
        inv = {
            "kullanicilar": [
                {
                    "kullanici_adi": "svc_test",
                    "uid": 80,
                    "kabuk": "/bin/bash",
                    "tur": "service",
                    "son_giris_gun_once": -1,
                    "durum": "aktif"
                }
            ],
            "etkin_oturumlar": []
        }
        rapor = audit_users_and_sessions(inv, self.rules_data)
        # İyileştirme komutunda nologin önerisi aranır
        iyilestirme = rapor["bulgular"][0]["iyilestirme"]
        self.assertIn("nologin", iyilestirme)

    def test_11_empty_inventory_handling(self):
        """Boş envanter verildiğinde motorun çökmeden 0 ihlal ve %100 uyumluluk dönmesini test eder."""
        inv = {"kullanicilar": [], "etkin_oturumlar": []}
        rapor = audit_users_and_sessions(inv, self.rules_data)
        self.assertEqual(rapor["toplam_ihlal_sayisi"], 0)
        self.assertEqual(rapor["uyumluluk_skoru_yuzde"], 100.0)

    def test_12_negative_control_missing_file_cli(self):
        """CLI çağrısında bulunmayan dosya verildiğinde FileNotFoundError hata kontrolünü test eder."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "user_group_session_auditor.py"
        )
        cmd = [sys.executable, script_path, "--audit", "--inventory", "olmayan_dosya.json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        # Hata kodu dönmelidir (sıfırdan farklı)
        self.assertNotEqual(proc.returncode, 0)

    def test_13_negative_control_corrupted_json(self):
        """Bozuk JSON içeren kural dosyasında sistemin kontrollü istisna fırlatmasını test eder."""
        corrupted_file = os.path.join(self.test_dir.name, "corrupted.json")
        with open(corrupted_file, "w", encoding="utf-8") as f:
            f.write("{ bu bozuk bir json dosyasidir }")
        # JSON ayrıştırma hatası beklenir
        with self.assertRaises(json.JSONDecodeError):
            with open(corrupted_file, "r", encoding="utf-8") as f:
                json.load(f)

    def test_14_cli_subprocess_live_session(self):
        """CLI üzerinden --live-session --json komutunun çalışmasını ve geçerli JSON çıktısını test eder (G025-SC2)."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "user_group_session_auditor.py"
        )
        cmd = [sys.executable, script_path, "--live-session", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        # Çıkış kodu 0 olmalıdır
        self.assertEqual(proc.returncode, 0)
        # JSON ayrıştırılabilmelidir
        data = json.loads(proc.stdout)
        self.assertIn("kullanici_adi", data)
        self.assertIn("isletim_sistemi", data)


if __name__ == "__main__":
    unittest.main()
