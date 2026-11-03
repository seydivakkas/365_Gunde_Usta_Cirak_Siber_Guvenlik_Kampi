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
"""Linux Dosya İzinleri RWX Denetim ve Geri Alma Birim Testleri.

Bu test modülü, 14 adet didaktik ve kapsamlı birim testi ile:
- POSIX rwx bit düzeyinde dönüşümleri,
- SUID/SGID/Sticky bit özel durumlarını,
- Umask matematiksel hesaplamalarını,
- CWE-732 ihlallerini ve uyumluluk raporlamasını,
- G024-SC2 kontrollü chmod değişikliğini ve geri alma (rollback) döngüsünü test eder.
"""

# Standart kütüphane test ve sistem modülleri yüklenir
import json  # JSON doğrulama ve veri hazırlama için
import os  # Dosya ve dizin yönetimi için
import subprocess  # CLI komut çalıştırma testi için
import sys  # Python yürütücüsü yolu ve sistem akışları için
import tempfile  # Güvenli geçici dosya oluşturmak için
import unittest  # Python standart birim test çatısı

# Test çalıştırıcısının uygulama modülünü bulabilmesi için dizin sys.path'e eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Uygulama modülü fonksiyonları içe aktarılır
from uygulama.linux_permission_rwx_auditor import (
    parse_octal_mode,
    octal_to_symbolic,
    symbolic_to_octal,
    calculate_umask_permissions,
    audit_permissions,
    execute_permission_change,
    rollback_permission_change,
)


class TestLinuxPermissionRwxAuditor(unittest.TestCase):
    """Linux RWX izinleri ve geri alma mekanizması test sınıfı."""

    def setUp(self):
        """Her testten önce ortak test ortamını hazırlar."""
        # Geçici bir çalışma dizini oluşturulur
        self.test_dir = tempfile.TemporaryDirectory()
        # Test için kullanılacak geçici dosya yolu belirlenir
        self.sample_file = os.path.join(self.test_dir.name, "lab_test_file.txt")
        # Dosya diske yazılır
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write("G024 RWX Test Dosyasi - Gizli Bilgi Yoktur.\n")
        # Geçici geri alma günlüğü yolu belirlenir
        self.journal_file = os.path.join(self.test_dir.name, "test_journal.json")

    def tearDown(self):
        """Her testten sonra geçici çalışma ortamını temizler."""
        # Geçici dizin ve içindekiler yok edilir
        self.test_dir.cleanup()

    def test_01_octal_to_symbolic_standard(self):
        """Standart 0755, 0644 ve 0600 izinlerinin sembolik dönüşümünü test eder."""
        # 0755 izni kullanıcı rwx, grup rx, diğerleri rx olmalıdır
        res_755 = octal_to_symbolic("0755")
        # Sonuç doğrulanır
        self.assertEqual(res_755, "-rwxr-xr-x")
        # 0644 izni kullanıcı rw, grup r, diğerleri r olmalıdır
        res_644 = octal_to_symbolic("0644")
        # Sonuç doğrulanır
        self.assertEqual(res_644, "-rw-r--r--")
        # 0600 izni yalnızca kullanıcı rw olmalıdır
        res_600 = octal_to_symbolic("0600")
        # Sonuç doğrulanır
        self.assertEqual(res_600, "-rw-------")

    def test_02_special_permissions_suid_sgid_sticky(self):
        """SUID (4000), SGID (2000) ve Sticky (1000) bitlerinin sembolik temsilini test eder."""
        # SUID aktif (4755) iken kullanıcı çalıştırma biti 's' olmalıdır
        res_suid = octal_to_symbolic("4755")
        # Sonuç kontrol edilir
        self.assertEqual(res_suid, "-rwsr-xr-x")
        # SGID aktif (2755) iken grup çalıştırma biti 's' olmalıdır
        res_sgid = octal_to_symbolic("2755")
        # Sonuç kontrol edilir
        self.assertEqual(res_sgid, "-rwxr-sr-x")
        # Sticky bit aktif (1777) ve dizin iken diğerleri çalıştırma biti 't' olmalıdır
        res_sticky = octal_to_symbolic("1777", is_directory=True)
        # Sonuç kontrol edilir
        self.assertEqual(res_sticky, "drwxrwxrwt")

    def test_03_symbolic_to_octal_standard(self):
        """Sembolik dizelerin standart oktal karşılıklarına çevrilmesini test eder."""
        # '-rwxr-xr-x' -> '0755'
        res_755 = symbolic_to_octal("-rwxr-xr-x")
        # Eşitlik kontrol edilir
        self.assertEqual(res_755, "0755")
        # 'rw-r--r--' -> '0644'
        res_644 = symbolic_to_octal("rw-r--r--")
        # Eşitlik kontrol edilir
        self.assertEqual(res_644, "0644")
        # '-rw-------' -> '0600'
        res_600 = symbolic_to_octal("-rw-------")
        # Eşitlik kontrol edilir
        self.assertEqual(res_600, "0600")

    def test_04_symbolic_to_octal_special_bits(self):
        """Sembolik gösterimdeki SUID ve Sticky bitlerin oktal değerini test eder."""
        # 'rwsr-xr-x' SUID içerir (4755)
        res_suid = symbolic_to_octal("rwsr-xr-x")
        # Sonuç kontrolü
        self.assertEqual(res_suid, "4755")
        # 'rwxrwxrwt' Sticky bit içerir (1777)
        res_sticky = symbolic_to_octal("rwxrwxrwt")
        # Sonuç kontrolü
        self.assertEqual(res_sticky, "1777")

    def test_05_umask_022_calculation(self):
        """Standart umask 022 için dosya ve dizin izin türetimini test eder."""
        # Umask 022 hesaplanır
        res = calculate_umask_permissions("022")
        # Dosya için 0666 & ~022 = 0644 olmalıdır
        self.assertEqual(res["dosya_varsayilan_izin"], "0644")
        # Dizin için 0777 & ~022 = 0755 olmalıdır
        self.assertEqual(res["dizin_varsayilan_izin"], "0755")
        # Güvenlik durumu true olmalıdır
        self.assertTrue(res["guvenli_mi"])

    def test_06_umask_027_hardened_calculation(self):
        """Güçlendirilmiş umask 027 (CIS Benchmark tavsiyesi) hesaplamasını test eder."""
        # Umask 027 hesaplanır
        res = calculate_umask_permissions("027")
        # Dosya için 0666 & ~027 = 0640 olmalıdır
        self.assertEqual(res["dosya_varsayilan_izin"], "0640")
        # Dizin için 0777 & ~027 = 0750 olmalıdır
        self.assertEqual(res["dizin_varsayilan_izin"], "0750")
        # Güvenlik durumu true olmalıdır
        self.assertTrue(res["guvenli_mi"])

    def test_07_insecure_umask_detection(self):
        """Tehlikeli umask 000 veya 002 durumunda güvenlik uyarısı üretilmesini test eder."""
        # Umask 000 hesaplanır
        res_000 = calculate_umask_permissions("000")
        # Güvenlik durumu False olmalıdır
        self.assertFalse(res_000["guvenli_mi"])
        # Risk açıklamalarında CWE-732 uyarısı aranır
        self.assertTrue(any("CWE-732" in r or "0000" in r for r in res_000["risk_aciklamalari"]))

    def test_08_audit_compliant_files(self):
        """Denetim motorunun uyumlu dosyaları doğru tanımasını test eder."""
        # Basit uyumlu envanter
        inv = {
            "dosyalar": [
                {
                    "dosya_yolu": "/etc/passwd",
                    "dosya_turu": "file",
                    "sahip": "root",
                    "grup": "root",
                    "mevcut_izin_oktal": "0644"
                }
            ]
        }
        # Kural seti
        rules = {
            "kurallar": [
                {
                    "kural_id": "R1",
                    "hedef_yol": "/etc/passwd",
                    "izin_verilen_en_fazla_oktal": "0644",
                    "onerilen_oktal": "0644",
                    "yasakli_bitler": ["o+w", "g+w"]
                }
            ]
        }
        # Denetim koşturulur
        rapor = audit_permissions(inv, rules)
        # Uyumlu sayısı 1 olmalıdır
        self.assertEqual(rapor["uyumlu_sayisi"], 1)
        # İhlal sayısı 0 olmalıdır
        self.assertEqual(rapor["ihlal_sayisi"], 0)
        # Uyumluluk oranı 100 olmalıdır
        self.assertEqual(rapor["uyumluluk_orani_yuzde"], 100.0)

    def test_09_audit_cwe732_world_writable_violation(self):
        """World-writable dosya tespitinde CWE-732 ihlali üretilmesini test eder."""
        # İhlalli envanter
        inv = {
            "dosyalar": [
                {
                    "dosya_yolu": "/var/log/syslog",
                    "dosya_turu": "file",
                    "sahip": "syslog",
                    "grup": "adm",
                    "mevcut_izin_oktal": "0666"
                }
            ]
        }
        # Kural seti
        rules = {
            "kurallar": [
                {
                    "kural_id": "R-LOG",
                    "hedef_yol": "/var/log/syslog",
                    "izin_verilen_en_fazla_oktal": "0640",
                    "onerilen_oktal": "0640",
                    "yasakli_bitler": ["o+w"],
                    "risk_seviyesi": "ORTA"
                }
            ]
        }
        # Denetim koşturulur
        rapor = audit_permissions(inv, rules)
        # İhlal sayısı 1 olmalıdır
        self.assertEqual(rapor["ihlal_sayisi"], 1)
        # Bulgu detayı incelenir
        b = rapor["bulgular"][0]
        # Uyumlu olmamalı
        self.assertFalse(b["uyumlu_mu"])
        # CWE-732 veya izin aşımı tespit edilmelidir
        self.assertTrue(any("CWE-732" in ih or "İzin aşımı" in ih for ih in b["ihlaller"]))

    def test_10_audit_shadow_sensitive_leak(self):
        """Kritik /etc/shadow dosyasının diğer kullanıcılarca okunabilmesi ihlalini test eder."""
        # /etc/shadow 0644 yapılmış tehlikeli senaryo
        inv = {
            "dosyalar": [
                {
                    "dosya_yolu": "/etc/shadow",
                    "dosya_turu": "file",
                    "sahip": "root",
                    "grup": "shadow",
                    "mevcut_izin_oktal": "0644"
                }
            ]
        }
        rules = {
            "kurallar": [
                {
                    "kural_id": "R-SHADOW",
                    "hedef_yol": "/etc/shadow",
                    "izin_verilen_en_fazla_oktal": "0640",
                    "onerilen_oktal": "0600",
                    "yasakli_bitler": ["o+r", "o+w"],
                    "risk_seviyesi": "KRITIK"
                }
            ]
        }
        rapor = audit_permissions(inv, rules)
        # Kritik ihlal sayısı 1 olmalıdır
        self.assertEqual(rapor["kritik_ihlal_sayisi"], 1)
        # Risk seviyesi KRITIK olmalıdır
        self.assertEqual(rapor["bulgular"][0]["risk_seviyesi"], "KRITIK")

    def test_11_execute_permission_change_and_journal(self):
        """Kontrollü chmod değişikliği ve günlük (journal) oluşturulmasını test eder (G024-SC2)."""
        # İlk olarak dosya izni 0600 yapılır
        os.chmod(self.sample_file, 0o0600)
        # Fonksiyon çağrılarak dosya izni 0644 yapılır
        res = execute_permission_change(
            self.sample_file,
            "0644",
            actor="test-analyst",
            reason="laboratuvar-testi",
            journal_path=self.journal_file
        )
        # Dönen kayıt incelenir
        self.assertEqual(res["durum"], "UYGULANDI")
        self.assertEqual(res["yeni_izin_oktal"], "0644")
        # Günlük dosyasının oluştuğu doğrulanır
        self.assertTrue(os.path.exists(self.journal_file))
        # Günlük içeriği doğrulanır
        with open(self.journal_file, "r", encoding="utf-8") as jf:
            jdata = json.load(jf)
        self.assertEqual(len(jdata), 1)
        self.assertEqual(jdata[0]["islem_yapan"], "test-analyst")

    def test_12_rollback_permission_change_cycle(self):
        """Chmod değişikliğinin geri alınarak orijinal izne dönülmesini test eder (G024-SC2)."""
        # 1. Başlangıç izni 0600 olarak ayarlanır ve değişiklik günlüğe işlenir
        execute_permission_change(
            self.sample_file,
            "0644",
            actor="analist-01",
            reason="gecici-yetki",
            journal_path=self.journal_file,
            initial_mode="0600"
        )
        # 2. Geri alma (Rollback) fonksiyonu çalıştırılır
        rb_res = rollback_permission_change(journal_path=self.journal_file, target_file=self.sample_file)
        # 3. Geri alma kaydı doğrulanır
        self.assertEqual(rb_res["durum"], "BASARIYLA_GERI_ALINDI")
        self.assertEqual(rb_res["geri_yuklenen_izin_oktal"], "0600")

    def test_13_rollback_negative_controls(self):
        """Geri alma günlüğü veya kayıt bulunamadığında negatif kontrol hata yönetimini test eder."""
        # Olmayan bir günlük dosyası ile rollback denenir
        with self.assertRaises(FileNotFoundError):
            rollback_permission_change(journal_path="olmayan_gunluk.json")

        # Boş bir günlük dosyası oluşturulur
        empty_journal = os.path.join(self.test_dir.name, "empty_journal.json")
        with open(empty_journal, "w", encoding="utf-8") as f:
            json.dump([], f)
        # Boş günlükle çağrıldığında ValueError fırlatmalıdır
        with self.assertRaises(ValueError):
            rollback_permission_change(journal_path=empty_journal)

    def test_14_cli_subprocess_execution(self):
        """CLI arayüzünün subprocess üzerinden çalışmasını ve çıkış kodunu test eder."""
        script_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "uygulama",
            "linux_permission_rwx_auditor.py"
        )
        # CLI umask testi icra edilir
        cmd = [sys.executable, script_path, "--umask", "027", "--json"]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        # Çıkış kodu 0 olmalıdır
        self.assertEqual(proc.returncode, 0)
        # Çıktı JSON olarak ayrıştırılabilir olmalıdır
        data = json.loads(proc.stdout)
        self.assertEqual(data["dosya_varsayilan_izin"], "0640")
        self.assertTrue(data["guvenli_mi"])


if __name__ == "__main__":
    unittest.main()
