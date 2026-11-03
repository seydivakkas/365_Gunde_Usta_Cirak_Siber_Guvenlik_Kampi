# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar yalnızca görüntüleme ve eğitim amaçlıdır.
# Siber Güvenlik 365 Gün Müfredatı - Gün 023 (Linux Terminali ve Kabuk)

"""Linux Kabuk ve Terminal Güvenlik Simülatörü Birim Test Paketi (Unit Tests).

Bu test paketi; POSIX kabuk komutlarının (pwd, cd, ls, cat, head) işlevselliğini,
göreceli yol tuzaklarını, dizin aşımı (CWE-22) risklerini, güvensiz PATH analizini (CWE-426)
ve CLI arayüzünü hem pozitif hem de negatif test senaryolarıyla doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır.
import unittest
# Dosya ve dizin işlemleri için os modülü içe aktarılır.
import os
# JSON formatlama ve doğrulama için json modülü içe aktarılır.
import json
# Geçici test dosyaları ve dizinleri için tempfile modülü içe aktarılır.
import tempfile
# Dizin ağacını temizlemek için shutil modülü içe aktarılır.
import shutil
# CLI alt süreç testleri için subprocess modülü içe aktarılır.
import subprocess
# Python yorumlayıcı yolunu almak için sys modülü içe aktarılır.
import sys

# Test edilecek simülatör sınıfı içe aktarılır.
from portfolio.hafta_04.gun_023.uygulama.linux_shell_security_simulator import LinuxShellSecuritySimulator


class TestLinuxShellSecuritySimulator(unittest.TestCase):
    """Gün 023 Linux Kabuk Güvenlik Simülatörü Test Sınıfı."""

    def setUp(self) -> None:
        """Her bir test öncesinde bağımsız geçici test ortamı ve simülatör nesnesini hazırlar."""
        # Geçici bir çalışma klasörü oluşturulur.
        self.test_dir = tempfile.mkdtemp()
        # Simülatör sınıfı varsayılan sanal dosya sistemiyle başlatılır.
        self.sim = LinuxShellSecuritySimulator()

    def tearDown(self) -> None:
        """Her testten sonra geçici test dosyalarını güvenli biçimde temizler."""
        # Geçici dizin mevcutsa temizlenir.
        if os.path.exists(self.test_dir):
            # Klasör ve içeriği silinir.
            shutil.rmtree(self.test_dir)

    def test_01_init_ve_varsayilan_dizin_yapisi(self) -> None:
        """Test 01: Sınıf başlatma, başlangıç dizini ve temel sanal ağacın doğrulanması."""
        # cwd'nin boş olmadığı doğrulanır.
        self.assertIsNotNone(self.sim.cwd)
        # Başlangıç dizini /home/analyst olmalıdır.
        self.assertEqual(self.sim.cwd, "/home/analyst")
        # Sanal dosya sisteminin varlığı kontrol edilir.
        self.assertIn("dizinler", self.sim.fs)
        # Dosyalar listesinin varlığı kontrol edilir.
        self.assertIn("dosyalar", self.sim.fs)

    def test_02_pwd_komutu_dogrulamasi(self) -> None:
        """Test 02: pwd komutunun mevcut çalışma dizinini eksiksiz döndürmesi."""
        # pwd çıktısı alınır.
        current_dir = self.sim.pwd()
        # Çıktı /home/analyst olmalıdır.
        self.assertEqual(current_dir, "/home/analyst")

    def test_03_cd_gecerli_dizin_degistirme(self) -> None:
        """Test 03: cd komutu ile mutlak ve göreceli dizin geçişlerinin doğrulanması."""
        # Mutlak yol ile /etc dizinine geçilir.
        new_dir = self.sim.cd("/etc")
        # Yeni dizin /etc olmalıdır.
        self.assertEqual(new_dir, "/etc")
        # pwd ile de doğrulanır.
        self.assertEqual(self.sim.pwd(), "/etc")

        # Göreceli '..' yolu ile kök dizine geçiş test edilir.
        up_dir = self.sim.cd("..")
        # Yeni dizin kök '/' olmalıdır.
        self.assertEqual(up_dir, "/")

    def test_04_cd_bulunamadi_negatif_kontrol(self) -> None:
        """Test 04: Var olmayan bir dizine geçilmek istendiğinde FileNotFoundError fırlatılması (Negatif Test)."""
        # Var olmayan dizine geçiş denenir.
        with self.assertRaises(FileNotFoundError):
            # cd komutu çağrılır.
            self.sim.cd("/var/olmayan_dizin")

    def test_05_cd_dosyaya_gitme_negatif_kontrol(self) -> None:
        """Test 05: Dizin yerine dosya yoluna cd yapılmak istendiğinde NotADirectoryError fırlatılması (Negatif Test)."""
        # Dosya yoluna cd denenir.
        with self.assertRaises(NotADirectoryError):
            # cd komutu çağrılır.
            self.sim.cd("/etc/passwd")

    def test_06_ls_mevcut_dizin_ve_ogeler(self) -> None:
        """Test 06: ls komutunun hedef dizin içeriğini tür, izin ve sahiplikle listelemesi."""
        # /home/analyst içeriği listelenir.
        items = self.sim.ls()
        # En az 1 öğe olmalıdır (notes.txt).
        self.assertGreaterEqual(len(items), 1)
        # notes.txt öğesi aranır.
        notes = [i for i in items if i["isim"] == "notes.txt"]
        # Öğenin varlığı onaylanır.
        self.assertEqual(len(notes), 1)
        # Türün FILE olduğu doğrulanır.
        self.assertEqual(notes[0]["tur"], "FILE")

    def test_07_ls_bulunamadi_negatif_kontrol(self) -> None:
        """Test 07: Var olmayan dizin listelenmek istendiğinde FileNotFoundError fırlatılması (Negatif Test)."""
        # Olmayan dizin listelenmeye çalışılır.
        with self.assertRaises(FileNotFoundError):
            # ls komutu çağrılır.
            self.sim.ls("/hayali_klasor")

    def test_08_cat_gecerli_dosya_okuma(self) -> None:
        """Test 08: cat komutunun dosya içeriğini eksiksiz döndürmesi."""
        # /etc/passwd dosyası okunur.
        content = self.sim.cat("/etc/passwd")
        # İçerikte root kullanıcısı aranır.
        self.assertIn("root:x:0:0", content)
        # İçerikte analyst kullanıcısı aranır.
        self.assertIn("analyst:x:1000", content)

    def test_09_cat_dosya_bulunamadi_negatif_kontrol(self) -> None:
        """Test 09: Var olmayan dosya cat ile istendiğinde FileNotFoundError fırlatılması (Negatif Test)."""
        # Olmayan dosya okunmaya çalışılır.
        with self.assertRaises(FileNotFoundError):
            # cat komutu çağrılır.
            self.sim.cat("/etc/olmayan_dosya.conf")

    def test_10_cat_dizine_uygulama_negatif_kontrol(self) -> None:
        """Test 10: Dizin yoluna cat komutu verildiğinde IsADirectoryError fırlatılması (Negatif Test)."""
        # /etc dizini okunmaya çalışılır.
        with self.assertRaises(IsADirectoryError):
            # cat komutu çağrılır.
            self.sim.cat("/etc")

    def test_11_head_satir_sayisi_sinirlama(self) -> None:
        """Test 11: head komutunun belirtilen satır adedi kadar veri döndürmesi."""
        # auth.log dosyasından ilk 2 satır istenir.
        output = self.sim.head("/var/log/auth.log", n=2)
        # Satırlar bölünür.
        lines = output.splitlines()
        # Satır adedi tam 2 olmalıdır.
        self.assertEqual(len(lines), 2)
        # İlk satırın sshd mesajı içerdiği kontrol edilir.
        self.assertIn("sshd", lines[0])

    def test_12_goreli_yol_ve_path_traversal_tespiti(self) -> None:
        """Test 12: Göreceli '../../' girdisinde Dizin Aşımı (CWE-22) riskinin tespit edilmesi (G023-SC1)."""
        # Şüpheli göreceli yol verilir.
        res = self.sim.audit_path_traversal("../../etc/shadow")
        # Risk seviyesinin YÜKSEK olduğu doğrulanır.
        self.assertEqual(res["risk_seviyesi"], "YUKSEK")
        # CWE-22 referansının yer aldığı onaylanır.
        self.assertIn("CWE-22", res["zafiyet"])

    def test_13_guvensiz_path_ortam_degiskeni_tespiti(self) -> None:
        """Test 13: PATH ortam değişkeninde '.' veya '/tmp' bulunduğunda KRİTİK risk tespiti (CWE-426)."""
        # Zafiyetli PATH dizesi oluşturulur (sonunda '.' var).
        vuln_path = "/usr/local/bin:/usr/bin:/bin:."
        # Analiz icra edilir.
        audit_res = self.sim.audit_path_environment(vuln_path)
        # Risk seviyesi KRİTİK olmalıdır.
        self.assertEqual(audit_res["risk_seviyesi"], "KRITIK")
        # En az 1 güvensiz girdi tespit edilmelidir.
        self.assertEqual(audit_res["guvensiz_girdi_sayisi"], 1)

    def test_14_tam_laboratuvar_akisi_ve_cli(self) -> None:
        """Test 14: 5 temel komutun (pwd, ls, cd, cat, head) sıralı laboratuvar akışının ve CLI'nin doğrulanması (G023-SC2)."""
        # Laboratuvar akışı çağrılır.
        lab_res = self.sim.run_full_lab_workflow()
        # 7 adımın tamamının üretildiği doğrulanır.
        self.assertIn("1_adim_pwd_baslangic", lab_res)
        self.assertIn("2_adim_ls_mevcut", lab_res)
        self.assertIn("3_adim_cd_hedef", lab_res)
        self.assertIn("4_adim_pwd_yeni", lab_res)
        self.assertIn("5_adim_head_log", lab_res)
        self.assertIn("6_adim_cat_notes", lab_res)
        self.assertIn("7_adim_head_passwd", lab_res)

        # CLI alt süreç testi
        script_path = os.path.join("portfolio", "hafta_04", "gun_023", "uygulama", "linux_shell_security_simulator.py")
        result = subprocess.run(
            [sys.executable, script_path, "--lab"],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        # CLI sıfır koduyla başarıyla tamamlanmalıdır.
        self.assertEqual(result.returncode, 0)
        # Çıktıda laboratuvar başlığı bulunmalıdır.
        self.assertIn("G023-SC2", result.stdout)


# Test suite doğrudan yürütme kontrolü
if __name__ == "__main__":
    unittest.main()
