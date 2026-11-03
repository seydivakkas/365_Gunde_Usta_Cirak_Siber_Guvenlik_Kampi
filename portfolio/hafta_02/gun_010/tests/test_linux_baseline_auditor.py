# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 010: Linux Sanal Makinesine Güvenli Başlangıç
Birim Testleri: test_linux_baseline_auditor.py

Bu test paketi; Linux Güvenlik Taban Çizgisi Denetleyicisinin
pozitif (CIS Seviye 1 sertleştirilmiş sistem), negatif (Root SSH, NOPASSWD, shadow ifşası, UFW kapalı)
ve hata yönetim sınır durumlarını %100 kapsama ile doğrular.
"""

import os
import sys
import json
import tempfile
import unittest

# Uygulama modülünü içe aktarabilmek için sistem arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../uygulama")))

# Denetleyici motor ve özel hata sınıfı içe aktarılıyor
from linux_baseline_auditor import LinuxBaselineAuditor, LinuxSecurityValidationError


class TestLinuxBaselineAuditor(unittest.TestCase):
    """
    Linux Güvenlik Taban Çizgisi Birim Test Paketi.
    """

    def setUp(self):
        """
        Her test öncesinde temiz, tam sertleştirilmiş bir temel Linux profili oluştur.
        """
        self.altin_sistem = {
            "sistem_id": "LINUX-TEST-SEC",
            "sistem_adi": "Test_Altin_Linux_VM",
            "dagitim": "Debian 12 Hardened",
            "hedef_rol": "İzole Güvenlik Test Düğümü",
            "guvenlik_seviyesi": "CIS_SEVIYE_1_HARDENED",
            "ssh_yapilandirmasi": {
                "port": 2222,
                "permit_root_login": "no",
                "password_authentication": "no",
                "pubkey_authentication": "yes",
                "max_auth_tries": 3,
                "x11_forwarding": "no",
                "allow_agent_forwarding": "no"
            },
            "kullanici_ve_yetki_yonetimi": {
                "root_oturum_kilitli": True,
                "sudoers_nopasswd_izinli": False,
                "sudo_yetki_kapsami": "Zorunlu_Parolali_Grup",
                "varsayilan_umask": "027",
                "parola_karma_algoritmasi": "yescrypt"
            },
            "dosya_sistemi_izinleri": {
                "etc_shadow": "0640",
                "etc_passwd": "0644",
                "etc_ssh_sshd_config": "0600",
                "root_ev_dizini": "0700"
            },
            "guvenlik_duvari_ufw": {
                "etkin": True,
                "varsayilan_gelen": "DENY",
                "varsayilan_giden": "ALLOW",
                "izinli_kurallar": [
                    {
                        "port": 2222,
                        "protokol": "tcp",
                        "kaynak": "192.168.56.0/24",
                        "hedef_eylem": "ALLOW"
                    }
                ]
            },
            "calisan_servisler": [
                "sshd",
                "chronyd",
                "fail2ban"
            ],
            "yasakli_guvensiz_servisler": []
        }

    def _gecici_profil_olustur(self, sistem_listesi):
        """
        Testler için geçici bir JSON dosyası üretir.
        """
        gecici = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"sistem_profilleri": sistem_listesi}, gecici)
        gecici.close()
        return gecici.name

    def test_01_cis_seviye_1_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: CIS Seviye 1 standartlarında sertleştirilmiş sistem
        denetlendiğinde 100/100 tam puan almalı, 0 bulgu üretmeli ve durumu 'GÜVENLİ' olmalıdır.
        """
        dosya_yolu = self._gecici_profil_olustur([self.altin_sistem])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(len(sonuclar), 1)
            self.assertEqual(sonuclar[0]["skor"], 100)
            self.assertEqual(sonuclar[0]["toplam_bulgu_sayisi"], 0)
            self.assertIn("GÜVENLİ", sonuclar[0]["risk_derecesi"])
        finally:
            os.remove(dosya_yolu)

    def test_02_permit_root_login_negatif_kontrol(self):
        """
        NEGATİF KONTROL: SSH'ta 'PermitRootLogin yes' açıldığında,
        doğrudan root kaba kuvvet riski nedeniyle KRİTİK bulgu üretilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["ssh_yapilandirmasi"]["permit_root_login"] = "yes"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)  # 35 ceza puanı
            self.assertTrue(any("PermitRootLogin yes" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_03_password_authentication_negatif_kontrol(self):
        """
        NEGATİF KONTROL: SSH'ta 'PasswordAuthentication yes' yapıldığında,
        parola kaba kuvvet saldırısı riski YÜKSEK seviye olarak raporlanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["ssh_yapilandirmasi"]["password_authentication"] = "yes"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)  # 25 ceza puanı
            self.assertTrue(any("PasswordAuthentication yes" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_04_sudoers_nopasswd_felaket_kontrol(self):
        """
        NEGATİF KONTROL: /etc/sudoers dosyasında 'NOPASSWD' açıldığında,
        doğrudan yetki yükseltme (LPE) tehlikesi nedeniyle FELAKET seviyesinde 50 puan ceza kesilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["kullanici_ve_yetki_yonetimi"]["sudoers_nopasswd_izinli"] = True

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("NOPASSWD", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_05_etc_shadow_izin_felaket_kontrol(self):
        """
        NEGATİF KONTROL: /etc/shadow dosyasının izinleri '0644' yapıldığında,
        parola hashlerinin dünya tarafından okunması FELAKET seviyesinde yakalanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["dosya_sistemi_izinleri"]["etc_shadow"] = "0644"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("/etc/shadow", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_06_etc_passwd_yazilabilir_felaket_kontrol(self):
        """
        NEGATİF KONTROL: /etc/passwd dosyası '0777' (herkes yazabilir) yapıldığında,
        yeni UID 0 kullanıcısı ekleme riski FELAKET seviyesinde engellenmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["dosya_sistemi_izinleri"]["etc_passwd"] = "0777"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("/etc/passwd", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_07_ufw_kapali_negatif_kontrol(self):
        """
        NEGATİF KONTROL: UFW güvenlik duvarı kapatıldığında ('etkin=False'),
        açık port tarama tehlikesi KRİTİK bulgu olarak yakalanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["guvenlik_duvari_ufw"]["etkin"] = False

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)
            self.assertTrue(any("UFW Güvenlik Duvarı Devre Dışı" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_08_ufw_varsayilan_gelen_allow_negatif_kontrol(self):
        """
        NEGATİF KONTROL: UFW varsayılan gelen politika 'ALLOW' yapıldığında,
        tüm kapıların açık olması KRİTİK bulgu olarak raporlanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["guvenlik_duvari_ufw"]["varsayilan_gelen"] = "ALLOW"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)
            self.assertTrue(any("Varsayılan Gelen Ağ Trafiği 'ALLOW'" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_09_yasakli_servis_telnet_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Şifresiz telnetd servisi aktif listede yer aldığında,
        parola koklama riski nedeniyle YÜKSEK seviye uyarı üretilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["calisan_servisler"].append("telnetd")

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 80)  # 20 ceza puanı
            self.assertTrue(any("telnetd" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_10_guvensiz_umask_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Varsayılan umask '000' yapıldığında,
        yeni dosyaların dünya tarafından yazılabilir olması YÜKSEK risk olarak raporlanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_sistem))
        bozuk["kullanici_ve_yetki_yonetimi"]["varsayilan_umask"] = "000"

        dosya_yolu = self._gecici_profil_olustur([bozuk])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 80)
            self.assertTrue(any("umask 000" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_11_sshd_ve_sudoers_dosya_uretim_kontrol(self):
        """
        İŞLEVSELLİK KONTROLÜ: urete_guvenli_sshd_config ve urete_guvenli_sudoers
        metotlarının ürettiği dosyalarda CIS Seviye 1 parametreleri yer almalıdır.
        """
        dosya_yolu = self._gecici_profil_olustur([self.altin_sistem])
        temp_dir = tempfile.mkdtemp()
        sshd_out = os.path.join(temp_dir, "test_sshd_config")
        sudoers_out = os.path.join(temp_dir, "test_sudoers")
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            motor.urete_guvenli_sshd_config("LINUX-TEST-SEC", sshd_out)
            motor.urete_guvenli_sudoers("LINUX-TEST-SEC", sudoers_out)

            self.assertTrue(os.path.exists(sshd_out))
            with open(sshd_out, "r", encoding="utf-8") as f:
                sshd_icerik = f.read()
            self.assertIn("PermitRootLogin no", sshd_icerik)
            self.assertIn("PasswordAuthentication no", sshd_icerik)
            self.assertIn("Port 2222", sshd_icerik)

            self.assertTrue(os.path.exists(sudoers_out))
            with open(sudoers_out, "r", encoding="utf-8") as f:
                sudoers_icerik = f.read()
            self.assertIn("Defaults umask=027", sudoers_icerik)
            self.assertIn("%sudo ALL=(ALL:ALL) ALL", sudoers_icerik)
        finally:
            os.remove(dosya_yolu)
            if os.path.exists(sshd_out):
                os.remove(sshd_out)
            if os.path.exists(sudoers_out):
                os.remove(sudoers_out)
            os.rmdir(temp_dir)

    def test_12_gecersiz_sema_ve_alan_eksikligi(self):
        """
        HATA YÖNETİMİ: Zorunlu alan eksik olduğunda LinuxSecurityValidationError fırlatılmalıdır.
        """
        eksik = {"sistem_id": "SYS-EKSIK"}
        dosya_yolu = self._gecici_profil_olustur([eksik])
        try:
            motor = LinuxBaselineAuditor(dosya_yolu)
            with self.assertRaises(LinuxSecurityValidationError):
                motor.denetle_tumunu()
        finally:
            os.remove(dosya_yolu)

    def test_13_olmayan_dosya_hatasi(self):
        """
        HATA YÖNETİMİ: Olmayan dosya yolu verildiğinde FileNotFoundError fırlatılmalıdır.
        """
        with self.assertRaises(FileNotFoundError):
            LinuxBaselineAuditor("C:/hayali_olmayan_klasor/linux_profil.json")


if __name__ == "__main__":
    unittest.main()
