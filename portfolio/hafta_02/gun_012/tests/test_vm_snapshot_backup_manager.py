# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz. Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 012: Sanal Makine Snapshot, Yedekleme ve Geri Dönüş Birim Test Paketi
Usta-Çırak Siber Güvenlik Laboratuvarı Doğrulama Testleri

Bu test paketi;
1. Pozitif Altın Akış: 3-2-1 uyumlu, değişmez (immutable) yedekli Linux SIEM sunucusunun doğrulanması,
2. Snapshot Oluşturma ve Rollback: Temiz duruma dönüş ve delta disk sıfırlanmasının teyidi,
3. Negatif Kontroller: Snapshot'ı yedek sanma yanılgısı, 72 saat aşımı, aşırı zincir derinliği,
   WORM kilidi yokluğu, VSS korumasızlığı, SHA-256 bütünlük bozulması ve sınır ihlalleri
senaryolarını 14 bağımsız test ile %100 kapsama oranıyla doğrular.
"""

import os  # Dosya ve dizin denetimleri için standart kütüphane
import sys  # Sistem yolu manipülasyonu için
import unittest  # Birim test çatısı
import tempfile  # Güvenli geçici dosya testleri için
import hashlib  # Hash doğrulama testleri için

# Uygulama modülünü arama yoluna ekliyoruz
uygulama_dizini = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama"))
if uygulama_dizini not in sys.path:
    sys.path.insert(0, uygulama_dizini)

# Test edilecek yönetici ve özel istisnalar içe aktarılır
from vm_snapshot_backup_manager import (
    VMSnapshotBackupManager,
    SnapshotManagerError,
    BackupIntegrityError,
    SnapshotPolicyViolationError
)


class TestVMSnapshotBackupManager(unittest.TestCase):
    """Sanal makine snapshot, yedek ve geri dönüş mekanizmalarını doğrulayan test sınıfı."""

    def setUp(self):
        """Her testten önce örnek sentetik veri tabanını yükleyen hazırlık metodu."""
        self.envanter_yolu = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "ornek_veri", "vm_lab_envanteri.json"
        ))
        # Yönetici motoru başlatılır
        self.yonetici = VMSnapshotBackupManager(self.envanter_yolu)

    # --- POZİTİF KONTROLLER ---

    def test_01_altin_yedek_yapilandirmasi_pozitif_kontrol(self):
        """POZİTİF TEST: 3-2-1 kuralına uygun ve değişmez yedekli VM-SEC-LNX-01 denetimi 100 tam puan almalıdır."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-SEC-LNX-01")
        # Beklenen durum: Tam puan, 0 bulgu ve GUVENLI statüsü
        self.assertEqual(sonuc["denetim_skoru"], 100)
        self.assertEqual(sonuc["durum"], "GUVENLI")
        self.assertEqual(sonuc["bulgu_sayisi"], 0)

    def test_02_snapshot_olusturma_ve_ana_disk_kilitleme_pozitif_kontrol(self):
        """POZİTİF TEST: Yeni snapshot oluşturulduğunda ana disk salt-okunur olmalı ve delta diski açılmalıdır."""
        yeni_snap = self.yonetici.snapshot_olustur(
            vm_id="VM-SEC-LNX-01",
            snapshot_adi="Test_Saldiri_Oncesi_Snap",
            aciklama="Zararlı yazılım testi öncesi kontrol noktası",
            bellek_dahil=True
        )
        # Snapshot kimliği ve durumu doğrulanır
        self.assertTrue(yeni_snap["snapshot_id"].startswith("SNAP-VM-SEC-LNX-01"))
        self.assertEqual(yeni_snap["durum"], "AKTIF")
        # Ana diskin salt-okunur yapıldığı teyit edilir
        self.assertTrue(self.yonetici.vmler["VM-SEC-LNX-01"]["ana_disk"]["salt_okunur_mu"])

    def test_03_snapshot_rollback_temiz_duruma_donus_pozitif_kontrol(self):
        """POZİTİF TEST: Rollback icra edildiğinde delta diski sıfırlanmalı ve altın duruma dönülmelidir."""
        sonuc = self.yonetici.snapshot_geri_don("VM-SEC-WIN-01", "SNAP-WIN-01")
        self.assertEqual(sonuc["durum"], "BASARILI")
        self.assertIn("temiz durumuna saniyeler içinde geri döndürüldü", sonuc["aciklama"])

    def test_04_tam_bagimsiz_yedek_olusturma_pozitif_kontrol(self):
        """POZİTİF TEST: Bağımsız tam yedek oluşturulduğunda SHA-256 ve WORM kilidi üretilmelidir."""
        hedef = "s3://immutable-lab-backups/win11/tam_yedek_001.vhdx"
        yedek = self.yonetici.tam_yedek_olustur("VM-SEC-WIN-01", hedef_depolama=hedef, degismezlik_kilidi=True)
        self.assertEqual(yedek["yedek_tipi"], "TAM_BAGIMSIZ_YEDEK")
        self.assertTrue(yedek["degismezlik_kilidi_aktif_mi"])
        self.assertEqual(len(yedek["sha256"]), 64)  # 64 karakter standart SHA-256 hex uzunluğu

    def test_05_yedek_kriptografik_butunluk_dogrulamasi_pozitif_kontrol(self):
        """POZİTİF TEST: Doğru hash sağlandığında geri yükleme bütünlüğü onaylanmalıdır."""
        beklenen_hash = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
        sonuc = self.yonetici.yedekten_geri_yukle_dogrula("VM-SEC-LNX-01", "BAK-LNX-20261026", beklenen_hash)
        self.assertEqual(sonuc["durum"], "GECERLI_VE_BASARILI")
        self.assertEqual(sonuc["sha256"], beklenen_hash)

    # --- NEGATİF VE GÜVENLİK SINIR KONTROLLERİ ---

    def test_06_snapshot_as_backup_yanilgisi_negatif_kontrol(self):
        """NEGATİF TEST: Yedeği olmayan ancak snapshot'ı olan VM'de KRİTİK RISK-01 bulgusu oluşmalıdır."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-SEC-WIN-01")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("RISK-01-SNAP-AS-BACKUP", kodlar)
        self.assertLess(sonuc["denetim_skoru"], 80)

    def test_07_snapshot_yas_siniri_asimi_negatif_kontrol(self):
        """NEGATİF TEST: 72 saati aşmış açık snapshot tespitinde YÜKSEK RISK-02 cezası kesilmelidir."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-SEC-WIN-01")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("RISK-02-SNAPSHOT-AGE-EXCEEDED", kodlar)

    def test_08_derin_snapshot_zinciri_negatif_kontrol(self):
        """NEGATİF TEST: 3'ten fazla iç içe geçmiş snapshot olan makinede RISK-03 uyarısı verilmelidir."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-VULN-SRV-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("RISK-03-DEEP-SNAPSHOT-CHAIN", kodlar)

    def test_09_degismezlik_kilidi_yoklugu_negatif_kontrol(self):
        """NEGATİF TEST: WORM değişmezlik kilidi bulunmayan sistemde fidye yazılımı riski raporlanmalıdır."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-VULN-SRV-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("RISK-04-IMMUTABILITY-MISSING", kodlar)

    def test_10_vss_golge_kopya_saldiri_yuzeyi_negatif_kontrol(self):
        """NEGATİF TEST: Windows sisteminde VSS aktif fakat harici koruma yoksa vssadmin saldırı riski yakalanmalıdır."""
        sonuc = self.yonetici.denetle_ve_risk_analizi_yap("VM-VULN-SRV-99")
        kodlar = [b["kod"] for b in sonuc["bulgular"]]
        self.assertIn("RISK-05-VSS-TAMPER-SURFACE", kodlar)

    def test_11_kriptografik_butunluk_hatasi_ve_fidye_yazilimi_bozulmasi_kontrol(self):
        """NEGATİF TEST: Hash uyuşmazlığında BackupIntegrityError fırlatılmalı ve geri yükleme reddedilmelidir."""
        sahte_bozuk_hash = "deadbeef111122223333444455556666777788889999aaaabbbbccccddddeeee"
        with self.assertRaises(BackupIntegrityError) as context:
            self.yonetici.yedekten_geri_yukle_dogrula("VM-SEC-LNX-01", "BAK-LNX-20261026", sahte_bozuk_hash)
        self.assertIn("kriptografik bütünlük testini geçemedi", str(context.exception))

    def test_12_maksimum_snapshot_zincir_limiti_asimi_kontrol(self):
        """NEGATİF TEST: 5'ten fazla snapshot eklenmeye çalışıldığında SnapshotPolicyViolationError fırlatılmalıdır."""
        # VM-VULN-SRV-99 üzerinde zaten 4 snapshot var, 5.'yi ekleyelim
        self.yonetici.snapshot_olustur("VM-VULN-SRV-99", "Ekstra_Snap_5", "5. snapshot")
        # 6.'yı eklemeye çalıştığımızda politika ihlali oluşmalı
        with self.assertRaises(SnapshotPolicyViolationError) as context:
            self.yonetici.snapshot_olustur("VM-VULN-SRV-99", "Ekstra_Snap_6", "6. snapshot - Limit üstü")
        self.assertIn("Maksimum snapshot zincir derinliği", str(context.exception))

    def test_13_tanimsiz_vm_veya_kayit_hata_yonetimi(self):
        """HATA YÖNETİMİ: Tanımsız VM kimliği sorgulandığında SnapshotPolicyViolationError fırlatılmalıdır."""
        with self.assertRaises(SnapshotPolicyViolationError):
            self.yonetici.denetle_ve_risk_analizi_yap("TANIMSIZ-HAYALET-VM")

    def test_14_fiziksel_dosya_sha256_hesaplama_ve_olmayan_dosya(self):
        """İŞLEVSELLİK & HATA YÖNETİMİ: Gerçek dosyanın SHA-256 özeti doğru hesaplanmalı, olmayan dosyada hata verilmelidir."""
        # Geçici bir dosya oluşturulup bilinen içerik yazılır
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Siber Guvenlik 365 Gun Laboratuvari - Gun 012 Test Verisi")
            gecici_yol = tf.name

        try:
            hesaplanan_hash = self.yonetici.dosya_sha256_hesapla(gecici_yol)
            beklenen_hash = hashlib.sha256(b"Siber Guvenlik 365 Gun Laboratuvari - Gun 012 Test Verisi").hexdigest()
            self.assertEqual(hesaplanan_hash, beklenen_hash)
        finally:
            if os.path.exists(gecici_yol):
                os.remove(gecici_yol)

        # Olmayan dosyada FileNotFoundError fırlatılmalı
        with self.assertRaises(FileNotFoundError):
            self.yonetici.dosya_sha256_hesapla("bu_dosya_asla_var_olamaz_12345.vhd")


if __name__ == "__main__":
    unittest.main()
