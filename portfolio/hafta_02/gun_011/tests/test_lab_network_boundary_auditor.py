# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 011: Laboratuvar Ağ Sınırları
Birim Testleri: test_lab_network_boundary_auditor.py

Bu test modülü; Laboratuvar Ağ Sınırları ve Bölümleme Denetleyicisinin
pozitif (4 bölgeli mikro-segmente, tam izole ağ), negatif (karantina internet çıkışı,
düz ağ, DNS sızıntısı, tersine kabuk, açık forward politikası) ve şablon üretim durumlarını %100 kapsama ile doğrular.
"""

import os
import sys
import json
import tempfile
import unittest

# Uygulama modülünü içe aktarmak için arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../uygulama")))

# Motor sınıfı ve özel hata sınıfı içe aktarılıyor
from lab_network_boundary_auditor import LabNetworkBoundaryAuditor, NetworkBoundaryValidationError


class TestLabNetworkBoundaryAuditor(unittest.TestCase):
    """
    Laboratuvar Ağ Sınırları Birim Test Paketi.
    """

    def setUp(self):
        """
        Her test öncesinde 4 bölgeli, mikro-segmente ve tam sertleştirilmiş temel altın topoloji oluştur.
        """
        self.altin_topoloji = {
            "topoloji_id": "TEST-TOPOLOGY-SEC",
            "topoloji_adi": "Test_Altin_Mikro_Segmentasyon_Agi",
            "mimari_tipi": "Mikro_Segmentasyon_4_Bolge",
            "guvenlik_seviyesi": "KRITIK_IZOLE_AIRGAPPED",
            "ag_bolgeleri": [
                {
                    "bolge_id": "ZONE-DETONATION",
                    "bolge_adi": "Karantina_Patlatma_Bolgesi",
                    "vlan_id": 66,
                    "alt_ag_cidr": "192.168.66.0/24",
                    "rol": "Zararlı Yazılım Analizi ve Kurban Makineler",
                    "internet_cikis_izni": False,
                    "dns_sinkhole_etkin": True,
                    "sinkhole_dns_ip": "192.168.66.2",
                    "harici_genel_dns_engelli": True
                },
                {
                    "bolge_id": "ZONE-ATTACKER",
                    "bolge_adi": "Kirmizi_Takim_Saldiri_Bolgesi",
                    "vlan_id": 10,
                    "alt_ag_cidr": "192.168.10.0/24",
                    "rol": "Saldırı ve Sızma Testi Düğümleri",
                    "internet_cikis_izni": False,
                    "dns_sinkhole_etkin": False,
                    "sinkhole_dns_ip": None,
                    "harici_genel_dns_engelli": True
                },
                {
                    "bolge_id": "ZONE-SOC-SIEM",
                    "bolge_adi": "Mavi_Takim_Gozlem_Bolgesi",
                    "vlan_id": 20,
                    "alt_ag_cidr": "192.168.20.0/24",
                    "rol": "Log Toplama ve Trafik İzleme",
                    "internet_cikis_izni": False,
                    "dns_sinkhole_etkin": False,
                    "sinkhole_dns_ip": None,
                    "harici_genel_dns_engelli": True
                },
                {
                    "bolge_id": "ZONE-MGMT",
                    "bolge_adi": "Yonetim_Out_of_Band_Bolgesi",
                    "vlan_id": 99,
                    "alt_ag_cidr": "192.168.99.0/24",
                    "rol": "Analist Yönetim Konsolu",
                    "internet_cikis_izni": False,
                    "dns_sinkhole_etkin": False,
                    "sinkhole_dns_ip": None,
                    "harici_genel_dns_engelli": True
                }
            ],
            "guvenlik_duvari_politikasi": {
                "varsayilan_forward_eylemi": "DROP",
                "varsayilan_input_eylemi": "DROP",
                "statefull_conntrack_aktif": True,
                "kurbandan_disariya_yeni_baglanti_engeli": True,
                "bolgeler_arasi_kurallar": [
                    {
                        "kural_id": "FW-RULE-01",
                        "kaynak_bolge": "ZONE-ATTACKER",
                        "hedef_bolge": "ZONE-DETONATION",
                        "protokol": "tcp",
                        "hedef_portlar": [80, 445],
                        "durum_takibi": "NEW,ESTABLISHED",
                        "eylem": "ACCEPT",
                        "aciklama": "Saldırgan kurbana erişebilir"
                    },
                    {
                        "kural_id": "FW-RULE-02",
                        "kaynak_bolge": "ZONE-DETONATION",
                        "hedef_bolge": "ZONE-ATTACKER",
                        "protokol": "tcp",
                        "hedef_portlar": [],
                        "durum_takibi": "ESTABLISHED,RELATED",
                        "eylem": "ACCEPT",
                        "aciklama": "Kurban yalnızca başlatılan oturuma yanıt verebilir"
                    }
                ]
            }
        }

    def _gecici_topoloji_olustur(self, topoloji_listesi):
        """
        Testler için geçici bir JSON dosyası üretir.
        """
        gecici = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"ag_topolojileri": topoloji_listesi}, gecici)
        gecici.close()
        return gecici.name

    def test_01_altin_topoloji_pozitif_kontrol(self):
        """
        POZİTİF KONTROL: 4 bölgeli, tam izole ve mikro-segmente laboratuvar topolojisi
        denetlendiğinde 100/100 tam puan almalı, sıfır bulgu üretmeli ve durumu 'GÜVENLİ' olmalıdır.
        """
        dosya_yolu = self._gecici_topoloji_olustur([self.altin_topoloji])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(len(sonuclar), 1)
            self.assertEqual(sonuclar[0]["skor"], 100)
            self.assertEqual(sonuclar[0]["toplam_bulgu_sayisi"], 0)
            self.assertIn("GÜVENLİ", sonuclar[0]["risk_derecesi"])
        finally:
            os.remove(dosya_yolu)

    def test_02_karantina_internet_cikis_felaket_kontrol(self):
        """
        NEGATİF KONTROL: Karantina / Patlatma bölgesinde internet çıkışına izin verilirse,
        canlı C2 iletişimi ve veri sızıntısı nedeniyle FELAKET uyarısıyla 50 ceza puanı kesilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["ag_bolgeleri"][0]["internet_cikis_izni"] = True

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("Karantina Bölgesinde Açık İnternet Erişimi", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_03_duz_ag_segmentasyon_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Topolojide bölge sayısı 3'ten az ise (düz ağ riski),
        YÜKSEK risk bulgusu ile 25 ceza puanı kesilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["ag_bolgeleri"] = [bozuk["ag_bolgeleri"][0]]  # Tek bir bölge kaldı

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 75)
            self.assertTrue(any("Düz Ağ Riski" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_04_cakisan_cidr_negatif_kontrol(self):
        """
        NEGATİF KONTROL: İki farklı bölgeye aynı alt ağ CIDR bloğu atanırsa,
        yönlendirme çöküşü riskiyle KRİTİK bulgu üretilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["ag_bolgeleri"][1]["alt_ag_cidr"] = "192.168.66.0/24"  # Bölge 0 ile aynı!

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)  # 30 ceza puanı
            self.assertTrue(any("Çakışan Alt Ağ" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_05_harici_dns_engellenmemis_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Karantina bölgesinde harici genel DNS sorgularına izin verilirse,
        DNS tünelleme ile veri sızıntısı riski YÜKSEK seviye olarak yakalanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["ag_bolgeleri"][0]["harici_genel_dns_engelli"] = False

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 80)  # 20 ceza puanı
            self.assertTrue(any("Harici DNS Sorguları İzinli" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_06_dns_sinkhole_eksik_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Karantinada DNS sinkhole / sahte yanıtlayıcı tanımlanmazsa,
        ORTA seviye bulgu ile 15 ceza puanı kesilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["ag_bolgeleri"][0]["dns_sinkhole_etkin"] = False

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 85)
            self.assertTrue(any("DNS Sinkhole" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_07_varsayilan_forward_accept_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Güvenlik duvarı varsayılan forward eylemi 'ACCEPT' yapıldığında,
        tüm bölgeler arası açık geçiş riski KRİTİK olarak raporlanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["guvenlik_duvari_politikasi"]["varsayilan_forward_eylemi"] = "ACCEPT"

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 65)  # 35 ceza puanı
            self.assertTrue(any("FORWARD Eylemi 'DROP' Değil" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_08_statefull_conntrack_kapali_negatif_kontrol(self):
        """
        NEGATİF KONTROL: Statefull conntrack (bağlantı takibi) kapatıldığında,
        durumsuz yönlendirme açığı KRİTİK bulgu olarak yakalanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["guvenlik_duvari_politikasi"]["statefull_conntrack_aktif"] = False

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)  # 30 ceza puanı
            self.assertTrue(any("Statefull Conntrack" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_09_kurbandan_yeni_baglanti_engeli_yok_kontrol(self):
        """
        NEGATİF KONTROL: Kurbandan dışarıya yeni bağlantı başlatma engeli kapatılırsa,
        tersine kabuk başlatma tehlikesi KRİTİK olarak raporlanmalıdır.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["guvenlik_duvari_politikasi"]["kurbandan_disariya_yeni_baglanti_engeli"] = False

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)
            self.assertTrue(any("Yeni (NEW) Bağlantılar Engellenmemiş" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_10_kurbandan_saldirgana_new_baglanti_tersine_kabuk_kontrol(self):
        """
        NEGATİF KONTROL: Kural setinde kurbandan saldırgana 'NEW' durumunda bağlantıya
        izin verilirse, tersine kabuk (Reverse Shell) açığı KRİTİK olarak engellenmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["guvenlik_duvari_politikasi"]["bolgeler_arasi_kurallar"].append({
            "kural_id": "FW-BAD-REVERSE",
            "kaynak_bolge": "ZONE-DETONATION",
            "hedef_bolge": "ZONE-ATTACKER",
            "protokol": "tcp",
            "hedef_portlar": [4444],
            "durum_takibi": "NEW,ESTABLISHED",
            "eylem": "ACCEPT"
        })

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            self.assertEqual(sonuclar[0]["skor"], 70)
            self.assertTrue(any("Tersine Bağlantı İzni" in b["baslik"] for b in sonuclar[0]["bulgular"]))
        finally:
            os.remove(dosya_yolu)

    def test_11_karantinadan_internete_genis_izin_felaket_kontrol(self):
        """
        NEGATİF KONTROL: Karantina bölgesinden dış internete (INTERNET) doğru ACCEPT kuralı
        varsa, FELAKET seviyesinde 50 puan ceza kesilmelidir.
        """
        bozuk = json.loads(json.dumps(self.altin_topoloji))
        bozuk["guvenlik_duvari_politikasi"]["bolgeler_arasi_kurallar"].append({
            "kural_id": "FW-BAD-INTERNET",
            "kaynak_bolge": "ZONE-DETONATION",
            "hedef_bolge": "INTERNET",
            "protokol": "all",
            "hedef_portlar": [],
            "durum_takibi": "ANY",
            "eylem": "ACCEPT"
        })

        dosya_yolu = self._gecici_topoloji_olustur([bozuk])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            sonuclar = motor.denetle_tumunu()

            felaketler = [b for b in sonuclar[0]["bulgular"] if b["seviye"] == "FELAKET"]
            self.assertEqual(len(felaketler), 1)
            self.assertIn("Güvensiz Geniş İzin Kuralı", felaketler[0]["baslik"])
        finally:
            os.remove(dosya_yolu)

    def test_12_iptables_betik_uretimi_dogrulamasi(self):
        """
        İŞLEVSELLİK KONTROLÜ: urete_iptables_kurallari metodu ile oluşturulan betikte
        -P FORWARD DROP, DNAT sinkhole ve sızıntı loglama kuralları doğrulanmalıdır.
        """
        dosya_yolu = self._gecici_topoloji_olustur([self.altin_topoloji])
        temp_dir = tempfile.mkdtemp()
        betik_yolu = os.path.join(temp_dir, "iptables_test.sh")
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            motor.urete_iptables_kurallari("TEST-TOPOLOGY-SEC", betik_yolu)

            self.assertTrue(os.path.exists(betik_yolu))
            with open(betik_yolu, "r", encoding="utf-8") as f:
                icerik = f.read()

            self.assertIn("iptables -P FORWARD DROP", icerik)
            self.assertIn("--to-destination 192.168.66.2:53", icerik)
            self.assertIn("--log-prefix \"[LAB-SIZINTI-ENGELI]: \"", icerik)
        finally:
            os.remove(dosya_yolu)
            if os.path.exists(betik_yolu):
                os.remove(betik_yolu)
            os.rmdir(temp_dir)

    def test_13_gecersiz_sema_ve_alan_eksikligi(self):
        """
        HATA YÖNETİMİ: Zorunlu alanlardan biri eksik olduğunda NetworkBoundaryValidationError fırlatılmalıdır.
        """
        eksik = {"topoloji_id": "TOPO-EKSIK"}
        dosya_yolu = self._gecici_topoloji_olustur([eksik])
        try:
            motor = LabNetworkBoundaryAuditor(dosya_yolu)
            with self.assertRaises(NetworkBoundaryValidationError):
                motor.denetle_tumunu()
        finally:
            os.remove(dosya_yolu)

    def test_14_olmayan_dosya_hatasi(self):
        """
        HATA YÖNETİMİ: Olmayan dosya yolu verildiğinde FileNotFoundError fırlatılmalıdır.
        """
        with self.assertRaises(FileNotFoundError):
            LabNetworkBoundaryAuditor("C:/hayali_olmayan_klasor/topoloji.json")


if __name__ == "__main__":
    unittest.main()
