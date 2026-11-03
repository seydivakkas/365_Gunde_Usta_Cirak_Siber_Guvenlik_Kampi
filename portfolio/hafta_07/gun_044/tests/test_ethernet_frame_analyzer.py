# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G044: Ethernet, MAC ve Çerçeve Yapısı Birim ve Negatif Test Süiti.

Bu test süiti, Katman 2 (Veri Bağlantısı) Ethernet çerçeve analiz motorunun
Unicast, Broadcast, Multicast, VLAN etiketleme, dolgu (padding) ve kural ihlali
(örn: kaynak MAC'in multicast olması) denetimlerini eksiksiz sınar.
"""

# Python'un yerleşik unittest kütüphanesini içe aktarıyoruz.
import unittest
# Dosya sistemi yolları ve kontrolleri için os modülünü kullanıyoruz.
import os
# JSON verilerini okuma ve serileştirme işlemleri için json modülünü yüklüyoruz.
import json
# Geçici dosya işlemleri için tempfile kütüphanesini dahil ediyoruz.
import tempfile

# Test edilecek hedef uygulama bileşenlerini içe aktarıyoruz.
from portfolio.hafta_07.gun_044.uygulama.ethernet_frame_analyzer import (
    validate_mac_address_format,
    validate_ethertype_format,
    analyze_mac_address,
    dissect_single_ethernet_frame,
    analyze_ethernet_dataset,
    generate_ethernet_markdown_report,
    EthernetFrameError,
    MIN_ETHERNET_FRAME_SIZE
)


class TestEthernetFrameAnalyzer(unittest.TestCase):
    """Ethernet çerçeve ve MAC analiz motoru için birim ve negatif test senaryoları sınıfı."""

    def setUp(self) -> None:
        """Her testten önce referans veri dosyalarının yollarını hazırlar ve yükler."""
        # Test dosyasının bulunduğu dizini tespit ediyoruz.
        test_dir = os.path.dirname(os.path.abspath(__file__))
        # Örnek veri dizininin tam yolunu oluşturuyoruz.
        self.sample_dir = os.path.join(test_dir, "..", "ornek_veri")
        # Referans çerçeve veri dosyasının yolunu belirliyoruz.
        self.sample_file = os.path.join(self.sample_dir, "sample_ethernet_frames.json")
        # Dosyayı diskten okuyup belleğe yüklüyoruz.
        with open(self.sample_file, "r", encoding="utf-8") as f:
            # Belleğe JSON sözlüğü olarak alıyoruz.
            self.dataset = json.load(f)

    def test_01_valid_dataset_loading(self) -> None:
        """Geçerli örnek veri setinin 3 adet çerçeve içerdiğini ve doğrulandığını test eder."""
        # Veri setini ayrıştırıyoruz.
        analyzed = analyze_ethernet_dataset(self.dataset)
        # 3 çerçevenin bulunduğunu teyit ediyoruz.
        self.assertEqual(len(analyzed), 3)

    def test_02_unicast_frame_dissection(self) -> None:
        """ETH-001 çerçevesinin tek noktaya yayın (Unicast) IPv4 çerçevesi olduğunu doğrular."""
        # İlk çerçeveyi ayrıştırıyoruz.
        frame = dissect_single_ethernet_frame(self.dataset["frames"][0], 1)
        # Hedef MAC iletim türünün UNICAST içerdiğini sınıyoruz.
        self.assertIn("UNICAST", frame["destination"]["cast_type"])
        # EtherType alanının 0x0800 olduğunu sınıyoruz.
        self.assertEqual(frame["ethertype"], "0x0800")
        # Protokol adında IPv4 geçtiğini teyit ediyoruz.
        self.assertIn("IPv4", frame["protocol_name"])

    def test_03_broadcast_arp_frame_dissection(self) -> None:
        """ETH-002 çerçevesinin genel yayın (Broadcast) ARP çerçevesi olduğunu doğrular."""
        # İkinci çerçeveyi ayrıştırıyoruz.
        frame = dissect_single_ethernet_frame(self.dataset["frames"][1], 2)
        # Hedef MAC'in FF:FF:FF:FF:FF:FF olduğunu sınıyoruz.
        self.assertEqual(frame["destination"]["mac_address"], "FF:FF:FF:FF:FF:FF")
        # İletim türünün BROADCAST olduğunu teyit ediyoruz.
        self.assertIn("BROADCAST", frame["destination"]["cast_type"])
        # EtherType alanının 0x0806 (ARP) olduğunu sınıyoruz.
        self.assertEqual(frame["ethertype"], "0x0806")

    def test_04_vlan_tagged_frame_dissection(self) -> None:
        """ETH-003 çerçevesinin 802.1Q VLAN etiketli ve VLAN ID 20 olduğunu test eder."""
        # Üçüncü çerçeveyi ayrıştırıyoruz.
        frame = dissect_single_ethernet_frame(self.dataset["frames"][2], 3)
        # VLAN etiketli olduğunu sınıyoruz.
        self.assertTrue(frame["vlan_tagged"])
        # VLAN ID değerinin 20 olduğunu teyit ediyoruz.
        self.assertEqual(frame["vlan_id"], 20)

    def test_05_multicast_destination_mac_detection(self) -> None:
        """ETH-003 hedef MAC adresinin (01:00:5E:...) çok noktaya yayın (Multicast) olduğunu doğrular."""
        # MAC analizi fonksiyonunu doğrudan hedef MAC ile çağırıyoruz.
        analysis = analyze_mac_address("01:00:5E:00:00:FB", is_source=False)
        # I/G bitinin 1 (True) olduğunu sınıyoruz.
        self.assertTrue(analysis["ig_bit_group"])
        # İletim türünde MULTICAST geçtiğini sınıyoruz.
        self.assertIn("MULTICAST", analysis["cast_type"])

    def test_06_oui_vendor_resolution(self) -> None:
        """OUI öneklerinin bilinen üreticilerle (VMware) doğru eşleştiğini test eder."""
        # VMware OUI içeren MAC adresini analiz ediyoruz.
        analysis = analyze_mac_address("00:50:56:C0:00:08", is_source=False)
        # Üretici adında VMware geçtiğini teyit ediyoruz.
        self.assertIn("VMware", analysis["vendor"])
        # OUI önekinin 00:50:56 olduğunu sınıyoruz.
        self.assertEqual(analysis["oui_prefix"], "00:50:56")

    def test_07_minimum_frame_size_padding(self) -> None:
        """ETH-002 için 18 baytlık dolgu ile asgari 64 bayt sınırının sağlandığını doğrular."""
        # İkinci çerçeveyi alıyoruz.
        frame = dissect_single_ethernet_frame(self.dataset["frames"][1], 2)
        # Dolgu baytının 18 olduğunu teyit ediyoruz.
        self.assertEqual(frame["padding_bytes"], 18)
        # Toplam boyutun tam olarak 64 bayt olduğunu sınıyoruz.
        self.assertEqual(frame["total_frame_size"], MIN_ETHERNET_FRAME_SIZE)

    def test_08_markdown_report_generation(self) -> None:
        """Üretilen Markdown raporunun zorunlu başlıkları, tabloları ve lisans bildirimini içerdiğini doğrular."""
        # Çerçeveleri ayrıştırıyoruz.
        analyzed = analyze_ethernet_dataset(self.dataset)
        # Markdown raporu üretiyoruz.
        report = generate_ethernet_markdown_report(self.dataset, analyzed)
        # Raporun boş olmadığını sınıyoruz.
        self.assertTrue(len(report) > 0)
        # Özel lisans uyarısının raporda bulunduğunu teyit ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report)
        # Tablo başlığının raporda yer aldığını sınıyoruz.
        self.assertIn("Ethernet Çerçeveleri Alan Etiketleme", report)
        # I/G ve U/L bit açıklamalarının varlığını kontrol ediyoruz.
        self.assertIn("I/G (Individual / Group) Biti", report)

    def test_09_negative_multicast_source_mac(self) -> None:
        """Negatif Kontrol: Kaynak MAC adresinde I/G bitinin 1 olması durumunda hata fırlatıldığını doğrular."""
        # Kaynak MAC multicast yapılmış geçersiz çerçeve örneği.
        invalid_frame = {
            "frame_id": "ERR-001",
            "destination_mac": "00:50:56:C0:00:08",
            "source_mac": "01:00:5E:00:01:02",
            "ethertype": "0x0800",
            "total_frame_size": 78
        }
        # EthernetFrameError fırlatılmasını bekliyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            dissect_single_ethernet_frame(invalid_frame, 1)
        # Hata mesajında multicast kaynak uyarısını sınıyoruz.
        self.assertIn("Kaynak MAC adresi", str(ctx.exception))
        self.assertIn("Multicast veya Broadcast olamaz", str(ctx.exception))

    def test_10_negative_invalid_mac_hex_format(self) -> None:
        """Negatif Kontrol: MAC adresinde geçersiz karakterler bulunduğunda hata fırlatıldığını doğrular."""
        # Hatalı MAC içeren çerçeve.
        invalid_frame = {
            "destination_mac": "00:1A:2B:3C:4D:ZZ",
            "source_mac": "00:0C:29:12:34:56",
            "ethertype": "0x0800",
            "total_frame_size": 78
        }
        # İstisnanın yakalandığını sınıyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            dissect_single_ethernet_frame(invalid_frame, 1)
        # Hata açıklamasını kontrol ediyoruz.
        self.assertIn("hedef MAC adresi geçersiz", str(ctx.exception))

    def test_11_negative_invalid_ethertype_format(self) -> None:
        """Negatif Kontrol: EtherType alanının formatı bozuksa hata fırlatıldığını test eder."""
        # Hatalı EtherType içeren çerçeve (0x08 yerine 0x0800 beklenir).
        invalid_frame = {
            "destination_mac": "00:50:56:C0:00:08",
            "source_mac": "00:0C:29:12:34:56",
            "ethertype": "0x08",
            "total_frame_size": 78
        }
        # Hata kontrolü yapıyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            dissect_single_ethernet_frame(invalid_frame, 1)
        # Mesajı teyit ediyoruz.
        self.assertIn("geçersiz EtherType formatı", str(ctx.exception))

    def test_12_negative_undersized_runt_frame(self) -> None:
        """Negatif Kontrol: Toplam çerçeve boyutu 64 baytın altında (Runt) olduğunda hata verildiğini doğrular."""
        # 38 baytlık geçersiz cüce (runt) çerçeve.
        invalid_frame = {
            "destination_mac": "00:50:56:C0:00:08",
            "source_mac": "00:0C:29:12:34:56",
            "ethertype": "0x0800",
            "total_frame_size": 38
        }
        # Hata fırlatıldığını sınıyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            dissect_single_ethernet_frame(invalid_frame, 1)
        # Runt Frame uyarısını sınıyoruz.
        self.assertIn("Runt Frame", str(ctx.exception))

    def test_13_negative_missing_mandatory_field(self) -> None:
        """Negatif Kontrol: Zorunlu alanlardan biri eksik olduğunda hata fırlatıldığını doğrular."""
        # destination_mac alanı bulunmayan eksik çerçeve.
        invalid_frame = {
            "source_mac": "00:0C:29:12:34:56",
            "ethertype": "0x0800",
            "total_frame_size": 78
        }
        # Hatanın yakalandığını teyit ediyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            dissect_single_ethernet_frame(invalid_frame, 1)
        # Eksik alan mesajını sınıyoruz.
        self.assertIn("zorunlu 'destination_mac' alanı eksik", str(ctx.exception))

    def test_14_negative_non_dict_frame_entry(self) -> None:
        """Negatif Kontrol: Çerçeve listesinde dize veya sayı geçtiğinde sistemin hata ürettiğini doğrular."""
        # Geçersiz girdi içeren veri seti.
        corrupted_dataset = {
            "frames": ["Bu bir cerceve sozlugu degildir"]
        }
        # Hata kontrolü yapıyoruz.
        with self.assertRaises(EthernetFrameError) as ctx:
            analyze_ethernet_dataset(corrupted_dataset)
        # Sözlük uyarısını sınıyoruz.
        self.assertIn("bir JSON sözlüğü olmalıdır", str(ctx.exception))


# Test doğrudan yürütüldüğünde çalıştırıyoruz.
if __name__ == "__main__":
    # Detaylı kipte başlatıyoruz.
    unittest.main()
