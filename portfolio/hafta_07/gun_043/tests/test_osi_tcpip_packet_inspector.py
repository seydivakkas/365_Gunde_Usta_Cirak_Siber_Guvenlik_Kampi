# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G043: OSI ve TCP/IP Katmanları Paket Denetim ve Kapsülleme Birim ve Negatif Test Süiti.

Bu test süiti, 7 katmanlı OSI ve 4 katmanlı TCP/IP modellerine göre hazırlanan
HTTPS paket kapsülleme verisinin tüm başlık alanlarını, adreslerini, portlarını,
bayraklarını ve negatif hata durumlarını doğrular.
"""

# Python'un yerleşik test kütüphanesini içe aktarıyoruz.
import unittest
# Dosya sistemi yolları için os modülünü kullanıyoruz.
import os
# JSON okuma ve geçici dosya testleri için json kütüphanesini çağırıyoruz.
import json
# Geçici dosya işlemleri için tempfile modülünü dahil ediyoruz.
import tempfile

# Test edilecek hedef uygulama bileşenlerini içe aktarıyoruz.
from portfolio.hafta_07.gun_043.uygulama.osi_tcpip_packet_inspector import (
    validate_mac_address,
    validate_ipv4_address,
    validate_port_number,
    validate_packet_structure,
    map_layers_to_models,
    generate_packet_dissection_report,
    PacketEncapsulationError,
    MANDATORY_OSI_LAYERS,
    VALID_TCP_FLAGS
)


class TestOSITCPIPPacketInspector(unittest.TestCase):
    """OSI ve TCP/IP paket ayrıştırma ve kapsülleme motoru için test senaryoları sınıfı."""

    def setUp(self) -> None:
        """Her testten önce çalıştırılarak örnek veri dosyalarının yollarını hazırlar."""
        # Test dosyasının bulunduğu dizini tespit ediyoruz.
        test_dir = os.path.dirname(os.path.abspath(__file__))
        # Örnek veri klasörünün yolunu hesaplıyoruz.
        self.sample_dir = os.path.join(test_dir, "..", "ornek_veri")
        # Geçerli HTTPS kapsülleme dosyasının yolunu belirliyoruz.
        self.sample_file = os.path.join(self.sample_dir, "sample_https_encapsulation.json")
        # Dosyayı diskten okuyup belleğe yüklüyoruz.
        with open(self.sample_file, "r", encoding="utf-8") as f:
            # Belleğe JSON olarak alıyoruz.
            self.sample_data = json.load(f)

    def test_01_valid_https_packet_loading(self) -> None:
        """Geçerli HTTPS paket kapsülleme JSON yapısının başarıyla doğrulandığını test eder."""
        # Yapıyı doğruluyoruz.
        valid_packet = validate_packet_structure(self.sample_data)
        # Kapsülleme alanının varlığını teyit ediyoruz.
        self.assertIn("encapsulation", valid_packet)
        # 7 katmanın tamamının mevcut olduğunu sınıyoruz.
        self.assertEqual(len(valid_packet["encapsulation"]), 7)

    def test_02_all_7_osi_layers_present(self) -> None:
        """Zorunlu 7 OSI katmanının tamamının kapsülleme sözlüğünde yer aldığını doğrular."""
        # Kapsülleme sözlüğünü alıyoruz.
        encap = self.sample_data["encapsulation"]
        # 7 katman anahtarını tek tek kontrol ediyoruz.
        for layer_key in MANDATORY_OSI_LAYERS:
            # Katmanın var olduğunu sınıyoruz.
            self.assertIn(layer_key, encap)
            # Katmanın sözlük tipinde olduğunu teyit ediyoruz.
            self.assertIsInstance(encap[layer_key], dict)

    def test_03_tcpip_model_mapping(self) -> None:
        """7 OSI katmanının 4 katmanlı TCP/IP modeline eksiksiz haritalandığını test eder."""
        # Katman eşleme fonksiyonunu çağırıyoruz.
        mapping = map_layers_to_models(self.sample_data["encapsulation"])
        # Eşleme sözlüğünde osi_layers ve tcpip_summary anahtarlarını kontrol ediyoruz.
        self.assertIn("osi_layers", mapping)
        self.assertIn("tcpip_summary", mapping)
        # 4 temel TCP/IP katmanının özette bulunduğunu teyit ediyoruz.
        tcp_keys = mapping["tcpip_summary"].keys()
        self.assertIn("Application", tcp_keys)
        self.assertIn("Transport", tcp_keys)
        self.assertIn("Internet", tcp_keys)
        self.assertIn("Network_Access", tcp_keys)

    def test_04_valid_ipv4_addresses(self) -> None:
        """Kaynak ve hedef IPv4 adreslerinin biçim ve sınır testlerini doğrular."""
        # Ağ katmanını alıyoruz.
        l3 = self.sample_data["encapsulation"]["layer_3_network"]
        # Kaynak IP adresini sınıyoruz.
        self.assertTrue(validate_ipv4_address(l3["source_ip"]))
        # Hedef IP adresini sınıyoruz.
        self.assertTrue(validate_ipv4_address(l3["destination_ip"]))
        # Protokol numarasının 6 (TCP) olduğunu teyit ediyoruz.
        self.assertEqual(l3["protocol_number"], 6)

    def test_05_valid_mac_addresses(self) -> None:
        """Veri bağlantısı katmanındaki MAC adreslerinin standart formata uyduğunu test eder."""
        # Veri bağlantısı katmanını alıyoruz.
        l2 = self.sample_data["encapsulation"]["layer_2_data_link"]
        # Kaynak MAC'i sınıyoruz.
        self.assertTrue(validate_mac_address(l2["source_mac"]))
        # Hedef MAC'i sınıyoruz.
        self.assertTrue(validate_mac_address(l2["destination_mac"]))
        # EtherType alanının 0x0800 (IPv4) olduğunu teyit ediyoruz.
        self.assertEqual(l2["ethertype"], "0x0800")

    def test_06_valid_ports_and_tls(self) -> None:
        """Hedef portun 443 olduğunu ve sunum katmanında TLS 1.3 şifrelemesinin aktifliğini denetler."""
        # Taşıma katmanını alıyoruz.
        l4 = self.sample_data["encapsulation"]["layer_4_transport"]
        # Hedef portun 443 olduğunu sınıyoruz.
        self.assertEqual(l4["destination_port"], 443)
        # Kaynak portun geçerli bir dinamik port aralığında olduğunu sınıyoruz.
        self.assertGreaterEqual(l4["source_port"], 1024)
        # Sunum katmanını alıyoruz.
        l6 = self.sample_data["encapsulation"]["layer_6_presentation"]
        # Şifreleme durumunun ENCRYPTED olduğunu teyit ediyoruz.
        self.assertEqual(l6["encryption_status"], "ENCRYPTED")
        # TLS 1.3 protokolünü kontrol ediyoruz.
        self.assertEqual(l6["protocol"], "TLSv1.3")

    def test_07_tcp_flags_verification(self) -> None:
        """Taşıma katmanındaki TCP bayraklarının standart kümede yer aldığını test eder."""
        # Taşıma katmanı bayraklarını alıyoruz.
        flags = self.sample_data["encapsulation"]["layer_4_transport"]["flags"]
        # Bayrakların geçerli kümenin alt kümesi olduğunu sınıyoruz.
        for f in flags:
            # Bayrağın geçerli olduğunu teyit ediyoruz.
            self.assertIn(f, VALID_TCP_FLAGS)

    def test_08_markdown_report_generation(self) -> None:
        """Üretilen Markdown raporunun zorunlu başlıkları, tabloları ve lisans bildirimini içerdiğini doğrular."""
        # Doğrulanmış veriyi alıyoruz.
        valid_packet = validate_packet_structure(self.sample_data)
        # Katman eşlemesini çıkarıyoruz.
        mapping = map_layers_to_models(valid_packet["encapsulation"])
        # Markdown raporu üretiyoruz.
        report = generate_packet_dissection_report(valid_packet, mapping)
        # Boş olmadığını sınıyoruz.
        self.assertTrue(len(report) > 0)
        # Özel lisans uyarısının raporda bulunduğunu teyit ediyoruz.
        self.assertIn("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR", report)
        # 7 katman tablosunun başlığının geçtiğini sınıyoruz.
        self.assertIn("7 Katmanlı OSI ve TCP/IP Kapsülleme", report)
        # Port 443 detayının raporda geçtiğini sınıyoruz.
        self.assertIn("443", report)

    def test_09_negative_ipv4_octet_overflow(self) -> None:
        """Negatif Kontrol: IPv4 okteti 255'i aştığında PacketEncapsulationError fırlatıldığını doğrular."""
        # Bozuk IP içeren kopya oluşturuyoruz.
        corrupted = dict(self.sample_data)
        # Kaynak IP'yi 999.300.1.1 yapıyoruz.
        corrupted["encapsulation"]["layer_3_network"]["source_ip"] = "999.300.1.1"
        # İstisnanın fırlatıldığını sınıyoruz.
        with self.assertRaises(PacketEncapsulationError) as ctx:
            validate_packet_structure(corrupted)
        # Hata mesajında geçersiz kaynak IP uyarısını teyit ediyoruz.
        self.assertIn("Geçersiz kaynak IPv4 adresi", str(ctx.exception))

    def test_10_negative_invalid_mac_format(self) -> None:
        """Negatif Kontrol: MAC adresinde onaltılık olmayan karakterler varsa hata fırlatıldığını doğrular."""
        # Bozuk MAC içeren kopya oluşturuyoruz.
        corrupted = dict(self.sample_data)
        # Kaynak MAC adresini geçersiz yapıyoruz.
        corrupted["encapsulation"]["layer_2_data_link"]["source_mac"] = "00:1A:2B:3C:GG:ZZ"
        # İstisnanın yakalandığını sınıyoruz.
        with self.assertRaises(PacketEncapsulationError) as ctx:
            validate_packet_structure(corrupted)
        # Hata mesajını teyit ediyoruz.
        self.assertIn("Geçersiz kaynak MAC adresi", str(ctx.exception))

    def test_11_negative_port_overflow(self) -> None:
        """Negatif Kontrol: Port numarasının 65535'i aşması durumunda sistemin hata ürettiğini doğrular."""
        # Bozuk port içeren kopya oluşturuyoruz.
        corrupted = dict(self.sample_data)
        # Hedef portu 70000 yapıyoruz.
        corrupted["encapsulation"]["layer_4_transport"]["destination_port"] = 70000
        # Hata fırlatıldığını sınıyoruz.
        with self.assertRaises(PacketEncapsulationError) as ctx:
            validate_packet_structure(corrupted)
        # Hata mesajında 1-65535 uyarısını sınıyoruz.
        self.assertIn("1-65535 aralığında olmalıdır", str(ctx.exception))

    def test_12_negative_port_negative_or_boolean(self) -> None:
        """Negatif Kontrol: Portun negatif sayı veya bool olması durumunda hata fırlatıldığını test eder."""
        # Negatif port testi.
        with self.assertRaises(PacketEncapsulationError):
            validate_port_number(-443, "Test Port")
        # Boolean port sızıntı testi.
        with self.assertRaises(PacketEncapsulationError):
            validate_port_number(True, "Test Port")

    def test_13_negative_missing_mandatory_layer(self) -> None:
        """Negatif Kontrol: 7 zorunlu katmandan biri (örn: layer_4_transport) eksikse hata verildiğini doğrular."""
        # Kapsülleme kopyası oluşturuyoruz.
        corrupted = json.loads(json.dumps(self.sample_data))
        # layer_4_transport katmanını siliyoruz.
        del corrupted["encapsulation"]["layer_4_transport"]
        # Hatanın yakalandığını sınıyoruz.
        with self.assertRaises(PacketEncapsulationError) as ctx:
            validate_packet_structure(corrupted)
        # Hata açıklamasında eksik katman adını teyit ediyoruz.
        self.assertIn("Zorunlu katman verisi eksik: 'layer_4_transport'", str(ctx.exception))

    def test_14_negative_invalid_tcp_flag(self) -> None:
        """Negatif Kontrol: TCP bayraklarında geçersiz bayrak dizesi varsa hata fırlatıldığını doğrular."""
        # Bozuk bayrak içeren kopya oluşturuyoruz.
        corrupted = json.loads(json.dumps(self.sample_data))
        # Geçersiz bayrak ekliyoruz.
        corrupted["encapsulation"]["layer_4_transport"]["flags"] = ["ACK", "INVALID_FLAG_XYZ"]
        # İstisnanın fırlatıldığını sınıyoruz.
        with self.assertRaises(PacketEncapsulationError) as ctx:
            validate_packet_structure(corrupted)
        # Hata mesajında geçersiz bayrak uyarısını sınıyoruz.
        self.assertIn("Geçersiz TCP bayrağı", str(ctx.exception))


# Test doğrudan yürütüldüğünde çalıştırıyoruz.
if __name__ == "__main__":
    # Detaylı kipte testleri başlatıyoruz.
    unittest.main()
