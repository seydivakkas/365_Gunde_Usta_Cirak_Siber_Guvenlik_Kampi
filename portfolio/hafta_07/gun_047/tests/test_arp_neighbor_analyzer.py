# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G047: ARP ve Yerel Ağ Komşuluğu Güvenlik Birim Testleri.
Bu test paketi, ARP önbellek yönetimini, statik korumayı, MAC normalizasyonunu,
meşru ARP paket işleme akışını, ARP Spoofing / Zehirleme tespit motorunu (MAC Flip, DAI),
ve biçimsel hata yakalama kontrollerini (negatif testler) kapsamlı olarak doğrular.
"""

import unittest  # Python standart birim test çatısı dahil edilir
import os  # Dosya ve dizin yolu çözümleme modülü dahil edilir
import sys  # Modül import yollarını yönetmek için sys modülü dahil edilir

# Test edilecek uygulamanın dizinini dinamik olarak Python çalışma yoluna ekler
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dosyasının bulunduğu dizini alır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # Uygulama kaynak kod dizini yolunu oluşturur
if app_dir not in sys.path:  # Uygulama dizini henüz Python yolunda kayıtlı değilse ekleme yapar
    sys.path.insert(0, app_dir)  # İlk sıraya ekleyerek modülün doğrudan bulunmasını sağlar

# Test edilecek fonksiyon, veri sınıfları ve hata sınıflarını içe aktarır
from arp_neighbor_analyzer import (
    ARPValidationError,  # Doğrulama hatalarını yakalamak için özel istisna sınıfı
    ARPCacheManager,  # ARP önbellek ve güvenlik yönetim sınıfı
    validate_ipv4,  # IPv4 doğrulama fonksiyonu
    validate_and_normalize_mac,  # MAC doğrulama ve normalizasyon fonksiyonu
    validate_arp_opcode,  # ARP işlem kodu doğrulama fonksiyonu
    generate_markdown_report  # Markdown rapor oluşturucu
)


class TestARPNeighborAnalyzer(unittest.TestCase):
    """ARP protokolü ve yerel ağ komşuluğu analiz motorunu denetleyen test sınıfı."""

    def setUp(self):
        """Her testten önce temiz bir ARPCacheManager örneği başlatır."""
        self.manager = ARPCacheManager()  # Önbellek yöneticisi nesnesini sıfırdan oluşturur

    def test_01_add_valid_dynamic_entry(self):
        """Test 1: Geçerli dinamik bir ARP girişinin önbelleğe eklenmesini doğrular."""
        entry = self.manager.add_or_update_entry("192.168.1.1", "00:1A:2B:3C:4D:01", "eth0", "Dinamik", "Ağ Geçidi")
        self.assertEqual(entry.ip_address, "192.168.1.1")  # IP adresinin doğruluğunu sınar
        self.assertEqual(entry.mac_address, "00:1A:2B:3C:4D:01")  # MAC adresinin doğruluğunu sınar
        self.assertEqual(entry.entry_type, "Dinamik")  # Dinamik türünü sınar
        self.assertFalse(entry.is_static)  # Statik olmadığını sınar
        self.assertIn("192.168.1.1", self.manager.cache)  # Önbellekte yer aldığını doğrular

    def test_02_add_static_entry_and_protection(self):
        """Test 2: Statik girişin dinamik zehirlemelere karşı kilitli kalmasını doğrular."""
        # Statik sunucu kaydı ekler
        entry = self.manager.add_or_update_entry("192.168.1.10", "00:1A:2B:3C:4D:0A", "eth0", "Statik", "DNS Sunucusu")
        self.assertTrue(entry.is_static)  # Statik bayrağını sınar
        # Aynı IP için dinamik sahte güncelleme gönderir
        updated = self.manager.add_or_update_entry("192.168.1.10", "AA:BB:CC:DD:EE:FF", "eth0", "Dinamik")
        # Statik koruma devrede olduğu için MAC adresinin DEĞİŞMEDİĞİNİ doğrular
        self.assertEqual(updated.mac_address, "00:1A:2B:3C:4D:0A")  # Orijinal MAC'in korunduğunu sınar

    def test_03_broadcast_and_multicast_mac_detection(self):
        """Test 3: Yayın (FF:FF:...) ve Çok Noktaya Yayın (01:00:5E:...) MAC bayraklarını doğrular."""
        b_entry = self.manager.add_or_update_entry("192.168.1.255", "FF:FF:FF:FF:FF:FF", "eth0", "Statik")
        self.assertTrue(b_entry.is_broadcast)  # Yayın bayrağını sınar
        self.assertFalse(b_entry.is_multicast)  # Multicast olmadığını sınar

        m_entry = self.manager.add_or_update_entry("224.0.0.1", "01:00:5E:00:00:01", "eth0", "Statik")
        self.assertTrue(m_entry.is_multicast)  # Multicast bayrağını sınar
        self.assertFalse(m_entry.is_broadcast)  # Broadcast olmadığını sınar

    def test_04_mac_normalization_formats(self):
        """Test 4: Cisco nokta ve tireli MAC adreslerinin standart formata dönüştürülmesini sınar."""
        mac_cisco = validate_and_normalize_mac("001a.2b3c.4d01")  # Cisco noktalı format
        mac_hyphen = validate_and_normalize_mac("00-1A-2B-3C-4D-01")  # Windows tireli format
        self.assertEqual(mac_cisco, "00:1A:2B:3C:4D:01")  # Standart iki nokta eşleşmesini sınar
        self.assertEqual(mac_hyphen, "00:1A:2B:3C:4D:01")  # Standart iki nokta eşleşmesini sınar

    def test_05_process_legitimate_arp_packets(self):
        """Test 5: Meşru ARP İstek ve Yanıt paketlerinin hatasız işlendiğini doğrular."""
        # Meşru istek
        alert1 = self.manager.process_arp_packet("E1", "10:00:01", "REQUEST", "192.168.1.50", "52:54:00:12:34:56", "192.168.1.1", "00:00:00:00:00:00")
        self.assertIsNone(alert1)  # Alarm üretilmediğini sınar
        # Meşru yanıt
        alert2 = self.manager.process_arp_packet("E2", "10:00:02", "REPLY", "192.168.1.1", "00:1A:2B:3C:4D:01", "192.168.1.50", "52:54:00:12:34:56")
        self.assertIsNone(alert2)  # Alarm üretilmediğini sınar
        self.assertEqual(self.manager.cache["192.168.1.1"].mac_address, "00:1A:2B:3C:4D:01")  # Ağ geçidinin kaydedildiğini doğrular

    def test_06_detect_arp_cache_poisoning_mac_flip(self):
        """Test 6: Önceden öğrenilmiş bir IP'nin MAC adresinin aniden değişmesiyle (MAC Flip) zehirleme tespitini sınar."""
        # 1. Meşru ağ geçidi öğrenilir
        self.manager.process_arp_packet("E1", "10:00:01", "REPLY", "192.168.1.1", "00:1A:2B:3C:4D:01", "192.168.1.50", "52:54:00:12:34:56")
        # 2. Saldırgan aynı IP için farklı MAC ile sahte yanıt anons eder
        alert = self.manager.process_arp_packet("E2", "10:00:05", "REPLY", "192.168.1.1", "AA:BB:CC:DD:EE:FF", "192.168.1.50", "52:54:00:12:34:56")
        self.assertIsNotNone(alert)  # Güvenlik alarmı oluştuğunu sınar
        self.assertEqual(alert.alert_type, "ARP_CACHE_POISONING_MAC_FLIP")  # Tehdit türünü doğrular
        self.assertEqual(alert.severity, "CRITICAL")  # Tehdit seviyesini doğrular
        self.assertEqual(alert.original_mac, "00:1A:2B:3C:4D:01")  # Eski meşru MAC adresini sınar
        self.assertEqual(alert.spoofed_mac, "AA:BB:CC:DD:EE:FF")  # Saldırgan MAC adresini sınar

    def test_07_detect_dai_dhcp_snooping_violation(self):
        """Test 7: Dynamic ARP Inspection (DAI) - DHCP Snooping veritabanı ihlal tespitini doğrular."""
        # Yetkili DHCP eşleşmesini kaydeder
        self.manager.set_trusted_dhcp_binding("192.168.1.100", "52:54:00:AA:BB:CC")
        # Saldırgan sahte MAC ile bu IP adına paket gönderir
        alert = self.manager.process_arp_packet("E1", "10:00:10", "REPLY", "192.168.1.100", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "00:1A:2B:3C:4D:01")
        self.assertIsNotNone(alert)  # Alarm üretildiğini sınar
        self.assertEqual(alert.alert_type, "DAI_DHCP_SNOOPING_VIOLATION")  # DAI kural ihlalini sınar
        self.assertEqual(alert.severity, "CRITICAL")  # Kritik seviyeyi doğrular

    def test_08_detect_single_mac_multiple_ip_abuse(self):
        """Test 8: Tek bir MAC adresinin birden fazla farklı IP'yi sahiplenmesi durumunu sınar."""
        # 1. IP eşleşmesi
        self.manager.process_arp_packet("E1", "10:00:01", "REPLY", "192.168.1.50", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "00:1A:2B:3C:4D:01")
        # 2. Farklı bir IP aynı saldırgan MAC ile anons edilir
        alert = self.manager.process_arp_packet("E2", "10:00:02", "REPLY", "192.168.1.99", "AA:BB:CC:DD:EE:FF", "192.168.1.1", "00:1A:2B:3C:4D:01")
        self.assertIsNotNone(alert)  # Alarm oluştuğunu sınar
        self.assertEqual(alert.alert_type, "SINGLE_MAC_MULTIPLE_IP_ABUSE")  # Çoklu IP ihlalini doğrular
        self.assertEqual(alert.severity, "HIGH")  # Tehdit seviyesini doğrular

    def test_09_markdown_report_generation(self):
        """Test 9: Markdown analiz raporunun eksiksiz tablo ve alarm bölümleri içerdiğini sınar."""
        self.manager.add_or_update_entry("192.168.1.1", "00:1A:2B:3C:4D:01", "eth0", "Statik", "Gateway")
        report = generate_markdown_report(self.manager)
        self.assertIn("# ARP Tablosu, Yerel Ağ Komşuluğu", report)  # Başlık kontrolü
        self.assertIn("192.168.1.1", report)  # IP girişi kontrolü
        self.assertIn("Dynamic ARP Inspection (DAI)", report)  # Savunma prensipleri kontrolü

    def test_10_negative_invalid_ip_octet_and_zero(self):
        """Test 10: Negatif kontrol: 255 üstü oktet ve leading zero formatını sınar."""
        with self.assertRaises(ARPValidationError) as ctx1:
            validate_ipv4("192.168.1.300")  # 300 geçersiz okteti
        self.assertIn("Geçersiz IPv4 adresi oktet değeri: 300", str(ctx1.exception))  # Hata mesajını sınar

        with self.assertRaises(ARPValidationError) as ctx2:
            validate_ipv4("192.168.01.1")  # Başta sıfır
        self.assertIn("gereksiz sıfır bulunamaz", str(ctx2.exception))  # Hata mesajını sınar

    def test_11_negative_invalid_mac_length_and_hex(self):
        """Test 11: Negatif kontrol: Eksik oktetli ve geçersiz harfli MAC adreslerini sınar."""
        with self.assertRaises(ARPValidationError) as ctx1:
            validate_and_normalize_mac("00:1A:2B:3C:4D")  # 5 oktet
        self.assertIn("6 oktetten (12 onaltılık hane) oluşmalıdır", str(ctx1.exception))  # Hata mesajını sınar

        with self.assertRaises(ARPValidationError) as ctx2:
            validate_and_normalize_mac("00:1A:2B:3C:4D:GG")  # GG geçersiz hex
        self.assertIn("geçersiz onaltılık (hex) karakter", str(ctx2.exception))  # Hata mesajını sınar

    def test_12_negative_unicast_all_zero_mac(self):
        """Test 12: Negatif kontrol: Tamamen sıfırlardan oluşan tekil MAC adresini sınar."""
        with self.assertRaises(ARPValidationError) as ctx:
            validate_and_normalize_mac("00:00:00:00:00:00")  # Tamamen sıfır MAC
        self.assertIn("tamamen sıfır", str(ctx.exception))  # Hata mesajını sınar

    def test_13_negative_missing_fields(self):
        """Test 13: Negatif kontrol: Boş IP, boş MAC veya boş arayüz durumlarını sınar."""
        with self.assertRaises(ARPValidationError):
            validate_ipv4("")  # Boş IP

        with self.assertRaises(ARPValidationError):
            validate_and_normalize_mac("")  # Boş MAC

        with self.assertRaises(ARPValidationError):
            self.manager.add_or_update_entry("192.168.1.1", "00:1A:2B:3C:4D:01", "")  # Boş arayüz

    def test_14_negative_invalid_arp_opcode(self):
        """Test 14: Negatif kontrol: Desteklenmeyen ARP işlem kodunu (Opcode) sınar."""
        with self.assertRaises(ARPValidationError) as ctx:
            validate_arp_opcode("INVALID_OPCODE_99")  # Geçersiz işlem kodu
        self.assertIn("Desteklenmeyen ARP işlem kodu", str(ctx.exception))  # Hata mesajını sınar


if __name__ == "__main__":
    unittest.main()  # Testler doğrudan çağrıldığında test motorunu yürütür
