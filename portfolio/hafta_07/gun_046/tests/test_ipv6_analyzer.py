# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G046: IPv6 Temel Kavramlar, Sıkıştırma (RFC 5952) ve Güvenlik Birim Testleri.
Bu test modülü, IPv6 adres ayrıştırma, tam açılım, kanonik sıkıştırma,
adres türü sınıflandırması, Solicited-Node Multicast hesaplama,
EUI-64 MAC dönüşümü ve kapsamlı negatif kontrolleri doğrular.
"""

import unittest  # Python standart birim test çatısı dahil edilir
import os  # Dosya ve dizin yolu çözümleme modülü dahil edilir
import sys  # Modül arama yollarını yönetmek için sys modülü dahil edilir

# Test edilecek uygulamanın dizinini dinamik olarak Python yoluna ekler
current_dir = os.path.dirname(os.path.abspath(__file__))  # Test dosyasının bulunduğu dizini alır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # Uygulama kaynak kod dizini yolunu oluşturur
if app_dir not in sys.path:  # Uygulama dizini henüz Python yolunda kayıtlı değilse ekleme yapar
    sys.path.insert(0, app_dir)  # İlk sıraya ekleyerek modülün doğrudan bulunmasını sağlar

# Test edilecek fonksiyon, veri sınıfları ve hata sınıflarını içe aktarır
from ipv6_analyzer import (
    IPv6ValidationError,  # Doğrulama hatalarını yakalamak için özel istisna sınıfı
    analyze_ipv6,  # IPv6 analiz ana fonksiyonu
    compress_ipv6_rfc5952,  # RFC 5952 kanonik sıkıştırma fonksiyonu
    calculate_solicited_node_multicast,  # Solicited-Node Multicast hesaplama fonksiyonu
    generate_eui64_from_mac,  # EUI-64 türetim fonksiyonu
    expand_ipv6_address  # IPv6 genişletme fonksiyonu
)


class TestIPv6Analyzer(unittest.TestCase):
    """IPv6 analiz motorunun biçimsel ve güvenlik kurallarını doğrulayan test sınıfı."""

    def test_01_global_unicast_compression(self):
        """Test 1: Genel Tekil Yayın (GUA) adresinin açılımını ve RFC 5952 sıkıştırmasını sınar."""
        res = analyze_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334/64")  # Örnek GUA adresini analiz eder
        self.assertEqual(res.expanded_address, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")  # 39 karakterlik tam açılımı sınar
        self.assertEqual(res.canonical_compressed, "2001:db8:85a3::8a2e:370:7334")  # RFC 5952 kanonik sıkıştırmasını sınar
        self.assertEqual(res.address_type, "Global Unicast (GUA)")  # Adres türünü doğrular
        self.assertEqual(res.scope, "Global")  # Etki alanının Global olduğunu doğrular
        self.assertTrue(res.is_global_unicast)  # GUA bayrağını doğrular
        self.assertEqual(res.prefix_length, 64)  # /64 önek uzunluğunu sınar

    def test_02_link_local_unicast(self):
        """Test 2: fe80::/10 Bağlantı Yerel (Link-Local) adresinin analizini sınar."""
        res = analyze_ipv6("fe80:0000:0000:0000:021a:2bff:fe3c:4d5e/64")  # Link-Local adresini analiz eder
        self.assertEqual(res.canonical_compressed, "fe80::21a:2bff:fe3c:4d5e")  # Kısaltılmış halini sınar
        self.assertEqual(res.address_type, "Link-Local Unicast")  # Link-Local türünü sınar
        self.assertEqual(res.scope, "Link-Local")  # Kapsamını doğrular
        self.assertTrue(res.is_link_local)  # Link-Local bayrağının True olduğunu doğrular
        self.assertFalse(res.is_global_unicast)  # GUA olmadığını doğrular

    def test_03_unique_local_address_ula(self):
        """Test 3: fc00::/7 Benzersiz Yerel Adres (ULA) analizini sınar."""
        res = analyze_ipv6("fd00:0000:0000:0001:0000:0000:0000:0005/64")  # ULA adresini analiz eder
        self.assertEqual(res.canonical_compressed, "fd00:0:0:1::5")  # En uzun 3 sıfırın '::' ile kısaltıldığını sınar
        self.assertEqual(res.address_type, "Unique Local Address (ULA)")  # ULA türünü sınar
        self.assertEqual(res.scope, "Unique Local")  # Kapsamını doğrular
        self.assertTrue(res.is_unique_local)  # ULA bayrağını doğrular

    def test_04_loopback_address(self):
        """Test 4: ::1/128 Geri Döngü (Loopback) adresinin analizini sınar."""
        res = analyze_ipv6("0000:0000:0000:0000:0000:0000:0000:0001/128")  # Tam açılmış loopback adresini işler
        self.assertEqual(res.canonical_compressed, "::1")  # Kısaltmanın ::1 olduğunu sınar
        self.assertEqual(res.address_type, "Loopback")  # Adres türünü sınar
        self.assertEqual(res.scope, "Node-Local")  # Düğüm içi yerel kapsamı sınar
        self.assertTrue(res.is_loopback)  # Loopback bayrağını doğrular
        self.assertEqual(res.int_value, 1)  # 128-bitlik değerin 1 olduğunu sınar

    def test_05_unspecified_address(self):
        """Test 5: ::/128 Belirtilmemiş (Unspecified) adresin analizini sınar."""
        res = analyze_ipv6("0000:0000:0000:0000:0000:0000:0000:0000/128")  # Belirtilmemiş adresi işler
        self.assertEqual(res.canonical_compressed, "::")  # Tüm sıfırların :: olduğunu sınar
        self.assertEqual(res.address_type, "Unspecified Address")  # Türünü sınar
        self.assertTrue(res.is_unspecified)  # Belirtilmemiş bayrağını doğrular
        self.assertEqual(res.int_value, 0)  # Tamsayı değerinin 0 olduğunu sınar

    def test_06_all_nodes_multicast(self):
        """Test 6: ff02::1 Tüm Düğümler Çok Noktaya Yayın (Multicast) adresini sınar."""
        res = analyze_ipv6("ff02:0000:0000:0000:0000:0000:0000:0001/16")  # Multicast adresini işler
        self.assertEqual(res.canonical_compressed, "ff02::1")  # Kısaltılmış halini sınar
        self.assertEqual(res.address_type, "Multicast (All Nodes)")  # Özel çok noktaya yayın türünü sınar
        self.assertTrue(res.is_multicast)  # Multicast bayrağını doğrular

    def test_07_ipv4_mapped_ipv6(self):
        """Test 7: ::ffff:c000:280/96 IPv4 Eşlemeli IPv6 adresini doğrular."""
        res = analyze_ipv6("0000:0000:0000:0000:0000:ffff:c000:0280/96")  # IPv4 mapped adresini işler
        self.assertEqual(res.canonical_compressed, "::ffff:c000:280")  # Sıkıştırılmış halini sınar
        self.assertEqual(res.address_type, "IPv4-Mapped IPv6")  # Geçiş türünü sınar
        self.assertTrue(res.is_ipv4_mapped)  # IPv4 mapped bayrağını doğrular

    def test_08_solicited_node_multicast(self):
        """Test 8: RFC 4291 Solicited-Node Multicast adres üretimini doğrular."""
        hextets1, _ = expand_ipv6_address("2001:db8:85a3::8a2e:370:7334")  # GUA adresini açar
        solicited1 = calculate_solicited_node_multicast(hextets1)  # Solicited multicast üretir
        self.assertEqual(solicited1, "ff02::1:ff70:7334")  # Son 24 bitin (70:7334) doğruluğunu sınar

        hextets2, _ = expand_ipv6_address("fe80::21a:2bff:fe3c:4d5e")  # Link-Local adresini açar
        solicited2 = calculate_solicited_node_multicast(hextets2)  # Solicited multicast üretir
        self.assertEqual(solicited2, "ff02::1:ff3c:4d5e")  # Son 24 bitin (3c:4d5e) doğruluğunu sınar

    def test_09_eui64_generation(self):
        """Test 9: 48-bit MAC adresinden EUI-64 Link-Local adres türetimini doğrular."""
        eui64_res = generate_eui64_from_mac("00:1A:2B:3C:4D:5E")  # Standart MAC adresi girer
        # 00 -> 02 (U/L biti ters) ve FF:FE ortada: fe80::21a:2bff:fe3c:4d5e/64
        self.assertEqual(eui64_res, "fe80::21a:2bff:fe3c:4d5e/64")  # EUI-64 çıktısının doğruluğunu sınar

    def test_10_eui64_different_mac_formats(self):
        """Test 10: Farklı MAC formatlarının (tire, nokta) EUI-64 çıktısını doğrular."""
        res_hyphen = generate_eui64_from_mac("00-1A-2B-3C-4D-5E")  # Tireli MAC formatı
        res_cisco = generate_eui64_from_mac("001a.2b3c.4d5e")  # Cisco noktalı MAC formatı
        self.assertEqual(res_hyphen, "fe80::21a:2bff:fe3c:4d5e/64")  # Tireli çıktıyı sınar
        self.assertEqual(res_cisco, "fe80::21a:2bff:fe3c:4d5e/64")  # Cisco çıktısını sınar

    def test_11_rfc5952_single_zero_hextet_not_compressed(self):
        """Test 11: RFC 5952 Kural 4.2.2: Tekil sıfır hextetinin '::' ile kısaltılamayacağını sınar."""
        hextets, _ = expand_ipv6_address("2001:db8:0:1:1:1:1:1")  # Tek sıfır içeren adres
        compressed = compress_ipv6_rfc5952(hextets)  # Kısaltmayı yürütür
        self.assertEqual(compressed, "2001:db8:0:1:1:1:1:1")  # Tek sıfırın :: OLMADIĞINI doğrular

    def test_12_negative_multiple_double_colons(self):
        """Test 12: Negatif kontrol: Birden fazla '::' bulunması durumunu sınar."""
        with self.assertRaises(IPv6ValidationError) as ctx:
            analyze_ipv6("2001::db8::1")  # İki adet '::' içeren geçersiz adres
        self.assertIn("en fazla bir adet '::'", str(ctx.exception))  # Hata mesajını doğrular

    def test_13_negative_invalid_hex_and_hextet_length(self):
        """Test 13: Negatif kontrol: Geçersiz onaltılık karakter ve uzun hexteti sınar."""
        with self.assertRaises(IPv6ValidationError) as ctx1:
            analyze_ipv6("2001:0db8:85g3::1")  # 'g' harfi içeren geçersiz hex
        self.assertIn("Geçersiz onaltılık (hex) karakter", str(ctx1.exception))  # Hata mesajını doğrular

        with self.assertRaises(IPv6ValidationError) as ctx2:
            analyze_ipv6("2001:00db8::1")  # 5 haneli hextet
        self.assertIn("1 ila 4 onaltılık karakterden oluşmalıdır", str(ctx2.exception))  # Hata mesajını doğrular

    def test_14_negative_prefix_and_hextet_count(self):
        """Test 14: Negatif kontrol: 8'den fazla/az hextet ve geçersiz önek uzunluğunu sınar."""
        with self.assertRaises(IPv6ValidationError) as ctx1:
            analyze_ipv6("1:2:3:4:5:6:7:8:9")  # 9 hextet içeren adres
        self.assertIn("tam olarak 8 hextet içermelidir", str(ctx1.exception))  # Hata mesajını doğrular

        with self.assertRaises(IPv6ValidationError) as ctx2:
            analyze_ipv6("2001:db8::1/129")  # 128'den büyük önek
        self.assertIn("0 ile 128 arasında olmalıdır", str(ctx2.exception))  # Önek sınır hatasını doğrular


if __name__ == "__main__":
    unittest.main()  # Testler doğrudan çağrıldığında test motorunu çalıştırır
