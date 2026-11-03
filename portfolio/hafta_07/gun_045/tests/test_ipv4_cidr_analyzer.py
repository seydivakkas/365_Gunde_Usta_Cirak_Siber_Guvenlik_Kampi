# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G045: IPv4 Adresleme, Alt Ağ (Subnetting) ve CIDR Analiz Birim ve Güvenlik Testleri.
Bu test paketi, IPv4 adres geçerleme, CIDR hesaplamaları, /31 ve /32 uç durumları,
RFC 1918 ve Bogon IP filtreleme kuralları, VLSM alt ağ bölme ve negatif kontrolleri
kapsamlı olarak doğrular.
"""

import unittest  # Python standart birim test çatısı test senaryolarını oluşturmak için dahil edilir
import os  # İşletim sistemi dosya yolu işlemlerini yürütmek için dahil edilir
import sys  # Sistem yolu manipülasyonu ve modül importu için dahil edilir

# Test edilen uygulamanın modül yolunu çalışma zamanı yol listesine ekler
current_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut test dosyasının bulunduğu dizini alır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # Uygulama kaynak kod dizini yolunu oluşturur
if app_dir not in sys.path:  # Uygulama dizini henüz Python yolunda kayıtlı değilse ekleme yapar
    sys.path.insert(0, app_dir)  # İlk sıraya ekleyerek modülün doğrudan bulunmasını sağlar

# Test edilecek fonksiyon, veri sınıfları ve hata sınıflarını içe aktarır
from ipv4_cidr_analyzer import (
    IPv4ValidationError,  # Doğrulama hatalarını yakalamak için özel istisna sınıfı
    calculate_subnet,  # Alt ağ hesaplama ana fonksiyonu
    is_ip_in_subnet,  # Alt ağ üyelik kontrolü fonksiyonu
    split_subnet,  # VLSM alt ağ bölme fonksiyonu
    mask_str_to_prefix,  # Ağ maskesinden CIDR öneki hesaplama fonksiyonu
    validate_and_parse_ip,  # IP format doğrulama fonksiyonu
    prefix_to_mask_int  # Önekten tamsayı maske üretme fonksiyonu
)


class TestIPv4CIDRAnalyzer(unittest.TestCase):
    """IPv4 Adresleme ve CIDR analiz fonksiyonlarının doğruluğunu denetleyen test sınıfı."""

    def test_01_standard_c_class_subnet(self):
        """Test 1: Standart C Sınıfı /24 alt ağ hesaplamalarını doğrular."""
        sub = calculate_subnet("192.168.1.10/24")  # 192.168.1.10/24 alt ağını hesaplar
        self.assertEqual(sub.network_address, "192.168.1.0")  # Ağ kimliğinin doğruluğunu sınar
        self.assertEqual(sub.broadcast_address, "192.168.1.255")  # Yayın adresinin doğruluğunu sınar
        self.assertEqual(sub.first_usable_host, "192.168.1.1")  # İlk konak adresinin doğruluğunu sınar
        self.assertEqual(sub.last_usable_host, "192.168.1.254")  # Son konak adresinin doğruluğunu sınar
        self.assertEqual(sub.total_addresses, 256)  # Toplam adres adedinin 256 olduğunu sınar
        self.assertEqual(sub.usable_hosts, 254)  # Kullanılabilir konak sayısının 254 olduğunu sınar
        self.assertEqual(sub.wildcard_str, "0.0.0.255")  # Ters maskenin 0.0.0.255 olduğunu sınar
        self.assertTrue(sub.is_private)  # RFC 1918 özel IP olduğunu doğrular
        self.assertTrue(sub.is_bogon)  # İnternet üzerinde bogon olduğunu doğrular

    def test_02_large_a_class_subnet(self):
        """Test 2: Geniş ölçekli A Sınıfı /16 kurumsal alt ağ hesaplamalarını doğrular."""
        sub = calculate_subnet("10.50.0.1/16")  # 10.50.0.1/16 alt ağını hesaplar
        self.assertEqual(sub.network_address, "10.50.0.0")  # Ağ adresinin 10.50.0.0 olduğunu sınar
        self.assertEqual(sub.broadcast_address, "10.50.255.255")  # Yayın adresinin 10.50.255.255 olduğunu sınar
        self.assertEqual(sub.usable_hosts, 65534)  # Kullanılabilir konak adedinin 65534 olduğunu sınar
        self.assertEqual(sub.netmask_str, "255.255.0.0")  # Alt ağ maskesini sınar
        self.assertEqual(sub.wildcard_str, "0.0.255.255")  # Wildcard maskesini sınar

    def test_03_micro_segmentation_dmz(self):
        """Test 3: Mikro-segmentasyon DMZ /28 alt ağ hesaplamalarını doğrular."""
        sub = calculate_subnet("172.16.100.45/28")  # 172.16.100.45/28 alt ağını hesaplar
        self.assertEqual(sub.network_address, "172.16.100.32")  # 32 tabanlı alt ağı sınar
        self.assertEqual(sub.broadcast_address, "172.16.100.47")  # Yayın adresini sınar
        self.assertEqual(sub.first_usable_host, "172.16.100.33")  # İlk konağı sınar
        self.assertEqual(sub.last_usable_host, "172.16.100.46")  # Son konağı sınar
        self.assertEqual(sub.usable_hosts, 14)  # 16 - 2 = 14 konak olduğunu sınar
        self.assertEqual(sub.netmask_str, "255.255.255.240")  # Maskeyi doğrular

    def test_04_traditional_point_to_point(self):
        """Test 4: Geleneksel yönlendirici /30 noktadan noktaya link ağını doğrular."""
        sub = calculate_subnet("10.0.0.1/30")  # 10.0.0.1/30 alt ağını hesaplar
        self.assertEqual(sub.network_address, "10.0.0.0")  # Ağ adresini sınar
        self.assertEqual(sub.broadcast_address, "10.0.0.3")  # Yayın adresini sınar
        self.assertEqual(sub.first_usable_host, "10.0.0.1")  # İlk konağı sınar
        self.assertEqual(sub.last_usable_host, "10.0.0.2")  # Son konağı sınar
        self.assertEqual(sub.usable_hosts, 2)  # Yalnızca 2 konak atanabilir olduğunu sınar

    def test_05_rfc3021_31_point_to_point(self):
        """Test 5: RFC 3021 /31 modern noktadan noktaya bağlantı istisnasını doğrular."""
        sub = calculate_subnet("192.0.2.1/31")  # RFC 3021 uyumlu /31 ağını hesaplar
        self.assertEqual(sub.network_address, "192.0.2.0")  # Ağ adresini sınar
        self.assertEqual(sub.broadcast_address, "Yok (RFC 3021)")  # Yayın adresi olmadığını doğrular
        self.assertEqual(sub.first_usable_host, "192.0.2.0")  # İlk konağın 192.0.2.0 olduğunu sınar
        self.assertEqual(sub.last_usable_host, "192.0.2.1")  # İkinci konağın 192.0.2.1 olduğunu sınar
        self.assertEqual(sub.usable_hosts, 2)  # Her iki adresin de konak olduğunu sınar

    def test_06_single_host_route_32(self):
        """Test 6: /32 tekil cihaz ve konak rotası istisnasını doğrular."""
        sub = calculate_subnet("198.51.100.5/32")  # /32 tekil IP girdisini hesaplar
        self.assertEqual(sub.network_address, "198.51.100.5")  # Ağ adresinin kendisi olduğunu sınar
        self.assertEqual(sub.broadcast_address, "Yok (/32 Tekil Host)")  # Yayın olmadığını doğrular
        self.assertEqual(sub.usable_hosts, 1)  # Sadece 1 konak olduğunu sınar
        self.assertEqual(sub.first_usable_host, "198.51.100.5")  # İlk konağı sınar
        self.assertEqual(sub.last_usable_host, "198.51.100.5")  # Son konağın da aynı olduğunu sınar

    def test_07_cgnat_shared_address(self):
        """Test 7: RFC 6598 Operatör Seviyesi NAT (CGNAT) bloğunu doğrular."""
        sub = calculate_subnet("100.64.10.50/20")  # 100.64.0.0/10 aralığında /20 alt ağını hesaplar
        self.assertEqual(sub.category, "RFC 6598 Shared Address Space (CGNAT)")  # CGNAT sınıfını sınar
        self.assertTrue(sub.is_bogon)  # İnternette filtrelenmesi gerektiğini doğrular
        self.assertEqual(sub.usable_hosts, 4094)  # 4096 - 2 = 4094 konak olduğunu sınar

    def test_08_public_ip_routable(self):
        """Test 8: Genel internette yönlendirilebilir Public IP bloğunu doğrular."""
        sub = calculate_subnet("8.8.8.8/24")  # Google DNS bloğundan /24 alt ağını hesaplar
        self.assertEqual(sub.category, "Public Routable IP")  # Genel yönlendirilebilir olduğunu sınar
        self.assertFalse(sub.is_bogon)  # Bogon olmadığını doğrular
        self.assertFalse(sub.is_private)  # Özel IP olmadığını doğrular

    def test_09_subnet_membership(self):
        """Test 9: Bir IP adresinin alt ağa ait olup olmadığını test eder."""
        self.assertTrue(is_ip_in_subnet("192.168.1.55", "192.168.1.0/24"))  # Alt ağa ait IP doğrulaması
        self.assertFalse(is_ip_in_subnet("192.168.2.1", "192.168.1.0/24"))  # Farklı alt ağdaki IP reddi
        self.assertTrue(is_ip_in_subnet("10.50.200.12", "10.50.0.0/16"))  # A sınıfı alt ağ üyeliği
        self.assertFalse(is_ip_in_subnet("10.51.0.1", "10.50.0.0/16"))  # Farklı ağdaki A sınıfı IP reddi

    def test_10_vlsm_subnet_splitting(self):
        """Test 10: VLSM ile bir ana ağı (/24) daha küçük alt ağlara (/26) bölmeyi doğrular."""
        subnets = split_subnet("192.168.1.0/24", 26)  # /24 ağını /26'ya böler
        self.assertEqual(len(subnets), 4)  # 2^(26-24) = 4 alt ağ oluştuğunu sınar
        self.assertEqual(subnets[0].network_address, "192.168.1.0")  # 1. alt ağ başlangıcı
        self.assertEqual(subnets[1].network_address, "192.168.1.64")  # 2. alt ağ başlangıcı
        self.assertEqual(subnets[2].network_address, "192.168.1.128")  # 3. alt ağ başlangıcı
        self.assertEqual(subnets[3].network_address, "192.168.1.192")  # 4. alt ağ başlangıcı

    def test_11_mask_str_to_prefix_and_non_contiguous(self):
        """Test 11: Noktalı alt ağ maskesi dönüşümünü ve bitişik olmayan maske reddini sınar."""
        self.assertEqual(mask_str_to_prefix("255.255.255.0"), 24)  # 255.255.255.0 -> 24 öneki
        self.assertEqual(mask_str_to_prefix("255.255.255.240"), 28)  # 255.255.255.240 -> 28 öneki
        with self.assertRaises(IPv4ValidationError):
            mask_str_to_prefix("255.255.0.255")  # Bitişik olmayan maske hatasını sınar

    def test_12_negative_octet_out_of_range(self):
        """Test 12: Negatif kontrol: 255 üstü oktet değerinin reddedilmesini sınar."""
        with self.assertRaises(IPv4ValidationError) as ctx:
            calculate_subnet("256.1.1.1/24")  # 256 hatalı okteti içeren IP'yi hesaplamaya çalışır
        self.assertIn("0 ile 255 arasında olmalıdır", str(ctx.exception))  # Hata mesajını doğrular

    def test_13_negative_octet_count_and_leading_zero(self):
        """Test 13: Negatif kontrol: Eksik oktet ve başta gereksiz sıfır formatını sınar."""
        with self.assertRaises(IPv4ValidationError) as ctx1:
            calculate_subnet("192.168.1/24")  # 3 oktetli eksik IP
        self.assertIn("tam olarak 4 oktetten oluşmalıdır", str(ctx1.exception))  # Hata mesajını doğrular

        with self.assertRaises(IPv4ValidationError) as ctx2:
            calculate_subnet("192.168.01.1/24")  # Başında 0 olan geçersiz oktet
        self.assertIn("leading zero", str(ctx2.exception))  # Leading zero hatasını doğrular

    def test_14_negative_prefix_out_of_range_and_missing_slash(self):
        """Test 14: Negatif kontrol: 32 üstü önek ve '/' eksikliğini sınar."""
        with self.assertRaises(IPv4ValidationError) as ctx1:
            calculate_subnet("192.168.1.1/33")  # Geçersiz 33 öneki
        self.assertIn("0 ile 32 arasında olmalıdır", str(ctx1.exception))  # Sınır aşım hatasını doğrular

        with self.assertRaises(IPv4ValidationError) as ctx2:
            calculate_subnet("192.168.1.1")  # CIDR ayracı olmayan IP
        self.assertIn("'/' ayracı bulunamadı", str(ctx2.exception))  # CIDR ayracı hatasını doğrular


if __name__ == "__main__":
    unittest.main()  # Testler doğrudan çağrıldığında test motorunu çalıştırır
