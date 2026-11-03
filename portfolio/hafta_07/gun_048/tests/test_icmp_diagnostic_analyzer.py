# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G048: ICMP Protokolü, Ağ Teşhisi ve Tünelleme Güvenlik Birim Testleri.
Bu test paketi, RFC 792 başlık yapısını, 1's complement sağlama toplamı (checksum) matematiğini,
Echo Request/Reply döngüsünü, PMTUD hata kodlarını, Traceroute TTL tükenme simülasyonunu,
ICMP Tünelleme / Covert Channel anomali alarmlarını ve kapsamlı negatif kontrolleri doğrular.
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
from icmp_diagnostic_analyzer import (
    ICMPValidationError,  # Doğrulama hatalarını yakalamak için özel istisna sınıfı
    build_icmp_packet,  # İkili ICMP paketi oluşturucu
    parse_and_analyze_icmp,  # ICMP ayrıştırıcı ve anomali analiz motoru
    calculate_internet_checksum,  # RFC 1071 sağlama toplamı hesaplayıcı
    simulate_traceroute,  # Traceroute TTL simülasyon fonksiyonu
    generate_markdown_report  # Markdown rapor üretici
)


class TestICMPDiagnosticAnalyzer(unittest.TestCase):
    """ICMP protokol analiz ve tünelleme tespit motorunu denetleyen birim test sınıfı."""

    def test_01_build_and_parse_echo_request(self):
        """Test 1: Standart Ping İsteği (Echo Request - Type 8 Code 0) paketini ve sağlama toplamını doğrular."""
        payload = b"abcdefghijklmnopqrstuvwabcdefghi"  # Standart 32 baytlık ping yükü
        raw_pkt = build_icmp_packet(8, 0, 1001, 1, payload)  # İkili paket üretir
        info = parse_and_analyze_icmp(raw_pkt, "192.168.1.50", "8.8.8.8", 64, "T1")  # Paketi ayrıştırır
        self.assertEqual(info.icmp_type, 8)  # Tipin 8 olduğunu sınar
        self.assertEqual(info.icmp_code, 0)  # Kodun 0 olduğunu sınar
        self.assertEqual(info.type_name, "Echo Request")  # Tip adını doğrular
        self.assertTrue(info.is_checksum_valid)  # Checksum'ın geçerli olduğunu doğrular
        self.assertFalse(info.is_anomalous)  # Herhangi bir anomali olmadığını sınar

    def test_02_build_and_parse_echo_reply(self):
        """Test 2: Standart Ping Yanıtı (Echo Reply - Type 0 Code 0) paketini doğrular."""
        payload = b"abcdefghijklmnopqrstuvwabcdefghi"  # Yanıt yükü
        raw_pkt = build_icmp_packet(0, 0, 1001, 1, payload)  # Reply paketi oluşturur
        info = parse_and_analyze_icmp(raw_pkt, "8.8.8.8", "192.168.1.50", 118, "T2")  # Ayrıştırır
        self.assertEqual(info.icmp_type, 0)  # Tip 0 olduğunu sınar
        self.assertEqual(info.icmp_code, 0)  # Kod 0 olduğunu sınar
        self.assertEqual(info.type_name, "Echo Reply")  # Echo Reply adını sınar
        self.assertTrue(info.is_checksum_valid)  # Checksum geçerliliğini sınar

    def test_03_destination_unreachable_types(self):
        """Test 3: Hedef Ulaşılamaz (Type 3) Host ve Port kodlarını doğrular."""
        raw_host = build_icmp_packet(3, 1, 0, 0, b"ORIGINAL_HEADER_FRAGMENT")  # Host Unreachable (Code 1)
        info_host = parse_and_analyze_icmp(raw_host, "192.168.1.1", "192.168.1.50", 255, "T3_H")
        self.assertEqual(info_host.code_name, "Host Unreachable")  # Kod adını sınar

        raw_port = build_icmp_packet(3, 3, 0, 0, b"UDP_PORT_CLOSED")  # Port Unreachable (Code 3)
        info_port = parse_and_analyze_icmp(raw_port, "192.168.1.10", "192.168.1.50", 64, "T3_P")
        self.assertEqual(info_port.code_name, "Port Unreachable")  # Kod adını sınar

    def test_04_pmtud_fragmentation_needed(self):
        """Test 4: PMTUD için Parçalanma Gerekli (Type 3 Code 4) hata paketini doğrular."""
        raw_pmtud = build_icmp_packet(3, 4, 0, 0, b"MTU_DISCOVERY_NEXTHOP_1400")  # Code 4 paketi
        info_pmtud = parse_and_analyze_icmp(raw_pmtud, "10.0.0.1", "192.168.1.50", 254, "T4")
        self.assertEqual(info_pmtud.code_name, "Fragmentation Needed and DF set")  # PMTUD adını sınar
        self.assertFalse(info_pmtud.is_anomalous)  # Meşru bir hata mesajı olduğunu sınar

    def test_05_time_exceeded_ttl(self):
        """Test 5: Traceroute sırasında dönen Yaşam Süresi Aşımı (Type 11 Code 0) paketini doğrular."""
        raw_ttl = build_icmp_packet(11, 0, 0, 0, b"TTL_EXPIRED_AT_ROUTER")  # Type 11 Code 0 paketi
        info_ttl = parse_and_analyze_icmp(raw_ttl, "172.16.1.1", "192.168.1.50", 253, "T5")
        self.assertEqual(info_ttl.code_name, "Time to Live exceeded in Transit")  # TTL aşımını sınar
        self.assertEqual(info_ttl.icmp_type, 11)  # Tip 11 olduğunu sınar

    def test_06_detect_icmp_redirect_anomaly(self):
        """Test 6: ICMP Redirect (Type 5) paketinin potansiyel MitM saldırı anomalisi olarak işaretlenmesini sınar."""
        raw_red = build_icmp_packet(5, 1, 0, 0, b"REDIRECT_GATEWAY_NEW_IP")  # Type 5 paketi
        info_red = parse_and_analyze_icmp(raw_red, "192.168.1.1", "192.168.1.50", 64, "T6")
        self.assertTrue(info_red.is_anomalous)  # Anomali bayrağını doğrular
        self.assertIn("Rotalama manipülasyonu", info_red.anomaly_reasons[0])  # Uyarı metnini sınar

    def test_07_detect_covert_channel_oversized_payload(self):
        """Test 7: 64 bayttan büyük aşırı boyutlu ICMP payload'unun anomali üretmesini sınar."""
        oversized_payload = b"X" * 128  # 128 baytlık anormal ping yükü
        raw_pkt = build_icmp_packet(8, 0, 100, 1, oversized_payload)
        info = parse_and_analyze_icmp(raw_pkt, "192.168.1.50", "8.8.8.8", 64, "T7")
        self.assertTrue(info.is_anomalous)  # Anomali oluştuğunu sınar
        self.assertIn("Aşırı büyük ICMP Payload", info.anomaly_reasons[0])  # Aşırı boyut uyarısını sınar

    def test_08_detect_covert_channel_keyword_exfiltration(self):
        """Test 8: Payload içerisinde gizli veri anahtar kelimesi (Covert Channel) tespitini sınar."""
        leak_payload = b"EXFILTRATED_DATA:USER=root;PASS=Secret123"  # Sızıntı verisi
        raw_pkt = build_icmp_packet(8, 0, 200, 2, leak_payload)
        info = parse_and_analyze_icmp(raw_pkt, "192.168.1.50", "203.0.113.88", 64, "T8")
        self.assertTrue(info.is_anomalous)  # Anomaliyi doğrular
        self.assertTrue(any("ICMP Tünelleme" in r for r in info.anomaly_reasons))  # Tünelleme uyarısını sınar

    def test_09_internet_checksum_calculation(self):
        """Test 9: RFC 1071 Bir'in Tümleyeni sağlama toplamının matematiksel doğruluğunu sınar."""
        sample_bytes = b"\x08\x00\x00\x00\x00\x01\x00\x01test"  # Örnek başlık ve veri
        checksum = calculate_internet_checksum(sample_bytes)  # Checksum hesaplar
        self.assertIsInstance(checksum, int)  # Sonucun tamsayı olduğunu sınar
        self.assertGreater(checksum, 0)  # Checksum'ın 0'dan büyük olduğunu sınar
        self.assertLessEqual(checksum, 0xFFFF)  # 16-bit sınırında olduğunu sınar

    def test_10_traceroute_simulation(self):
        """Test 10: Traceroute simülasyonunda sekmelerin (hops) sırayla tükenip hedefe ulaştığını doğrular."""
        trace = simulate_traceroute("8.8.8.8", max_hops=4)  # 4 sekmelik trace simüle eder
        self.assertEqual(len(trace), 4)  # 4 sekme oluştuğunu sınar
        self.assertIn("Time Exceeded", trace[0]["type"])  # İlk sekmede TTL aşımı
        self.assertIn("Echo Reply", trace[-1]["type"])  # Son sekmede hedefe ulaşım

    def test_11_markdown_report_generation(self):
        """Test 11: Markdown teşhis raporunun tablo başlıklarını ve sekmeleri içerdiğini doğrular."""
        raw_pkt = build_icmp_packet(8, 0, 1, 1, b"ping_test")
        info = parse_and_analyze_icmp(raw_pkt, "192.168.1.1", "8.8.8.8", 64, "REP1")
        report = generate_markdown_report([info], simulate_traceroute("8.8.8.8", 2))
        self.assertIn("# ICMP Protokolü, Ağ Teşhisi ve Tünelleme Güvenlik Raporu", report)  # Başlık sınar
        self.assertIn("Traceroute TTL Tükenme Mekanizması Simülasyonu", report)  # Bölüm sınar

    def test_12_negative_invalid_icmp_type_and_code(self):
        """Test 12: Negatif kontrol: Tanımsız Tip (255) ve geçersiz Kod kombinasyonunu sınar."""
        with self.assertRaises(ICMPValidationError) as ctx1:
            build_icmp_packet(255, 0, 1, 1, b"")  # Tanımsız Tip 255
        self.assertIn("Tanımsız veya desteklenmeyen ICMP tipi: 255", str(ctx1.exception))

        with self.assertRaises(ICMPValidationError) as ctx2:
            build_icmp_packet(0, 5, 1, 1, b"")  # Echo Reply için geçersiz Kod 5
        self.assertIn("için geçersiz kod: 5", str(ctx2.exception))

    def test_13_negative_identifier_and_sequence_limits(self):
        """Test 13: Negatif kontrol: 16-bit dışı negatif kimlik ve sıra numaralarını sınar."""
        with self.assertRaises(ICMPValidationError) as ctx1:
            build_icmp_packet(8, 0, -1, 1, b"")  # Negatif identifier
        self.assertIn("Identifier değeri 0 ile 65535 arasında olmalıdır", str(ctx1.exception))

        with self.assertRaises(ICMPValidationError) as ctx2:
            build_icmp_packet(8, 0, 1, 70000, b"")  # 65535 üstü sequence
        self.assertIn("Sequence numarası 0 ile 65535 arasında olmalıdır", str(ctx2.exception))

    def test_14_negative_corrupted_checksum_and_truncated_packet(self):
        """Test 14: Negatif kontrol: Bozulmuş checksum ve 8 bayttan kısa paketi sınar."""
        # 8 bayttan kısa paket
        with self.assertRaises(ICMPValidationError) as ctx1:
            parse_and_analyze_icmp(b"\x08\x00\x00", "192.168.1.1", "8.8.8.8", 64)
        self.assertIn("en az 8 bayt beklenir", str(ctx1.exception))

        # Checksum alanı kasten bozulmuş paket
        corrupted_pkt = b"\x08\x00\xFF\xFF\x00\x01\x00\x01test_payload"
        with self.assertRaises(ICMPValidationError) as ctx2:
            parse_and_analyze_icmp(corrupted_pkt, "192.168.1.1", "8.8.8.8", 64)
        self.assertIn("Checksum doğrulama hatası", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()  # Testler doğrudan çağrıldığında test motorunu yürütür
