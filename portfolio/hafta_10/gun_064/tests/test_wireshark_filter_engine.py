# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G064: Hafta 10 Gün 64 - Wireshark Görüntüleme Filtresi Test Paketi.
Bu modül, Wireshark sözdizimi ayrıştırma, AST oluşturma, siber tehdit avcılığı
ve 9 negatif sınır/hata senaryosunu 14 bağımsız birim test ile doğrular.
"""

# Birim test çerçevesi unittest modülü içe aktarılır
import unittest
# JSON ayrıştırma kütüphanesi içe aktarılır
import json
# Dosya yolları yönetimi için pathlib içe aktarılır
from pathlib import Path

# Test edilecek filtre motoru ve istisna sınıfları içe aktarılır
from portfolio.hafta_10.gun_064.uygulama.wireshark_filter_engine import (
    WiresharkFilterEngine,
    WiresharkFilterError,
    FilterSyntaxError,
    UnknownFieldError,
    FilterTypeError,
    SliceOutOfBoundsError,
    RegexFilterError,
    EmptyFilterError,
    InvalidOperatorError,
    MalformedPacketError,
    FilterTokenizeError
)


# Test sınıfı tanımı
class TestWiresharkFilterEngine(unittest.TestCase):
    """Wireshark filtre motoru ve tehdit avı kuralları için kapsamlı test sınıfı."""

    # Her test öncesinde çalışan hazırlık metodu
    def setUp(self) -> None:
        """Test ortamını ve paket veri setlerini yükler."""
        # Temel dizin yolu belirlenir
        base_dir = Path(__file__).parent.parent
        # Örnek paketler JSON dosyası yolu
        self.sample_packets_path = base_dir / "ornek_veri" / "sample_packets.json"
        # Negatif testler JSON dosyası yolu
        self.invalid_inputs_path = base_dir / "ornek_veri" / "invalid_filter_inputs.json"
        # Örnek paketler okunur
        with open(self.sample_packets_path, "r", encoding="utf-8") as f:
            # JSON sözlüğüne dönüştürülür
            self.sample_data = json.load(f)
        # Negatif veri seti okunur
        with open(self.invalid_inputs_path, "r", encoding="utf-8") as f:
            # Sözlüğe dönüştürülür
            self.invalid_data = json.load(f)
        # Paket havuzu listesi alınır
        self.packets = self.sample_data["paketler"]
        # Her test için bağımsız filtre motoru başlatılır
        self.engine = WiresharkFilterEngine()

    # Test 1: Basit eşitlik (equality) filtresi testi
    def test_01_simple_equality_filter(self) -> None:
        """ip.src == '192.168.1.100' filtresinin doğru paketleri eşleştirdiğini test eder."""
        # Filtre dizesi tanımlanır
        filter_str = 'ip.src == "192.168.1.100"'
        # Paketler filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # 192.168.1.100 kaynaklı 5 paket (1, 2, 6, 9, 10) eşleşmelidir
        self.assertEqual(len(matched), 5)
        # Eşleşen tüm paketlerin kaynak IP'si doğrulanır
        for pkt in matched:
            # Kaynak IP kontrolü
            self.assertEqual(pkt["ip.src"], "192.168.1.100")

    # Test 2: Takma alanlar (ip.addr ve tcp.port) testi
    def test_02_alias_fields_ip_addr_and_tcp_port(self) -> None:
        """ip.addr ve tcp.port takma alanlarının kaynak veya hedef fark etmeksizin çalıştığını test eder."""
        # tcp.port filtresi tanımlanır (port 80 hem kaynakta hem hedefte eşleşebilir)
        port_filter = "tcp.port == 80"
        # Filtre koşturulur
        matched_port = self.engine.filter_packets(self.packets, port_filter)
        # Paket 1 ve 2 port 80 trafiğidir
        self.assertEqual(len(matched_port), 2)

        # ip.addr filtresi tanımlanır
        addr_filter = 'ip.addr == "192.168.1.1"'
        # Filtre koşturulur
        matched_addr = self.engine.filter_packets(self.packets, addr_filter)
        # Paket 3 (hedef) ve Paket 4 (kaynak) 192.168.1.1 içerir
        self.assertEqual(len(matched_addr), 2)

    # Test 3: Mantıksal VE (AND / &&) operatörü testi
    def test_03_logical_and_operator(self) -> None:
        """İki koşulun && ile bağlandığı ve her iki koşulun sağlandığını test eder."""
        # Kaynak IP ve hedef port filtre dizesi
        filter_str = 'ip.src == "192.168.1.100" && tcp.dstport == 80'
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Yalnızca paket 1 ve 2 bu koşulu sağlar
        self.assertEqual(len(matched), 2)
        # Paket numaraları kontrol edilir
        frame_numbers = [p["frame.number"] for p in matched]
        # 1 ve 2 olduğunu test eder
        self.assertEqual(frame_numbers, [1, 2])

    # Test 4: Mantıksal VEYA (OR / ||) ve parantez önceliği testi
    def test_04_logical_or_and_parentheses(self) -> None:
        """Parantezli OR ifadesinin mantıksal önceliğe uygun çalıştığını test eder."""
        # Web portları (80 veya 443) ve TCP protokolü
        filter_str = '(tcp.dstport == 80 || tcp.dstport == 443) && ip.proto == 6'
        # Süzgeç işletilir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Paket 1 (80), 2 (80), 3 (443), 9 (443) eşleşmelidir (Toplam 4 paket)
        self.assertEqual(len(matched), 4)
        # Paket numaraları listelenir
        frame_numbers = [p["frame.number"] for p in matched]
        # Doğrulanır
        self.assertEqual(frame_numbers, [1, 2, 3, 9])

    # Test 5: Mantıksal DEĞİL (NOT / !) operatörü testi
    def test_05_logical_not_operator(self) -> None:
        """Ünlem işareti (!) ile koşulun tersinin başarıyla alındığını test eder."""
        # TCP olmayan (ip.proto != 6) paketler
        filter_str = "! (ip.proto == 6)"
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Paket 5 (UDP/DNS), 6 (UDP/DNS), 10 (ICMP) olmak üzere 3 paket TCP dışıdır
        self.assertEqual(len(matched), 3)

    # Test 6: İlişkisel operatörler (> ve <=) boyutsal denetim testi
    def test_06_relational_operators_length(self) -> None:
        """Paket uzunluğunun büyüktür (>) operatörü ile doğru süzüldüğünü test eder."""
        # 200 bayttan büyük paketler
        filter_str = "frame.len > 200"
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Paket 2 (350 bayt) ve Paket 9 (540 bayt) eşleşir
        self.assertEqual(len(matched), 2)

    # Test 7: Metin içerir (contains) operatörü testi
    def test_07_contains_operator_payload(self) -> None:
        """HTTP gövdesinde şifre metni arama testini gerçekleştirir."""
        # Parola arama filtresi
        filter_str = 'http.body contains "password"'
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Yalnızca Paket 2'de password geçer
        self.assertEqual(len(matched), 1)
        # Paket numarası 2 olmalıdır
        self.assertEqual(matched[0]["frame.number"], 2)

    # Test 8: Düzenli ifade (matches) operatörü testi
    def test_08_regex_matches_operator(self) -> None:
        """URI deseninin regex ile arandığını test eder."""
        # /api/ ile başlayan URI filtresi
        filter_str = 'http.request.uri matches "^/api/.*"'
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Paket 2 (/api/login) eşleşmelidir
        self.assertEqual(len(matched), 1)
        # Paket numarası kontrol edilir
        self.assertEqual(matched[0]["frame.number"], 2)

    # Test 9: Bayt dilimleme (slice [start:len]) operatörü testi
    def test_09_byte_slice_operator(self) -> None:
        """tcp.payload_hex[0:4] dilimlemesi ile '4745' (ASCII 'GE') aramasını test eder."""
        # GET isteğinin ilk 2 baytı (4 hex karakteri: 47 45)
        filter_str = 'tcp.payload_hex[0:4] == "4745"'
        # Filtrelenir
        matched = self.engine.filter_packets(self.packets, filter_str)
        # Paket 1 GET isteğidir
        self.assertEqual(len(matched), 1)
        # Paket 1 olduğunu doğrular
        self.assertEqual(matched[0]["frame.number"], 1)

    # Test 10: Siber Tehdit Avcılığı (Threat Hunting) profil koşusu testi
    def test_10_threat_hunting_profile_run(self) -> None:
        """Tüm güvenlik avcılığı profillerinin tehditleri yakaladığını test eder."""
        # Tehdit avı profili koşturulur
        results = self.engine.run_threat_hunting_profile(self.packets)
        # Bulgular sözlüğü incelenir
        findings = results["bulgular"]
        # SYN flood veya port tarama yakalandı mı
        self.assertEqual(findings["SYN_FLOOD_VEYA_TARAMA"]["eslesen_paket_sayisi"], 1)
        # Port tarama RST yanıtı yakalandı mı
        self.assertEqual(findings["PORT_TARAMA_RST_YANITI"]["eslesen_paket_sayisi"], 1)
        # Açık metin parola yakalandı mı
        self.assertEqual(findings["ACIK_METIN_KIMLIK_BILGISI"]["eslesen_paket_sayisi"], 1)
        # DNS tünelleme sızıntısı yakalandı mı
        self.assertEqual(findings["DNS_TUNELLEME_SIZINTISI"]["eslesen_paket_sayisi"], 1)
        # Sıfır pencere kilitlenmesi yakalandı mı
        self.assertEqual(findings["SIFIR_PENCERE_KILITLENMESI"]["eslesen_paket_sayisi"], 1)
        # Toplam 5 adet güvenlik uyarısı üretilmiş olmalıdır
        self.assertEqual(len(results["guvenlik_uyarilari"]), 5)

    # Test 11: NEG_01 ve NEG_06 Parantez hatası ve boş filtre testi
    def test_11_neg01_neg06_syntax_and_empty_errors(self) -> None:
        """Dengesiz parantezde FilterSyntaxError ve boş filtrede EmptyFilterError fırlatıldığını test eder."""
        # NEG_01 senaryosu
        neg1 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_01")
        # FilterSyntaxError beklenir
        with self.assertRaises(FilterSyntaxError):
            # Derleme çağrılır
            self.engine.compile_filter(neg1["filtre"])

        # NEG_06 senaryosu
        neg6 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_06")
        # EmptyFilterError beklenir
        with self.assertRaises(EmptyFilterError):
            # Derleme çağrılır
            self.engine.compile_filter(neg6["filtre"])

    # Test 12: NEG_02 ve NEG_03 Tanımsız alan ve tip uyuşmazlığı testi
    def test_12_neg02_neg03_unknown_field_and_type_errors(self) -> None:
        """Bilinmeyen alanda UnknownFieldError ve uyumsuz tipte FilterTypeError fırlatıldığını test eder."""
        # NEG_02 senaryosu
        neg2 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_02")
        # UnknownFieldError beklenir
        with self.assertRaises(UnknownFieldError):
            # Derleme denenir
            self.engine.compile_filter(neg2["filtre"])

        # NEG_03 senaryosu
        neg3 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_03")
        # FilterTypeError beklenir
        with self.assertRaises(FilterTypeError):
            # Derleme denenir
            self.engine.compile_filter(neg3["filtre"])

    # Test 13: NEG_04 ve NEG_05 Dilimleme aşımı ve bozuk regex testi
    def test_13_neg04_neg05_slice_and_regex_errors(self) -> None:
        """Aralık aşımında SliceOutOfBoundsError ve hatalı regexte RegexFilterError fırlatıldığını test eder."""
        # NEG_04 senaryosu
        neg4 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_04")
        # Filtre derlenir
        ast_node = self.engine.compile_filter(neg4["filtre"])
        # Kısa payload içeren paket üzerinde koşturulurken SliceOutOfBoundsError fırlatılmalıdır
        with self.assertRaises(SliceOutOfBoundsError):
            # Paket 1 üzerinde evaluate denenir
            self.engine.evaluate_packet(self.packets[0], ast_node)

        # NEG_05 senaryosu
        neg5 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_05")
        # Regex derlenirken veya pakete uygulanırken RegexFilterError beklenir
        ast_node_regex = self.engine.compile_filter(neg5["filtre"])
        # Paket 2 üzerinde koşturulduğunda regex hatası fırlatılır
        with self.assertRaises(RegexFilterError):
            # Paket 2 test edilir
            self.engine.evaluate_packet(self.packets[1], ast_node_regex)

    # Test 14: NEG_07, NEG_08 ve NEG_09 Geçersiz operatör, bozuk paket ve tırnak hatası testi
    def test_14_neg07_to_neg09_invalid_op_malformed_pkt_tokenize_errors(self) -> None:
        """Geçersiz operatör, geçersiz paket tipi ve açık tırnak hatalarını test eder."""
        # NEG_07 senaryosu (=== operatörü)
        neg7 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_07")
        # InvalidOperatorError fırlatılmalıdır
        with self.assertRaises(InvalidOperatorError):
            # Derleme çağrılır
            self.engine.compile_filter(neg7["filtre"])

        # NEG_08 senaryosu (bozuk paket nesnesi - dict olmayan)
        neg8 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_08")
        # Geçerli filtre derlenir
        ast_valid = self.engine.compile_filter(neg8["filtre"])
        # String paket verilince MalformedPacketError fırlatılmalıdır
        with self.assertRaises(MalformedPacketError):
            # Bozuk paket işletilir
            self.engine.evaluate_packet(neg8["paket_override"], ast_valid)

        # NEG_09 senaryosu (kapatılmamış tırnak)
        neg9 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_09")
        # FilterTokenizeError fırlatılmalıdır
        with self.assertRaises(FilterTokenizeError):
            # Derleme çağrılır
            self.engine.compile_filter(neg9["filtre"])


# Doğrudan yürütülürse testleri başlatır
if __name__ == "__main__":
    # Test çalıştırıcı çağrılır
    unittest.main()
