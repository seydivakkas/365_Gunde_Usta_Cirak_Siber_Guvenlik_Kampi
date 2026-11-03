# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# 
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
# 
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
# 
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
# 
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ==============================================================================
"""
G060: HTTP/2 ve HTTP/3 Kapsamlı Test Paketi (14 Test).

Bu test paketi; 9 baytlık HTTP/2 ikili çerçeve başlık ayrıştırmasını, çerçeve kurallarını,
RST_STREAM ve PING yük kısıtlamalarını, CVE-2023-44487 Rapid Reset tespitini,
RFC 9000 QUIC Anti-Amplification sınırını ve HoL Blokajı simülasyonunu doğrular.
"""

# Standart birim test kütüphanesini içe aktar
import unittest
# JSON veri yükleme ve işleme kütüphanesi
import json
# Dosya sistemi yolları için pathlib kütüphanesi
from pathlib import Path
# İkili veri paketleme için struct modülü
import struct

# Test edilecek uygulama bileşenlerini ve hata sınıflarını içe aktar
from portfolio.hafta_09.gun_060.uygulama.http2_http3_analyzer import (
    parse_http2_frame_header,
    validate_frame_payload_rules,
    detect_rapid_reset_attack,
    enforce_quic_anti_amplification,
    simulate_hol_blocking,
    compare_http_versions_detailed,
    build_synthetic_h2_frame,
    HTTP2ValidationError,
    HTTP2MalformedFrameError,
    HTTP2RapidResetAttackError,
    QUICAmplificationError
)


class TestHTTP2HTTP3Analyzer(unittest.TestCase):
    """HTTP/2 ve HTTP/3 Analiz Motoru Birim Testleri."""

    @classmethod
    def setUpClass(cls):
        """Test sınıfı başlatılırken örnek veri ve negatif senaryoları yükler."""
        # Geçerli test dosyasının bulunduğu dizini tespit et
        current_dir = Path(__file__).resolve().parent
        # Örnek veri dizinine erişim yolunu oluştur
        ornek_veri_dir = current_dir.parent / "ornek_veri"
        
        # Pozitif çerçeve senaryolarını oku
        with open(ornek_veri_dir / "sample_frames_and_quic.json", "r", encoding="utf-8") as f:
            cls.sample_data = json.load(f)
            
        # Negatif test senaryolarını oku
        with open(ornek_veri_dir / "invalid_h2_h3_inputs.json", "r", encoding="utf-8") as f:
            cls.invalid_data = json.load(f)

    def test_01_valid_settings_frame_header_parsing(self):
        """Pozitif Test 1: Bağlantı seviyesi SETTINGS çerçeve başlığının başarıyla ayrıştırılması."""
        # 6 baytlık yük taşıyan SETTINGS çerçevesi oluştur (Type 0x4, Flags 0, Stream ID 0)
        payload = b"\x00\x03\x00\x00\x00\x64"
        raw_frame = build_synthetic_h2_frame(frame_type=0x04, flags=0, stream_id=0, payload=payload)
        # Başlığı ayrıştır
        header = parse_http2_frame_header(raw_frame)
        # Yük uzunluğunun 6 olduğunu doğrula
        self.assertEqual(header.payload_length, 6)
        # Çerçeve tipinin SETTINGS olduğunu doğrula
        self.assertEqual(header.frame_type, 4)
        self.assertEqual(header.frame_type_name, "SETTINGS")
        # Akış kimliğinin 0 olduğunu doğrula
        self.assertEqual(header.stream_id, 0)

    def test_02_valid_headers_frame_parsing(self):
        """Pozitif Test 2: Akış seviyesi HEADERS çerçevesinin ayrıştırılması."""
        # 10 baytlık sahte başlık yükü taşıyan HEADERS çerçevesi (Type 0x1, Flags 0x5, Stream ID 1)
        payload = b"testheaders"
        raw_frame = build_synthetic_h2_frame(frame_type=0x01, flags=0x05, stream_id=1, payload=payload)
        # Başlığı ayrıştır
        header = parse_http2_frame_header(raw_frame)
        self.assertEqual(header.frame_type_name, "HEADERS")
        self.assertEqual(header.flags, 5)
        self.assertEqual(header.stream_id, 1)

    def test_03_negative_truncated_frame_header(self):
        """Negatif Test 3: 9 bayttan kısa kesilmiş çerçeve başlığında HTTP2MalformedFrameError."""
        # 5 baytlık eksik başlık verisi hazırla
        truncated = b"\x00\x00\x05\x01\x05"
        # HTTP2MalformedFrameError fırlatılmalı
        with self.assertRaises(HTTP2MalformedFrameError) as ctx:
            parse_http2_frame_header(truncated)
        self.assertIn("en az 9 bayt", str(ctx.exception))

    def test_04_negative_unknown_frame_type(self):
        """Negatif Test 4: RFC 7540 standardında tanımsız çerçeve tipinde HTTP2ValidationError."""
        # 255 (0xFF) bilinmeyen tip içeren 9 baytlık başlık
        raw_unknown = build_synthetic_h2_frame(frame_type=0xFF, flags=0, stream_id=1, payload=b"test")
        with self.assertRaises(HTTP2ValidationError) as ctx:
            parse_http2_frame_header(raw_unknown)
        self.assertIn("Bilinmeyen HTTP/2 cerceve tipi", str(ctx.exception))

    def test_05_negative_frame_length_overflow(self):
        """Negatif Test 5: 16384 bayt sınırını aşan yük uzunluğunda HTTP2ValidationError."""
        # 20000 baytlık aşırı uzunluk bildiren çerçeve başlığı
        length_bytes = (20000).to_bytes(3, byteorder="big")
        overflow_header = length_bytes + bytes([0x00, 0x00]) + struct.pack("!I", 1)
        with self.assertRaises(HTTP2ValidationError) as ctx:
            parse_http2_frame_header(overflow_header)
        self.assertIn("maksimum siniri", str(ctx.exception))

    def test_06_negative_payload_length_mismatch(self):
        """Negatif Test 6: Bildirilen boyuttan daha kısa gövde akışında HTTP2MalformedFrameError."""
        # Başlıkta 30 bayt bildir ama sadece 5 bayt gönder
        length_bytes = (30).to_bytes(3, byteorder="big")
        mismatched = length_bytes + bytes([0x00, 0x00]) + struct.pack("!I", 1) + b"12345"
        with self.assertRaises(HTTP2MalformedFrameError) as ctx:
            parse_http2_frame_header(mismatched)
        self.assertIn("uyusmuyor", str(ctx.exception))

    def test_07_negative_data_frame_on_stream_zero(self):
        """Negatif Test 7: DATA çerçevesinin Akış ID 0 ile gönderilmesi ihlalinin reddi."""
        # Akış ID 0 olan DATA çerçevesi oluştur
        raw_data_stream_zero = build_synthetic_h2_frame(frame_type=0x00, flags=0, stream_id=0, payload=b"data")
        with self.assertRaises(HTTP2ValidationError) as ctx:
            parse_http2_frame_header(raw_data_stream_zero)
        self.assertIn("Akis ID 0 uzerinden gonderilemez", str(ctx.exception))

    def test_08_negative_settings_frame_on_stream_positive(self):
        """Negatif Test 8: SETTINGS çerçevesinin Akış ID > 0 ile gönderilmesi ihlalinin reddi."""
        # Akış ID 1 olan SETTINGS çerçevesi oluştur
        raw_settings_stream_one = build_synthetic_h2_frame(frame_type=0x04, flags=0, stream_id=1, payload=b"\x00\x01\x00\x00\x10\x00")
        with self.assertRaises(HTTP2ValidationError) as ctx:
            parse_http2_frame_header(raw_settings_stream_one)
        self.assertIn("yalnizca baglanti seviyesinde", str(ctx.exception))

    def test_09_rst_stream_payload_validation(self):
        """Pozitif ve Negatif Test 9: RST_STREAM yükünün tam 4 bayt olmasının denetimi."""
        # Geçerli 4 baytlık CANCEL (0x8) hata kodlu çerçeve
        valid_rst = build_synthetic_h2_frame(frame_type=0x03, flags=0, stream_id=1, payload=struct.pack("!I", 8))
        h_valid = parse_http2_frame_header(valid_rst)
        validate_frame_payload_rules(h_valid, struct.pack("!I", 8))

        # Geçersiz 2 baytlık RST yükü
        with self.assertRaises(HTTP2MalformedFrameError):
            validate_frame_payload_rules(h_valid, b"\x00\x08")

    def test_10_ping_payload_validation(self):
        """Pozitif ve Negatif Test 10: PING yükünün tam 8 bayt olmasının denetimi."""
        # Geçerli 8 baytlık PING yükü
        valid_ping = build_synthetic_h2_frame(frame_type=0x06, flags=1, stream_id=0, payload=b"12345678")
        h_ping = parse_http2_frame_header(valid_ping)
        validate_frame_payload_rules(h_ping, b"12345678")

        # Geçersiz 4 baytlık PING yükü
        with self.assertRaises(HTTP2MalformedFrameError):
            validate_frame_payload_rules(h_ping, b"1234")

    def test_11_settings_payload_multiple_of_six(self):
        """Pozitif ve Negatif Test 11: SETTINGS yükünün 6 baytın katı olması kuralının denetimi."""
        # Geçerli 6 baytlık ayar yükü
        valid_settings = build_synthetic_h2_frame(frame_type=0x04, flags=0, stream_id=0, payload=b"\x00\x01\x00\x00\x10\x00")
        h_set = parse_http2_frame_header(valid_settings)
        validate_frame_payload_rules(h_set, b"\x00\x01\x00\x00\x10\x00")

        # Geçersiz 5 baytlık ayar yükü
        with self.assertRaises(HTTP2MalformedFrameError):
            validate_frame_payload_rules(h_set, b"\x00\x01\x00\x00\x10")

    def test_12_rapid_reset_ddos_detection(self):
        """Pozitif ve Negatif Test 12: CVE-2023-44487 HTTP/2 Rapid Reset DDoS tespiti."""
        # Normal iptal oranı (5 iptal / 1 sn) güvenli olmalıdır
        self.assertTrue(detect_rapid_reset_attack(reset_count=5, window_seconds=1.0, threshold=100))

        # Saldırı boyutu (150 iptal / 1 sn) HTTP2RapidResetAttackError fırlatmalıdır
        with self.assertRaises(HTTP2RapidResetAttackError) as ctx:
            detect_rapid_reset_attack(reset_count=150, window_seconds=1.0, threshold=100)
        self.assertIn("Rapid Reset Saldirisi (CVE-2023-44487)", str(ctx.exception))

    def test_13_quic_anti_amplification_limit(self):
        """Pozitif ve Negatif Test 13: RFC 9000 3x Anti-Amplification kuralının denetimi."""
        # 1200 baytlık istemci paketine karşılık 3000 bayt sunucu yanıtı (3000 <= 3600 -> İzinli)
        self.assertTrue(enforce_quic_anti_amplification(1200, 3000, is_address_validated=False))

        # 1200 baytlık istemci paketine karşılık 4500 bayt sunucu yanıtı (4500 > 3600 -> Reddedilir)
        with self.assertRaises(QUICAmplificationError) as ctx:
            enforce_quic_anti_amplification(1200, 4500, is_address_validated=False)
        self.assertIn("QUIC Anti-Amplification Limiti (3x) asildi", str(ctx.exception))

        # Adres doğrulanmışsa katsayı kuralı uygulanmaz
        self.assertTrue(enforce_quic_anti_amplification(1200, 10000, is_address_validated=True))

    def test_14_hol_blocking_simulation_and_matrix_comparison(self):
        """Pozitif Test 14: HTTP/2 ve HTTP/3 HoL blokajı davranış simülasyonu ve karşılaştırma matrisi."""
        # Akış 2'de paket kaybı olduğunda simülasyon çalıştır
        sim = simulate_hol_blocking(packet_loss_stream_id=2, total_streams=3)
        # HTTP/2'de tüm akışların bloklandığını doğrula
        self.assertIn("Tum akislar durdu", sim["http2_sonucu"]["etki"])
        # HTTP/3'te diğer akışların çalıştığını doğrula
        self.assertIn("kesintisiz calisti", sim["http3_sonucu"]["etki"])
        self.assertIn("AKIS DEVAM EDIYOR", sim["http3_sonucu"]["akis_durumlari"][1])

        # Kapsamlı karşılaştırma matrisini sorgula
        matrix = compare_http_versions_detailed()
        self.assertIn("QUIC uzerinde UDP", matrix["tasima_katmani"]["http_3"])
        self.assertIn("Rapid Reset", matrix["ana_guvenlik_tehditleri"]["http_2"])


if __name__ == "__main__":
    # Testleri detaylı çıktıyla çalıştır
    unittest.main()
