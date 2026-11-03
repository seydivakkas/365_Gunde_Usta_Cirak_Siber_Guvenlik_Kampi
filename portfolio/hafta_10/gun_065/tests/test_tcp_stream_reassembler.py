# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G065: Hafta 10 Gün 65 - Follow TCP Stream ve Yeniden Birleştirme Test Paketi.
Bu modül, TCP segment birleştirme, sıra dışı paket arabellekleme, örtüşen yük çelişkisi tespiti,
ve 9 negatif sınır senaryosunu 14 bağımsız birim test ile doğrular.
"""

# Birim test çerçevesi unittest modülü içe aktarılır
import unittest
# JSON verilerini okumak ve dönüştürmek için json kütüphanesi içe aktarılır
import json
# Dosya yollarını güvenli yönetmek için pathlib içe aktarılır
from pathlib import Path

# Test edilecek yeniden birleştirme motoru ve hata sınıfları içe aktarılır
from portfolio.hafta_10.gun_065.uygulama.tcp_stream_reassembler import (
    FollowTCPStreamEngine,
    DirectionalStreamReassembler,
    TCPSegment,
    TCPStreamSession,
    TCPReassemblyError,
    SequenceGapError,
    OverlappingPayloadConflictError,
    CorruptedSegmentError,
    ReassemblyBufferOverflowError,
    UnreassembledDataLossError,
    MissingHandshakeError,
    StreamSessionMismatchError,
    EmptyStreamError,
    InvalidProtocolError
)


# Test sınıfı tanımı
class TestTCPStreamReassembler(unittest.TestCase):
    """TCP Stream yeniden birleştirme motoru için kapsamlı test sınıfı."""

    # Her test öncesinde çalışan hazırlık metodu
    def setUp(self) -> None:
        """Test ortamını ve örnek segment veri setlerini yükler."""
        # Temel dizin yolu belirlenir
        base_dir = Path(__file__).parent.parent
        # Örnek geçerli akış dosyası yolu
        self.sample_stream_path = base_dir / "ornek_veri" / "sample_tcp_stream.json"
        # Negatif sınır testleri dosyası yolu
        self.invalid_inputs_path = base_dir / "ornek_veri" / "invalid_stream_inputs.json"
        # Geçerli akış dosyası açılır ve JSON olarak yüklenir
        with open(self.sample_stream_path, "r", encoding="utf-8") as f:
            # Örnek veri sözlüğe aktarılır
            self.sample_data = json.load(f)
        # Negatif senaryolar dosyası açılır ve JSON olarak yüklenir
        with open(self.invalid_inputs_path, "r", encoding="utf-8") as f:
            # Negatif veri sözlüğe aktarılır
            self.invalid_data = json.load(f)
        # Her test için bağımsız motor başlatılır
        self.engine = FollowTCPStreamEngine()

    # Test 1: Geçerli akışın yüklenmesi ve 3'lü el sıkışma ISN denetimi
    def test_01_load_valid_stream_and_handshake(self) -> None:
        """TCP 3'lü el sıkışması ile istemci ve sunucu ISN değerlerinin kurulduğunu test eder."""
        # Akış verisi motora yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data, strict_handshake=True)
        # Oturumun geçerli bir nesne olduğu doğrulanır
        self.assertIsInstance(session, TCPStreamSession)
        # İstemci ISN değerinin 1000000 olduğu doğrulanır
        self.assertEqual(session.client_to_server.isn, 1000000)
        # Sunucu ISN değerinin 2000000 olduğu doğrulanır
        self.assertEqual(session.server_to_client.isn, 2000000)

    # Test 2: İstemci HTTP isteğinin sıralı olarak birleştirilmesi
    def test_02_in_order_client_http_request_reassembly(self) -> None:
        """İstemciden gönderilen iki segmentin kesintisiz HTTP GET isteği olarak birleştiğini test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # İstemciden giden birleştirilmiş metin alınır
        client_text = session.client_to_server.reassembled_text
        # Beklenen HTTP GET isteği metni
        expected_request = "GET /api/v1/telemetry HTTP/1.1\r\nHost: kurumsal.local\r\nAccept: */*\r\n\r\n"
        # Birleştirilen metnin beklenenle birebir aynı olduğu doğrulanır
        self.assertEqual(client_text, expected_request)
        # İstemci tarafında sıra dışı segment olmadığını doğrular (sıralı geldi)
        self.assertEqual(session.client_to_server.out_of_order_count, 0)

    # Test 3: Sunucu HTTP yanıtında sıra dışı (out-of-order) segment çözümü
    def test_03_out_of_order_server_response_reassembly(self) -> None:
        """Gövdesi başlığından önce gelen sunucu segmentlerinin doğru sıralandığını test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # Sunucudan gelen birleştirilmiş metin alınır
        server_text = session.server_to_client.reassembled_text
        # HTTP durum satırı ile başladığı doğrulanır
        self.assertTrue(server_text.startswith("HTTP/1.1 200 OK"))
        # JSON yanıt gövdesini içerdiği doğrulanır
        self.assertIn('"sensor_id": "SN-4021"', server_text)
        # Sunucu yönünde tam 1 adet sıra dışı segment yakalandığı doğrulanır
        self.assertEqual(session.server_to_client.out_of_order_count, 1)

    # Test 4: Yeniden iletim ve kopya segmentlerin (duplicate) elenmesi testi
    def test_04_duplicate_retransmission_handling(self) -> None:
        """Aynı sıra numarasına sahip kopya segmentin veriyi çoğaltmadan elendiğini test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # Sunucu yönünde 1 adet yeniden iletim (retransmission) yakalandığı doğrulanır
        self.assertEqual(session.server_to_client.retransmission_count, 1)
        # JSON gövdesinin metinde sadece 1 kez geçtiği test edilir (kopya eklenmedi)
        self.assertEqual(session.server_to_client.reassembled_text.count('"sensor_id": "SN-4021"'), 1)

    # Test 5: Bağlantının FIN/ACK ile temiz sonlandırılması testi
    def test_05_clean_connection_teardown_fin_ack(self) -> None:
        """FIN ve ACK paketleri ile akışın arabellekte parça kalmadan kapandığını test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # Her iki yönün de sonlandırıldığı doğrulanır
        self.assertTrue(session.client_to_server.is_terminated)
        self.assertTrue(session.server_to_client.is_terminated)
        # Her iki yönde de arabelleğin boş olduğu doğrulanır
        self.assertEqual(len(session.client_to_server.out_of_order_buffer), 0)
        self.assertEqual(len(session.server_to_client.out_of_order_buffer), 0)

    # Test 6: Wireshark Follow TCP Stream formatında çıktı üretimi
    def test_06_render_follow_stream_format(self) -> None:
        """Çift yönlü sohbet dökümünün Wireshark diyalog formatında basıldığını test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # Çıktı formatı oluşturulur
        rendered = self.engine.render_follow_stream(session)
        # Başlık formatının doğruluğu test edilir
        self.assertIn("WIRESHARK FOLLOW TCP STREAM", rendered)
        # İstemci etiketi varlığı test edilir
        self.assertIn("[CLIENT -> SERVER", rendered)
        # Sunucu etiketi varlığı test edilir
        self.assertIn("[SERVER -> CLIENT", rendered)
        # İstemci isteği metni çıktıda yer almalıdır
        self.assertIn("GET /api/v1/telemetry", rendered)
        # Sunucu yanıtı metni çıktıda yer almalıdır
        self.assertIn("HTTP/1.1 200 OK", rendered)

    # Test 7: Özet metrik ve istatistik raporu doğrulaması
    def test_07_summary_report_metrics(self) -> None:
        """Bayt hacmi, paket sayıları ve anomali istatistiklerinin tam doğruluğunu test eder."""
        # Akış yüklenir
        session = self.engine.load_stream_from_dict(self.sample_data)
        # Özet rapor üretilir
        report = self.engine.generate_summary_report(session)
        # Toplam segment sayısının 11 olduğu doğrulanır
        self.assertEqual(report["toplam_segment"], 11)
        # İstemcinin 69 bayt gönderdiği doğrulanır (38 + 31)
        self.assertEqual(report["istemci_gonderilen_bayt"], 69)
        # Sunucunun 188 bayt gönderdiği doğrulanır (110 + 78)
        self.assertEqual(report["sunucu_gonderilen_bayt"], 188)
        # Toplam akış baytının 257 olduğu doğrulanır (69 + 188)
        self.assertEqual(report["toplam_akis_bayt"], 257)
        # Sıra dışı paket sayısının 1 olduğu test edilir
        self.assertEqual(report["sira_disi_paket_sayisi"], 1)
        # Yeniden iletim sayısının 1 olduğu test edilir
        self.assertEqual(report["yeniden_iletim_sayisi"], 1)

    # Test 8: NEG_01 Giderilemeyen sıra boşluğu (Sequence Gap Stall) testi
    def test_08_neg01_sequence_gap_stall_error(self) -> None:
        """Aradaki segment kaybolduğunda SequenceGapError fırlatıldığını test eder."""
        # NEG_01 senaryosu filtrelenir
        neg1 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_01")
        # Motor el sıkışmasız modda çalıştırıldığında SequenceGapError vermelidir
        with self.assertRaises(SequenceGapError):
            # Akış yüklenir
            self.engine.load_stream_from_dict(neg1, strict_handshake=False)

    # Test 9: NEG_02 Çelişkili örtüşen yük ile IDS atlatma (Ptacek-Newsham) testi
    def test_09_neg02_overlapping_payload_conflict_ids_evasion(self) -> None:
        """Örtüşen parçada farklı veri geldiğinde OverlappingPayloadConflictError fırlatıldığını test eder."""
        # NEG_02 senaryosu filtrelenir
        neg2 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_02")
        # Çelişkili örtüşme hatası beklenir
        with self.assertRaises(OverlappingPayloadConflictError):
            # Akış yüklenir
            self.engine.load_stream_from_dict(neg2, strict_handshake=False)

    # Test 10: NEG_03 Bildirilen boyut ile gerçek metin uzunluğu uyuşmazlığı testi
    def test_10_neg03_corrupted_segment_payload_size(self) -> None:
        """Bozuk segment boyutu durumunda CorruptedSegmentError fırlatıldığını test eder."""
        # NEG_03 senaryosu filtrelenir
        neg3 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_03")
        # CorruptedSegmentError beklenir
        with self.assertRaises(CorruptedSegmentError):
            # Akış yüklenir
            self.engine.load_stream_from_dict(neg3, strict_handshake=False)

    # Test 11: NEG_04 Sıra dışı arabellek kuyruğu taşma (Buffer Overflow) testi
    def test_11_neg04_reassembly_buffer_overflow(self) -> None:
        """Çok fazla dağınık segment arabelleğe dolduğunda ReassemblyBufferOverflowError fırlatıldığını test eder."""
        # NEG_04 senaryosu filtrelenir
        neg4 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_04")
        # Arabellek taşma hatası beklenir
        with self.assertRaises(ReassemblyBufferOverflowError):
            # Akış yüklenir
            self.engine.load_stream_from_dict(neg4, strict_handshake=False)

    # Test 12: NEG_05 Birleşmemiş veri varken erken FIN/RST sonlandırması testi
    def test_12_neg05_unreassembled_data_loss_on_rst(self) -> None:
        """Arabellekte kopuk parça varken RST geldiğinde UnreassembledDataLossError fırlatıldığını test eder."""
        # NEG_05 senaryosu filtrelenir
        neg5 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_05")
        # Veri kaybı hatası beklenir
        with self.assertRaises(UnreassembledDataLossError):
            # Akış yüklenir
            self.engine.load_stream_from_dict(neg5, strict_handshake=False)

    # Test 13: NEG_06 Eksik el sıkışma (SYN olmadan gelen akış) testi
    def test_13_neg06_missing_handshake_syn_error(self) -> None:
        """Strict modda SYN bulunmadığında MissingHandshakeError fırlatıldığını test eder."""
        # NEG_06 senaryosu filtrelenir
        neg6 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_06")
        # MissingHandshakeError fırlatılmalıdır
        with self.assertRaises(MissingHandshakeError):
            # Strict handshake ile yüklenir
            self.engine.load_stream_from_dict(neg6, strict_handshake=True)

    # Test 14: NEG_07, NEG_08 ve NEG_09 Oturum uyuşmazlığı, boş akış ve geçersiz protokol testi
    def test_14_neg07_to_neg09_mismatch_empty_and_invalid_protocol(self) -> None:
        """Yabancı soket enjeksiyonu, boş segment listesi ve TCP dışı protokol hatalarını test eder."""
        # NEG_07 Oturum uyuşmazlığı (farklı IP/port)
        neg7 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_07")
        # StreamSessionMismatchError beklenir
        with self.assertRaises(StreamSessionMismatchError):
            # Yükleme çağrılır
            self.engine.load_stream_from_dict(neg7, strict_handshake=False)

        # NEG_08 Boş segment akışı
        neg8 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_08")
        # EmptyStreamError beklenir
        with self.assertRaises(EmptyStreamError):
            # Yükleme çağrılır
            self.engine.load_stream_from_dict(neg8, strict_handshake=False)

        # NEG_09 Geçersiz protokol (UDP paketi)
        neg9 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_09")
        # InvalidProtocolError beklenir
        with self.assertRaises(InvalidProtocolError):
            # Yükleme çağrılır
            self.engine.load_stream_from_dict(neg9, strict_handshake=False)


# Doğrudan çalıştırıldığında testleri yürütür
if __name__ == "__main__":
    # Test yürütücü çağrılır
    unittest.main()
