# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G063: Hafta 09 Mini Proje 8 - Protokol Zaman Çizelgesi Test Paketi.
Bu modül, zaman serisi paket olaylarını analiz eden motorun tüm işlevsel,
gecikme ve zamansal anomali tespit kabiliyetlerini 14 bağımsız test ile doğrular.
"""

# Birim test çerçevesi unittest modülü içe aktarılır
import unittest
# JSON dosya okuma ve ayrıştırma için json kütüphanesi içe aktarılır
import json
# Dosya yolları yönetimi için os ve pathlib modülleri içe aktarılır
import os
from pathlib import Path

# Test edilecek protokol analiz motoru ve veri sınıfları içe aktarılır
from portfolio.hafta_09.gun_063.uygulama.protocol_timeline_analyzer import (
    ProtocolTimelineAnalyzer,
    NetworkEvent,
    FlowSession,
    TimelineError,
    TimelineOrderError,
    TimestampFormatError,
    HandshakeViolationError,
    SequenceAnomalyError,
    SlowlorisAnomalyError,
    PortScanAnomalyError,
    DnsTunnelingAnomalyError,
    MissingEventFieldError,
    IllegalStateTransitionError
)


# Test sınıfı tanımı
class TestProtocolTimelineAnalyzer(unittest.TestCase):
    """Protokol zaman çizelgesi analiz motoru için kapsamlı birim test sınıfı."""

    # Her test öncesinde çalışan hazırlık metodu
    def setUp(self) -> None:
        """Test ortamını ve örnek veri setlerini hazırlar."""
        # Test modülünün bulunduğu dizin tespit edilir
        base_dir = Path(__file__).parent.parent
        # Örnek geçerli ağ izi dosyasının yolu oluşturulur
        self.sample_trace_path = base_dir / "ornek_veri" / "sample_network_trace.json"
        # Negatif sınır testleri dosyasının yolu oluşturulur
        self.invalid_inputs_path = base_dir / "ornek_veri" / "invalid_timeline_inputs.json"
        # Geçerli örnek ağ izi JSON dosyası UTF-8 olarak açılır ve okunur
        with open(self.sample_trace_path, "r", encoding="utf-8") as f:
            # JSON verisi sözlüğe ayrıştırılır
            self.sample_data = json.load(f)
        # Negatif senaryolar JSON dosyası UTF-8 olarak açılır ve okunur
        with open(self.invalid_inputs_path, "r", encoding="utf-8") as f:
            # Negatif veri seti sözlüğe ayrıştırılır
            self.invalid_data = json.load(f)
        # Her test için bağımsız yeni analiz motoru örneği oluşturulur
        self.analyzer = ProtocolTimelineAnalyzer()

    # Test 1: Geçerli ağ izinin yüklenmesi ve olay sayısı denetimi
    def test_01_load_valid_trace_and_count_events(self) -> None:
        """Standart veri setinden olayların doğru sayıda ve eksiksiz yüklendiğini test eder."""
        # Motor sözlükten olayları yükler ve toplam sayı alınır
        event_count = self.analyzer.load_events_from_dict(self.sample_data)
        # Örnek veri setinde tam 16 adet kronolojik olay olmalıdır
        self.assertEqual(event_count, 16)
        # İlk olayın DNS sorgusu olduğu doğrulanır
        self.assertEqual(self.analyzer.olaylar[0].protokol, "DNS")
        # İlk olayın kaynak IP adresi doğrulanır
        self.assertEqual(self.analyzer.olaylar[0].kaynak_ip, "192.168.1.100")

    # Test 2: Kronolojik sıralama ve delta süresi hesaplama testi
    def test_02_validate_and_sort_chronological_order(self) -> None:
        """Olayların zaman sırasına dizildiğini ve milisaniye deltalarının hesaplandığını test eder."""
        # Olaylar motora yüklenir
        self.analyzer.load_events_from_dict(self.sample_data)
        # Zaman sıralaması ve delta hesaplama işletilir
        self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=True)
        # İlk olayın deltası 0.0 olmalıdır
        self.assertEqual(self.analyzer.olaylar[0].delta_ms, 0.0)
        # İkinci olayın (DNS yanıtı) deltası yaklaşık 15.2 ms olmalıdır
        self.assertAlmostEqual(self.analyzer.olaylar[1].delta_ms, 15.2, places=1)
        # Tüm olayların pozitif veya sıfır deltaya sahip olduğu doğrulanır
        for ev in self.analyzer.olaylar:
            # Delta süresi sıfırdan küçük olamaz
            self.assertGreaterEqual(ev.delta_ms, 0.0)

    # Test 3: TCP 3'lü el sıkışma doğrulaması ve RTT hesaplama testi
    def test_03_tcp_three_way_handshake_rtt_calculation(self) -> None:
        """TCP SYN -> SYN-ACK -> ACK akışını ve RTT gecikme süresini test eder."""
        # Olaylar yüklenir ve sıralanır
        self.analyzer.load_events_from_dict(self.sample_data)
        # Kronolojik sıra doğrulanır
        self.analyzer.validate_and_sort_timeline()
        # Akışlar yeniden oluşturulur
        flows = self.analyzer.reconstruct_flows()
        # TCP HTTPS akış kimliği oluşturulur
        tcp_flow_id = self.analyzer.build_flow_id("192.168.1.100", 49152, "10.10.20.50", 443)
        # Akışın mevcut olduğu doğrulanır
        self.assertIn(tcp_flow_id, flows)
        # İlgili TCP akış oturumu nesnesi alınır
        tcp_flow = flows[tcp_flow_id]
        # TCP el sıkışmasının ESTABLISHED durumuna geçtiği test edilir
        self.assertEqual(tcp_flow.tcp_durumu, "CLOSED")  # Oturum sonunda FIN/ACK ile kapandı
        # Handshake RTT süresinin 40.0 ms civarında hesaplandığı doğrulanır (0.065 - 0.025 = 40.0 ms)
        self.assertIsNotNone(tcp_flow.rtt_ms)
        # RTT süresinin 40.0 ms olduğu doğrulanır
        self.assertAlmostEqual(tcp_flow.rtt_ms, 40.0, places=1)

    # Test 4: TLS 1.3 el sıkışma durumu izleme testi
    def test_04_tls_handshake_completion_state(self) -> None:
        """TLS ClientHello ve ServerHello sonrası güvenli tünelin kurulduğunu test eder."""
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(self.sample_data)
        # Sıralama yapılır
        self.analyzer.validate_and_sort_timeline()
        # Akışlar rekonstrükte edilir
        flows = self.analyzer.reconstruct_flows()
        # TCP/TLS akış kimliği bulunur
        tcp_flow_id = self.analyzer.build_flow_id("192.168.1.100", 49152, "10.10.20.50", 443)
        # TLS el sıkışma tamamlanma bayrağının True olduğu doğrulanır
        self.assertTrue(flows[tcp_flow_id].tls_el_sikisma_tamamlandi)

    # Test 5: HTTP/2 çoklu akım (multiplexed streams) takibi testi
    def test_05_http2_multiplexed_stream_tracking(self) -> None:
        """HTTP/2 çerçevelerinde akım kimliklerinin (Stream 1 ve Stream 3) ayrıştırıldığını test eder."""
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(self.sample_data)
        # Sıralanır
        self.analyzer.validate_and_sort_timeline()
        # Akışlar oluşturulur
        flows = self.analyzer.reconstruct_flows()
        # İlgili akış oturumu alınır
        tcp_flow_id = self.analyzer.build_flow_id("192.168.1.100", 49152, "10.10.20.50", 443)
        # Akışta Stream 0 (SETTINGS), Stream 1 ve Stream 3'ün kayıtlı olduğu doğrulanır
        stream_ids = flows[tcp_flow_id].http2_akimlar
        # Stream 1 varlığı test edilir
        self.assertIn(1, stream_ids)
        # Stream 3 varlığı test edilir
        self.assertIn(3, stream_ids)

    # Test 6: Bağlantı sonlandırma FIN/ACK döngüsü testi
    def test_06_connection_teardown_fin_ack_sequence(self) -> None:
        """Çift yönlü FIN ve ACK paketleriyle bağlantının CLOSED durumuna geldiğini test eder."""
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(self.sample_data)
        # Sıralanır
        self.analyzer.validate_and_sort_timeline()
        # Akışlar incelenir
        flows = self.analyzer.reconstruct_flows()
        # Akış referansı alınır
        tcp_flow_id = self.analyzer.build_flow_id("192.168.1.100", 49152, "10.10.20.50", 443)
        # Nihai durumun CLOSED olduğu doğrulanır
        self.assertEqual(flows[tcp_flow_id].tcp_durumu, "CLOSED")

    # Test 7: ASCII merdiven zaman çizelgesi çıktısı testi
    def test_07_generate_ascii_timeline_output(self) -> None:
        """ASCII formatında çizilen zaman çizelgesinin tüm protokol ve başlıkları içerdiğini test eder."""
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(self.sample_data)
        # Sıralanır
        self.analyzer.validate_and_sort_timeline()
        # ASCII şeması üretilir
        ascii_art = self.analyzer.generate_ascii_timeline()
        # Çıktının boş olmadığı doğrulanır
        self.assertIsInstance(ascii_art, str)
        # Başlık metninin varlığı test edilir
        self.assertIn("PROTOKOL ZAMAN CIZELGESI", ascii_art)
        # DNS protokolünün tabloda yer aldığı doğrulanır
        self.assertIn("DNS", ascii_art)
        # HTTP2 protokolünün tabloda yer aldığı doğrulanır
        self.assertIn("HTTP2", ascii_art)

    # Test 8: NEG_01 Zaman gerilemesi / negatif delta istisnası testi
    def test_08_neg01_timeline_order_error_clock_skew(self) -> None:
        """Kronolojik gerileme olduğunda TimelineOrderError fırlatıldığını test eder."""
        # NEG_01 senaryosu filtrelenir
        neg1 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_01")
        # Olaylar motora yüklenir
        self.analyzer.load_events_from_dict(neg1)
        # Kronolojik denetim çalıştırıldığında TimelineOrderError fırlatılmalıdır
        with self.assertRaises(TimelineOrderError):
            # Sıralama ve denetim metodu çağrılır
            self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=True)

    # Test 9: NEG_02 Geçersiz ISO-8601 zaman damgası biçimi testi
    def test_09_neg02_timestamp_format_error(self) -> None:
        """Bozuk tarih/zaman dizgisi verildiğinde TimestampFormatError fırlatıldığını test eder."""
        # NEG_02 senaryosu filtrelenir
        neg2 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_02")
        # Geçersiz tarih yüklenirken TimestampFormatError fırlatılmalıdır
        with self.assertRaises(TimestampFormatError):
            # Yükleme işlemi çağrılır
            self.analyzer.load_events_from_dict(neg2)

    # Test 10: NEG_03 El sıkışma tamamlanmadan erken veri enjeksiyonu testi
    def test_10_neg03_handshake_violation_premature_data(self) -> None:
        """TCP el sıkışması tamamlanmadan veri gönderildiğinde HandshakeViolationError fırlatıldığını test eder."""
        # NEG_03 senaryosu filtrelenir
        neg3 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_03")
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(neg3)
        # Sıralama yapılır
        self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # Akış oluşturulurken HandshakeViolationError fırlatılmalıdır
        with self.assertRaises(HandshakeViolationError):
            # Akış rekonstrüksiyonu çağrılır
            self.analyzer.reconstruct_flows()

    # Test 11: NEG_04 TCP sıra numarası sıçraması (Session Hijacking) testi
    def test_11_neg04_sequence_anomaly_tcp_jump(self) -> None:
        """Açıklanamayan sıra numarası sıçramasında SequenceAnomalyError fırlatıldığını test eder."""
        # NEG_04 senaryosu filtrelenir
        neg4 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_04")
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(neg4)
        # Sıralama yapılır
        self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # Akışlar oluşturulur
        self.analyzer.reconstruct_flows()
        # Anomali taraması yapıldığında SequenceAnomalyError fırlatılmalıdır
        with self.assertRaises(SequenceAnomalyError):
            # Anomali tespit fonksiyonu çağrılır
            self.analyzer.detect_anomalies()

    # Test 12: NEG_05 Slowloris yavaş başlık damlatma saldırısı tespiti
    def test_12_neg05_slowloris_drip_attack_detection(self) -> None:
        """25 saniyelik yapay başlık gecikmesinde SlowlorisAnomalyError fırlatıldığını test eder."""
        # NEG_05 senaryosu filtrelenir
        neg5 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_05")
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(neg5)
        # Sıralanır
        self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # Akışlar kurulur
        self.analyzer.reconstruct_flows()
        # Anomali taraması çağrıldığında SlowlorisAnomalyError fırlatılmalıdır
        with self.assertRaises(SlowlorisAnomalyError):
            # Anomali tespiti işletilir
            self.analyzer.detect_anomalies()

    # Test 13: NEG_06 Hızlı port taraması (SYN Burst) tespiti
    def test_13_neg06_rapid_port_scan_syn_burst(self) -> None:
        """Kısa sürede 6 farklı porta SYN gönderildiğinde PortScanAnomalyError fırlatıldığını test eder."""
        # NEG_06 senaryosu filtrelenir
        neg6 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_06")
        # Olaylar yüklenir
        self.analyzer.load_events_from_dict(neg6)
        # Sıralama yapılır
        self.analyzer.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # Anomali taraması çağrıldığında PortScanAnomalyError fırlatılmalıdır
        with self.assertRaises(PortScanAnomalyError):
            # Anomali tespiti işletilir
            self.analyzer.detect_anomalies()

    # Test 14: NEG_07, NEG_08, NEG_09 ve Özet Raporlama Doğrulaması
    def test_14_neg07_to_neg09_tunneling_missing_fields_illegal_state(self) -> None:
        """DNS tünelleme, eksik alanlar, geçersiz durum geçişi ve özet rapor doğrulanır."""
        # NEG_07 DNS tünelleme testi
        neg7 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_07")
        # Ayrı motor örneği
        analyzer7 = ProtocolTimelineAnalyzer()
        # Olaylar yüklenir
        analyzer7.load_events_from_dict(neg7)
        # Sıralanır
        analyzer7.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # DNS tünelleme anomali hatası beklenir
        with self.assertRaises(DnsTunnelingAnomalyError):
            # Anomali tespiti işletilir
            analyzer7.detect_anomalies()

        # NEG_08 Eksik alan denetimi
        neg8 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_08")
        # Ayrı motor örneği
        analyzer8 = ProtocolTimelineAnalyzer()
        # MissingEventFieldError fırlatılmalıdır
        with self.assertRaises(MissingEventFieldError):
            # Yükleme denenir
            analyzer8.load_events_from_dict(neg8)

        # NEG_09 Geçersiz TCP durum geçişi (unopened akışta erken FIN)
        neg9 = next(s for s in self.invalid_data["test_senaryolari"] if s["test_kodu"] == "NEG_09")
        # Ayrı motor örneği
        analyzer9 = ProtocolTimelineAnalyzer()
        # Olaylar yüklenir
        analyzer9.load_events_from_dict(neg9)
        # Sıralanır
        analyzer9.validate_and_sort_timeline(enforce_strict_monotonic=False)
        # IllegalStateTransitionError fırlatılmalıdır
        with self.assertRaises(IllegalStateTransitionError):
            # Akış rekonstrüksiyonu denenir
            analyzer9.reconstruct_flows()

        # Standart temiz veri için özet rapor doğrulanır
        self.analyzer.load_events_from_dict(self.sample_data)
        # Sıralanır
        self.analyzer.validate_and_sort_timeline()
        # Akışlar kurulur
        self.analyzer.reconstruct_flows()
        # Anomali taraması temiz bitmelidir
        anomalies = self.analyzer.detect_anomalies()
        # Anomali listesinin boş olduğu test edilir
        self.assertEqual(len(anomalies), 0)
        # Özet rapor üretilir
        report = self.analyzer.generate_summary_report()
        # Güvenlik durumunun TEMİZ olduğu doğrulanır
        self.assertEqual(report["guvenlik_durumu"], "TEMIZ")
        # Toplam olay sayısının 16 olduğu doğrulanır
        self.assertEqual(report["toplam_olay_sayisi"], 16)


# Test modülü doğrudan çalıştırıldığında testleri icra eder
if __name__ == "__main__":
    # Test çalıştırıcısı çağrılır
    unittest.main()
