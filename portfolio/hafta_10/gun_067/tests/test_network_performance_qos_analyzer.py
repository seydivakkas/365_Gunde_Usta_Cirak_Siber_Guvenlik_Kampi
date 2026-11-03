# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G067: Hafta 10 Gün 67 - Paket Kaybı, Gecikme ve Jitter Birim Test Paketi.
Bu test paketi, ağ performansı ve QoS telemetri motorunun tüm hesaplama metriklerini,
SLA ihlal kontrollerini, istatistiksel filtrelerini ve negatif sınır durumlarını doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# JSON veri setlerini işlemek için json kütüphanesi içe aktarılır
import json
# Dosya yollarını işletim sistemi bağımsız yönetmek için Path içe aktarılır
from pathlib import Path

# Test edilecek QoS analiz motoru ve istisnalar içe aktarılır
from portfolio.hafta_10.gun_067.uygulama.network_performance_qos_analyzer import (
    # Ana analiz motoru sınıfı
    NetworkPerformanceQoSAnalyzer,
    # QoS metrik sonuç veri sınıfı
    QoSMetricsResult,
    # Temel QoS hata üst sınıfı
    QoSAnalysisError,
    # Boş paket akışı istisnası
    EmptyPacketStreamError,
    # Geçersiz zaman damgası sıralaması istisnası
    InvalidTimestampOrderError,
    # Negatif gecikme süresi istisnası
    NegativeDelayError,
    # QoS SLA eşik aşımı istisnası
    QoSSLAThresholdViolationError,
    # Aşırı paket kaybı DoS istisnası
    ExcessivePacketLossError,
    # Bozuk sıra numarası istisnası
    MalformedSequenceError,
    # Geçersiz telemetri veri biçimi istisnası
    InvalidTelemetryFormatError,
    # Saat kayması anomali istisnası
    ClockSkewAnomalyError
)


# Ağ performans ve QoS analiz test sınıfı
class TestNetworkPerformanceQoSAnalyzer(unittest.TestCase):
    """G067 QoS ve ağ analiz motorunun birim testlerini yürüten test sınıfı."""

    # Test sınıfı öncesi hazırlık metodu
    def setUp(self) -> None:
        """Her testten önce analiz motorunu ve test veri setlerini hazır hale getirir."""
        # Yeni bir QoS analiz motoru başlatılır
        self.analyzer = NetworkPerformanceQoSAnalyzer()
        # Örnek veri dizini belirlenir
        self.data_dir = Path(__file__).resolve().parent.parent / "ornek_veri"
        # Örnek ağ telemetrisi dosya yolu
        self.sample_telemetry_file = self.data_dir / "sample_network_telemetry.json"
        # Negatif sınır testleri dosya yolu
        self.invalid_inputs_file = self.data_dir / "invalid_qos_inputs.json"

        # Örnek telemetri JSON dosyası yüklenir
        with open(self.sample_telemetry_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe dönüştürülür
            self.telemetry_data = json.load(f)

        # Negatif girdi JSON dosyası yüklenir
        with open(self.invalid_inputs_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe dönüştürülür
            self.invalid_data = json.load(f)

    # Test 01: Telemetri veri setinin yapısal doğrulaması
    def test_01_telemetri_veri_seti_yukleme_ve_dogrulama(self) -> None:
        """Telemetri dosyasının 4 ana akışı eksiksiz içerdiğini teyit eder."""
        # Referans akış kontrolü
        self.assertIn("referans_akisi", self.telemetry_data)
        # VoIP RTP akış kontrolü
        self.assertIn("voip_rtp_akisi", self.telemetry_data)
        # TCP retransmission akış kontrolü
        self.assertIn("tcp_retransmission_akisi", self.telemetry_data)
        # DoS saldırı akış kontrolü
        self.assertIn("dos_saldiri_akisi", self.telemetry_data)

    # Test 02: Referans temiz akışta gecikme ve sıfır kayıp doğrulaması
    def test_02_referans_temiz_akis_gecikme_ve_sifir_kayip(self) -> None:
        """İdeal ağ ortamında sıfır kayıp ve sabit gecikmenin hesaplandığını doğrular."""
        # Temiz referans akışı seçilir
        clean_flow = self.telemetry_data["referans_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_udp_voip_stream(clean_flow, raise_on_sla_violation=False)
        # Gönderilen paket sayısı 10 olmalıdır
        self.assertEqual(result.gonderilen_paket_sayisi, 10)
        # Alınan paket sayısı 10 olmalıdır
        self.assertEqual(result.alinan_paket_sayisi, 10)
        # Kaybolan paket sayısı sıfır olmalıdır
        self.assertEqual(result.kaybolan_paket_sayisi, 0)
        # Kayıp oranı %0 olmalıdır
        self.assertEqual(result.kayip_orani_yuzde, 0.0)
        # Ortalama gecikme 10.0 ms olmalıdır (her paket 10ms sonra varmıştır)
        self.assertEqual(result.ortalama_gecikme_ms, 10.0)
        # Gecikme sabit olduğu için jitter 0.0 ms olmalıdır
        self.assertEqual(result.ortalama_jitter_ms, 0.0)
        # SLA durumu UYUMLU olmalıdır
        self.assertEqual(result.sla_durumu, "UYUMLU")

    # Test 03: VoIP RTP akışında gecikme metriklerinin hesaplanması
    def test_03_voip_rtp_gecikme_hesaplama(self) -> None:
        """VoIP akışında ortalama, minimum ve maksimum tek yönlü gecikmeyi test eder."""
        # VoIP RTP akışı seçilir
        voip_flow = self.telemetry_data["voip_rtp_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_udp_voip_stream(voip_flow, raise_on_sla_violation=False)
        # Minimum gecikmenin pozitif olduğu doğrulanır
        self.assertGreater(result.min_gecikme_ms, 0.0)
        # Maksimum gecikmenin minimum gecikmeden büyük olduğu doğrulanır
        self.assertGreater(result.max_gecikme_ms, result.min_gecikme_ms)
        # Ortalama gecikmenin min ve max arasında olduğu doğrulanır
        self.assertTrue(result.min_gecikme_ms <= result.ortalama_gecikme_ms <= result.max_gecikme_ms)

    # Test 04: VoIP RTP akışında RFC 3393 ve RFC 3550 jitter hesaplaması
    def test_04_voip_rtp_jitter_rfc3393_ve_rfc3550(self) -> None:
        """Gecikme değişimlerinin (jitter) pozitif ve beklenen aralıkta çıktığını doğrular."""
        # VoIP akışı seçilir
        voip_flow = self.telemetry_data["voip_rtp_akisi"]
        # Analiz yapılır
        result = self.analyzer.analyze_udp_voip_stream(voip_flow, raise_on_sla_violation=False)
        # Ortalama jitter değerinin sıfırdan büyük olduğu test edilir
        self.assertGreater(result.ortalama_jitter_ms, 0.0)
        # RFC 3550 filtrelenmiş jitter değerinin hesaplandığı kontrol edilir
        self.assertGreater(result.rfc3550_jitter_ms, 0.0)

    # Test 05: VoIP RTP akışında sıra numarası boşlukları ile paket kaybı tespiti
    def test_05_voip_rtp_paket_kaybi_tespiti(self) -> None:
        """Eksik sıra numaralarından hareketle kaybolan paketlerin ve oranının tespiti doğrulanır."""
        # VoIP akışı (1..10 arası sıra no, 4 ve 9 eksik -> 8 paket var, 2 paket kayıp)
        voip_flow = self.telemetry_data["voip_rtp_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_udp_voip_stream(voip_flow, raise_on_sla_violation=False)
        # Toplam beklenen paket sayısı 10 olmalıdır
        self.assertEqual(result.gonderilen_paket_sayisi, 10)
        # Alınan paket sayısı 8 olmalıdır
        self.assertEqual(result.alinan_paket_sayisi, 8)
        # Kaybolan paket sayısı 2 olmalıdır
        self.assertEqual(result.kaybolan_paket_sayisi, 2)
        # Kayıp oranı %20.0 olmalıdır
        self.assertEqual(result.kayip_orani_yuzde, 20.0)

    # Test 06: TCP akışında RTT (Round Trip Time) hesaplaması
    def test_06_tcp_rtt_gecikme_hesaplama(self) -> None:
        """TCP segmentlerinin ACK geliş sürelerinden RTT hesaplamasının doğruluğu test edilir."""
        # TCP akışı seçilir
        tcp_flow = self.telemetry_data["tcp_retransmission_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_tcp_stream(tcp_flow, raise_on_sla_violation=False)
        # Protokolün TCP olduğu doğrulanır
        self.assertEqual(result.protokol, "TCP")
        # Ortalama RTT süresinin sıfırdan büyük olduğu doğrulanır
        self.assertGreater(result.ortalama_gecikme_ms, 0.0)
        # Minimum RTT kontrolü yapılır
        self.assertGreater(result.min_gecikme_ms, 0.0)

    # Test 07: TCP akışında Retransmission ve kayıp oranı tespiti
    def test_07_tcp_retransmission_ve_kayip_orani(self) -> None:
        """Tekrarlanan segmentlerden TCP yeniden iletim sayısının ve oranının tespiti doğrulanır."""
        # TCP akışı seçilir (8 segmentten 2 tanesi is_retrans=True)
        tcp_flow = self.telemetry_data["tcp_retransmission_akisi"]
        # Analiz yapılır
        result = self.analyzer.analyze_tcp_stream(tcp_flow, raise_on_sla_violation=False)
        # Toplam iletilen segment sayısı 8 olmalıdır
        self.assertEqual(result.gonderilen_paket_sayisi, 8)
        # Yeniden iletim sayısı 2 olmalıdır
        self.assertEqual(result.retransmission_sayisi, 2)
        # Yeniden iletim oranı %25.0 olmalıdır (2 / 8 * 100)
        self.assertEqual(result.retransmission_orani_yuzde, 25.0)

    # Test 08: DoS / Tıkanıklık akışında aşırı gecikme ve kayıp tespiti
    def test_08_dos_saldiri_akisi_asiri_gecikme_ve_kayip(self) -> None:
        """Trafik patlaması ve DoS saldırısı altında gelişen yüksek gecikme ve kaybı test eder."""
        # DoS akışı seçilir
        dos_flow = self.telemetry_data["dos_saldiri_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_udp_voip_stream(dos_flow, raise_on_sla_violation=False)
        # Beklenen toplam paket sayısı 9 olmalıdır (1'den 9'a kadar)
        self.assertEqual(result.gonderilen_paket_sayisi, 9)
        # Alınan paket sayısı 4 olmalıdır
        self.assertEqual(result.alinan_paket_sayisi, 4)
        # Kayıp sayısı 5 olmalıdır
        self.assertEqual(result.kaybolan_paket_sayisi, 5)
        # Kayıp oranı %50'nin üzerinde olmalıdır
        self.assertGreater(result.kayip_orani_yuzde, 50.0)
        # Durumun KRITIK_TEHLIKE olarak işaretlendiği doğrulanır
        self.assertEqual(result.sla_durumu, "KRITIK_TEHLIKE")

    # Test 09: SLA uyumluluk ve ihlal gerekçelerinin raporlanması
    def test_09_sla_uyumluluk_ve_ihlal_sebepleri(self) -> None:
        """SLA limitleri aşıldığında ihlal gerekçelerinin listelendiğini doğrular."""
        # VoIP akışı seçilir (Kayıp oranı %20, varsayılan limit %3)
        voip_flow = self.telemetry_data["voip_rtp_akisi"]
        # Analiz yürütülür
        result = self.analyzer.analyze_udp_voip_stream(voip_flow, raise_on_sla_violation=False)
        # Durumun IHLAL_VAR veya KRITIK_TEHLIKE olduğu doğrulanır
        self.assertIn(result.sla_durumu, ["IHLAL_VAR", "KRITIK_TEHLIKE"])
        # En az bir ihlal gerekçesi yazılmış olmalıdır
        self.assertGreater(len(result.sla_ihlal_sebepleri), 0)

    # Test 10: Özel SLA eşik değerleri ile dinamik değerlendirme
    def test_10_ozel_sla_esik_degerleri_enjeksiyonu(self) -> None:
        """Kullanıcı tanımlı çok sıkı SLA limitleri verildiğinde ihlal tespitini doğrular."""
        # Çok sıkı SLA kuralı tanımlanır (max gecikme 5ms)
        strict_sla = {
            "max_ortalama_gecikme_ms": 5.0,
            "max_jitter_ms": 1.0,
            "max_kayip_orani_yuzde": 0.5
        }
        # Referans akış (gecikmesi 10ms olan) seçilir
        clean_flow = self.telemetry_data["referans_akisi"]
        # Sıkı SLA ile analiz edilir
        result = self.analyzer.analyze_udp_voip_stream(clean_flow, sla_limits=strict_sla, raise_on_sla_violation=False)
        # Normalde uyumlu olan akış şimdi ihlale düşmelidir
        self.assertEqual(result.sla_durumu, "IHLAL_VAR")

    # Test 11: Toplu telemetri veri seti analizi ve ağ sağlığı özeti
    def test_11_toplu_telemetri_raporlama(self) -> None:
        """Tüm ağ telemetri veri setinin toplu analizinde üretilen konsolide raporu doğrular."""
        # Toplu analiz çalıştırılır
        batch_report = self.analyzer.analyze_full_telemetry_batch(self.telemetry_data)
        # Toplam 4 akışın incelendiği doğrulanır
        self.assertEqual(batch_report["toplam_akis_sayisi"], 4)
        # En az 1 uyumlu akış olduğu doğrulanır
        self.assertGreaterEqual(batch_report["uyumlu_akis_sayisi"], 1)
        # İhlal edilen akış sayısının pozitif olduğu doğrulanır
        self.assertGreaterEqual(batch_report["ihlal_edilen_akis_sayisi"], 1)
        # Genel ağ sağlığının ihlal uyarısı verdiği kontrol edilir
        self.assertEqual(batch_report["genel_ag_sagligi"], "TIKANIKLIK_VE_IHLAL_TESPIT_EDILDI")

    # Test 12: Tek paketli sınır durumu analizi
    def test_12_tekil_paket_gecikme_sinir_durumu(self) -> None:
        """Yalnızca tek bir pakete sahip uç durumda jitter ve kayıp hesaplarının çökmediğini doğrular."""
        # Tek paketli yapay akış
        single_pkt_flow = {
            "akis_id": "FLOW-SINGLE-01",
            "protokol": "UDP",
            "paketler": [
                {"sira_no": 1, "gonderim_zamani": 100.0, "varis_zamani": 100.015}
            ]
        }
        # Analiz yapılır
        result = self.analyzer.analyze_udp_voip_stream(single_pkt_flow, raise_on_sla_violation=False)
        # Paket sayısı 1 olmalıdır
        self.assertEqual(result.gonderilen_paket_sayisi, 1)
        # Gecikme 15ms olmalıdır
        self.assertEqual(result.ortalama_gecikme_ms, 15.0)
        # Tek paket olduğu için jitter 0.0 olmalıdır
        self.assertEqual(result.ortalama_jitter_ms, 0.0)

    # Test 13: Negatif sınır senaryoları Grup 1 (NEG_01 - NEG_04)
    def test_13_negatif_sinir_senaryolari_grup_1(self) -> None:
        """NEG_01'den NEG_04'e kadar olan istisnaların eksiksiz fırlatıldığını doğrular."""
        # Senaryolar sözlükte haritalanır
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_01: Boş paket akışı hatası
        s1 = scenarios["NEG_01"]
        # İstisna kontrolü
        with self.assertRaises(EmptyPacketStreamError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s1["akis_verisi"])

        # NEG_02: Zamanda geriye gidiş hatası
        s2 = scenarios["NEG_02"]
        # İstisna kontrolü
        with self.assertRaises(InvalidTimestampOrderError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s2["akis_verisi"])

        # NEG_03: Negatif gecikme süresi hatası
        s3 = scenarios["NEG_03"]
        # İstisna kontrolü
        with self.assertRaises(NegativeDelayError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s3["akis_verisi"])

        # NEG_04: SLA eşik aşımı hatası (raise_on_sla_violation=True ile)
        s4 = scenarios["NEG_04"]
        # İstisna kontrolü
        with self.assertRaises(QoSSLAThresholdViolationError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s4["akis_verisi"], sla_limits=s4["sla_limitleri"], raise_on_sla_violation=True)

    # Test 14: Negatif sınır senaryoları Grup 2 (NEG_05 - NEG_09)
    def test_14_negatif_sinir_senaryolari_grup_2(self) -> None:
        """NEG_05'ten NEG_09'a kadar olan DoS kaybı, sıra hatası, biçim ve saat kayması istisnalarını test eder."""
        # Senaryolar sözlükte haritalanır
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_05: Aşırı kayıp ve olası DoS hatası
        s5 = scenarios["NEG_05"]
        # İstisna kontrolü
        with self.assertRaises(ExcessivePacketLossError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s5["akis_verisi"], sla_limits=s5["sla_limitleri"], raise_on_sla_violation=True)

        # NEG_06: Negatif sıra numarası hatası
        s6 = scenarios["NEG_06"]
        # İstisna kontrolü
        with self.assertRaises(MalformedSequenceError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s6["akis_verisi"])

        # NEG_07: Geçersiz telemetri veri biçimi hatası
        s7 = scenarios["NEG_07"]
        # İstisna kontrolü
        with self.assertRaises(InvalidTelemetryFormatError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s7["akis_verisi"])

        # NEG_08: Aşırı saat kayması anomali hatası
        s8 = scenarios["NEG_08"]
        # İstisna kontrolü
        with self.assertRaises(ClockSkewAnomalyError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s8["akis_verisi"])

        # NEG_09: Eksik paket alanları hatası
        s9 = scenarios["NEG_09"]
        # İstisna kontrolü
        with self.assertRaises(InvalidTelemetryFormatError):
            # Analiz çağrılır
            self.analyzer.analyze_udp_voip_stream(s9["akis_verisi"])


# Komut satırından çalıştırıldığında testleri başlatan blok
if __name__ == "__main__":
    # unittest modülü main fonksiyonu çağrılır
    unittest.main()
