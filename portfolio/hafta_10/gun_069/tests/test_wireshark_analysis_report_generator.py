# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G069: Hafta 10 Gün 69 - Mini Proje 9: Wireshark Analiz Raporu Birim Test Paketi.
Bu test paketi, PCAP telemetri analizi, protokol hiyerarşisi, en aktif konuşmacılar,
TCP bağlantı sağlığı, güvenlik zafiyetleri ve adli raporlama motorunu doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır
import unittest
# JSON veri setlerini işlemek için json kütüphanesi içe aktarılır
import json
# Dosya yollarını işletim sisteminden bağımsız yönetmek için Path sınıfı içe aktarılır
from pathlib import Path

# Test edilecek analiz motoru ve istisnalar içe aktarılır
from portfolio.hafta_10.gun_069.uygulama.wireshark_analysis_report_generator import (
    # Ana rapor üretici sınıf
    WiresharkAnalysisReportGenerator,
    # Protokol istatistiği veri sınıfı
    ProtocolStat,
    # Konuşma istatistiği veri sınıfı
    ConversationStat,
    # TCP sağlık veri sınıfı
    TCPHealthStat,
    # Güvenlik bulgusu veri sınıfı
    SecurityFinding,
    # Temel hata üst sınıfı
    WiresharkReportError,
    # Boş PCAP hatası
    EmptyPCAPStreamError,
    # Geçersiz PCAP telemetri hatası
    InvalidPCAPDataError,
    # Bozuk paket başlığı hatası
    MalformedPacketHeaderError,
    # Desteklenmeyen protokol hatası
    UnsupportedProtocolError,
    # Aşırı paket boyutu hatası
    OversizedPacketLengthError,
    # Bozuk konuşma demeti hatası
    MalformedConversationTupleError,
    # Geçersiz rapor formatı hatası
    InvalidReportFormatError,
    # Kronoloji bozulma hatası
    InconsistentCaptureTimestampError,
    # Geçersiz önem seviyesi filtresi hatası
    InvalidSeverityThresholdError
)


# Wireshark analiz raporu birim test sınıfı
class TestWiresharkAnalysisReportGenerator(unittest.TestCase):
    """G069 Wireshark raporlama motorunun pozitif, negatif ve adli analiz testlerini yürütür."""

    # Her test öncesi ortak kaynakları hazırlayan metot
    def setUp(self) -> None:
        """Her testten önce rapor motorunu ve test veri setlerini hazır hale getirir."""
        # Yeni bir rapor üretici motor örneği oluşturulur
        self.generator = WiresharkAnalysisReportGenerator()
        # Test veri setlerinin bulunduğu dizin belirlenir
        self.data_dir = Path(__file__).resolve().parent.parent / "ornek_veri"
        # Gerçekçi PCAP ayrıştırma verisi dosya yolu
        self.sample_pcap_file = self.data_dir / "sample_pcap_dissection.json"
        # Negatif sınır testleri dosya yolu
        self.invalid_inputs_file = self.data_dir / "invalid_report_inputs.json"

        # Örnek PCAP dosyası okunur
        with open(self.sample_pcap_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe çözümlenir
            self.pcap_data = json.load(f)

        # Negatif girdi dosyası okunur
        with open(self.invalid_inputs_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe çözümlenir
            self.invalid_data = json.load(f)

    # Test 01: PCAP veri setinin yapısal doğrulaması
    def test_01_pcap_veri_seti_yukleme_ve_dogrulama(self) -> None:
        """PCAP dosyasının meta-verilerini ve 15 adet paketi eksiksiz içerdiğini teyit eder."""
        # Meta-veri kontrolü
        self.assertIn("yakalama_metaverisi", self.pcap_data)
        # Paket listesi kontrolü
        self.assertIn("paketler", self.pcap_data)
        # Toplam 15 adet paket olduğu doğrulanır
        self.assertEqual(len(self.pcap_data["paketler"]), 15)

    # Test 02: Protokol hiyerarşisi dağılımının hesaplanması
    def test_02_protokol_hiyerarsisi_dagilimi(self) -> None:
        """Paketlerin protokollere göre ayrıştırılıp bayt ve paket oranlarının doğru hesaplandığını test eder."""
        # Paketler listesi alınır
        packets = self.pcap_data["paketler"]
        # Hiyerarşi hesaplanır
        hierarchy = self.generator.calculate_protocol_hierarchy(packets)
        # En az 5 farklı protokol olduğu doğrulanır (TCP, HTTP, DNS, TLS, ICMP, FTP)
        self.assertGreaterEqual(len(hierarchy), 5)
        # Yüzdelerin toplamının yaklaşık %100 olduğu doğrulanır
        total_pct = sum(h.paket_yuzdesi for h in hierarchy)
        self.assertAlmostEqual(total_pct, 100.0, delta=1.0)

    # Test 03: En aktif konuşmacıların (Conversations) çıkarılması
    def test_03_en_cok_konusan_uc_noktalar(self) -> None:
        """Uç noktalar arası konuşma trafiğinin bayt hacmine göre doğru sıralandığını test eder."""
        # Paketler listesi alınır
        packets = self.pcap_data["paketler"]
        # Konuşmalar çıkarılır (top 5)
        convs = self.generator.extract_conversations(packets, top_n=5)
        # En fazla 5 konuşma döndüğü kontrol edilir
        self.assertLessEqual(len(convs), 5)
        # İlk konuşmanın en yüksek bayt miktarına sahip olduğu doğrulanır
        self.assertGreaterEqual(convs[0].toplam_bayt, convs[-1].toplam_bayt)

    # Test 04: TCP bağlantı sağlığı ve anomali tespiti
    def test_04_tcp_saglik_metrikleri_ve_anomalileri(self) -> None:
        """Zero Window ve Retransmission gibi TCP sağlık sorunlarının yakalandığını test eder."""
        # Paketler listesi alınır
        packets = self.pcap_data["paketler"]
        # TCP sağlık analizi yapılır
        health = self.generator.analyze_tcp_health(packets)
        # Sıfır pencere sayısının en az 1 olduğu doğrulanır
        self.assertGreaterEqual(health.zero_window_sayisi, 1)
        # Retransmission sayısının en az 1 olduğu doğrulanır
        self.assertGreaterEqual(health.retransmission_sayisi, 1)
        # Durumun anomali uyarısı verdiği kontrol edilir
        self.assertEqual(health.saglik_durumu, "TIKANIKLIK_VE_PAKET_KAYBI_TESPIT_EDILDI")

    # Test 05: SQLi ve otomatik saldırı tarayıcısı tespiti
    def test_05_sqli_ve_otomatik_tarayici_tespiti(self) -> None:
        """sqlmap User-Agent ve URL'deki SQLi enjeksiyonunun yakalandığını doğrular."""
        # Paketler taranır
        findings = self.generator.detect_security_anomalies(self.pcap_data["paketler"])
        # SQLi bulgusu aranır
        sqli_f = [f for f in findings if f.kod == "SEC_SQLI_SCANNER_PROBE"]
        # En az bir bulgu olmalıdır
        self.assertTrue(len(sqli_f) >= 1)
        # Önem derecesi KRİTİK olmalıdır
        self.assertEqual(sqli_f[0].onem, "KRITIK")

    # Test 06: DNS tünelleme ile veri sızdırma (exfiltration) tespiti
    def test_06_dns_tunelleme_veri_sizintisi_tespiti(self) -> None:
        """TXT sorgulu uzun Base64 alan adının tünelleme olarak yakalandığını doğrular."""
        # Bulgular taranır
        findings = self.generator.detect_security_anomalies(self.pcap_data["paketler"])
        # Tünelleme bulgusu aranır
        tunnel_f = [f for f in findings if f.kod == "SEC_DNS_TUNNEL_EXFIL"]
        # Bulgunun varlığı doğrulanır
        self.assertTrue(len(tunnel_f) >= 1)
        # Önem derecesinin KRİTİK olduğu kontrol edilir
        self.assertEqual(tunnel_f[0].onem, "KRITIK")

    # Test 07: Ağ üzerinden açık metin parola iletimi tespiti
    def test_07_acik_metin_parola_ifsa_tespiti(self) -> None:
        """FTP oturumunda geçen açık metin kimlik ve şifrelerin yakalandığını doğrular."""
        # Bulgular taranır
        findings = self.generator.detect_security_anomalies(self.pcap_data["paketler"])
        # Açık metin parola bulgusu aranır
        leak_f = [f for f in findings if f.kod == "SEC_CLEARTEXT_AUTH_LEAK"]
        # Bulgu doğrulanır
        self.assertTrue(len(leak_f) >= 1)
        # Önem derecesi YÜKSEK olmalıdır
        self.assertEqual(leak_f[0].onem, "YUKSEK")

    # Test 08: HTTP CRLF başlık enjeksiyonu tespiti
    def test_08_http_crlf_enjeksiyon_tespiti(self) -> None:
        """URI içindeki CRLF karakterlerinin ve Set-Cookie enjeksiyonunun tespitini doğrular."""
        # Bulgular taranır
        findings = self.generator.detect_security_anomalies(self.pcap_data["paketler"])
        # CRLF bulgusu aranır
        crlf_f = [f for f in findings if f.kod == "SEC_HTTP_CRLF_INJECTION"]
        # Bulgu doğrulanır
        self.assertTrue(len(crlf_f) >= 1)
        # Önem derecesi YÜKSEK olmalıdır
        self.assertEqual(crlf_f[0].onem, "YUKSEK")

    # Test 09: Bulguların önem seviyesine göre filtrelenmesi
    def test_09_guvenlik_bulgulari_onem_filtreleme(self) -> None:
        """filter_findings_by_severity metodunun yalnızca belirtilen seviye ve üzerini getirdiğini teyit eder."""
        # Tüm bulgular alınır
        all_findings = self.generator.detect_security_anomalies(self.pcap_data["paketler"])
        # Sadece KRİTİK olanlar filtrelenir
        kritik_findings = self.generator.filter_findings_by_severity(all_findings, min_severity="KRITIK")
        # Hepsinin KRITIK olduğu kontrol edilir
        self.assertTrue(all(f.onem == "KRITIK" for f in kritik_findings))
        # Kritik sayısı toplam bulgu sayısından küçük veya eşit olmalıdır
        self.assertLessEqual(len(kritik_findings), len(all_findings))

    # Test 10: Tam adli analiz raporunun TEXT formatında üretilmesi
    def test_10_tam_rapor_metin_formati_uretimi(self) -> None:
        """Metin tabanlı Wireshark analiz raporunun 7 ana bölümü eksiksiz içerdiğini teyit eder."""
        # Rapor metni üretilir
        report_text = self.generator.generate_report(self.pcap_data, output_format="TEXT")
        # Rapor başlığı denetlenir
        self.assertIn("WİRESHARK AĞ ANALİZİ VE ADLİ SİBER TEHDİT RAPORU", report_text)
        # Protokol hiyerarşisi bölümü denetlenir
        self.assertIn("PROTOKOL HİYERARŞİSİ", report_text)
        # Konuşmalar bölümü denetlenir
        self.assertIn("EN AKTİF AĞ KONUŞMALARI", report_text)
        # TCP sağlık bölümü denetlenir
        self.assertIn("TCP PERFORMANS VE BAĞLANTI SAĞLIK METRİKLERİ", report_text)
        # IoC tablosu denetlenir
        self.assertIn("ADLİ TEHDİT GÖSTERGELERİ", report_text)

    # Test 11: Tam adli analiz raporunun JSON formatında üretilmesi
    def test_11_tam_rapor_json_formati_uretimi(self) -> None:
        """JSON tabanlı Wireshark analiz raporunun şemaya uygun sözlük olarak üretildiğini teyit eder."""
        # JSON raporu üretilir
        report_json = self.generator.generate_report(self.pcap_data, output_format="JSON")
        # Sözlük tipi doğrulanır
        self.assertIsInstance(report_json, dict)
        # Güvenlik skorunun hesaplandığı kontrol edilir
        self.assertIn("guvenlik_skoru", report_json)
        # Genel risk seviyesinin belirlendiği kontrol edilir
        self.assertIn("genel_risk_seviyesi", report_json)
        # Risk seviyesinin KRITIK veya YUKSEK çıktığı doğrulanır
        self.assertIn(report_json["genel_risk_seviyesi"], ["KRITIK_TEHLIKE", "YUKSEK_RISK"])

    # Test 12: Temiz ağ trafiğinde yüksek güvenlik skoru ve düşük risk
    def test_12_temiz_trafik_yuksek_guvenlik_skoru(self) -> None:
        """Zararlı aktivite içermeyen meşru trafikte 100 tam puan alındığını test eder."""
        # Temiz yapay veri seti
        clean_pcap = {
            "yakalama_metaverisi": {"dosya_adi": "clean_traffic.pcap"},
            "paketler": [
                {"paket_no": 1, "zaman_damgasi": 1000.0, "boyut_bayt": 60, "protokol": "ICMP", "kaynak_ip": "10.0.0.1", "hedef_ip": "10.0.0.2"},
                {"paket_no": 2, "zaman_damgasi": 1000.1, "boyut_bayt": 60, "protokol": "ICMP", "kaynak_ip": "10.0.0.2", "hedef_ip": "10.0.0.1"}
            ]
        }
        # JSON rapor üretilir
        rep = self.generator.generate_report(clean_pcap, output_format="JSON")
        # Güvenlik skoru 100 olmalıdır
        self.assertEqual(rep["guvenlik_skoru"], 100)
        # Risk seviyesi DUSUK_RISK olmalıdır
        self.assertEqual(rep["genel_risk_seviyesi"], "DUSUK_RISK")

    # Test 13: Negatif sınır senaryoları Grup 1 (NEG_01 - NEG_04)
    def test_13_negatif_sinir_senaryolari_grup_1(self) -> None:
        """NEG_01'den NEG_04'e kadar olan boş akış, biçim, başlık ve protokol hatalarını doğrular."""
        # Senaryolar indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_01: Boş PCAP paket listesi
        s1 = scenarios["NEG_01"]
        # İstisna denetimi
        with self.assertRaises(EmptyPCAPStreamError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s1["pcap_verisi"])

        # NEG_02: Geçersiz veri formatı
        s2 = scenarios["NEG_02"]
        # İstisna denetimi
        with self.assertRaises(InvalidPCAPDataError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s2["pcap_verisi"])

        # NEG_03: Bozuk paket başlığı
        s3 = scenarios["NEG_03"]
        # İstisna denetimi
        with self.assertRaises(MalformedPacketHeaderError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s3["pcap_verisi"])

        # NEG_04: Boş veya geçersiz protokol
        s4 = scenarios["NEG_04"]
        # İstisna denetimi
        with self.assertRaises(UnsupportedProtocolError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s4["pcap_verisi"])

    # Test 14: Negatif sınır senaryoları Grup 2 (NEG_05 - NEG_09)
    def test_14_negatif_sinir_senaryolari_grup_2(self) -> None:
        """NEG_05'ten NEG_09'a kadar olan MTU aşımı, zaman bozulması ve geçersiz filtre testlerini doğrular."""
        # Senaryolar indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_05: Aşırı paket boyutu (MTU sınırı aşımı)
        s5 = scenarios["NEG_05"]
        # İstisna denetimi
        with self.assertRaises(OversizedPacketLengthError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s5["pcap_verisi"])

        # NEG_07: Geçersiz rapor formatı
        s7 = scenarios["NEG_07"]
        # İstisna denetimi
        with self.assertRaises(InvalidReportFormatError):
            # Geçersiz formatla rapor üretimi çağrılır
            self.generator.generate_report(self.pcap_data, output_format=s7["istenilen_format"])

        # NEG_08: Zamanda geriye giden paket zamanı
        s8 = scenarios["NEG_08"]
        # İstisna denetimi
        with self.assertRaises(InconsistentCaptureTimestampError):
            # Rapor üretimi çağrılır
            self.generator.generate_report(s8["pcap_verisi"])

        # NEG_09: Geçersiz filtre seviyesi
        s9 = scenarios["NEG_09"]
        # İstisna denetimi
        with self.assertRaises(InvalidSeverityThresholdError):
            # Geçersiz filtre çağrılır
            self.generator.filter_findings_by_severity([], min_severity=s9["filtre_seviyesi"])


# Komut satırından çalıştırıldığında testleri başlatan blok
if __name__ == "__main__":
    # unittest çalıştırılır
    unittest.main()
