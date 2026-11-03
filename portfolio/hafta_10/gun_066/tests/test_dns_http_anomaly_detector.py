# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G066: Hafta 10 Gün 66 - DNS ve HTTP Anomali İşaretleri Birim Test Paketi.
Bu test modülü, DNS (DGA, tünelleme, amplifikasyon, Fast Flux) ve HTTP (Request Smuggling,
CRLF enjeksiyonu, Path Traversal, otomatik tarayıcılar) protokol anomali tespit motorunun
tüm fonksiyonlarını, istatistiksel sınırlarını ve istisnai durumlarını doğrular.
"""

# Birim test çerçevesi için unittest modülü içe aktarılır
import unittest
# JSON veri setlerini yüklemek için json kütüphanesi içe aktarılır
import json
# Dosya yollarını işletim sisteminden bağımsız yönetmek için Path sınıfı içe aktarılır
from pathlib import Path

# Test edilecek tespit motoru ve ilişkili sınıflar içe aktarılır
from portfolio.hafta_10.gun_066.uygulama.dns_http_anomaly_detector import (
    # Ana tespit motoru sınıfı
    DNSHTTPAnomalyDetector,
    # Tekil anomali bulgusu veri sınıfı
    AnomalyFinding,
    # Temel anomali hatası üst sınıfı
    AnomalyDetectionError,
    # DGA alan adı tespit istisnası
    DGAAnomalyError,
    # DNS tünelleme tespit istisnası
    DNSTunnelingError,
    # DNS amplifikasyon tespit istisnası
    DNSAmplificationError,
    # HTTP Request Smuggling tespit istisnası
    HTTPRequestSmugglingError,
    # HTTP CRLF başlık enjeksiyonu istisnası
    HeaderInjectionError,
    # Dizin geçişi (Path Traversal) tespit istisnası
    PathTraversalError,
    # Zararlı saldırı tarayıcısı tespit istisnası
    MaliciousScannerError,
    # Bozuk telemetri veya kayıt nesnesi istisnası
    MalformedRecordError,
    # Fast Flux botnet C2 tespit istisnası
    FastFluxAnomalyError
)


# DNS ve HTTP anomali tespit test sınıfı
class TestDNSHTTPAnomalyDetector(unittest.TestCase):
    """G066 anomali tespit motorunun tüm pozitif ve negatif senaryolarını test eder."""

    # Test sınıfı öncesi ortak kaynakları hazırlayan metot
    def setUp(self) -> None:
        """Her testten önce anomali motorunu ve test veri setlerini hazır hale getirir."""
        # Yeni bir tespit motoru örneği oluşturulur
        self.detector = DNSHTTPAnomalyDetector()
        # Test veri setlerinin bulunduğu dizin belirlenir
        self.data_dir = Path(__file__).resolve().parent.parent / "ornek_veri"
        # Gerçekçi trafik göstergeleri dosya yolu belirlenir
        self.sample_traffic_file = self.data_dir / "sample_traffic_indicators.json"
        # Negatif sınır testleri dosya yolu belirlenir
        self.invalid_inputs_file = self.data_dir / "invalid_anomaly_inputs.json"

        # Örnek trafik dosyası okunur
        with open(self.sample_traffic_file, "r", encoding="utf-8") as f:
            # JSON içeriği sözlüğe çözümlenir
            self.traffic_data = json.load(f)

        # Negatif girdi dosyası okunur
        with open(self.invalid_inputs_file, "r", encoding="utf-8") as f:
            # JSON içeriği sözlüğe çözümlenir
            self.invalid_data = json.load(f)

    # Test 01: Örnek trafik veri setinin yapısal doğrulaması
    def test_01_ornek_trafik_veri_seti_yukleme_ve_dogrulama(self) -> None:
        """Trafik veri setinin eksiksiz yüklendiğini ve beklenen şemaya uyduğunu doğrular."""
        # DNS kayıtlarının varlığı denetlenir
        self.assertIn("dns_kayitlari", self.traffic_data)
        # HTTP kayıtlarının varlığı denetlenir
        self.assertIn("http_kayitlari", self.traffic_data)
        # Toplam 5 adet DNS kaydı olduğu doğrulanır
        self.assertEqual(len(self.traffic_data["dns_kayitlari"]), 5)
        # Toplam 5 adet HTTP kaydı olduğu doğrulanır
        self.assertEqual(len(self.traffic_data["http_kayitlari"]), 5)

    # Test 02: Normal ve meşru DNS trafiğinin temiz çıkması
    def test_02_normal_dns_trafigi_temiz_analiz(self) -> None:
        """Standart kurumsal alan adı sorgusunun anomali üretmediğini teyit eder."""
        # İlk kayıt olan normal DNS verisi seçilir (api.kurumsal.local)
        normal_dns = self.traffic_data["dns_kayitlari"][0]
        # Anomali analizi çalıştırılır
        findings = self.detector.analyze_dns_record(normal_dns, raise_on_detection=False)
        # Hiçbir güvenlik anomalisinin tespit edilmediği doğrulanır
        self.assertEqual(len(findings), 0)

    # Test 03: Normal ve meşru HTTP trafiğinin temiz çıkması
    def test_03_normal_http_trafigi_temiz_analiz(self) -> None:
        """Standart HTTP GET isteğinin temiz sonuçlandığını ve anomali üretmediğini doğrular."""
        # Normal HTTP kaydı seçilir (/dashboard/overview)
        normal_http = self.traffic_data["http_kayitlari"][0]
        # Anomali analizi yürütülür
        findings = self.detector.analyze_http_record(normal_http, raise_on_detection=False)
        # Bulgular listesinin boş olduğu doğrulanır
        self.assertEqual(len(findings), 0)

    # Test 04: DGA (Domain Generation Algorithm) alan adı tespiti
    def test_04_dga_alan_adi_entropi_ve_sessiz_harf_tespiti(self) -> None:
        """Rastgele üretilmiş yüksek entropili DGA alan adının başarıyla yakalandığını test eder."""
        # DGA kaydı seçilir (xkf92mqp7vla81zk.top)
        dga_record = self.traffic_data["dns_kayitlari"][1]
        # Anomali analizi yapılır
        findings = self.detector.analyze_dns_record(dga_record, raise_on_detection=False)
        # En az bir bulgu üretildiği doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Bulgu anomali kodu doğrulanır
        self.assertEqual(findings[0].anomali_kodu, "DGA_ALAN_ADI_TESPITI")
        # Önem derecesinin KRİTİK olduğu doğrulanır
        self.assertEqual(findings[0].onem_derecesi, "KRITIK")
        # Şannon entropisinin 3.4 üzerinde olduğu doğrulanır
        self.assertGreaterEqual(findings[0].gostergeler["entropi"], 3.4)

    # Test 05: DNS tünelleme ile veri sızdırma (exfiltration) tespiti
    def test_05_dns_tunelleme_veri_sizintisi_tespiti(self) -> None:
        """Aşırı uzun alt alan etiketine sahip TXT tünelleme sorgusunun yakalandığını test eder."""
        # DNS tünelleme kaydı seçilir
        tunnel_record = self.traffic_data["dns_kayitlari"][2]
        # Analiz gerçekleştirilir
        findings = self.detector.analyze_dns_record(tunnel_record, raise_on_detection=False)
        # Bulgu üretildiği doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Anomali kodu doğrulanır
        self.assertEqual(findings[0].anomali_kodu, "DNS_TUNELLEME_SIZINTISI")
        # Kategori doğrulanır
        self.assertEqual(findings[0].kategori, "DNS")

    # Test 06: DNS Amplification yansıtma ve büyütme tespiti
    def test_06_dns_amplification_yansitma_ve_buyutme_tespiti(self) -> None:
        """Yüksek yanıt/istek oranına ve ANY sorgusuna sahip DoS paterninin tespitini doğrular."""
        # Amplifikasyon kaydı seçilir
        amp_record = self.traffic_data["dns_kayitlari"][3]
        # Analiz yürütülür
        findings = self.detector.analyze_dns_record(amp_record, raise_on_detection=False)
        # Bulgu üretildiği teyit edilir
        self.assertTrue(len(findings) >= 1)
        # Anomali kodu doğrulanır
        self.assertEqual(findings[0].anomali_kodu, "DNS_AMPLIFICATION_SALDIRISI")
        # Büyütme faktörünün 25 kat veya üstünde olduğu doğrulanır
        self.assertGreaterEqual(findings[0].gostergeler["buyutme_orani"], 25.0)

    # Test 07: Fast Flux botnet C2 mikro-TTL ve IP rotasyonu tespiti
    def test_07_fast_flux_botnet_c2_mikro_ttl_tespiti(self) -> None:
        """Kısa TTL ve çok sayıda dinamik IP adresi içeren Fast Flux C2 ağının yakalandığını test eder."""
        # Fast flux kaydı seçilir
        flux_record = self.traffic_data["dns_kayitlari"][4]
        # Analiz yürütülür
        findings = self.detector.analyze_dns_record(flux_record, raise_on_detection=False)
        # Bulgu varlığı doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Kodun doğruluğu kontrol edilir
        self.assertEqual(findings[0].anomali_kodu, "FAST_FLUX_BOTNET_C2")
        # TTL'in 30 saniye altında olduğu doğrulanır
        self.assertLessEqual(findings[0].gostergeler["ttl"], 30)
        # Çözülen IP sayısının en az 5 olduğu teyit edilir
        self.assertGreaterEqual(findings[0].gostergeler["ip_sayisi"], 5)

    # Test 08: HTTP Request Smuggling (CL.TE / TE.CL) çatışması tespiti
    def test_08_http_request_smuggling_cl_te_catismasi_tespiti(self) -> None:
        """Hem Content-Length hem de Transfer-Encoding içeren sızdırma isteğinin yakalandığını test eder."""
        # Smuggling isteği seçilir
        smuggle_record = self.traffic_data["http_kayitlari"][1]
        # Analiz yapılır
        findings = self.detector.analyze_http_record(smuggle_record, raise_on_detection=False)
        # Bulgunun üretildiği doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Kod doğrulanır
        self.assertEqual(findings[0].anomali_kodu, "HTTP_REQUEST_SMUGGLING")
        # Kritik önem derecesi denetlenir
        self.assertEqual(findings[0].onem_derecesi, "KRITIK")

    # Test 09: HTTP Header Injection / CRLF bölünmesi tespiti
    def test_09_http_crlf_baslik_enjeksiyonu_tespiti(self) -> None:
        """URI içinde URL-encoded CRLF ve Set-Cookie enjeksiyon girişiminin tespitini test eder."""
        # CRLF kaydı seçilir
        crlf_record = self.traffic_data["http_kayitlari"][2]
        # Analiz yapılır
        findings = self.detector.analyze_http_record(crlf_record, raise_on_detection=False)
        # Bulgu doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Kod kontrol edilir
        self.assertEqual(findings[0].anomali_kodu, "HTTP_CRLF_ENJEKSIYONU")
        # Önem derecesi doğrulanır
        self.assertEqual(findings[0].onem_derecesi, "YUKSEK")

    # Test 10: HTTP Dizin Geçişi (Path Traversal / LFI) tespiti
    def test_10_http_path_traversal_dizin_gecisi_tespiti(self) -> None:
        """URI içinde ../ dizin dışına çıkma ve /etc/passwd okuma denemesinin yakalandığını test eder."""
        # Traversal kaydı seçilir
        traversal_record = self.traffic_data["http_kayitlari"][3]
        # Analiz yapılır
        findings = self.detector.analyze_http_record(traversal_record, raise_on_detection=False)
        # Bulgu doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Kod kontrol edilir
        self.assertEqual(findings[0].anomali_kodu, "PATH_TRAVERSAL_DIZIN_GECISI")

    # Test 11: Otomatik saldırı tarayıcısı User-Agent imzası tespiti
    def test_11_otomatik_saldiri_tarayicisi_imza_tespiti(self) -> None:
        """sqlmap gibi otomatik tarayıcıların başlık imzasıyla yakalandığını test eder."""
        # Tarayıcı kaydı seçilir
        scanner_record = self.traffic_data["http_kayitlari"][4]
        # Analiz yapılır
        findings = self.detector.analyze_http_record(scanner_record, raise_on_detection=False)
        # Bulgu doğrulanır
        self.assertTrue(len(findings) >= 1)
        # Kod kontrol edilir
        self.assertEqual(findings[0].anomali_kodu, "OTOMATIK_TARAMA_TESPITI")
        # Eşleşen imza denetlenir
        self.assertEqual(findings[0].gostergeler["eslesen_imza"], "sqlmap")

    # Test 12: Toplu trafik analizi ve metrik dağılımı doğrulaması
    def test_12_toplu_trafik_analizi_ve_metrik_dagilimi(self) -> None:
        """Tüm DNS ve HTTP paketlerinin toplu analizinde üretilen güvenlik raporunu denetler."""
        # Toplu analiz çalıştırılır
        report = self.detector.analyze_full_traffic(self.traffic_data)
        # Toplam DNS kayıt sayısı doğrulanır
        self.assertEqual(report["toplam_dns_kaydi"], 5)
        # Toplam HTTP kayıt sayısı doğrulanır
        self.assertEqual(report["toplam_http_kaydi"], 5)
        # Toplam anomali sayısı doğrulanır (4 DNS + 4 HTTP = 8 anomali)
        self.assertEqual(report["toplam_anomali_sayisi"], 8)
        # Güvenlik durumunun tehditli çıktığı doğrulanır
        self.assertEqual(report["guvenlik_durumu"], "TEHDITLER_TESPIT_EDILDI")
        # Dağılım sözlüğünde kritik sayısının 4 olduğu doğrulanır (DGA, Tunnel, FastFlux, Smuggle)
        self.assertEqual(report["onem_dagilimi"]["KRITIK"], 4)

    # Test 13: Negatif sınır senaryoları Grup 1 (NEG_01 - NEG_04)
    def test_13_negatif_sinir_senaryolari_grup_1(self) -> None:
        """NEG_01'den NEG_04'e kadar olan anomali istisnalarının fırlatıldığını teyit eder."""
        # Senaryolar sözlükte indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_01: DGA istisnası
        s1 = scenarios["NEG_01"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(DGAAnomalyError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_dns_record(s1["dns_kaydi"], raise_on_detection=True)

        # NEG_02: DNS Tünelleme istisnası
        s2 = scenarios["NEG_02"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(DNSTunnelingError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_dns_record(s2["dns_kaydi"], raise_on_detection=True)

        # NEG_03: DNS Amplification istisnası
        s3 = scenarios["NEG_03"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(DNSAmplificationError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_dns_record(s3["dns_kaydi"], raise_on_detection=True)

        # NEG_04: HTTP Request Smuggling istisnası
        s4 = scenarios["NEG_04"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(HTTPRequestSmugglingError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_http_record(s4["http_kaydi"], raise_on_detection=True)

    # Test 14: Negatif sınır senaryoları Grup 2 (NEG_05 - NEG_09)
    def test_14_negatif_sinir_senaryolari_grup_2(self) -> None:
        """NEG_05'ten NEG_09'a kadar olan anomali ve bozuk veri istisnalarını test eder."""
        # Senaryolar sözlükte indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_05: CRLF Başlık enjeksiyonu istisnası
        s5 = scenarios["NEG_05"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(HeaderInjectionError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_http_record(s5["http_kaydi"], raise_on_detection=True)

        # NEG_06: Path Traversal istisnası
        s6 = scenarios["NEG_06"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(PathTraversalError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_http_record(s6["http_kaydi"], raise_on_detection=True)

        # NEG_07: Zararlı tarayıcı User-Agent istisnası
        s7 = scenarios["NEG_07"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(MaliciousScannerError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_http_record(s7["http_kaydi"], raise_on_detection=True)

        # NEG_08: Bozuk veri nesnesi istisnası
        s8 = scenarios["NEG_08"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(MalformedRecordError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_dns_record(s8["dns_kaydi"], raise_on_detection=True)

        # NEG_09: Fast Flux mikro-TTL istisnası
        s9 = scenarios["NEG_09"]
        # Beklenen istisna bağlamı açılır
        with self.assertRaises(FastFluxAnomalyError):
            # Analiz hata fırlatma moduyla çalıştırılır
            self.detector.analyze_dns_record(s9["dns_kaydi"], raise_on_detection=True)


# Komut satırından doğrudan çalıştırıldığında testleri yürüten blok
if __name__ == "__main__":
    # unittest çalıştırıcısı çağrılır
    unittest.main()
