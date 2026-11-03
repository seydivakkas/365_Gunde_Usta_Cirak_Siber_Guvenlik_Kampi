# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G068: Hafta 10 Gün 68 - Ağ Günlükleri ve Kişisel Veri Arındırma Birim Test Paketi.
Bu test paketi, ağ telemetrisi içerisindeki kişisel verilerin (IP, MAC, E-posta, TCKN,
Kredi Kartı, Yetki Başlıkları) maskeleme, tuzlu özetleme ve KVKK/GDPR uyum kurallarını doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# JSON veri setlerini yüklemek için json kütüphanesi içe aktarılır
import json
# Dosya yollarını işletim sistemi bağımsız yönetmek için Path sınıfı içe aktarılır
from pathlib import Path

# Test edilecek arındırma motoru ve ilişkili istisnalar içe aktarılır
from portfolio.hafta_10.gun_068.uygulama.network_log_pii_sanitizer import (
    # Ana arındırma motoru sınıfı
    NetworkLogPIISanitizer,
    # Temel PII arındırma hata sınıfı
    PIISanitizationError,
    # Boş günlük akışı hatası
    EmptyLogStreamError,
    # Geçersiz günlük veri biçimi hatası
    InvalidLogFormatError,
    # Geçersiz IP adresi formatı hatası
    InvalidIPAddressFormatError,
    # Yetersiz tuzlama anahtarı hatası
    InvalidSaltKeyError,
    # Açıkta kalan PII tespit hatası
    UnmaskedPIIDetectedError,
    # Bozuk kayıt verisi hatası
    MalformedRecordDataError,
    # Güvenlik ve gizlilik politikası ihlali hatası
    PolicyViolationError,
    # Veri saklama süresi aşımı hatası
    DataRetentionPolicyError
)


# Ağ günlükleri PII arındırma test sınıfı
class TestNetworkLogPIISanitizer(unittest.TestCase):
    """G068 PII arındırma motorunun tüm fonksiyonlarını ve sınır senaryolarını test eder."""

    # Her test öncesi ortak kaynakları hazırlayan metot
    def setUp(self) -> None:
        """Her testten önce analiz motorunu ve test veri setlerini hazır hale getirir."""
        # Yeni bir arındırma motoru başlatılır
        self.sanitizer = NetworkLogPIISanitizer(varsayilan_tuz="G068_GIZLI_TEST_TUZU_2026")
        # Örnek veri dizini belirlenir
        self.data_dir = Path(__file__).resolve().parent.parent / "ornek_veri"
        # Örnek ham günlükler dosya yolu
        self.sample_logs_file = self.data_dir / "sample_raw_network_logs.json"
        # Negatif sınır testleri dosya yolu
        self.invalid_inputs_file = self.data_dir / "invalid_sanitization_inputs.json"

        # Örnek günlükler dosyası okunur
        with open(self.sample_logs_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe çözümlenir
            self.sample_data = json.load(f)

        # Negatif girdi dosyası okunur
        with open(self.invalid_inputs_file, "r", encoding="utf-8") as f:
            # JSON sözlüğe çözümlenir
            self.invalid_data = json.load(f)

    # Test 01: Örnek günlük veri setinin yapısal doğrulaması
    def test_01_ornek_gunluk_veri_seti_yukleme_ve_dogrulama(self) -> None:
        """Ham günlük veri setinin 5 farklı ağ günlüğü içerdiğini doğrular."""
        # Günlük listesinin varlığı kontrol edilir
        self.assertIn("gunluk_kayitlari", self.sample_data)
        # Toplam 5 adet kayıt olduğu doğrulanır
        self.assertEqual(len(self.sample_data["gunluk_kayitlari"]), 5)

    # Test 02: IP adreslerinin alt ağ maskeleme (/24) ile korunması
    def test_02_ip_adresi_alt_ag_maskeleme(self) -> None:
        """IPv4 adreslerinin son oktetinin sıfırlanıp /24 olarak maskelendiğini doğrular."""
        # Test IP adresi
        raw_ip = "192.168.1.145"
        # Maskeleme metodu çalıştırılır
        masked_ip = self.sanitizer.mask_ip_address(raw_ip, method="subnet")
        # Beklenen son oktet sıfırlama kontrolü yapılır
        self.assertEqual(masked_ip, "192.168.1.0/24")

    # Test 03: IP adreslerinin tuzlu sözde-anonimleştirilmesi (Pseudonymization)
    def test_03_ip_adresi_tuzlu_sozde_anonimlestirme(self) -> None:
        """HMAC-SHA256 ile IP adreslerinin deterministik ve geri döndürülemez hash'lendiğini doğrular."""
        # Test IP adresi
        raw_ip = "10.0.5.20"
        # İlk hashleme
        pseudo_1 = self.sanitizer.mask_ip_address(raw_ip, method="pseudonymize")
        # İkinci hashleme (aynı tuz ile)
        pseudo_2 = self.sanitizer.mask_ip_address(raw_ip, method="pseudonymize")
        # Başlığın IP_PSEUDO_ ile başladığı kontrol edilir
        self.assertTrue(pseudo_1.startswith("IP_PSEUDO_"))
        # Aynı tuzla aynı girdi için sonucun deterministik olduğu doğrulanır
        self.assertEqual(pseudo_1, pseudo_2)

    # Test 04: MAC adreslerinin üretici OUI kodunun korunarak maskelenmesi
    def test_04_mac_adresi_oui_korumali_maskeleme(self) -> None:
        """MAC adresinin ilk 3 oktetinin korunup son 3 oktetinin XX ile gizlendiğini test eder."""
        # Test MAC adresi
        raw_mac = "00:1A:2B:3C:4D:5E"
        # Maskeleme metodu çağrılır
        masked_mac = self.sanitizer.mask_mac_address(raw_mac, preserve_oui=True)
        # Üretici kısmının korunduğu ve sonunun XX olduğu teyit edilir
        self.assertEqual(masked_mac, "00:1A:2B:XX:XX:XX")

    # Test 05: E-posta adresinin kullanıcı adı maskelemesi
    def test_05_eposta_adresi_maskeleme(self) -> None:
        """E-posta adresinin ilk ve son harfi haricinde yıldızlandığını doğrular."""
        # Test e-posta adresi
        email = "ahmet.yilmaz@kurum.com.tr"
        # Maskeleme çalıştırılır
        masked = self.sanitizer.mask_email(email)
        # Doğru maskelendiği teyit edilir
        self.assertEqual(masked, "a***z@kurum.com.tr")

    # Test 06: Kredi kartı numarasının PCI-DSS standartlarında maskelenmesi
    def test_06_kredi_karti_pci_dss_maskeleme(self) -> None:
        """Kredi kartının ilk 4 ve son 4 hanesi korunup ortasının yıldızlandığını test eder."""
        # Test kart numarası
        card = "4543123456789012"
        # Maskeleme uygulanır
        masked = self.sanitizer.mask_credit_card(card)
        # Maske formatı doğrulanır
        self.assertEqual(masked, "4543 **** **** 9012")

    # Test 07: TCKN kimlik numarasının maskelenmesi
    def test_07_tckn_kimlik_numarasi_maskeleme(self) -> None:
        """TC Kimlik numarasının ilk 2 ve son 2 hanesinin korunup aranın yıldızlandığını test eder."""
        # Test TCKN
        tckn = "12345678901"
        # Maskeleme çağrılır
        masked = self.sanitizer.mask_tckn(tckn)
        # 11 haneli maskeli format kontrol edilir
        self.assertEqual(masked, "12*******01")

    # Test 08: HTTP hassas başlıklarının (Authorization, Cookie) arındırılması
    def test_08_http_baslik_arindirma(self) -> None:
        """Authorization ve Cookie başlıklarının temizlenip Host başlığının korunduğunu test eder."""
        # Test başlıkları sözlüğü
        headers = {
            "Host": "api.kurum.local",
            "Authorization": "Bearer gizli_jwt_token_123",
            "Cookie": "session=gizli_oturum_id_456"
        }
        # Arındırma çalıştırılır
        clean_headers = self.sanitizer.sanitize_http_headers(headers)
        # Host başlığının korunduğu doğrulanır
        self.assertEqual(clean_headers["Host"], "api.kurum.local")
        # Authorization içeriğinin maskelendiği doğrulanır
        self.assertEqual(clean_headers["Authorization"], "Bearer [REDACTED_TOKEN]")
        # Cookie içeriğinin maskelendiği doğrulanır
        self.assertEqual(clean_headers["Cookie"], "[REDACTED_SESSION_COOKIE]")

    # Test 09: URI sorgu parametrelerindeki kişisel verilerin arındırılması
    def test_09_uri_sorgu_parametresi_arindirma(self) -> None:
        """URI query içerisindeki ?email= ve &tckn= parametrelerinin maskelendiğini doğrular."""
        # Test URI adresi
        raw_uri = "/api/v1/profile?email=ahmet.yilmaz@kurum.com.tr&tckn=12345678901"
        # Arındırma uygulanır
        clean_uri = self.sanitizer.sanitize_uri_query(raw_uri)
        # Ham e-postanın URI içinde kalmadığı doğrulanır
        self.assertNotIn("ahmet.yilmaz@kurum.com.tr", clean_uri)
        # Ham TCKN'nin URI içinde kalmadığı doğrulanır
        self.assertNotIn("12345678901", clean_uri)
        # Maskelenmiş e-postanın varlığı (URL-encoded karakterlerle) kontrol edilir
        self.assertIn("a%2A%2A%2Az%40kurum.com.tr", clean_uri)

    # Test 10: Serbest metin gövdesi ve Syslog mesajlarının taranıp arındırılması
    def test_10_serbest_metin_ve_syslog_arindirma(self) -> None:
        """Syslog veya metin gövdesinde geçen e-posta ve telefonun temizlendiğini test eder."""
        # Ham metin
        raw_text = "Giriş başarılı: email=zeynep.kaya@sirket.com tel=+905551234567"
        # Temizleme metodu çağrılır
        clean_text, stats = self.sanitizer.sanitize_free_text(raw_text)
        # Ham e-postanın bulunmadığı teyit edilir
        self.assertNotIn("zeynep.kaya@sirket.com", clean_text)
        # Ham telefonun bulunmadığı teyit edilir
        self.assertNotIn("+905551234567", clean_text)
        # İstatistiklerde 1 e-posta ve 1 telefon yakalandığı kontrol edilir
        self.assertEqual(stats["eposta"], 1)
        self.assertEqual(stats["telefon"], 1)

    # Test 11: Tekil günlük kaydının uçtan uca arındırılma bütünlüğü
    def test_11_tekil_kayit_arindirma_butunlugu(self) -> None:
        """Tüm PII alanlarını içeren karmaşık bir web kaydının tamamen arındırıldığını test eder."""
        # İlk örnek kayıt (LOG-WEB-01) seçilir
        raw_record = self.sample_data["gunluk_kayitlari"][0]
        # Arındırma yürütülür
        clean_rec = self.sanitizer.sanitize_log_record(raw_record)
        # İstemci IP'sinin maskelendiği doğrulanır
        self.assertEqual(clean_rec["istemci_ip"], "192.168.1.0/24")
        # İstemci MAC'inin OUI korumalı maskelendiği doğrulanır
        self.assertEqual(clean_rec["istemci_mac"], "00:1A:2B:XX:XX:XX")
        # Başlıkların arındırıldığı kontrol edilir
        self.assertEqual(clean_rec["basliklar"]["Authorization"], "Bearer [REDACTED_TOKEN]")

    # Test 12: Toplu günlük veri seti arındırma ve uyum raporu üretimi
    def test_12_toplu_gunluk_arindirma_ve_uyum_raporu(self) -> None:
        """5 kaydın tamamının topluca arındırıldığını ve KVKK raporunun üretildiğini teyit eder."""
        # Toplu arındırma metodu çağrılır
        batch_res = self.sanitizer.sanitize_log_batch(self.sample_data)
        # Toplam işlenen kayıt sayısı 5 olmalıdır
        self.assertEqual(batch_res["toplam_islenen_kayit"], 5)
        # Maskelenen IP sayısının 5 olduğu doğrulanır
        self.assertEqual(batch_res["maskelenen_ip_sayisi"], 5)
        # Uyum durumunun TAM_UYUMLU çıktığı teyit edilir
        self.assertEqual(batch_res["kvkk_gdpr_uyum_durumu"], "TAM_UYUMLU")

    # Test 13: Negatif sınır senaryoları Grup 1 (NEG_01 - NEG_04)
    def test_13_negatif_sinir_senaryolari_grup_1(self) -> None:
        """NEG_01'den NEG_04'e kadar olan boş akış, biçim, IP ve tuz hatalarını doğrular."""
        # Senaryolar indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_01: Boş günlük akışı
        s1 = scenarios["NEG_01"]
        # İstisna denetimi
        with self.assertRaises(EmptyLogStreamError):
            # Analiz çağrılır
            self.sanitizer.sanitize_log_batch({"gunluk_kayitlari": s1["log_verisi"]})

        # NEG_02: Geçersiz format
        s2 = scenarios["NEG_02"]
        # İstisna denetimi
        with self.assertRaises(InvalidLogFormatError):
            # Analiz çağrılır
            self.sanitizer.sanitize_log_batch(s2["log_verisi"])

        # NEG_03: Geçersiz IP adresi
        s3 = scenarios["NEG_03"]
        # İstisna denetimi
        with self.assertRaises(InvalidIPAddressFormatError):
            # Tekil kayıt arındırma çağrılır
            self.sanitizer.sanitize_log_record(s3["log_verisi"])

        # NEG_04: Yetersiz tuz anahtarı
        s4 = scenarios["NEG_04"]
        # İstisna denetimi
        with self.assertRaises(InvalidSaltKeyError):
            # Kısa tuz ile arındırma çağrılır
            self.sanitizer.sanitize_log_record(s4["log_verisi"], salt=s4["tuz_anahtari"])

    # Test 14: Negatif sınır senaryoları Grup 2 (NEG_05 - NEG_09)
    def test_14_negatif_sinir_senaryolari_grup_2(self) -> None:
        """NEG_05'ten NEG_09'a kadar olan açık PII, bozuk kayıt, politika ve saklama süresi testlerini doğrular."""
        # Senaryolar indekslenir
        scenarios = {s["test_kodu"]: s for s in self.invalid_data["test_senaryolari"]}

        # NEG_05: Açık PII kalıntı tespiti
        s5 = scenarios["NEG_05"]
        # İstisna denetimi
        with self.assertRaises(UnmaskedPIIDetectedError):
            # PII kontrolü çağrılır
            self.sanitizer.assert_no_unmasked_pii(s5["denetlenecek_metin"])

        # NEG_06: Bozuk kayıt verisi (eksik kayit_id)
        s6 = scenarios["NEG_06"]
        # İstisna denetimi
        with self.assertRaises(MalformedRecordDataError):
            # Kayıt arındırma çağrılır
            self.sanitizer.sanitize_log_record(s6["log_verisi"])

        # NEG_07: Açık kredi kartı loglama politika ihlali
        s7 = scenarios["NEG_07"]
        # İstisna denetimi
        with self.assertRaises(PolicyViolationError):
            # PII kontrolü çağrılır
            self.sanitizer.assert_no_unmasked_pii(s7["ham_metin"])

        # NEG_08: Yasal veri saklama süresi aşımı
        s8 = scenarios["NEG_08"]
        # İstisna denetimi
        with self.assertRaises(DataRetentionPolicyError):
            # Kayıt arındırma çağrılır
            self.sanitizer.sanitize_log_record(s8["log_verisi"])

        # NEG_09: Bozuk MAC adresi biçimi
        s9 = scenarios["NEG_09"]
        # İstisna denetimi
        with self.assertRaises(InvalidLogFormatError):
            # Kayıt arındırma çağrılır
            self.sanitizer.sanitize_log_record(s9["log_verisi"])


# Komut satırından çalıştırıldığında testleri yürüten blok
if __name__ == "__main__":
    # unittest çağrılır
    unittest.main()
