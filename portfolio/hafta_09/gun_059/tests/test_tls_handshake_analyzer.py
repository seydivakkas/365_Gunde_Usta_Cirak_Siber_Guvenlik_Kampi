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
G059: HTTPS ve TLS El Sıkışması Kapsamlı Test Paketi (14 Test).

Bu test paketi; TLS Record Layer başlık ayrıştırmasını, SNI etki alanı doğrulamasını,
CRIME sıkıştırma korumasını, RFC 8446 sürüm düşürme (downgrade) saldırı tespitini,
şifreleme paketi güvenlik analizini ve TLS 1.2 / TLS 1.3 karşılaştırmalarını doğrular.
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
from portfolio.hafta_09.gun_059.uygulama.tls_handshake_analyzer import (
    parse_record_layer_header,
    validate_sni_hostname,
    check_compression_security,
    verify_downgrade_protection,
    assess_cipher_suite_security,
    compare_tls12_and_tls13,
    build_raw_client_hello_record,
    analyze_tls_handshake_session,
    TLSValidationError,
    TLSMalformedRecordError,
    TLSDowngradeDetectedError,
    DOWNGRADE_SENTINEL_TLS12
)


class TestTLSHandshakeAnalyzer(unittest.TestCase):
    """TLS El Sıkışması ve Güvenlik Motoru Birim Testleri."""

    @classmethod
    def setUpClass(cls):
        """Test sınıfı başlatılırken örnek veri dosyalarını yükler."""
        # Geçerli test dosyasının bulunduğu dizini tespit et
        current_dir = Path(__file__).resolve().parent
        # Örnek veri dizinine erişim yolunu oluştur
        ornek_veri_dir = current_dir.parent / "ornek_veri"
        
        # Pozitif el sıkışma senaryolarını oku
        with open(ornek_veri_dir / "sample_tls_handshake.json", "r", encoding="utf-8") as f:
            # JSON verisini sınıf niteliğine yükle
            cls.sample_data = json.load(f)
            
        # Negatif test senaryolarını oku
        with open(ornek_veri_dir / "invalid_tls_inputs.json", "r", encoding="utf-8") as f:
            # Negatif JSON verisini sınıf niteliğine yükle
            cls.invalid_data = json.load(f)

    def test_01_valid_record_layer_header_parsing(self):
        """Pozitif Test 1: Geçerli TLS Record Layer başlığının 5 bayttan başarıyla ayrıştırılması."""
        # 22 (Handshake), 0x0303 (TLS 1.2/1.3 Legacy), Uzunluk 4 bayt olan geçerli 9 baytlık paket oluştur
        raw_record = struct.pack("!BHH", 22, 0x0303, 4) + b"\x01\x00\x00\x00"
        # Başlığı ayrıştır
        header = parse_record_layer_header(raw_record)
        # Content Type değerinin 22 olduğunu doğrula
        self.assertEqual(header.content_type, 22)
        # Content Type adının "Handshake" olduğunu doğrula
        self.assertEqual(header.content_type_name, "Handshake")
        # Protokol sürümünün 0x0303 olduğunu doğrula
        self.assertEqual(header.version_raw, 0x0303)
        # Sürüm adının "TLS 1.2" olduğunu doğrula
        self.assertEqual(header.version_name, "TLS 1.2")
        # Yük uzunluğunun 4 bayt olduğunu doğrula
        self.assertEqual(header.payload_length, 4)

    def test_02_negative_truncated_record_header(self):
        """Negatif Test 2: 5 bayttan daha kısa başlıkta TLSMalformedRecordError fırlatılması."""
        # 3 baytlık kesik veri hazırla
        truncated_header = b"\x16\x03\x03"
        # TLSMalformedRecordError beklenir
        with self.assertRaises(TLSMalformedRecordError) as ctx:
            # Başlık ayrıştırmayı dene
            parse_record_layer_header(truncated_header)
        # Hata mesajında en az 5 bayt kuralının geçtiğini doğrula
        self.assertIn("en az 5 bayt", str(ctx.exception))

    def test_03_negative_invalid_content_type(self):
        """Negatif Test 3: Standart dışı Content Type (ör. 99) durumunda TLSValidationError fırlatılması."""
        # 99 numaralı tanımsız içerik tipi içeren 5 baytlık başlık hazırla
        invalid_type_raw = struct.pack("!BHH", 99, 0x0303, 0)
        # TLSValidationError beklenir
        with self.assertRaises(TLSValidationError) as ctx:
            # Başlık ayrıştırmayı dene
            parse_record_layer_header(invalid_type_raw)
        # Hata mesajında bilinmeyen tip ifadesinin geçtiğini doğrula
        self.assertIn("Bilinmeyen TLS Content-Type", str(ctx.exception))

    def test_04_negative_obsolete_ssl_version(self):
        """Negatif Test 4: Güvensiz SSL 3.0 (0x0300) sürümünün reddedilmesi."""
        # SSL 3.0 sürüm koduyla (0x0300) kayıt başlığı oluştur
        ssl3_record = struct.pack("!BHH", 22, 0x0300, 0)
        # TLSValidationError beklenir
        with self.assertRaises(TLSValidationError) as ctx:
            # Başlık ayrıştırmayı dene
            parse_record_layer_header(ssl3_record)
        # Hata mesajında POODLE veya güvensiz sürüm ifadesini doğrula
        self.assertIn("guvensiz SSL/TLS", str(ctx.exception))

    def test_05_negative_record_length_overflow(self):
        """Negatif Test 5: 16384 bayt sınırını aşan yük uzunluğunda TLSValidationError fırlatılması."""
        # 20000 baytlık aşırı uzunluk bildiren başlık oluştur
        overflow_record = struct.pack("!BHH", 22, 0x0303, 20000)
        # TLSValidationError beklenir
        with self.assertRaises(TLSValidationError) as ctx:
            # Başlık ayrıştırmayı dene
            parse_record_layer_header(overflow_record)
        # Hata mesajında maksimum sınır uyarısını doğrula
        self.assertIn("maksimum siniri", str(ctx.exception))

    def test_06_negative_payload_length_mismatch(self):
        """Negatif Test 6: Bildirilen uzunluktan daha kısa veri akışında TLSMalformedRecordError."""
        # Başlıkta 50 bayt yük bildir ama sadece 5 bayt yük gönder
        mismatched_record = struct.pack("!BHH", 22, 0x0303, 50) + b"12345"
        # TLSMalformedRecordError beklenir
        with self.assertRaises(TLSMalformedRecordError) as ctx:
            # Başlık ayrıştırmayı dene
            parse_record_layer_header(mismatched_record)
        # Hata mesajında veri akışının kesildiğini doğrula
        self.assertIn("uyusmuyor", str(ctx.exception))

    def test_07_valid_sni_hostname_validation(self):
        """Pozitif Test 7: RFC 6066 uyumlu geçerli alan adlarının onaylanması."""
        # Geçerli alan adları listesi
        valid_hosts = ["banka.com", "sube1.guvenli-servis.internal", "api-v2.odeme.gov.tr"]
        # Her bir geçerli alan adını döngüde test et
        for host in valid_hosts:
            # Doğrulama sonucunun True olduğunu doğrula
            self.assertTrue(validate_sni_hostname(host))

    def test_08_negative_invalid_sni_hostname(self):
        """Negatif Test 8: Null-byte, aşırı uzun veya geçersiz karakterli SNI alan adlarının reddi."""
        # Boş SNI için hata kontrolü
        with self.assertRaises(TLSValidationError):
            validate_sni_hostname("")
        # Null-byte enjeksiyonu için hata kontrolü
        with self.assertRaises(TLSValidationError) as ctx:
            validate_sni_hostname("kotu-sunucu\x00.internal")
        self.assertIn("null-byte", str(ctx.exception))
        # 256 karakterlik aşırı uzun domain kontrolü
        long_host = "a" * 250 + ".com"
        with self.assertRaises(TLSValidationError):
            validate_sni_hostname(long_host)

    def test_09_valid_compression_methods_security(self):
        """Pozitif Test 9: Yalnızca Null (0x00) sıkıştırmanın güvenli kabul edilmesi."""
        # Yalnızca Null sıkıştırma içeren liste
        methods = [0]
        # Hata fırlatılmadan başarıyla tamamlandığını doğrula
        try:
            check_compression_security(methods)
        except TLSValidationError:
            self.fail("Gecerli null sikistirma icin hata firlatilmamalidir.")

    def test_10_negative_insecure_compression_crime_detection(self):
        """Negatif Test 10: DEFLATE (0x01) sıkıştırma aktif edildiğinde CRIME zaafiyeti tespiti."""
        # Null ve DEFLATE içeren güvensiz liste
        methods = [0, 1]
        # TLSValidationError fırlatıldığını doğrula
        with self.assertRaises(TLSValidationError) as ctx:
            check_compression_security(methods)
        # Hata açıklamasında CRIME CVE-2012-4929 geçtiğini doğrula
        self.assertIn("CRIME (CVE-2012-4929)", str(ctx.exception))

    def test_11_valid_downgrade_protection(self):
        """Pozitif Test 11: Normal TLS 1.3 el sıkışmasında sürüm düşürme alarmı verilmemesi."""
        # Temiz rastgele baytlar üret
        clean_random = b"\x01\x02\x03\x04" * 8
        # İstemci ve sunucu ikisi de TLS 1.3 uzlaştığında
        is_safe = verify_downgrade_protection("TLS 1.3", clean_random, "TLS 1.3")
        # Sonucun güvenli olduğunu doğrula
        self.assertTrue(is_safe)

    def test_12_negative_downgrade_mitm_detection(self):
        """Negatif Test 12: TLS 1.3 istemciye TLS 1.2 dayatıldığında sentinel ile MitM tespiti."""
        # Son 8 baytında DOWNGRD\x01 sentineli taşıyan server random oluştur
        mitm_server_random = (b"\xaa" * 24) + DOWNGRADE_SENTINEL_TLS12
        # TLSDowngradeDetectedError fırlatılmalı
        with self.assertRaises(TLSDowngradeDetectedError) as ctx:
            verify_downgrade_protection("TLS 1.3", mitm_server_random, "TLS 1.2")
        # Hata mesajında sürüm düşürme ifadesini doğrula
        self.assertIn("Downgrade Attack", str(ctx.exception))

    def test_13_cipher_suite_security_assessment(self):
        """Pozitif Test 13: Şifreleme paketi güvenlik ve PFS değerlendirmesi."""
        # Güvenli TLS 1.3 paketi (AES-GCM, PFS)
        sec_eval = assess_cipher_suite_security("TLS_AES_256_GCM_SHA384")
        self.assertTrue(sec_eval["is_secure"])
        self.assertTrue(sec_eval["pfs_supported"])
        self.assertEqual(len(sec_eval["findings"]), 0)

        # Güvensiz statik RSA ve CBC paketi (PFS yok, Lucky13 riski)
        insec_eval = assess_cipher_suite_security("TLS_RSA_WITH_AES_128_CBC_SHA")
        self.assertFalse(insec_eval["is_secure"])
        self.assertFalse(insec_eval["pfs_supported"])
        self.assertGreater(len(insec_eval["findings"]), 0)

    def test_14_end_to_end_synthetic_client_hello_and_comparison(self):
        """Pozitif Test 14: İkili ClientHello sentezleme, ayrıştırma ve TLS 1.2 vs 1.3 karşılaştırması."""
        # Sentetik TLS 1.3 ClientHello paketi üret
        raw_packet = build_raw_client_hello_record(
            hostname="odeme.banka.internal",
            use_tls13=True,
            include_insecure_ciphers=False,
            enable_compression=False
        )
        # Paketin 5 bayttan büyük olduğunu doğrula
        self.assertGreater(len(raw_packet), 5)
        # Başlığı ayrıştır ve doğrula
        header = parse_record_layer_header(raw_packet)
        self.assertEqual(header.content_type, 22)
        self.assertEqual(header.version_name, "TLS 1.2")

        # Protokol karşılaştırma matrisini sorgula
        comparison = compare_tls12_and_tls13()
        # 1-RTT gecikme bilgisinin varlığını doğrula
        self.assertIn("1-RTT", comparison["el_sikisma_gecikmesi"]["tls_1_3"])
        # 2-RTT gecikme bilgisinin varlığını doğrula
        self.assertIn("2-RTT", comparison["el_sikisma_gecikmesi"]["tls_1_2"])


if __name__ == "__main__":
    # Testleri detaylı çıktıyla çalıştır
    unittest.main()
