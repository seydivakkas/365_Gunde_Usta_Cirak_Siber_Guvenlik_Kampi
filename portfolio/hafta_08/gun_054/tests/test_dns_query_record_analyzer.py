# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G054: DNS Sorguları ve Kayıt Türleri Test Süiti.
Bu modül RFC 1034/1035 standartlarında DNS başlık ve soru ikili kodlamasını,
A, AAAA, CNAME, MX ve TXT kayıt türlerinin doğrulanmasını,
SPF/DMARC e-posta güvenlik denetimini, Sahipsiz CNAME (Subdomain Takeover) riskini,
ve DNS Tünelleme (Veri Sızıntısı) anomalilerini doğrular.
Her bir kod satırı didaktik açıklamalarla zenginleştirilmiştir.
"""

import unittest  # Birim test süitini tanımlamak ve yürütmek için standart kütüphane
from portfolio.hafta_08.gun_054.uygulama.dns_query_record_analyzer import (  # Uygulama modülünden sınıflar içe aktarılır
    DNSHeader,  # 12 baytlık ikili DNS başlık sınıfı
    DNSQuestion,  # DNS soru bölümü sınıfı
    DNSRecord,  # DNS kaynak kaydı (RR) sınıfı
    DNSSecurityAuditor,  # DNS güvenlik denetim motoru
    DNSType,  # Kayıt türü kod ve isim haritası
    DNSValidationError,  # DNS doğrulama hatası sınıfı
    decode_domain_name,  # Alan adı etiket çözümleme fonksiyonu
    encode_domain_name,  # Alan adı etiket kodlama fonksiyonu
)  # İçe aktarma tanımı tamamlanır


class TestDNSQueryRecordAnalyzer(unittest.TestCase):  # Test sınıfı tanımı
    """G054 DNS Sorguları ve Kayıt Türleri Test Senaryoları."""

    def setUp(self) -> None:  # Her test öncesi çalışan kurulum metodu
        """Test değişkenlerini ve güvenlik denetim motorunu hazırlar."""
        self.auditor = DNSSecurityAuditor()  # Güvenlik denetçisi nesnesi oluşturulur

    def test_dns_type_mapping_codes_and_names(self) -> None:  # Test 1: Tür kodları
        """Test 1: Standart DNS kayıt türlerinin sayısal kod ve isim eşleşmelerini doğrular."""
        self.assertEqual(DNSType.get_name(1), "A")  # Tip 1'in A kaydı olduğu test edilir
        self.assertEqual(DNSType.get_name(28), "AAAA")  # Tip 28'in AAAA kaydı olduğu doğrulanır
        self.assertEqual(DNSType.get_name(5), "CNAME")  # Tip 5'in CNAME olduğu doğrulanır
        self.assertEqual(DNSType.get_name(15), "MX")  # Tip 15'in MX olduğu doğrulanır
        self.assertEqual(DNSType.get_name(16), "TXT")  # Tip 16'nın TXT olduğu doğrulanır
        self.assertEqual(DNSType.get_code("A"), 1)  # A isminden kod 1 elde edildiği teyit edilir
        self.assertEqual(DNSType.get_code("MX"), 15)  # MX isminden kod 15 elde edildiği teyit edilir

    def test_domain_name_encoding_and_decoding(self) -> None:  # Test 2: Etiketleme
        """Test 2: RFC 1035 uzunluk önekli etiket kodlama ve çözümlemesini doğrular."""
        domain = "example.com"  # Test alan adı
        encoded = encode_domain_name(domain)  # Etiket kodlaması yapılır
        expected_bytes = b"\x07example\x03com\x00"  # Beklenen 7 + 'example' + 3 + 'com' + 0 baytları
        self.assertEqual(encoded, expected_bytes)  # Kodlamanın doğruluğu test edilir
        decoded_name, offset = decode_domain_name(encoded)  # Geri çözümleme yapılır
        self.assertEqual(decoded_name, "example.com")  # Çözülen adın orijinali ile aynı olduğu doğrulanır
        self.assertEqual(offset, len(encoded))  # İmlecin bayt sonuna ulaştığı teyit edilir

    def test_dns_header_binary_pack_and_unpack(self) -> None:  # Test 3: 12 bayt başlık
        """Test 3: RFC 1035 12 baytlık ikili başlığın paketlenmesi ve bayrak çıkarımını doğrular."""
        header = DNSHeader(tx_id=0x1234, qr=0, rd=1, qd_count=1)  # Standart sorgu başlığı oluşturulur
        raw_header = header.pack()  # İkili baytlara dönüştürülür
        self.assertEqual(len(raw_header), 12)  # DNS başlığının kesinlikle 12 bayt olduğu doğrulanır
        unpacked = DNSHeader.unpack(raw_header)  # Baytlardan geri nesne açılır
        self.assertEqual(unpacked.tx_id, 0x1234)  # Transaction ID korunmalıdır
        self.assertEqual(unpacked.qr, 0)  # QR biti sorgu (0) olmalıdır
        self.assertEqual(unpacked.rd, 1)  # RD biti yineleme isteniyor (1) olmalıdır
        self.assertEqual(unpacked.qd_count, 1)  # Soru sayısı 1 olmalıdır

    def test_dns_question_binary_pack(self) -> None:  # Test 4: Soru paketleme
        """Test 4: DNS Soru bölümünün ikili ağ formatına dönüştürüldüğünü doğrular."""
        question = DNSQuestion(name="api.example.com", qtype=DNSType.A, qclass=1)  # A sorgusu oluşturulur
        raw_q = question.pack()  # İkili paketleme yapılır
        self.assertTrue(raw_q.startswith(b"\x03api\x07example\x03com\x00"))  # Etiketli ad kontrol edilir
        self.assertTrue(raw_q.endswith(b"\x00\x01\x00\x01"))  # QTYPE=1 ve QCLASS=1 son eki kontrol edilir

    def test_dns_record_a_valid_creation(self) -> None:  # Test 5: A kaydı
        """Test 5: Geçerli bir IPv4 A kaydının doğrulandığını ve sözlük üretildiğini test eder."""
        record_a = DNSRecord(name="example.com", rtype="A", ttl=3600, rdata="93.184.216.34")  # A kaydı üret
        self.assertEqual(record_a.type_code, 1)  # Tip kodunun 1 olduğu doğrulanır
        self.assertEqual(record_a.rdata, "93.184.216.34")  # IP değerinin korunduğu teyit edilir
        data = record_a.to_dict()  # Sözlük temsili alınır
        self.assertEqual(data["tur"], "A")  # Türün A olduğu doğrulanır

    def test_dns_record_aaaa_valid_creation(self) -> None:  # Test 6: AAAA kaydı
        """Test 6: Geçerli bir IPv6 AAAA kaydının doğrulandığını test eder."""
        ipv6_str = "2606:2800:220:1:248:1893:25c8:1946"  # Geçerli IPv6 adresi
        record_aaaa = DNSRecord(name="example.com", rtype="AAAA", ttl=3600, rdata=ipv6_str)  # AAAA kaydı
        self.assertEqual(record_aaaa.type_code, 28)  # Tip kodunun 28 olduğu teyit edilir
        self.assertEqual(record_aaaa.rdata, ipv6_str)  # IPv6 verisi doğrulanır

    def test_dns_record_cname_and_mx_creation(self) -> None:  # Test 7: CNAME ve MX
        """Test 7: CNAME ve öncelik değerli MX kayıtlarının oluşturulmasını doğrular."""
        record_cname = DNSRecord(name="www.example.com", rtype="CNAME", ttl=1800, rdata="example.com")  # CNAME
        self.assertEqual(record_cname.type_code, 5)  # CNAME kodunun 5 olduğu teyit edilir
        record_mx = DNSRecord(  # Parametre / ifade: record_mx = DNSRecord(
            name="example.com", rtype="MX", ttl=3600, rdata="mail.example.com", preference=10  # Parametre / ifade: name="example.com", rtype="MX", ttl=3600, rdata="mail.example.com", preference=10
        )  # Öncelik 10 olan MX kaydı
        self.assertEqual(record_mx.type_code, 15)  # MX kodunun 15 olduğu doğrulanır
        self.assertEqual(record_mx.preference, 10)  # Öncelik değerinin 10 olduğu teyit edilir

    def test_dns_record_txt_creation(self) -> None:  # Test 8: TXT kayıtları
        """Test 8: SPF ve DMARC içeren TXT kayıtlarının doğru saklandığını doğrular."""
        spf_txt = "v=spf1 ip4:192.0.2.0/24 -all"  # SPF metni
        record_txt = DNSRecord(name="example.com", rtype="TXT", ttl=3600, rdata=spf_txt)  # TXT kaydı
        self.assertEqual(record_txt.type_code, 16)  # TXT kodunun 16 olduğu doğrulanır
        self.assertIn("v=spf1", record_txt.rdata)  # SPF önekinin varlığı teyit edilir

    def test_security_audit_spf_and_dmarc_hardened(self) -> None:  # Test 9: Sıkılaştırılmış e-posta
        """Test 9: Katı SPF (-all) ve DMARC (p=reject) kayıtlarının güvenli onaylandığını doğrular."""
        records = [  # Parametre / ifade: records = [
            DNSRecord("example.com", "TXT", 3600, "v=spf1 ip4:93.184.216.0/24 -all"),  # Katı SPF
            DNSRecord("_dmarc.example.com", "TXT", 3600, "v=DMARC1; p=reject; rua=mailto:rep@example.com"),  # Katı DMARC
        ]  # Güvenli kayıtlar
        audit = self.auditor.audit_email_security_txt(records)  # Denetle
        self.assertTrue(audit["spf_mevcut"])  # SPF varlığı doğrulanır
        self.assertTrue(audit["dmarc_mevcut"])  # DMARC varlığı doğrulanır
        self.assertEqual(len(audit["bulgular"]), 0)  # Hiçbir zafiyet bulgusu üretilmemelidir

    def test_security_audit_weak_or_missing_spf_and_dmarc(self) -> None:  # Test 10: Zayıf e-posta politikası
        """Test 10: Eksik SPF ve zayıf DMARC (p=none) durumlarının güvenlik uyarısı ürettiğini doğrular."""
        weak_records = [  # Parametre / ifade: weak_records = [
            DNSRecord("example.com", "TXT", 3600, "v=spf1 +all"),  # Herkese izin veren zayıf SPF
            DNSRecord("_dmarc.example.com", "TXT", 3600, "v=DMARC1; p=none;"),  # Yalnızca izleme modu DMARC
        ]  # Zayıf kayıtlar
        audit = self.auditor.audit_email_security_txt(weak_records)  # Denetle
        categories = {b["kategori"] for b in audit["bulgular"]}  # Bulunan kategoriler kümesi
        self.assertIn("WEAK_SPF_POLICY", categories)  # Zayıf SPF uyarısı doğrulanır
        self.assertIn("DMARC_MONITORING_ONLY", categories)  # İzleme modu uyarısı doğrulanır

    def test_security_audit_subdomain_takeover_detection(self) -> None:  # Test 11: Subdomain Takeover
        """Test 11: Sahipsiz üçüncü taraf S3 deposuna işaret eden CNAME kaydının yakalandığını doğrular."""
        dangling_cname = DNSRecord(  # Parametre / ifade: dangling_cname = DNSRecord(
            name="blog.example.com",  # Parametre / ifade: name="blog.example.com",
            rtype="CNAME",  # Parametre / ifade: rtype="CNAME",
            ttl=300,  # Parametre / ifade: ttl=300,
            rdata="abandoned-bucket.s3-website-us-east-1.amazonaws.com",  # Parametre / ifade: rdata="abandoned-bucket.s3-website-us-east-1.amazonaws.com",
        )  # Tehlikeli CNAME kaydı
        audit = self.auditor.audit_subdomain_takeover([dangling_cname])  # Denetle
        self.assertTrue(audit["risk_bulundu_mu"])  # Risk bayrağının aktifleştiği doğrulanır
        self.assertEqual(audit["bulgular"][0]["seviye"], "CRITICAL")  # Seviyenin CRITICAL olduğu doğrulanır
        self.assertEqual(audit["bulgular"][0]["kategori"], "SUBDOMAIN_TAKEOVER_RISK")  # Kategori teyit edilir

    def test_security_audit_dns_tunneling_detection(self) -> None:  # Test 12: DNS Tünelleme
        """Test 12: Yüksek entropili hex kodlu sorguların DNS Tünelleme olarak tespit edildiğini doğrular."""
        tunnel_query = "48656c6c6f576f726c64457866696c74726174696f6e.c2.attacker.com"  # Tünelleme sorgusu
        report_tunnel = self.auditor.audit_dns_tunneling(tunnel_query)  # Analiz et
        self.assertTrue(report_tunnel["tunelleme_suphesi"])  # Tünelleme şüphesinin doğrulandığı test edilir
        self.assertGreaterEqual(report_tunnel["shannon_entropisi"], 2.8)  # Yüksek entropi teyit edilir
        legit_query = "api.example.com"  # Standart meşru sorgu
        report_legit = self.auditor.audit_dns_tunneling(legit_query)  # Analiz et
        self.assertFalse(report_legit["tunelleme_suphesi"])  # Meşru sorgunun temiz çıktığı doğrulanır

    def test_negative_label_length_and_total_domain_overflow(self) -> None:  # Test 13: Etiket ve ad sınırı
        """Test 13: Negatif kontrol: 63 karakter üstü etiket ve 253 karakter üstü alan adının reddedildiğini test eder."""
        long_label_domain = "a" * 64 + ".com"  # 64 karakterlik etiket (RFC 1035 sınırı 63)
        with self.assertRaises(DNSValidationError):  # Hata fırlatılmalıdır
            encode_domain_name(long_label_domain)  # Kodlama denenir
        total_overflow_domain = ".".join(["a" * 60 for _ in range(5)])  # 300+ karakterlik toplam ad
        with self.assertRaises(DNSValidationError):  # Hata fırlatılmalıdır
            encode_domain_name(total_overflow_domain)  # Kodlama denenir

    def test_negative_malformed_ips_negative_ttl_and_empty_domain(self) -> None:  # Test 14: Format hataları
        """Test 14: Negatif kontrol: Hatalı IP adresleri, negatif TTL ve boş adın reddedildiğini doğrular."""
        with self.assertRaises(DNSValidationError):  # Hatalı IPv4 denemesi
            DNSRecord(name="example.com", rtype="A", ttl=3600, rdata="999.1.2.3")  # Hata beklenir
        with self.assertRaises(DNSValidationError):  # Hatalı IPv6 denemesi
            DNSRecord(name="example.com", rtype="AAAA", ttl=3600, rdata="invalid_ipv6_str")  # Hata beklenir
        with self.assertRaises(DNSValidationError):  # Negatif TTL denemesi
            DNSRecord(name="example.com", rtype="A", ttl=-10, rdata="1.1.1.1")  # Hata beklenir
        with self.assertRaises(DNSValidationError):  # Boş alan adı denemesi
            DNSRecord(name="", rtype="A", ttl=300, rdata="1.1.1.1")  # Hata beklenir


if __name__ == "__main__":  # Doğrudan yürütme bloğu
    unittest.main()  # Testleri çalıştır
