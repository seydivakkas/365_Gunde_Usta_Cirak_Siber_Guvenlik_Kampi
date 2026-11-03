# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G052: UDP ve Kullanım Alanları Test Süiti.  # G052: UDP ve Kullanım Alanları Test Süiti.
Bu test modülü RFC 768 ikili başlık biçimi, sahte başlık sağlama toplamı hesaplama,  # Bu test modülü RFC 768 ikili başlık biçimi, sahte başlık sağlama toplamı hesaplama,
DNS/NTP protokol sınıflandırma, Amplifikasyon / Yansıtma DDoS tespiti,  # DNS/NTP protokol sınıflandırma, Amplifikasyon / Yansıtma DDoS tespiti,
UDP Flood ve Port Sweep anomalileri ile negatif sınır denetimlerini doğrular.  # UDP Flood ve Port Sweep anomalileri ile negatif sınır denetimlerini doğrular.
Her bir kod satırı didaktik açıklamalarla zenginleştirilmiştir.  # Her bir kod satırı didaktik açıklamalarla zenginleştirilmiştir.
"""

import struct  # İkili bayt dizilerini doğrulamak için struct kütüphanesi içe aktarılır
import unittest  # Birim test süitini çalıştırmak ve iddiaları test etmek için unittest modülü
from portfolio.hafta_08.gun_052.uygulama.udp_protocol_analyzer import (  # Uygulama modülünden sınıflar içe aktarılır
    UDPChecksumMismatchError,  # Sağlama toplamı uyumsuzluğu hata sınıfı
    UDPDatagram,  # Tam UDP datagram veri yapısı ve doğrulama sınıfı
    UDPHeader,  # RFC 768 8-baytlık UDP başlık sınıfı
    UDPProtocolAnalyzer,  # Trafik analizörü ve anomali tespit motoru
    UDPProtocolError,  # Temel UDP hata sınıfı
    UDPValidationError,  # Doğrulama hatası sınıfı
    validate_ipv4_address,  # IPv4 doğrulama yardımcısı fonksiyonu
)  # İçe aktarma tanımı tamamlanır


class TestUDPProtocolAnalyzer(unittest.TestCase):  # Nesne yönelimli veri modeli ve işlev sınıfı tanımı
    """G052 UDP Protokolü ve Kullanım Alanları Test Senaryoları."""

    def setUp(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Her testten önce temiz analizör nesnesini ve temel test değişkenlerini hazırlar."""
        self.analyzer = UDPProtocolAnalyzer()  # Analizör motoru örneği başlatılır
        self.src_ip = "192.168.1.100"  # Varsayılan test kaynak IP adresi
        self.dst_ip = "8.8.8.8"  # Varsayılan test hedef IP adresi (DNS Sunucusu)

    def test_udp_header_binary_pack_and_unpack(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 1: RFC 768 8 baytlık başlığın ikili paketlenmesi ve geri açılmasını doğrular."""
        header = UDPHeader(src_port=5353, dst_port=53, length=28, checksum=0x1234)  # Test başlığı oluşturulur
        raw_bytes = header.pack()  # Başlık ikili (binary) bayt dizisine dönüştürülür
        self.assertEqual(len(raw_bytes), 8)  # UDP başlığının kesinlikle 8 bayt olduğu doğrulanır
        unpacked = UDPHeader.unpack(raw_bytes)  # İkili baytlardan başlık nesnesi geri açılır
        self.assertEqual(unpacked.src_port, 5353)  # Kaynak portun doğru geri açıldığı doğrulanır
        self.assertEqual(unpacked.dst_port, 53)  # Hedef portun doğru geri açıldığı doğrulanır
        self.assertEqual(unpacked.length, 28)  # Uzunluk bilgisinin korunduğu doğrulanır
        self.assertEqual(unpacked.checksum, 0x1234)  # Checksum bilgisinin korunduğu doğrulanır

    def test_udp_checksum_calculation_with_pseudo_header(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 2: IPv4 Sahte Başlığı (Pseudo-Header) ile sağlama toplamı hesaplamasını doğrular."""
        payload = b"TEST_PAYLOAD"  # 12 baytlık test yükü
        checksum = UDPHeader.calculate_checksum(self.src_ip, self.dst_ip, 5000, 8080, payload)  # Checksum hesaplanır
        self.assertIsInstance(checksum, int)  # Checksum'ın tamsayı olduğu doğrulanır
        self.assertGreater(checksum, 0)  # Checksum'ın sıfırdan büyük olduğu doğrulanır
        self.assertLessEqual(checksum, 0xFFFF)  # Checksum'ın 16-bit sınırında (<= 65535) olduğu doğrulanır

    def test_udp_checksum_verification_valid_and_corrupt(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 3: Bozulmamış datagramda checksum onayını, değiştirilmiş veride ise hata tespitini doğrular."""
        payload = b"GuvenliVeri123"  # Orijinal veri yükü
        datagram = UDPDatagram.create(self.src_ip, self.dst_ip, 4000, 5000, payload, compute_checksum=True)  # Datagram üret
        self.assertTrue(datagram.verify_checksum())  # Değiştirilmemiş paketin sağlama toplamının geçerli olduğu test edilir
        tampered_header = UDPHeader(  # tampered_header = UDPHeader(
            src_port=datagram.header.src_port,  # src_port=datagram.header.src_port,
            dst_port=datagram.header.dst_port,  # dst_port=datagram.header.dst_port,
            length=datagram.header.length,  # length=datagram.header.length,
            checksum=datagram.header.checksum,  # checksum=datagram.header.checksum,
        )  # Orijinal başlık korunur
        tampered_datagram = UDPDatagram(  # tampered_datagram = UDPDatagram(
            self.src_ip, self.dst_ip, tampered_header, payload=b"BozukVeri12345"  # self.src_ip, self.dst_ip, tampered_header, payload=b"BozukVeri12345"
        )  # Yük aynı boyutta fakat içeriği değiştirilerek checksum uyuşmazlığı oluşturulur
        self.assertFalse(tampered_datagram.verify_checksum())  # Değiştirilmiş yükte checksum doğrulamasının başarısız olduğu kanıtlanır

    def test_udp_zero_checksum_ipv4_allowed(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 4: RFC 768 gereğince IPv4'te checksum=0x0000 durumunun geçerli kabul edildiğini doğrular."""
        datagram = UDPDatagram.create(self.src_ip, self.dst_ip, 6000, 7000, b"ZeroChk", compute_checksum=False)  # Checksum=0
        self.assertEqual(datagram.header.checksum, 0)  # Checksum'ın sıfır olduğu doğrulanır
        self.assertTrue(datagram.verify_checksum())  # RFC 768 standardına göre doğrulamanın geçerli olduğu teyit edilir

    def test_dns_datagram_inspection_and_classification(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 5: DNS sorgu paketinin tespiti ve DNS başlık alanlarının ayrıştırılmasını doğrular."""
        dns_query_payload = bytes.fromhex("1a2b01000001000000000000076578616d706c6503636f6d0000010001")  # DNS Sorgu yükü
        datagram = UDPDatagram.create(self.src_ip, "8.8.8.8", 53123, 53, dns_query_payload)  # Port 53 DNS datagramı üret
        result = self.analyzer.classify_datagram(datagram)  # Analizör ile sınıflandır
        self.assertEqual(result["protokol"], "DNS")  # Protokolün DNS olarak tanındığı test edilir
        self.assertEqual(result["detaylar"]["tur"], "QUERY")  # Paketin sorgu tipi olduğu doğrulanır
        self.assertEqual(result["detaylar"]["soru_sayisi"], 1)  # 1 adet soru kaydı içerdiği doğrulanır
        self.assertEqual(result["detaylar"]["dns_transaction_id"], "0x1a2b")  # Transaction ID doğru ayrıştırılmıştır

    def test_ntp_datagram_inspection_mode_classification(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 6: NTP İstemci isteği (Mode 3) ve Sunucu yanıtı (Mode 4) ayrıştırmasını doğrular."""
        ntp_req_payload = bytes.fromhex(  # ntp_req_payload = bytes.fromhex(
            "23000000000000000000000000000000000000000000000000000000000000000000000000000000e700000000000000"  # "23000000000000000000000000000000000000000000000000000000000000000000000000000000e700000000000000"
        )  # Mode 3 Client yükü
        datagram = UDPDatagram.create(self.src_ip, "192.168.1.1", 49152, 123, ntp_req_payload)  # NTP datagramı üret
        result = self.analyzer.classify_datagram(datagram)  # Sınıflandır
        self.assertEqual(result["protokol"], "NTP")  # NTP olarak tanınır
        self.assertEqual(result["detaylar"]["ntp_version"], 4)  # NTPv4 olduğu doğrulanır
        self.assertEqual(result["detaylar"]["mode_kod"], 3)  # Mode 3 (Client) olduğu doğrulanır
        self.assertEqual(result["detaylar"]["mode_aciklama"], "Client")  # Açıklamanın doğruluğu test edilir

    def test_ntp_monlist_amplification_detection(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 7: NTP Mode 7 'monlist' sorgusunun ve yüksek BAF amplifikasyon riskinin tespitini doğrular."""
        monlist_req_payload = bytes.fromhex("1700032a00000000")  # Mode 7 monlist istek yükü (8 bayt)
        datagram = UDPDatagram.create("203.0.113.50", "198.51.100.10", 58210, 123, monlist_req_payload)  # Datagram üret
        classification = self.analyzer.classify_datagram(datagram)  # Sınıflandır
        self.assertTrue(classification["detaylar"]["monlist_riski"])  # Monlist zafiyet bayrağının tetiklendiği doğrulanır
        amp_eval = self.analyzer.evaluate_amplification_factor(request_size=8, response_size=4000, protocol="NTP")  # BAF hesabı
        self.assertEqual(amp_eval["tehdit_seviyesi"], "CRITICAL")  # Tehdit seviyesinin CRITICAL olduğu doğrulanır
        self.assertGreaterEqual(amp_eval["baf_katsayisi"], 500.0)  # BAF katsayısının 500x üzerinde olduğu test edilir
        self.assertTrue(any("monlist" in s.lower() for s in amp_eval["onerilen_savunma"]))  # Monlist kapatma tavsiyesi aranır

    def test_dns_any_amplification_detection(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 8: DNS ANY sorgusu yanıtındaki yüksek BAF ve amplifikasyon DDoS riskini doğrular."""
        req_len = 50  # 50 baytlık küçük DNS sorgusu
        resp_len = 3200  # 3200 baytlık devasa DNS ANY yanıtı
        amp_eval = self.analyzer.evaluate_amplification_factor(req_len, resp_len, protocol="DNS")  # Değerlendir
        self.assertEqual(amp_eval["tehdit_seviyesi"], "CRITICAL")  # Kritik tehdit seviyesi doğrulanır
        self.assertGreater(amp_eval["baf_katsayisi"], 30.0)  # BAF'ın 30 katından fazla olduğu doğrulanır
        self.assertTrue(any("BCP 38" in s for s in amp_eval["onerilen_savunma"]))  # BCP 38 önerisi varlığı teyit edilir

    def test_udp_flood_anomaly_detection(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 9: Yüksek paket hızına (PPS) sahip UDP Flood anomalisinin tespit edildiğini doğrular."""
        flood_packets = []  # Paket listesi
        for i in range(25):  # 25 adet hızlı paket üretilir
            t = 100.0 + (i * 0.002)  # 500 PPS hızına denk gelen aralık (0.002 saniye)
            dg = UDPDatagram.create("10.0.0.99", "192.168.1.1", 50000 + i, 80, b"FLOOD", timestamp=t)  # Flood paketi
            flood_packets.append(dg)  # Listeye ekle
        anomaly_report = self.analyzer.detect_traffic_anomalies(flood_packets, flood_pps_threshold=100.0)  # Anomalileri analiz et
        self.assertTrue(anomaly_report["anomali_tespit_edildi_mi"])  # Anomali varlığının doğrulandığı test edilir
        flood_events = [e for e in anomaly_report["tespit_edilen_anomaliler"] if e["tip"] == "UDP_FLOOD_ATTACK"]  # Flood olayları
        self.assertGreaterEqual(len(flood_events), 1)  # En az 1 flood anomalisinin yakalandığı doğrulanır
        self.assertEqual(flood_events[0]["kaynak_ip"], "10.0.0.99")  # Saldırgan IP'sinin doğru tespit edildiği test edilir

    def test_udp_port_sweep_detection(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 10: Tek bir kaynaktan çok sayıda farklı porta yapılan UDP Port Taraması (Sweep) tespitini doğrular."""
        scan_packets = []  # Tarama paketleri listesi
        target_ports = [21, 22, 53, 69, 123, 161, 500, 5060]  # 8 farklı hedef port
        for idx, p in enumerate(target_ports):  # Portlar üzerinde döngü
            dg = UDPDatagram.create("10.0.0.50", "192.168.1.5", 45000, p, b"", timestamp=200.0 + idx)  # Tarama paketi
            scan_packets.append(dg)  # Listeye ekle
        report = self.analyzer.detect_traffic_anomalies(scan_packets, scan_port_threshold=5)  # Eşik 5 olarak analiz et
        self.assertTrue(report["anomali_tespit_edildi_mi"])  # Anomali tespit bayrağı doğrulanır
        scan_events = [e for e in report["tespit_edilen_anomaliler"] if e["tip"] == "UDP_PORT_SWEEP_SCAN"]  # Tarama olayları
        self.assertGreaterEqual(len(scan_events), 1)  # Port tarama anomalisinin yakalandığı teyit edilir
        self.assertEqual(scan_events[0]["kaynak_ip"], "10.0.0.50")  # Saldırgan IP doğrulaması yapılır
        self.assertEqual(scan_events[0]["hedef_port_sayisi"], 8)  # Taranan 8 portun tespit edildiği doğrulanır

    def test_kaminsky_source_port_randomization_check(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 11: Tahmin edilebilir sıralı portlar ile rastgele portların ayırt edildiğini doğrular."""
        predictable_ports = [1050, 1051, 1052, 1053, 1054, 1055, 1056]  # Sıralı güvensiz portlar
        audit_vuln = self.analyzer.audit_source_port_randomization(predictable_ports)  # Güvensiz port denetimi
        self.assertFalse(audit_vuln["guvenli_mi"])  # Sıralı portların güvensiz olarak işaretlendiği test edilir
        self.assertTrue(audit_vuln["sirali_mi"])  # Sıralı artış tespit edildiği doğrulanır
        self.assertIn("KAMINSKY_DNS_POISONING_VULNERABLE", audit_vuln["zafiyet"])  # Kaminsky zafiyet uyarısı kontrol edilir
        randomized_ports = [49812, 12054, 61203, 33190, 54002, 19877, 42109]  # Yüksek entropili rastgele portlar
        audit_secure = self.analyzer.audit_source_port_randomization(randomized_ports)  # Güvenli port denetimi
        self.assertTrue(audit_secure["guvenli_mi"])  # Rastgele portların güvenli olarak onaylandığı test edilir
        self.assertFalse(audit_secure["sirali_mi"])  # Sıralı olmadığı teyit edilir

    def test_negative_invalid_ports_and_length_underflow(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 12: Negatif kontrol: Aralık dışı port ve yetersiz başlık uzunluğunun reddedildiğini doğrular."""
        with self.assertRaises(UDPValidationError):  # Negatif portta hata fırlatılmalıdır
            UDPHeader(src_port=-1, dst_port=53, length=8)  # -1 portu denenir
        with self.assertRaises(UDPValidationError):  # 65535 üstü portta hata fırlatılmalıdır
            UDPHeader(src_port=53, dst_port=70000, length=8)  # 70000 portu denenir
        with self.assertRaises(UDPValidationError):  # 8 bayttan küçük uzunlukta hata fırlatılmalıdır
            UDPHeader(src_port=53, dst_port=53, length=7)  # 7 bayt uzunluk denenir

    def test_negative_length_payload_mismatch(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 13: Negatif kontrol: Başlık uzunluğu ile yük boyutu uyuşmadığında paketin reddedildiğini doğrular."""
        invalid_header = UDPHeader(src_port=1000, dst_port=2000, length=30, checksum=0)  # Başlık uzunluğu 30 bayt
        with self.assertRaises(UDPValidationError):  # Uzunluk uyuşmazlığında hata beklenir
            UDPDatagram(self.src_ip, self.dst_ip, header=invalid_header, payload=b"KISA")  # Yük sadece 4 bayt (toplam 12 != 30)

    def test_negative_malformed_pseudo_header_ip(self) -> None:  # İlgili işlevi ve parametreleri tanımlayan fonksiyon/metot
        """Test 14: Negatif kontrol: Sahte başlık hesaplamasında geçersiz IP formatının reddedildiğini doğrular."""
        with self.assertRaises(UDPValidationError):  # Hatalı IP'de hata beklenir
            UDPHeader.calculate_checksum("999.1.2.3", self.dst_ip, 5000, 6000, b"DATA")  # Oktet > 255 olan IP denenir
        with self.assertRaises(UDPValidationError):  # Hatalı dizgi IP'de hata beklenir
            UDPHeader.calculate_checksum(self.src_ip, "gecersiz_ip_adresi", 5000, 6000, b"DATA")  # Harf dizgisi denenir


if __name__ == "__main__":  # if __name__ == "__main__":
    unittest.main()  # Test süitini doğrudan çalıştırma çağrısı
