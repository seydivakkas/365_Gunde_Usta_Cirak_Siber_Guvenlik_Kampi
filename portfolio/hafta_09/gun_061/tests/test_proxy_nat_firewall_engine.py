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
G061: Proxy, NAT ve Güvenlik Duvarı Kapsamlı Test Paketi (14 Test).

Bu test paketi; IPv4 adres doğrulamasını, TCP bayrak anomali kontrollerini (SYN+FIN, Null, Xmas),
durum takipli güvenlik duvarı filtrelemesini (NEW, ESTABLISHED, INVALID),
PAT port tahsis ve tükenme mekanizmalarını, ters/ileri vekil sunucu politikalarını doğrular.
"""

# Standart birim test kütüphanesini içe aktar
import unittest
# JSON veri yükleme ve işleme kütüphanesi
import json
# Dosya sistemi yolları için pathlib kütüphanesi
from pathlib import Path

# Test edilecek uygulama bileşenlerini ve hata sınıflarını içe aktar
from portfolio.hafta_09.gun_061.uygulama.proxy_nat_firewall_engine import (
    TCPPacket,
    StatefulFirewall,
    PATEngine,
    ProxyEngine,
    validate_ipv4_address,
    validate_tcp_flags,
    NetworkValidationError,
    InvalidPacketFlagsError,
    FirewallDropError,
    ConntrackOverflowError,
    NATExhaustionError,
    ProxySecurityViolationError,
    ProxyAccessDeniedError
)


class TestProxyNATFirewallEngine(unittest.TestCase):
    """Proxy, NAT ve Güvenlik Duvarı Motoru Birim Testleri."""

    @classmethod
    def setUpClass(cls):
        """Test sınıfı başlatılırken ağ kuralları ve negatif senaryoları yükler."""
        # Geçerli test dosyasının bulunduğu dizini tespit et
        current_dir = Path(__file__).resolve().parent
        # Örnek veri dizinine erişim yolunu oluştur
        ornek_veri_dir = current_dir.parent / "ornek_veri"
        
        # Ağ kuralları ve yapilandirma verisini oku
        with open(ornek_veri_dir / "sample_network_rules.json", "r", encoding="utf-8") as f:
            cls.rules_data = json.load(f)
            
        # Negatif test senaryolarını oku
        with open(ornek_veri_dir / "invalid_traffic_inputs.json", "r", encoding="utf-8") as f:
            cls.invalid_data = json.load(f)

    def test_01_ipv4_validation_positive_and_negative(self):
        """Pozitif ve Negatif Test 1: IPv4 adres biçimi doğrulaması."""
        # Geçerli IPv4 adreslerinin True döndürdüğünü doğrula
        self.assertTrue(validate_ipv4_address("192.168.1.1"))
        self.assertTrue(validate_ipv4_address("203.0.113.10"))

        # Geçersiz adreslerde NetworkValidationError fırlatıldığını doğrula
        with self.assertRaises(NetworkValidationError):
            validate_ipv4_address("999.999.999.999")
        with self.assertRaises(NetworkValidationError):
            validate_ipv4_address("gecersiz.ip.adresi")
        with self.assertRaises(NetworkValidationError):
            validate_ipv4_address("")

    def test_02_valid_tcp_flags_acceptance(self):
        """Pozitif Test 2: Standart TCP bayrak kombinasyonlarının onaylanması."""
        # Geçerli bayrak listeleri
        valid_combos = [["SYN"], ["SYN", "ACK"], ["ACK"], ["FIN", "ACK"], ["RST"]]
        for combo in valid_combos:
            # Hata fırlatılmadan başarıyla geçildiğini doğrula
            try:
                validate_tcp_flags(combo)
            except InvalidPacketFlagsError:
                self.fail(f"Gecerli bayrak kombinasyonu reddedilmemelidir: {combo}")

    def test_03_negative_null_scan_detection(self):
        """Negatif Test 3: Boş bayraklı Null Scan taramasının tespiti ve engellenmesi."""
        # Hiçbir bayrak içermeyen liste
        with self.assertRaises(InvalidPacketFlagsError) as ctx:
            validate_tcp_flags([])
        self.assertIn("Null Scan", str(ctx.exception))

    def test_04_negative_syn_fin_scan_detection(self):
        """Negatif Test 4: RFC 793 ihlali SYN+FIN saldırı taramasının tespiti."""
        # SYN ve FIN içeren liste
        with self.assertRaises(InvalidPacketFlagsError) as ctx:
            validate_tcp_flags(["SYN", "FIN"])
        self.assertIn("SYN+FIN", str(ctx.exception))

    def test_05_negative_xmas_scan_detection(self):
        """Negatif Test 5: FIN+PSH+URG bayraklarını içeren Xmas Scan taramasının tespiti."""
        # Xmas bayrakları
        with self.assertRaises(InvalidPacketFlagsError) as ctx:
            validate_tcp_flags(["FIN", "PSH", "URG"])
        self.assertIn("Xmas Scan", str(ctx.exception))

    def test_06_stateful_firewall_new_connection(self):
        """Pozitif Test 6: İzin verilen porta gelen ilk SYN paketine NEW oturumu açılması."""
        # Güvenlik duvarını başlat ve port 443 kuralı ekle
        fw = StatefulFirewall(default_policy="DROP")
        fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT", description="HTTPS")
        
        # Gelen SYN paketi oluştur
        pkt = TCPPacket(src_ip="198.51.100.5", src_port=52341, dst_ip="192.168.1.100", dst_port=443, flags=["SYN"])
        result = fw.process_packet(pkt, direction="INGRESS")
        
        # Durumun ACCEPT (NEW) olduğunu doğrula
        self.assertEqual(result, "ACCEPT (NEW)")
        # Conntrack tablosuna girdi eklendiğini doğrula
        self.assertEqual(len(fw.conntrack_table), 1)

    def test_07_stateful_firewall_return_traffic_established(self):
        """Pozitif Test 7: Sunucunun döndüğü SYN-ACK yanıtının conntrack ile onaylanması."""
        # Güvenlik duvarı ve kural hazırla
        fw = StatefulFirewall(default_policy="DROP")
        fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT")
        
        # İlk SYN paketi (İstemci -> Sunucu)
        syn_pkt = TCPPacket(src_ip="198.51.100.5", src_port=52341, dst_ip="192.168.1.100", dst_port=443, flags=["SYN"])
        fw.process_packet(syn_pkt, direction="INGRESS")
        
        # Karşı taraftan dönen SYN-ACK paketi (Sunucu -> İstemci)
        syn_ack_pkt = TCPPacket(src_ip="192.168.1.100", src_port=443, dst_ip="198.51.100.5", dst_port=52341, flags=["SYN", "ACK"])
        reply_result = fw.process_packet(syn_ack_pkt, direction="EGRESS")
        
        # Yanıtın kabul edildiğini ve durumun ESTABLISHED olduğunu doğrula
        self.assertEqual(reply_result, "ACCEPT (ESTABLISHED/REPLY)")

    def test_08_stateful_firewall_established_data_stream(self):
        """Pozitif Test 8: Kurulmuş oturum üzerinden veri (ACK) paketlerinin kesintisiz akışı."""
        fw = StatefulFirewall(default_policy="DROP")
        fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT")
        
        # Oturumu başlat
        syn = TCPPacket(src_ip="198.51.100.5", src_port=52341, dst_ip="192.168.1.100", dst_port=443, flags=["SYN"])
        fw.process_packet(syn, direction="INGRESS")
        
        # İstemciden gelen sonraki ACK veri paketi
        ack_data = TCPPacket(src_ip="198.51.100.5", src_port=52341, dst_ip="192.168.1.100", dst_port=443, flags=["ACK"], payload=b"GET / HTTP/1.1")
        res = fw.process_packet(ack_data, direction="INGRESS")
        self.assertEqual(res, "ACCEPT (ESTABLISHED)")

    def test_09_negative_unsolicited_out_of_state_packet(self):
        """Negatif Test 9: Durum tablosunda olmayan beklenmedik ACK paketinin engellenmesi."""
        fw = StatefulFirewall(default_policy="DROP")
        fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT")
        
        # Hiç el sıkışması yapılmadan doğrudan gönderilen sahte ACK paketi
        fake_ack = TCPPacket(src_ip="198.51.100.9", src_port=55555, dst_ip="192.168.1.100", dst_port=443, flags=["ACK"])
        with self.assertRaises(FirewallDropError) as ctx:
            fw.process_packet(fake_ack, direction="INGRESS")
        self.assertIn("INVALID State", str(ctx.exception))

    def test_10_negative_blocked_inbound_port(self):
        """Negatif Test 10: İzin verilmeyen port 23 (Telnet) üzerine gelen SYN paketinin düşürülmesi."""
        fw = StatefulFirewall(default_policy="DROP")
        fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT")
        
        # Port 23 üzerine gelen paket
        telnet_pkt = TCPPacket(src_ip="198.51.100.9", src_port=43210, dst_ip="192.168.1.100", dst_port=23, flags=["SYN"])
        with self.assertRaises(FirewallDropError) as ctx:
            fw.process_packet(telnet_pkt, direction="INGRESS")
        self.assertIn("Port 23 icin erisim kurali bulunamadi", str(ctx.exception))

    def test_11_negative_conntrack_table_overflow(self):
        """Negatif Test 11: Maksimum kapasite dolduğunda ConntrackOverflowError üretilmesi."""
        # Yalnızca 2 girdilik minik conntrack kapasitesi oluştur
        small_fw = StatefulFirewall(default_policy="DROP", max_conntrack_entries=2)
        small_fw.add_rule(direction="INGRESS", dst_port=443, action="ACCEPT")
        
        # 1. Oturum
        small_fw.process_packet(TCPPacket("1.1.1.1", 1001, "192.168.1.100", 443, ["SYN"]))
        # 2. Oturum (Kapasite doldu)
        small_fw.process_packet(TCPPacket("1.1.1.2", 1002, "192.168.1.100", 443, ["SYN"]))
        
        # 3. Oturum denendiğinde ConntrackOverflowError fırlatılmalı
        with self.assertRaises(ConntrackOverflowError) as ctx:
            small_fw.process_packet(TCPPacket("1.1.1.3", 1003, "192.168.1.100", 443, ["SYN"]))
        self.assertIn("conntrack durum tablosu maksimum kapasiteye ulasti", str(ctx.exception))

    def test_12_pat_outbound_and_inbound_translation(self):
        """Pozitif Test 12: PAT ile dışa doğru kaynak IP/port dönüşümü ve geri dönüş çevrimi."""
        pat = PATEngine(public_ip="203.0.113.10", port_range_start=10000, port_range_end=10005)
        
        # İç ağdan internetteki bir sunucuya giden paket
        internal_pkt = TCPPacket(src_ip="192.168.1.50", src_port=45678, dst_ip="93.184.216.34", dst_port=80, flags=["SYN"])
        outbound_translated = pat.translate_outbound(internal_pkt)
        
        # Kaynak IP'nin genel IP'ye dönüştüğünü doğrula
        self.assertEqual(outbound_translated.src_ip, "203.0.113.10")
        # Portun 10000 olduğunu doğrula
        self.assertEqual(outbound_translated.src_port, 10000)
        
        # İnternetteki sunucudan dönen yanıt paketi
        response_pkt = TCPPacket(src_ip="93.184.216.34", src_port=80, dst_ip="203.0.113.10", dst_port=10000, flags=["SYN", "ACK"])
        inbound_translated = pat.translate_inbound(response_pkt)
        
        # Hedef IP ve portun orijinal istemciye dönüştürüldüğünü doğrula
        self.assertEqual(inbound_translated.dst_ip, "192.168.1.50")
        self.assertEqual(inbound_translated.dst_port, 45678)

    def test_13_negative_nat_port_exhaustion(self):
        """Negatif Test 13: PAT port havuzu tükendiğinde NATExhaustionError üretilmesi."""
        # Yalnızca 1 portluk (10000 - 10000) dar havuz oluştur
        tiny_pat = PATEngine(public_ip="203.0.113.10", port_range_start=10000, port_range_end=10000)
        
        # 1. Oturum tek portu kapar
        p1 = TCPPacket("192.168.1.10", 5000, "1.1.1.1", 80, ["SYN"])
        tiny_pat.translate_outbound(p1)
        
        # 2. Oturum için boş port kalmamıştır
        p2 = TCPPacket("192.168.1.11", 5001, "2.2.2.2", 80, ["SYN"])
        with self.assertRaises(NATExhaustionError) as ctx:
            tiny_pat.translate_outbound(p2)
        self.assertIn("PAT port havuzu tukendi", str(ctx.exception))

    def test_14_proxy_xff_spoofing_defense_and_connect_tunnel(self):
        """Pozitif ve Negatif Test 14: Ters vekil XFF sahtecilik engeli ve ileri vekil CONNECT kuralı."""
        proxy = ProxyEngine(trusted_proxies=["127.0.0.1"], allowed_connect_ports=[443])
        
        # 1. Güvenilmeyen istemci sahte 127.0.0.1 XFF enjekte ettiğinde engellenmeli
        with self.assertRaises(ProxySecurityViolationError) as ctx:
            proxy.process_reverse_proxy_request(
                client_ip="198.51.100.40",
                incoming_headers={"X-Forwarded-For": "127.0.0.1"}
            )
        self.assertIn("sahte X-Forwarded-For", str(ctx.exception))

        # 2. Forward Proxy üzerinden port 22'ye CONNECT tüneli reddedilmeli
        with self.assertRaises(ProxyAccessDeniedError) as ctx:
            proxy.process_forward_proxy_connect(method="CONNECT", target_host_port="internal:22")
        self.assertIn("Port 22 engellendi", str(ctx.exception))

        # 3. Port 443'e CONNECT tüneli başarıyla açılmalı
        connect_res = proxy.process_forward_proxy_connect(method="CONNECT", target_host_port="target.com:443")
        self.assertEqual(connect_res["status"], "TUNNEL_ESTABLISHED")


if __name__ == "__main__":
    # Testleri detaylı çıktıyla çalıştır
    unittest.main()
