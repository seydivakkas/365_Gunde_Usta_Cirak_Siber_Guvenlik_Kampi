# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G056 - Mini Proje 7: Protokol Haritası Test Süiti.
14 Adet Kapsamlı Birim, Entegrasyon, Güvenlik Tehdit ve Negatif Sınır Testi.
"""

# Test süiti çatısı için standart unittest modülü
import unittest
# Test veri dosyalarını yüklemek için json modülü
import json
# İkili paket başlıkları simülasyonu için struct modülü
import struct
# Dosya yolları yönetimi için pathlib
from pathlib import Path

# Test edilecek protokol analiz modülünden sınıflar ve sabitler içe aktarılır
from portfolio.hafta_08.gun_056.uygulama.protocol_map_analyzer import (
    ProtocolDissector,
    ProtocolMapWorkbench,
    PacketParsingError,
    SecurityAnomalyAlert,
    ETHERTYPE_IPV4,
    ETHERTYPE_ARP,
    PROTO_TCP,
    PROTO_UDP
)


class TestProtocolMapAnalyzer(unittest.TestCase):
    """Mini Proje 7 Protokol Haritası ve Paket Çözümleme test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz analiz motorunu ve örnek test verilerini hazırlar."""
        # Yetkili DHCP sunucusu 192.168.1.1 olarak tanımlı çalışma kitabı başlatılır
        self.workbench = ProtocolMapWorkbench(authorized_dhcp_server="192.168.1.1")
        # Örnek PCAP çerçeveleri dosya yolu belirlenir
        self.sample_pcap_path = Path("portfolio/hafta_08/gun_056/ornek_veri/sample_pcap_frames.json")

    def test_01_raw_ethernet_dissection(self) -> None:
        """Test 1: 14 baytlık ham ikili Ethernet II başlığının ayrıştırılması ve EtherType kontrolü."""
        # 6B Dst MAC + 6B Src MAC + 2B EtherType (0x0800 IPv4)
        raw_eth = bytes.fromhex("525400123456000c294f8e350800") + b"A" * 20
        frame = ProtocolDissector.dissect_ethernet_raw(raw_eth)
        # Alanların doğruluğu denetlenir
        self.assertEqual(frame.dst_mac, "52:54:00:12:34:56")
        self.assertEqual(frame.src_mac, "00:0c:29:4f:8e:35")
        self.assertEqual(frame.ethertype, ETHERTYPE_IPV4)
        self.assertEqual(len(frame.payload), 20)

    def test_02_raw_ipv4_dissection(self) -> None:
        """Test 2: 20 baytlık ham IPv4 başlığının ayrıştırılması ve IP adreslerinin doğrulanması."""
        # Version 4, IHL 5, Total Length 40, TTL 64, Protocol 6 (TCP), Src 192.168.1.100, Dst 192.168.1.10
        raw_ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 40, 1234, 0, 64, PROTO_TCP, 0,
            bytes([192, 168, 1, 100]), bytes([192, 168, 1, 10])
        ) + b"TCPDATA12345"
        ip_hdr, payload = ProtocolDissector.dissect_ipv4_raw(raw_ip)
        self.assertEqual(ip_hdr.version, 4)
        self.assertEqual(ip_hdr.ihl, 5)
        self.assertEqual(ip_hdr.src_ip, "192.168.1.100")
        self.assertEqual(ip_hdr.dst_ip, "192.168.1.10")
        self.assertEqual(ip_hdr.protocol, PROTO_TCP)
        self.assertEqual(payload, b"TCPDATA12345")

    def test_03_raw_tcp_dissection(self) -> None:
        """Test 3: 20 baytlık ham TCP başlığının ayrıştırılması, bayraklar ve portların doğrulanması."""
        # Src Port 54321, Dst Port 80, Seq 1000, Ack 0, Offset 5 (0x50), Flags SYN (0x02), Window 64240
        raw_tcp = struct.pack("!HHLLBBHHH", 54321, 80, 1000, 0, 0x50, 0x02, 64240, 0, 0) + b"GET / HTTP/1.1"
        tcp_hdr, payload = ProtocolDissector.dissect_tcp_raw(raw_tcp)
        self.assertEqual(tcp_hdr.src_port, 54321)
        self.assertEqual(tcp_hdr.dst_port, 80)
        self.assertEqual(tcp_hdr.seq, 1000)
        self.assertEqual(tcp_hdr.flags, "SYN")
        self.assertEqual(tcp_hdr.window, 64240)
        self.assertEqual(payload, b"GET / HTTP/1.1")

    def test_04_raw_udp_dissection(self) -> None:
        """Test 4: 8 baytlık ham UDP başlığının ayrıştırılması ve uzunluk doğrulaması."""
        # Src Port 52111, Dst Port 53, Length 18, Checksum 0
        raw_udp = struct.pack("!HHHH", 52111, 53, 18, 0) + b"DNSQUERY01"
        udp_hdr, payload = ProtocolDissector.dissect_udp_raw(raw_udp)
        self.assertEqual(udp_hdr.src_port, 52111)
        self.assertEqual(udp_hdr.dst_port, 53)
        self.assertEqual(udp_hdr.length, 18)
        self.assertEqual(payload, b"DNSQUERY01")

    def test_05_sample_pcap_batch_ingestion(self) -> None:
        """Test 5: sample_pcap_frames.json dosyasındaki 15 paketin topluca başarıyla ayrıştırılması."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        # Toplam paket sayısı 15 olmalıdır
        self.assertEqual(len(self.workbench.packets), 15)

    def test_06_protocol_hierarchy_distribution(self) -> None:
        """Test 6: Katmanlar arası protokol dağılım istatistiklerinin (Ethernet, IPv4, TCP, UDP vb.) hesaplanması."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        # İstatistikler kontrol edilir
        self.assertEqual(self.workbench.layer_stats["Ethernet"]["paket"], 15)
        self.assertEqual(self.workbench.layer_stats["ARP"]["paket"], 1)
        self.assertEqual(self.workbench.layer_stats["IPv4"]["paket"], 14)
        self.assertEqual(self.workbench.layer_stats["TCP"]["paket"], 8)
        self.assertEqual(self.workbench.layer_stats["UDP"]["paket"], 6)
        # Rapor metni oluşturulabilirliği test edilir
        report = self.workbench.generate_protocol_hierarchy_report()
        self.assertIn("PROTOCOL HIERARCHY MAP", report)

    def test_07_flow_matrix_creation_and_state(self) -> None:
        """Test 7: 5'li demet (5-tuple) iletişim akışlarının gruplanması ve TCP durum geçişleri."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        # Akış matrisinde 192.168.1.100:54321 <-> 192.168.1.10:80 TCP akışı bulunmalıdır
        flow_key = ("192.168.1.100", 54321, "192.168.1.10", 80, "TCP")
        self.assertIn(flow_key, self.workbench.flow_matrix)
        flow = self.workbench.flow_matrix[flow_key]
        # Durumu ESTABLISHED olmalıdır (SYN ve ACK görüldüğü için)
        self.assertEqual(flow.state, "ESTABLISHED")
        # Rapor üretimi test edilir
        matrix_rep = self.workbench.generate_flow_matrix_report()
        self.assertIn("COMMUNICATION FLOW MATRIX", matrix_rep)

    def test_08_tcp_retransmission_tracking(self) -> None:
        """Test 8: Paket akışında yinelenen (yeniden iletilen) TCP segmentinin tespiti."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        flow_key = ("192.168.1.100", 54321, "192.168.1.10", 80, "TCP")
        flow = self.workbench.flow_matrix[flow_key]
        # Yeniden iletim sayısı 1 olmalıdır (Paket 6)
        self.assertEqual(flow.retransmission_count, 1)

    def test_09_security_port_scan_detection(self) -> None:
        """Test 9: Hızlı port taraması (SYN Scan Flood) saldırısının güvenlik olayı olarak yakalanması."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        # Olaylar arasında PORT_SCAN_SYN_FLOOD aranır
        scan_events = [e for e in self.workbench.security_incidents if e["tip"] == "PORT_SCAN_SYN_FLOOD"]
        self.assertGreaterEqual(len(scan_events), 1)
        self.assertEqual(scan_events[0]["saldirgan_ip"], "10.0.0.99")
        self.assertEqual(scan_events[0]["hedef_portlar"], [21, 22, 23])

    def test_10_security_dns_tunneling_detection(self) -> None:
        """Test 10: Yüksek Shannon entropili uzun DNS sorgularının (DNS Tunneling) tespiti."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        tunnel_events = [e for e in self.workbench.security_incidents if e["tip"] == "DNS_TUNNELING_EXFILTRATION"]
        self.assertEqual(len(tunnel_events), 1)
        self.assertIn("7a810f44bcde77189a2b001fc3", tunnel_events[0]["sorgu_adi"])

    def test_11_security_rogue_dhcp_detection(self) -> None:
        """Test 11: Yetkisiz kaynaktan gelen sahte DHCP Offer paketinin güvenlik olayı olarak yakalanması."""
        with open(self.sample_pcap_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for frame_dict in data["paketler"]:
            self.workbench.ingest_frame_dict(frame_dict)
        rogue_events = [e for e in self.workbench.security_incidents if e["tip"] == "ROGUE_DHCP_SERVER"]
        self.assertEqual(len(rogue_events), 1)
        self.assertEqual(rogue_events[0]["sahte_sunucu_ip"], "192.168.1.199")

    def test_12_negative_short_headers(self) -> None:
        """Test 12 (Negatif): Kırpılmış Ethernet, IPv4, TCP ve UDP başlıklarında PacketParsingError fırlatılması."""
        # 10 baytlık kırpık ethernet
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.dissect_ethernet_raw(b"\x00" * 10)
        # 16 baytlık kırpık IPv4
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.dissect_ipv4_raw(b"\x45" + b"\x00" * 15)
        # 12 baytlık kırpık TCP
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.dissect_tcp_raw(b"\x00" * 12)
        # 4 baytlık kırpık UDP
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.dissect_udp_raw(b"\x00" * 4)

    def test_13_negative_invalid_protocol_and_version(self) -> None:
        """Test 13 (Negatif): Geçersiz EtherType, geçersiz IP versiyonu ve bilinmeyen L4 protokol hataları."""
        # Geçersiz EtherType (0xFFFF)
        with self.assertRaises(PacketParsingError) as ctx:
            ProtocolDissector.dissect_ethernet_raw(bytes.fromhex("525400123456000c294f8e35ffff") + b"A" * 10)
        self.assertIn("Desteklenmeyen veya gecersiz EtherType", str(ctx.exception))

        # Geçersiz IP Versiyonu (Sürüm 2)
        bad_ver_ip = struct.pack("!BBHHHBBH4s4s", 0x25, 0, 40, 1, 0, 64, 6, 0, bytes([10,0,0,1]), bytes([10,0,0,2]))
        with self.assertRaises(PacketParsingError) as ctx:
            ProtocolDissector.dissect_ipv4_raw(bad_ver_ip)
        self.assertIn("Gecersiz IP versiyonu", str(ctx.exception))

        # Desteklenmeyen L4 protokolü (Protokol 99)
        bad_proto_ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 99, 0, bytes([10,0,0,1]), bytes([10,0,0,2]))
        with self.assertRaises(PacketParsingError) as ctx:
            ProtocolDissector.dissect_ipv4_raw(bad_proto_ip)
        self.assertIn("Desteklenmeyen L4 protokol kodu", str(ctx.exception))

    def test_14_negative_malformed_addresses(self) -> None:
        """Test 14 (Negatif): Hatalı formatlı MAC adresi ve geçersiz oktetli IPv4 adresi doğrulaması."""
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.validate_mac("00:11:ZZ:44:55:66")
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.validate_mac("00:11:22")
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.validate_ipv4("999.1.1.1")
        with self.assertRaises(PacketParsingError):
            ProtocolDissector.validate_ipv4("192.168.1")


if __name__ == "__main__":
    unittest.main()
