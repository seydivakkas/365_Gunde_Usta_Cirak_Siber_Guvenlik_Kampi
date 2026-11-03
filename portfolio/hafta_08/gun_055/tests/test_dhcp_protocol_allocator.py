# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G055 - DHCP ve IP Ataması Test Süiti.
14 Adet Kapsamlı Birim, Entegrasyon, Negatif Sınır ve Güvenlik Testi.
"""

# Test süiti çatısı için standart unittest modülü
import unittest
# Zaman manipülasyonu ve gecikme testleri için time modülü
import time
# JSON test girdilerini okumak için json modülü
import json
# Dosya yolları yönetimi için pathlib
from pathlib import Path

# Test edilecek DHCP modülünden sınıflar ve sabitler içe aktarılır
from portfolio.hafta_08.gun_055.uygulama.dhcp_protocol_allocator import (
    DHCPPacket,
    DHCPLeasePool,
    RogueDHCPDetector,
    DHCPStarvationDetector,
    DHCPSnoopingSwitch,
    DHCPValidationError,
    DHCPSecurityAlert,
    BOOTREQUEST,
    BOOTREPLY,
    HTYPE_ETHERNET,
    HLEN_ETHERNET,
    DHCP_MAGIC_COOKIE,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_RELEASE,
    OPT_DHCP_MESSAGE_TYPE,
    OPT_SERVER_IDENTIFIER,
    OPT_LEASE_TIME,
    OPT_SUBNET_MASK,
    OPT_ROUTER,
    OPT_DNS_SERVERS,
    OPT_REQUESTED_IP,
    OPT_PARAMETER_REQUEST_LIST
)


class TestDHCPProtocolAllocator(unittest.TestCase):
    """DHCP protokol çözümleme, DORA yaşam döngüsü ve güvenlik motoru test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce temiz test ortamı ve havuzu başlatır."""
        # 192.168.1.100 - 192.168.1.105 arası 6 IP adreslik kontrollü havuz oluşturulur
        self.pool = DHCPLeasePool(
            start_ip="192.168.1.100",
            end_ip="192.168.1.105",
            subnet_mask="255.255.255.0",
            router_ip="192.168.1.1",
            dns_servers=["8.8.8.8", "1.1.1.1"],
            default_lease_time=3600
        )
        # Standart istemci MAC adresi
        self.client_mac = "00:0c:29:4f:8e:35"

    def test_01_dhcp_discover_serialization_and_parsing(self) -> None:
        """Test 1: DHCP Discover paketinin 236B ikili başlık ve TLV olarak serileştirilip ayrıştırılması."""
        # Discover paketi oluşturulur
        pkt = DHCPPacket(
            op=BOOTREQUEST,
            htype=HTYPE_ETHERNET,
            hlen=HLEN_ETHERNET,
            xid=0x12345678,
            chaddr=self.client_mac,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER,
                OPT_PARAMETER_REQUEST_LIST: [1, 3, 6, 15]
            }
        )
        # Bayt akışına serileştirilir
        raw_bytes = pkt.serialize()
        # En az 236 bayt başlık + 4 bayt cookie + seçenekler olmalıdır
        self.assertGreater(len(raw_bytes), 240)
        # Ham baytlardan tekrar paket nesnesi ayrıştırılır
        parsed = DHCPPacket.parse(raw_bytes)
        # Alanların doğruluğu teyit edilir
        self.assertEqual(parsed.op, BOOTREQUEST)
        self.assertEqual(parsed.xid, 0x12345678)
        self.assertEqual(parsed.chaddr, self.client_mac)
        self.assertEqual(parsed.options[OPT_DHCP_MESSAGE_TYPE], DHCP_DISCOVER)
        self.assertEqual(parsed.options[OPT_PARAMETER_REQUEST_LIST], [1, 3, 6, 15])

    def test_02_dhcp_dora_complete_flow(self) -> None:
        """Test 2: Tam DORA (Discover, Offer, Request, ACK) döngüsünün ve IP atamasının doğrulanması."""
        # 1. Aşama: Discover paketi hazırlanır
        discover = DHCPPacket(
            op=BOOTREQUEST,
            xid=0xabcdef12,
            chaddr=self.client_mac,
            options={OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER}
        )
        # Sunucu Discover paketini işler ve Offer üretir
        offer = self.pool.process_discover(discover)
        self.assertEqual(offer.op, BOOTREPLY)
        self.assertEqual(offer.options[OPT_DHCP_MESSAGE_TYPE], DHCP_OFFER)
        self.assertEqual(offer.yiaddr, "192.168.1.100")
        self.assertEqual(offer.options[OPT_ROUTER], "192.168.1.1")

        # 2. Aşama: İstemci Offer'ı kabul edip Request paketi yayınlar
        request = DHCPPacket(
            op=BOOTREQUEST,
            xid=0xabcdef12,
            chaddr=self.client_mac,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_REQUEST,
                OPT_REQUESTED_IP: offer.yiaddr,
                OPT_SERVER_IDENTIFIER: "192.168.1.1"
            }
        )
        # Sunucu Request'i onaylar ve ACK üretir
        ack = self.pool.process_request(request)
        self.assertEqual(ack.op, BOOTREPLY)
        self.assertEqual(ack.options[OPT_DHCP_MESSAGE_TYPE], DHCP_ACK)
        self.assertEqual(ack.yiaddr, "192.168.1.100")

        # Havuzdaki kiralamanın aktifliği doğrulanır
        self.assertIn(self.client_mac, self.pool.leases)
        self.assertEqual(self.pool.leases[self.client_mac].ip_address, "192.168.1.100")
        self.assertEqual(self.pool.leases[self.client_mac].state, "ACTIVE")

    def test_03_dhcp_release_cycle(self) -> None:
        """Test 3: DHCP Release paketi ile kiralanan IP'nin boşa çıkması ve havuza dönüşü."""
        # İstemciye önce IP tahsis edilir
        discover = DHCPPacket(op=BOOTREQUEST, xid=0x111, chaddr=self.client_mac, options={OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER})
        offer = self.pool.process_discover(discover)
        request = DHCPPacket(op=BOOTREQUEST, xid=0x111, chaddr=self.client_mac, options={OPT_DHCP_MESSAGE_TYPE: DHCP_REQUEST, OPT_REQUESTED_IP: offer.yiaddr})
        self.pool.process_request(request)

        # Tahsis edilen IP kontrol edilir
        self.assertNotIn("192.168.1.100", self.pool.available_ips)

        # İstemci Release paketi gönderir
        release = DHCPPacket(
            op=BOOTREQUEST,
            xid=0x222,
            ciaddr="192.168.1.100",
            chaddr=self.client_mac,
            options={OPT_DHCP_MESSAGE_TYPE: DHCP_RELEASE}
        )
        released = self.pool.process_release(release)
        self.assertTrue(released)
        # IP adresi kullanılabilirler listesine dönmüş olmalıdır
        self.assertIn("192.168.1.100", self.pool.available_ips)
        self.assertNotIn(self.client_mac, self.pool.leases)

    def test_04_dhcp_nak_on_invalid_requested_ip(self) -> None:
        """Test 4: Havuzda olmayan veya geçersiz IP talep edildiğinde sunucunun NAK yanıtı dönmesi."""
        # İstemci havuz dışındaki 10.0.0.50 adresini talep eder
        bad_request = DHCPPacket(
            op=BOOTREQUEST,
            xid=0x999,
            chaddr=self.client_mac,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_REQUEST,
                OPT_REQUESTED_IP: "10.0.0.50"
            }
        )
        response = self.pool.process_request(bad_request)
        # Yanıt NAK olmalıdır
        self.assertEqual(response.options[OPT_DHCP_MESSAGE_TYPE], DHCP_NAK)
        self.assertEqual(response.yiaddr, "0.0.0.0")

    def test_05_expired_lease_cleanup(self) -> None:
        """Test 5: Süresi dolan kiralamaların temizlenmesi ve adreslerin havuza iadesi."""
        # 1 saniyelik test kiralaması havuzu oluşturulur
        fast_pool = DHCPLeasePool("192.168.1.200", "192.168.1.201", default_lease_time=1)
        disc = DHCPPacket(op=BOOTREQUEST, xid=0x55, chaddr="00:11:22:33:44:55", options={OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER})
        off = fast_pool.process_discover(disc)
        req = DHCPPacket(op=BOOTREQUEST, xid=0x55, chaddr="00:11:22:33:44:55", options={OPT_DHCP_MESSAGE_TYPE: DHCP_REQUEST, OPT_REQUESTED_IP: off.yiaddr})
        fast_pool.process_request(req)

        # Kiralamanın aktif olduğu ve IP'nin havuzdan çıktığı teyit edilir
        self.assertNotIn("192.168.1.200", fast_pool.available_ips)

        # 1.1 saniye sonra kiralama süresi dolmuş olur (yapay olarak start_time geriye çekilir)
        fast_pool.leases["00:11:22:33:44:55"].start_time -= 10.0
        cleaned = fast_pool.clean_expired_leases()
        self.assertEqual(cleaned, 1)
        self.assertIn("192.168.1.200", fast_pool.available_ips)

    def test_06_rogue_dhcp_detection(self) -> None:
        """Test 6: Yetkisiz Sahte (Rogue) DHCP sunucusu teklifinin tespiti ve güvenlik alarmı."""
        # Yalnızca 192.168.1.1 yetkilidir
        detector = RogueDHCPDetector(authorized_servers=["192.168.1.1"])

        # Sahte sunucu paketi (192.168.1.199)
        rogue_offer = DHCPPacket(
            op=BOOTREPLY,
            xid=0x777,
            yiaddr="192.168.1.222",
            chaddr=self.client_mac,
            options={
                OPT_DHCP_MESSAGE_TYPE: DHCP_OFFER,
                OPT_SERVER_IDENTIFIER: "192.168.1.199",
                OPT_ROUTER: "192.168.1.199",
                OPT_DNS_SERVERS: ["192.168.1.199"]
            }
        )
        # Güvenlik alarmı (DHCPSecurityAlert) fırlatılmalıdır
        with self.assertRaises(DHCPSecurityAlert) as ctx:
            detector.inspect_packet(rogue_offer, source_ip="192.168.1.199")
        self.assertIn("Sahte (Rogue) DHCP", str(ctx.exception))
        self.assertEqual(len(detector.detected_alerts), 1)

    def test_07_dhcp_starvation_attack_detection(self) -> None:
        """Test 7: Sahte rastgele MAC adresleriyle yapılan DHCP Starvation sel saldırısının yakalanması."""
        starvation_detector = DHCPStarvationDetector(max_discovers_per_second=3, sliding_window_seconds=1.0)

        # 3 istek kabul edilir
        for i in range(3):
            mac = f"02:00:00:00:00:0{i}"
            pkt = DHCPPacket(op=BOOTREQUEST, xid=i, chaddr=mac, options={OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER})
            starvation_detector.inspect_discover(pkt)

        # 4. farklı MAC'ten gelen istek eşik değerini aşıp Starvation alarmı vermelidir
        starvation_mac = "02:00:00:00:00:99"
        starvation_pkt = DHCPPacket(op=BOOTREQUEST, xid=99, chaddr=starvation_mac, options={OPT_DHCP_MESSAGE_TYPE: DHCP_DISCOVER})
        with self.assertRaises(DHCPSecurityAlert) as ctx:
            starvation_detector.inspect_discover(starvation_pkt)
        self.assertIn("DHCP Starvation", str(ctx.exception))
        self.assertIn(starvation_mac, starvation_detector.blocked_entities)

    def test_08_dhcp_snooping_drops_untrusted_server_offer(self) -> None:
        """Test 8: DHCP Snooping kuralı uyarınca untrusted porttan gelen Offer paketinin düşürülmesi."""
        switch = DHCPSnoopingSwitch()
        switch.configure_port("Fa0/1", "untrusted")
        switch.configure_port("Gi0/1", "trusted")

        # Untrusted porta gelen Offer paketi
        offer_pkt = DHCPPacket(
            op=BOOTREPLY,
            xid=0x888,
            yiaddr="192.168.1.150",
            chaddr=self.client_mac,
            options={OPT_DHCP_MESSAGE_TYPE: DHCP_OFFER, OPT_SERVER_IDENTIFIER: "192.168.1.200"}
        )
        with self.assertRaises(DHCPSecurityAlert) as ctx:
            switch.filter_packet("Fa0/1", offer_pkt)
        self.assertIn("untrusted", str(ctx.exception))
        self.assertEqual(len(switch.snooping_violations), 1)

    def test_09_dhcp_snooping_builds_binding_database(self) -> None:
        """Test 9: Trusted porttan geçen onaylı ACK ile DHCP Snooping Binding Tablosunun güncellenmesi."""
        switch = DHCPSnoopingSwitch()
        switch.configure_port("Gi0/1", "trusted")

        # Trusted porttan gelen meşru ACK paketi
        ack_pkt = DHCPPacket(
            op=BOOTREPLY,
            xid=0x888,
            yiaddr="192.168.1.105",
            chaddr=self.client_mac,
            options={OPT_DHCP_MESSAGE_TYPE: DHCP_ACK, OPT_LEASE_TIME: 86400}
        )
        allowed = switch.filter_packet("Gi0/1", ack_pkt)
        self.assertTrue(allowed)
        # Binding tablosunda istemci kaydı olmalıdır
        self.assertIn(self.client_mac, switch.binding_database)
        self.assertEqual(switch.binding_database[self.client_mac]["ip"], "192.168.1.105")
        self.assertEqual(switch.binding_database[self.client_mac]["port"], "Gi0/1")

    def test_10_negative_invalid_op_code(self) -> None:
        """Test 10 (Negatif): Geçersiz op kodunda (99) DHCPValidationError fırlatılması."""
        with self.assertRaises(DHCPValidationError) as ctx:
            DHCPPacket(op=99, chaddr=self.client_mac)
        self.assertIn("Gecersiz BOOTP op kodu", str(ctx.exception))

    def test_11_negative_invalid_hardware_fields(self) -> None:
        """Test 11 (Negatif): Geçersiz donanım tipi (htype!=1) veya uzunluğu (hlen!=6) kontrolü."""
        with self.assertRaises(DHCPValidationError):
            DHCPPacket(htype=0, chaddr=self.client_mac)
        with self.assertRaises(DHCPValidationError):
            DHCPPacket(hlen=12, chaddr=self.client_mac)

    def test_12_negative_invalid_magic_cookie(self) -> None:
        """Test 12 (Negatif): Geçersiz sihirli çerez (Magic Cookie) tespitinde hata üretilmesi."""
        bad_cookie = bytes([0x11, 0x22, 0x33, 0x44])
        with self.assertRaises(DHCPValidationError) as ctx:
            DHCPPacket(magic_cookie=bad_cookie, chaddr=self.client_mac)
        self.assertIn("Gecersiz DHCP Magic Cookie", str(ctx.exception))

    def test_13_negative_invalid_mac_format(self) -> None:
        """Test 13 (Negatif): Hatalı veya hex dışı karakter içeren MAC adreslerinin reddedilmesi."""
        with self.assertRaises(DHCPValidationError):
            DHCPPacket(chaddr="00:11:ZZ:44:55:66")
        with self.assertRaises(DHCPValidationError):
            DHCPPacket(chaddr="00:11:22")

    def test_14_negative_truncated_raw_packet(self) -> None:
        """Test 14 (Negatif): 236 bayt BOOTP başlığından kısa kesik veri akışının reddedilmesi."""
        short_bytes = b"\x01\x01\x06\x00" * 10  # 40 bayt
        with self.assertRaises(DHCPValidationError) as ctx:
            DHCPPacket.parse(short_bytes)
        self.assertIn("Paket uzunlugu yetersiz", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
