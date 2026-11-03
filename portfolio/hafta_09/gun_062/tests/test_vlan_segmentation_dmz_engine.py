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
G062: VLAN, Segmentasyon ve DMZ Kapsamlı Test Paketi (14 Test).

Bu test paketi; IEEE 802.1Q etiket ayrıştırmasını, Access/Trunk port mantığını,
VLAN Hopping (Double Tagging & DTP Switch Spoofing) saldırı engellemelerini,
DMZ çevre ağı izolasyonunu ve Inter-VLAN güvenlik duvarı kurallarını doğrular.
"""

# Standart birim test kütüphanesini içe aktar
import unittest
# JSON yapılandırma dosyalarını okumak için json modülü
import json
# Dosya sistemi yolları için pathlib kütüphanesi
from pathlib import Path

# Test edilecek uygulama bileşenlerini ve hata sınıflarını içe aktar
from portfolio.hafta_09.gun_062.uygulama.vlan_segmentation_dmz_engine import (
    Dot1QTag,
    EthernetFrame,
    SwitchPort,
    ManagedSwitch,
    InterVLANFirewall,
    validate_mac_address,
    validate_vlan_id,
    parse_8021q_tag,
    build_8021q_tag,
    VLANValidationError,
    MalformedVLANFrameError,
    VLANHoppingAttackError,
    SwitchSpoofingError,
    InterVLANPolicyViolationError,
    VLANIngressViolationError,
    TrunkVLANNotAllowedError
)


class TestVLANSegmentationDMZEngine(unittest.TestCase):
    """VLAN, Segmentasyon ve DMZ Güvenlik Motoru Birim Testleri."""

    @classmethod
    def setUpClass(cls):
        """Test sınıfı başlatılırken örnek kuralları ve negatif senaryoları yükler."""
        # Geçerli test dosyasının bulunduğu dizini tespit et
        current_dir = Path(__file__).resolve().parent
        # Örnek veri dizinine erişim yolunu oluştur
        ornek_veri_dir = current_dir.parent / "ornek_veri"
        
        # Ağ kuralları ve topoloji verisini oku
        with open(ornek_veri_dir / "sample_vlan_dmz_rules.json", "r", encoding="utf-8") as f:
            cls.rules_data = json.load(f)
            
        # Negatif test senaryolarını oku
        with open(ornek_veri_dir / "invalid_vlan_inputs.json", "r", encoding="utf-8") as f:
            cls.invalid_data = json.load(f)

    def test_01_valid_8021q_tag_parsing(self):
        """Pozitif Test 1: Geçerli 4 baytlık IEEE 802.1Q etiketinin doğru ayrıştırılması."""
        # TPID 0x8100, PCP 5, DEI 0, VID 20 için ikili etiket oluştur
        tag_bytes = build_8021q_tag(vlan_id=20, pcp=5, dei=0)
        # 4 baytlık etiketi ayrıştır
        tag = parse_8021q_tag(tag_bytes)
        # TPID değerinin 0x8100 olduğunu doğrula
        self.assertEqual(tag.tpid, 0x8100)
        # PCP değerinin 5 olduğunu doğrula
        self.assertEqual(tag.pcp, 5)
        # DEI değerinin 0 olduğunu doğrula
        self.assertEqual(tag.dei, 0)
        # VLAN ID değerinin 20 olduğunu doğrula
        self.assertEqual(tag.vlan_id, 20)

    def test_02_negative_vlan_id_range_validation(self):
        """Negatif Test 2: IEEE 802.1Q sınır dışı (0, 4095, 5000) VLAN ID'lerinde hata üretilmesi."""
        # 0 (Öncelikli etiketleme - standart dışı)
        with self.assertRaises(VLANValidationError):
            validate_vlan_id(0)
        # 4095 (Rezerve VLAN ID)
        with self.assertRaises(VLANValidationError):
            validate_vlan_id(4095)
        # 5000 (12-bit sınır aşımı)
        with self.assertRaises(VLANValidationError):
            validate_vlan_id(5000)

    def test_03_negative_truncated_8021q_tag(self):
        """Negatif Test 3: 4 bayttan kısa kesilmiş etiket başlığında MalformedVLANFrameError."""
        # Yalnızca 2 baytlık eksik veri
        truncated = b"\x81\x00"
        with self.assertRaises(MalformedVLANFrameError) as ctx:
            parse_8021q_tag(truncated)
        self.assertIn("tam 4 bayt", str(ctx.exception))

    def test_04_mac_address_validation_positive_and_negative(self):
        """Pozitif ve Negatif Test 4: MAC adresi format doğrulaması."""
        # Geçerli MAC adresleri
        self.assertTrue(validate_mac_address("00:1A:2B:3C:4D:5E"))
        self.assertTrue(validate_mac_address("FF:FF:FF:FF:FF:FF"))
        
        # Geçersiz karakter veya blok sayılı MAC adresleri
        with self.assertRaises(VLANValidationError):
            validate_mac_address("00:11:22:33:GG:ZZ")
        with self.assertRaises(VLANValidationError):
            validate_mac_address("00:11:22:33:44")

    def test_05_access_port_normal_untagged_frame_forwarding(self):
        """Pozitif Test 5: Access porta gelen etiketsiz çerçevenin port VLAN'ına atanması."""
        # Anahtar oluştur ve Fa0/1 portunu VLAN 10 olarak yapılandır
        sw = ManagedSwitch(switch_id="SW-TEST-01")
        sw.configure_access_port(port_id="Fa0/1", vlan_id=10)
        
        # Etiketsiz standart Ethernet çerçevesi oluştur
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="00:AA:BB:CC:DD:EE", vlan_tags=[])
        res = sw.process_incoming_frame(ingress_port_id="Fa0/1", frame=frame)
        
        # Durumun ILETILDI olduğunu ve VLAN 10'a atandığını doğrula
        self.assertEqual(res["durum"], "ILETILDI")
        self.assertEqual(res["assigned_vlan"], 10)

    def test_06_negative_access_port_vlan_ingress_violation(self):
        """Negatif Test 6: Access porta yabancı etiketli paket geldiğinde VLANIngressViolationError."""
        sw = ManagedSwitch()
        sw.configure_access_port(port_id="Fa0/1", vlan_id=10)
        
        # Port VLAN 10 iken, içinde VLAN 20 etiketi taşıyan paket gönder
        tag_vlan20 = Dot1QTag(tpid=0x8100, pcp=0, dei=0, vlan_id=20)
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="00:AA:BB:CC:DD:EE", vlan_tags=[tag_vlan20])
        
        with self.assertRaises(VLANIngressViolationError) as ctx:
            sw.process_incoming_frame(ingress_port_id="Fa0/1", frame=frame)
        self.assertIn("farkli bir VLAN ID", str(ctx.exception))

    def test_07_trunk_port_tagged_frame_forwarding(self):
        """Pozitif Test 7: Trunk porttan izinli VLAN etiketli çerçevenin başarıyla geçişi."""
        sw = ManagedSwitch()
        # Gi0/1 trunk portu; izinli VLAN'lar: 10, 20, 30
        sw.configure_trunk_port(port_id="Gi0/1", native_vlan=99, allowed_vlans=[10, 20, 30])
        
        # VLAN 20 etiketli paket gönder
        tag_vlan20 = Dot1QTag(tpid=0x8100, pcp=0, dei=0, vlan_id=20)
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="00:AA:BB:CC:DD:EE", vlan_tags=[tag_vlan20])
        res = sw.process_incoming_frame(ingress_port_id="Gi0/1", frame=frame)
        
        # Çerçevenin VLAN 20 olarak iletildiğini doğrula
        self.assertEqual(res["durum"], "ILETILDI")
        self.assertEqual(res["assigned_vlan"], 20)

    def test_08_negative_trunk_port_disallowed_vlan(self):
        """Negatif Test 8: Trunk portun izinli listesinde olmayan VLAN'ın reddedilmesi."""
        sw = ManagedSwitch()
        sw.configure_trunk_port(port_id="Gi0/1", native_vlan=99, allowed_vlans=[10, 20, 30])
        
        # İzin verilmeyen VLAN 50 paketi gönder
        tag_vlan50 = Dot1QTag(tpid=0x8100, pcp=0, dei=0, vlan_id=50)
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="00:AA:BB:CC:DD:EE", vlan_tags=[tag_vlan50])
        
        with self.assertRaises(TrunkVLANNotAllowedError) as ctx:
            sw.process_incoming_frame(ingress_port_id="Gi0/1", frame=frame)
        self.assertIn("izinli VLAN listesinde", str(ctx.exception))

    def test_09_negative_double_tagging_vlan_hopping_detection(self):
        """Negatif Test 9: Çift 802.1Q etiketli VLAN Hopping saldırısının tespiti ve engellenmesi."""
        sw = ManagedSwitch()
        # Access port Fa0/1 (VLAN 10)
        sw.configure_access_port(port_id="Fa0/1", vlan_id=10)
        
        # Çift etiketli paket: Dış etiket Native/VLAN 10, İç etiket hedef VLAN 30 (Veritabanı)
        outer_tag = Dot1QTag(tpid=0x8100, pcp=0, dei=0, vlan_id=10)
        inner_tag = Dot1QTag(tpid=0x8100, pcp=0, dei=0, vlan_id=30)
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="00:AA:BB:CC:DD:EE", vlan_tags=[outer_tag, inner_tag])
        
        # VLANHoppingAttackError fırlatılmalıdır
        with self.assertRaises(VLANHoppingAttackError) as ctx:
            sw.process_incoming_frame(ingress_port_id="Fa0/1", frame=frame)
        self.assertIn("Double Tagging", str(ctx.exception))

    def test_10_negative_dtp_switch_spoofing_detection(self):
        """Negatif Test 10: Access porta DTP gönderildiğinde SwitchSpoofingError ve err-disable."""
        sw = ManagedSwitch()
        sw.configure_access_port(port_id="Fa0/1", vlan_id=10)
        
        # Access porta DTP paketi gönder
        frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="01:00:0C:CC:CC:CC")
        with self.assertRaises(SwitchSpoofingError) as ctx:
            sw.process_incoming_frame(ingress_port_id="Fa0/1", frame=frame, is_dtp_packet=True)
        self.assertIn("Switch Spoofing", str(ctx.exception))
        
        # Portun operasyonel durumunun ERR_DISABLED olduğunu doğrula
        self.assertEqual(sw.ports["Fa0/1"].operational_status, "ERR_DISABLED")

    def test_11_inter_vlan_firewall_permitted_rule(self):
        """Pozitif Test 11: DMZ'den (VLAN 20) Veritabanına (VLAN 30) port 5432 erişiminin kabulü."""
        fw = InterVLANFirewall(default_policy="DROP")
        fw.add_inter_vlan_rule(
            rule_id="RULE_DMZ_TO_DB",
            src_vlan=20,
            dst_vlan=30,
            allowed_ports=[5432],
            protocol="TCP",
            action="ACCEPT"
        )
        
        decision = fw.route_packet(src_vlan=20, dst_vlan=30, dst_port=5432, protocol="TCP")
        self.assertIn("ACCEPT", decision)

    def test_12_negative_dmz_to_internal_lateral_movement_block(self):
        """Negatif Test 12: DMZ'den (VLAN 20) İç Kullanıcı Ağına (VLAN 10) yanal yayılımın engeli."""
        fw = InterVLANFirewall(default_policy="DROP")
        
        # DMZ'deki ele geçirilmiş web sunucusunun iç ağa (VLAN 10) port 445 SMB erişim girişimi
        with self.assertRaises(InterVLANPolicyViolationError) as ctx:
            fw.route_packet(src_vlan=20, dst_vlan=10, dst_port=445, protocol="TCP")
        self.assertIn("Yanal Yayilim Korunmasi", str(ctx.exception))

    def test_13_negative_unauthorized_inter_vlan_port(self):
        """Negatif Test 13: İzin verilmeyen porta (ör. DMZ'den DB'ye port 22 SSH) erişimin reddi."""
        fw = InterVLANFirewall(default_policy="DROP")
        fw.add_inter_vlan_rule("RULE_DMZ_TO_DB", 20, 30, [5432], "TCP", "ACCEPT")
        
        # Port 22 erişim denemesi varsayılan DROP politikasıyla engellenmelidir
        with self.assertRaises(InterVLANPolicyViolationError) as ctx:
            fw.route_packet(src_vlan=20, dst_vlan=30, dst_port=22, protocol="TCP")
        self.assertIn("erisim kurali bulunamadi", str(ctx.exception))

    def test_14_broadcast_domain_isolation_simulation(self):
        """Pozitif Test 14: L2 Broadcast paketinin yalnızca aynı VLAN'daki portlara yayılması."""
        sw = ManagedSwitch()
        # VLAN 10'da Fa0/1 ve Fa0/2
        sw.configure_access_port("Fa0/1", vlan_id=10)
        sw.configure_access_port("Fa0/2", vlan_id=10)
        # VLAN 20'de Fa0/3
        sw.configure_access_port("Fa0/3", vlan_id=20)
        # VLAN 30'da Fa0/4
        sw.configure_access_port("Fa0/4", vlan_id=30)
        
        # Fa0/1 üzerinden Broadcast paketi gönder
        bcast_frame = EthernetFrame(src_mac="00:11:22:33:44:55", dst_mac="FF:FF:FF:FF:FF:FF")
        sim_res = sw.simulate_broadcast_flood(source_port_id="Fa0/1", frame=bcast_frame)
        
        # Paketin yalnızca Fa0/2'ye taştığını doğrula
        self.assertEqual(sim_res["flooded_ports"], ["Fa0/2"])
        # Diğer VLAN portlarının (Fa0/3, Fa0/4) kesinlikle izole kaldığını doğrula
        self.assertIn("Fa0/3", sim_res["isolated_ports"])
        self.assertIn("Fa0/4", sim_res["isolated_ports"])


if __name__ == "__main__":
    # Testleri detaylı çıktıyla çalıştır
    unittest.main()
