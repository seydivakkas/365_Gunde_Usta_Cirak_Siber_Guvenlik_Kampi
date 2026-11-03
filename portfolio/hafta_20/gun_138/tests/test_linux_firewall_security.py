# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Güvenlik Duvarı (nftables/UFW) Birim Testleri
Bu test paketi, LinuxFirewallSecurityEngine sınıfının Default Deny politikalarını,
durum denetimli (stateful) paket filtrelemeyi, loopback izolasyonunu, tehlikeli açık port
kontrollerini ve sınır durumlarını 15 birim test ile doğrular.
"""

# Birim test kütüphanesi dahil edilir
import unittest
# Dosya yolu ve sistem kütüphaneleri dahil edilir
import os
import sys

# Test edilecek motor ve sınıflar arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from linux_firewall_engine import LinuxFirewallSecurityEngine, FirewallConfiguration, FirewallRule


class TestLinuxFirewallSecurity(unittest.TestCase):
    """
    Güvenlik duvarı motorunun denetim yeteneklerini test eden sınıf.
    """

    def setUp(self) -> None:
        """
        Her test öncesi temiz bir motor örneği oluşturur.
        """
        self.engine = LinuxFirewallSecurityEngine()

    def test_01_fully_hardened_nftables_score_100(self) -> None:
        """
        Test 1: Tam sıkılaştırılmış nftables ortamı 100/100 tam puan almalı ve sıfır bulgu üretmelidir.
        """
        config = FirewallConfiguration(
            firewall_type="nftables",
            is_active=True,
            is_enabled_on_boot=True,
            input_policy="drop",
            forward_policy="drop",
            output_policy="accept",
            logging_enabled=True,
            loopback_accepted=True,
            loopback_spoof_drop=True,
            stateful_established_accepted=True,
            stateful_invalid_dropped=True,
            config_file_mode="0600",
            rules=[
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="10.0.0.0/8", dest_port="22"),
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="any", dest_port="80"),
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="any", dest_port="443")
            ]
        )

        report = self.engine.audit_firewall(config)
        self.assertEqual(report["guvenlik_skoru"], 100.0)
        self.assertEqual(report["toplam_bulgu"], 0)
        self.assertIn("GÜVENLİ", report["durum"])

    def test_02_fully_hardened_ufw_score_100(self) -> None:
        """
        Test 2: Tam sıkılaştırılmış UFW yapılandırması 100/100 tam puan almalıdır.
        """
        config = FirewallConfiguration(
            firewall_type="ufw",
            is_active=True,
            is_enabled_on_boot=True,
            input_policy="deny",
            forward_policy="deny",
            output_policy="accept",
            logging_enabled=True,
            loopback_accepted=True,
            loopback_spoof_drop=True,
            stateful_established_accepted=True,
            stateful_invalid_dropped=True,
            config_file_mode="0644",
            rules=[
                FirewallRule(chain="input", action="limit", protocol="tcp", source_ip="any", dest_port="22")
            ]
        )

        report = self.engine.audit_firewall(config)
        self.assertEqual(report["guvenlik_skoru"], 100.0)
        self.assertEqual(report["toplam_bulgu"], 0)

    def test_03_inactive_firewall_detection(self) -> None:
        """
        Test 3: Güvenlik duvarı durdurulmuşsa (is_active=False) FW-001 (CRITICAL) üretilmelidir.
        """
        config = FirewallConfiguration(is_active=False)
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-001", rule_ids)
        self.assertGreaterEqual(report["kritik_bulgu_sayisi"], 1)

    def test_04_disabled_on_boot_detection(self) -> None:
        """
        Test 4: Açılışta başlamayan güvenlik duvarında FW-001 üretilmelidir.
        """
        config = FirewallConfiguration(is_active=True, is_enabled_on_boot=False)
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-001", rule_ids)

    def test_05_input_policy_accept_violation(self) -> None:
        """
        Test 5: Varsayılan giriş politikası ACCEPT ise FW-002 (CRITICAL) tespit edilmelidir.
        """
        config = FirewallConfiguration(input_policy="accept")
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-002", rule_ids)

    def test_06_forward_policy_accept_violation(self) -> None:
        """
        Test 6: Varsayılan yönlendirme politikası ACCEPT ise FW-003 (HIGH) üretilmelidir.
        """
        config = FirewallConfiguration(forward_policy="accept")
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-003", rule_ids)

    def test_07_missing_stateful_inspection(self) -> None:
        """
        Test 7: Durum denetimli (conntrack) paket filtreleme kapalıysa FW-004 üretilmelidir.
        """
        config = FirewallConfiguration(
            stateful_established_accepted=False,
            stateful_invalid_dropped=False
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-004", rule_ids)

    def test_08_missing_loopback_isolation(self) -> None:
        """
        Test 8: Loopback kabul edilmiyor veya anti-spoofing eksikse FW-005 üretilmelidir.
        """
        config = FirewallConfiguration(
            loopback_accepted=False,
            loopback_spoof_drop=False
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-005", rule_ids)

    def test_09_open_dangerous_port_telnet(self) -> None:
        """
        Test 9: Telnet portu (23) tüm ağa açıksa FW-006 (HIGH) tespit edilmelidir.
        """
        config = FirewallConfiguration(
            rules=[
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="any", dest_port="23")
            ]
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-006", rule_ids)

    def test_10_open_dangerous_port_smb(self) -> None:
        """
        Test 10: SMB portu (445) tüm ağa açıksa FW-006 (HIGH) tespit edilmelidir.
        """
        config = FirewallConfiguration(
            rules=[
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="0.0.0.0/0", dest_port="445")
            ]
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-006", rule_ids)

    def test_11_restricted_port_not_flagged(self) -> None:
        """
        Test 11: Port erişimi belirli bir IP alt ağıyla sınırlandırılmışsa tehlikeli port uyarısı verilmemelidir.
        """
        config = FirewallConfiguration(
            rules=[
                FirewallRule(chain="input", action="accept", protocol="tcp", source_ip="192.168.1.0/24", dest_port="22")
            ]
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertNotIn("FW-006", rule_ids)

    def test_12_logging_disabled_detection(self) -> None:
        """
        Test 12: Güvenlik duvarı loglaması kapalıysa FW-007 (MEDIUM) üretilmelidir.
        """
        config = FirewallConfiguration(logging_enabled=False)
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-007", rule_ids)

    def test_13_loose_config_file_permissions(self) -> None:
        """
        Test 13: Güvenlik duvarı dosya izinleri 0666 ise FW-008 (LOW) tespit edilmelidir.
        """
        config = FirewallConfiguration(
            config_file_path="/etc/nftables.conf",
            config_file_mode="0666"
        )
        report = self.engine.audit_firewall(config)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("FW-008", rule_ids)

    def test_14_nftables_template_generation(self) -> None:
        """
        Test 14: generate_nftables_hardening_conf fonksiyonu CIS standartlarında kurallar üretmelidir.
        """
        tmpl = self.engine.generate_nftables_hardening_conf()
        self.assertIn("table inet filter", tmpl)
        self.assertIn("policy drop;", tmpl)
        self.assertIn("ct state established,related accept", tmpl)
        self.assertIn("ct state invalid drop", tmpl)
        self.assertIn("iif \"lo\" accept", tmpl)

    def test_15_ufw_remediation_generation(self) -> None:
        """
        Test 15: generate_ufw_hardening_script fonksiyonu geçerli UFW sertleştirme komutları üretmelidir.
        """
        script = self.engine.generate_ufw_hardening_script()
        self.assertIn("ufw default deny incoming", script)
        self.assertIn("ufw default deny routed", script)
        self.assertIn("ufw logging on", script)
        self.assertIn("ufw --force enable", script)


if __name__ == "__main__":
    unittest.main()
