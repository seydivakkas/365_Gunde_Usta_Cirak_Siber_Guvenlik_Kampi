# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Servisleri ve Systemd Güvenliği Birim Testleri
Bu test takımı, LinuxSystemdSecurityEngine sınıfının sandboxing direktiflerini,
izin kontrollerini, exposure maruziyet hesaplarını ve sınır durumlarını 15 test ile doğrular.
"""

# Birim test çerçevesi unittest modülü içe aktarılır
import unittest
# Dosya ve sistem yolu işlemleri için os ve sys modülleri dahil edilir
import os
import sys

# Test edilecek motor ve veri sınıfları uygulama dizininden içe aktarılır
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from linux_systemd_engine import LinuxSystemdSecurityEngine, ServiceUnit, SecurityFinding


class TestLinuxSystemdSecurity(unittest.TestCase):
    """
    Systemd güvenlik motoru için kapsamlı birim test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her testten önce temiz bir motor örneği oluşturur.
        """
        # Test motoru başlatılır
        self.engine = LinuxSystemdSecurityEngine()

    def test_01_fully_hardened_service_score_100(self) -> None:
        """
        Test 1: Tam sıkılaştırılmış ve izole edilmiş bir servis 100/100 almalı ve sıfır bulgu üretmelidir.
        """
        # Tüm CIS ve sandboxing direktiflerine sahip güvenli servis tanımlanır
        secure_service = ServiceUnit(
            name="secure-api.service",
            path="/etc/systemd/system/secure-api.service",
            file_owner="root",
            file_group="root",
            file_mode="0644",
            user="apiuser",
            group="apiuser",
            exec_start="/usr/local/bin/api-server",
            binary_owner="root",
            binary_mode="0755",
            binary_suid=False,
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True,
            protect_kernel_tunables=True,
            protect_control_groups=True,
            capability_bounding_set=["CAP_NET_BIND_SERVICE"],
            restrict_address_families=["AF_INET", "AF_INET6"]
        )

        # Denetim icra edilir
        report = self.engine.audit_services([secure_service])

        # Skor 100.0 olmalı, bulgu sayısı 0 olmalıdır
        self.assertEqual(report["guvenlik_skoru"], 100.0)
        self.assertEqual(report["toplam_bulgu"], 0)
        self.assertIn("GÜVENLİ", report["durum"])
        # Exposure skoru 0.0 olmalıdır
        self.assertEqual(report["servis_detaylari"][0]["exposure_skoru"], 0.0)

    def test_02_legacy_insecure_service_detection(self) -> None:
        """
        Test 2: Aktif telnet.socket veya rsh.service gibi legacy servisler SYS-001 (CIS 2.1) üretmelidir.
        """
        # Telnet soket servisi tanımlanır
        telnet_unit = ServiceUnit(
            name="telnet.socket",
            path="/lib/systemd/system/telnet.socket",
            user="root",
            active=True,
            enabled=True,
            masked=False
        )

        # Denetim yapılır
        report = self.engine.audit_services([telnet_unit])

        # SYS-001 kuralının tetiklendiği kontrol edilir
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-001", rule_ids)
        self.assertGreater(report["toplam_bulgu"], 0)

    def test_03_legacy_masked_service_no_penalty(self) -> None:
        """
        Test 3: Telnet gibi servisler eğer 'masked=True' yapılmışsa risk üretmemelidir.
        """
        # Maskelenmiş telnet servisi
        masked_telnet = ServiceUnit(
            name="telnet.socket",
            path="/lib/systemd/system/telnet.socket",
            user="root",
            active=False,
            enabled=False,
            masked=True
        )

        report = self.engine.audit_services([masked_telnet])
        # Maskelenmiş serviste SYS-001 üretilmemelidir
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertNotIn("SYS-001", rule_ids)

    def test_04_loose_unit_file_permissions(self) -> None:
        """
        Test 4: Servis unit dosyası 0666 veya root dışı sahiplikteyse SYS-002 (CWE-732) tetiklenmelidir.
        """
        # Herkese yazılabilir unit dosyası
        vuln_unit = ServiceUnit(
            name="writable.service",
            path="/etc/systemd/system/writable.service",
            file_owner="nobody",
            file_mode="0666",
            user="appuser",
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([vuln_unit])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-002", rule_ids)
        # Kritik bulgu sayısı en az 1 olmalıdır
        self.assertGreaterEqual(report["kritik_bulgu_sayisi"], 1)

    def test_05_insecure_binary_suid_or_writable(self) -> None:
        """
        Test 5: ExecStart ikili dosyasında SUID bayrağı varsa SYS-003 (CRITICAL / T1548.001) tespit edilmelidir.
        """
        # SUID bayraklı ikili dosyaya sahip servis
        suid_service = ServiceUnit(
            name="suid-daemon.service",
            path="/etc/systemd/system/suid-daemon.service",
            user="appuser",
            binary_suid=True,
            binary_mode="4755",
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([suid_service])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-003", rule_ids)

    def test_06_running_as_root_or_missing_user(self) -> None:
        """
        Test 6: Serviste User= tanımlanmamışsa veya doğrudan root atanmışsa SYS-004 (CWE-250) tetiklenmelidir.
        """
        # User tanımlanmamış servis
        root_service = ServiceUnit(
            name="web-daemon.service",
            path="/etc/systemd/system/web-daemon.service",
            user="",  # Boş (systemd varsayılanı root)
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([root_service])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-004", rule_ids)

    def test_07_missing_no_new_privileges(self) -> None:
        """
        Test 7: NoNewPrivileges=false iken SYS-005 (HIGH / T1548) kuralı devreye girmelidir.
        """
        no_nnp_service = ServiceUnit(
            name="test-privs.service",
            path="/etc/systemd/system/test-privs.service",
            user="appuser",
            no_new_privileges=False,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([no_nnp_service])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-005", rule_ids)

    def test_08_missing_protect_system(self) -> None:
        """
        Test 8: ProtectSystem tanımsız veya 'no' ise SYS-006 (CWE-732) tespit edilmelidir.
        """
        unprot_system = ServiceUnit(
            name="db-service.service",
            path="/etc/systemd/system/db-service.service",
            user="appuser",
            no_new_privileges=True,
            protect_system="no",
            protect_home="yes",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([unprot_system])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-006", rule_ids)

    def test_09_missing_protect_home(self) -> None:
        """
        Test 9: ProtectHome tanımsız veya 'no' ise SYS-007 (CWE-200) tespit edilmelidir.
        """
        unprot_home = ServiceUnit(
            name="report-svc.service",
            path="/etc/systemd/system/report-svc.service",
            user="appuser",
            no_new_privileges=True,
            protect_system="strict",
            protect_home="",
            private_tmp=True,
            private_devices=True
        )

        report = self.engine.audit_services([unprot_home])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-007", rule_ids)

    def test_10_missing_private_tmp_and_devices(self) -> None:
        """
        Test 10: PrivateTmp ve PrivateDevices bayrakları eksikse SYS-008 ve SYS-009 üretilmelidir.
        """
        unisolated_svc = ServiceUnit(
            name="worker.service",
            path="/etc/systemd/system/worker.service",
            user="appuser",
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=False,
            private_devices=False
        )

        report = self.engine.audit_services([unisolated_svc])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-008", rule_ids)
        self.assertIn("SYS-009", rule_ids)

    def test_11_dangerous_capabilities_detection(self) -> None:
        """
        Test 11: CapabilityBoundingSet içinde CAP_SYS_ADMIN veya CAP_SYS_PTRACE varsa SYS-010 üretilmelidir.
        """
        cap_service = ServiceUnit(
            name="privileged-agent.service",
            path="/etc/systemd/system/privileged-agent.service",
            user="appuser",
            no_new_privileges=True,
            protect_system="strict",
            protect_home="yes",
            private_tmp=True,
            private_devices=True,
            capability_bounding_set=["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]
        )

        report = self.engine.audit_services([cap_service])
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SYS-010", rule_ids)

    def test_12_unit_file_parser_ini_format(self) -> None:
        """
        Test 12: Ham .service dosya metnini parse_unit_file fonksiyonu hatasız ayrıştırmalıdır.
        """
        raw_content = """
        [Unit]
        Description=My Custom Backend Service
        After=network.target

        [Service]
        Type=simple
        User=customuser
        Group=customgroup
        ExecStart=/opt/custom/bin/daemon --port 8080
        NoNewPrivileges=yes
        ProtectSystem=strict
        ProtectHome=yes
        PrivateTmp=yes
        PrivateDevices=yes
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        """

        unit = self.engine.parse_unit_file(raw_content, service_name="custom.service")

        self.assertEqual(unit.name, "custom.service")
        self.assertEqual(unit.description, "My Custom Backend Service")
        self.assertEqual(unit.user, "customuser")
        self.assertEqual(unit.group, "customgroup")
        self.assertTrue(unit.no_new_privileges)
        self.assertEqual(unit.protect_system, "strict")
        self.assertEqual(unit.protect_home, "yes")
        self.assertTrue(unit.private_tmp)
        self.assertTrue(unit.private_devices)
        self.assertIn("CAP_NET_BIND_SERVICE", unit.capability_bounding_set)

    def test_13_remediation_script_generation(self) -> None:
        """
        Test 13: generate_remediation_script fonksiyonu geçerli Bash direktifleri üretmelidir.
        """
        vuln_unit = ServiceUnit(
            name="insecure-app.service",
            path="/etc/systemd/system/insecure-app.service",
            file_mode="0666",
            user="root",
            exec_start="/usr/local/bin/app",
            no_new_privileges=False,
            protect_system="no"
        )
        legacy_unit = ServiceUnit(
            name="telnet.socket",
            path="/lib/systemd/system/telnet.socket",
            active=True
        )

        script = self.engine.generate_remediation_script([vuln_unit, legacy_unit])

        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("systemctl mask telnet.socket", script)
        self.assertIn("chmod 0644 /etc/systemd/system/insecure-app.service", script)
        self.assertIn("NoNewPrivileges=yes", script)
        self.assertIn("systemctl daemon-reload", script)

    def test_14_secure_template_generation(self) -> None:
        """
        Test 14: generate_secure_unit_template CIS uyumlu güvenlik şablonu oluşturmalıdır.
        """
        template = self.engine.generate_secure_unit_template(
            service_name="payment-gateway.service",
            exec_path="/usr/local/bin/payment-gw",
            user="payuser"
        )

        self.assertIn("[Service]", template)
        self.assertIn("User=payuser", template)
        self.assertIn("NoNewPrivileges=yes", template)
        self.assertIn("ProtectSystem=strict", template)
        self.assertIn("ProtectHome=yes", template)
        self.assertIn("PrivateTmp=yes", template)
        self.assertIn("PrivateDevices=yes", template)

    def test_15_empty_services_boundary_condition(self) -> None:
        """
        Test 15: Boş servis listesi verildiğinde sistem istisna fırlatmadan varsayılan rapor üretmelidir.
        """
        report = self.engine.audit_services([])

        self.assertEqual(report["toplam_servis"], 0)
        self.assertEqual(report["guvenlik_skoru"], 0.0)
        self.assertIn("KRİTİK RİSK", report["durum"])


if __name__ == "__main__":
    unittest.main()
