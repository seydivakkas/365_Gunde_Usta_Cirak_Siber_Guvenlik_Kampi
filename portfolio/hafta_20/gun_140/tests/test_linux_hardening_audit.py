# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 20 / Gün 140 - Mini Proje 19: Linux Sertleştirme Kontrolü Birim Test Paketi.
15 kapsamlı birim testi ile motorun tüm denetim kurallarını, sınır durumlarını
ve negatif zafiyet senaryolarını titizlikle doğrular.
"""

# Test modülü için standart Python unittest kütüphanesi
import unittest
# Dosya yolları ve işletim sistemi fonksiyonları
import os
# Sistem çalışma yolu yönetimi
import sys
# JSON verisi manipülasyonu
import json
# Geçici dosya ve dizin oluşturma desteği
import tempfile

# Uygulama kaynak kod dizinini sys.path içerisine ekle
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.abspath(os.path.join(current_dir, "..", "uygulama"))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

# Denetim motoru sınıfını import et
from linux_hardening_audit_engine import LinuxHardeningAuditEngine, OverallHardeningReport


class TestLinuxHardeningAuditEngine(unittest.TestCase):
    """
    Linux Sertleştirme ve Denetim Motoru test sınıfı.
    """

    def setUp(self):
        """
        Her birim testinden önce çalıştırılarak temiz referans verisi hazırlar.
        """
        # Standart referans envanter yolu
        self.ref_inventory_path = os.path.abspath(os.path.join(current_dir, "..", "ornek_veri", "enterprise_linux_audit_inventory.json"))
        # Motoru ilklendir
        self.engine = LinuxHardeningAuditEngine()
        if os.path.exists(self.ref_inventory_path):
            self.engine.load_inventory_from_file(self.ref_inventory_path)

    def test_01_load_inventory_valid(self):
        """Test 01: Geçerli envanter dosyasının doğru şekilde belleğe yüklenmesini doğrular."""
        self.assertIsNotNone(self.engine.inventory)
        self.assertEqual(self.engine.inventory["host_info"]["hostname"], "prod-sec-node01.corp.internal")

    def test_02_load_inventory_missing_file(self):
        """Test 02: Olmayan bir dosya yüklendiğinde FileNotFoundError fırlatıldığını doğrular."""
        dummy_engine = LinuxHardeningAuditEngine()
        with self.assertRaises(FileNotFoundError):
            dummy_engine.load_inventory_from_file("gecersiz_olmayan_dosya.json")

    def test_03_audit_sudo_security_pass(self):
        """Test 03: Güvenli sudo yapılandırmasının %100 puan ile PASS aldığını doğrular."""
        sudo_res = self.engine.audit_sudo_security()
        self.assertEqual(sudo_res.score, 100.0)
        self.assertEqual(sudo_res.failed_checks, 0)
        self.assertEqual(sudo_res.passed_checks, 4)

    def test_04_audit_sudo_security_fail_nopasswd_escape(self):
        """Test 04: NOPASSWD /bin/bash kabuk yetkisinin tespit edilip FAIL verildiğini doğrular."""
        self.engine.inventory["sudo_spec"]["rules"] = ["developer ALL=(ALL) NOPASSWD: /bin/bash"]
        sudo_res = self.engine.audit_sudo_security()
        self.assertGreater(sudo_res.failed_checks, 0)
        finding = next(f for f in sudo_res.findings if f.rule_id == "CIS-1.3.4")
        self.assertEqual(finding.status, "FAIL")

    def test_05_audit_pam_pwquality_pass(self):
        """Test 05: Güçlü pam_pwquality politikasının başarıyla doğrulandığını test eder."""
        pam_res = self.engine.audit_pam_session_security()
        self.assertEqual(pam_res.score, 100.0)
        minlen_finding = next(f for f in pam_res.findings if f.rule_id == "CIS-5.4.1")
        self.assertEqual(minlen_finding.status, "PASS")

    def test_06_audit_pam_faillock_fail(self):
        """Test 06: Gevşek hesap kilitleme değerlerinin (deny=20) FAIL olarak işaretlendiğini doğrular."""
        self.engine.inventory["pam_spec"]["faillock"]["deny"] = 20
        pam_res = self.engine.audit_pam_session_security()
        finding = next(f for f in pam_res.findings if f.rule_id == "CIS-5.4.3")
        self.assertEqual(finding.status, "FAIL")

    def test_07_audit_systemd_prohibited_services(self):
        """Test 07: Yasaklanmış servislerin (telnet) varlığında FAIL üretildiğini test eder."""
        self.engine.inventory["systemd_spec"]["running_services"].append("telnet")
        sys_res = self.engine.audit_systemd_services()
        finding = next(f for f in sys_res.findings if f.rule_id == "CIS-2.1.1")
        self.assertEqual(finding.status, "FAIL")

    def test_08_audit_systemd_sandboxing_pass_and_fail(self):
        """Test 08: Systemd servislerinde sandboxing direktiflerinin varlığını doğrular."""
        # Varsayılan durumda PASS
        sys_res = self.engine.audit_systemd_services()
        self.assertEqual(sys_res.score, 100.0)

        # İzolasyonu boz ve FAIL al
        self.engine.inventory["systemd_spec"]["monitored_units"]["api_gateway.service"]["NoNewPrivileges"] = False
        sys_res_fail = self.engine.audit_systemd_services()
        finding = next(f for f in sys_res_fail.findings if f.rule_id == "CIS-2.2.1")
        self.assertEqual(finding.status, "FAIL")

    def test_09_audit_ssh_security_pass(self):
        """Test 09: Güvenli SSH yapılandırmasının (PermitRootLogin no, PasswordAuthentication no) doğrulandığını test eder."""
        ssh_res = self.engine.audit_ssh_security()
        self.assertEqual(ssh_res.score, 100.0)
        self.assertEqual(ssh_res.failed_checks, 0)

    def test_10_audit_ssh_private_key_permissions(self):
        """Test 10: Güvensiz özel anahtar dosya izninin (0644) FAIL olarak yakalandığını test eder."""
        self.engine.inventory["ssh_spec"]["private_key_mode"] = "0644"
        ssh_res = self.engine.audit_ssh_security()
        finding = next(f for f in ssh_res.findings if f.rule_id == "CIS-5.2.4")
        self.assertEqual(finding.status, "FAIL")

    def test_11_audit_firewall_default_policy(self):
        """Test 11: Güvenlik duvarı varsayılan politikası DROP olduğunda PASS, ACCEPT olduğunda FAIL olduğunu test eder."""
        # İlk durumda PASS
        fw_res = self.engine.audit_firewall_security()
        self.assertEqual(fw_res.score, 100.0)

        # ACCEPT yap ve FAIL bekle
        self.engine.inventory["firewall_spec"]["default_input_policy"] = "ACCEPT"
        fw_res_fail = self.engine.audit_firewall_security()
        finding = next(f for f in fw_res_fail.findings if f.rule_id == "CIS-3.4.2")
        self.assertEqual(finding.status, "FAIL")

    def test_12_audit_firewall_dangerous_ports(self):
        """Test 12: Güvenlik duvarında açık olan tehlikeli portların (21/FTP) tespit edildiğini test eder."""
        self.engine.inventory["firewall_spec"]["listening_ports"].append(21)
        fw_res = self.engine.audit_firewall_security()
        finding = next(f for f in fw_res.findings if f.rule_id == "CIS-3.4.4")
        self.assertEqual(finding.status, "FAIL")

    def test_13_audit_logging_immutable_and_fss(self):
        """Test 13: Audit -e 2 ve journald FSS kriptografik mühürlemesinin doğrulandığını test eder."""
        log_res = self.engine.audit_logging_security()
        self.assertEqual(log_res.score, 100.0)
        imm_finding = next(f for f in log_res.findings if f.rule_id == "CIS-4.1.18")
        fss_finding = next(f for f in log_res.findings if f.rule_id == "CIS-4.2.1")
        self.assertEqual(imm_finding.status, "PASS")
        self.assertEqual(fss_finding.status, "PASS")

    def test_14_full_hardening_audit_score_and_status(self):
        """Test 14: Tam sistem denetiminde genel uyumluluk puanının ve COMPLIANT durumunun hesaplanmasını test eder."""
        report = self.engine.run_full_hardening_audit()
        self.assertEqual(report.compliance_score, 100.0)
        self.assertEqual(report.overall_status, "COMPLIANT")
        self.assertEqual(report.summary_counts["failed_checks"], 0)
        self.assertEqual(len(report.domain_results), 6)

    def test_15_generate_remediation_script(self):
        """Test 15: Otomatik Bash sıkılaştırma betiğinin hatasız üretildiğini ve chmod/sed komutlarını içerdiğini doğrular."""
        # Birkaç kontrolü bilinçli olarak FAIL yap
        self.engine.inventory["sudo_spec"]["file_mode"] = "0777"
        self.engine.inventory["ssh_spec"]["sshd_config"]["PermitRootLogin"] = "yes"
        self.engine.inventory["firewall_spec"]["active"] = False

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".sh") as tmp:
            tmp_path = tmp.name

        try:
            content = self.engine.generate_remediation_script(output_path=tmp_path)
            self.assertIn("chmod 0440 /etc/sudoers", content)
            self.assertIn("PermitRootLogin no", content)
            self.assertIn("systemctl enable --now nftables", content)
            self.assertTrue(os.path.exists(tmp_path))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
