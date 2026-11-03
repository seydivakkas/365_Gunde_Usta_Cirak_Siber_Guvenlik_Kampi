# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirme Birim Testleri
Bu test paketi, LinuxSshSecurityEngine sınıfının anahtar izinlerini, kriptografik
dayanıklılık kontrollerini, sshd_config denetimlerini ve sınır durumlarını 15 birim test ile doğrular.
"""

# Birim test kütüphanesi dahil edilir
import unittest
# Dosya yolu ve sistem kütüphaneleri dahil edilir
import os
import sys

# Test edilecek motor ve sınıflar arama yoluna eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from linux_ssh_engine import LinuxSshSecurityEngine, SshKey, AuthorizedKeyEntry, SshdConfig


class TestLinuxSshSecurity(unittest.TestCase):
    """
    SSH güvenlik motorunun yeteneklerini test eden sınıf.
    """

    def setUp(self) -> None:
        """
        Her test öncesi temiz bir motor örneği oluşturur.
        """
        self.engine = LinuxSshSecurityEngine()

    def test_01_fully_hardened_environment_score_100(self) -> None:
        """
        Test 1: Tam sıkılaştırılmış SSH ortamında 0 bulgu ve 100/100 tam puan alınmalıdır.
        """
        # Güvenli Ed25519 anahtar
        secure_key = SshKey(
            name="id_ed25519",
            path="/home/deploy/.ssh/id_ed25519",
            key_type="ed25519",
            key_bits=256,
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0600",
            associated_user="deploy"
        )
        # Güvenli authorized_keys kaydı
        secure_auth = AuthorizedKeyEntry(
            user="deploy",
            key_type="ssh-ed25519",
            key_bits=256,
            comment="deploy@cluster",
            file_path="/home/deploy/.ssh/authorized_keys",
            file_mode="0600",
            file_owner="deploy"
        )
        # Sıkılaştırılmış sshd_config
        secure_sshd = SshdConfig(
            permit_root_login="no",
            password_authentication=False,
            pubkey_authentication=True,
            permit_empty_passwords=False,
            x11_forwarding=False,
            max_auth_tries=3,
            client_alive_interval=300,
            client_alive_count_max=2
        )

        report = self.engine.audit_environment([secure_key], [secure_auth], secure_sshd)

        self.assertEqual(report["guvenlik_skoru"], 100.0)
        self.assertEqual(report["toplam_bulgu"], 0)
        self.assertIn("GÜVENLİ", report["durum"])

    def test_02_loose_private_key_permissions(self) -> None:
        """
        Test 2: Özel anahtar 0644 modundaysa SSH-001 (CRITICAL / CWE-732) tespit edilmelidir.
        """
        insecure_key = SshKey(
            name="id_rsa",
            path="/home/dev/.ssh/id_rsa",
            key_type="rsa",
            key_bits=3072,
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0644"  # Gevşek izin
        )
        report = self.engine.audit_environment([insecure_key], [], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-001", rule_ids)
        self.assertGreaterEqual(report["kritik_bulgu_sayisi"], 1)

    def test_03_unprotected_private_key_passphrase(self) -> None:
        """
        Test 3: Şifresiz özel anahtar SSH-002 (MEDIUM / CWE-522) üretmelidir.
        """
        unprotected_key = SshKey(
            name="id_ed25519",
            path="/home/dev/.ssh/id_ed25519",
            key_type="ed25519",
            key_bits=256,
            is_private=True,
            is_passphrase_protected=False,  # Parolasız
            file_mode="0600"
        )
        report = self.engine.audit_environment([unprotected_key], [], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-002", rule_ids)

    def test_04_deprecated_dsa_key_detection(self) -> None:
        """
        Test 4: 1024-bit DSA anahtarı SSH-003 (CRITICAL / CWE-327) üretmelidir.
        """
        dsa_key = SshKey(
            name="id_dsa",
            path="/home/dev/.ssh/id_dsa",
            key_type="dsa",
            key_bits=1024,
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0600"
        )
        report = self.engine.audit_environment([dsa_key], [], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-003", rule_ids)

    def test_05_weak_rsa_key_length(self) -> None:
        """
        Test 5: 1024-bit RSA anahtarı SSH-004 (HIGH / CWE-326) üretmelidir.
        """
        weak_rsa = SshKey(
            name="id_rsa",
            path="/home/dev/.ssh/id_rsa",
            key_type="rsa",
            key_bits=1024,  # Yetersiz uzunluk
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0600"
        )
        report = self.engine.audit_environment([weak_rsa], [], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-004", rule_ids)

    def test_06_strong_rsa_key_accepted(self) -> None:
        """
        Test 6: 3072 veya 4096-bit RSA anahtarında zayıflık uyarısı verilmemelidir.
        """
        strong_rsa = SshKey(
            name="id_rsa",
            path="/home/dev/.ssh/id_rsa",
            key_type="rsa",
            key_bits=4096,
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0600"
        )
        report = self.engine.audit_environment([strong_rsa], [], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertNotIn("SSH-004", rule_ids)

    def test_07_loose_authorized_keys_permissions(self) -> None:
        """
        Test 7: authorized_keys dosyası 0666 ise SSH-005 (CRITICAL / CWE-732) üretilmelidir.
        """
        insecure_auth = AuthorizedKeyEntry(
            user="admin",
            key_type="ssh-ed25519",
            key_bits=256,
            file_path="/home/admin/.ssh/authorized_keys",
            file_mode="0666"  # Başkalarınca yazılabilir
        )
        report = self.engine.audit_environment([], [insecure_auth], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-005", rule_ids)

    def test_08_weak_key_in_authorized_keys(self) -> None:
        """
        Test 8: authorized_keys içinde ssh-dss anahtarı varsa SSH-006 üretilmelidir.
        """
        dsa_auth = AuthorizedKeyEntry(
            user="admin",
            key_type="ssh-dss",
            key_bits=1024,
            comment="old-dsa-key",
            file_path="/home/admin/.ssh/authorized_keys",
            file_mode="0600"
        )
        report = self.engine.audit_environment([], [dsa_auth], SshdConfig())
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-006", rule_ids)

    def test_09_sshd_permit_root_login_yes(self) -> None:
        """
        Test 9: PermitRootLogin yes ise SSH-007 (HIGH / CWE-250) tetiklenmelidir.
        """
        vuln_sshd = SshdConfig(permit_root_login="yes")
        report = self.engine.audit_environment([], [], vuln_sshd)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-007", rule_ids)

    def test_10_sshd_password_authentication_yes(self) -> None:
        """
        Test 10: PasswordAuthentication yes ise SSH-008 (HIGH / CWE-307) tetiklenmelidir.
        """
        vuln_sshd = SshdConfig(password_authentication=True)
        report = self.engine.audit_environment([], [], vuln_sshd)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-008", rule_ids)

    def test_11_sshd_permit_empty_passwords_yes(self) -> None:
        """
        Test 11: PermitEmptyPasswords yes ise SSH-009 (CRITICAL / CWE-258) tetiklenmelidir.
        """
        vuln_sshd = SshdConfig(permit_empty_passwords=True)
        report = self.engine.audit_environment([], [], vuln_sshd)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-009", rule_ids)

    def test_12_sshd_max_auth_tries_exceeded(self) -> None:
        """
        Test 12: MaxAuthTries > 4 ise SSH-010 (MEDIUM / CWE-307) tetiklenmelidir.
        """
        vuln_sshd = SshdConfig(max_auth_tries=8)
        report = self.engine.audit_environment([], [], vuln_sshd)
        rule_ids = [b["rule_id"] for b in report["bulgular"]]
        self.assertIn("SSH-010", rule_ids)

    def test_13_sshd_config_parser(self) -> None:
        """
        Test 13: parse_sshd_config ham OpenSSH yapılandırmasını doğru ayrıştırmalıdır.
        """
        raw_config = """
        # Global SSH Settings
        Port 2222
        PermitRootLogin no
        PasswordAuthentication no
        PubkeyAuthentication yes
        PermitEmptyPasswords no
        X11Forwarding no
        MaxAuthTries 3
        ClientAliveInterval 300
        ClientAliveCountMax 2
        """
        cfg = self.engine.parse_sshd_config(raw_config)
        self.assertEqual(cfg.port, 2222)
        self.assertEqual(cfg.permit_root_login, "no")
        self.assertFalse(cfg.password_authentication)
        self.assertTrue(cfg.pubkey_authentication)
        self.assertFalse(cfg.permit_empty_passwords)
        self.assertFalse(cfg.x11_forwarding)
        self.assertEqual(cfg.max_auth_tries, 3)
        self.assertEqual(cfg.client_alive_interval, 300)

    def test_14_remediation_script_generation(self) -> None:
        """
        Test 14: generate_remediation_script fonksiyonu geçerli Bash direktifleri üretmelidir.
        """
        bad_key = SshKey(
            name="id_rsa",
            path="/home/test/.ssh/id_rsa",
            key_type="rsa",
            key_bits=2048,
            is_private=True,
            is_passphrase_protected=True,
            file_mode="0644"
        )
        script = self.engine.generate_remediation_script([bad_key], [], SshdConfig())
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("chmod 0600 /home/test/.ssh/id_rsa", script)
        self.assertIn("PermitRootLogin no", script)
        self.assertIn("systemctl reload sshd", script)

    def test_15_hardened_sshd_template_generation(self) -> None:
        """
        Test 15: generate_hardened_sshd_config CIS standartlarında şablon üretmelidir.
        """
        template = self.engine.generate_hardened_sshd_config()
        self.assertIn("PermitRootLogin no", template)
        self.assertIn("PasswordAuthentication no", template)
        self.assertIn("PubkeyAuthentication yes", template)
        self.assertIn("KexAlgorithms curve25519-sha256", template)
        self.assertIn("Ciphers chacha20-poly1305@openssh.com", template)


if __name__ == "__main__":
    unittest.main()
