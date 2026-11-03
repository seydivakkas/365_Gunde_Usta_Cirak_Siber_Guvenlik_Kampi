"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli test ve sistem kütüphaneleri içe aktarılır
import hashlib
import sys
import unittest
from pathlib import Path

# Uygulama dizini sys.path'e dahil edilir
sys.path.insert(0, str(Path(__file__).parent.parent / "uygulama"))

# Motor sınıfları ve veri modelleri içe aktarılır
from disk_encryption_tpm_engine import (
    DiskEncryptionAuditor,
    VolumeEncryptionConfig,
    EncryptionAlgorithm,
    KeyProtectorType,
    KeyDerivationFunction,
    Tpm2Simulator,
    PhysicalAttackSimulator,
    PCR_ZERO_DIGEST
)


class TestDiskEncryptionAndTpm(unittest.TestCase):
    """Disk Şifreleme (BitLocker/LUKS) ve TPM 2.0 Güvenlik Motoru Birim Testleri (15 Test)."""

    def setUp(self) -> None:
        """Her testten önce standart kurumsal sertleştirilmiş bir yapılandırma hazırlar."""
        self.hardened_config = VolumeEncryptionConfig(
            volume_identifier="C:",
            os_type="windows",
            cipher_algorithm=EncryptionAlgorithm.XTS_AES_256,
            protectors=[KeyProtectorType.TPM_AND_PIN, KeyProtectorType.RECOVERY_PASSWORD],
            sealed_pcr_indices=[0, 2, 4, 7, 11],
            secure_boot_enabled=True,
            kernel_dma_protection=True,
            luks_kdf=KeyDerivationFunction.ARGON2ID,
            recovery_key_backed_up=True,
            plaintext_recovery_key_on_disk=False,
            pin_length=8
        )

    def test_01_clean_hardened_config_no_findings(self) -> None:
        """Test 1: Tam sertleştirilmiş BitLocker/TPM yapılandırması denetlendiğinde sıfır bulgu üretmelidir."""
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        self.assertEqual(len(findings), 0, "Sertleştirilmiş yapılandırmada sıfır bulgu beklenirken bulgular çıktı")

    def test_02_detect_plaintext_unencrypted_storage(self) -> None:
        """Test 2: Şifrelenmemiş (PLAINTEXT) disk birimi CRITICAL seviyesinde tespit edilmelidir."""
        self.hardened_config.cipher_algorithm = EncryptionAlgorithm.PLAINTEXT
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-ALGO-PLAINTEXT", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-ALGO-PLAINTEXT")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_03_detect_weak_cbc_mode_cipher(self) -> None:
        """Test 3: Zayıf CBC modu şifreleme (AES-CBC-256) kullanıldığında HIGH seviyesinde tespit edilmelidir."""
        self.hardened_config.cipher_algorithm = EncryptionAlgorithm.AES_CBC_256
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-ALGO-CBC-MODE", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-ALGO-CBC-MODE")
        self.assertEqual(finding.severity, "HIGH")

    def test_04_detect_tpm_only_without_pin(self) -> None:
        """Test 4: PIN içermeyen yalnızca TPM (TPM_ONLY) koruyucu HIGH seviyesinde tespit edilmelidir."""
        self.hardened_config.protectors = [KeyProtectorType.TPM_ONLY, KeyProtectorType.RECOVERY_PASSWORD]
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-PROT-TPM-NO-PIN", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-PROT-TPM-NO-PIN")
        self.assertEqual(finding.severity, "HIGH")

    def test_05_detect_missing_pcr_7_secure_boot(self) -> None:
        """Test 5: PCR 7 (Güvenli Önyükleme) mühür politikasında olmadığında CRITICAL seviyesinde alarm verilmelidir."""
        self.hardened_config.sealed_pcr_indices = [0, 2, 4]  # PCR 7 eksik
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-PCR-NO-SECUREBOOT", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-PCR-NO-SECUREBOOT")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_06_detect_missing_pcr_0_4_boot_integrity(self) -> None:
        """Test 6: Bellenim (PCR 0) ve önyükleyici (PCR 4) mühür listesinde olmadığında HIGH bulgu üretilmelidir."""
        self.hardened_config.sealed_pcr_indices = [7, 11]  # PCR 0 ve 4 eksik
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-PCR-MISSING-BOOT-INTEGRITY", rule_ids)

    def test_07_detect_secure_boot_disabled(self) -> None:
        """Test 7: UEFI Güvenli Önyükleme (Secure Boot) kapalı olduğunda CRITICAL bulgu tespit edilmelidir."""
        self.hardened_config.secure_boot_enabled = False
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-HW-SECUREBOOT-DISABLED", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-HW-SECUREBOOT-DISABLED")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_08_detect_missing_kernel_dma_protection(self) -> None:
        """Test 8: Çekirdek DMA Koruması (IOMMU) devre dışı olduğunda HIGH bulgu üretilmelidir."""
        self.hardened_config.kernel_dma_protection = False
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-HW-NO-DMA-PROTECTION", rule_ids)

    def test_09_detect_luks_weak_pbkdf2_kdf(self) -> None:
        """Test 9: Linux LUKS2 biriminde PBKDF2 kullanıldığında MEDIUM seviyesinde sapma bildirilmelidir."""
        self.hardened_config.os_type = "linux"
        self.hardened_config.luks_kdf = KeyDerivationFunction.PBKDF2
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-LUKS-WEAK-KDF", rule_ids)

    def test_10_detect_plaintext_recovery_key_on_disk(self) -> None:
        """Test 10: Kurtarma parolası yerel diskte düz metin saklandığında CRITICAL tespit edilmelidir."""
        self.hardened_config.plaintext_recovery_key_on_disk = True
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-KEY-PLAINTEXT-ON-DISK", rule_ids)
        finding = next(f for f in findings if f.rule_id == "ENC-KEY-PLAINTEXT-ON-DISK")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_11_detect_unbacked_up_recovery_key(self) -> None:
        """Test 11: Kurtarma anahtarı merkezi kasaya yedeklenmediğinde HIGH seviyesinde tespit edilmelidir."""
        self.hardened_config.recovery_key_backed_up = False
        auditor = DiskEncryptionAuditor(self.hardened_config)
        findings = auditor.audit_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("ENC-KEY-NO-CENTRAL-BACKUP", rule_ids)

    def test_12_tpm_pcr_extend_and_hash_chain(self) -> None:
        """Test 12: TPM PCR genişletme zinciri (Extend) matematiksel formüle göre doğrulanmalıdır."""
        tpm = Tpm2Simulator()
        self.assertEqual(tpm.pcrs[0].digest, PCR_ZERO_DIGEST)

        firmware_bytes = b"BIOS_VER_2.4.0_GENUINE"
        expected_measurement_hash = hashlib.sha256(firmware_bytes).digest()
        zero_bytes = bytes.fromhex(PCR_ZERO_DIGEST)
        expected_new_digest = hashlib.sha256(zero_bytes + expected_measurement_hash).hexdigest()

        actual_digest = tpm.extend_pcr(0, firmware_bytes)
        self.assertEqual(actual_digest, expected_new_digest)
        self.assertEqual(tpm.pcrs[0].digest, expected_new_digest)

    def test_13_tpm_sealing_and_legitimate_unsealing(self) -> None:
        """Test 13: Meşru PCR durumunda ve doğru PIN ile mühürlenmiş disk anahtarı başarıyla çözülmelidir."""
        tpm = Tpm2Simulator()
        tpm.extend_pcr(0, b"BIOS_CODE")
        tpm.extend_pcr(4, b"BOOTLOADER_CODE")
        tpm.extend_pcr(7, b"SECURE_BOOT_ON")

        master_key = "SECRET_FVEK_KEY_0x1122334455"
        pin = "987654"
        blob = tpm.seal_key(master_key, [0, 4, 7], user_pin=pin)

        res = tpm.unseal_key(blob, user_pin=pin)
        self.assertTrue(res.success)
        self.assertEqual(res.status_code, "TPM_SUCCESS")
        self.assertEqual(res.unsealed_key, master_key)

    def test_14_evil_maid_bootloader_tampering_blocks_unseal(self) -> None:
        """Test 14: Evil Maid saldırısında önyükleyici kurcalandığında (PCR 4) TPM kilidi devreye girmelidir."""
        tpm = Tpm2Simulator()
        tpm.extend_pcr(0, b"BIOS_CODE")
        tpm.extend_pcr(4, b"BOOTLOADER_CODE")
        tpm.extend_pcr(7, b"SECURE_BOOT_ON")

        master_key = "CRITICAL_SYSTEM_DISK_KEY"
        blob = tpm.seal_key(master_key, [0, 4, 7])

        attack_res = PhysicalAttackSimulator.simulate_evil_maid_bootloader_tampering(tpm, blob)
        self.assertFalse(attack_res.success)
        self.assertEqual(attack_res.status_code, "TPM_RC_PCR_CHANGED")
        self.assertIsNone(attack_res.unsealed_key)
        self.assertIn(4, attack_res.pcr_mismatches)

    def test_15_tpm_pin_auth_failure_and_secure_boot_tampering(self) -> None:
        """Test 15: Yanlış PIN girildiğinde ve Secure Boot (PCR 7) kurcalandığında anahtar çözülmemelidir."""
        tpm = Tpm2Simulator()
        tpm.extend_pcr(7, b"SECURE_BOOT_STATE_ON")

        master_key = "ENCRYPTED_OS_DRIVE_KEY"
        blob = tpm.seal_key(master_key, [7], user_pin="555444")

        # 1. Hatalı PIN denemesi
        pin_fail_res = tpm.unseal_key(blob, user_pin="000000")
        self.assertFalse(pin_fail_res.success)
        self.assertEqual(pin_fail_res.status_code, "TPM_RC_AUTH_FAIL")

        # 2. Secure boot manipülasyonu
        sb_attack_res = PhysicalAttackSimulator.simulate_secure_boot_tampering(tpm, blob)
        self.assertFalse(sb_attack_res.success)
        self.assertEqual(sb_attack_res.status_code, "TPM_RC_PCR_CHANGED")
        self.assertIn(7, sb_attack_res.pcr_mismatches)


if __name__ == "__main__":
    unittest.main()
