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
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Uygulama dizini sys.path'e dahil edilir
sys.path.insert(0, str(Path(__file__).parent.parent / "uygulama"))

# Motor sınıfları ve veri modelleri içe aktarılır
from backup_recovery_engine import (
    BackupRecoveryEngine,
    BackupPolicy,
    BackupArtifact,
    StorageMediaType,
    ImmutabilityMode,
    BackupType,
    RansomwareAttackSimulator,
    BackupHardeningRemediationGenerator
)


class TestBackupRecoverySecurity(unittest.TestCase):
    """Yedek Doğrulama ve Kurtarma Noktası Güvenlik Motoru Birim Testleri (15 Test)."""

    def setUp(self) -> None:
        """Her testten önce 3-2-1-1-0 standardına tam uyumlu bir yedekleme profili hazırlar."""
        # Standart kurumsal politika (RPO: 60 dk, RTO: 120 dk, 3 kopya, 2 ortam, Off-site, WORM)
        self.hardened_policy = BackupPolicy(
            policy_name="Enterprise_Tier1_Backup_Policy",
            target_rpo_minutes=60,
            target_rto_minutes=120,
            required_min_copies=3,
            required_min_media_types=2,
            require_offsite_copy=True,
            require_immutable_copy=True,
            max_verification_interval_days=30,
            enforce_vss_hardening=True
        )

        now = datetime.now(timezone.utc)
        recent_time = (now - timedelta(minutes=20)).isoformat()
        yesterday_time = (now - timedelta(days=1)).isoformat()
        verified_time = (now - timedelta(days=2)).isoformat()
        retention_time = (now + timedelta(days=30)).isoformat()

        # 1. Birincil Yerel Hızlı Kopya (NVMe)
        art1 = BackupArtifact(
            backup_id="BCK-PROD-NVME-001",
            created_at_utc=recent_time,
            backup_type=BackupType.INCREMENTAL,
            media_type=StorageMediaType.LOCAL_NVME,
            is_offsite=False,
            is_air_gapped=False,
            immutability_mode=ImmutabilityMode.NONE,
            retention_expiry_utc=None,
            size_mb=2500,
            sha256_checksum="a" * 64,
            is_corrupted=False,
            vss_shadow_protected=True,
            last_verified_at_utc=verified_time
        )

        # 2. İkincil Ağ Depolama Kopyası (NAS/SAN)
        art2 = BackupArtifact(
            backup_id="BCK-PROD-SAN-002",
            created_at_utc=yesterday_time,
            backup_type=BackupType.FULL,
            media_type=StorageMediaType.ENTERPRISE_SAN,
            is_offsite=False,
            is_air_gapped=False,
            immutability_mode=ImmutabilityMode.GOVERNANCE,
            retention_expiry_utc=retention_time,
            size_mb=50000,
            sha256_checksum="b" * 64,
            is_corrupted=False,
            vss_shadow_protected=True,
            last_verified_at_utc=verified_time
        )

        # 3. Üçüncül Bulut Değiştirilemez Kopyası (S3 Object Lock COMPLIANCE / WORM)
        art3 = BackupArtifact(
            backup_id="BCK-PROD-S3-WORM-003",
            created_at_utc=recent_time,
            backup_type=BackupType.INCREMENTAL,
            media_type=StorageMediaType.CLOUD_S3_OBJECT,
            is_offsite=True,
            is_air_gapped=False,
            immutability_mode=ImmutabilityMode.COMPLIANCE,
            retention_expiry_utc=retention_time,
            size_mb=2500,
            sha256_checksum="c" * 64,
            is_corrupted=False,
            vss_shadow_protected=True,
            last_verified_at_utc=verified_time
        )

        self.clean_artifacts = [art1, art2, art3]

    def test_01_clean_hardened_backup_audit_no_findings(self) -> None:
        """Test 1: Tam sertleştirilmiş 3-2-1 ve WORM yedekleme mimarisi denetlendiğinde sıfır bulgu üretmelidir."""
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        self.assertEqual(len(findings), 0, "Sertleştirilmiş yedeklemede sıfır bulgu beklenirken bulgular çıktı")

    def test_02_detect_insufficient_total_copies(self) -> None:
        """Test 2: Toplam kopya sayısı 3'ün altına düştüğünde CRITICAL seviyesinde tespit edilmelidir."""
        incomplete_artifacts = self.clean_artifacts[:2]  # Yalnızca 2 kopya
        engine = BackupRecoveryEngine(self.hardened_policy, incomplete_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-321-TOTAL-COPIES", rule_ids)
        finding = next(f for f in findings if f.rule_id == "BCK-321-TOTAL-COPIES")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_03_detect_insufficient_media_diversity(self) -> None:
        """Test 3: Tüm kopyalar tek bir depolama medyasına (örn: sadece NVMe) yazıldığında HIGH tespit edilmelidir."""
        for art in self.clean_artifacts:
            art.media_type = StorageMediaType.LOCAL_NVME
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-321-MEDIA-TYPES", rule_ids)
        finding = next(f for f in findings if f.rule_id == "BCK-321-MEDIA-TYPES")
        self.assertEqual(finding.severity, "HIGH")

    def test_04_detect_missing_offsite_copy(self) -> None:
        """Test 4: Saha dışı (Off-site / Cloud) kopya bulunmadığında CRITICAL seviyesinde tespit edilmelidir."""
        for art in self.clean_artifacts:
            art.is_offsite = False
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-321-NO-OFFSITE", rule_ids)
        finding = next(f for f in findings if f.rule_id == "BCK-321-NO-OFFSITE")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_05_detect_missing_immutable_worm(self) -> None:
        """Test 5: Değiştirilemez (WORM / Compliance) modda kopya olmadığında CRITICAL seviyesinde alarm verilmelidir."""
        for art in self.clean_artifacts:
            art.immutability_mode = ImmutabilityMode.NONE
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-IMMUTABLE-COMPLIANCE", rule_ids)
        finding = next(f for f in findings if f.rule_id == "BCK-IMMUTABLE-COMPLIANCE")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_06_detect_rpo_sla_breach(self) -> None:
        """Test 6: Son yedekten bu yana geçen süre RPO SLA hedefini (60 dk) aştığında HIGH tespit edilmelidir."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()
        for art in self.clean_artifacts:
            art.created_at_utc = old_time
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-RPO-BREACH", rule_ids)

    def test_07_detect_unverified_backups_staleness(self) -> None:
        """Test 7: Son geri yükleme doğrulama testi 30 günü geçtiğinde HIGH seviyesinde bulgu üretilmelidir."""
        stale_time = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        for art in self.clean_artifacts:
            art.last_verified_at_utc = stale_time
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-UNVERIFIED-TESTS", rule_ids)

    def test_08_detect_checksum_bit_rot_corruption(self) -> None:
        """Test 8: Sessiz veri bozulması (Bit rot) veya hash uyumsuzluğu tespit edildiğinde CRITICAL alarm verilmelidir."""
        self.clean_artifacts[0].is_corrupted = True
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-CHECKSUM-CORRUPTED", rule_ids)
        finding = next(f for f in findings if f.rule_id == "BCK-CHECKSUM-CORRUPTED")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_09_detect_unprotected_vss_shadows(self) -> None:
        """Test 9: Gölge kopyalar (VSS) fidye yazılımı silmelerine karşı korunmadığında HIGH bulgu üretilmelidir."""
        for art in self.clean_artifacts:
            art.vss_shadow_protected = False
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        findings = engine.audit_backup_architecture()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("BCK-VSS-UNPROTECTED", rule_ids)

    def test_10_restore_simulation_success_and_sla_compliance(self) -> None:
        """Test 10: Taze ve geçerli yedekten geri yükleme simülasyonu RPO ve RTO şartlarını sağlamalıdır."""
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        res = engine.simulate_recovery()
        self.assertTrue(res.success)
        self.assertEqual(res.status, "RECOVERY_SUCCESS")
        self.assertTrue(res.rpo_compliant)
        self.assertTrue(res.rto_compliant)
        self.assertTrue(res.checksum_verified)

    def test_11_restore_simulation_fails_when_all_corrupted(self) -> None:
        """Test 11: Mevcut tüm yedek arşivleri bozulduğunda geri yükleme simülasyonu başarısız olmalıdır."""
        for art in self.clean_artifacts:
            art.is_corrupted = True
        engine = BackupRecoveryEngine(self.hardened_policy, self.clean_artifacts)
        res = engine.simulate_recovery()
        self.assertFalse(res.success)
        self.assertEqual(res.status, "RANSOMWARE_WIPEOUT")

    def test_12_ransomware_simulation_wipes_unprotected_and_retains_worm(self) -> None:
        """Test 12: Fidye yazılımı saldırısında WORM Compliance yedek silinememeli, felaketten kurtuluş sağlanmalıdır."""
        surviving, summary = RansomwareAttackSimulator.simulate_attack(self.clean_artifacts)
        self.assertTrue(summary["ransomware_wipeout_resisted"])
        self.assertEqual(summary["surviving_backups"], 1)  # Yalnızca S3 COMPLIANCE hayatta kaldı
        self.assertEqual(surviving[0].immutability_mode, ImmutabilityMode.COMPLIANCE)

    def test_13_ransomware_simulation_complete_wipeout_when_no_worm(self) -> None:
        """Test 13: Değiştirilemez WORM koruması yoksa fidye yazılımı tüm yedekleri silmeli ve sistem çökmelidir."""
        for art in self.clean_artifacts:
            art.immutability_mode = ImmutabilityMode.NONE
            art.is_air_gapped = False
        surviving, summary = RansomwareAttackSimulator.simulate_attack(self.clean_artifacts)
        self.assertFalse(summary["ransomware_wipeout_resisted"])
        self.assertEqual(summary["surviving_backups"], 0)
        self.assertEqual(len(surviving), 0)

    def test_14_sha256_checksum_verification_math(self) -> None:
        """Test 14: Sentetik veri akışında SHA-256 sağlama toplamı doğrulaması ve bit bozulması tespiti yapılmalıdır."""
        data_block = b"CRITICAL_DATABASE_TRANSACTION_LOGS_20261108"
        expected_hash = hashlib.sha256(data_block).hexdigest()

        # Doğrulama: Temiz veri hash ile uyuşur
        actual_clean_hash = hashlib.sha256(data_block).hexdigest()
        self.assertEqual(actual_clean_hash, expected_hash)

        # Bozulma: 1 bitlik oynama hash'i tamamen bozar (Avalanche Effect)
        tampered_block = b"CRITICAL_DATABASE_TRANSACTION_LOGS_20261109"
        tampered_hash = hashlib.sha256(tampered_block).hexdigest()
        self.assertNotEqual(tampered_hash, expected_hash)

    def test_15_remediation_scripts_generation(self) -> None:
        """Test 15: Otomatik oluşturulan PowerShell ve Bash sertleştirme betikleri zorunlu komutları içermelidir."""
        ps1_script = BackupHardeningRemediationGenerator.generate_windows_vss_and_backup_hardening_script()
        self.assertIn("vssadmin", ps1_script)
        self.assertIn("icacls", ps1_script)
        self.assertIn("SHA256", ps1_script)

        sh_script = BackupHardeningRemediationGenerator.generate_linux_immutable_backup_script("test-vault")
        self.assertIn("COMPLIANCE", sh_script)
        self.assertIn("object-lock", sh_script)
        self.assertIn("sha256sum", sh_script)


if __name__ == "__main__":
    unittest.main()
