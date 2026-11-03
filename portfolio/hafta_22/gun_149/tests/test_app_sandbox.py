"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli test ve sistem kütüphaneleri içe aktarılır
import sys
import unittest
from pathlib import Path

# Uygulama dizini sys.path'e eklenir
sys.path.insert(0, str(Path(__file__).parent.parent / "uygulama"))

# Motor sınıfları ve veri modelleri içe aktarılır
from app_sandbox_engine import (
    AppSandboxEngine,
    SandboxProfile,
    SeccompAction,
    WindowsIntegrityLevel,
    NetworkIsolationMode,
    ResourceLimits,
    OciSeccompGenerator,
    SandboxRemediationGenerator,
    CRITICAL_MASKED_PATHS,
    DANGEROUS_SYSCALLS
)


class TestAppSandboxSecurity(unittest.TestCase):
    """Uygulama İzinleri ve Sandbox Güvenlik Motoru Birim Testleri (15 Test)."""

    def setUp(self) -> None:
        """Her testten önce tam sertleştirilmiş temel bir sandbox profili hazırlar."""
        # Engellenen sistem çağrıları sözlüğü hazırlanır
        blocked = {sc: SeccompAction.SCMP_ACT_ERRNO for sc in DANGEROUS_SYSCALLS.keys()}
        # İzin verilen temel sistem çağrıları kümesi
        allowed = {"read", "write", "openat", "close", "fstat", "mmap", "exit_group"}

        # Standart sertleştirilmiş profil başlatılır
        self.hardened_profile = SandboxProfile(
            profile_name="production_hardened_runner",
            os_family="linux",
            default_seccomp_action=SeccompAction.SCMP_ACT_ERRNO,
            allowed_syscalls=allowed,
            blocked_syscalls=blocked,
            granted_capabilities=set(),  # Sıfır yetenek (Drop all capabilities)
            read_only_root_fs=True,
            masked_paths=list(CRITICAL_MASKED_PATHS),
            network_mode=NetworkIsolationMode.DISCONNECTED,
            resource_limits=ResourceLimits(max_memory_mb=256, max_pids=32, cpu_quota_pct=25),
            windows_integrity_level=WindowsIntegrityLevel.LOW,
            windows_app_container=True,
            disabled_windows_privileges=["SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege"]
        )

    def test_01_clean_profile_audit_no_findings(self) -> None:
        """Test 1: Tam sertleştirilmiş profil denetlendiğinde hiçbir zafiyet veya sapma bulunmamalıdır."""
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        self.assertEqual(len(findings), 0, "Hardened profilde sıfır bulgu beklenirken bulgular çıktı")

    def test_02_detect_dangerous_cap_sys_admin(self) -> None:
        """Test 2: CAP_SYS_ADMIN yeteneği verildiğinde CRITICAL seviyesinde tespit edilmelidir."""
        self.hardened_profile.granted_capabilities.add("CAP_SYS_ADMIN")
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-CAP-SYS_ADMIN", rule_ids)
        cap_finding = next(f for f in findings if f.rule_id == "SBX-CAP-SYS_ADMIN")
        self.assertEqual(cap_finding.severity, "CRITICAL")

    def test_03_detect_dangerous_cap_net_raw(self) -> None:
        """Test 3: CAP_NET_RAW yeteneği verildiğinde HIGH seviyesinde tespit edilmelidir."""
        self.hardened_profile.granted_capabilities.add("CAP_NET_RAW")
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-CAP-NET_RAW", rule_ids)
        net_finding = next(f for f in findings if f.rule_id == "SBX-CAP-NET_RAW")
        self.assertEqual(net_finding.severity, "HIGH")

    def test_04_detect_seccomp_default_allow(self) -> None:
        """Test 4: Varsayılan Seccomp eylemi ALLOW olduğunda CRITICAL bulgu üretilmelidir."""
        self.hardened_profile.default_seccomp_action = SeccompAction.SCMP_ACT_ALLOW
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-SECCOMP-DEFAULT-ALLOW", rule_ids)

    def test_05_detect_unfiltered_ptrace_syscall(self) -> None:
        """Test 5: ptrace sistem çağrısı engellenmediğinde veya allowlist'e eklendiğinde CRITICAL tespit edilmelidir."""
        self.hardened_profile.allowed_syscalls.add("ptrace")
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-SYSCALL-PTRACE", rule_ids)

    def test_06_detect_unfiltered_bpf_syscall(self) -> None:
        """Test 6: bpf sistem çağrısı filtrelenmediğinde CRITICAL seviyesinde alarm verilmelidir."""
        self.hardened_profile.allowed_syscalls.add("bpf")
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-SYSCALL-BPF", rule_ids)

    def test_07_detect_writable_root_filesystem(self) -> None:
        """Test 7: Kök dosya sistemi yazılabilir olduğunda HIGH seviyesinde bulgu oluşmalıdır."""
        self.hardened_profile.read_only_root_fs = False
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-FS-WRITABLE-ROOT", rule_ids)

    def test_08_detect_unmasked_docker_socket(self) -> None:
        """Test 8: Kritik /var/run/docker.sock yolu maskelenmediğinde CRITICAL bulgu üretilmelidir."""
        self.hardened_profile.masked_paths.remove("/var/run/docker.sock")
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertTrue(any("docker.sock" in r or "var_run_docker.sock" in r for r in rule_ids))

    def test_09_detect_unrestricted_network(self) -> None:
        """Test 9: Ağ modu UNRESTRICTED olarak ayarlandığında HIGH seviyesinde tespit edilmelidir."""
        self.hardened_profile.network_mode = NetworkIsolationMode.UNRESTRICTED
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-NET-UNRESTRICTED", rule_ids)

    def test_10_detect_windows_high_integrity_level(self) -> None:
        """Test 10: Windows ortamında HIGH bütünlük seviyesi ayarlandığında CRITICAL tespit edilmelidir."""
        self.hardened_profile.os_family = "windows"
        self.hardened_profile.windows_integrity_level = WindowsIntegrityLevel.HIGH
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-WIN-HIGH-INTEGRITY", rule_ids)

    def test_11_detect_windows_missing_appcontainer(self) -> None:
        """Test 11: Windows ortamında AppContainer devre dışı bırakıldığında HIGH bulgu üretilmelidir."""
        self.hardened_profile.os_family = "windows"
        self.hardened_profile.windows_app_container = False
        engine = AppSandboxEngine(self.hardened_profile)
        findings = engine.audit_sandbox_security()
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("SBX-WIN-NO-APPCONTAINER", rule_ids)

    def test_12_simulation_blocks_ptrace_syscall(self) -> None:
        """Test 12: Simülasyonda ptrace sistem çağrısı seccomp filtresi tarafından engellenmelidir."""
        engine = AppSandboxEngine(self.hardened_profile)
        res = engine.simulate_execution("syscall", "ptrace")
        self.assertFalse(res.allowed)
        self.assertIn("SCMP_ACT_ERRNO", res.verdict)
        self.assertEqual(res.enforcing_layer, "Linux Seccomp-BPF")

    def test_13_simulation_blocks_unauthorized_capability(self) -> None:
        """Test 13: Sürece tahsis edilmemiş bir Linux yeteneği (CAP_SYS_ADMIN) istendiğinde EPERM ile reddedilmelidir."""
        engine = AppSandboxEngine(self.hardened_profile)
        res = engine.simulate_execution("capability", "CAP_SYS_ADMIN")
        self.assertFalse(res.allowed)
        self.assertIn("EPERM", res.verdict)

    def test_14_simulation_blocks_writable_root_and_masked_file(self) -> None:
        """Test 14: Salt-okunur kök sisteme yazma ve maskelenmiş yola (/proc/kcore) erişim engellenmelidir."""
        engine = AppSandboxEngine(self.hardened_profile)
        res_write = engine.simulate_execution("filesystem", "/etc/malicious.sh", {"mode": "write"})
        self.assertFalse(res_write.allowed)
        self.assertIn("EROFS", res_write.verdict)

        res_masked = engine.simulate_execution("filesystem", "/proc/kcore", {"mode": "read"})
        self.assertFalse(res_masked.allowed)
        self.assertIn("ENOENT", res_masked.verdict)

    def test_15_simulation_cgroups_fork_bomb_and_oci_generation(self) -> None:
        """Test 15: pids.max sınırını aşan fork bomb simülasyonu engellenmeli ve geçerli OCI Seccomp JSON üretilmelidir."""
        engine = AppSandboxEngine(self.hardened_profile)
        res_fork = engine.simulate_execution("process_fork", "bash", {"current_pids": 32})
        self.assertFalse(res_fork.allowed)
        self.assertIn("EAGAIN", res_fork.verdict)

        oci_doc = OciSeccompGenerator.generate_oci_seccomp_profile(self.hardened_profile)
        self.assertEqual(oci_doc["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertIn("SCMP_ARCH_X86_64", oci_doc["architectures"])
        self.assertTrue(len(oci_doc["syscalls"]) > 0)


if __name__ == "__main__":
    unittest.main()
