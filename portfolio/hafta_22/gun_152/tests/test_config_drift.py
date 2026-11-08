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

# Uygulama dizini sys.path'e dahil edilir
sys.path.insert(0, str(Path(__file__).parent.parent / "uygulama"))

# Motor sınıfları ve veri modelleri içe aktarılır
from config_drift_engine import (
    ConfigDriftAuditor,
    AutoRemediationEngine,
    ConfigRule,
    SettingType,
    SeverityLevel
)


class TestConfigDriftEngine(unittest.TestCase):
    """Güvenli Yapılandırma Sapması (Configuration Drift) Birim Testleri (15 Test)."""

    def setUp(self) -> None:
        """Her testten önce standart kurumsal CIS/DISA güvenlik temel hattını hazırlar."""
        self.rules = [
            ConfigRule(
                rule_id="CIS-WIN-1.1",
                setting_type=SettingType.REGISTRY,
                target_key="HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
                expected_value=1,
                severity=SeverityLevel.CRITICAL,
                title="Kullanıcı Hesabı Denetimi (UAC) Etkin Olmalıdır",
                compliance_ref="CIS Windows 11 Benchmark 2.3.17.1",
                description="UAC kapatıldığında zararlı yazılımlar yönetici haklarını sessizce ele geçirebilir.",
                remediation_cmd_ps1="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.2",
                setting_type=SettingType.REGISTRY,
                target_key="HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
                expected_value=0,
                severity=SeverityLevel.CRITICAL,
                title="Microsoft Defender Gerçek Zamanlı Koruma Açık Olmalıdır",
                compliance_ref="CIS Windows 11 Benchmark 18.9.46.1",
                description="Gerçek zamanlı koruma kapatıldığında kötü amaçlı yazılımlar diskte serbestçe çalışır.",
                remediation_cmd_ps1="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Value 0 -Type DWord"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.3",
                setting_type=SettingType.REGISTRY,
                target_key="HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL",
                expected_value=1,
                severity=SeverityLevel.HIGH,
                title="LSA Koruma Modu (RunAsPPL) Açık Olmalıdır",
                compliance_ref="Microsoft Security Baseline / Credential Guard",
                description="LSA koruması kapalıyken Mimikatz gibi araçlar LSASS belleğinden NTLM/Kerberos biletlerini çalabilir.",
                remediation_cmd_ps1="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.4",
                setting_type=SettingType.LOCAL_USER_GROUP,
                target_key="Administrators_Members",
                expected_value=["Administrator", "Domain Admins"],
                severity=SeverityLevel.CRITICAL,
                title="Yerel Yöneticiler Grubunda Yalnızca Onaylı Hesaplar Bulunmalıdır",
                compliance_ref="CIS Controls v8 5.4 / Least Privilege",
                description="Yetkisiz bir hesabın local admin yapılması doğrudan kalıcılık (persistence) veya yetki yükseltme göstergesidir.",
                remediation_cmd_ps1="Remove-LocalGroupMember -Group 'Administrators' -Member 'backdoor_admin'"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.5",
                setting_type=SettingType.FIREWALL_RULE,
                target_key="DomainProfile_Enabled",
                expected_value=True,
                severity=SeverityLevel.HIGH,
                title="Windows Güvenlik Duvarı Etki Alanı Profili Açık Olmalıdır",
                compliance_ref="CIS Benchmark 9.1.1",
                description="Güvenlik duvarı kapalıyken gelen yetkisiz ağ bağlantıları filtrelenemez.",
                remediation_cmd_ps1="Set-NetFirewallProfile -Profile Domain -Enabled True"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.6",
                setting_type=SettingType.SECURITY_POLICY,
                target_key="MinimumPasswordLength",
                expected_value=14,
                severity=SeverityLevel.HIGH,
                title="Minimum Parola Uzunluğu En Az 14 Karakter Olmalıdır",
                compliance_ref="DISA STIG WN11-AC-000010",
                description="Kısa parolalar kaba kuvvet (brute-force) ve gökkuşağı tablosu ataklarıyla kolayca kırılabilir.",
                remediation_cmd_ps1="net accounts /minpwlen:14"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.7",
                setting_type=SettingType.SECURITY_POLICY,
                target_key="AccountLockoutThreshold",
                expected_value=5,
                severity=SeverityLevel.HIGH,
                title="Hesap Kilitleme Eşiği 5 Deneme Olarak Ayarlanmalıdır",
                compliance_ref="CIS Benchmark 1.1.1",
                description="Hesap kilitleme kapalıyken saldırganlar sınırsız parola denemesi yapabilir.",
                remediation_cmd_ps1="net accounts /lockoutthreshold:5"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.8",
                setting_type=SettingType.SECURITY_POLICY,
                target_key="GuestAccountStatus",
                expected_value="Disabled",
                severity=SeverityLevel.MEDIUM,
                title="Konuk (Guest) Hesabı Devre Dışı Bırakılmalıdır",
                compliance_ref="CIS Benchmark 2.3.1.1",
                description="Konuk hesabı aktif bırakıldığında parolasız anonim erişime izin verilebilir.",
                remediation_cmd_ps1="net user Guest /active:no"
            ),
            ConfigRule(
                rule_id="CIS-WIN-1.9",
                setting_type=SettingType.SERVICE_STATE,
                target_key="RemoteRegistry_Service",
                expected_value="Stopped",
                severity=SeverityLevel.MEDIUM,
                title="RemoteRegistry Servisi Durdurulmuş Olmalıdır",
                compliance_ref="CIS Benchmark 5.18",
                description="Uzak kayıt defteri servisi ağ üzerinden kayıt defteri kurcalamalarına zemin hazırlar.",
                remediation_cmd_ps1="Stop-Service -Name RemoteRegistry; Set-Service -Name RemoteRegistry -StartupType Disabled"
            ),
            ConfigRule(
                rule_id="CIS-LNX-2.1",
                setting_type=SettingType.LINUX_SYSCTL,
                target_key="net.ipv4.ip_forward",
                expected_value=0,
                severity=SeverityLevel.HIGH,
                title="IP Yönlendirme (IP Forwarding) Devre Dışı Olmalıdır",
                compliance_ref="CIS Linux Benchmark 3.1.1",
                description="Yönlendirici olmayan bir uç noktada IP yönlendirmenin açık olması ağ atlama riskine yol açar.",
                remediation_cmd_bash="sysctl -w net.ipv4.ip_forward=0"
            ),
            ConfigRule(
                rule_id="CIS-LNX-2.2",
                setting_type=SettingType.LINUX_SYSCTL,
                target_key="kernel.randomize_va_space",
                expected_value=2,
                severity=SeverityLevel.CRITICAL,
                title="Adres Alanı Düzeni Rastgeleleştirme (ASLR) Tam Açık Olmalıdır",
                compliance_ref="CIS Linux Benchmark 1.5.3",
                description="ASLR kapalı olduğunda bellek taşması (buffer overflow) istismarları deterministik hale gelir.",
                remediation_cmd_bash="sysctl -w kernel.randomize_va_space=2"
            )
        ]

        # Temel hatla %100 uyumlu temiz uç nokta durumu
        self.clean_state = {
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA": 1,
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring": 0,
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL": 1,
            "Administrators_Members": ["Administrator", "Domain Admins"],
            "DomainProfile_Enabled": True,
            "MinimumPasswordLength": 14,
            "AccountLockoutThreshold": 5,
            "GuestAccountStatus": "Disabled",
            "RemoteRegistry_Service": "Stopped",
            "net.ipv4.ip_forward": 0,
            "kernel.randomize_va_space": 2
        }

    def test_01_clean_baseline_audit_100_percent_compliance(self) -> None:
        """Test 1: Temel hat ile birebir eşleşen uç nokta %100 uyumluluk ve sıfır sapma üretmelidir."""
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-CLEAN", self.clean_state)
        self.assertEqual(report.compliance_score_pct, 100.0)
        self.assertEqual(report.total_drifted, 0)
        self.assertEqual(len(report.findings), 0)

    def test_02_detect_uac_disabled_drift(self) -> None:
        """Test 2: UAC devre dışı bırakıldığında (EnableLUA = 0) CRITICAL sapma tespit edilmelidir."""
        state = dict(self.clean_state)
        state["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"] = 0
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.1", rule_ids)
        finding = next(f for f in report.findings if f.rule_id == "CIS-WIN-1.1")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_03_detect_windows_defender_realtime_disabled(self) -> None:
        """Test 3: Windows Defender gerçek zamanlı koruma kapatıldığında CRITICAL tespit edilmelidir."""
        state = dict(self.clean_state)
        state["HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"] = 1
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.2", rule_ids)
        finding = next(f for f in report.findings if f.rule_id == "CIS-WIN-1.2")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_04_detect_lsa_protection_disabled(self) -> None:
        """Test 4: LSA RunAsPPL koruması kapatıldığında HIGH seviyesinde tespit edilmelidir."""
        state = dict(self.clean_state)
        state["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL"] = 0
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.3", rule_ids)

    def test_05_detect_unauthorized_local_admin(self) -> None:
        """Test 5: Administrators grubuna yetkisiz kullanıcı eklendiğinde CRITICAL tespit edilmelidir."""
        state = dict(self.clean_state)
        state["Administrators_Members"] = ["Administrator", "Domain Admins", "backdoor_admin"]
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.4", rule_ids)
        finding = next(f for f in report.findings if f.rule_id == "CIS-WIN-1.4")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn("backdoor_admin", finding.risk_description)

    def test_06_detect_firewall_domain_profile_disabled(self) -> None:
        """Test 6: Güvenlik duvarı etki alanı profili kapatıldığında HIGH seviyesinde tespit edilmelidir."""
        state = dict(self.clean_state)
        state["DomainProfile_Enabled"] = False
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.5", rule_ids)

    def test_07_detect_insecure_guest_account_enabled(self) -> None:
        """Test 7: Guest hesabı aktifleştirildiğinde MEDIUM seviyesinde tespit edilmelidir."""
        state = dict(self.clean_state)
        state["GuestAccountStatus"] = "Enabled"
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.8", rule_ids)

    def test_08_detect_weak_password_length_relaxed(self) -> None:
        """Test 8: Minimum parola uzunluğu 14'ten 6'ya düşürüldüğünde HIGH tespit edilmelidir."""
        state = dict(self.clean_state)
        state["MinimumPasswordLength"] = 6
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.6", rule_ids)

    def test_09_detect_account_lockout_threshold_disabled(self) -> None:
        """Test 9: Hesap kilitleme eşiği 0 yapıldığında (kilitlenme kapalı) HIGH tespit edilmelidir."""
        state = dict(self.clean_state)
        state["AccountLockoutThreshold"] = 0
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.7", rule_ids)

    def test_10_detect_remote_registry_service_enabled(self) -> None:
        """Test 10: RemoteRegistry servisi çalışır duruma getirildiğinde MEDIUM tespit edilmelidir."""
        state = dict(self.clean_state)
        state["RemoteRegistry_Service"] = "Running"
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-WIN-1.9", rule_ids)

    def test_11_detect_linux_ip_forwarding_enabled(self) -> None:
        """Test 11: Linux sistemde net.ipv4.ip_forward = 1 yapıldığında HIGH tespit edilmelidir."""
        state = dict(self.clean_state)
        state["net.ipv4.ip_forward"] = 1
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("LNX-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-LNX-2.1", rule_ids)

    def test_12_detect_linux_aslr_disabled(self) -> None:
        """Test 12: Linux sistemde ASLR kapatıldığında (randomize_va_space = 0) CRITICAL tespit edilmelidir."""
        state = dict(self.clean_state)
        state["kernel.randomize_va_space"] = 0
        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("LNX-DRIFTED", state)
        rule_ids = [f.rule_id for f in report.findings]
        self.assertIn("CIS-LNX-2.2", rule_ids)
        finding = next(f for f in report.findings if f.rule_id == "CIS-LNX-2.2")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_13_auto_remediation_engine_fixes_drift(self) -> None:
        """Test 13: AutoRemediationEngine sapmış değerleri temel hata döndürerek %100 uyumluluk sağlamalıdır."""
        drifted_state = dict(self.clean_state)
        drifted_state["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"] = 0
        drifted_state["DomainProfile_Enabled"] = False
        drifted_state["kernel.randomize_va_space"] = 0

        # İyileştirme koşturulur
        fixed_state = AutoRemediationEngine.remediate_state(drifted_state, self.rules)

        auditor = ConfigDriftAuditor(self.rules)
        re_report = auditor.evaluate_endpoint_state("WIN11-REMEDIATED", fixed_state)
        self.assertEqual(re_report.compliance_score_pct, 100.0)
        self.assertEqual(re_report.total_drifted, 0)

    def test_14_compliance_score_calculation_accuracy(self) -> None:
        """Test 14: Kısmi sapmalarda uyumluluk skoru yüzdesi matematiksel olarak doğru hesaplanmalıdır."""
        state = dict(self.clean_state)
        # 11 kuraldan 2 tanesi sapmış -> 9 uyumlu -> %81.82
        state["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"] = 0
        state["DomainProfile_Enabled"] = False

        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-PARTIAL", state)
        self.assertEqual(report.total_evaluated, 11)
        self.assertEqual(report.total_compliant, 9)
        self.assertEqual(report.total_drifted, 2)
        self.assertEqual(report.compliance_score_pct, 81.82)

    def test_15_remediation_script_content_verification(self) -> None:
        """Test 15: Üretilen PowerShell ve Bash betikleri ilgili düzeltme komutlarını içermelidir."""
        state = dict(self.clean_state)
        state["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"] = 0
        state["kernel.randomize_va_space"] = 0

        auditor = ConfigDriftAuditor(self.rules)
        report = auditor.evaluate_endpoint_state("WIN11-SCRIPT-TEST", state)

        ps1 = AutoRemediationEngine.generate_powershell_remediation_script(report.findings)
        self.assertIn("EnableLUA", ps1)
        self.assertIn("Set-ItemProperty", ps1)

        bash = AutoRemediationEngine.generate_bash_remediation_script(report.findings)
        self.assertIn("sysctl", bash)


if __name__ == "__main__":
    unittest.main()
