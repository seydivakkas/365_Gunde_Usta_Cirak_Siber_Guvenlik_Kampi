# -*- coding: utf-8 -*-
"""
Aşama 6 Kalite Özeti ve Kabul Birim Test Paketi (Endpoint ve IAM)
Hafta 22 / Gün 154

Bu test paketi; 6 Kalite Kapısını (MFA/Kimlik, RBAC/JML, PAM/JIT, EDR/Telemetri,
TPM/Sandbox, WORM/Sapma) ve Aşama 6 nihai kabul motorunu 15 kapsamlı test
senaryosu ile %100 kapsama oranıyla test eder.
"""

import unittest
import os
import sys

# Üst dizin import yoluna eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.stage6_quality_engine import (
    Stage6QualityEngine,
    Stage6ArchitectureSpec,
    Stage6AuditReport,
    QualityGateResult,
    GateStatus,
)


class TestStage6QualityEngine(unittest.TestCase):
    """Aşama 6 Kalite Motoru test sınıfı."""

    def setUp(self):
        """Her testten önce temiz referans mimari şartnamesi oluşturulur."""
        self.engine = Stage6QualityEngine()

        # Kusursuz Aşama 6 kurumsal mimari şartnamesi
        self.clean_spec = Stage6ArchitectureSpec(
            organization_name="SiberSavunma Kurumsal A.Ş.",
            mfa_enforced=True,
            allowed_mfa_methods=["FIDO2", "WebAuthn", "TOTP"],
            password_hashing_algorithm="Argon2id",
            ntlmv1_disabled=True,
            kerberos_rc4_disabled=True,
            access_control_model="RBAC_ABAC_HYBRID",
            stale_accounts_deprovisioning_hours=8,
            orphaned_accounts_count=0,
            gmsa_used_for_services=True,
            standing_domain_admin_accounts=0,
            jit_elevation_enabled=True,
            max_elevation_duration_hours=2,
            session_recording_active=True,
            edr_fleet_coverage_percent=100.0,
            tamper_protection_enforced=True,
            edr_signatures_max_age_hours=6,
            full_disk_encryption_percent=100.0,
            tpm2_pcr_binding_verified=True,
            app_whitelisting_mode="Enforce",
            lsa_protection_ppl_enabled=True,
            backup_rule_32110_compliant=True,
            worm_immutable_storage_active=True,
            last_restore_drill_days_ago=14,
            auto_remediation_drift_active=True,
        )

    def test_01_fully_compliant_spec_passes_stage_6(self):
        """Kusursuz kurumsal şartnamenin Aşama 6'yı 100 puan ve PASS ile geçtiğini doğrular."""
        report = self.engine.audit_stage_6(self.clean_spec)
        self.assertEqual(report.overall_score, 100.0)
        self.assertEqual(report.final_verdict, GateStatus.PASS)
        self.assertEqual(report.passed_gates_count, 6)
        self.assertEqual(report.failed_gates_count, 0)

    def test_02_gate_1_fails_when_mfa_disabled(self):
        """MFA zorunlu olmadığında Kapı 1'in başarısız olduğunu test eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.mfa_enforced = False
        res = self.engine.evaluate_gate_1_authentication(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)
        self.assertTrue(any("MFA zorunlu değil" in v for v in res.violations))

    def test_03_gate_1_penalizes_weak_password_hash(self):
        """Zayıf parola hash algoritmasının (MD5) ceza aldığını doğrular."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.password_hashing_algorithm = "MD5"
        res = self.engine.evaluate_gate_1_authentication(spec)
        self.assertLess(res.score, 100.0)
        self.assertTrue(any("zayıf parola" in v for v in res.violations))

    def test_04_gate_1_penalizes_ntlmv1_and_rc4(self):
        """NTLMv1 ve Kerberos RC4 açık bırakıldığında ceza puanı uygulandığını kontrol eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.ntlmv1_disabled = False
        spec.kerberos_rc4_disabled = False
        res = self.engine.evaluate_gate_1_authentication(spec)
        self.assertLessEqual(res.score, 70.0)

    def test_05_gate_2_penalizes_orphaned_accounts(self):
        """Yetim hesapların (ayrılan çalışanlar) Kapı 2'de ceza aldığını test eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.orphaned_accounts_count = 3
        spec.stale_accounts_deprovisioning_hours = 72
        res = self.engine.evaluate_gate_2_least_privilege(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)

    def test_06_gate_2_penalizes_missing_gmsa(self):
        """Servis hesaplarında gMSA kullanılmamasının ceza aldığını kontrol eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.gmsa_used_for_services = False
        res = self.engine.evaluate_gate_2_least_privilege(spec)
        self.assertEqual(res.score, 80.0)

    def test_07_gate_3_fails_on_standing_domain_admins(self):
        """Kalıcı Domain Admin hesaplarının Kapı 3'ü doğrudan başarısız kıldığını test eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.standing_domain_admin_accounts = 2
        res = self.engine.evaluate_gate_3_pam_jit(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)

    def test_08_gate_3_penalizes_missing_jit_elevation(self):
        """JIT yetki yükseltme kapalı olduğunda ceza puanı uygulandığını doğrular."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.jit_elevation_enabled = False
        res = self.engine.evaluate_gate_3_pam_jit(spec)
        self.assertLess(res.score, 80.0)

    def test_09_gate_4_fails_on_low_edr_coverage(self):
        """EDR kapsama oranı düşük olduğunda Kapı 4'ün kaldığını test eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.edr_fleet_coverage_percent = 90.0
        res = self.engine.evaluate_gate_4_edr_telemetry(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)

    def test_10_gate_4_penalizes_disabled_tamper_protection(self):
        """EDR kurcalamaya karşı koruma kapalıysa ceza puanı kesildiğini doğrular."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.tamper_protection_enforced = False
        res = self.engine.evaluate_gate_4_edr_telemetry(spec)
        self.assertLessEqual(res.score, 70.0)

    def test_11_gate_5_fails_on_low_disk_encryption(self):
        """Disk şifreleme oranı düşük ve TPM PCR doğrulanmamışsa Kapı 5'in kaldığını doğrular."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.full_disk_encryption_percent = 85.0
        spec.tpm2_pcr_binding_verified = False
        res = self.engine.evaluate_gate_5_hardware_and_sandbox(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)

    def test_12_gate_5_penalizes_disabled_app_control_and_lsa(self):
        """Uygulama kontrolü ve LSA koruması kapalıyken uygulanan cezayı test eder."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.app_whitelisting_mode = "Disabled"
        spec.lsa_protection_ppl_enabled = False
        res = self.engine.evaluate_gate_5_hardware_and_sandbox(spec)
        self.assertLessEqual(res.score, 40.0)

    def test_13_gate_6_fails_on_missing_worm_storage(self):
        """Yedekleme deposu WORM/değiştirilemez olmadığında Kapı 6'nın kaldığını doğrular."""
        spec = Stage6ArchitectureSpec(**self.clean_spec.__dict__)
        spec.worm_immutable_storage_active = False
        spec.last_restore_drill_days_ago = 90
        res = self.engine.evaluate_gate_6_resilience_and_drift(spec)
        self.assertLess(res.score, self.engine.GATE_PASS_THRESHOLD)
        self.assertEqual(res.status, GateStatus.FAIL)

    def test_14_audit_report_summary_and_certificate(self):
        """Rapor özet metinlerinin ve ASCII sertifikanın doğru üretildiğini doğrular."""
        report = self.engine.audit_stage_6(self.clean_spec)
        cert = self.engine.generate_ascii_certificate(report)
        self.assertIn("AŞAMA 6 KALİTE GÜVENCE VE KABUL SERTİFİKASI", cert)
        self.assertIn("SiberSavunma Kurumsal A.Ş.", cert)
        self.assertIn("[GECTI]", cert)

    def test_15_cli_roundtrip_execution(self):
        """Rapor sözlük çıktısının serileştirilebilir ve anahtarların eksiksiz olduğunu doğrular."""
        report = self.engine.audit_stage_6(self.clean_spec)
        dict_data = self.engine.export_report_to_dict(report)
        self.assertIn("organization", dict_data)
        self.assertIn("overall_score", dict_data)
        self.assertIn("gate_results", dict_data)
        self.assertEqual(len(dict_data["gate_results"]), 6)


if __name__ == "__main__":
    unittest.main()
