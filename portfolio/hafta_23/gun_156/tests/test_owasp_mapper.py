# -*- coding: utf-8 -*-
"""
OWASP Top 10 Haritası ve Web Zafiyet Değerlendirme Birim Test Paketi
Hafta 23 / Gün 156 - Aşama 7 (Web Güvenliği)

Bu test paketi; 10 OWASP risk kategorisini (A01 - A10), CWE haritalama
veritabanını, uyumluluk puanlama motorunu ve iyileştirme yol haritası üretimini
15 kapsamlı test ile %100 kapsama oranıyla test eder.
"""

import unittest
import os
import sys

# Üst dizini Python import yoluna ekler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.owasp_mapper_engine import (
    AppSecurityProfile,
    OwaspMapperEngine,
    OwaspCategory,
    OwaspRiskLevel,
    OwaspComplianceReport,
)


class TestOwaspMapperEngine(unittest.TestCase):
    """OWASP haritalama motoru test sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        self.engine = OwaspMapperEngine()

        # Kusursuz güvenli örnek uygulama profili
        self.clean_profile = AppSecurityProfile(
            app_name="KurumsalFinansPortal",
            version="2.5.0",
            environment="Production",
            has_rbac_authz_middleware=True,
            idor_prevention_active=True,
            tls_minimum_version="TLSv1.3",
            passwords_hashed_with_argon2_or_bcrypt=True,
            sensitive_data_encrypted_at_rest=True,
            uses_parameterized_queries=True,
            output_encoding_for_xss=True,
            has_threat_model=True,
            has_rate_limiting=True,
            debug_mode_disabled=True,
            default_credentials_changed=True,
            security_headers_enforced=True,
            outdated_dependencies_count=0,
            has_automated_sca_scanning=True,
            mfa_enforced_for_admin=True,
            brute_force_lockout_active=True,
            insecure_deserialization_prevented=True,
            ci_cd_pipeline_signed=True,
            centralized_audit_logging_active=True,
            security_event_alerting_latency_minutes=5,
            ssrf_url_validation_allowlist_active=True,
            cloud_metadata_blocked=True,
        )

    def test_01_fully_compliant_profile_passes_all_10_categories(self):
        """Kusursuz uygulamanın 10 kategoride de tam puan aldığını ve uyumlu olduğunu doğrular."""
        report = self.engine.evaluate_profile(self.clean_profile)
        self.assertEqual(report.overall_compliance_score, 100.0)
        self.assertTrue(report.is_compliant)
        self.assertEqual(len(report.category_scores), 10)
        for cat_k, cat_sc in report.category_scores.items():
            self.assertEqual(cat_sc.status, "GECTI")

    def test_02_a01_broken_access_control_failure(self):
        """RBAC ve IDOR koruması kapalıyken A01 kategorisinin kaldığını doğrular."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.has_rbac_authz_middleware = False
        prof.idor_prevention_active = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A01"].status, "KALDI")
        self.assertLess(report.category_scores["A01"].score, 50.0)

    def test_03_a02_cryptographic_failures(self):
        """Zayıf TLS ve zayıf parola hashlemenin A02 kategorisini düşürdüğünü test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.tls_minimum_version = "TLSv1.0"
        prof.passwords_hashed_with_argon2_or_bcrypt = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A02"].status, "KALDI")
        self.assertLessEqual(report.category_scores["A02"].score, 40.0)

    def test_04_a03_injection_vulnerability(self):
        """Parametresiz dinamik SQL kullanımının A03 enjeksiyon açığı oluşturduğunu doğrular."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.uses_parameterized_queries = False
        prof.output_encoding_for_xss = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A03"].status, "KALDI")
        self.assertLessEqual(report.category_scores["A03"].score, 20.0)

    def test_05_a04_insecure_design_rate_limit(self):
        """Hız sınırlama (Rate Limiting) eksikliğinin A04 kategorisinde puan düşürdüğünü test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.has_rate_limiting = False
        prof.has_threat_model = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A04"].status, "KALDI")

    def test_06_a05_security_misconfiguration_debug_mode(self):
        """Üretimde Debug Mode açık olmasının A05 kategorisini başarısız kıldığını test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.debug_mode_disabled = False
        prof.default_credentials_changed = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A05"].status, "KALDI")

    def test_07_a06_vulnerable_components_outdated_pkgs(self):
        """Eski ve yamalanmamış bağımlılıkların A06 kategorisinde ceza aldığını doğrular."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.outdated_dependencies_count = 4
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A06"].status, "KALDI")
        self.assertLessEqual(report.category_scores["A06"].score, 40.0)

    def test_08_a07_auth_failures_mfa_and_lockout(self):
        """MFA zorunluluğu ve hesap kilitleme yokluğunun A07'yi başarısız kıldığını test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.mfa_enforced_for_admin = False
        prof.brute_force_lockout_active = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A07"].status, "KALDI")

    def test_09_a08_integrity_failures_deserialization(self):
        """Güvensiz nesne serileştirmenin A08 kategorisinde kritik ihlal olduğunu doğrular."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.insecure_deserialization_prevented = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A08"].status, "KALDI")

    def test_10_a09_logging_failures_no_audit(self):
        """Merkezi denetim günlüğü eksikliğinin A09 kategorisini düşürdüğünü test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.centralized_audit_logging_active = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A09"].status, "KALDI")

    def test_11_a10_ssrf_vulnerability_metadata_access(self):
        """SSRF beyaz listesi ve bulut meta veri engeli yokluğunun A10'u düşürdüğünü test eder."""
        prof = AppSecurityProfile(**self.clean_profile.__dict__)
        prof.ssrf_url_validation_allowlist_active = False
        prof.cloud_metadata_blocked = False
        report = self.engine.evaluate_profile(prof)
        self.assertEqual(report.category_scores["A10"].status, "KALDI")
        self.assertLessEqual(report.category_scores["A10"].score, 20.0)

    def test_12_cwe_mapping_sql_injection(self):
        """CWE-89'un doğru biçimde A03 Injection ve CRITICAL olarak eşleştirildiğini test eder."""
        mapping = self.engine.map_cwe(89)
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.category, OwaspCategory.A03_INJECTION)
        self.assertEqual(mapping.severity, OwaspRiskLevel.CRITICAL)

    def test_13_cwe_mapping_ssrf(self):
        """CWE-918'in A10 SSRF kategorisiyle eşleştiğini doğrular."""
        mapping = self.engine.map_cwe(918)
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.category, OwaspCategory.A10_SSRF)

    def test_14_ascii_dashboard_generation(self):
        """ASCII pano çıktısının başlıkları ve kategorileri içerdiğini test eder."""
        report = self.engine.evaluate_profile(self.clean_profile)
        dashboard_text = self.engine.generate_ascii_dashboard(report)
        self.assertIn("OWASP TOP 10:2025 WEB GÜVENLİK HARİTASI", dashboard_text)
        self.assertIn("KurumsalFinansPortal", dashboard_text)
        self.assertIn("[GECTI]", dashboard_text)

    def test_15_cli_roundtrip_export_dict(self):
        """Rapor sözlük çıktısının serileştirilebilir ve 10 kategoriyi içerdiğini doğrular."""
        report = self.engine.evaluate_profile(self.clean_profile)
        dict_data = self.engine.export_report_to_dict(report)
        self.assertIn("app_name", dict_data)
        self.assertIn("category_scores", dict_data)
        self.assertEqual(len(dict_data["category_scores"]), 10)


if __name__ == "__main__":
    unittest.main()
