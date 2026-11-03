# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 126 BİRİM TESTLERİ (Aşama 5 Kalite ve Kabul Motoru)
------------------------------------------------------
Bu test paketi, Aşama 5 Kalite Denetçisinin kriptografik değerlendirme,
mimari ilkeler (Saltzer-Schroeder), savunma derinliği ve yönetişim
kontrollerini 15 kapsamlı senaryo ile test eder.
"""

# İşletim sistemi fonksiyonları için os modülü
import os
# Sistem arama yolu kontrolü için sys modülü
import sys
# Birim test çatısı için unittest modülü
import unittest

# Uygulama modülünü arama yoluna dahil ediyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
# Üst dizindeki uygulama klasörünü hesaplıyoruz
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")
# Modül arama yolunun başına ekliyoruz
sys.path.insert(0, app_dir)

# Test edilecek motor sınıflarını içe aktarıyoruz
from stage5_quality_engine import (
    Stage5QualityAuditor,
    CryptographicComponentSpec,
    ArchitecturalControlSpec,
    StageAcceptanceDecision
)


class TestStage5QualityAuditor(unittest.TestCase):
    """Aşama 5 Kalite ve Kabul Denetçisi Test Sınıfı."""

    def setUp(self):
        """Her testten önce standart bir denetçi nesnesi kurar."""
        # Denetçi motorunu başlatıyoruz
        self.auditor = Stage5QualityAuditor("Test Kalite Komitesi")

    def test_01_approved_crypto_suite_gets_full_score(self):
        """NIST onaylı modern kriptografik algoritmalar 100 tam puan almalıdır."""
        # Onaylı bileşenleri tanımlıyoruz
        components = [
            CryptographicComponentSpec(
                component_name="Veri Depolama Şifreleme",
                cipher_or_hash_algorithm="AES-256-GCM",
                key_or_digest_bits=256,
                mode_of_operation="GCM",
                random_source="CSPRNG",
                uses_constant_time_compare=True
            ),
            CryptographicComponentSpec(
                component_name="Parola Özetleme",
                cipher_or_hash_algorithm="PBKDF2-HMAC-SHA256",
                key_or_digest_bits=256,
                pbkdf2_iterations=100000,
                random_source="CSPRNG",
                uses_constant_time_compare=True
            )
        ]
        # Kripto değerlendirmesi yapıyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite(components)
        # Skorun 100 olduğunu doğruluyoruz
        self.assertEqual(score, 100.0)
        # Hiçbir bulgu olmamalıdır
        self.assertEqual(len(findings), 0)
        # Hiçbir CWE ihlali olmamalıdır
        self.assertEqual(len(cwes), 0)

    def test_02_banned_md5_algorithm_penalized(self):
        """Kırık MD5 algoritması tespit edildiğinde puan kırılmalı ve CWE-327 raporlanmalıdır."""
        # MD5 içeren bileşen tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="Oturum Özetleyici",
            cipher_or_hash_algorithm="MD5",
            key_or_digest_bits=128
        )
        # Değerlendirme yapıyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puanın kırıldığını doğruluyoruz (100 - 30 = 70)
        self.assertLessEqual(score, 70.0)
        # CWE-327 ihlalini doğruluyoruz
        self.assertIn("CWE-327", cwes)
        # Bulguda MD5 geçtiğini doğruluyoruz
        self.assertTrue(any("MD5" in f for f in findings))

    def test_03_banned_sha1_algorithm_penalized(self):
        """Güvensiz SHA-1 algoritması kullanıldığında puan kırılmalı ve CWE-327 bildirilmelidir."""
        # SHA-1 bileşeni tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="İmza Özeti",
            cipher_or_hash_algorithm="SHA-1",
            key_or_digest_bits=160
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puan kırılmasını denetliyoruz
        self.assertLessEqual(score, 70.0)
        # CWE listesini denetliyoruz
        self.assertIn("CWE-327", cwes)

    def test_04_ecb_mode_penalized(self):
        """AES için güvensiz ECB çalışma modu tespit edildiğinde CWE-327 ihlali üretilmelidir."""
        # ECB modlu bileşen tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="Blok Şifreleyici",
            cipher_or_hash_algorithm="AES",
            key_or_digest_bits=256,
            mode_of_operation="ECB"
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puanın kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 75.0)
        # ECB bulgusunu denetliyoruz
        self.assertTrue(any("ECB" in f for f in findings))

    def test_05_insufficient_rsa_key_length_penalized(self):
        """NIST standartlarına göre 2048 bitten küçük RSA anahtarları CWE-326 ile cezalandırılmalıdır."""
        # RSA 1024-bit bileşeni tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="Kimlik Doğrulama Anahtarı",
            cipher_or_hash_algorithm="RSA-1024",
            key_or_digest_bits=1024
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 80.0)
        # CWE-326 varlığını doğruluyoruz
        self.assertIn("CWE-326", cwes)

    def test_06_weak_prng_randomness_source_penalized(self):
        """Kriptografik olmayan sözde rastgelelik kaynağı (PRNG) CWE-338 ile cezalandırılmalıdır."""
        # PRNG kaynaklı bileşen tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="Token Üretici",
            cipher_or_hash_algorithm="AES-256-GCM",
            key_or_digest_bits=256,
            random_source="PRNG"
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 80.0)
        # CWE-338 varlığını doğruluyoruz
        self.assertIn("CWE-338", cwes)

    def test_07_insufficient_pbkdf2_iterations_penalized(self):
        """PBKDF2 iterasyon sayısı 100.000 altında olduğunda CWE-916 ihlali bildirilmelidir."""
        # 10.000 iterasyonlu zayıf KDF bileşeni tanımlıyoruz
        comp = CryptographicComponentSpec(
            component_name="Parola Saklama",
            cipher_or_hash_algorithm="PBKDF2",
            key_or_digest_bits=256,
            pbkdf2_iterations=10000
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 85.0)
        # CWE-916 varlığını doğruluyoruz
        self.assertIn("CWE-916", cwes)

    def test_08_timing_attack_non_constant_time_penalized(self):
        """Sabit zamanlı karşılaştırma yapılmadığında zamanlama saldırısı (CWE-208) raporlanmalıdır."""
        # Sabit zamanlı karşılaştırma yapmayan bileşen
        comp = CryptographicComponentSpec(
            component_name="HMAC Doğrulayıcı",
            cipher_or_hash_algorithm="HMAC-SHA256",
            key_or_digest_bits=256,
            uses_constant_time_compare=False
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_crypto_suite([comp])
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 85.0)
        # CWE-208 varlığını doğruluyoruz
        self.assertIn("CWE-208", cwes)

    def test_09_default_deny_enforced_architecture_passes(self):
        """Saltzer-Schroeder Varsayılan Ret (Default-Deny) ilkesi devredeyken mimari tam puan almalıdır."""
        # Tam uyumlu mimari kontrolleri tanımlıyoruz
        arch = ArchitecturalControlSpec(
            control_name="Kurumsal Güvenlik Mimarisi",
            defense_layers_covered=["Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"],
            control_types=["Önleyici", "Tespit Edici", "Düzeltici"],
            default_deny_enforced=True,
            fail_secure_on_outage=True,
            static_sod_enforced=True,
            wildcard_permissions_allowed=False,
            log_masking_enabled=True
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_architectural_controls(arch)
        # 100 puan aldığını doğruluyoruz
        self.assertEqual(score, 100.0)
        # Hiçbir ihlal olmadığını teyit ediyoruz
        self.assertEqual(len(cwes), 0)

    def test_10_default_allow_architecture_heavily_penalized(self):
        """Varsayılan İzin (Default-Allow) mimarisi CWE-1188 ile ağır şekilde cezalandırılmalıdır."""
        # Default-Allow mimarisi
        arch = ArchitecturalControlSpec(
            control_name="Hatalı Mimari",
            defense_layers_covered=["Ağ", "Uygulama"],
            control_types=["Önleyici"],
            default_deny_enforced=False,
            fail_secure_on_outage=True,
            static_sod_enforced=True,
            wildcard_permissions_allowed=False,
            log_masking_enabled=True
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_architectural_controls(arch)
        # Puanın kırıldığını doğruluyoruz
        self.assertLessEqual(score, 65.0)
        # CWE-1188 ihlalini doğruluyoruz
        self.assertIn("CWE-1188", cwes)

    def test_11_fail_open_outage_penalized(self):
        """Altyapı kesintisinde kapıları açık bırakan Fail-Open davranışı CWE-636 ile cezalandırılmalıdır."""
        # Fail-Open mimarisi
        arch = ArchitecturalControlSpec(
            control_name="Açık Kapı Mimarisi",
            defense_layers_covered=["Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"],
            control_types=["Önleyici"],
            default_deny_enforced=True,
            fail_secure_on_outage=False,
            static_sod_enforced=True,
            wildcard_permissions_allowed=False,
            log_masking_enabled=True
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_architectural_controls(arch)
        # Puanın kırıldığını doğruluyoruz
        self.assertLessEqual(score, 70.0)
        # CWE-636 ihlalini doğruluyoruz
        self.assertIn("CWE-636", cwes)

    def test_12_static_sod_violation_penalized(self):
        """Statik Görevler Ayrılığı (SoD) zorunlu tutulmadığında CWE-863 ihlali bildirilmelidir."""
        # SoD eksik mimari
        arch = ArchitecturalControlSpec(
            control_name="SoD Olmayan Mimari",
            defense_layers_covered=["Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"],
            control_types=["Önleyici"],
            default_deny_enforced=True,
            fail_secure_on_outage=True,
            static_sod_enforced=False,
            wildcard_permissions_allowed=False,
            log_masking_enabled=True
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_architectural_controls(arch)
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 80.0)
        # CWE-863 varlığını doğruluyoruz
        self.assertIn("CWE-863", cwes)

    def test_13_wildcard_permission_violates_polp(self):
        """Normal rollere joker (*) izin verilmesi En Az Yetki İlkesini (CWE-250) ihlal eder."""
        # Joker izinli mimari
        arch = ArchitecturalControlSpec(
            control_name="Geniş Yetki Mimarisi",
            defense_layers_covered=["Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"],
            control_types=["Önleyici"],
            default_deny_enforced=True,
            fail_secure_on_outage=True,
            static_sod_enforced=True,
            wildcard_permissions_allowed=True,
            log_masking_enabled=True
        )
        # Değerlendiriyoruz
        score, findings, cwes = self.auditor.evaluate_architectural_controls(arch)
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 85.0)
        # CWE-250 varlığını doğruluyoruz
        self.assertIn("CWE-250", cwes)

    def test_14_log_masking_disabled_penalized(self):
        """Denetim kütüklerinde sır maskelemesi kapalıysa CWE-532 ihlali üretilmelidir."""
        # Maskeleme kapalı mimari
        arch = ArchitecturalControlSpec(
            control_name="Log Maskelemesiz",
            defense_layers_covered=["Ağ", "Host", "Uygulama", "Veri"],
            control_types=["Önleyici"],
            default_deny_enforced=True,
            fail_secure_on_outage=True,
            static_sod_enforced=True,
            wildcard_permissions_allowed=False,
            log_masking_enabled=False
        )
        # Yönetişim değerlendirmesi yapıyoruz
        score, findings, cwes = self.auditor.evaluate_governance_and_evidence(arch, True, True)
        # Puan kırıldığını teyit ediyoruz
        self.assertLessEqual(score, 70.0)
        # CWE-532 varlığını doğruluyoruz
        self.assertIn("CWE-532", cwes)

    def test_15_full_audit_produces_accepted_pass_and_certificate(self):
        """Kusursuz Aşama 5 şartnamesinde genel skor >= 85 olmalı ve ACCEPTED_PASS kararı verilmelidir."""
        # Kusursuz kriptografik bileşenler
        crypto_components = [
            CryptographicComponentSpec(
                component_name="Veri Tabanı Şifreleme",
                cipher_or_hash_algorithm="AES-256-GCM",
                key_or_digest_bits=256,
                mode_of_operation="GCM",
                random_source="CSPRNG"
            ),
            CryptographicComponentSpec(
                component_name="Kullanıcı Kimlik Doğrulama",
                cipher_or_hash_algorithm="PBKDF2-HMAC-SHA256",
                key_or_digest_bits=256,
                pbkdf2_iterations=100000,
                random_source="CSPRNG"
            )
        ]
        # Kusursuz mimari şartname
        arch_spec = ArchitecturalControlSpec(
            control_name="Kurumsal Savunma Mimarisi",
            defense_layers_covered=["Fiziksel", "Çevre", "Ağ", "Host", "Uygulama", "Veri", "İnsan"],
            control_types=["Önleyici", "Tespit Edici", "Düzeltici", "Telafi Edici", "Caydırıcı"],
            default_deny_enforced=True,
            fail_secure_on_outage=True,
            static_sod_enforced=True,
            wildcard_permissions_allowed=False,
            log_masking_enabled=True
        )
        # Tam denetimi icra ediyoruz
        audit_res = self.auditor.perform_full_stage5_audit(
            target_system_name="Kurumsal Üretim Sistemi",
            crypto_specs=crypto_components,
            arch_spec=arch_spec,
            has_executable_tests=True,
            has_negative_controls=True
        )
        # 100 tam puan aldığını doğruluyoruz
        self.assertEqual(audit_res.overall_quality_score, 100.0)
        # Kararın ACCEPTED_PASS olduğunu doğruluyoruz
        self.assertEqual(audit_res.decision, StageAcceptanceDecision.ACCEPTED_PASS)
        # Markdown sertifikasını üretiyoruz
        cert_md = self.auditor.generate_markdown_certificate(audit_res)
        # Sertifika içeriğini doğruluyoruz
        self.assertIn("AŞAMA 5 KABUL EDİLDİ (PASS)", cert_md)
        self.assertIn("100.0 / 100", cert_md)


# Testler doğrudan çalıştırıldığında unittest main çağrılır
if __name__ == "__main__":
    unittest.main()
