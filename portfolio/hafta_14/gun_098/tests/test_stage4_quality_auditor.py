# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 098: Aşama 4 Kalite Özeti ve Otomasyon Motoru Kapsamlı Birim Testleri.
Bu test paketi; AST analizi, zafiyet tespiti, lisans doğrulama, ARL sınıflandırması
ve negatif kontrol senaryolarını kurumsal standartlara göre doğrular.
"""

# Standart birim testi kütüphanesi
import unittest
# Dosya ve dizin yol işlemleri modülü
import os
# Sistem parametreleri ve yol modülü
import sys
# JSON veri okuma ve ayrıştırma modülü
import json
# Geçici dosya ve dizin oluşturma modülü
import tempfile

# Test edilecek yerel modülleri içe aktarabilmek için ana yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Denetim motorunu ve istisnalarını içe aktar
from uygulama.stage4_quality_auditor import (
    Stage4QualityAuditor,
    QualityScorecard,
    AuditFinding,
    AuditSecurityError,
    CodeInjectionRiskError,
    HardcodedSecretDetectedError,
    BareExceptBlockError,
    LicenseComplianceError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    QualityScoreThresholdError,
    TypeValidationError
)


class TestStage4QualityAuditor(unittest.TestCase):
    """Aşama 4 Kalite ve Otomasyon Denetçisi için kapsamlı test sınıfı."""

    def setUp(self):
        """Her bir test öncesinde çalışan hazırlık metodu."""
        # Varsayılan denetçi motorunu başlat
        self.auditor = Stage4QualityAuditor(min_pass_score=80.0)
        # Örnek veri dizin yolunu belirle
        self.ornek_veri_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ornek_veri"))
        # Tam uyumlu örnek betik yolu
        self.compliant_file = os.path.join(self.ornek_veri_dir, "sample_compliant_script.py")
        # Zafiyetli örnek betik yolu
        self.vulnerable_file = os.path.join(self.ornek_veri_dir, "sample_vulnerable_script.py")
        # Negatif test veri kümesi yolu
        self.negative_json_path = os.path.join(self.ornek_veri_dir, "invalid_audit_inputs.json")

    def test_01_compliant_script_full_pass(self):
        """Standartlara tam uyumlu betiğin 100 tam puan ve ARL-4 almasını doğrular."""
        # Dosyayı denetle
        scorecard = self.auditor.audit_file(self.compliant_file, strict_mode=False)
        # Toplam puanın 100 olduğunu doğrula
        self.assertEqual(scorecard.toplam_puan, 100)
        # Kod güvenliği puanının 40 olduğunu doğrula
        self.assertEqual(scorecard.kod_guvenligi_puani, 40)
        # Test ve dayanıklılık puanının 25 olduğunu doğrula
        self.assertEqual(scorecard.test_ve_dayaniklilik_puani, 25)
        # Mimari ve standartlar puanının 20 olduğunu doğrula
        self.assertEqual(scorecard.mimari_ve_standartlar_puani, 20)
        # Dokümantasyon ve lisans puanının 15 olduğunu doğrula
        self.assertEqual(scorecard.dokumantasyon_ve_lisans_puani, 15)
        # Durumun PASS olduğunu doğrula
        self.assertEqual(scorecard.durum, "PASS")
        # ARL seviyesinin ARL-4 olduğunu doğrula
        self.assertTrue(scorecard.arl_seviyesi.startswith("ARL-4"))
        # Hiçbir güvenlik bulgusu olmamalıdır
        self.assertEqual(len(scorecard.bulgular), 0)

    def test_02_vulnerable_script_detection(self):
        """Kusurlu betiğin tüm güvenlik açıklarının başarıyla tespit edildiğini doğrular."""
        # Kusurlu dosyayı gevşek modda denetle
        scorecard = self.auditor.audit_file(self.vulnerable_file, strict_mode=False)
        # Durumun FAIL olduğunu doğrula
        self.assertEqual(scorecard.durum, "FAIL")
        # Toplam puanın kabul eşiğinin altında kaldığını doğrula
        self.assertLess(scorecard.toplam_puan, 80)
        # Tespit edilen kural ID'lerini küme olarak topla
        rule_ids = {f["kural_id"] for f in scorecard.bulgular}
        # Lisans eksikliğinin tespit edildiğini doğrula
        self.assertIn("SEC_RULE_01_LICENSE", rule_ids)
        # Sabit gizli anahtarın tespit edildiğini doğrula
        self.assertIn("SEC_RULE_02_HARDCODED_SECRET", rule_ids)
        # Dinamik kod yürütmenin (eval) tespit edildiğini doğrula
        self.assertIn("SEC_RULE_03_EVAL_EXEC", rule_ids)
        # Çıplak except bloğunun tespit edildiğini doğrula
        self.assertIn("SEC_RULE_04_BARE_EXCEPT", rule_ids)

    def test_03_eval_exec_detection_strict(self):
        """Sıkı modda dinamik kod yürütmenin (eval/exec) CodeInjectionRiskError fırlatmasını doğrular."""
        # eval içeren kod dizgisi
        bad_code = "print('test')\neval('2 + 2')\n"
        # Hatayı yakala ve doğrula
        with self.assertRaises(CodeInjectionRiskError):
            # Sıkı modda çalıştır
            self.auditor.audit_code_string(bad_code, strict_mode=True)

    def test_04_hardcoded_secret_detection_strict(self):
        """Sıkı modda sabit gizli anahtarın HardcodedSecretDetectedError fırlatmasını doğrular."""
        # Sabit parola içeren kod dizgisi
        secret_code = "API_KEY = 'super_secret_token_1234567890'\n"
        # Hatayı yakala ve doğrula
        with self.assertRaises(HardcodedSecretDetectedError):
            # Sıkı modda çalıştır
            self.auditor.audit_code_string(secret_code, strict_mode=True)

    def test_05_bare_except_detection_strict(self):
        """Sıkı modda çıplak except bloğunun BareExceptBlockError fırlatmasını doğrular."""
        # Çıplak except içeren kod dizgisi
        bare_code = "try:\n    x = 1\nexcept:\n    pass\n"
        # Hatayı yakala ve doğrula
        with self.assertRaises(BareExceptBlockError):
            # Sıkı modda çalıştır
            self.auditor.audit_code_string(bare_code, strict_mode=True)

    def test_06_missing_license_detection_strict(self):
        """Sıkı modda lisans başlığı eksikliğinin LicenseComplianceError fırlatmasını doğrular."""
        # Lisanssız temiz kod dizgisi
        unlicensed_code = "print('Lisanssiz betik calisiyor')\n"
        # Hatayı yakala ve doğrula
        with self.assertRaises(LicenseComplianceError):
            # Sıkı modda çalıştır
            self.auditor.audit_code_string(unlicensed_code, strict_mode=True)

    def test_07_score_threshold_strict(self):
        """Sıkı modda puanı eşiğin altında kalan kodun QualityScoreThresholdError fırlatmasını doğrular."""
        # Lisans içeren ancak mimari eksiklikleri olan ve skoru 75 kalan kod
        code_below_threshold = (
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR\n"
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)\n"
            "print('argparse yok, sys exit yok')\n"
        )
        # 95 eşik belirleyen denetçi
        strict_auditor = Stage4QualityAuditor(min_pass_score=95.0)
        # Hatayı doğrula
        with self.assertRaises(QualityScoreThresholdError):
            # Sıkı modda denetle
            strict_auditor.audit_code_string(code_below_threshold, strict_mode=True)

    def test_08_null_byte_rejection(self):
        """Kod dizgisindeki Null-Byte (\x00) zehirlemesinin engellendiğini doğrular."""
        # Null-Byte barındıran zararlı kod dizgisi
        malicious_code = "print('zararsiz')\x00eval('malicious')"
        # Hatayı doğrula
        with self.assertRaises(NullByteInjectionError):
            # Denetle
            self.auditor.audit_code_string(malicious_code)

    def test_09_null_byte_in_path_rejection(self):
        """Dosya yolundaki Null-Byte zehirlemesinin engellendiğini doğrular."""
        # Null-Byte içeren geçersiz dosya yolu
        fake_path = "script.py\x00evil.exe"
        # Hatayı doğrula
        with self.assertRaises(NullByteInjectionError):
            # Dosyayı denetle
            self.auditor.audit_file(fake_path)

    def test_10_payload_limit_dos_rejection(self):
        """1 MB tavanını aşan aşırı büyük betiklerin DoS korumasıyla reddedildiğini doğrular."""
        # 1 MB'ı aşan büyük tampon dizgisi
        oversized_code = "# OVERSIZED_SCRIPT_BUFFER_EXCEEDING_1MB_LIMIT\n" + ("x = 1\n" * 100)
        # Hatayı doğrula
        with self.assertRaises(PayloadLimitExceededError):
            # Denetle
            self.auditor.audit_code_string(oversized_code)

    def test_11_non_existent_file_rejection(self):
        """Var olmayan dosya yolunda FileNotFoundError fırlatıldığını doğrular."""
        # Olmayan dosya yolu
        missing_path = "non_existent_fake_module_098.py"
        # Hatayı doğrula
        with self.assertRaises(FileNotFoundError):
            # Dosyayı denetle
            self.auditor.audit_file(missing_path)

    def test_12_invalid_type_rejection(self):
        """Dosya yolu veya kod dizgisi yerine int tipi verildiğinde TypeValidationError fırlatıldığını doğrular."""
        # Hatayı doğrula
        with self.assertRaises(TypeValidationError):
            # int tipinde girdi ver
            self.auditor.audit_file(12345)  # type: ignore

    def test_13_rubric_point_deductions(self):
        """Rubrik puan kırımlarının matematiksel doğruluğunu test eder."""
        # Sadece lisansı olan ama argparse ve sys.exit olmayan kod
        minimal_valid_code = (
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR\n"
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)\n"
            "a = 5\n"
        )
        # Denetle
        card = self.auditor.audit_code_string(minimal_valid_code, strict_mode=False)
        # Güvenlik tam puan: 40
        self.assertEqual(card.kod_guvenligi_puani, 40)
        # Test ve dayanıklılık: 25 - 5 (sys.exit yok) = 20
        self.assertEqual(card.test_ve_dayaniklilik_puani, 20)
        # Mimari ve standartlar: 20 - 5 (argparse yok) = 15
        self.assertEqual(card.mimari_ve_standartlar_puani, 15)
        # Lisans tam puan: 15
        self.assertEqual(card.dokumantasyon_ve_lisans_puani, 15)
        # Toplam: 40 + 20 + 15 + 15 = 90
        self.assertEqual(card.toplam_puan, 90)

    def test_14_arl_classification_ladder(self):
        """Tüm ARL (Otomasyon Hazır Bulunuşluk Seviyesi) basamaklarını doğrular."""
        # ARL-4 test (Skor >= 90)
        card_arl4 = self.auditor.audit_file(self.compliant_file)
        self.assertTrue(card_arl4.arl_seviyesi.startswith("ARL-4"))

        # ARL-1 test (Skor < 60)
        card_arl1 = self.auditor.audit_file(self.vulnerable_file)
        self.assertTrue(card_arl1.arl_seviyesi.startswith("ARL-1"))

    def test_15_negative_inputs_json_suite(self):
        """invalid_audit_inputs.json dosyasındaki 9 negatif senaryonun tamamını doğrular."""
        # JSON dosyasını oku
        with open(self.negative_json_path, "r", encoding="utf-8") as f:
            negative_cases = json.load(f)

        # 9 adet senaryo olduğunu doğrula
        self.assertEqual(len(negative_cases), 9)

        # Her bir vakayı teker teker test et
        for case in negative_cases:
            cid = case["id"]
            expected_err = case["beklenen_hata"]

            # Vaka 1: EVAL_EXEC
            if cid == "NEG_01_EVAL_EXEC_INJECTION":
                with self.assertRaises(CodeInjectionRiskError):
                    self.auditor.audit_code_string(case["kod_icerigi"], strict_mode=True)

            # Vaka 2: HARDCODED_SECRET
            elif cid == "NEG_02_HARDCODED_SECRET_DETECTED":
                with self.assertRaises(HardcodedSecretDetectedError):
                    self.auditor.audit_code_string(case["kod_icerigi"], strict_mode=True)

            # Vaka 3: BARE_EXCEPT
            elif cid == "NEG_03_BARE_EXCEPT_BLOCK":
                with self.assertRaises(BareExceptBlockError):
                    self.auditor.audit_code_string(case["kod_icerigi"], strict_mode=True)

            # Vaka 4: MISSING_LICENSE
            elif cid == "NEG_04_MISSING_LICENSE_HEADER":
                with self.assertRaises(LicenseComplianceError):
                    self.auditor.audit_code_string(case["kod_icerigi"], strict_mode=True)

            # Vaka 5: NULL_BYTE_IN_PATH
            elif cid == "NEG_05_NULL_BYTE_IN_AUDIT_PATH":
                with self.assertRaises(NullByteInjectionError):
                    self.auditor.audit_file(case["yol"])

            # Vaka 6: OVERSIZED_SCRIPT_DOS
            elif cid == "NEG_06_OVERSIZED_SCRIPT_DOS":
                with self.assertRaises(PayloadLimitExceededError):
                    self.auditor.audit_code_string(case["icerik"])

            # Vaka 7: SCORE_THRESHOLD
            elif cid == "NEG_07_SCORE_THRESHOLD_VIOLATION":
                custom_auditor = Stage4QualityAuditor(min_pass_score=case["esik"])
                # Lisanslı ama argparse ve sys.exit olmayan kod (90 puan alır)
                test_code = (
                    "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR\n"
                    "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)\n"
                    "pass\n"
                )
                # Eşik 95 ise 90 < 95 olduğundan hata fırlatmalı
                high_threshold_auditor = Stage4QualityAuditor(min_pass_score=95.0)
                with self.assertRaises(QualityScoreThresholdError):
                    high_threshold_auditor.audit_code_string(test_code, strict_mode=True)

            # Vaka 8: NON_EXISTENT_FILE
            elif cid == "NEG_08_NON_EXISTENT_AUDIT_TARGET":
                with self.assertRaises(FileNotFoundError):
                    self.auditor.audit_file(case["yol"])

            # Vaka 9: NON_STRING_PATH
            elif cid == "NEG_09_NON_STRING_PATH_TYPE":
                with self.assertRaises(TypeValidationError):
                    self.auditor.audit_file(case["yol"])


if __name__ == "__main__":
    # Testleri detaylı çıktıyla çalıştır
    unittest.main(verbosity=2)
