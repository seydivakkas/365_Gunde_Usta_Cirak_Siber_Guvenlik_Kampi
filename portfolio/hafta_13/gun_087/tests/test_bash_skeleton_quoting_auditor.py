# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G087: Bash Betik İskeleti ve Quoting Güvenlik Motoru Birim Testleri (unittest).
Bu test paketi; shebang kontrolünü, set -euo pipefail katı kipini, IFS ayarlarını,
eval komut enjeksiyonunu (CWE-78), tırnaksız değişken genişlemesini (CWE-732) ve
kelime bölünmesi / globbing (CWE-88) senaryolarını test eder.
"""

from pathlib import Path  # Dosya yollari yonetimi icin Path modulu ice aktarilir
import unittest  # Birim test cercevesi ice aktarilir

from portfolio.hafta_13.gun_087.uygulama.bash_skeleton_quoting_auditor import (  # Uygulama modulleri
    BashFinding,  # Bulgu sinifi
    BashScriptSizeLimitException,  # Boyut limiti istisnasi
    BashSeverity,  # Ciddiyet enum degeri
    BashSkeletonParser,  # Iskelet ayrastirici
    BashSkeletonQuotingAuditor,  # Façade denetim motoru
    DangerousEvalException,  # Eval istisnasi
    GlobbingInjectionException,  # Globbing istisnasi
    MissingShebangException,  # Shebang istisnasi
    MissingStrictModeException,  # Kati mod istisnasi
    NullByteForbiddenException,  # Null byte istisnasi
    QuotingSecurityScanner,  # Quoting tarayici
    RuntimeWordSplittingSimulator,  # Kelime bolunmesi simulatoru
    UnquotedArrayExpansionException,  # Dizi genisleme istisnasi
    UnquotedVariableException,  # Tirnaksiz degisken istisnasi
    WordSplittingDetectedException,  # Kelime bolunmesi istisnasi
)


class TestBashSkeletonQuotingAuditor(unittest.TestCase):
    """Bash betik iskeleti ve quoting guvenlik motoru test senaryolari."""

    def setUp(self) -> None:
        """Her testten once taze denetim motoru ornegi ve ornek betik yollarini hazirlar."""
        self.auditor = BashSkeletonQuotingAuditor()  # Denetim motoru ornegi olusturulur
        base_dir = Path(__file__).resolve().parent.parent / "ornek_veri"  # Ornek veri yolu
        self.secure_script_path = base_dir / "sample_secure_script.sh"  # Guvenli betik yolu
        self.vulnerable_script_path = base_dir / "sample_vulnerable_script.sh"  # Zaafiyetli betik yolu

    def test_01_parse_secure_bash_skeleton(self) -> None:
        """Guvenli Bash betiginin shebang, kati kip, IFS ve trap kurallarini gectigini test eder."""
        report = self.auditor.audit_script_file(self.secure_script_path)  # Guvenli betik denetlenir
        self.assertTrue(report.has_shebang)  # Shebang mevcut olmali
        self.assertTrue(report.has_strict_mode)  # set -euo pipefail mevcut olmali
        self.assertTrue(report.has_ifs)  # Guvenli IFS tanimli olmali
        self.assertTrue(report.has_trap)  # Trap yakalayicisi mevcut olmali
        self.assertTrue(report.is_secure)  # Guvenli olarak isaretlenmeli

    def test_02_detect_missing_shebang(self) -> None:
        """Betiğin basinda shebang eksikliginin MEDIUM seviyede tespit edildigini test eder."""
        snippet = "set -euo pipefail\necho 'Test without shebang'\n"  # Shebangsiz betik
        report = self.auditor.audit_script_text(snippet)  # Denetim calistirilir
        self.assertFalse(report.has_shebang)  # Shebang olmadigi dogrulanir
        self.assertTrue(any(f.rule_id == "MISSING_OR_INVALID_SHEBANG" for f in report.findings))  # Bulgu kontrolu

    def test_03_detect_missing_strict_mode(self) -> None:
        """Kati kip (set -euo pipefail) eksikliginin HIGH seviyede yakalandigini test eder."""
        snippet = "#!/usr/bin/env bash\necho 'No strict mode'\n"  # Kati modsuz betik
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertFalse(report.has_strict_mode)  # Kati kip olmadigi dogrulanir
        self.assertTrue(any(f.rule_id == "MISSING_STRICT_MODE" for f in report.findings))  # Bulgu kontrolu

    def test_04_detect_dangerous_eval(self) -> None:
        """Dinamik eval komutunun CRITICAL seviyede komut enjeksiyonu olarak yakalandigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\neval $USER_INPUT\n"  # eval iceren betik
        report = self.auditor.audit_script_text(snippet)  # Denetim calistirilir
        self.assertTrue(any(f.rule_id == "DANGEROUS_EVAL_USAGE" for f in report.findings))  # Bulgu kurali
        self.assertTrue(any(f.severity == BashSeverity.CRITICAL for f in report.findings))  # Seviye kontrolu

    def test_05_detect_dangerous_eval_strict_exception(self) -> None:
        """strict=True modunda eval tespit edildiginde DangerousEvalException firlatildigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\neval $DYNAMIC_CMD\n"  # eval betigi
        with self.assertRaises(DangerousEvalException):  # Istisna beklenir
            self.auditor.audit_script_text(snippet, strict=True)  # Kati modda calistirilir

    def test_06_detect_catastrophic_unquoted_rm(self) -> None:
        """rm -rf komutunda tirnaksiz degisken genislemesinin CRITICAL risk olarak yakalandigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\nrm -rf $TARGET_DIR/*\n"  # Tirnaksiz rm
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_id == "CATASTROPHIC_UNQUOTED_VARIABLE" for f in report.findings))  # Bulgu

    def test_07_detect_catastrophic_unquoted_rm_strict_exception(self) -> None:
        """strict=True modunda tirnaksiz rm tespit edildiginde UnquotedVariableException firlatildigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\nrm -rf $TARGET_DIR\n"  # Tirnaksiz rm
        with self.assertRaises(UnquotedVariableException):  # Istisna beklenir
            self.auditor.audit_script_text(snippet, strict=True)  # Kati modda denenir

    def test_08_detect_unquoted_array_expansion(self) -> None:
        """Tirnaksiz $* ve $@ kullaniminin HIGH riskli kural ihlali olarak tespit edildigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\necho $*\n"  # Tirnaksiz $*
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_id == "UNQUOTED_ARRAY_EXPANSION" for f in report.findings))  # Bulgu kontrolu

    def test_09_detect_unquoted_ls_loop(self) -> None:
        """for f in $(ls ...) kalibinin kelime bolunmesi riski olarak yakalandigini test eder."""
        snippet = "#!/usr/bin/env bash\nset -euo pipefail\nfor f in $(ls /tmp); do echo $f; done\n"  # ls dongusu
        report = self.auditor.audit_script_text(snippet)  # Denetim yapilir
        self.assertTrue(any(f.rule_id == "UNQUOTED_LS_COMMAND_SUBSTITUTION" for f in report.findings))  # Bulgu

    def test_10_word_splitting_simulation_quoted_vs_unquoted(self) -> None:
        """Simulatorde tirnakli ve tirnaksiz genislemelerin kelime bolunmesi farkini test eder."""
        payload = "dosya adi bosluklu.txt diger_dosya.log"  # Bosluklu dosya adlari
        tokens_unquoted = RuntimeWordSplittingSimulator.simulate_expansion(payload, quoted=False)  # Tirnaksiz
        tokens_quoted = RuntimeWordSplittingSimulator.simulate_expansion(payload, quoted=True)  # Tirnakli
        self.assertEqual(len(tokens_unquoted), 4)  # Tirnaksizda 4 ayri sozcuk olusmali
        self.assertEqual(len(tokens_quoted), 1)  # Tirnaklida tek sozcuk kalmali
        self.assertEqual(tokens_quoted[0], payload)  # Deger bozulmamali

    def test_11_globbing_flag_injection_detection(self) -> None:
        """Simulatorde tire (-) ile baslayan parametrelerin bayrak enjeksiyonu olarak algilandigini test eder."""
        tokens = ["normal_file.txt", "-rf", "test.log"]  # -rf iceren liste
        has_flag_risk = RuntimeWordSplittingSimulator.test_flag_injection_risk(tokens)  # Risk kontrolu
        self.assertTrue(has_flag_risk)  # Bayrak riski tespit edilmeli

    def test_12_reject_null_byte(self) -> None:
        """Betik metninde null-byte (0x00) bulunmasi durumunda NullByteForbiddenException firlatildigini test eder."""
        with self.assertRaises(NullByteForbiddenException):  # Istisna beklenir
            self.auditor.audit_script_text("#!/bin/bash\necho 'test\x00data'\n")  # Null byte iceren betik

    def test_13_reject_oversized_script(self) -> None:
        """64 KB limitini asan devasa betiklerde BashScriptSizeLimitException firlatildigini test eder."""
        huge_script = "#!/bin/bash\n" + ("# yorum satir\n" * 5000)  # Devasa metin
        with self.assertRaises(BashScriptSizeLimitException):  # Istisna beklenir
            self.auditor.audit_script_text(huge_script)  # Limit kontrolu

    def test_14_audit_vulnerable_script_full_report(self) -> None:
        """Zaafiyetli ornek betigin tum aciklarinin tespit edildigini ve is_secure=False dondugunu dogrular."""
        report = self.auditor.audit_script_file(self.vulnerable_script_path)  # Zaafiyetli betik okunur
        self.assertFalse(report.is_secure)  # Guvenli olmamali
        self.assertFalse(report.has_strict_mode)  # Kati kip olmamali
        rule_ids = [f.rule_id for f in report.findings]  # Kural kimlikleri listelenir
        self.assertIn("DANGEROUS_EVAL_USAGE", rule_ids)  # eval bulunmali
        self.assertIn("CATASTROPHIC_UNQUOTED_VARIABLE", rule_ids)  # rm bulunmali
        self.assertIn("UNQUOTED_ARRAY_EXPANSION", rule_ids)  # $* bulunmali


if __name__ == "__main__":
    unittest.main()  # Modul calistirildiginda testler yurutulur
