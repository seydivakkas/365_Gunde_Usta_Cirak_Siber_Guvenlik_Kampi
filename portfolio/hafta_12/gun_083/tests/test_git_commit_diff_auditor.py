# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G083: Git commit ve degisiklik inceleme motoru birim testleri (Unit Tests).
Bu test paketi, GitCommitDiffAuditor bileseninin ayrastirma, guvenlik taramasi,
Shannon entropisi hesaplama, Trojan Source ve DoS onleme yeteneklerini dogrular.
"""

from pathlib import Path  # Dosya sistemi yollari icin Path modulu ice aktarilir
import unittest  # Birim test cercevesi ice aktarilir

from portfolio.hafta_12.gun_083.uygulama.git_commit_diff_auditor import (  # Uygulama modulu siniflari ice aktarilir
    AuditVerdict,  # Karar enum degeri
    DiffSizeLimitExceededException,  # Boyut asim istisnasi
    FindingSeverity,  # Bulgu onem seviyesi enum degeri
    GitCommitDiffAuditor,  # Façade denetim motoru sinifi
    HighEntropySecretException,  # Yuksek entropi istisnasi
    MalformedDiffException,  # Bozuk format istisnasi
    SecretDetectedException,  # Gizli anahtar istisnasi
    ShannonEntropyCalculator,  # Entropi hesaplayici
    TrojanSourceAttackException,  # Trojan source istisnasi
    UnifiedDiffParser,  # Diff ayrastirici sinif
)


class TestGitCommitDiffAuditor(unittest.TestCase):
    """Git commit ve diff inceleme motoru test senaryolari."""

    def setUp(self) -> None:
        """Her test kosulundan once calisarak temiz bir denetim motoru ve ornek diff yukler."""
        self.auditor = GitCommitDiffAuditor()  # Varsayilan denetim motoru ornegi olusturulur
        ornek_diff_yolu = Path(__file__).resolve().parent.parent / "ornek_veri" / "sample_commit.diff"  # Ornek yol
        with open(ornek_diff_yolu, "r", encoding="utf-8") as f:  # Ornek diff dosyasi acilir
            self.temiz_diff_metni = f.read()  # Dosya icerigi degiskene yuklenir

    def test_01_parse_valid_safe_commit_metadata(self) -> None:
        """Gecerli commit ustbilgilerinin (hash, yazar, e-posta, mesaj) basariyla ayrastirildigini dogrular."""
        parser = UnifiedDiffParser()  # Bagimsiz parser ornegi olusturulur
        metadata, _ = parser.parse(self.temiz_diff_metni)  # Diff ayrastirilarak metadata alinir
        self.assertEqual(metadata.commit_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")  # Hash
        self.assertEqual(metadata.yazar_adi, "Seydi Eryilmaz")  # Yazar adi kontrol edilir
        self.assertEqual(metadata.yazar_eposta, "seydi@guvenlik.local")  # E-posta kontrol edilir
        self.assertIn("feat(security): refactor authentication middleware", metadata.mesaj)  # Mesaj icerigi

    def test_02_parse_file_deltas_and_hunks(self) -> None:
        """Dosya deltalarinin, eklenen ve silinen satir adetlerinin dogru ayrastirildigini test eder."""
        parser = UnifiedDiffParser()  # Parser olusturulur
        _, dosyalar = parser.parse(self.temiz_diff_metni)  # Dosya listesi ayrastirilir
        self.assertEqual(len(dosyalar), 2)  # Ornek diff icerisinde 2 dosya oldugu dogrulanir
        self.assertEqual(dosyalar[0].yeni_yol, "src/auth/middleware.py")  # Ilk dosya yolu kontrol edilir
        self.assertEqual(dosyalar[1].yeni_yol, "config/security.json")  # Ikinci dosya yolu kontrol edilir
        self.assertGreater(dosyalar[0].eklenen_toplam, 0)  # Eklenen satir sayisi sifirdan buyuk olmali
        self.assertGreater(dosyalar[0].silinen_toplam, 0)  # Silinen satir sayisi sifirdan buyuk olmali

    def test_03_audit_clean_commit_approved(self) -> None:
        """Guvenli ve temiz degisikliklerin 100 puan ile APPROVE karari aldigini dogrular."""
        rapor = self.auditor.audit(self.temiz_diff_metni)  # Temiz diff denetlenir
        self.assertEqual(rapor.verdict, AuditVerdict.APPROVE)  # Kararin onay oldugu dogrulanir
        self.assertEqual(rapor.guvenlik_puani, 100)  # Guvenlik puaninin tam 100 oldugu dogrulanir
        self.assertEqual(len(rapor.bulgular), 0)  # Hicbir guvenlik bulgusu olmamalidir

    def test_04_shannon_entropy_calculation_accuracy(self) -> None:
        """Shannon entropi hesaplayicisinin dusuk ve yuksek entropili metinleri dogru olctugunu test eder."""
        dusuk_entropi = ShannonEntropyCalculator.calculate_entropy("aaaaaaa")  # Tekrar eden karakterler
        self.assertEqual(dusuk_entropi, 0.0)  # Tekrar eden karakter entropisi sifir olmalidir
        orta_entropi = ShannonEntropyCalculator.calculate_entropy("hello world")  # Duz metin entropisi
        self.assertLess(orta_entropi, 3.5)  # Duz metin 3.5 bit/karakterden az olmalidir
        yuksek_entropi = ShannonEntropyCalculator.calculate_entropy("s7K9#mQ2$vL8!pZ4@wX1%yR3^bN6&cT5")  # Rastgele token
        self.assertGreater(yuksek_entropi, 4.5)  # Yuksek entropi 4.5 bit/karakterden yuksek olmalidir

    def test_05_detect_hardcoded_aws_access_key(self) -> None:
        """Diff icine eklenen hardcoded AWS anahtarinin CRITICAL seviyede yakalandigini test eder."""
        diff_payload = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )  # AWS anahtari iceren diff
        rapor = self.auditor.audit(diff_payload)  # Denetim yapilir
        self.assertEqual(rapor.verdict, AuditVerdict.REJECT)  # Commit reddedilmeli
        self.assertTrue(any(b.kural_adi == "AWS_ACCESS_KEY" for b in rapor.bulgular))  # AWS kurali bulunmali
        self.assertTrue(any(b.severity == FindingSeverity.CRITICAL for b in rapor.bulgular))  # Seviye kritik olmali

    def test_06_detect_rsa_private_key_block(self) -> None:
        """Diff icine sizdirilan RSA ozel anahtar blogunun tespit edildigini test eder."""
        diff_payload = (
            "diff --git a/server.key b/server.key\n"
            "--- a/server.key\n"
            "+++ b/server.key\n"
            "@@ -0,0 +1,2 @@\n"
            "+-----BEGIN RSA PRIVATE KEY-----\n"
            "+MIIEowIBAAKCAQEA0Y1mQv7\n"
        )  # RSA basligi iceren diff
        rapor = self.auditor.audit(diff_payload)  # Denetim yapilir
        self.assertEqual(rapor.verdict, AuditVerdict.REJECT)  # Commit reddedilmeli
        self.assertTrue(any(b.kural_adi == "RSA_PRIVATE_KEY" for b in rapor.bulgular))  # Kural eslesmesi

    def test_07_detect_github_personal_access_token(self) -> None:
        """Diff icine eklenen GitHub PAT belirtecinin tespit edildigini test eder."""
        diff_payload = (
            "diff --git a/ci.yml b/ci.yml\n"
            "--- a/ci.yml\n"
            "+++ b/ci.yml\n"
            "@@ -1,1 +1,2 @@\n"
            "+TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyzAB'\n"
        )  # GitHub PAT diff
        rapor = self.auditor.audit(diff_payload)  # Denetim calistirilir
        self.assertEqual(rapor.verdict, AuditVerdict.REJECT)  # Karar ret olmali
        self.assertTrue(any(b.kural_adi == "GITHUB_PAT" for b in rapor.bulgular))  # Kural adi dogrulanir

    def test_08_detect_trojan_source_bidi_character(self) -> None:
        """CVE-2021-42574 Trojan Source Bidi karakteri enjeksiyonunun CRITICAL olarak yakalandigini test eder."""
        diff_payload = (
            "diff --git a/auth.py b/auth.py\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -5,1 +5,2 @@\n"
            "+is_admin = False \u202e } \u2066if True\u2069 \u2066 begin admin \n"
        )  # Bidi override karakteri iceren diff
        rapor = self.auditor.audit(diff_payload)  # Denetim calistirilir
        self.assertEqual(rapor.verdict, AuditVerdict.REJECT)  # Karar ret olmali
        self.assertTrue(any(b.kural_adi == "TROJAN_SOURCE_BIDI_INJECTION" for b in rapor.bulgular))  # Kural kontrolu

    def test_09_detect_trojan_source_in_commit_message(self) -> None:
        """Commit basliginda ve aciklama mesajinda gizlenen Bidi kontrol karakterlerinin tespitini test eder."""
        diff_payload = (
            "commit 112233445566778899aabbccddeeff0011223344\n"
            "Author: Attacker <hacker@evil.local>\n"
            "Date:   Sun Nov 1 04:00:00 2026 +0300\n"
            "\n"
            "    fix bug in auth \u202e malicious message payload\n"
            "\n"
            "diff --git a/a.txt b/a.txt\n"
            "--- a/a.txt\n"
            "+++ b/a.txt\n"
            "@@ -1,1 +1,1 @@\n"
            "+safe\n"
        )  # Commit mesajinda Bidi karakteri
        rapor = self.auditor.audit(diff_payload)  # Denetim calistirilir
        self.assertTrue(any(b.kural_adi == "TROJAN_SOURCE_IN_COMMIT_MESSAGE" for b in rapor.bulgular))  # Kural

    def test_10_detect_dangerous_code_eval_and_exec(self) -> None:
        """Diff ile eklenen eval() gibi tehlikeli kod yurutme fonksiyonlarinin tespitini dogrular."""
        diff_payload = (
            "diff --git a/handler.py b/handler.py\n"
            "--- a/handler.py\n"
            "+++ b/handler.py\n"
            "@@ -10,1 +10,2 @@\n"
            "+parsed_val = eval(user_supplied_str)\n"
        )  # eval cagrisi eklenen diff
        rapor = self.auditor.audit(diff_payload)  # Denetim yapilir
        self.assertEqual(rapor.verdict, AuditVerdict.REJECT)  # Karar ret olmali
        self.assertTrue(any(b.kural_adi == "DANGEROUS_EVAL" for b in rapor.bulgular))  # Eval bulgusu bulunmali

    def test_11_detect_high_entropy_secret_token(self) -> None:
        """Standart kaliplara uymayan ancak yuksek entropiye sahip rastgele parolalarin tespitini dogrular."""
        diff_payload = (
            "diff --git a/const.py b/const.py\n"
            "--- a/const.py\n"
            "+++ b/const.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+SECRET_SALT = 's7K9#mQ2$vL8!pZ4@wX1%yR3^bN6&cT5'\n"
        )  # Yuksek entropili token eklenen diff
        rapor = self.auditor.audit(diff_payload)  # Denetim yapilir
        self.assertTrue(any(b.kural_adi == "HIGH_ENTROPY_SECRET_DETECTED" for b in rapor.bulgular))  # Entropi kurali

    def test_12_fail_fast_mode_raises_exception_immediately(self) -> None:
        """fail_fast=True parametresi verildiginde ilk kritik ihlalde istisna firlatildigini dogrular."""
        diff_payload = (
            "diff --git a/sec.py b/sec.py\n"
            "--- a/sec.py\n"
            "+++ b/sec.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )  # AWS anahtari
        with self.assertRaises(SecretDetectedException):  # Aninda firlatilmasi beklenen istisna
            self.auditor.audit(diff_payload, fail_fast=True)  # Hizli hata modunda calistirilir

    def test_13_reject_null_byte_in_diff(self) -> None:
        """Diff akisina enjekte edilen null byte (0x00) karakterinin MalformedDiffException ile reddini test eder."""
        diff_payload = "diff --git a/test.py b/test.py\n\x00corrupt"  # Null byte iceren diff
        with self.assertRaises(MalformedDiffException):  # Istisna beklenir
            self.auditor.audit(diff_payload)  # Ayrastirma denenir

    def test_14_reject_oversized_diff_bomb(self) -> None:
        """Maksimum bayt veya satir limitini asan diff akisinin DoS korumasi ile reddini test eder."""
        kucuk_parser = UnifiedDiffParser(max_bytes=100)  # 100 baytlik kucuk sinir tanimlanir
        buyuk_diff = "diff --git a/big.py b/big.py\n" + ("+line\n" * 50)  # 100 bayti rahatlikla asan diff
        with self.assertRaises(DiffSizeLimitExceededException):  # Boyut asim istisnasi beklenir
            kucuk_parser.parse(buyuk_diff)  # Ayrastirma yapilir


if __name__ == "__main__":
    unittest.main()  # Test modulu dogrudan calistirildiginda unit testler baslatilir
