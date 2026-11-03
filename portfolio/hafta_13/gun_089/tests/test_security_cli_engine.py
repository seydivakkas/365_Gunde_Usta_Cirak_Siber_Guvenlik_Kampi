# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G089: Argparse ve CLI Güvenlik Motoru Birim Testleri (unittest).
Bu test paketi; alt komut ayrıştırmasını, karşılıklı dışlayan parametreleri,
dizin atlama korumasını (CWE-22), port aralıklarını (CWE-20), kriptografik özetleri
ve DoS tavan kontrollerini doğrular.
"""

from pathlib import Path  # Dosya yollari yonetimi icin Path modulu
import unittest  # Birim test kutuphanesi

from portfolio.hafta_13.gun_089.uygulama.security_cli_engine import (  # Uygulama bilesenleri
    CliMissingRequiredSubcommandException,  # Eksik alt komut istisnasi
    CliMutuallyExclusiveConflictException,  # Cakisma istisnasi
    CliNullByteException,  # Null byte istisnasi
    CliOversizedPayloadException,  # Boyut limiti istisnasi
    CliPathTraversalException,  # Dizin atlama istisnasi
    CliPortOutOfRangeException,  # Port aralik disi istisnasi
    InvalidCliArgumentException,  # Gecersiz arguman istisnasi
    SecurityCliEngine,  # Façade motor sinifi
)


class TestSecurityCliEngine(unittest.TestCase):
    """Argparse ve CLI guvenlik motoru test senaryolari."""

    def setUp(self) -> None:
        """Her test kosumundan once taze motor ornegi ve ornek veri yollarini hazirlar."""
        self.engine = SecurityCliEngine()  # Motor nesnesi olusturulur
        self.sample_file = Path(__file__).resolve().parent.parent / "ornek_veri" / "sample_cli_commands.json"

    def test_01_parse_valid_scan_subcommand(self) -> None:
        """scan alt komutunun gecerli host ve port parametreleriyle basariyla ayrastirildigini test eder."""
        args = ["scan", "--host", "10.0.0.1", "--port", "8443", "--mode", "thorough"]
        ns = self.engine.parse_arguments(args)  # Ayrastirma yapilir
        self.assertEqual(ns.subcommand, "scan")  # Alt komut scan olmali
        self.assertEqual(ns.host, "10.0.0.1")  # Host dogrulanmali
        self.assertEqual(ns.port, 8443)  # Port integer olmali
        res = self.engine.execute_cli_action(ns)  # Eylem yurutulur
        self.assertEqual(res["status"], "COMPLETED")  # Durum dogrulanir

    def test_02_parse_valid_audit_subcommand(self) -> None:
        """audit alt komutunun var olan dosya ile basariyla calistigini dogrular."""
        args = ["audit", "--file", self.sample_file.as_posix(), "--strict"]
        ns = self.engine.parse_arguments(args)  # Ayrastirma
        self.assertEqual(ns.subcommand, "audit")  # Alt komut audit
        self.assertTrue(ns.strict)  # Strict aktif olmali
        res = self.engine.execute_cli_action(ns)  # Yurutulur
        self.assertEqual(res["status"], "SECURE")  # Guvenli durum kontrolu

    def test_03_parse_valid_hash_subcommand(self) -> None:
        """hash alt komutunun SHA256 ozetini basariyla hesapladigini test eder."""
        args = ["hash", "--file", self.sample_file.as_posix(), "--algo", "sha256"]
        ns = self.engine.parse_arguments(args)  # Ayrastirma
        res = self.engine.execute_cli_action(ns)  # Ozet hesaplanir
        self.assertEqual(res["status"], "VERIFIED")  # Dogrulandi
        self.assertEqual(res["algorithm"], "SHA256")  # Algoritma kontrolu
        self.assertEqual(len(res["digest"]), 64)  # 64 karakter hex ozet olmali

    def test_04_reject_missing_subcommand(self) -> None:
        """Zorunlu alt komut girilmediginde CliMissingRequiredSubcommandException firlatildigini test eder."""
        with self.assertRaises(CliMissingRequiredSubcommandException):  # Istisna beklenir
            self.engine.parse_arguments([])  # Bos arguman girilir

    def test_05_reject_mutually_exclusive_flags(self) -> None:
        """--fast ve --deep bayraklari ayni anda girildiginde CliMutuallyExclusiveConflictException test eder."""
        args = ["scan", "--host", "127.0.0.1", "--port", "80", "--fast", "--deep"]
        with self.assertRaises(CliMutuallyExclusiveConflictException):  # Cakisma beklenir
            self.engine.parse_arguments(args)  # Calistirilir

    def test_06_reject_path_traversal_in_file_arg(self) -> None:
        """--file parametresinde '..' dizin atlama girisiminin engellendigini dogrular."""
        args = ["audit", "--file", "../../etc/passwd"]
        with self.assertRaises(CliPathTraversalException):  # Dizin atlama istisnasi
            self.engine.parse_arguments(args)

    def test_07_reject_nonexistent_file(self) -> None:
        """Dosya sisteminde var olmayan dosya yolunda InvalidCliArgumentException firlatildigini test eder."""
        args = ["audit", "--file", "portfolio/hafta_13/gun_089/ornek_veri/missing_file_xyz.txt"]
        with self.assertRaises(InvalidCliArgumentException):  # Gecersiz dosya istisnasi
            self.engine.parse_arguments(args)

    def test_08_reject_port_out_of_range(self) -> None:
        """65535'ten buyuk port degerinde CliPortOutOfRangeException firlatildigini dogrular."""
        args = ["scan", "--host", "127.0.0.1", "--port", "75000"]
        with self.assertRaises(CliPortOutOfRangeException):  # Aralik disi port
            self.engine.parse_arguments(args)

    def test_09_reject_invalid_port_string(self) -> None:
        """Sayisal olmayan port degerinde CliPortOutOfRangeException firlatildigini test eder."""
        args = ["scan", "--host", "127.0.0.1", "--port", "http_port"]
        with self.assertRaises(CliPortOutOfRangeException):  # Tamsayi disi port
            self.engine.parse_arguments(args)

    def test_10_reject_host_command_injection(self) -> None:
        """Host adinda komut ayirici ozel karakterler oldugunda InvalidCliArgumentException test eder."""
        args = ["scan", "--host", "127.0.0.1; rm -rf /", "--port", "80"]
        with self.assertRaises(InvalidCliArgumentException):  # Enjeksiyon istisnasi
            self.engine.parse_arguments(args)

    def test_11_reject_weak_hash_algorithm(self) -> None:
        """Desteklenmeyen zayif kriptografik algoritma (md5) girildiginde secim hatasi firlatildigini test eder."""
        args = ["hash", "--file", self.sample_file.as_posix(), "--algo", "md5"]
        with self.assertRaises(InvalidCliArgumentException):  # Gecersiz secim
            self.engine.parse_arguments(args)

    def test_12_reject_null_byte_in_cli_argument(self) -> None:
        """Argumanda null-byte (0x00) tespit edildiginde CliNullByteException firlatildigini test eder."""
        args = ["scan", "--host", "server\x00.internal", "--port", "80"]
        with self.assertRaises(CliNullByteException):  # Null byte istisnasi
            self.engine.parse_arguments(args)

    def test_13_reject_oversized_argument_payload(self) -> None:
        """4096 karakterden uzun tekil argumanda CliOversizedPayloadException firlatildigini test eder."""
        huge_host = "A" * 5000  # Asiri uzun girdi
        args = ["scan", "--host", huge_host, "--port", "80"]
        with self.assertRaises(CliOversizedPayloadException):  # Boyut limiti istisnasi
            self.engine.parse_arguments(args)

    def test_14_reject_too_many_arguments_dos(self) -> None:
        """100'den fazla arguman ile DoS saldirisi girisiminde CliOversizedPayloadException test eder."""
        too_many_args = ["scan"] + ["--verbose"] * 150  # 151 arguman
        with self.assertRaises(CliOversizedPayloadException):  # Sayi limiti istisnasi
            self.engine.parse_arguments(too_many_args)


if __name__ == "__main__":
    unittest.main()  # Modul calistirildiginda birim testler yurutulur
