# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 078: Dosya Okuma ve Pathlib Güvenlik Birim Testleri
Bu test paketi; Path Traversal (CWE-22), Mutlak Yol Kaçışı, Null-Byte Enjeksiyonu,
Uzantı Beyaz Listesi, Boyut Sınırı ve Atomik Yazma işlemlerini 14 birim test ile doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# Yol ve sistem işlemleri için os ve sys modülleri içe aktarılır
import os
import sys
# Modern dosya yolları için pathlib içe aktarılır
from pathlib import Path

# Uygulama modülünü dinamik olarak içe aktarmak için modül yolu sys.path'e eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulanacak ana güvenlik dosya yöneticisi sınıfı içe aktarılır
from secure_file_and_path_manager import SecureFileAndPathManager


class TestSecureFileAndPathManager(unittest.TestCase):
    """
    Pathlib tabanlı güvenli dosya işlemlerini denetleyen test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde sandbox depo dizini belirlenir ve motor nesnesi oluşturulur.
        """
        self.sandbox_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "guvenli_dosya_deposu")
        )
        self.manager = SecureFileAndPathManager(self.sandbox_dir)

    def test_01_resolve_safe_path_valid_file(self) -> None:
        """
        Test 01: Sandbox içindeki meşru bir dosyanın (config.json) başarıyla çözümlendiğini doğrular.
        """
        resolved = self.manager.resolve_safe_path("config.json")
        self.assertTrue(resolved.is_file())
        self.assertEqual(resolved.name, "config.json")

    def test_02_resolve_safe_path_path_traversal_relative_raises(self) -> None:
        """
        Test 02: Göreceli dizin atlama (../../) ile sandbox dışına çıkma denemesinde PermissionError fırlatıldığını doğrular.
        """
        with self.assertRaises(PermissionError):
            self.manager.resolve_safe_path("../../Windows/System32/cmd.exe")

    def test_03_resolve_safe_path_absolute_windows_raises(self) -> None:
        """
        Test 03: Windows mutlak yol enjeksiyonunun (C:\\Windows...) PermissionError ile engellendiğini test eder.
        """
        with self.assertRaises(PermissionError):
            self.manager.resolve_safe_path("C:\\Windows\\System32\\drivers\\etc\\hosts")

    def test_04_resolve_safe_path_null_byte_raises(self) -> None:
        """
        Test 04: Dosya yoluna enjekte edilen Null-Byte (\\x00) karakterinin ValueError ürettiğini doğrular.
        """
        with self.assertRaises(ValueError):
            self.manager.resolve_safe_path("config.json\x00.exe")

    def test_05_resolve_safe_path_forbidden_extension_raises(self) -> None:
        """
        Test 05: İzin verilmeyen dosya uzantısının (.sh) ValueError ile reddedildiğini test eder.
        """
        with self.assertRaises(ValueError):
            self.manager.resolve_safe_path("exploit.sh")

    def test_06_safe_read_text_valid_content(self) -> None:
        """
        Test 06: Güvenli dosya okuyucunun dosya içeriğini hatasız şekilde okuduğunu doğrular.
        """
        content = self.manager.safe_read_text("config.json")
        self.assertIn("Kurumsal Guvenlik Sandbox Deposu", content)

    def test_07_safe_read_text_non_existent_raises(self) -> None:
        """
        Test 07: Var olmayan dosya talep edildiğinde FileNotFoundError fırlatıldığını doğrular.
        """
        with self.assertRaises(FileNotFoundError):
            self.manager.safe_read_text("missing_secret_vault.json")

    def test_08_safe_read_text_directory_as_file_raises(self) -> None:
        """
        Test 08: Dizin yolunun dosya gibi açılmaya çalışılmasında IsADirectoryError fırlatıldığını test eder.
        """
        with self.assertRaises(IsADirectoryError):
            self.manager.safe_read_text(".")

    def test_09_safe_read_text_size_exceeded_raises(self) -> None:
        """
        Test 09: Dosya boyutu tavanı aşıldığında (CWE-400) ValueError üretildiğini doğrular.
        """
        # 50 bayt sınır verilerek 226 baytlık log dosyasının okunması engellenir
        with self.assertRaises(ValueError):
            self.manager.safe_read_text("security_audit.log", max_bytes=50)

    def test_10_safe_stream_lines_yields_all_lines(self) -> None:
        """
        Test 10: Satır satır akış üretecinin (generator) bellek tüketmeden satırları doğru akıttığını doğrular.
        """
        lines = list(self.manager.safe_stream_lines("security_audit.log"))
        self.assertEqual(len(lines), 3)
        self.assertIn("[INFO] Guvenlik denetim servisi baslatildi.", lines[0])

    def test_11_atomic_write_text_creates_file(self) -> None:
        """
        Test 11: Atomik yazma fonksiyonunun geçici dosya (.tmp) üzerinden hedef dosyayı güvenle oluşturduğunu doğrular.
        """
        target_name = "test_atomic_policy.txt"
        test_content = "ENFORCEMENT=ACTIVE\nINTEGRITY=VERIFIED\n"
        written_path = self.manager.atomic_write_text(target_name, test_content)

        self.assertTrue(written_path.is_file())
        read_back = self.manager.safe_read_text(target_name)
        self.assertEqual(read_back, test_content)

        # Test sonrası temizlik
        if written_path.exists():
            written_path.unlink()

    def test_12_atomic_write_text_traversal_raises(self) -> None:
        """
        Test 12: Atomik yazma işleminde sandbox dışına dosya yazma girişiminin PermissionError ile engellendiğini doğrular.
        """
        with self.assertRaises(PermissionError):
            self.manager.atomic_write_text("../malicious_payload.txt", "MALICIOUS DATA")

    def test_13_inspect_sandbox_status_hashes(self) -> None:
        """
        Test 13: Sandbox denetim fonksiyonunun SHA-256 özetlerini ve dosya listesini doğru raporladığını doğrular.
        """
        status = self.manager.inspect_sandbox_status()
        self.assertGreaterEqual(status["total_files"], 3)
        file_names = [f["relative_path"] for f in status["files"]]
        self.assertIn("config.json", file_names)

    def test_14_invalid_sandbox_dir_init_raises(self) -> None:
        """
        Test 14: Var olmayan bir sandbox dizini ile başlatma denemesinde FileNotFoundError üretildiğini doğrular.
        """
        with self.assertRaises(FileNotFoundError):
            SecureFileAndPathManager("Z:\\Invalid_Non_Existent_Sandbox_Dir_9999")


if __name__ == "__main__":
    unittest.main()
