# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G071: Python Ortamı ve Bağımlılık Tedarik Zinciri Güvenlik Test Paketi.

Bu modül, PythonEnvAndDependencyAuditor sınıfının yeteneklerini
14 birim test ve 9 negatif sınır vakası üzerinden sınar.
"""

# Birim test çerçevesi için unittest modülünü dahil ediyoruz.
import unittest
# JSON veri yükleme ve denetimi için json modülünü içeri aktarıyoruz.
import json
# Dosya yolları ve işletim sistemi kontrolleri için os kütüphanesini çağırıyoruz.
import os

# Test edilecek analizör ve özel istisna sınıfını uygulama modülünden alıyoruz.
from portfolio.hafta_11.gun_071.uygulama.python_env_and_dependency_auditor import (
    PythonEnvAndDependencyAuditor,
    EnvSecurityAuditError,
)


class TestPythonEnvAndDependencyAuditor(unittest.TestCase):
    """Python sanal ortam ve bağımlılık denetleyicisi birim test sınıfı."""

    @classmethod
    def setUpClass(cls) -> None:
        """Tüm testler öncesinde örnek veri dosyalarını yükler."""
        # pyvenv.cfg dosya yolunu belirliyoruz.
        cls.pyvenv_cfg_path = os.path.join(
            "portfolio", "hafta_11", "gun_071", "ornek_veri", "pyvenv.cfg"
        )
        # Güvenli requirements.txt dosya yolunu belirliyoruz.
        cls.req_path = os.path.join(
            "portfolio", "hafta_11", "gun_071", "ornek_veri", "guvenli_requirements.txt"
        )
        # Negatif test girdileri dosya yolunu belirliyoruz.
        cls.invalid_data_path = os.path.join(
            "portfolio", "hafta_11", "gun_071", "ornek_veri", "invalid_env_inputs.json"
        )

        # pyvenv.cfg içeriğini UTF-8 ile okuyoruz.
        with open(cls.pyvenv_cfg_path, "r", encoding="utf-8") as f:
            # Yapılandırma metnini değişkene alıyoruz.
            cls.pyvenv_text = f.read()

        # requirements.txt içeriğini UTF-8 ile okuyoruz.
        with open(cls.req_path, "r", encoding="utf-8") as f:
            # Bağımlılık metnini değişkene alıyoruz.
            cls.req_text = f.read()

        # Negatif test senaryolarını JSON olarak yüklüyoruz.
        with open(cls.invalid_data_path, "r", encoding="utf-8") as f:
            # JSON verisini sözlüğe ayrıştırıyoruz.
            cls.invalid_data = json.load(f)

    def setUp(self) -> None:
        """Her testten önce taze bir analizör nesnesi ilklendirir."""
        # Analizör nesnesini varsayılan parametrelerle başlatıyoruz.
        self.auditor = PythonEnvAndDependencyAuditor()

    def test_01_valid_pyvenv_cfg_audit(self) -> None:
        """Geçerli pyvenv.cfg dosyasının hatasız ayrıştırılıp tam izole onay aldığını sınar."""
        # Konfigürasyon metnini ayrıştırıyoruz.
        cfg_map = self.auditor.parse_pyvenv_cfg(self.pyvenv_text)
        # Ayrıştırılan anahtar sayısını kontrol ediyoruz.
        self.assertIn("home", cfg_map)
        # Yalıtım denetimini icra ediyoruz.
        result = self.auditor.audit_pyvenv_cfg(cfg_map)
        # Durumun PASS olduğunu teyit ediyoruz.
        self.assertEqual(result["status"], "PASS")
        # Tam yalıtım bayrağının True olduğunu sınıyoruz.
        self.assertTrue(result["hermetic_isolation"])
        # Sürüm numarasının 3.12.2 olduğunu doğruluyoruz.
        self.assertEqual(result["python_version"], "3.12.2")

    def test_02_valid_requirements_parsing_with_hashes(self) -> None:
        """Güvenli requirements.txt dosyasının 6 paket ve SHA-256 hashleri ile ayrıştırıldığını test eder."""
        # Bağımlılık dosyasını ayrıştırıyoruz.
        packages = self.auditor.parse_requirements_content(self.req_text, strict_hash=True)
        # Toplam paket adedinin 6 olduğunu teyit ediyoruz.
        self.assertEqual(len(packages), 6)
        # Her bir paketin == işlecine ve en az 1 hash değerine sahip olduğunu sınıyoruz.
        for p in packages:
            # Kesin sürüm işleci kontrolü.
            self.assertEqual(p["operator"], "==")
            # Hash sayısının en az 1 olduğunu teyit ediyoruz.
            self.assertGreaterEqual(p["hash_count"], 1)
            # Güvenlik durumunun SECURE olduğunu kontrol ediyoruz.
            self.assertEqual(p["status"], "SECURE")

    def test_03_full_security_audit_pipeline(self) -> None:
        """Tam güvenlik boru hattının PASS ve 100 tam puan ürettiğini test eder."""
        # Tam boru hattını çalıştırıyoruz.
        audit_res = self.auditor.run_full_security_audit(
            pyvenv_cfg_path=self.pyvenv_cfg_path,
            requirements_path=self.req_path,
            strict_hash=True
        )
        # Genel durumun PASS olduğunu teyit ediyoruz.
        self.assertEqual(audit_res["overall_status"], "PASS")
        # Hijyen skorunun 100.0 olduğunu sınıyoruz.
        self.assertEqual(audit_res["security_hygiene_score"], 100.0)
        # Hash kapsama oranının %100 olduğunu kontrol ediyoruz.
        self.assertEqual(audit_res["hash_coverage_pct"], 100.0)
        # Typosquatting tespitinin 0 olduğunu doğruluyoruz.
        self.assertEqual(audit_res["typosquatting_detected"], 0)

    def test_04_text_and_json_report_generation(self) -> None:
        """Metin ve JSON rapor formatlarının eksiksiz ve hatasız üretildiğini sınar."""
        # Denetim sonucunu alıyoruz.
        audit_res = self.auditor.run_full_security_audit(
            pyvenv_cfg_path=self.pyvenv_cfg_path,
            requirements_path=self.req_path,
            strict_hash=True
        )
        # Metin raporunu üretiyoruz.
        txt_report = self.auditor.generate_text_report(audit_res)
        # Metin raporunda başlığın bulunduğunu teyit ediyoruz.
        self.assertIn("G071: PYTHON ÇALIŞMA ORTAMI VE BAĞIMLILIK", txt_report)
        # Yalıtım onayının raporda geçtiğini sınıyoruz.
        self.assertIn("TAM İZOLE (PASS)", txt_report)

        # JSON raporunu üretiyoruz.
        json_report = self.auditor.generate_json_report(audit_res)
        # JSON dizgisini nesneye ayrıştırıyoruz.
        parsed = json.loads(json_report)
        # Ayrıştırılan JSON nesnesinin skorunu kontrol ediyoruz.
        self.assertEqual(parsed["security_hygiene_score"], 100.0)

    def test_05_levenshtein_distance_algorithm(self) -> None:
        """Levenshtein düzenleme uzaklığı fonksiyonunun doğru hesaplama yaptığını sınar."""
        # Aynı iki kelimenin uzaklığının 0 olduğunu teyit ediyoruz.
        self.assertEqual(self.auditor._levenshtein_distance("requests", "requests"), 0)
        # Tek harf yer değişimi (typosquat: reqeusts) uzaklığının 2 olduğunu sınıyoruz.
        self.assertEqual(self.auditor._levenshtein_distance("reqeusts", "requests"), 2)
        # Tek harf eksikliğinin uzaklığının 1 olduğunu doğruluyoruz.
        self.assertEqual(self.auditor._levenshtein_distance("scap", "scapy"), 1)

    def test_06_neg_01_corrupt_pyvenv_cfg(self) -> None:
        """NEG_01: Eşittir içermeyen bozuk pyvenv.cfg satırında istisna fırlatıldığını sınar."""
        # Negatif veri senaryosunu çekiyoruz.
        case = self.invalid_data["NEG_01_CORRUPT_PYVENV_CFG"]
        # EnvSecurityAuditError istisnasının tetiklendiğini sınıyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Bozuk metin ile ayrıştırma yapıyoruz.
            self.auditor.parse_pyvenv_cfg(case["cfg_content"])
        # Beklenen hata mesajının varlığını teyit ediyoruz.
        self.assertIn("ayrıştırılamayan anahtar-değer satırı", str(ctx.exception))

    def test_07_neg_02_system_packages_leak(self) -> None:
        """NEG_02: include-system-site-packages true olduğunda yalıtım ihlali fırlatıldığını sınar."""
        # Negatif test verisini alıyoruz.
        case = self.invalid_data["NEG_02_SYSTEM_PACKAGES_LEAK"]
        # Yapılandırma sözlüğünü oluşturuyoruz.
        cfg_map = self.auditor.parse_pyvenv_cfg(case["cfg_content"])
        # İstisna oluşumunu kontrol ediyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Denetimi tetikliyoruz.
            self.auditor.audit_pyvenv_cfg(cfg_map)
        # Yalıtım ihlali mesajını sınıyoruz.
        self.assertIn("Yalıtım ihlali", str(ctx.exception))

    def test_08_neg_03_obsolete_python_version(self) -> None:
        """NEG_03: Python 2.7 gibi eski/miras sürümlerde hata fırlatıldığını sınar."""
        # Negatif veriyi yüklüyoruz.
        case = self.invalid_data["NEG_03_OBSOLETE_PYTHON_VERSION"]
        # Yapılandırmayı ayrıştırıyoruz.
        cfg_map = self.auditor.parse_pyvenv_cfg(case["cfg_content"])
        # İstisnanın tetiklendiğini kontrol ediyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Denetimi başlatıyoruz.
            self.auditor.audit_pyvenv_cfg(cfg_map)
        # Miras Python sürüm uyarısını teyit ediyoruz.
        self.assertIn("Miras Python sürümü", str(ctx.exception))

    def test_09_neg_04_unpinned_package(self) -> None:
        """NEG_04: Sürüm belirtilmemiş pakette istisna fırlatıldığını sınar."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_04_UNPINNED_PACKAGE"]
        # İstisnanın oluştuğunu sınıyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Sürüm belirtilmemiş paket satırını ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"])
        # Sabitlenmemiş paket uyarısını teyit ediyoruz.
        self.assertIn("Sabitlenmemiş paket tespiti", str(ctx.exception))

    def test_10_neg_05_loosely_pinned_package(self) -> None:
        """NEG_05: >= gibi gevşek sürüm sabitlemelerinde hata verildiğini sınar."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_05_LOOSELY_PINNED_PACKAGE"]
        # İstisna oluşumunu sınıyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Gevşek sabitleme satırını ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"])
        # Gevşek sürüm uyarısını teyit ediyoruz.
        self.assertIn("Gevşek sürüm sabitleme", str(ctx.exception))

    def test_11_neg_06_typosquatting_attack(self) -> None:
        """NEG_06: Typosquatting saldırısı tespit edildiğinde hata fırlatıldığını sınar."""
        # Negatif test senaryosunu alıyoruz.
        case = self.invalid_data["NEG_06_TYPOSQUATTING_ATTACK"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # reqeusts satırını ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"])
        # Typosquatting uyarısının verildiğini teyit ediyoruz.
        self.assertIn("Typosquatting", str(ctx.exception))

    def test_12_neg_07_known_vulnerability(self) -> None:
        """NEG_07: Bilinen zafiyetli kütüphane sürümü tespitinde CVE hatası verildiğini sınar."""
        # Negatif vakayı yüklüyoruz.
        case = self.invalid_data["NEG_07_KNOWN_VULNERABILITY"]
        # İstisnanın fırlatıldığını denetliyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # urllib3==1.26.5 satırını ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"])
        # CVE uyarısının bulunduğunu teyit ediyoruz.
        self.assertIn("CVE-2023-45803", str(ctx.exception))

    def test_13_neg_08_missing_hash_pinning(self) -> None:
        """NEG_08: Sıkı modda SHA-256 hash sabitlemesi bulunmadığında hata verildiğini sınar."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_08_MISSING_HASH_PINNING"]
        # İstisnayı sınıyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Hashsiz satırı strict_hash=True ile ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"], strict_hash=True)
        # Kriptografik bütünlük uyarısını teyit ediyoruz.
        self.assertIn("Kriptografik bütünlük eksikliği", str(ctx.exception))

    def test_14_neg_09_malformed_hash(self) -> None:
        """NEG_09: Hatalı veya geçersiz SHA-256 hash biçiminde hata fırlatıldığını sınar."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_09_MALFORMED_HASH"]
        # İstisna kontrolünü icra ediyoruz.
        with self.assertRaises(EnvSecurityAuditError) as ctx:
            # Geçersiz hash içeren satırı ayrıştırıyoruz.
            self.auditor.parse_requirements_content(case["req_line"], strict_hash=True)
        # Geçersiz hash biçimi uyarısını teyit ediyoruz.
        self.assertIn("Geçersiz SHA-256 hash biçimi", str(ctx.exception))


# Test modülünün doğrudan çalıştırılmasını yönetiyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
