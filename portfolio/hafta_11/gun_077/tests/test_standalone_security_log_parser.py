# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 077: Mini Proje 10 — Bağımsız Log Ayrıştırıcı Birim Testleri
Bu test paketi; çok formatlı log ayrıştırma (Web, SSH, FW), ReDoS koruması,
Trojan Bidi ve Null-byte savunması, Brute-Force tespiti ve Whitelist bastırmasını 14 test ile doğrular.
"""

# Birim test çatısı için unittest modülü içe aktarılır
import unittest
# Dosya yolu manipülasyonu için os ve sys modülleri içe aktarılır
import os
import sys

# Uygulama modülünü dinamik olarak içe aktarmak için modül yolu sys.path'e eklenir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Doğrulanacak ana log ayrıştırıcı motor sınıfı içe aktarılır
from standalone_security_log_parser import StandaloneSecurityLogParser


class TestStandaloneSecurityLogParser(unittest.TestCase):
    """
    Mini Proje 10 log ayrıştırıcı motorunun işlevsel ve savunmacı yeteneklerini test eden sınıf.
    """

    def setUp(self) -> None:
        """
        Her test öncesinde bağımsız bir ayrıştırıcı motoru ve örnek kural seti oluşturulur.
        """
        self.parser = StandaloneSecurityLogParser()
        # IoC ve Beyaz liste tanımlamaları yapılır
        self.parser.ioc_set = {"198.51.100.25", "198.51.100.99", "8.8.8.8"}
        self.parser.whitelist_set = {"8.8.8.8", "192.168.1.50"}
        # Örnek kural dosyasından imzaları yükler
        rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "threat_intel_and_whitelist_rules.json"))
        if os.path.exists(rules_path):
            self.parser.load_rules_and_ioc(rules_path)

    def test_01_parse_web_log_valid_fields(self) -> None:
        """
        Test 01: Standart web erişim logunun isimlendirilmiş alanlarının doğru ayrıştırıldığını doğrular.
        """
        line = '192.168.1.50 - - [31/Oct/2026:10:00:01 +0300] "GET /index.html HTTP/1.1" 200 1420 "https://kurum.local" "Mozilla/5.0"'
        rec = self.parser.parse_single_line(line)
        self.assertEqual(rec["log_type"], "WEB_ACCESS")
        self.assertEqual(rec["ip"], "192.168.1.50")
        self.assertEqual(rec["method"], "GET")
        self.assertEqual(rec["status"], 200)

    def test_02_parse_sshd_log_valid_failed_auth(self) -> None:
        """
        Test 02: Linux SSHD başarısız parola denemesinin doğru ayrıştırıldığını doğrular.
        """
        line = "Oct 31 10:00:10 srv-auth01 sshd[14201]: Failed password for invalid user admin from 198.51.100.99 port 52341 ssh2"
        rec = self.parser.parse_single_line(line)
        self.assertEqual(rec["log_type"], "SSH_AUTH")
        self.assertEqual(rec["auth_action"], "Failed")
        self.assertEqual(rec["user"], "admin")
        self.assertEqual(rec["ip"], "198.51.100.99")

    def test_03_parse_firewall_log_valid_drop(self) -> None:
        """
        Test 03: Güvenlik duvarı engelleme (DROP) kaydının alanlarının doğru ayrıştırıldığını doğrular.
        """
        line = "OCT 31 10:00:25 fw-edge kernel: [FW_BLOCK] SRC=203.0.113.5 DST=192.168.1.10 PROTO=TCP SPT=49152 DPT=4444 ACTION=DROP"
        rec = self.parser.parse_single_line(line)
        self.assertEqual(rec["log_type"], "FIREWALL_TRAFFIC")
        self.assertEqual(rec["src_ip"], "203.0.113.5")
        self.assertEqual(rec["action"], "DROP")

    def test_04_parse_unrecognized_log_line(self) -> None:
        """
        Test 04: Tanımsız formattaki satırların çökmeksizin UNRECOGNIZED olarak işaretlendiğini doğrular.
        """
        garbage = "GARBAGE DATA WITHOUT REGEX PATTERN MATCH"
        rec = self.parser.parse_single_line(garbage)
        self.assertEqual(rec["log_type"], "UNRECOGNIZED")
        self.assertEqual(rec["status"], "PARSE_SKIPPED")

    def test_05_oversized_line_raises_redos_protection(self) -> None:
        """
        Test 05: ReDoS koruması için 4096 karakter sınırını aşan satırda ValueError üretildiğini test eder.
        """
        huge_line = "A" * (self.parser.MAX_LINE_LENGTH + 1)
        with self.assertRaises(ValueError):
            self.parser.parse_single_line(huge_line)

    def test_06_null_byte_injection_raises(self) -> None:
        """
        Test 06: Log satırında Null-byte (\x00) tespit edildiğinde ValueError ile reddedildiğini doğrular.
        """
        tainted = '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET /test\x00.php HTTP/1.1" 200 100 "-" "curl"'
        with self.assertRaises(ValueError):
            self.parser.parse_single_line(tainted)

    def test_07_bidi_trojan_source_raises(self) -> None:
        """
        Test 07: Trojan Source Bidi yön değiştirme karakteri (\u202E) enjeksiyonunun engellendiğini doğrular.
        """
        bidi_line = "Oct 31 10:00:10 srv sshd[123]: Failed password for invalid user \u202Eroot from 10.0.0.1 port 22 ssh2"
        with self.assertRaises(ValueError):
            self.parser.parse_single_line(bidi_line)

    def test_08_malformed_ip_in_web_log_raises(self) -> None:
        """
        Test 08: Web logundaki geçersiz IP adresinin (999.999.999.999) ValueError ürettiğini doğrular.
        """
        bad_ip_line = '999.999.999.999 - - [31/Oct/2026:10:00:01 +0300] "GET /index.html HTTP/1.1" 200 100 "-" "curl"'
        with self.assertRaises(ValueError):
            self.parser.parse_single_line(bad_ip_line)

    def test_09_web_attack_signature_sqli_detection(self) -> None:
        """
        Test 09: Web isteğinde SQL Injection (UNION SELECT) imzasının yakalanıp alarm üretildiğini doğrular.
        """
        sqli_line = '192.168.1.1 - - [31/Oct/2026:10:00:01 +0300] "GET /item.php?id=1%20UNION%20SELECT%20null HTTP/1.1" 500 100 "-" "sqlmap"'
        self.parser.parse_single_line(sqli_line)
        alarm_types = [a["alert_type"] for a in self.parser.alerts]
        self.assertIn("WEB_ATTACK_SQL_INJECTION", alarm_types)

    def test_10_web_attack_signature_path_traversal(self) -> None:
        """
        Test 10: Web isteğinde Directory Traversal (../../) imzasının yakalanıp alarm üretildiğini doğrular.
        """
        lfi_line = '192.168.1.1 - - [31/Oct/2026:10:00:01 +0300] "GET /../../etc/passwd HTTP/1.1" 403 100 "-" "curl"'
        self.parser.parse_single_line(lfi_line)
        alarm_types = [a["alert_type"] for a in self.parser.alerts]
        self.assertIn("WEB_ATTACK_DIRECTORY_TRAVERSAL", alarm_types)

    def test_11_brute_force_lockout_after_threshold(self) -> None:
        """
        Test 11: Aynı IP'den gelen 5 ardışık başarısız SSH denemesinin BRUTE_FORCE_LOCKOUT ürettiğini doğrular.
        """
        attacker_ip = "198.51.100.99"
        for i in range(5):
            line = f"Oct 31 10:00:1{i} srv-auth01 sshd[1420{i}]: Failed password for invalid user u{i} from {attacker_ip} port 5234{i} ssh2"
            self.parser.parse_single_line(line)

        self.assertIn(attacker_ip, self.parser.locked_out_ips)
        alarm_types = [a["alert_type"] for a in self.parser.alerts]
        self.assertIn("BRUTE_FORCE_LOCKOUT", alarm_types)

    def test_12_whitelist_suppression_prevents_false_positive(self) -> None:
        """
        Test 12: Beyaz listede yer alan IP (8.8.8.8) IoC listesinde olsa dahi alarm üretilmediğini doğrular.
        """
        fw_line = "OCT 31 10:00:30 fw-edge kernel: [FW_ALLOW] SRC=8.8.8.8 DST=192.168.1.100 PROTO=UDP SPT=53 DPT=58912 ACTION=ALLOW"
        self.parser.parse_single_line(fw_line)
        # 8.8.8.8 için hiçbir karaliste alarmı üretilmemiş olmalıdır
        alert_ips = [a["source_ip"] for a in self.parser.alerts]
        self.assertNotIn("8.8.8.8", alert_ips)

    def test_13_non_existent_file_raises_filenotfound(self) -> None:
        """
        Test 13: Var olmayan log dosya yolunda FileNotFoundError fırlatıldığını doğrular.
        """
        with self.assertRaises(FileNotFoundError):
            self.parser.parse_log_file("missing_non_existent_file.log")

    def test_14_ansi_escape_code_stripping(self) -> None:
        """
        Test 14: Log satırındaki ANSI kaçış kodlarının temizlendiğini doğrular.
        """
        tainted_ssh = "Oct 31 10:00:10 srv-auth01 sshd[14201]: \x1b[2J\x1b[H Failed password for invalid user root from 192.168.1.1 port 52341 ssh2"
        rec = self.parser.parse_single_line(tainted_ssh)
        self.assertEqual(rec["log_type"], "SSH_AUTH")
        self.assertEqual(rec["user"], "root")


if __name__ == "__main__":
    unittest.main()
