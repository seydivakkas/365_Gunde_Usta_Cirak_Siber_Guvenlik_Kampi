# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G073: Koşullar, Kontrol Akışı ve Savunmacı Döngüler Test Paketi.

Bu modül, SecurityControlFlowEngine sınıfının politika değerlendirme,
fail-closed varsayılanları, sonsuz döngü koruması ve hız sınırlama yeteneklerini
14 birim test ve 9 negatif sınır kontrolü üzerinden sınar.
"""

# Birim test çerçevesi için unittest modülünü dahil ediyoruz.
import unittest
# JSON verilerini okumak için json kütüphanesini içeri aktarıyoruz.
import json
# Dosya yolları ve işletim sistemi kontrolleri için os modülünü kullanıyoruz.
import os

# Test edilecek kontrol akışı motoru ve istisna sınıfını uygulama modülünden alıyoruz.
from portfolio.hafta_11.gun_073.uygulama.security_control_flow_engine import (
    SecurityControlFlowEngine,
    ControlFlowSecurityError,
)


class TestSecurityControlFlowEngine(unittest.TestCase):
    """Kontrol akışı ve savunmacı döngüler motoru birim test sınıfı."""

    @classmethod
    def setUpClass(cls) -> None:
        """Tüm testler öncesinde geçerli ve geçersiz veri kümelerini yükler."""
        # Geçerli veri dosya yolunu belirliyoruz.
        cls.valid_path = os.path.join(
            "portfolio", "hafta_11", "gun_073", "ornek_veri", "guvenlik_kurallari_ve_donguler.json"
        )
        # Negatif sınır testleri dosya yolunu belirliyoruz.
        cls.invalid_path = os.path.join(
            "portfolio", "hafta_11", "gun_073", "ornek_veri", "invalid_control_flow_inputs.json"
        )

        # Geçerli veriyi UTF-8 formatında açıyoruz.
        with open(cls.valid_path, "r", encoding="utf-8") as f:
            # Belleğe sözlük olarak yüklüyoruz.
            cls.valid_data = json.load(f)

        # Negatif test verisini UTF-8 ile açıyoruz.
        with open(cls.invalid_path, "r", encoding="utf-8") as f:
            # Negatif vakaları yüklüyoruz.
            cls.invalid_data = json.load(f)

    def setUp(self) -> None:
        """Her testten önce taze bir kontrol akışı motoru ilklendirir."""
        # Motor nesnesini oluşturuyoruz.
        self.engine = SecurityControlFlowEngine()

    def test_01_firewall_rule_matching_priority(self) -> None:
        """Öncelikli kuralın (Rule 1, SSH 22, 10.100.0.0/24) ALLOW kararı verdiğini sınar."""
        # Yönetim ağı SSH paketini oluşturuyoruz.
        packet = {"source_ip": "10.100.0.15", "dest_port": 22, "protocol": "TCP"}
        # Güvenlik duvarı politikasını değerlendiriyoruz.
        res = self.engine.evaluate_firewall_policy(self.valid_data["firewall_policy"], packet)
        # Kararın ALLOW olduğunu teyit ediyoruz.
        self.assertEqual(res["decision"], "ALLOW")
        # Eşleşen kural ID'sinin 1 olduğunu sınıyoruz.
        self.assertEqual(res["matched_rule_id"], 1)

    def test_02_firewall_rule_default_deny(self) -> None:
        """Hiçbir kurala uymayan paketin 'for ... else' ile varsayılan DENY aldığını test eder."""
        # Tanımsız bir dış ağ paketi oluşturuyoruz.
        packet = {"source_ip": "192.168.1.99", "dest_port": 8080, "protocol": "UDP"}
        # Politikayı değerlendiriyoruz.
        res = self.engine.evaluate_firewall_policy(self.valid_data["firewall_policy"], packet)
        # Kararın varsayılan DENY olduğunu teyit ediyoruz (Fail-closed).
        self.assertEqual(res["decision"], "DENY")
        # Eşleşen kural ID'sinin 0 olduğunu sınıyoruz.
        self.assertEqual(res["matched_rule_id"], 0)

    def test_03_firewall_rule_exact_ip_deny(self) -> None:
        """Yüksek öncelikli (priority 5) zararlı IP engelleme kuralının çalıştığını test eder."""
        # Yasaklı IP paketi tanımlıyoruz.
        packet = {"source_ip": "198.51.100.44", "dest_port": 443, "protocol": "TCP"}
        # Politikayı değerlendiriyoruz.
        res = self.engine.evaluate_firewall_policy(self.valid_data["firewall_policy"], packet)
        # Kararın DENY olduğunu kontrol ediyoruz.
        self.assertEqual(res["decision"], "DENY")
        # Eşleşen kural ID'sinin 3 olduğunu teyit ediyoruz.
        self.assertEqual(res["matched_rule_id"], 3)

    def test_04_safe_pointer_traversal_success(self) -> None:
        """Döngüsel olmayan meşru gösterici zincirinin hatasız sonlandığını sınar."""
        # Geçerli gösterici yükünü alıyoruz.
        payload = self.valid_data["pointer_traversal_payload"]
        # Güvenli gezintiyi icra ediyoruz.
        path = self.engine.safe_pointer_traversal(payload)
        # Beklenen gezinti zincirini teyit ediyoruz: 0 -> 16 -> 48 -> 80
        self.assertEqual(path, [0, 16, 48, 80])

    def test_05_rate_limiter_brute_force_detection(self) -> None:
        """60 saniyede 5'ten fazla başarısız denemenin kilitlenme tetiklediğini test eder."""
        # Kimlik doğrulama olaylarını alıyoruz.
        events = self.valid_data["authentication_events"]
        # Hız sınırlayıcıyı çalıştırıyoruz.
        res = self.engine.detect_brute_force_rate_limit(events, window_seconds=60, threshold=5)
        # Kilitlenen IP sayısının 1 olduğunu teyit ediyoruz.
        self.assertEqual(res["locked_out_ips_count"], 1)
        # 203.0.113.5 adresinin kilitlendiğini sınıyoruz.
        self.assertIn("203.0.113.5", res["lockout_details"])
        # Başarısız deneme sayısının 6 olduğunu kontrol ediyoruz.
        self.assertEqual(res["lockout_details"]["203.0.113.5"]["failure_count"], 6)

    def test_06_threat_ioc_stream_for_else_malware_detected(self) -> None:
        """Threat IoC akışında zararlı etiket bulunduğunda döngünün break ile kırıldığını test eder."""
        # IoC akışını alıyoruz.
        stream = self.valid_data["threat_ioc_stream"]
        # Tarayıcıyı çalıştırıyoruz.
        res = self.engine.scan_threat_ioc_stream(stream)
        # Durumun ALERT olduğunu sınıyoruz.
        self.assertEqual(res["status"], "ALERT")
        # Tehdit bulunduğunu teyit ediyoruz.
        self.assertTrue(res["threat_found"])
        # Zararlı etiketini kontrol ediyoruz.
        self.assertEqual(res["threat_detail"]["label"], "MALWARE_KNOWN_EMOTET")

    def test_07_threat_ioc_stream_clean_stream(self) -> None:
        """Yalnızca temiz eserler içeren akışta 'for ... else' bloğunun PASS verdiğini test eder."""
        # Temiz liste oluşturuyoruz.
        clean_stream = [
            {"artifact_id": "C1", "label": "clean"},
            {"artifact_id": "C2", "label": "benign"}
        ]
        # Tarayıcıyı çağırıyoruz.
        res = self.engine.scan_threat_ioc_stream(clean_stream)
        # Durumun PASS olduğunu teyit ediyoruz.
        self.assertEqual(res["status"], "PASS")
        # Tehdit bulunmadığını sınıyoruz.
        self.assertFalse(res["threat_found"])

    def test_08_neg_01_pointer_cycle_detected(self) -> None:
        """NEG_01: 10 -> 20 -> 10 döngüsel atıfında Pointer Cycle istisnası verildiğini sınar."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_01_POINTER_CYCLE_DETECTED"]
        # ControlFlowSecurityError istisnasını bekliyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # Döngüsel yük ile gezintiyi tetikliyoruz.
            self.engine.safe_pointer_traversal(case["payload"])
        # Hata mesajında döngü uyarısını sınıyoruz.
        self.assertIn("Döngüsel gösterici (Pointer Cycle) tespit edildi", str(ctx.exception))

    def test_09_neg_02_max_iterations_exceeded(self) -> None:
        """NEG_02: Yineleme tavanı aşıldığında Anti-DoS istisnası fırlatıldığını sınar."""
        # Negatif senaryoyu yüklüyoruz.
        case = self.invalid_data["NEG_02_MAX_ITERATIONS_EXCEEDED"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # 3 adımlık sınır ile 4 adımlı zinciri gezdiriyoruz.
            self.engine.safe_pointer_traversal(case["payload"], max_iterations=case["max_iterations"])
        # Tavan aşımı uyarısını teyit ediyoruz.
        self.assertIn("Azami döngü yineleme tavanı aşıldı", str(ctx.exception))

    def test_10_neg_03_invalid_policy_rule_schema(self) -> None:
        """NEG_03: Kuralda 'action' alanı eksik olduğunda şema hatası verildiğini sınar."""
        # Negatif kuralı alıyoruz.
        case = self.invalid_data["NEG_03_INVALID_POLICY_RULE_SCHEMA"]
        # Bozuk kurallı politika oluşturuyoruz.
        bad_policy = {"default_action": "DENY", "rules": [case["rule"]]}
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # Değerlendirmeyi tetikliyoruz.
            self.engine.evaluate_firewall_policy(bad_policy, {})
        # Kural şema uyarısını doğruluyoruz.
        self.assertIn("Kural şema ihlali", str(ctx.exception))

    def test_11_neg_04_undefined_default_action(self) -> None:
        """NEG_04: Varsayılan eylem ALLOW veya DENY olmadığında hata fırlatıldığını sınar."""
        # Negatif politika verisini çekiyoruz.
        case = self.invalid_data["NEG_04_UNDEFINED_DEFAULT_ACTION"]
        # İstisnanın oluştuğunu teyit ediyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # Hatalı politika ile değerlendirme başlatıyoruz.
            self.engine.evaluate_firewall_policy(case["policy"], {})
        # Geçersiz varsayılan eylem mesajını sınıyoruz.
        self.assertIn("Geçersiz varsayılan politika eylemi", str(ctx.exception))

    def test_12_neg_05_ambiguous_evaluation_none_vs_false(self) -> None:
        """NEG_05: 'None' değeri kesin boolean değerlendirmesine sokulduğunda hata verildiğini test eder."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_05_AMBIGUOUS_EVALUATION_NONE_VS_FALSE"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # None değerini sınıyoruz.
            self.engine.evaluate_strict_condition(case["condition_value"])
        # Belirsizlik uyarısını teyit ediyoruz.
        self.assertIn("Belirsiz mantıksal değerlendirme", str(ctx.exception))

    def test_13_neg_06_rate_limiter_window_negative(self) -> None:
        """NEG_06: Hız sınırlayıcı kayan pencere süresi negatif olduğunda hata verildiğini sınar."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_06_RATE_LIMITER_WINDOW_NEGATIVE"]
        # İstisna oluşumunu kontrol ediyoruz.
        with self.assertRaises(ControlFlowSecurityError) as ctx:
            # -60 saniyelik pencere ile çalıştırıyoruz.
            self.engine.detect_brute_force_rate_limit([], window_seconds=case["window_seconds"], threshold=case["threshold"])
        # Kayan pencere uyarısını sınıyoruz.
        self.assertIn("Geçersiz kayan pencere süresi", str(ctx.exception))

    def test_14_neg_07_to_09_boundary_errors(self) -> None:
        """NEG_07, NEG_08 ve NEG_09 sınır aşımı ve biçim bozulması hatalarını sınar."""
        # 1. Eşik 0 hatası (NEG_07)
        c7 = self.invalid_data["NEG_07_RATE_LIMITER_THRESHOLD_ZERO"]
        with self.assertRaises(ControlFlowSecurityError) as ctx7:
            self.engine.detect_brute_force_rate_limit([], window_seconds=c7["window_seconds"], threshold=c7["threshold"])
        self.assertIn("Geçersiz hız sınırı eşiği", str(ctx7.exception))

        # 2. Tampon sınır aşımı (NEG_08)
        c8 = self.invalid_data["NEG_08_CORRUPT_POINTER_OFFSET"]
        with self.assertRaises(ControlFlowSecurityError) as ctx8:
            self.engine.safe_pointer_traversal(c8["payload"])
        self.assertIn("Arabellek sınır aşımı", str(ctx8.exception))

        # 3. Liste olmayan olay akışı (NEG_09)
        c9 = self.invalid_data["NEG_09_MALFORMED_EVENT_STREAM"]
        with self.assertRaises(ControlFlowSecurityError) as ctx9:
            self.engine.detect_brute_force_rate_limit(c9["events"])
        self.assertIn("Olay akışı bir liste (list) olmalıdır", str(ctx9.exception))


# Test modülünün doğrudan çalıştırılmasını yönetiyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda icra ediyoruz.
    unittest.main()
