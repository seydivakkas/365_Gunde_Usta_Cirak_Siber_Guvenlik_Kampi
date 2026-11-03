# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G072: Değişkenler, Veri Tipleri ve Güvenli Giriş Test Paketi.

Bu test modülü, SecureInputAndTypeValidator sınıfının girdi doğrulama,
kanonikleştirme, tip güvenliği ve saldırı engelleme yeteneklerini
14 birim test ve 9 negatif sınır vakası üzerinden sınar.
"""

# Birim test çerçevesi için unittest modülünü dahil ediyoruz.
import unittest
# JSON veri yükleme ve doğrulaması için json kütüphanesini içeri aktarıyoruz.
import json
# Dosya yolları ve işletim sistemi kontrolleri için os modülünü kullanıyoruz.
import os

# Test edilecek doğrulayıcı ve özel istisna sınıfını uygulama paketinden alıyoruz.
from portfolio.hafta_11.gun_072.uygulama.secure_input_and_type_validator import (
    SecureInputAndTypeValidator,
    SecureInputValidationError,
)


class TestSecureInputAndTypeValidator(unittest.TestCase):
    """Güvenli girdi ve tip doğrulayıcısı için 14 senaryolu birim test sınıfı."""

    @classmethod
    def setUpClass(cls) -> None:
        """Tüm testler öncesinde geçerli ve geçersiz girdi veri kümelerini yükler."""
        # Geçerli örnek verilerin dosya yolunu belirliyoruz.
        cls.valid_path = os.path.join(
            "portfolio", "hafta_11", "gun_072", "ornek_veri", "guvenli_girdi_ornekleri.json"
        )
        # Negatif test vakalarının dosya yolunu belirliyoruz.
        cls.invalid_path = os.path.join(
            "portfolio", "hafta_11", "gun_072", "ornek_veri", "invalid_input_test_cases.json"
        )

        # Geçerli veri dosyasını UTF-8 formatında açıyoruz.
        with open(cls.valid_path, "r", encoding="utf-8") as f:
            # Geçerli veriyi sözlük olarak bellğe yüklüyoruz.
            cls.valid_data = json.load(f)

        # Geçersiz veri dosyasını UTF-8 formatında açıyoruz.
        with open(cls.invalid_path, "r", encoding="utf-8") as f:
            # Negatif test vakalarını belleğe yüklüyoruz.
            cls.invalid_data = json.load(f)

    def setUp(self) -> None:
        """Her testten önce taze bir doğrulayıcı nesnesi ilklendirir."""
        # Doğrulayıcı örneğini oluşturuyoruz.
        self.validator = SecureInputAndTypeValidator()

    def test_01_valid_scanner_payload(self) -> None:
        """Geçerli ağ tarayıcı yükünün (scanner_task) tüm alanlarının hatasız doğrulandığını sınar."""
        # Tarayıcı görev verisini alıyoruz.
        task = self.valid_data["scanner_task"]
        # Şema kurallarını tanımlıyoruz.
        schema = {
            "target_ip": "ipv4",
            "target_port": "port",
            "hostname": "hostname",
            "timeout_sec": "integer",
            "verbose": "boolean",
            "packet_count": "integer",
            "log_filename": "safe_path"
        }
        # Yükü doğruluyoruz.
        sanitized = self.validator.validate_payload(task, schema, base_dir="logs")
        # IP adresinin kanonik olduğunu teyit ediyoruz.
        self.assertEqual(sanitized["target_ip"], "192.168.1.100")
        # Port numarasının integer tipinde ve 443 olduğunu sınıyoruz.
        self.assertEqual(sanitized["target_port"], 443)
        # Verbose alanının boolean True olduğunu kontrol ediyoruz.
        self.assertIs(sanitized["verbose"], True)
        # Timeout alanının tamsayı olduğunu sınıyoruz.
        self.assertEqual(sanitized["timeout_sec"], 5)

    def test_02_valid_firewall_rule_payload(self) -> None:
        """Güvenlik duvarı kural yükünün katı tiplerle başarıyla doğrulandığını test eder."""
        # Güvenlik duvarı kuralını alıyoruz.
        rule = self.valid_data["firewall_rule"]
        # Şema kurallarını belirliyoruz.
        schema = {
            "source_ip": "ipv4",
            "destination_ip": "ipv4",
            "destination_port": "port",
            "protocol": "string",
            "is_active": "boolean",
            "priority": "integer"
        }
        # Doğrulamayı çalıştırıyoruz.
        sanitized = self.validator.validate_payload(rule, schema)
        # Kaynak IP kontrolü.
        self.assertEqual(sanitized["source_ip"], "10.0.0.15")
        # Hedef port kontrolü.
        self.assertEqual(sanitized["destination_port"], 22)
        # 'true' string değerinin True boolean'a dönüştüğünü teyit ediyoruz.
        self.assertIs(sanitized["is_active"], True)

    def test_03_canonicalization_and_nfkc(self) -> None:
        """Unicode NFKC normalizasyonu ve boşluk temizleme yeteneğini sınar."""
        # Tam genişlikte (fullwidth) Unicode karakterler içeren ham dize
        raw = "  \uFF27\uFF41\uFF54\uFF45\uFF57\uFF41\uFF59  " # Gateway
        # Kanonikleştirme fonksiyonunu çağırıyoruz.
        clean = self.validator.canonicalize_string(raw)
        # Normal ASCII 'Gateway' haline geldiğini teyit ediyoruz.
        self.assertEqual(clean, "Gateway")

    def test_04_text_and_json_report_generation(self) -> None:
        """Metin ve JSON raporlama çıktılarının hatasız üretildiğini test eder."""
        # Basit doğrulanmış veri sözlüğü oluşturuyoruz.
        sample = {"ip": "127.0.0.1", "port": 80, "active": True}
        # Metin raporunu üretiyoruz.
        txt_rep = self.validator.generate_text_report(sample)
        # Raporda başlığın bulunduğunu sınıyoruz.
        self.assertIn("G072: DEĞİŞKENLER, VERİ TİPLERİ VE GÜVENLİ GİRİŞ", txt_rep)
        # JSON raporunu üretiyoruz.
        json_rep = self.validator.generate_json_report(sample)
        # JSON dizgisini ayrıştırıyoruz.
        parsed = json.loads(json_rep)
        # Puanın 100 olduğunu teyit ediyoruz.
        self.assertEqual(parsed["security_score"], 100.0)

    def test_05_safe_path_resolution(self) -> None:
        """Güvenli kök dizin altındaki geçerli alt dosya yollarının kabul edildiğini test eder."""
        # Güvenli temel dizin ve geçerli dosya adı
        base = "logs"
        filename = "analiz_2026.log"
        # Yolu doğruluyoruz.
        safe_path = self.validator.validate_safe_path(base, filename)
        # Mutlak yolun 'logs' içerdiğini sınıyoruz.
        self.assertTrue(safe_path.endswith(os.path.join(base, filename)))

    def test_06_neg_01_type_confusion_boolean_as_int(self) -> None:
        """NEG_01: Boolean tipi int/port olarak verildiğinde tip karmaşası hatası fırlatıldığını sınar."""
        # Negatif veri örneğini çekiyoruz.
        case = self.invalid_data["NEG_01_TYPE_CONFUSION_BOOLEAN_AS_INT"]
        # SecureInputValidationError istisnasını sınıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # True değerini port olarak doğrulatıyoruz.
            self.validator.validate_port(case["val"])
        # Tip karmaşası uyarısını teyit ediyoruz.
        self.assertIn("Tip karmaşası", str(ctx.exception))

    def test_07_neg_02_port_out_of_bounds(self) -> None:
        """NEG_02: 1-65535 dışındaki port numaralarında sınır aşımı hatası verildiğini sınar."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_02_PORT_OUT_OF_BOUNDS"]
        # İstisnanın oluştuğunu teyit ediyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # 70000 portunu sınıyoruz.
            self.validator.validate_port(case["val"])
        # Port sınır aşımı uyarısını doğruluyoruz.
        self.assertIn("Port sınır aşımı", str(ctx.exception))

    def test_08_neg_03_command_injection_in_hostname(self) -> None:
        """NEG_03: Hostname içinde kabuk metakarakteri tespitinde enjeksiyon hatası fırlatıldığını sınar."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_03_COMMAND_INJECTION_IN_HOSTNAME"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # ';' içeren ana makine adını denetliyoruz.
            self.validator.validate_hostname(case["val"])
        # Komut enjeksiyonu uyarısını sınıyoruz.
        self.assertIn("Komut enjeksiyonu riski", str(ctx.exception))

    def test_09_neg_04_path_traversal_attack(self) -> None:
        """NEG_04: ../ içeren dizin atlatma saldırılarının engellendiğini sınar."""
        # Negatif veriyi yüklüyoruz.
        case = self.invalid_data["NEG_04_PATH_TRAVERSAL_ATTACK"]
        # İstisnanın tetiklendiğini sınıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # ../../../../etc/shadow yolunu denetliyoruz.
            self.validator.validate_safe_path("logs", case["val"])
        # Dizin atlatma uyarısını teyit ediyoruz.
        self.assertIn("Dizin atlatma", str(ctx.exception))

    def test_10_neg_05_invalid_ipv4_octet(self) -> None:
        """NEG_05: 255'ten büyük oktet içeren geçersiz IPv4 adresinin reddedildiğini test eder."""
        # Negatif veri örneğini alıyoruz.
        case = self.invalid_data["NEG_05_INVALID_IPV4_OCTET"]
        # İstisna oluşumunu kontrol ediyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # 192.168.1.300 adresini sınıyoruz.
            self.validator.validate_ipv4(case["val"])
        # Geçersiz IPv4 uyarısını doğruluyoruz.
        self.assertIn("Geçersiz IPv4 adresi", str(ctx.exception))

    def test_11_neg_06_ambiguous_boolean_value(self) -> None:
        """NEG_06: 'maybe' gibi belirsiz değerlerin mantıksal tipe çevrilemeyip reddedildiğini sınar."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_06_AMBIGUOUS_BOOLEAN_VALUE"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # 'maybe' değerini boolean olarak denetliyoruz.
            self.validator.validate_boolean(case["val"])
        # Belirsiz boolean uyarısını sınıyoruz.
        self.assertIn("Belirsiz mantıksal değer", str(ctx.exception))

    def test_12_neg_07_null_byte_injection(self) -> None:
        """NEG_07: Null byte (\\x00) içeren girdilerin derhal reddedildiğini test eder."""
        # Negatif veriyi alıyoruz.
        case = self.invalid_data["NEG_07_NULL_BYTE_INJECTION"]
        # İstisnanın tetiklendiğini teyit ediyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # Null byte içeren dosya adını kanonikleştiriyoruz.
            self.validator.canonicalize_string(case["val"])
        # Null byte uyarısını sınıyoruz.
        self.assertIn("Null byte enjeksiyonu", str(ctx.exception))

    def test_13_neg_08_string_oversized_dos(self) -> None:
        """NEG_08: RFC sınırını aşan devasa uzunluktaki dizelerin engellendiğini test eder."""
        # Negatif veriyi çekiyoruz.
        case = self.invalid_data["NEG_08_STRING_OVERSIZED_DOS"]
        # İstisna kontrolü yapıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # 290 karakterlik ana makine adını denetliyoruz.
            self.validator.validate_hostname(case["val"])
        # Dize uzunluk sınırı uyarısını sınıyoruz.
        self.assertIn("Dize uzunluk sınırı aşıldı", str(ctx.exception))

    def test_14_neg_09_malformed_payload_schema(self) -> None:
        """NEG_09: Yükün sözlük yerine dizi formatında gelmesi durumunda hata fırlatıldığını sınar."""
        # Negatif veri senaryosunu yüklüyoruz.
        case = self.invalid_data["NEG_09_MALFORMED_PAYLOAD_SCHEMA"]
        # İstisnanın oluştuğunu sınıyoruz.
        with self.assertRaises(SecureInputValidationError) as ctx:
            # Liste tipindeki yükü sözlük şeması ile sınıyoruz.
            self.validator.validate_payload(case["payload"], {})
        # Sözlük gereksinimi uyarısını teyit ediyoruz.
        self.assertIn("JSON sözlüğü", str(ctx.exception))


# Test betiğinin doğrudan çalıştırılmasını yönetiyoruz.
if __name__ == "__main__":
    # Testleri detaylı modda tetikliyoruz.
    unittest.main()
