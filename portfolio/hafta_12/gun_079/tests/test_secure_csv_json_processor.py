# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G079: CSV ve JSON Veri İşleme Test Paketi (14 Birim Test)
"""

# Dosya yolları ve geçici dizin işlemleri için Path nesnesini içeri aktarıyoruz.
from pathlib import Path
# Geçici dosya ve dizin üretimi için tempfile modülünü içeri aktarıyoruz.
import tempfile
# Birim test çerçevesi için Python standart unittest modülünü içeri aktarıyoruz.
import unittest

# Test edilecek CSV, JSON ve Ingestion motorlarını içeri aktarıyoruz.
from portfolio.hafta_12.gun_079.uygulama.secure_csv_json_processor import (
    FormulaInjectionWarning,
    SecureCsvProcessor,
    SecureJsonProcessor,
    SecurityDataIngestionEngine,
)


class TestSecureCsvJsonProcessor(unittest.TestCase):
    """
    CSV ve JSON güvenli veri işleme motorunun savunmacı kabiliyetlerini doğrulayan test sınıfı.
    """

    def setUp(self) -> None:
        """
        Her test öncesi bağımsız işlemci nesnelerini ve geçici çalışma dizinini hazırlar.
        """
        # CSV işlemcisini 1024 baytlık küçük alan limitiyle başlatıyoruz.
        self.csv_proc = SecureCsvProcessor(max_field_size_bytes=1024, max_rows=100)
        # JSON işlemcisini 5 derinlik limitiyle başlatıyoruz.
        self.json_proc = SecureJsonProcessor(max_payload_bytes=1024 * 1024, max_depth=5)
        # Test izolasyonu için geçici bir dizin açıyoruz.
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        # Geçici dizinin Path nesnesini alıyoruz.
        self.temp_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        """
        Her test sonrasında geçici dizin ve artık dosyaları temizler.
        """
        # Geçici dizini ve içindeki dosyaları temizliyoruz.
        self.temp_dir_obj.cleanup()

    def test_01_csv_has_formula_injection_risk_detection(self) -> None:
        """
        Excel formül enjeksiyonu riski taşıyan karakterlerin doğru tespit edildiğini sınar.
        """
        # Eşittir ile başlayan DDE komutunun riskli olarak tespit edildiğini doğruluyoruz.
        self.assertTrue(self.csv_proc.has_formula_injection_risk("=cmd|'/C calc'!A0"))
        # Artı ile başlayan formülün riskli bulunduğunu test ediyoruz.
        self.assertTrue(self.csv_proc.has_formula_injection_risk("+1+2"))
        # Eksi ile başlayan formülün tespit edildiğini doğruluyoruz.
        self.assertTrue(self.csv_proc.has_formula_injection_risk("-SUM(A1:A10)"))
        # Et (@) işareti ile başlayan formülün yakalandığını doğruluyoruz.
        self.assertTrue(self.csv_proc.has_formula_injection_risk("@SUM(A1)"))
        # Boşluktan sonra gelen formülün de kırpılarak yakalandığını test ediyoruz.
        self.assertTrue(self.csv_proc.has_formula_injection_risk("   =1+1"))
        # Normal bir metnin risk taşımadığını doğruluyoruz.
        self.assertFalse(self.csv_proc.has_formula_injection_risk("normal_metin"))
        # Normal bir IP adresinin risk taşımadığını teyit ediyoruz.
        self.assertFalse(self.csv_proc.has_formula_injection_risk("192.168.1.1"))

    def test_02_csv_sanitize_cell_neutralization(self) -> None:
        """
        Riskli hücrelerin başına tek tırnak eklenerek formülün metne dönüştürüldüğünü sınar.
        """
        # Riskli hücreyi nötralize ediyoruz.
        sanitized = self.csv_proc.sanitize_csv_cell("=1+1")
        # Başına tek tırnak eklendiğini doğruluyoruz.
        self.assertEqual(sanitized, "'=1+1")
        # Meşru bir metnin değiştirilmediğini sınıyoruz.
        clean_text = self.csv_proc.sanitize_csv_cell("guvenli_veri")
        # Değerin orijinal kaldığını teyit ediyoruz.
        self.assertEqual(clean_text, "guvenli_veri")

    def test_03_csv_read_valid_records(self) -> None:
        """
        Geçerli bir CSV dosyasının başarıyla ayrıştırıldığını ve kayıtların alındığını doğrular.
        """
        # Test CSV dosyasının yolunu oluşturuyoruz.
        csv_path = self.temp_dir / "valid.csv"
        # CSV içeriğini dosyaya yazıyoruz.
        csv_path.write_text("id,name,role\n1,Alice,Analyst\n2,Bob,Engineer\n", encoding="utf-8")
        # CSV dosyasını okuyoruz.
        records = self.csv_proc.read_csv_safely(csv_path, expected_headers=["id", "name", "role"])
        # Toplam 2 kayıt döndüğünü teyit ediyoruz.
        self.assertEqual(len(records), 2)
        # İlk kaydın ad alanını sınıyoruz.
        self.assertEqual(records[0]["name"], "Alice")
        # İkinci kaydın rolünü sınıyoruz.
        self.assertEqual(records[1]["role"], "Engineer")

    def test_04_csv_read_nonexistent_file_raises(self) -> None:
        """
        Var olmayan bir CSV dosyası istendiğinde FileNotFoundError fırlatıldığını doğrular.
        """
        # Olmayan dosya yolunu tanımlıyoruz.
        fake_path = self.temp_dir / "nonexistent.csv"
        # FileNotFoundError fırlatılmasını bekliyoruz.
        with self.assertRaises(FileNotFoundError):
            # Olmayan dosyayı okumaya çalışıyoruz.
            self.csv_proc.read_csv_safely(fake_path)

    def test_05_csv_read_column_count_mismatch_raises(self) -> None:
        """
        Satırdaki sütun sayısı başlık sayısıyla uyuşmadığında ValueError fırlatıldığını test eder.
        """
        # Tutarsız CSV dosyasını hazırlıyoruz.
        broken_csv = self.temp_dir / "mismatch.csv"
        # Başlıkta 3 sütun varken ikinci satırda 2 sütun veriyoruz.
        broken_csv.write_text("c1,c2,c3\nv1,v2\n", encoding="utf-8")
        # ValueError fırlatıldığını sınıyoruz.
        with self.assertRaises(ValueError):
            # Dosyayı okumaya çalışıyoruz.
            self.csv_proc.read_csv_safely(broken_csv)

    def test_06_csv_read_oversized_field_raises(self) -> None:
        """
        Hücre boyutu tanımlanan tavanı aştığında ValueError fırlatıldığını test eder.
        """
        # Aşırı büyük alan içeren CSV dosyasını hazırlıyoruz.
        oversized_csv = self.temp_dir / "oversized.csv"
        # 1024 bayt sınırını aşan 2000 baytlık veri üretiyoruz.
        big_val = "A" * 2000
        # Dosyayı kaydediyoruz.
        oversized_csv.write_text(f"col1,col2\n1,{big_val}\n", encoding="utf-8")
        # ValueError fırlatıldığını doğruluyoruz.
        with self.assertRaises(ValueError):
            # Dosyayı okumayı deniyoruz.
            self.csv_proc.read_csv_safely(oversized_csv)

    def test_07_csv_read_null_byte_raises(self) -> None:
        """
        CSV hücresinde null-byte enjeksiyonu tespit edildiğinde ValueError fırlatıldığını doğrular.
        """
        # Null-byte içeren dosyayı hazırlıyoruz.
        null_csv = self.temp_dir / "null_byte.csv"
        # Hücreye null byte yerleştiriyoruz.
        null_csv.write_text("id,val\n1,evil\x00data\n", encoding="utf-8")
        # ValueError fırlatılmasını sınıyoruz.
        with self.assertRaises(ValueError):
            # Dosyayı okuyoruz.
            self.csv_proc.read_csv_safely(null_csv)

    def test_08_csv_write_safely_with_neutralization(self) -> None:
        """
        CSV yazılırken tehlikeli formül karakterlerinin tek tırnakla nötralize edildiğini doğrular.
        """
        # Hedef dosya yolunu belirliyoruz.
        out_csv = self.temp_dir / "sanitized_out.csv"
        # Başlıkları tanımlıyoruz.
        headers = ["id", "action"]
        # Zararlı formül içeren satırlar hazırlıyoruz.
        rows = [{"id": "1", "action": "=cmd|'calc'!A0"}, {"id": "2", "action": "normal_login"}]
        # Dosyayı güvenli yazma fonksiyonu ile kaydediyoruz.
        written = self.csv_proc.write_csv_safely(out_csv, headers, rows, neutralize_formulas=True)
        # 2 satır yazıldığını teyit ediyoruz.
        self.assertEqual(written, 2)
        # Yazılan dosyanın ham içeriğini okuyoruz.
        content = out_csv.read_text(encoding="utf-8")
        # Formülün başına tek tırnak geldiğini doğruluyoruz.
        self.assertIn("'=cmd|'calc'!A0", content)

    def test_09_json_parse_valid_object(self) -> None:
        """
        Geçerli bir JSON nesnesinin doğru biçimde sözlüğe dönüştürüldüğünü sınar.
        """
        # Meşru JSON dizesi hazırlıyoruz.
        raw_json = '{"user": "seydi", "admin": true, "score": 100}'
        # Dizeyi güvenli ayrıştırıcı ile yüklüyoruz.
        parsed = self.json_proc.parse_json_safely(raw_json)
        # Kullanıcı alanını kontrol ediyoruz.
        self.assertEqual(parsed["user"], "seydi")
        # Puan alanını kontrol ediyoruz.
        self.assertEqual(parsed["score"], 100)

    def test_10_json_duplicate_key_collision_raises(self) -> None:
        """
        Aynı JSON nesnesinde mükerrer anahtar geçtiğinde ValueError fırlatıldığını doğrular.
        """
        # Aynı nesnede çift 'role' anahtarı içeren saldırı yükü hazırlıyoruz.
        raw_attack_json = '{"role": "guest", "role": "admin"}'
        # ValueError fırlatıldığını sınıyoruz.
        with self.assertRaises(ValueError):
            # Ayrıştırmayı deniyoruz.
            self.json_proc.parse_json_safely(raw_attack_json)

    def test_11_json_deep_recursion_bomb_raises(self) -> None:
        """
        Azami derinliği aşan JSON Bomb DoS girişimlerinin ValueError ile durdurulduğunu test eder.
        """
        # 5 derinlik sınırını aşacak 8 seviyeli iç içe geçmiş JSON oluşturuyoruz.
        deep_json = '{"a": {"b": {"c": {"d": {"e": {"f": {"g": "boom"}}}}}}}'
        # Derinlik aşımı hatası fırlatıldığını sınıyoruz.
        with self.assertRaises(ValueError):
            # Ayrıştırmayı deniyoruz.
            self.json_proc.parse_json_safely(deep_json)

    def test_12_json_null_byte_in_string_raises(self) -> None:
        """
        JSON dize değerinde null-byte tespit edildiğinde ValueError fırlatıldığını test eder.
        """
        # Dize içinde null byte barındıran JSON hazırlıyoruz.
        null_json = '{"filename": "report.pdf\\u0000.exe"}'
        # ValueError fırlatıldığını sınıyoruz.
        with self.assertRaises(ValueError):
            # Ayrıştırmayı deniyoruz.
            self.json_proc.parse_json_safely(null_json)

    def test_13_json_schema_validation_success_and_failures(self) -> None:
        """
        JSON şema doğrulamasında tip uyumunu ve zorunlu alan eksikliğini test eder.
        """
        # Şema kuralı belirliyoruz.
        schema = {"ip": str, "port": int, "active": bool}
        # Geçerli veriyi sınıyoruz.
        valid_data = {"ip": "10.0.0.1", "port": 80, "active": True}
        # Geçerli verinin True döndüğünü teyit ediyoruz.
        self.assertTrue(self.json_proc.validate_schema(valid_data, schema))

        # Tip uyumsuzluğu olan veriyi hazırlıyoruz (port yerine dize verilmiş).
        invalid_type_data = {"ip": "10.0.0.1", "port": "SEKSEN", "active": True}
        # TypeError fırlatıldığını sınıyoruz.
        with self.assertRaises(TypeError):
            # Doğrulamayı deniyoruz.
            self.json_proc.validate_schema(invalid_type_data, schema)

        # Zorunlu alanı eksik veriyi hazırlıyoruz ('active' alanı yok).
        missing_key_data = {"ip": "10.0.0.1", "port": 80}
        # ValueError fırlatıldığını sınıyoruz.
        with self.assertRaises(ValueError):
            # Doğrulamayı deniyoruz.
            self.json_proc.validate_schema(missing_key_data, schema)

    def test_14_engine_threat_feed_and_events_ingestion(self) -> None:
        """
        SecurityDataIngestionEngine sınıfının uçtan uca besleme analizini doğruladığını test eder.
        """
        # Üst motoru başlatıyoruz.
        engine = SecurityDataIngestionEngine()
        # Örnek CSV dosyasını hazırlıyoruz.
        csv_file = self.temp_dir / "feed.csv"
        # Tehdit kayıtlarını yazıyoruz.
        csv_file.write_text(
            "timestamp,indicator_ip,threat_score,malware_family,action_taken\n"
            "2026-11-01T00:00:00Z,10.0.0.1,=cmd|'calc'!A0,Spyware,BLOCK\n"
            "2026-11-01T00:01:00Z,10.0.0.2,50,Adware,ALERT\n",
            encoding="utf-8"
        )
        # CSV beslemesini işliyoruz.
        csv_res = engine.process_threat_feed_csv(csv_file)
        # Toplam 2 kayıt işlendiğini sınıyoruz.
        self.assertEqual(csv_res["toplam_kayit"], 2)
        # 1 adet formül riski nötralize edildiğini sınıyoruz.
        self.assertEqual(csv_res["tespit_edilen_formula_riski"], 1)

        # Örnek JSON olaylarını hazırlıyoruz.
        json_payload = (
            '{"security_events": ['
            '{"event_id": "EVT-1", "source_ip": "1.1.1.1", "threat_score": 90, "severity": "CRITICAL", "is_blocked": true},'
            '{"event_id": "EVT-2", "source_ip": "2.2.2.2", "threat_score": 30, "severity": "LOW", "is_blocked": false}'
            ']}'
        )
        # JSON olaylarını işliyoruz.
        json_res = engine.process_security_events_json(json_payload)
        # Toplam 2 olay olduğunu teyit ediyoruz.
        self.assertEqual(json_res["toplam_olay"], 2)
        # 70 puan üstü 1 kritik olay filtrelendiğini sınıyoruz.
        self.assertEqual(json_res["kritik_ve_yuksek_olay_sayisi"], 1)


# Testler doğrudan çağrıldığında çalıştırılmasını sağlıyoruz.
if __name__ == "__main__":
    # Test yürütücüyü ayrıntılı çıktı modunda başlatıyoruz.
    unittest.main()
