# -*- coding: utf-8 -*-
"""
Gün 162: SQL Injection Neden Oluşur Birim Testleri (test_sql_injection.py)

Bu test paketi; SQLi tehdit sensörünü, zafiyetli dize birleştirme mekanizmasını,
güvenli parametrik sorgu (Prepared Statement) korumasını ve dinamik belirteç
güvenlik denetimlerini 15 kapsamlı birim test senaryosu ile doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yolu işlemleri için os modülü dahil edilir
import sys  # Sistem yolu ve import yönetimi için sys modülü dahil edilir
import unittest  # Birim test çerçevesi için unittest modülü dahil edilir

# Test edilecek modül dizininin sys.path içerisine eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut test dosyasının bulunduğu dizin alınır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizininin mutlak yolu oluşturulur
if app_dir not in sys.path:  # Uygulama dizini sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa eklenerek içe aktarma önceliği sağlanır

# Test edilecek sınıfların içe aktarılması
from sql_injection_engine import (  # sql_injection_engine modülünden gerekli sınıflar çağrılır
    SQLInjectionDefenseEngine,  # Savunma ve karşılaştırma motoru
    SQLiThreatSensor,  # Tehdit tarayıcısı
    SQLiType,  # SQLi türleri enum sınıfı
    SQLiSeverity,  # Ciddiyet dereceleri enum sınıfı
    MockDatabaseEngine  # SQLite test veritabanı motoru
)


class TestSQLInjectionEngine(unittest.TestCase):
    """SQL Injection kök neden ve savunma mekanizması için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz motor ve veritabanı örnekleri oluşturulur."""
        self.engine = SQLInjectionDefenseEngine()  # Ana savunma motoru başlatılır
        self.sensor = SQLiThreatSensor()  # Tehdit sensörü başlatılır
        self.db = MockDatabaseEngine()  # In-memory veritabanı motoru başlatılır

    def test_01_tautology_boolean_bypass_detection(self):
        """1. Test: Mantıksal totoloji (' OR '1'='1) kalıbının tespitini doğrular."""
        payload = "admin' OR '1'='1"  # Klasik totoloji yükü
        findings = self.sensor.scan_input(payload)  # Girdi taranır
        self.assertGreaterEqual(len(findings), 1)  # En az 1 bulgu saptanmalıdır
        types = [f.sqli_type for f in findings]  # Tür listesi çıkarılır
        self.assertIn(SQLiType.TAUTOLOGY_BOOLEAN, types)  # Totoloji türü doğrulanır

    def test_02_union_select_detection(self):
        """2. Test: UNION SELECT veri sızdırma kalıbının tespitini doğrular."""
        payload = "' UNION SELECT 1, username, password_hash, role, balance FROM users --"  # UNION yükü
        findings = self.sensor.scan_input(payload)  # Girdi taranır
        types = [f.sqli_type for f in findings]  # Türler alınır
        self.assertIn(SQLiType.UNION_BASED, types)  # UNION tespit edilmelidir

    def test_03_time_based_sleep_detection(self):
        """3. Test: Zaman tabanlı kör enjeksiyon (SLEEP / pg_sleep) tespitini doğrular."""
        payload = "admin' AND SLEEP(5) --"  # Zaman gecikmeli kör yük
        findings = self.sensor.scan_input(payload)  # Taranır
        types = [f.sqli_type for f in findings]  # Türler listelenir
        self.assertIn(SQLiType.TIME_BASED_BLIND, types)  # Zaman tabanlı saptanmalıdır

    def test_04_stacked_queries_detection(self):
        """4. Test: Noktalı virgül ile zincirlenen yıkıcı sorguların (Stacked Queries) tespitini doğrular."""
        payload = "admin'; DROP TABLE users; --"  # Yığılmış sorgu yükü
        findings = self.sensor.scan_input(payload)  # Taranır
        types = [f.sqli_type for f in findings]  # Türler
        self.assertIn(SQLiType.STACKED_QUERIES, types)  # Stacked query tespit edilmelidir

    def test_05_error_based_detection(self):
        """5. Test: Hata tabanlı veri çıkarma fonksiyonlarının (EXTRACTVALUE vb.) tespitini doğrular."""
        payload = "admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) --"  # Hata tabanlı yük
        findings = self.sensor.scan_input(payload)  # Taranır
        types = [f.sqli_type for f in findings]  # Türler
        self.assertIn(SQLiType.ERROR_BASED, types)  # Hata tabanlı doğrulanır

    def test_06_out_of_band_detection(self):
        """6. Test: Bant dışı dosya erişim fonksiyonunun (LOAD_FILE) tespitini doğrular."""
        payload = "' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3, 4, 5 --"  # OOB yükü
        findings = self.sensor.scan_input(payload)  # Taranır
        types = [f.sqli_type for f in findings]  # Türler
        self.assertIn(SQLiType.OUT_OF_BAND, types)  # OOB tespit edilmelidir

    def test_07_clean_benign_input_evaluation(self):
        """7. Test: Masum ve zararsız alfanümerik girdinin tehdit üretmediğini doğrular."""
        clean_input = "ahmet_kaya_2026"  # Masum kullanıcı adı
        findings = self.sensor.scan_input(clean_input)  # Taranır
        self.assertEqual(len(findings), 0)  # Hiçbir bulgu olmamalıdır

    def test_08_vulnerable_execution_tautology_bypass_success(self):
        """8. Test: Zafiyetli dize birleştirme ile ' OR '1'='1 yükünün kimlik doğrulamasını aştığını doğrular."""
        raw_user = "admin' OR '1'='1"  # Totoloji yükü
        raw_pass = "herhangi_bir_parola"  # Rastgele parola
        success, rows, sql, err = self.db.execute_vulnerable_query(raw_user, raw_pass)  # Zafiyetli çağrı
        self.assertTrue(success)  # Giriş aşılmış olmalıdır
        self.assertGreater(len(rows), 0)  # Veritabanından kayıt dönmelidir
        self.assertIsNone(err)  # Sözdizim hatası olmamalıdır

    def test_09_secure_parameterized_query_blocks_tautology(self):
        """9. Test: Parametrik sorgunun (Prepared Statement) ' OR '1'='1 yükünü düz dize sayarak engellediğini doğrular."""
        raw_user = "admin' OR '1'='1"  # Totoloji yükü
        raw_pass = "herhangi_bir_parola"  # Parola
        success, rows, sql = self.db.execute_secure_parameterized_query(raw_user, raw_pass)  # Güvenli çağrı
        self.assertFalse(success)  # Kesinlikle giriş aşılmamalıdır
        self.assertEqual(len(rows), 0)  # Hiçbir satır dönmemelidir
        self.assertIn("?", sql)  # Parametrik yer tutucu bulunmalıdır

    def test_10_vulnerable_execution_syntax_error_handling(self):
        """10. Test: Kapanmamış tırnak içeren bozuk SQL enjeksiyonunun veritabanı hatası ürettiğini doğrular."""
        malformed_user = "admin' AND ("  # Bozuk sözdizim
        success, rows, sql, err = self.db.execute_vulnerable_query(malformed_user, "pass")  # Çalıştırma
        self.assertFalse(success)  # Başarısız olmalıdır
        self.assertIsNotNone(err)  # Veritabanı hata mesajı dönmelidir

    def test_11_secure_parameterized_query_valid_credentials(self):
        """11. Test: Geçerli kimlik bilgilerinin parametrik sorgu ile doğru kullanıcı kaydını getirdiğini doğrular."""
        user = "ahmet_kaya"  # Doğru kullanıcı
        pwd_hash = "KayaHash9988!"  # Doğru parola özeti
        success, rows, sql = self.db.execute_secure_parameterized_query(user, pwd_hash)  # Güvenli çağrı
        self.assertTrue(success)  # Başarılı olmalıdır
        self.assertEqual(len(rows), 1)  # Tek kayıt dönmelidir
        self.assertEqual(rows[0]["username"], "ahmet_kaya")  # Kullanıcı adı doğrulanmalıdır

    def test_12_secure_dynamic_identifier_valid_table_and_column(self):
        """12. Test: İzinli (allowlist) tablo ve kolon belirteçlerinin güvenle çalıştırıldığını doğrular."""
        success, rows, sql = self.db.execute_secure_dynamic_identifier(table_name="users", sort_column="balance")  # Güvenli dinamik
        self.assertTrue(success)  # Başarılı olmalıdır
        self.assertEqual(len(rows), 4)  # 4 kullanıcı sıralanmalıdır
        self.assertIn("ORDER BY balance ASC", sql)  # Sıralama sorgusu doğrulanmalıdır

    def test_13_secure_dynamic_identifier_rejects_unwhitelisted_table(self):
        """13. Test: İzinli olmayan yabancı tablo adının ValueError ile engellendiğini doğrular."""
        with self.assertRaises(ValueError) as ctx:  # İstisna beklenir
            self.db.execute_secure_dynamic_identifier(table_name="secret_credentials", sort_column="id")  # Yasak tablo
        self.assertIn("Geçersiz tablo", str(ctx.exception))  # Hata mesajı kontrolü

    def test_14_secure_dynamic_identifier_rejects_sql_injection_in_sort(self):
        """14. Test: Sıralama kolonuna SQLi enjekte edilmeye çalışıldığında allowlist ile engellendiğini doğrular."""
        with self.assertRaises(ValueError) as ctx:  # İstisna beklenir
            self.db.execute_secure_dynamic_identifier(table_name="users", sort_column="balance; DROP TABLE users;")  # Enjeksiyonlu kolon
        self.assertIn("Geçersiz sıralama kolonu", str(ctx.exception))  # Hata mesajı kontrolü

    def test_15_engine_analyze_and_compare_output_structure(self):
        """15. Test: Motorun karşılaştırmalı analiz raporunun tüm anahtarları eksiksiz içerdiğini doğrular."""
        result = self.engine.analyze_and_compare("admin' OR 1=1 --", "nopass")  # Karşılaştırma
        self.assertTrue(result["is_attack_detected"])  # Tehdit yakalanmalıdır
        self.assertIn("vulnerable_execution", result)  # Zafiyetli bölüm bulunmalıdır
        self.assertIn("secure_parameterized_execution", result)  # Güvenli bölüm bulunmalıdır
        self.assertIn("root_cause_analysis", result)  # Kök neden açıklaması bulunmalıdır
        self.assertTrue(result["vulnerable_execution"]["bypassed_authentication"])  # Zafiyetli modda bypass olmalı
        self.assertFalse(result["secure_parameterized_execution"]["bypassed_authentication"])  # Güvenli modda engellenmeli


if __name__ == "__main__":  # Doğrudan çalıştırıldığında
    unittest.main()  # Testler başlatılır
