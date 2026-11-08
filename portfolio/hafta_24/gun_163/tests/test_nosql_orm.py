# -*- coding: utf-8 -*-
"""
Gün 163: NoSQL ve ORM Sınırları Birim Testleri (test_nosql_orm.py)

Bu test paketi; NoSQL operatör enjeksiyonlarını ($ne, $gt, $regex, $where),
nesne yolu manipülasyonlarını, ORM Mass Assignment zafiyetlerini ve katı
DTO beyaz liste korumalarını 15 kapsamlı birim test senaryosuyla doğrular.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yolu işlemleri için os modülü dahil edilir
import sys  # Sistem yolu ve modül arama önceliği için sys modülü dahil edilir
import unittest  # Birim test çerçevesi için unittest modülü dahil edilir

# Test edilecek modül dizininin sys.path içerisine eklenmesi
current_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut test dosyasının bulunduğu dizin alınır
app_dir = os.path.join(os.path.dirname(current_dir), "uygulama")  # uygulama dizininin mutlak yolu oluşturulur
if app_dir not in sys.path:  # Uygulama dizini sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # En başa eklenerek içe aktarma önceliği sağlanır

# Test edilecek sınıfların içe aktarılması
from nosql_orm_engine import (  # nosql_orm_engine modülünden gerekli sınıflar çağrılır
    NoSQLORMDefenseEngine,  # Merkezi savunma ve karşılaştırma motoru
    NoSQLThreatDetector,  # Tehdit tespit modülü
    NoSQLiType,  # Tehdit türleri numaralandırması
    NoSQLiSeverity,  # Ciddiyet seviyeleri numaralandırması
    MockNoSQLCollection  # In-memory doküman koleksiyonu
)


class TestNoSQLORMEngine(unittest.TestCase):
    """NoSQL enjeksiyonu ve ORM kütlesel atama güvenliği için 15 fonksiyonel birim test sınıfı."""

    def setUp(self):
        """Her testten önce temiz dedektör, koleksiyon ve motor örnekleri oluşturulur."""
        self.detector = NoSQLThreatDetector()  # Tehdit tarayıcısı başlatılır
        self.collection = MockNoSQLCollection()  # Test koleksiyonu başlatılır
        self.engine = NoSQLORMDefenseEngine()  # Ana savunma motoru başlatılır

    def test_01_nosql_operator_ne_detection(self):
        """1. Test: $ne (not equal) operatör enjeksiyonunun tespitini doğrular."""
        payload = {"username": "admin", "password_hash": {"$ne": ""}}  # $ne operatör yükü
        findings = self.detector.scan_query_dict(payload)  # Tarama yapılır
        self.assertGreaterEqual(len(findings), 1)  # En az 1 bulgu saptanmalıdır
        types = [f.threat_type for f in findings]  # Tür listesi çıkarılır
        self.assertIn(NoSQLiType.OPERATOR_INJECTION, types)  # Operatör enjeksiyonu doğrulanır

    def test_02_nosql_operator_gt_detection(self):
        """2. Test: $gt (greater than) operatör enjeksiyonunun tespitini doğrular."""
        payload = {"username": {"$gt": ""}, "password_hash": {"$gt": ""}}  # $gt operatör yükü
        findings = self.detector.scan_query_dict(payload)  # Tarama yapılır
        self.assertGreaterEqual(len(findings), 2)  # 2 operatör saptanmalıdır
        self.assertEqual(findings[0].threat_type, NoSQLiType.OPERATOR_INJECTION)  # Tür doğrulanır

    def test_03_nosql_regex_blind_detection(self):
        """3. Test: $regex kör karakter sızdırma operatörünün tespitini doğrular."""
        payload = {"username": "admin", "password_hash": {"$regex": "^Admin.*"}}  # $regex yükü
        findings = self.detector.scan_query_dict(payload)  # Tarama yapılır
        types = [f.threat_type for f in findings]  # Tür listesi
        self.assertIn(NoSQLiType.REGEX_BLIND_INJECTION, types)  # Regex türü yakalanmalıdır

    def test_04_nosql_where_javascript_eval_detection(self):
        """4. Test: $where sunucu taraflı JavaScript çalıştırma operatörünün tespitini doğrular."""
        payload = {"$where": "this.password_hash.length > 5"}  # $where yükü
        findings = self.detector.scan_query_dict(payload)  # Taranır
        types = [f.threat_type for f in findings]  # Türler
        self.assertIn(NoSQLiType.JAVASCRIPT_EVAL, types)  # JS eval doğrulanır
        self.assertEqual(findings[0].severity, NoSQLiSeverity.CRITICAL)  # Kritik ciddiyet doğrulanır

    def test_05_nosql_object_path_pollution_detection(self):
        """5. Test: Nokta notasyonu içeren nesne yolu kirliliğinin (Path Pollution) tespitini doğrular."""
        payload = {"profile.role": "admin"}  # Noktalı alan
        findings = self.detector.scan_query_dict(payload)  # Taranır
        types = [f.threat_type for f in findings]  # Türler
        self.assertIn(NoSQLiType.OBJECT_PATH_POLLUTION, types)  # Yol kirliliği yakalanmalıdır

    def test_06_mass_assignment_is_admin_detection(self):
        """6. Test: Güncelleme gövdesindeki is_admin korumalı alanının (Mass Assignment) tespitini doğrular."""
        payload = {"full_name": "Ahmet K.", "is_admin": True}  # is_admin içeren payload
        findings = self.detector.scan_mass_assignment(payload)  # Taranır
        self.assertGreaterEqual(len(findings), 1)  # Bulgu yakalanmalı
        self.assertEqual(findings[0].threat_type, NoSQLiType.MASS_ASSIGNMENT)  # Mass assignment türü

    def test_07_mass_assignment_role_escalation_detection(self):
        """7. Test: Güncelleme gövdesindeki role: ADMIN ayrıcalık yükseltme girişiminin tespitini doğrular."""
        payload = {"role": "ADMIN", "email": "hacked@evil.com"}  # Rol değiştirme denemesi
        findings = self.detector.scan_mass_assignment(payload)  # Taranır
        types = [f.threat_type for f in findings]  # Türler
        self.assertIn(NoSQLiType.MASS_ASSIGNMENT, types)  # Kütlesel atama doğrulanır

    def test_08_clean_benign_query_evaluation(self):
        """8. Test: Masum skaler değerler içeren sorgunun hiçbir tehdit üretmediğini doğrular."""
        clean_query = {"username": "ahmet_kaya", "email": "ahmet@kurum.internal"}  # Masum sorgu
        findings = self.detector.scan_query_dict(clean_query)  # Taranır
        self.assertEqual(len(findings), 0)  # Sıfır bulgu dönmelidir

    def test_09_vulnerable_find_auth_bypass_with_ne(self):
        """9. Test: Zafiyetli find() metodunun $ne ile parola bilmeden admin oturumunu aştığını doğrular."""
        malicious_query = {"username": "admin", "password_hash": {"$ne": ""}}  # $ne yükü
        results = self.collection.vulnerable_find(malicious_query)  # Zafiyetli arama
        self.assertEqual(len(results), 1)  # 1 belge dönmelidir
        self.assertEqual(results[0]["username"], "admin")  # Admin belgesi sızdırılmış olmalıdır

    def test_10_secure_find_blocks_operator_injection(self):
        """10. Test: Güvenli find() metodunun sözlük/operatör içeren alanı ValueError ile reddettiğini doğrular."""
        malicious_query = {"username": "admin", "password_hash": {"$ne": ""}}  # $ne yükü
        with self.assertRaises(ValueError) as ctx:  # İstisna beklenir
            self.collection.secure_find(malicious_query)  # Güvenli çağrı
        self.assertIn("geçersiz karmaşık nesne", str(ctx.exception))  # Hata mesajı doğrulanır

    def test_11_secure_find_blocks_top_level_dollar_operator(self):
        """11. Test: Güvenli find() metodunun tepe seviyedeki $ operatörünü ($where) engellediğini doğrular."""
        malicious_query = {"$where": "true"}  # $where yükü
        with self.assertRaises(ValueError) as ctx:  # İstisna beklenir
            self.collection.secure_find(malicious_query)  # Güvenli çağrı
        self.assertIn("operatör enjeksiyonu engellendi", str(ctx.exception))  # Hata kontrolü

    def test_12_secure_find_valid_scalar_credentials(self):
        """12. Test: Geçerli skaler dize kimlik bilgilerinin güvenli find() ile doğru kaydı getirdiğini doğrular."""
        valid_query = {"username": "ahmet_kaya", "password_hash": "KayaHash9988!"}  # Doğru bilgiler
        results = self.collection.secure_find(valid_query)  # Güvenli arama
        self.assertEqual(len(results), 1)  # Tek kayıt bulunmalı
        self.assertEqual(results[0]["username"], "ahmet_kaya")  # Kullanıcı adı doğrulanmalı

    def test_13_vulnerable_update_allows_mass_assignment(self):
        """13. Test: Zafiyetli güncellemenin normal kullanıcının is_admin alanını True yaptığını doğrular."""
        payload = {"is_admin": True, "role": "ADMIN"}  # Ayrıcalık yükseltme payloadı
        ok, updated_doc = self.collection.vulnerable_update_user(user_id=2, payload=payload)  # Zafiyetli çağrı
        self.assertTrue(ok)  # Güncelleme başarılı olmalı
        self.assertTrue(updated_doc["is_admin"])  # is_admin ezilmiş olmalıdır (ZAFİYET!)
        self.assertEqual(updated_doc["role"], "ADMIN")  # Rol ezilmiş olmalıdır

    def test_14_secure_update_enforces_dto_allowlist(self):
        """14. Test: Güvenli güncellemenin DTO allowlist ile is_admin alanını budayarak koruduğunu doğrular."""
        payload = {"full_name": "Ahmet Güncel", "is_admin": True, "balance": 999999.0}  # Tehlikeli alanlar
        ok, updated_doc = self.collection.secure_update_user(user_id=2, payload=payload)  # Güvenli çağrı
        self.assertTrue(ok)  # Güncelleme tamamlandı
        self.assertEqual(updated_doc["full_name"], "Ahmet Güncel")  # İzinli alan güncellendi
        self.assertFalse(updated_doc["is_admin"])  # is_admin KESİNLİKLE False kalmalıdır
        self.assertEqual(updated_doc["balance"], 3450.50)  # Bakiye KESİNLİKLE değişmemelidir

    def test_15_engine_inspect_and_test_nosqli_structure(self):
        """15. Test: Motorun karşılaştırmalı NoSQL analiz çıktısının tüm beklenen alanları içerdiğini doğrular."""
        query = {"username": "admin", "password_hash": {"$ne": ""}}  # $ne sorgusu
        result = self.engine.inspect_and_test_nosqli(query)  # Motor analizi
        self.assertTrue(result["is_threat_detected"])  # Tehdit saptanmalı
        self.assertTrue(result["vulnerable_execution"]["authentication_bypassed"])  # Zafiyetli modda bypass olmalı
        self.assertTrue(result["secure_execution"]["blocked_by_sanitizer"])  # Güvenli modda engellenmeli
        self.assertIsNotNone(result["secure_execution"]["sanitizer_error"])  # Hata mesajı bulunmalı


if __name__ == "__main__":  # Doğrudan çalıştırıldığında
    unittest.main()  # Testler icra edilir
