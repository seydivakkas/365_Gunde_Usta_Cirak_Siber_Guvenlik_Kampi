# -*- coding: utf-8 -*-
"""
Gün 162: SQL Injection Neden Oluşur ve Savunma Motoru (sql_injection_engine.py)

Bu modül; SQL enjeksiyonunun (SQLi - CWE-89) kök nedenini (Kod ile Veri karışımı -
Code vs. Data ambiguity), saldırı varyantlarını (Boolean/Tautology, UNION-based,
Error-based, Time-based Blind, Stacked Queries) analiz eden; güvensiz dinamik dize
birleştirme ile güvenli parametrik sorgu (Prepared Statement) arasındaki yapısal
ve yürütme farklarını in-memory SQLite motoru üzerinde somutlaştıran kurumsal bir motordur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import re  # Sözdizimsel kalıp ve tehdit imzaları taraması için re modülü dahil edilir
import sqlite3  # Gerçek veritabanı yürütme ve parametrik bağlama simülasyonu için sqlite3 dahil edilir
from enum import Enum  # Güçlü tip güvenliği için Enum sınıfı dahil edilir
from typing import Dict, List, Optional, Tuple, Any, Set  # Tip ipuçları için typing modülü dahil edilir


class SQLiType(str, Enum):
    """SQL Injection saldırı türlerini sınıflandıran numaralandırma."""
    TAUTOLOGY_BOOLEAN = "TAUTOLOGY_BOOLEAN"  # Mantıksal totoloji (' OR '1'='1) ile kimlik doğrulama bypassı
    UNION_BASED = "UNION_BASED"  # UNION operatörü ile yetkisiz tablolardan veri sızdırma
    ERROR_BASED = "ERROR_BASED"  # Hata mesajı içine veritabanı çıktısını gömerek sızdırma
    TIME_BASED_BLIND = "TIME_BASED_BLIND"  # Gecikme fonksiyonları (sleep) ile çıkarım yapma
    STACKED_QUERIES = "STACKED_QUERIES"  # Noktalı virgül ile zincirleme komut çalıştırma (; DROP TABLE)
    OUT_OF_BAND = "OUT_OF_BAND"  # DNS veya SMB kanalları üzerinden veri kaçırma (xp_dirtree, LOAD_FILE)


class SQLiSeverity(str, Enum):
    """Tespit edilen SQLi tehdidinin ciddiyet derecesi."""
    CRITICAL = "CRITICAL"  # Veritabanını tamamen boşaltma veya silme riski
    HIGH = "HIGH"  # Kimlik doğrulama aşma veya yetkisiz veri okuma
    MEDIUM = "MEDIUM"  # Şüpheli karakter dizisi veya zayıf kör enjeksiyon belirtisi
    LOW = "LOW"  # Bilgi toplama veya düşük etkili karakter anomalisi


class SQLiFinding:
    """Tespit edilen bir SQLi saldırı vektörünü temsil eden veri yapısı."""
    def __init__(self, sqli_type: SQLiType, severity: SQLiSeverity, pattern_name: str, description: str, matched_text: str):
        self.sqli_type: SQLiType = sqli_type  # Tehdit türü atanır
        self.severity: SQLiSeverity = severity  # Risk derecesi atanır
        self.pattern_name: str = pattern_name  # Eşleşen imza kuralı adı atanır
        self.description: str = description  # Teknik izahat atanır
        self.matched_text: str = matched_text  # Girdide yakalanan zararlı parça atanır

    def to_dict(self) -> Dict[str, Any]:
        """Bulguyu serileştirilebilir sözlüğe dönüştürür."""
        return {
            "sqli_type": self.sqli_type.value,  # Tür dizesi aktarılır
            "severity": self.severity.value,  # Ciddiyet dizesi aktarılır
            "pattern_name": self.pattern_name,  # Desen adı aktarılır
            "description": self.description,  # Açıklama aktarılır
            "matched_text": self.matched_text[:80]  # Eşleşen parça sınırlandırılarak aktarılır
        }


class SQLiThreatSensor:
    """Kullanıcı girdilerindeki SQL enjeksiyonu örüntülerini tespit eden analiz katmanı."""

    # 1. Totoloji ve Mantıksal Bypass Kalıpları (' OR '1'='1, ' OR 1=1 --)
    TAUTOLOGY_PATTERN = re.compile(
        r"(\b(?:OR|AND)\b\s+(['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|1\s*=\s*1|0\s*=\s*0|true\b))",
        re.IGNORECASE
    )
    # 2. UNION Tabanlı Sorgu Kalıpları (UNION SELECT, UNION ALL SELECT)
    UNION_PATTERN = re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE)
    # 3. Hata Tabanlı Fonksiyonlar (EXTRACTVALUE, UPDATEXML, CAST AS, CONVERT)
    ERROR_BASED_PATTERN = re.compile(r"\b(?:EXTRACTVALUE|UPDATEXML|CAST\s*\(.+AS\b|CONVERT\s*\()", re.IGNORECASE)
    # 4. Zaman Tabanlı Kör Fonksiyonlar (SLEEP, pg_sleep, WAITFOR DELAY, BENCHMARK)
    TIME_BASED_PATTERN = re.compile(r"\b(?:SLEEP\s*\(|pg_sleep\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()", re.IGNORECASE)
    # 5. Yığılmış Sorgular ve Yıkıcı Komutlar (; DROP, ; DELETE, ; UPDATE)
    STACKED_PATTERN = re.compile(r";\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|TRUNCATE)\b", re.IGNORECASE)
    # 6. SQL Yorum Satırı Ayrıştırıcıları (-- , /* */, #)
    COMMENT_PATTERN = re.compile(r"(--|/\*|\*/|#)", re.IGNORECASE)
    # 7. Bant Dışı ve Dosya Erişim Fonksiyonları (LOAD_FILE, xp_dirtree, UTL_FILE)
    OUT_OF_BAND_PATTERN = re.compile(r"\b(?:LOAD_FILE|xp_dirtree|xp_cmdshell|UTL_HTTP|UTL_FILE)\b", re.IGNORECASE)

    def scan_input(self, raw_input: str) -> List[SQLiFinding]:
        """Girdideki potansiyel SQLi vektörlerini tarar ve bulguları listeler."""
        findings: List[SQLiFinding] = []  # Boş bulgu listesi oluşturulur
        if not raw_input or not isinstance(raw_input, str):  # Boş veya geçersiz tip kontrolü
            return findings  # Boş liste döndürülür
            
        clean_text = raw_input.strip()  # Baş ve son boşluklar temizlenir
        
        # 1. Totoloji denetimi
        t_match = self.TAUTOLOGY_PATTERN.search(clean_text)  # Totoloji aranır
        if t_match:  # Bulunması halinde
            findings.append(SQLiFinding(
                SQLiType.TAUTOLOGY_BOOLEAN,  # Totoloji türü
                SQLiSeverity.CRITICAL,  # Kritik seviye
                "TAUTOLOGY_BOOLEAN_BYPASS",  # İmza adı
                "Mantıksal totoloji (' OR '1'='1) ile kimlik doğrulama bypassı tespit edildi.",  # Açıklama
                t_match.group(0)  # Eşleşen parça
            ))
            
        # 2. UNION denetimi
        u_match = self.UNION_PATTERN.search(clean_text)  # UNION aranır
        if u_match:  # Eşleşme varsa
            findings.append(SQLiFinding(
                SQLiType.UNION_BASED,  # UNION türü
                SQLiSeverity.CRITICAL,  # Kritik seviye
                "UNION_SELECT_INJECTION",  # İmza adı
                "Ek veri çekmek amacıyla UNION SELECT sorgu birleştirmesi saptandı.",  # Açıklama
                u_match.group(0)  # Eşleşme
            ))
            
        # 3. Hata tabanlı enjeksiyon denetimi
        e_match = self.ERROR_BASED_PATTERN.search(clean_text)  # Hata fonksiyonları aranır
        if e_match:  # Bulunursa
            findings.append(SQLiFinding(
                SQLiType.ERROR_BASED,  # Hata türü
                SQLiSeverity.HIGH,  # Yüksek ciddiyet
                "ERROR_BASED_FUNCTION",  # İmza adı
                "Hata mesajı üzerinden veri sızdırma amaçlı fonksiyon çağrısı bulundu.",  # Açıklama
                e_match.group(0)  # Eşleşme
            ))
            
        # 4. Zaman tabanlı kör denetim
        time_match = self.TIME_BASED_PATTERN.search(clean_text)  # Zaman fonksiyonu aranır
        if time_match:  # Eşleşme varsa
            findings.append(SQLiFinding(
                SQLiType.TIME_BASED_BLIND,  # Zaman tabanlı
                SQLiSeverity.HIGH,  # Yüksek ciddiyet
                "TIME_BASED_SLEEP_INJECTION",  # İmza adı
                "Zaman gecikmeli kör (Blind) SQLi fonksiyonu tespit edildi.",  # Açıklama
                time_match.group(0)  # Eşleşme
            ))
            
        # 5. Yığılmış sorgular (Stacked queries)
        stack_match = self.STACKED_PATTERN.search(clean_text)  # Yığılmış komut aranır
        if stack_match:  # Bulunursa
            findings.append(SQLiFinding(
                SQLiType.STACKED_QUERIES,  # Yığılmış tür
                SQLiSeverity.CRITICAL,  # Kritik ciddiyet
                "STACKED_QUERY_ATTEMPT",  # İmza adı
                "Noktalı virgül ile zincirlenen yıkıcı SQL komutu tespit edildi.",  # Açıklama
                stack_match.group(0)  # Eşleşme
            ))
            
        # 6. Yorum satırı ayrıştırıcıları
        c_match = self.COMMENT_PATTERN.search(clean_text)  # Yorum ayracı aranır
        if c_match:  # Varsa
            findings.append(SQLiFinding(
                SQLiType.TAUTOLOGY_BOOLEAN,  # Genellikle sorgu sonunu budamada kullanılır
                SQLiSeverity.MEDIUM,  # Orta ciddiyet
                "SQL_COMMENT_DELIMITER",  # İmza adı
                "Sorgunun kalan kısmını etkisiz kılmak için SQL yorum ayracı kullanılmış.",  # Açıklama
                c_match.group(0)  # Eşleşme
            ))
            
        # 7. Bant dışı veri sızdırma
        oob_match = self.OUT_OF_BAND_PATTERN.search(clean_text)  # OOB aranır
        if oob_match:  # Bulunursa
            findings.append(SQLiFinding(
                SQLiType.OUT_OF_BAND,  # OOB türü
                SQLiSeverity.CRITICAL,  # Kritik seviye
                "OUT_OF_BAND_EXFILTRATION",  # İmza adı
                "Bant dışı dosya erişimi veya DNS sızdırma fonksiyonu tespit edildi.",  # Açıklama
                oob_match.group(0)  # Eşleşme
            ))
            
        return findings  # Tüm bulgular döndürülür


class MockDatabaseEngine:
    """SQL enjeksiyonunun kök nedenini somutlaştıran in-memory SQLite veritabanı motoru."""

    def __init__(self):
        self.conn = sqlite3.connect(":memory:")  # Bellek içi SQLite veritabanı başlatılır
        self.cursor = self.conn.cursor()  # Veritabanı imleci oluşturulur
        self._initialize_schema()  # Test şeması ve tohum verileri yüklenir

    def _initialize_schema(self):
        """Kullanıcılar ve hesaplar tablolarını oluşturup örnek veriler ekler."""
        # Kullanıcılar tablosu oluşturulur
        self.cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                full_name TEXT,
                role TEXT,
                balance REAL
            )
        """)  # Tablo oluşturma sorgusu çalıştırılır
        
        # Tohum veriler eklenir
        seed_users = [
            ("admin", "AdminSecretPassHash2026!", "Sistem Yöneticisi", "ADMIN", 150000.0),  # Yönetici hesabı
            ("ahmet_kaya", "KayaHash9988!", "Ahmet Kaya", "USER", 3450.50),  # Normal kullanıcı 1
            ("ayse_demir", "DemirHash3344!", "Ayşe Demir", "USER", 8920.00),  # Normal kullanıcı 2
            ("mehmet_oz", "OzSecurePass1122!", "Mehmet Öz", "USER", 1240.25)   # Normal kullanıcı 3
        ]
        self.cursor.executemany("""
            INSERT INTO users (username, password_hash, full_name, role, balance)
            VALUES (?, ?, ?, ?, ?)
        """, seed_users)  # Toplu ekleme sorgusu yürütülür
        self.conn.commit()  # Değişiklikler işlenir

    def execute_vulnerable_query(self, username: str, password: str) -> Tuple[bool, List[Dict[str, Any]], str, Optional[str]]:
        """
        ZAFİYETLİ YÜRÜTME: Veri ve kodun dinamik dize birleştirme ile karıştırıldığı yöntem.
        Saldırgan girdisi doğrudan SQL ayrıştırıcısının mantık ağacını (AST) değiştirir.
        """
        # Hatalı ve güvensiz dinamik SQL sorgusu oluşturulur
        raw_sql = f"SELECT id, username, full_name, role, balance FROM users WHERE username = '{username}' AND password_hash = '{password}'"  # Dize birleştirme
        try:  # Çalıştırma denenir
            self.cursor.execute(raw_sql)  # Ham SQL çalıştırılır
            rows = self.cursor.fetchall()  # Satırlar çekilir
            result = [  # Sözlük listesi oluşturulur
                {"id": r[0], "username": r[1], "full_name": r[2], "role": r[3], "balance": r[4]}
                for r in rows
            ]
            success = len(result) > 0  # Sonuç varsa başarılı sayılır
            return success, result, raw_sql, None  # Başarı, sonuçlar, sorgu ve hata yok dönülür
        except sqlite3.Error as e:  # SQL sözdizim hatası durumunda
            return False, [], raw_sql, str(e)  # Hata mesajı dönülür

    def execute_secure_parameterized_query(self, username: str, password: str) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        GÜVENLİ YÜRÜTME: Parametrik Sorgu / Prepared Statement kullanımı.
        Sorgu şablonu önceden derlenir; kullanıcı girdisi sadece veri literali olarak bağlanır,
        asla SQL sözdizimi olarak yürütülemez.
        """
        # Parametrik güvenli SQL şablonu tanımlanır
        param_sql = "SELECT id, username, full_name, role, balance FROM users WHERE username = ? AND password_hash = ?"  # Soru işaretleri parametredir
        self.cursor.execute(param_sql, (username, password))  # Veri ayrık bir demet olarak bağlanır
        rows = self.cursor.fetchall()  # Sonuçlar çekilir
        result = [  # Sözlük listesi üretilir
            {"id": r[0], "username": r[1], "full_name": r[2], "role": r[3], "balance": r[4]}
            for r in rows
        ]
        success = len(result) > 0  # Sonuç kontrolü
        return success, result, param_sql  # Başarı, sonuç ve parametrik şablon döndürülür

    def execute_secure_dynamic_identifier(self, table_name: str, sort_column: str) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        DİNAMİK BELİRTEÇ GÜVENLİĞİ: Tablo veya kolon adları Prepared Statement ile parametre yapılamaz.
        Bu durumlarda katı allowlist (beyaz liste) eşlemesi zorunludur.
        """
        # İzin verilen tablo ve kolon listeleri
        ALLOWED_TABLES: Set[str] = {"users"}  # İzinli tablolar
        ALLOWED_COLUMNS: Set[str] = {"id", "username", "full_name", "role", "balance"}  # İzinli sıralama kolonları
        
        if table_name not in ALLOWED_TABLES:  # Tablo allowlist dışıysa
            raise ValueError(f"Geçersiz tablo adı: {table_name}")  # Güvenlik istisnası
        if sort_column not in ALLOWED_COLUMNS:  # Kolon allowlist dışıysa
            raise ValueError(f"Geçersiz sıralama kolonu: {sort_column}")  # Güvenlik istisnası
            
        safe_sql = f"SELECT id, username, full_name, role, balance FROM {table_name} ORDER BY {sort_column} ASC"  # Güvenli dinamik sorgu
        self.cursor.execute(safe_sql)  # Sorgu yürütülür
        rows = self.cursor.fetchall()  # Satırlar alınır
        result = [  # Sözlüğe çevrilir
            {"id": r[0], "username": r[1], "full_name": r[2], "role": r[3], "balance": r[4]}
            for r in rows
        ]
        return True, result, safe_sql  # Sonuç dönülür


class SQLInjectionDefenseEngine:
    """SQLi tehdit analizini ve koruma mekanizmalarını yöneten ana orkestratör."""

    def __init__(self):
        self.sensor = SQLiThreatSensor()  # Tehdit tarayıcısı başlatılır
        self.db = MockDatabaseEngine()  # Veritabanı motoru başlatılır

    def analyze_and_compare(self, username_input: str, password_input: str) -> Dict[str, Any]:
        """
        Girdileri analiz eder, tehditleri belirler ve zafiyetli vs. güvenli yürütme
        sonuçlarını karşılaştırmalı olarak raporlar.
        """
        # 1. Tehdit taraması
        u_findings = self.sensor.scan_input(username_input)  # Kullanıcı adı taranır
        p_findings = self.sensor.scan_input(password_input)  # Parola taranır
        all_findings = u_findings + p_findings  # Bulgular birleştirilir
        is_attack = len(all_findings) > 0  # Saldırı bayrağı belirlenir
        
        # 2. Zafiyetli Yürütme Simülasyonu
        v_success, v_rows, v_sql, v_err = self.db.execute_vulnerable_query(username_input, password_input)  # Zafiyetli çağrı
        
        # 3. Güvenli Parametrik Yürütme Simülasyonu
        s_success, s_rows, s_sql = self.db.execute_secure_parameterized_query(username_input, password_input)  # Güvenli çağrı
        
        # 4. Kök Neden Analizi Çıkarımı
        root_cause_explanation = (
            "SQL Injection'ın temel kök nedeni, kullanıcıdan gelen verinin (Data) SQL sözdizimi "
            "yorumlayıcısı (Code) tarafından derleme aşamasında sorgu yapısını değiştirecek biçimde "
            "doğrudan dinamik dize olarak birleştirilmesidir (Code vs. Data Ambiguity). "
            "Prepared Statement (Parametrik Sorgu) kullanıldığında, veritabanı motoru sorgu yapısını "
            "(AST) önceden derler; kullanıcı girdisini hiçbir koşulda yürütülebilir kod olarak yorumlamaz, "
            "yalnızca düz veri literali olarak eşleştirir."
        )
        
        return {
            "is_attack_detected": is_attack,  # Saldırı tespiti
            "findings_count": len(all_findings),  # Bulgu sayısı
            "findings": [f.to_dict() for f in all_findings],  # Bulgular listesi
            "vulnerable_execution": {  # Zafiyetli sonuçlar
                "executed_sql": v_sql,  # Üretilen ham SQL
                "bypassed_authentication": v_success,  # Giriş aşıldı mı
                "records_leaked_count": len(v_rows),  # Sızdırılan kayıt adedi
                "database_error": v_err  # Hata mesajı
            },
            "secure_parameterized_execution": {  # Güvenli sonuçlar
                "parameterized_template": s_sql,  # Güvenli şablon
                "bypassed_authentication": s_success,  # Güvenli modda giriş aşıldı mı
                "records_returned_count": len(s_rows)  # Dönen kayıt adedi
            },
            "root_cause_analysis": root_cause_explanation  # Kök neden izahatı
        }
