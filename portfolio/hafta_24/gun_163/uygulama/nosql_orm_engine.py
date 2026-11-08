# -*- coding: utf-8 -*-
"""
Gün 163: NoSQL ve ORM Sınırları Savunma Motoru (nosql_orm_engine.py)

Bu modül; NoSQL Injection (CWE-943) operatör saldırılarını ($ne, $gt, $regex, $where),
ORM Mass Assignment (Toplu Atama) zafiyetlerini ve güvensiz dinamik nesne bağlamalarını
in-memory doküman tabanlı bir koleksiyon üzerinde simüle eden, katı tip denetimi
ve DTO beyaz liste arındırması uygulayan kurumsal bir savunma motorudur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import re  # Düzenli ifadeler ile regex ve desen denetimi için re modülü dahil edilir
import copy  # Nesne derin kopyalama ve veri izolasyonu için copy modülü dahil edilir
from enum import Enum  # Güçlü tip güvenliği için Enum sınıfı dahil edilir
from typing import Dict, List, Optional, Tuple, Any, Set  # Tip ipuçları için typing modülü dahil edilir


class NoSQLiType(str, Enum):
    """NoSQL ve ORM güvenlik tehditlerini sınıflandıran numaralandırma."""
    OPERATOR_INJECTION = "OPERATOR_INJECTION"  # $ne, $gt, $in gibi sorgu operatörlerinin enjekte edilmesi
    REGEX_BLIND_INJECTION = "REGEX_BLIND_INJECTION"  # $regex ile karakter karakter veri sızdırma
    JAVASCRIPT_EVAL = "JAVASCRIPT_EVAL"  # $where veya sunucu taraflı JS çalıştırma denemeleri
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"  # ORM modellerinde yetkisiz alanların (role, is_admin) ezilmesi
    OBJECT_PATH_POLLUTION = "OBJECT_PATH_POLLUTION"  # Nokta notasyonu (user.role) ile nesne ağacını bozma


class NoSQLiSeverity(str, Enum):
    """Tespit edilen NoSQL/ORM tehdidinin ciddiyet derecesi."""
    CRITICAL = "CRITICAL"  # Kimlik doğrulama bypass veya uzaktan yetkisiz ayrıcalık yükseltme
    HIGH = "HIGH"  # Yetkisiz veri sızdırma veya hassas model alanlarının tahrif edilmesi
    MEDIUM = "MEDIUM"  # Şüpheli filtreleme veya beklenmeyen nesne yapısı
    LOW = "LOW"  # Küçük biçim uyumsuzluğu


class NoSQLFinding:
    """Tespit edilen bir NoSQL veya ORM zafiyetini tutan veri modeli."""
    def __init__(self, threat_type: NoSQLiType, severity: NoSQLiSeverity, pattern_name: str, description: str, matched_element: Any):
        self.threat_type: NoSQLiType = threat_type  # Tehdit türü atanır
        self.severity: NoSQLiSeverity = severity  # Risk seviyesi atanır
        self.pattern_name: str = pattern_name  # Kural veya imza adı atanır
        self.description: str = description  # Açıklama atanır
        self.matched_element: Any = matched_element  # Yakalanan zararlı veri/anahtar atanır

    def to_dict(self) -> Dict[str, Any]:
        """Bulguyu serileştirilebilir sözlüğe dönüştürür."""
        return {
            "threat_type": self.threat_type.value,  # Tür dize olarak aktarılır
            "severity": self.severity.value,  # Ciddiyet aktarılır
            "pattern_name": self.pattern_name,  # Desen adı aktarılır
            "description": self.description,  # Açıklama metni aktarılır
            "matched_element": str(self.matched_element)[:100]  # Eşleşen eleman aktarılır
        }


class NoSQLThreatDetector:
    """Girdilerdeki NoSQL sorgu operatörlerini ve ORM sınır ihlallerini tespit eden denetçi."""

    # Yasaklı BSON / NoSQL operatörleri kümesi
    FORBIDDEN_OPERATORS: Set[str] = {
        "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex",
        "$where", "$exists", "$or", "$and", "$nor", "$expr", "$text", "$mod"
    }

    # ORM modellerinde dışarıdan yazılması kesinlikle yasak olan hassas alanlar (Mass Assignment)
    PROTECTED_MODEL_FIELDS: Set[str] = {
        "is_admin", "is_superuser", "is_staff", "role", "roles",
        "balance", "credit_limit", "permissions", "password_hash", "token", "api_key"
    }

    def scan_query_dict(self, data: Any, current_path: str = "") -> List[NoSQLFinding]:
        """İç içe geçmiş sözlük yapılarında NoSQL operatörlerini özyinelemeli tarar."""
        findings: List[NoSQLFinding] = []  # Boş bulgu listesi oluşturulur
        
        if isinstance(data, dict):  # Eğer veri bir sözlük ise
            for key, val in data.items():  # Anahtar ve değerler döngüye alınır
                field_path = f"{current_path}.{key}" if current_path else key  # Hiyerarşik yol oluşturulur
                
                # 1. $ ile başlayan operatör kontrolü
                if isinstance(key, str) and key.startswith("$"):  # Anahtar $ ile başlıyorsa
                    if key == "$where":  # Sunucu taraflı JS çalıştırma
                        findings.append(NoSQLFinding(
                            NoSQLiType.JAVASCRIPT_EVAL,  # JS eval türü
                            NoSQLiSeverity.CRITICAL,  # Kritik seviye
                            "NOSQL_JAVASCRIPT_WHERE_CLAUSE",  # İmza adı
                            "Tehlikeli $where sunucu taraflı JavaScript çalıştırma operatörü tespit edildi.",  # Açıklama
                            {key: val}  # Eşleşen yapı
                        ))
                    elif key == "$regex":  # Kör regex çıkarma
                        findings.append(NoSQLFinding(
                            NoSQLiType.REGEX_BLIND_INJECTION,  # Regex türü
                            NoSQLiSeverity.HIGH,  # Yüksek seviye
                            "NOSQL_REGEX_BLIND_OPERATOR",  # İmza adı
                            "Karakter çıkarma amaçlı $regex operatörü tespit edildi.",  # Açıklama
                            {key: val}  # Eşleşme
                        ))
                    elif key in self.FORBIDDEN_OPERATORS:  # Diğer yasaklı operatörler ($ne, $gt vb.)
                        findings.append(NoSQLFinding(
                            NoSQLiType.OPERATOR_INJECTION,  # Operatör enjeksiyonu
                            NoSQLiSeverity.CRITICAL,  # Kritik seviye
                            "NOSQL_RESERVED_OPERATOR_INJECTION",  # İmza adı
                            f"Yasaklı NoSQL BSON operatörü enjeksiyonu tespit edildi: '{key}'",  # Açıklama
                            {key: val}  # Eşleşme
                        ))
                        
                # 2. Nokta notasyonu (path pollution) kontrolü
                if isinstance(key, str) and "." in key:  # Anahtarda nokta geçiyorsa
                    findings.append(NoSQLFinding(
                        NoSQLiType.OBJECT_PATH_POLLUTION,  # Yol kirliliği
                        NoSQLiSeverity.MEDIUM,  # Orta ciddiyet
                        "OBJECT_PATH_DOT_NOTATION",  # İmza adı
                        f"İç içe nesne ağacını manipüle eden nokta notasyonu saptandı: '{key}'",  # Açıklama
                        key  # Anahtar adı
                    ))
                    
                # 3. Özyinelemeli alt tarama
                findings.extend(self.scan_query_dict(val, field_path))  # Alt seviye taranır
                
        elif isinstance(data, list):  # Eğer veri liste ise
            for idx, item in enumerate(data):  # Elemanlar taranır
                findings.extend(self.scan_query_dict(item, f"{current_path}[{idx}]"))  # Liste elemanı taranır
                
        return findings  # Tespit edilen bulgular döndürülür

    def scan_mass_assignment(self, update_payload: Dict[str, Any]) -> List[NoSQLFinding]:
        """Kullanıcı güncelleme gövdesindeki kütlesel atama (Mass Assignment) ihlallerini yakalar."""
        findings: List[NoSQLFinding] = []  # Boş liste oluşturulur
        if not isinstance(update_payload, dict):  # Sözlük değilse
            return findings  # Boş dönülür
            
        for key in update_payload.keys():  # Gönderilen tüm anahtarlar incelenir
            lower_key = key.lower().strip()  # Küçük harfe çevrilir
            if lower_key in self.PROTECTED_MODEL_FIELDS:  # Korunan model alanlarından biriyse
                findings.append(NoSQLFinding(
                    NoSQLiType.MASS_ASSIGNMENT,  # Kütlesel atama türü
                    NoSQLiSeverity.HIGH,  # Yüksek ciddiyet
                    "ORM_MASS_ASSIGNMENT_VULNERABILITY",  # İmza adı
                    f"Korumalı ve yetkisiz model alanına yazma girişimi (Mass Assignment): '{key}'",  # Açıklama
                    key  # Alan adı
                ))
                
        return findings  # Bulgular döndürülür


class MockNoSQLCollection:
    """NoSQL enjeksiyonu ve Mass Assignment zafiyetlerini simüle eden in-memory doküman koleksiyonu."""

    def __init__(self):
        # Örnek tohum kullanıcı belgeleri (Doküman veritabanı simülasyonu)
        self.documents: List[Dict[str, Any]] = [
            {
                "id": 1,  # Kimlik
                "username": "admin",  # Kullanıcı adı
                "password_hash": "AdminSecretHash2026!",  # Parola özeti
                "role": "ADMIN",  # Rol
                "is_admin": True,  # Yönetici bayrağı
                "balance": 150000.0,  # Bakiye
                "full_name": "Sistem Yöneticisi",  # İsim
                "email": "admin@kurum.internal"  # E-posta
            },
            {
                "id": 2,  # Kimlik
                "username": "ahmet_kaya",  # Kullanıcı adı
                "password_hash": "KayaHash9988!",  # Parola
                "role": "USER",  # Rol
                "is_admin": False,  # Yönetici değil
                "balance": 3450.50,  # Bakiye
                "full_name": "Ahmet Kaya",  # İsim
                "email": "ahmet@kurum.internal"  # E-posta
            },
            {
                "id": 3,  # Kimlik
                "username": "ayse_demir",  # Kullanıcı adı
                "password_hash": "DemirHash3344!",  # Parola
                "role": "USER",  # Rol
                "is_admin": False,  # Yönetici değil
                "balance": 8920.00,  # Bakiye
                "full_name": "Ayşe Demir",  # İsim
                "email": "ayse@kurum.internal"  # E-posta
            }
        ]

    def vulnerable_find(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        ZAFİYETLİ SORGU: MongoDB sorgu operatörlerini ($ne, $gt, $regex) doğrudan yorumlar.
        Geliştirici gelen JSON/nesne girdisini doğrudan find() içine ilettiğinde çalışır.
        """
        matched = []  # Eşleşen kayıtlar listesi
        for doc in self.documents:  # Tüm belgeler taranır
            is_match = True  # Eşleşme bayrağı
            for q_key, q_val in query.items():  # Sorgu kriterleri incelenir
                doc_val = doc.get(q_key)  # Belgedeki gerçek değer
                
                if isinstance(q_val, dict):  # Eğer sorgu değeri bir operatör sözlüğü ise (ZAFİYET!)
                    for op, target in q_val.items():  # Operatörler ayrıştırılır
                        if op == "$ne":  # Eşit değil operatörü ($ne: "")
                            if doc_val == target:  # Eşitse şart bozulur
                                is_match = False  # Eşleşmedi
                        elif op == "$gt":  # Büyüktür operatörü ($gt: "")
                            if not (doc_val > target):  # Büyük değilse
                                is_match = False  # Eşleşmedi
                        elif op == "$regex":  # Düzenli ifade operatörü
                            if not re.search(str(target), str(doc_val)):  # Regex uymuyorsa
                                is_match = False  # Eşleşmedi
                        elif op == "$in":  # Liste içi kontrolü
                            if doc_val not in target:  # Listede yoksa
                                is_match = False  # Eşleşmedi
                        else:  # Bilinmeyen operatör
                            is_match = False  # Eşleşmedi
                else:  # Doğrudan eşitlik kontrolü
                    if doc_val != q_val:  # Değer uyuşmuyorsa
                        is_match = False  # Eşleşmedi
                        
            if is_match:  # Tüm şartlar sağlandıysa
                matched.append(copy.deepcopy(doc))  # Belge kopyası eklenir
                
        return matched  # Eşleşen belgeler döndürülür

    def secure_find(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        GÜVENLİ SORGU: Katı Tip Denetimi (Type Enforcement) ve BSON Sanitization uygular.
        Tüm $ operatörleri reddedilir; sorgu alanlarının kesinlikle ilkel (string, int) scalar tipte olması şart koşulur.
        """
        clean_query: Dict[str, Any] = {}  # Temiz sorgu kriterleri
        for key, val in query.items():  # Kriterler taranır
            # 1. $ ile başlayan operatör anahtarları reddedilir
            if isinstance(key, str) and key.startswith("$"):  # Operatör tespit edilirse
                raise ValueError(f"NoSQL operatör enjeksiyonu engellendi: '{key}'")  # İstisna fırlatılır
                
            # 1.1 Nokta notasyonu içeren nesne yolu manipülasyonu reddedilir
            if isinstance(key, str) and "." in key:  # Nokta tespit edilirse
                raise ValueError(f"NoSQL nokta notasyonu (path pollution) enjeksiyonu engellendi: '{key}'")  # İstisna fırlatılır
                
            # 2. Değerin nesne/sözlük olması engellenir (Yalnızca skaler tipler)
            if isinstance(val, dict):  # Değer sözlük ise ($ne vs.)
                raise ValueError(f"Sorgu alanında geçersiz karmaşık nesne/operatör tipi tespit edildi: '{key}'")  # İstisna
                
            # 3. Yalnızca temel tiplere izin verilir (str, int, float, bool)
            if not isinstance(val, (str, int, float, bool)):  # İlkel tip değilse
                raise ValueError(f"Desteklenmeyen veri tipi: '{type(val)}'")  # İstisna
                
            clean_query[key] = val  # Temiz skaler değer eklenir
            
        # Güvenli skaler eşleştirme yürütülür
        matched = []  # Eşleşenler
        for doc in self.documents:  # Belgeler taranır
            match_all = True  # Bayrak
            for ck, cv in clean_query.items():  # Kriterler
                if doc.get(ck) != cv:  # Eşleşmiyorsa
                    match_all = False  # İptal
                    break  # Döngü kırılır
            if match_all:  # Tam eşleştiyse
                matched.append(copy.deepcopy(doc))  # Eklenir
                
        return matched  # Sonuçlar döndürülür

    def vulnerable_update_user(self, user_id: int, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        ZAFİYETLİ GÜNCELLEME (Mass Assignment): Kullanıcıdan gelen tüm alanları filtresiz modele yazar.
        Saldırgan is_admin: True veya role: ADMIN göndererek yetkisini yükseltebilir.
        """
        for doc in self.documents:  # Belgeler taranır
            if doc["id"] == user_id:  # Hedef kullanıcı bulunduysa
                doc.update(payload)  # Gelen tüm payload doğrudan ezilerek atanır (ZAFİYET!)
                return True, copy.deepcopy(doc)  # Güncellenen belge döner
        return False, {}  # Bulunamadı

    def secure_update_user(self, user_id: int, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        GÜVENLİ GÜNCELLEME (DTO Allowlist): Yalnızca izin verilen alanların güncellenmesine müsaade eder.
        is_admin, role, balance gibi kritik alanlar sessizce budanır veya reddedilir.
        """
        ALLOWED_UPDATE_FIELDS: Set[str] = {"full_name", "email"}  # Yalnızca profil alanları güncellenebilir
        
        # Payload filtrelenir
        sanitized_patch: Dict[str, Any] = {}  # Temiz veri sözlüğü
        for k, v in payload.items():  # Alanlar taranır
            if k in ALLOWED_UPDATE_FIELDS:  # İzinli alansa
                sanitized_patch[k] = v  # Temiz listeye alınır
                
        for doc in self.documents:  # Belgeler taranır
            if doc["id"] == user_id:  # Hedef kullanıcı
                doc.update(sanitized_patch)  # Yalnızca güvenli alanlar güncellenir
                return True, copy.deepcopy(doc)  # Güncel belge döner
        return False, {}  # Bulunamadı


class NoSQLORMDefenseEngine:
    """Tüm NoSQLi ve ORM güvenlik analizlerini koordine eden merkezi motor."""

    def __init__(self):
        self.detector = NoSQLThreatDetector()  # Tehdit dedektörü başlatılır
        self.collection = MockNoSQLCollection()  # Test koleksiyonu başlatılır

    def inspect_and_test_nosqli(self, query_payload: Dict[str, Any]) -> Dict[str, Any]:
        """NoSQL sorgusunu tarar, zafiyetli ve güvenli arama sonuçlarını karşılaştırır."""
        # 1. Tehdit taraması
        findings = self.detector.scan_query_dict(query_payload)  # Sorgu taranır
        is_threat = len(findings) > 0  # Tehdit var mı
        
        # 2. Zafiyetli Yürütme Simülasyonu
        v_results = self.collection.vulnerable_find(query_payload)  # Zafiyetli find çağrısı
        v_bypassed = len(v_results) > 0 and is_threat  # Operatör ile kayıt çekilebildi mi
        
        # 3. Güvenli Yürütme Simülasyonu
        s_results: List[Dict[str, Any]] = []  # Güvenli sonuç listesi
        s_blocked = False  # Engellenme durumu
        s_error: Optional[str] = None  # Güvenlik hata mesajı
        try:  # Güvenli çalıştırma denenir
            s_results = self.collection.secure_find(query_payload)  # Katı tip denetimli çağrı
        except ValueError as e:  # Operatör yakalandığında
            s_blocked = True  # Başarıyla engellendi
            s_error = str(e)  # Hata mesajı kaydedilir
            
        return {
            "is_threat_detected": is_threat,  # Tehdit tespiti
            "findings_count": len(findings),  # Bulgu adedi
            "findings": [f.to_dict() for f in findings],  # Bulgular
            "vulnerable_execution": {  # Zafiyetli yürütme
                "records_matched": len(v_results),  # Çekilen kayıt sayısı
                "authentication_bypassed": v_bypassed,  # Bypass durumu
                "data_preview": v_results[:2]  # Önizleme
            },
            "secure_execution": {  # Güvenli yürütme
                "blocked_by_sanitizer": s_blocked,  # Temizleyici tarafından engellendi mi
                "sanitizer_error": s_error,  # Hata mesajı
                "records_matched": len(s_results)  # Dönen kayıt adedi
            }
        }

    def inspect_and_test_mass_assignment(self, user_id: int, update_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Kütlesel atama (Mass Assignment) tehditlerini analiz eder ve güvenli DTO'yu uygular."""
        findings = self.detector.scan_mass_assignment(update_payload)  # Kütlesel atama taranır
        
        # Zafiyetli test
        v_col = MockNoSQLCollection()  # Ayrı koleksiyon örneği
        _, v_updated = v_col.vulnerable_update_user(user_id, update_payload)  # Zafiyetli güncelleme
        
        # Güvenli test
        s_col = MockNoSQLCollection()  # Ayrı koleksiyon örneği
        _, s_updated = s_col.secure_update_user(user_id, update_payload)  # Güvenli güncelleme
        
        return {
            "mass_assignment_detected": len(findings) > 0,  # Tehdit tespiti
            "findings": [f.to_dict() for f in findings],  # Bulgular
            "vulnerable_doc_after_update": v_updated,  # Zafiyetli sonuç (is_admin ezildi)
            "secure_doc_after_update": s_updated  # Güvenli sonuç (is_admin korundu)
        }
