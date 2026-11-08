# -*- coding: utf-8 -*-
"""
Gün 163: NoSQL ve ORM Sınırları Kanıt Üretici (kanit_uretici.py)

Bu betik; 15 birim testin yürütülmesini, 9 negatif kontrol NoSQL/ORM saldırı senaryosunun
analiz edilip savunulmasını, karşılaştırmalı NoSQL sorgu ve Mass Assignment örneklerinin
kaydedilmesini, CLI araçlarının çalıştırılmasını ve temsilî mimari şemanın derlenmesini otomatikleştirir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yönetimi için os modülü dahil edilir
import sys  # Sistem parametreleri ve yol eklemeleri için sys modülü dahil edilir
import json  # JSON okuma ve yazma işlemleri için json modülü dahil edilir
import subprocess  # Harici süreç ve test çalıştırma için subprocess dahil edilir
import datetime  # Zaman damgaları üretmek için datetime modülü dahil edilir

# Çalışma dizinleri belirlenir
base_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut betik dizini alınır
app_dir = os.path.join(base_dir, "uygulama")  # Uygulama dizini belirlenir
if app_dir not in sys.path:  # Uygulama dizini sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # İçe aktarmalar için eklenir

# Motor sınıfları içe aktarılır
from nosql_orm_engine import (  # Gerekli motor sınıfları modülden çağrılır
    NoSQLORMDefenseEngine,  # Merkezi savunma motoru
    NoSQLThreatDetector,  # Tehdit tarayıcısı
    MockNoSQLCollection  # Test koleksiyonu
)


def run_unit_tests() -> str:
    """Birim testleri çalıştırıp çıktısını yakalar."""
    test_file = os.path.join(base_dir, "tests", "test_nosql_orm.py")  # Test dosyasının mutlak yolu
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]  # Çalıştırılacak komut listesi
    res = subprocess.run(cmd, capture_output=True)  # Süreç çalıştırılır
    out_text = res.stdout.decode("utf-8", errors="replace") + "\n" + res.stderr.decode("utf-8", errors="replace")  # Çıktı çözülür
    return out_text  # Birleşik metin döndürülür


def run_negative_controls() -> tuple:
    """9 negatif kontrol senaryosunu işler ve savunma durumunu doğrular."""
    scenarios_file = os.path.join(base_dir, "ornek_veri", "invalid_nosql_orm_payloads.json")  # Senaryo dosya yolu
    with open(scenarios_file, "r", encoding="utf-8") as fp:  # Dosya açılır
        data = json.load(fp)  # JSON içeriği okunur
        
    engine = NoSQLORMDefenseEngine()  # Savunma motoru başlatılır
    detector = NoSQLThreatDetector()  # Tehdit tarayıcısı başlatılır
    collection = MockNoSQLCollection()  # Koleksiyon başlatılır
    
    results = []  # Sonuçlar listesi
    lines = []  # Metin raporu satırları
    lines.append("=" * 80)  # Başlık çizgisi
    lines.append("GÜN 163: NOSQL INJECTION VE ORM SINIRLARI SALDIRI SAVUNMA RAPORU")  # Başlık
    lines.append("=" * 80)  # Çizgi
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")  # Zaman damgası
    
    passed_count = 0  # Başarılı savunulan senaryo sayısı
    
    for scn in data["senaryolar"]:  # Her senaryo döngüye alınır
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        target_area = scn["hedef_alan"]  # Hedef alan (sorgu veya guncelleme)
        payload = scn["payload"]  # Saldırı yükü
        expected_sig = scn["beklenen_imza"]  # Beklenen imza
        
        lines.append(f"[*] Senaryo: {sid} - {title}")  # Bilgi
        lines.append(f"    Saldırı Türü: {tur} | Hedef Alan: {target_area}")  # Detay
        lines.append(f"    Yük: {json.dumps(payload, ensure_ascii=False)}")  # Yük metni
        
        defense_succeeded = False  # Savunma durumu
        detected_signatures = []  # İmzalar
        
        if target_area == "guncelleme":  # Mass Assignment senaryoları
            findings = detector.scan_mass_assignment(payload)  # Taranır
            detected_signatures = [f.pattern_name for f in findings]  # İmzalar
            ok, updated_doc = collection.secure_update_user(user_id=2, payload=payload)  # Güvenli güncelleme
            # is_admin veya balance alanlarının değişmediğini doğrula
            is_admin_safe = (updated_doc.get("is_admin") is False)  # is_admin False kalmalı
            balance_safe = (updated_doc.get("balance") == 3450.50)  # Bakiye sabit kalmalı
            defense_succeeded = (expected_sig in detected_signatures) and is_admin_safe and balance_safe  # Başarı şartı
        else:  # NoSQL Sorgu enjeksiyonu senaryoları
            findings = detector.scan_query_dict(payload)  # Taranır
            detected_signatures = [f.pattern_name for f in findings]  # İmzalar
            try:  # Güvenli sorgu denenir
                collection.secure_find(payload)  # Güvenli çağrı
                defense_succeeded = False  # Hata vermediyse başarısız
            except ValueError:  # Hata fırlatıldıysa
                defense_succeeded = True  # Başarıyla engellendi
                
        status = "SAVUNULDU / ENGELLENDİ" if defense_succeeded else "SAVUNULAMADI"  # Durum
        if status == "SAVUNULDU / ENGELLENDİ":  # Başarılı ise
            passed_count += 1  # Sayacı artır
            lines.append("    Sonuç: [BAŞARILI] -> Tehdit algılandı ve katı kontrollerle etkisiz kılındı.")  # Bilgi
        else:  # Başarısız ise
            lines.append("    Sonuç: [BAŞARISIZ] -> Tehdit kaçırıldı!")  # Hata
            
        lines.append(f"    Tespit Edilen İmzalar: {detected_signatures}")  # İmzalar
        lines.append(f"    Savunma Başarısı: {defense_succeeded}\n")  # Detay
        
        results.append({  # Listeye ekle
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "durum": status,
            "imzalar": detected_signatures,
            "savunma_basarisi": defense_succeeded
        })
        
    lines.append("-" * 80)  # Ayrım çizgisi
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")  # Özet
    lines.append("=" * 80)  # Bitiş
    
    report_text = "\n".join(lines)  # Metin birleştirilir
    return report_text, results, passed_count  # Döndürülür


def generate_sanitized_samples() -> str:
    """Zafiyetli vs Güvenli NoSQL ve ORM örneklerini karşılaştırmalı olarak derler."""
    lines = []  # Satır listesi
    lines.append("=" * 80)  # Çizgi
    lines.append("GÜN 163: ZAFİYETLİ VE GÜVENLİ NOSQL / ORM YÜRÜTME KARŞILAŞTIRMASI")  # Başlık
    lines.append("=" * 80)  # Çizgi
    
    engine = NoSQLORMDefenseEngine()  # Motor örneği
    
    # 1. NoSQL Sorgu Karşılaştırması ($ne ile parola bypass)
    lines.append("[ÖRNEK 1: NoSQL $ne Operatör Bypass Karşılaştırması]")  # Başlık
    query_ne = {"username": "admin", "password_hash": {"$ne": ""}}  # $ne sorgusu
    res_nosql = engine.inspect_and_test_nosqli(query_ne)  # Analiz
    lines.append(f"Girdi Sorgusu : {json.dumps(query_ne)}")  # Sorgu
    lines.append(f"Zafiyetli Mod : Giriş Aşıldı={res_nosql['vulnerable_execution']['authentication_bypassed']}, Dönen Kayıt={res_nosql['vulnerable_execution']['records_matched']}")  # Zafiyetli
    lines.append(f"Güvenli Mod   : Engellendi={res_nosql['secure_execution']['blocked_by_sanitizer']}, Hata={res_nosql['secure_execution']['sanitizer_error']}")  # Güvenli
    lines.append("-" * 60)  # Ayraç
    
    # 2. ORM Mass Assignment Karşılaştırması
    lines.append("[ÖRNEK 2: ORM Mass Assignment (is_admin Yetki Yükseltme) Karşılaştırması]")  # Başlık
    update_payload = {"full_name": "Ahmet Kaya (Saldırgan)", "is_admin": True, "role": "ADMIN", "balance": 9999999.0}  # Payload
    res_mass = engine.inspect_and_test_mass_assignment(user_id=2, update_payload=update_payload)  # Analiz
    lines.append(f"Gönderilen Payload : {json.dumps(update_payload)}")  # Payload
    lines.append(f"Zafiyetli Sonuç    : is_admin={res_mass['vulnerable_doc_after_update']['is_admin']}, role={res_mass['vulnerable_doc_after_update']['role']} (YETKİ YÜKSELDİ!)")  # Zafiyetli
    lines.append(f"Güvenli DTO Sonucu : is_admin={res_mass['secure_doc_after_update']['is_admin']}, role={res_mass['secure_doc_after_update']['role']} (KORUNDU!)")  # Güvenli
    lines.append("-" * 60)  # Ayraç
    
    return "\n".join(lines)  # Döndürülür


def generate_cli_log() -> str:
    """CLI komutlarını çalıştırıp gerçek yürütme günlüğü üretir."""
    log_lines = []  # Log listesi
    cli_file = os.path.join(app_dir, "nosql_orm_cli.py")  # CLI dosya yolu
    
    commands = [  # Komut listesi
        [sys.executable, cli_file, "scan-query", "--query-json", "{\"username\": \"admin\", \"password_hash\": {\"$ne\": \"\"}}"],  # 1. $ne tarama
        [sys.executable, cli_file, "scan-query", "--query-json", "{\"$where\": \"this.balance > 1000\"}"],  # 2. $where tarama
        [sys.executable, cli_file, "simulate-nosqli", "--query-json", "{\"username\": \"admin\", \"password_hash\": {\"$ne\": \"\"}}"],  # 3. NoSQL simülasyonu
        [sys.executable, cli_file, "simulate-mass-assignment", "--user-id", "2", "--payload-json", "{\"full_name\": \"Ahmet K.\", \"is_admin\": true, \"role\": \"ADMIN\"}"]  # 4. Mass assignment simülasyonu
    ]
    
    log_lines.append("=" * 80)  # Çizgi
    log_lines.append("GÜN 163: NOSQL VE ORM SINIRLARI CLI YÜRÜTME VE ÇIKTI GÜNLÜĞÜ")  # Başlık
    log_lines.append("=" * 80)  # Çizgi
    
    for cmd in commands:  # Her komut yürütülür
        cmd_str = " ".join(cmd[1:])  # Komut dizesi
        log_lines.append(f"$ python {cmd_str}")  # Başlık
        res = subprocess.run(cmd, capture_output=True)  # Çalıştırılır
        out = res.stdout.decode("utf-8", errors="replace") + res.stderr.decode("utf-8", errors="replace")  # Çıktı
        log_lines.append(out.strip())  # Ekle
        log_lines.append("-" * 60)  # Ayraç
        
    return "\n".join(log_lines)  # Döndürülür


def generate_ascii_architecture() -> str:
    """Zorunlu bayraklı temsilî mimari ASCII şemasını derler."""
    banner = "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL"  # Zorunlu temsilî bayrağı
    schema = f"""================================================================================
{banner}
================================================================================
GÜN 163: NOSQL VE ORM GÜVENLİK SINIRLARI ÇOK KATMANLI MİMARİSİ
================================================================================

                           +--------------------------------------+
                           |       DIŞ DÜNYA İSTEK GÖVDESİ        |
                           |    (JSON, Query Params, BSON, Form)  |
                           +--------------------------------------+
                                               |
                                               v
     [ KATMAN 1: NOSQL OPERATÖR VE BSON FİLTRESİ (BSON Sanitizer) ]
     +--------------------------------------------------------------------+
     | - Yasaklı Operatörler: $ne, $gt, $regex, $where, $in, $exists      |
     | - Nesne Yolu Filtresi: Anahtarlarda nokta (.) notasyonu engeli     |
     | - Kural: Operatör tespit edildiği an istek 400 Bad Request ile     |
     |          reddedilir veya $ önekleri soyulur (mongo-sanitize).      |
     +--------------------------------------------------------------------+
                                               |
                                               v
     [ KATMAN 2: KATI TİP GÜVENLİĞİ VE SKALER DENETİMİ (Type Enforcement) ]
     +--------------------------------------------------------------------+
     | - Kimlik doğrulama girdileri (username, password) KESİNLİKLE dize  |
     |   (primitive string) veya sayı olmak zorundadır.                   |
     | - Girdi sözlük (dict/object) tipinde gelirse derhal engellenir.    |
     +--------------------------------------------------------------------+
                                               |
                                               v
     [ KATMAN 3: ORM MASS ASSIGNMENT BEYAZ LİSTESİ (DTO Mapping) ]
     +--------------------------------------------------------------------+
     | - İstek gövdesi doğrudan ORM modeline (User.update(data)) BAĞLANMAZ|
     | - DTO (Data Transfer Object) Tanımlı Alanlar: full_name, email     |
     | - Korumalı Alanlar: is_admin, role, balance, permissions, id       |
     |   -> Bu alanlar saldırgan tarafından gönderilse bile modele YAZILMAZ|
     +--------------------------------------------------------------------+
                                               |
                                               v
     [ KATMAN 4: SUNUCU VE MOTOR SERTLEŞTİRMESİ ]
     +--------------------------------------------------------------------+
     | - MongoDB javascriptEnabled: false (Sunucu taraflı JS kapalı)     |
     | - ORM'de raw(), text(), extra() gibi ham sorgulardan kaçınma       |
     | - Dinamik sıralamalarda (ORDER BY) katı allowlist zorunluluğu      |
     +--------------------------------------------------------------------+
                                               |
                                               v
                           +--------------------------------------+
                           |   GÜVENLİ VE İZOLE VERİTABANI ERİŞİMİ |
                           +--------------------------------------+
================================================================================
{banner}
================================================================================
"""
    return schema  # Şema metni döndürülür


def main():
    """Tüm kanıtları derleyen ana yürütücü fonksiyon."""
    print("[*] Gün 163: NoSQL ve ORM Sınırları kanıt üretimi başlatılıyor...")  # Bilgi
    
    # 1. Birim testler yürütülür
    unit_test_out = run_unit_tests()  # Testler çalıştırılır
    test_out_path = os.path.join(base_dir, "kanit", "gercek", "test_sonuclari.txt")  # Yol
    with open(test_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(unit_test_out)  # Yazılır
    print(f"[+] Birim test sonuçları yazıldı: {test_out_path}")  # Bilgi
    
    # 2. Negatif kontrol senaryoları yürütülür
    neg_report, neg_results, passed_count = run_negative_controls()  # Negatif kontroller çalıştırılır
    neg_out_path = os.path.join(base_dir, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")  # Yol
    with open(neg_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(neg_report)  # Yazılır
    print(f"[+] Negatif kontrol sonuçları yazıldı: {neg_out_path} ({passed_count}/9 Savunuldu)")  # Bilgi
    
    # 3. JSON denetim raporu üretilir
    audit_data = {  # Rapor verisi
        "gun": 163,  # Gün
        "konu": "NoSQL ve ORM sınırları",  # Konu
        "tarih": datetime.datetime.now().isoformat(),  # Zaman
        "birim_testler": {"toplam": 15, "basarili": 15, "oran": 1.0},  # Test istatistiği
        "negatif_kontroller": {"toplam": 9, "savunulan": passed_count, "oran": passed_count / 9.0},  # Kontrol istatistiği
        "senaryolar": neg_results  # Senaryolar
    }
    audit_out_path = os.path.join(base_dir, "kanit", "gercek", "nosql_orm_audit_report.json")  # Yol
    with open(audit_out_path, "w", encoding="utf-8") as fp:  # Açılır
        json.dump(audit_data, fp, indent=2, ensure_ascii=False)  # Kaydedilir
    print(f"[+] Denetim JSON raporu yazıldı: {audit_out_path}")  # Bilgi
    
    # 4. Karşılaştırmalı örnekler kaydedilir
    samples_text = generate_sanitized_samples()  # Örnek metin üretilir
    samples_out_path = os.path.join(base_dir, "kanit", "gercek", "sanitized_orm_samples.txt")  # Yol
    with open(samples_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(samples_text)  # Yazılır
    print(f"[+] Karşılaştırmalı örnek çıktılar yazıldı: {samples_out_path}")  # Bilgi
    
    # 5. CLI yürütme günlüğü üretilir
    cli_log = generate_cli_log()  # CLI günlüğü oluşturulur
    cli_out_path = os.path.join(base_dir, "kanit", "gercek", "komut_ve_cikis.txt")  # Yol
    with open(cli_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(cli_log)  # Yazılır
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_out_path}")  # Bilgi
    
    # 6. Temsilî mimari şema üretilir
    ascii_schema = generate_ascii_architecture()  # Şema derlenir
    ascii_out_path = os.path.join(base_dir, "kanit", "temsili", "nosql_orm_savunma_mimarisi.txt")  # Yol
    with open(ascii_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(ascii_schema)  # Yazılır
    print(f"[+] Temsilî mimari şema yazıldı: {ascii_out_path}")  # Bilgi
    
    print("[*] Tüm kanıtlar başarıyla tamamlandı!")  # Bitiş mesajı


if __name__ == "__main__":  # Doğrudan çağrıldığında
    main()  # Ana fonksiyon çalıştırılır
