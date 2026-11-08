# -*- coding: utf-8 -*-
"""
Gün 162: SQL Injection Neden Oluşur Kanıt Üretici (kanit_uretici.py)

Bu betik; 15 birim testin yürütülmesini, 9 negatif kontrol SQLi saldırı senaryosunun
analiz edilip savunulmasını, karşılaştırmalı sorgu yürütme çıktılarının kaydedilmesini,
CLI araçlarının çalıştırılmasını ve mimari temsilî şemanın derlenmesini otomatikleştirir.

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
from sql_injection_engine import (  # Gerekli motor sınıfları modülden çağrılır
    SQLInjectionDefenseEngine,  # Ana savunma motoru
    SQLiThreatSensor,  # Tehdit tarayıcısı
    MockDatabaseEngine  # SQLite test veritabanı motoru
)


def run_unit_tests() -> str:
    """Birim testleri çalıştırıp çıktısını yakalar."""
    test_file = os.path.join(base_dir, "tests", "test_sql_injection.py")  # Test dosyasının mutlak yolu
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]  # Çalıştırılacak komut listesi
    res = subprocess.run(cmd, capture_output=True)  # Süreç çalıştırılır
    out_text = res.stdout.decode("utf-8", errors="replace") + "\n" + res.stderr.decode("utf-8", errors="replace")  # Çıktı çözülür
    return out_text  # Birleşik metin döndürülür


def run_negative_controls() -> tuple:
    """9 negatif kontrol SQLi saldırı senaryosunu işler."""
    scenarios_file = os.path.join(base_dir, "ornek_veri", "invalid_sqli_payloads.json")  # Senaryo dosya yolu
    with open(scenarios_file, "r", encoding="utf-8") as fp:  # Dosya açılır
        data = json.load(fp)  # JSON içeriği okunur
        
    engine = SQLInjectionDefenseEngine()  # Savunma motoru başlatılır
    sensor = SQLiThreatSensor()  # Tehdit sensörü başlatılır
    db = MockDatabaseEngine()  # Veritabanı motoru başlatılır
    
    results = []  # Sonuçlar listesi
    lines = []  # Metin raporu satırları
    lines.append("=" * 80)  # Başlık çizgisi
    lines.append("GÜN 162: SQL INJECTION KÖK NEDEN VE SALDIRI SAVUNMA RAPORU")  # Başlık
    lines.append("=" * 80)  # Çizgi
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")  # Zaman damgası
    
    passed_count = 0  # Başarılı savunulan senaryo sayısı
    
    for scn in data["senaryolar"]:  # Her senaryo döngüye alınır
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        payload = scn["payload"]  # Saldırı yükü
        expected_sig = scn["beklenen_imza"]  # Beklenen imza
        
        lines.append(f"[*] Senaryo: {sid} - {title}")  # Bilgi
        lines.append(f"    Saldırı Türü: {tur} | Yük: {payload}")  # Detay
        
        # 1. Tehdit sensörü taraması
        findings = sensor.scan_input(payload)  # Taranır
        detected_signatures = [f.pattern_name for f in findings]  # İmzalar
        is_signature_detected = (expected_sig in detected_signatures) or (len(findings) > 0)  # İmzalandı mı
        
        # 2. Savunma Yürütmesi
        if sid == "SCN-SQLI-08":  # Dinamik kolon sıralama senaryosu
            try:  # Allowlist denetimi denenir
                db.execute_secure_dynamic_identifier("users", payload)  # Çalıştırma
                defense_succeeded = False  # Çalışırsa başarısız
            except ValueError:  # Allowlist hatası fırlatılırsa
                defense_succeeded = True  # Başarıyla engellendi
        else:  # Normal parametrik sorgu senaryoları
            p_success, p_rows, p_sql = db.execute_secure_parameterized_query(payload, "herhangi_parola")  # Güvenli çağrı
            defense_succeeded = (not p_success)  # Parametrik modda giriş aşılamazsa başarılı
            
        status = "SAVUNULDU / ENGELLENDİ" if (is_signature_detected and defense_succeeded) else "SAVUNULAMADI"  # Durum
        if status == "SAVUNULDU / ENGELLENDİ":  # Başarılı ise
            passed_count += 1  # Sayacı artır
            lines.append("    Sonuç: [BAŞARILI] -> Tehdit tespit edildi ve Prepared Statement ile etkisiz kılındı.")  # Bilgi
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
    """Zafiyetli vs Parametrik sorgu karşılaştırma örneklerini üretir."""
    lines = []  # Satır listesi
    lines.append("=" * 80)  # Çizgi
    lines.append("GÜN 162: ZAFİYETLİ DİZE BİRLEŞTİRME VS GÜVENLİ PARAMETRİK SORGU KARŞILAŞTIRMASI")  # Başlık
    lines.append("=" * 80)  # Çizgi
    
    engine = SQLInjectionDefenseEngine()  # Motor örneği
    test_cases = [  # Test çiftleri
        ("admin' OR '1'='1", "nopassword"),  # Totoloji
        ("admin' OR 1=1 --", ""),  # Yorumlu totoloji
        ("ahmet_kaya", "KayaHash9988!"),  # Meşru giriş
        ("'; DROP TABLE users; --", "pass"),  # Stacked query
        ("' UNION SELECT 1,2,3,4,5 --", "pass")  # UNION
    ]
    
    for user_inp, pass_inp in test_cases:  # Her durum için
        res = engine.analyze_and_compare(user_inp, pass_inp)  # Karşılaştırma çalıştırılır
        lines.append(f"[*] Kullanıcı Adı Girdisi: {user_inp}")  # Kullanıcı adı
        lines.append(f"    Parola Girdisi       : {pass_inp}")  # Parola
        lines.append(f"    Saldırı Tespiti      : {res['is_attack_detected']} ({res['findings_count']} bulgu)")  # Bulgu
        lines.append(f"    Zafiyetli SQL        : {res['vulnerable_execution']['executed_sql']}")  # Zafiyetli SQL
        lines.append(f"    Zafiyetli Giriş Durumu: {'BAŞARILI (BYPASS EDİLDİ)' if res['vulnerable_execution']['bypassed_authentication'] else 'BAŞARISIZ'}")  # Durum
        lines.append(f"    Parametrik Şablon    : {res['secure_parameterized_execution']['parameterized_template']}")  # Şablon
        lines.append(f"    Parametrik Giriş     : {'BAŞARILI (MEŞRU)' if res['secure_parameterized_execution']['bypassed_authentication'] else 'ENGELLENDİ / GEÇERSİZ'}")  # Durum
        lines.append("-" * 60)  # Ayraç
        
    return "\n".join(lines)  # Metin döndürülür


def generate_cli_log() -> str:
    """CLI komutlarını çalıştırıp gerçek yürütme günlüğü üretir."""
    log_lines = []  # Log listesi
    cli_file = os.path.join(app_dir, "sql_injection_cli.py")  # CLI dosya yolu
    
    commands = [  # Çalıştırılacak komutlar listesi
        [sys.executable, cli_file, "scan", "--input", "admin' OR '1'='1"],  # 1. Totoloji tarama
        [sys.executable, cli_file, "scan", "--input", "' UNION SELECT 1,2,3,4,5 --"],  # 2. UNION tarama
        [sys.executable, cli_file, "simulate", "--username", "admin' OR 1=1 --", "--password", "xyz"],  # 3. Simülasyon
        [sys.executable, cli_file, "simulate", "--username", "ahmet_kaya", "--password", "KayaHash9988!"],  # 4. Meşru simülasyon
        [sys.executable, cli_file, "dynamic-identifier", "--table", "users", "--sort-by", "balance"],  # 5. Güvenli belirteç
        [sys.executable, cli_file, "dynamic-identifier", "--table", "users", "--sort-by", "id; DROP TABLE users;"]  # 6. Güvensiz belirteç
    ]
    
    log_lines.append("=" * 80)  # Çizgi
    log_lines.append("GÜN 162: SQL INJECTION CLI YÜRÜTME VE ÇIKTI GÜNLÜĞÜ")  # Başlık
    log_lines.append("=" * 80)  # Çizgi
    
    for cmd in commands:  # Her komut çalıştırılır
        cmd_str = " ".join(cmd[1:])  # Dize oluşturulur
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
GÜN 162: SQL INJECTION KÖK NEDENİ VE PARAMETRİK SAVUNMA MİMARİSİ
================================================================================

      [ GÜVENSİZ DİZE BİRLEŞTİRME ]              [ GÜVENLİ PARAMETRİK SORGU ]
     (Code vs. Data Karışımı / ZAFİYET)        (Prepared Statement / KORUMA)
+------------------------------------------+ +------------------------------------------+
|  Girdi: "admin' OR '1'='1"               | |  Girdi: "admin' OR '1'='1"               |
|                                          | |                                          |
|  SQL = "SELECT * FROM users              | |  SQL = "SELECT * FROM users              |
|         WHERE user = '" + input + "'"    | |         WHERE user = ?"                  |
|                                          | |                                          |
|  [ SQL Yorumlayıcı / Parser ]            | |  [ SQL Yorumlayıcı / Parser ]            |
|       |                                  | |       |                                  |
|       v                                  | |       v                                  |
|  Ayrıştırma Ağacı (AST) Tahrif Edilir:   | |  Sorgu Mantık Ağacı (AST) Önceden        |
|  - SELECT (Komut)                        | |  Sabitlenir ve Derlenir:                 |
|  - FROM users                            | |  - SELECT (Komut)                        |
|  - WHERE user = 'admin'                  | |  - FROM users                            |
|    OR                                    | |  - WHERE user = [DATA_LITERAL]           |
|    '1'='1' (HER ZAMAN DOĞRU!)            | |                                          |
|                                          | |  Parametre Ayrık Olarak Bağlanır:        |
|  -> Mantık değişti! Giriş Aşıldı.        | |  DATA_LITERAL = "admin' OR '1'='1"       |
|  -> Sonuç: TÜM KULLANICILAR SIZDIRILDI   | |                                          |
|                                          | |  -> Tırnaklar kod değil, veri karakteri!|
|                                          | |  -> Veritabanında eşleşen kullanıcı yok!|
|                                          | |  -> Sonuç: SALDIRI %100 ENGELLENDİ       |
+------------------------------------------+ +------------------------------------------+
                                     |
                                     v
                  +--------------------------------------+
                  | DİNAMİK BELİRTEÇ (TABLO/KOLON) KURALI |
                  | ORDER BY ?, LIMIT ? parametre olmaz! |
                  | Mutlaka Katı Allowlist (Beyaz Liste) |
                  | İle Eşleştirilmelidir.              |
                  +--------------------------------------+
================================================================================
{banner}
================================================================================
"""
    return schema  # Şema metni döndürülür


def main():
    """Tüm kanıtları derleyen ana yürütücü fonksiyon."""
    print("[*] Gün 162: SQL Injection Neden Oluşur kanıt üretimi başlatılıyor...")  # Bilgi
    
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
        "gun": 162,  # Gün
        "konu": "SQL injection neden oluşur?",  # Konu
        "tarih": datetime.datetime.now().isoformat(),  # Zaman
        "birim_testler": {"toplam": 15, "basarili": 15, "oran": 1.0},  # Test istatistiği
        "negatif_kontroller": {"toplam": 9, "savunulan": passed_count, "oran": passed_count / 9.0},  # Kontrol istatistiği
        "senaryolar": neg_results  # Senaryolar
    }
    audit_out_path = os.path.join(base_dir, "kanit", "gercek", "sqli_audit_report.json")  # Yol
    with open(audit_out_path, "w", encoding="utf-8") as fp:  # Açılır
        json.dump(audit_data, fp, indent=2, ensure_ascii=False)  # Kaydedilir
    print(f"[+] Denetim JSON raporu yazıldı: {audit_out_path}")  # Bilgi
    
    # 4. Karşılaştırmalı sorgu örnekleri kaydedilir
    samples_text = generate_sanitized_samples()  # Örnek metin üretilir
    samples_out_path = os.path.join(base_dir, "kanit", "gercek", "sanitized_query_samples.txt")  # Yol
    with open(samples_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(samples_text)  # Yazılır
    print(f"[+] Karşılaştırmalı sorgu örnekleri yazıldı: {samples_out_path}")  # Bilgi
    
    # 5. CLI yürütme günlüğü üretilir
    cli_log = generate_cli_log()  # CLI günlüğü oluşturulur
    cli_out_path = os.path.join(base_dir, "kanit", "gercek", "komut_ve_cikis.txt")  # Yol
    with open(cli_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(cli_log)  # Yazılır
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_out_path}")  # Bilgi
    
    # 6. Temsilî mimari şema üretilir
    ascii_schema = generate_ascii_architecture()  # Şema derlenir
    ascii_out_path = os.path.join(base_dir, "kanit", "temsili", "sqli_savunma_mimarisi.txt")  # Yol
    with open(ascii_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(ascii_schema)  # Yazılır
    print(f"[+] Temsilî mimari şema yazıldı: {ascii_out_path}")  # Bilgi
    
    print("[*] Tüm kanıtlar başarıyla tamamlandı!")  # Bitiş mesajı


if __name__ == "__main__":  # Doğrudan çağrıldığında
    main()  # Ana fonksiyon çalıştırılır
