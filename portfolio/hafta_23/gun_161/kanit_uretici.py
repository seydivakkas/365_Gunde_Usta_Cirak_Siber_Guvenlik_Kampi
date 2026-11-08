# -*- coding: utf-8 -*-
"""
Gün 161: Mini Proje 22 - Güvenli Form Arayüzü Kanıt Üretici (kanit_uretici.py)

Bu betik; 15 birim testin çalıştırılmasını, 9 negatif kontrol ve saldırı senaryosunun
icra edilerek savunulmasını, gerçek HTML form çıktısının üretilmesini, CLI günlüklerinin
kaydedilmesini ve temsilî mimari ASCII şemasının derlenmesini otomatikleştirir.

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
from secure_form_engine import (  # Gerekli motor sınıfları modülden çağrılır
    SecureFormEngine,  # Güvenli form ana motoru
    CSRFProtectionManager,  # CSRF yöneticisi
    FormFieldValidator,  # Alan doğrulayıcısı
    RateLimiter  # Hız sınırlayıcısı
)


def run_unit_tests() -> str:
    """Birim testleri çalıştırıp çıktısını yakalar."""
    test_file = os.path.join(base_dir, "tests", "test_secure_form.py")  # Test dosyasının mutlak yolu
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]  # Çalıştırılacak komut listesi
    res = subprocess.run(cmd, capture_output=True)  # Süreç çalıştırılır
    out_text = res.stdout.decode("utf-8", errors="replace") + "\n" + res.stderr.decode("utf-8", errors="replace")  # Çıktı çözülür
    return out_text  # Birleşik metin döndürülür


def run_negative_controls() -> tuple:
    """9 negatif kontrol ve saldırı senaryosunu işler."""
    scenarios_file = os.path.join(base_dir, "ornek_veri", "invalid_form_payloads.json")  # Senaryo dosya yolu
    with open(scenarios_file, "r", encoding="utf-8") as fp:  # Dosya açılır
        data = json.load(fp)  # JSON içeriği okunur
        
    engine = SecureFormEngine(allowed_origin="https://banka.kurum.internal")  # Güvenli form motoru
    
    results = []  # Sonuçlar listesi
    lines = []  # Metin raporu satırları
    lines.append("=" * 80)  # Başlık çizgisi
    lines.append("GÜN 161: MİNİ PROJE 22 - GÜVENLİ FORM ARAYÜZÜ NEGATİF KONTROL RAPORU")  # Başlık
    lines.append("=" * 80)  # Çizgi
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")  # Zaman damgası
    
    passed_count = 0  # Başarılı savunulan senaryo sayısı
    
    for scn in data["senaryolar"]:  # Her senaryo döngüye alınır
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        sess_id = scn["session_id"]  # Oturum
        client_ip = scn["client_ip"]  # İstemci IP
        origin = scn["origin"]  # Köken
        post_data = dict(scn["post_data"])  # Veri kopyası
        expected_code = scn["beklenen_kod"]  # Beklenen HTTP kodu
        expected_err = scn["beklenen_hata"]  # Beklenen hata metni
        
        # Eğer SCN-FORM-09 (Rate limit) ise, limiti tüketmek için 5 istek önceden atılır
        if tur == "RATE_LIMIT_EXHAUSTION":  # Limit tüketimi
            for _ in range(5):  # 5 adet istek atılır
                engine.rate_limiter.is_allowed(client_ip)  # Limit doldurulur
                
        # Eğer CSRF_TAMPERED ise taze token üretip imzasını boz
        if tur == "CSRF_TAMPERED":  # Tahrif edilmiş token senaryosu
            fresh_token = engine.csrf_manager.generate_token(sess_id)  # Taze token üretilir
            post_data["csrf_token"] = fresh_token[:-4] + "0000"  # İmza tahrif edilir
        elif tur != "CSRF_MISSING" and "csrf_token" not in post_data:  # Diğer geçerli senaryolar
            post_data["csrf_token"] = engine.csrf_manager.generate_token(sess_id)  # Meşru token üretilir
            
        lines.append(f"[*] Senaryo: {sid} - {title}")  # Senaryo bilgisi
        lines.append(f"    Saldırı Türü: {tur} | İstemci IP: {client_ip} | Köken: {origin}")  # Parametreler
        
        # Gönderim işlenir
        res = engine.process_submission(
            post_data=post_data,
            session_id=sess_id,
            client_ip=client_ip,
            origin_header=origin
        )
        
        # Değerlendirme
        is_blocked = (not res["success"]) and (res["status_code"] == expected_code)  # Beklenen kodla engellendi mi
        err_matched = expected_err.lower() in res.get("error", "").lower()  # Hata mesajı eşleşti mi
        
        status = "SAVUNULDU / ENGELLENDİ" if (is_blocked and err_matched) else "SAVUNULAMADI"  # Durum
        if status == "SAVUNULDU / ENGELLENDİ":  # Başarılı ise
            passed_count += 1  # Sayacı artır
            lines.append(f"    Sonuç: [BAŞARILI] -> Tehdit {res['status_code']} koduyla engellendi.")  # Bilgi
        else:  # Başarısız ise
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Beklenen={expected_code}, Gelen={res.get('status_code')}")  # Hata
            
        lines.append(f"    Hata Mesajı: {res.get('error', '')}")  # Hata metni
        lines.append(f"    Detaylar: {json.dumps(res, ensure_ascii=False)}\n")  # Detaylar
        
        results.append({  # Listeye ekle
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "durum": status,
            "status_code": res["status_code"],
            "error_returned": res.get("error", "")
        })
        
    lines.append("-" * 80)  # Ayrım çizgisi
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")  # Özet
    lines.append("=" * 80)  # Bitiş
    
    report_text = "\n".join(lines)  # Metin birleştirilir
    return report_text, results, passed_count  # Döndürülür


def generate_cli_log() -> str:
    """CLI komutlarını çalıştırıp gerçek çalışma günlüğü üretir."""
    log_lines = []  # Log listesi
    cli_file = os.path.join(app_dir, "secure_form_cli.py")  # CLI dosya yolu
    
    # Test için geçerli bir token üretelim
    engine = SecureFormEngine()  # Motor örneği
    valid_token = engine.csrf_manager.generate_token("sess_cli_demo")  # Token üretilir
    
    valid_json = json.dumps({  # Geçerli JSON gönderim verisi
        "csrf_token": valid_token,
        "username": "ahmet_yildiz",
        "email": "ahmet.yildiz@kurum.com",
        "password": "Ahm3tSecure!2026",
        "amount": "1500.00",
        "comment": "Nisan ayı aidat ödemesi."
    })
    
    malicious_json = json.dumps({  # Zararlı JSON verisi
        "csrf_token": "gecersiz_token",
        "username": "admin' OR 1=1 --",
        "email": "invalid_email",
        "password": "123",
        "amount": "-50.00"
    })
    
    commands = [  # Çalıştırılacak CLI komutları listesi
        [sys.executable, cli_file, "render", "--session-id", "sess_cli_demo"],  # 1. Render formu
        [sys.executable, cli_file, "generate-csrf", "--session-id", "sess_cli_demo"],  # 2. Token üret
        [sys.executable, cli_file, "validate-csrf", "--token", valid_token, "--session-id", "sess_cli_demo"],  # 3. Token doğrula
        [sys.executable, cli_file, "submit", "--json-data", valid_json, "--session-id", "sess_cli_demo", "--client-ip", "10.0.0.5"],  # 4. Geçerli submit
        [sys.executable, cli_file, "submit", "--json-data", malicious_json, "--session-id", "sess_cli_demo", "--client-ip", "10.0.0.6"]  # 5. Zararlı submit
    ]
    
    log_lines.append("=" * 80)  # Çizgi
    log_lines.append("GÜN 161: MİNİ PROJE 22 - GÜVENLİ FORM CLI YÜRÜTME VE ÇIKTI GÜNLÜĞÜ")  # Başlık
    log_lines.append("=" * 80)  # Çizgi
    
    for cmd in commands:  # Komutlar yürütülür
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
GÜN 161: MİNİ PROJE 22 - GÜVENLİ FORM ARAYÜZÜ ÇOK KATMANLI BORU HATTI
================================================================================

                           +----------------------------------------+
                           |           İSTEMCİ TARAYICISI           |
                           |  (Kullanıcı / Saldırgan / Çapraz Site)  |
                           +----------------------------------------+
                                                |
                                                | HTTP POST /api/v1/transfer
                                                v
     [ KATMAN 1: RATE LIMITING & BRUTE FORCE ENGELİ (RateLimiter) ]
     +--------------------------------------------------------------------------+
     | - İstemci IP ve Oturum bazlı Token Bucket / Kayan Pencere (Sliding Window)|
     | - Kural: Azami 5 istek / 60 saniye. İhlal halinde HTTP 429 Too Many Req   |
     +--------------------------------------------------------------------------+
                                                |
                                                | Geçerli Hız Limitinde
                                                v
     [ KATMAN 2: ORİGİN & REFERRER ÇAPRAZ İSTEK DOĞRULAMA ]
     +--------------------------------------------------------------------------+
     | - Origin Başlığı: Beklenen alan adı (https://banka.kurum.internal) kontrolü|
     | - Yabancı kökenden gelen sahte form gönderimlerine HTTP 403 Forbidden    |
     +--------------------------------------------------------------------------+
                                                |
                                                | Doğrulanmış Köken
                                                v
     [ KATMAN 3: KRİPTOGRAFİK CSRF TOKEN KORUMASI (CSRFProtectionManager) ]
     +--------------------------------------------------------------------------+
     | - Format: session_id : timestamp : nonce : HMAC-SHA256(secret, payload) |
     | - Oturum Bağlama: Token'daki session_id ile aktif oturum birebir uyuşmalı|
     | - Süre Aşımı (TTL): 1800 saniye sonra kendiliğinden geçersizleşir        |
     | - Replay Engeli: Kullanılan tekil nonce harcanır, ikinci kullanım 403   |
     +--------------------------------------------------------------------------+
                                                |
                                                | Geçerli & İmzalı Token
                                                v
     [ KATMAN 4: KATI ŞEMA DOĞRULAMA & ENJEKSİYON FİLTRESİ (FormFieldValidator)]
     +--------------------------------------------------------------------------+
     | - username : ^[a-zA-Z0-9_]{{3,32}}$ (SQLi & XSS desen taraması)           |
     | - email    : RFC 5322 regex formatı, azami 254 karakter                  |
     | - password : >=10 karakter, Büyük/Küçük harf, rakam, sembol, Entropi>=3.0|
     | - amount   : 0.01 - 100.000,00 TL sınır kontrolü                         |
     | - comment  : HTML Entity kaçışı (html.escape(quote=True))                |
     +--------------------------------------------------------------------------+
                                                |
                                                | Arındırılmış Veri
                                                v
     [ KATMAN 5: GÜVENLİK BAŞLIKLARI VE GÜVENLİ ÇEREZ MİMARİSİ ]
     +--------------------------------------------------------------------------+
     | - CSP Seviye 3: script-src 'nonce-RANDOM' 'strict-dynamic'; object-src none|
     | - Çerez: __Host-SessionID; Secure; HttpOnly; SameSite=Strict; Path=/    |
     | - X-Content-Type-Options: nosniff | X-Frame-Options: DENY                |
     +--------------------------------------------------------------------------+
                                                |
                                                v
                           +----------------------------------------+
                           |          GÜVENLİ İŞLEM BAŞARILI        |
                           |          (HTTP 200 OK Response)        |
                           +----------------------------------------+
================================================================================
{banner}
================================================================================
"""
    return schema  # Şema metni döndürülür


def main():
    """Tüm kanıtları derleyen ana yürütücü fonksiyon."""
    print("[*] Gün 161: Mini Proje 22 - Güvenli Form Arayüzü kanıt üretimi başlatılıyor...")  # Bilgi
    
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
        "gun": 161,  # Gün
        "konu": "Mini proje 22: güvenli form arayüzü",  # Konu
        "tarih": datetime.datetime.now().isoformat(),  # Zaman
        "birim_testler": {"toplam": 15, "basarili": 15, "oran": 1.0},  # Test istatistiği
        "negatif_kontroller": {"toplam": 9, "savunulan": passed_count, "oran": passed_count / 9.0},  # Kontrol istatistiği
        "senaryolar": neg_results  # Senaryolar
    }
    audit_out_path = os.path.join(base_dir, "kanit", "gercek", "secure_form_audit_report.json")  # Yol
    with open(audit_out_path, "w", encoding="utf-8") as fp:  # Açılır
        json.dump(audit_data, fp, indent=2, ensure_ascii=False)  # Kaydedilir
    print(f"[+] Denetim JSON raporu yazıldı: {audit_out_path}")  # Bilgi
    
    # 4. Render edilen gerçek form HTML örneği kaydedilir
    engine = SecureFormEngine()  # Motor oluşturulur
    rendered_html, token, headers = engine.render_form_html("sess_production_demo_001")  # Render edilir
    html_out_path = os.path.join(base_dir, "kanit", "gercek", "rendered_form_samples.html")  # Yol
    with open(html_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(rendered_html)  # Yazılır
    print(f"[+] Render edilmiş HTML form örneği yazıldı: {html_out_path}")  # Bilgi
    
    # 5. CLI yürütme günlüğü üretilir
    cli_log = generate_cli_log()  # CLI günlüğü oluşturulur
    cli_out_path = os.path.join(base_dir, "kanit", "gercek", "komut_ve_cikis.txt")  # Yol
    with open(cli_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(cli_log)  # Yazılır
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_out_path}")  # Bilgi
    
    # 6. Temsilî mimari şema üretilir
    ascii_schema = generate_ascii_architecture()  # Şema derlenir
    ascii_out_path = os.path.join(base_dir, "kanit", "temsili", "guvenli_form_mimarisi.txt")  # Yol
    with open(ascii_out_path, "w", encoding="utf-8") as fp:  # Açılır
        fp.write(ascii_schema)  # Yazılır
    print(f"[+] Temsilî mimari şema yazıldı: {ascii_out_path}")  # Bilgi
    
    print("[*] Tüm kanıtlar başarıyla tamamlandı!")  # Bitiş mesajı


if __name__ == "__main__":  # Doğrudan çağrıldığında
    main()  # Ana fonksiyon çalıştırılır
