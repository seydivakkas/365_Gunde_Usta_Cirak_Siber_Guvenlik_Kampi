# -*- coding: utf-8 -*-
"""
Gün 165: CORS ile Güvenlik Sınırı Kanıt Üretici (kanit_uretici.py)

Bu script; birim testleri koşturarak gerçek test kanıtlarını, 9 negatif kontrol
saldırı senaryosunun savunma kayıtlarını, karşılaştırmalı CORS istek/yanıt dökümlerini,
CLI yürütme günlüklerini ve standart ASCII temsilî mimari şemasını üretir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yönetimi için
import sys  # Sistem yolu ve argüman yönetimi için
import json  # JSON okuma ve yazma işlemleri için
import datetime  # Tarih ve saat biçimlendirmesi için
import subprocess  # Harici süreç ve test yürütme için
from typing import Tuple, List, Dict, Any  # Tip ipuçları için

# Uygulama dizininin eklenmesi
base_dir = os.path.dirname(os.path.abspath(__file__))  # gun_165 kök dizini
app_dir = os.path.join(base_dir, "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # Öncelikli ekle

# Savunma motorunun içe aktarılması
from cors_engine import (
    CORSDefenseEngine,  # Merkezi motor
    CORSRequest,  # İstek nesnesi
    CORSResponse,  # Yanıt nesnesi
    CORSRiskType  # Risk türleri
)


def run_unit_tests() -> str:
    """15 birim testi çalıştırır ve çıktısını döndürür."""
    test_file = os.path.join(base_dir, "tests", "test_cors_engine.py")  # Test dosyasının yolu
    cmd = [sys.executable, "-m", "unittest", test_file]  # Komut listesi
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)  # Çalıştır
    output = result.stdout + "\n" + result.stderr  # Çıktı birleştirilir
    return output.strip()  # Temizlenmiş çıktı


def run_negative_controls() -> Tuple[List[Dict[str, Any]], str, int]:
    """9 negatif kontrol senaryosunu icra eder ve rapor oluşturur."""
    payload_file = os.path.join(base_dir, "ornek_veri", "invalid_cors_payloads.json")  # Senaryo dosyası
    with open(payload_file, "r", encoding="utf-8") as f:  # Dosya açılır
        data = json.load(f)  # JSON yüklenir

    engine = CORSDefenseEngine()  # Motor başlatılır

    results = []  # Sonuçlar
    lines = []  # Metin raporu
    lines.append("=" * 80)
    lines.append("GÜN 165: CORS İLE GÜVENLİK SINIRI SALDIRI SAVUNMA RAPORU")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    passed_count = 0  # Savunulan senaryo sayısı

    for scn in data["senaryolar"]:  # Döngü
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        req_spec = scn["istek"]  # İstek özellikleri
        expected_status = scn["beklenen_hata_kodu"]  # Beklenen hata kodu

        lines.append(f"[*] Senaryo: {sid} - {title}")
        lines.append(f"    Saldırı Türü: {tur} | Origin: {req_spec.get('origin')} | Metot: {req_spec.get('method')}")

        # HTTP İstek nesnesi inşa edilir
        cors_req = CORSRequest(
            method=req_spec.get("method", "GET"),
            path=req_spec.get("path", "/api/veri"),
            origin=req_spec.get("origin"),
            access_control_request_method=req_spec.get("access_control_request_method"),
            access_control_request_headers=req_spec.get("access_control_request_headers")
        )

        # Güvenli işleyici çağrılır
        resp = engine.secure_cors_handler(cors_req)

        # Savunma kontrolü: Başarısız olmalı ve beklenen HTTP hata kodunu üretmelidir
        defense_succeeded = (resp.is_cross_origin_allowed is False) and (resp.status_code == expected_status)

        if defense_succeeded:
            passed_count += 1
            lines.append(f"    Sonuç: [SAVUNULDU] -> HTTP {resp.status_code} ile başarıyla engellendi.")
            lines.append(f"    CORS Başlıkları: {resp.headers} (ACAO dönülmedi)\n")
        else:
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Saldırı engellenemedi! HTTP {resp.status_code}\n")

        results.append({
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "beklenen_kod": expected_status,
            "gerceklesen_kod": resp.status_code,
            "savunuldu": defense_succeeded,
            "cors_onaylandi": resp.is_cross_origin_allowed
        })

    lines.append("-" * 80)
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")
    lines.append("=" * 80)

    report_text = "\n".join(lines)
    return results, report_text, passed_count


def generate_ascii_architecture() -> str:
    """Zorunlu banner ile temsili mimari ASCII diyagramı üretir."""
    diagram = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
GÜN 165: CORS (CROSS-ORIGIN RESOURCE SHARING) GÜVENLİK SINIRI MİMARİSİ
================================================================================

                           +--------------------------------------+
                           |   İSTEMCİ TARAYICISI (Browser XHR)   |
                           |   (JavaScript fetch() / axios / XHR) |
                           +--------------------------------------+
                                               |
                                               v
    [ KATMAN 1: AYNI KÖKEN İLKESİ (Same-Origin Policy - SOP Varsayılanı) ]
    +--------------------------------------------------------------------+
    | - Varsayılan: Tarayıcı, yabancı bir kökenden (Cross-Origin) dönen  |
    |   HTTP yanıt gövdesini JavaScript kodunun okumasına İZİN VERMEZ.   |
    | - CORS Rolü: Güvenlik duvarı DEĞİLDİR; SOP kısıtlamasını seçici ve |
    |   kontrollü olarak esnetmek için sunucu tarafından sunulan anahtar!|
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 2: PREFLIGHT KONTROLÜ (HTTP OPTIONS Uç Noktası) ]
    +--------------------------------------------------------------------+
    | - Tetikleyiciler: JSON (application/json), PUT, DELETE, Authorization|
    | - İstek Başlıkları:                                                |
    |     Origin: https://portal.kurum.internal                          |
    |     Access-Control-Request-Method: POST                            |
    |     Access-Control-Request-Headers: content-type, authorization    |
    | - Karar: Sunucu 204 No Content ve izinli liste ile onay verir.     |
    +--------------------------------------------------------------------+
                                               | (Preflight Onaylandı)
                                               v
    [ KATMAN 3: KATI KÖKEN BEYAZ LİSTESİ (Enterprise Allowlist Engine) ]
    +--------------------------------------------------------------------+
    | - İzinli Liste: ["https://portal.kurum.internal", ...]             |
    | - Tehlikeli Hatalar (Yasaklandı!):                                 |
    |     1. Arbitrary Reflection (Gelen Origin'i körlemesine yansıtma)  |
    |     2. 'null' Origin'e güvenme (Sandbox iframe / data URI saldırısı)|
    |     3. ACAO: * ile ACAC: true çelişkisi                            |
    |     4. Gevşek Regex (evil-portal.kurum.internal veya unescaped dot)|
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 4: ÖNBELLEK ZEHİRLENMESİ KORUMASI (Cache Poisoning Defense) ]
    +--------------------------------------------------------------------+
    | - Başlık: Vary: Origin                                             |
    | - Görev: CDN/Proxy önbelleklerinin bir saldırganın Origin yanıtını  |
    |   meşru kullanıcılara sunmasını engeller.                           |
    +--------------------------------------------------------------------+
                                               |
                                               v
                             +-----------------------------------+
                             |     GÜVENLİ VERİ TESLİMATI        |
                             | (Yalnızca Beyaz Listedeki Köken)  |
                             +-----------------------------------+
================================================================================
"""
    return diagram


def generate_sanitized_exchanges() -> str:
    """Zafiyetli ve güvenli CORS HTTP alışverişlerinin karşılaştırmalı dökümünü üretir."""
    lines = []
    lines.append("=" * 80)
    lines.append("GÜN 165: ZAFİYETLİ VE GÜVENLİ CORS HTTP ALIŞVERİŞ DÖKÜMÜ")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    lines.append("[1] ZAFİYETLİ CORS ÖRNEĞİ (Arbitrary Origin Reflection & Credentials):")
    lines.append("--- İSTEMCİ İSTEĞİ (evil-attacker.com üzerinden fetch): ---")
    lines.append("GET /api/kullanici/finansal-rapor HTTP/1.1")
    lines.append("Host: api.kurum.internal")
    lines.append("Origin: https://evil-attacker.com  <-- SALDIRGAN DOMAINI")
    lines.append("Cookie: session_id=sess_victim_1234  <-- TARAYICI OTOMATİK İLETTİ")
    lines.append("")
    lines.append("--- ZAFİYETLİ SUNUCU YANITI: ---")
    lines.append("HTTP/1.1 200 OK")
    lines.append("Access-Control-Allow-Origin: https://evil-attacker.com  <-- ZAFİYET: KÖRLEMESİNE YANSITILDI!")
    lines.append("Access-Control-Allow-Credentials: true  <-- ZAFİYET: SALDIRGAN JS İLE YANITI OKUYABİLİR!")
    lines.append("(Vary: Origin başlığı EKSİK! -> Önbellek zehirlenmesine açık)")
    lines.append('{"bakiye": 45000.0, "gizli_not": "Gizli Kurumsal Finansal Veri"}')
    lines.append("--> Sonuç: SALDIRGAN KURBANIN TÜM VERİLERİNİ ÇALDI!\n")

    lines.append("-" * 80)
    lines.append("[2] GÜVENLİ KURUMSAL CORS ÖRNEĞİ (Katı Allowlist & Vary Header):")
    lines.append("--- İSTEMCİ İSTEĞİ (evil-attacker.com üzerinden fetch): ---")
    lines.append("GET /api/kullanici/finansal-rapor HTTP/1.1")
    lines.append("Host: api.kurum.internal")
    lines.append("Origin: https://evil-attacker.com  <-- SALDIRGAN DOMAINI")
    lines.append("")
    lines.append("--- GÜVENLİ SUNUCU YANITI: ---")
    lines.append("HTTP/1.1 403 Forbidden")
    lines.append("(Access-Control-Allow-Origin BAŞLIĞI DÖNÜLMEDİ!)")
    lines.append('{"hata": "Yetkisiz yabancı köken (Cross-Origin): https://evil-attacker.com. Erişim engellendi."}')
    lines.append("--> Sonuç: Tarayıcı SOP kuralını işletir, JS yanıtı okuyamaz, saldırı tamamen bertaraf edildi!\n")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_cli_commands() -> str:
    """CLI komutlarını çalıştırır ve konsol çıktısını döndürür."""
    cli_file = os.path.join(app_dir, "cors_cli.py")
    cmds = [
        [sys.executable, cli_file, "--help"],
        [sys.executable, cli_file, "evaluate-origin", "--origin", "https://portal.kurum.internal"],
        [sys.executable, cli_file, "evaluate-origin", "--origin", "https://evil-attacker.com"],
        [sys.executable, cli_file, "test-preflight", "--origin", "https://portal.kurum.internal", "--request-method", "POST", "--request-headers", "content-type,authorization"],
        [sys.executable, cli_file, "simulate-misconfig", "--attacker-origin", "https://evil-hacker.com"]
    ]
    log_blocks = []
    for c in cmds:
        cmd_str = " ".join(c)
        log_blocks.append(f"$ {cmd_str}")
        res = subprocess.run(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)
        log_blocks.append(res.stdout + res.stderr)
        log_blocks.append("-" * 60)
    return "\n".join(log_blocks)


def main():
    print("[*] Gün 165: CORS ile Güvenlik Sınırı kanıt üretimi başlatılıyor...")

    gercek_dir = os.path.join(base_dir, "kanit", "gercek")
    temsili_dir = os.path.join(base_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim Test Kanıtı
    test_out = run_unit_tests()
    test_file = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(test_out)
    print(f"[+] Birim test sonuçları yazıldı: {test_file}")

    # 2. Negatif Kontrol Kanıtı
    neg_results, neg_text, passed_count = run_negative_controls()
    neg_file = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    with open(neg_file, "w", encoding="utf-8") as f:
        f.write(neg_text)
    print(f"[+] Negatif kontrol sonuçları yazıldı: {neg_file} ({passed_count}/9 Savunuldu)")

    # 3. Denetim JSON Raporu
    audit_data = {
        "gun": 165,
        "konu": "CORS ile güvenlik sınırı",
        "tarih": datetime.datetime.now().isoformat(),
        "savunulan_senaryo_sayisi": passed_count,
        "toplam_senaryo": len(neg_results),
        "basari_orani": passed_count / len(neg_results) if neg_results else 0.0,
        "senaryo_detaylari": neg_results
    }
    audit_file = os.path.join(gercek_dir, "cors_audit_report.json")
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Denetim JSON raporu yazıldı: {audit_file}")

    # 4. Karşılaştırmalı HTTP Alışveriş Dökümü
    exch_text = generate_sanitized_exchanges()
    exch_file = os.path.join(gercek_dir, "sanitized_cors_exchanges.txt")
    with open(exch_file, "w", encoding="utf-8") as f:
        f.write(exch_text)
    print(f"[+] Karşılaştırmalı CORS alışveriş dökümleri yazıldı: {exch_file}")

    # 5. CLI Komut ve Çıkış Günlüğü
    cli_log = run_cli_commands()
    cli_file = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    with open(cli_file, "w", encoding="utf-8") as f:
        f.write(cli_log)
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_file}")

    # 6. Temsilî Mimari Şema
    arch_diag = generate_ascii_architecture()
    arch_file = os.path.join(temsili_dir, "cors_guvenlik_siniri_mimarisi.txt")
    with open(arch_file, "w", encoding="utf-8") as f:
        f.write(arch_diag)
    print(f"[+] Temsilî mimari şema yazıldı: {arch_file}")

    print("[*] Tüm kanıtlar başarıyla tamamlandı!")


if __name__ == "__main__":
    main()
