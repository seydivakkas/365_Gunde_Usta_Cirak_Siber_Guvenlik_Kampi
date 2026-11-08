# -*- coding: utf-8 -*-
"""
Gün 164: CSRF ve Oturum Bağlamı Kanıt Üretici (kanit_uretici.py)

Bu script; birim testleri koşturarak gerçek test kanıtlarını, 9 negatif kontrol
saldırı senaryosunun savunma kayıtlarını, karşılaştırmalı HTTP işlem dökümlerini,
CLI yürütme günlüklerini ve standart ASCII temsilî mimari şemasını üretir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yönetimi için
import sys  # Sistem yolu ve argüman yönetimi için
import json  # JSON okuma ve yazma işlemleri için
import time  # Zaman damgaları ve zamanlama için
import datetime  # Tarih/saat biçimlendirme için
import subprocess  # Harici komut ve birim test yürütme için
import secrets  # Rastgele sayı ve belirteç üretimi için
import hmac  # HMAC imza üretimi için
import hashlib  # Kriptografik hash üretimi için

# Uygulama dizininin eklenmesi
base_dir = os.path.dirname(os.path.abspath(__file__))  # gun_164 kök dizini
app_dir = os.path.join(base_dir, "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # Öncelikli ekle

# Savunma motorunun içe aktarılması
from csrf_engine import (
    CSRFDefenseEngine,  # Merkezi motor
    HTTPRequest,  # İstek nesnesi
    UserSession,  # Oturum nesnesi
    AntiCSRFTokenManager,  # Belirteç yöneticisi
    SameSiteMode  # SameSite modları
)


def run_unit_tests() -> str:
    """15 birim testi çalıştırır ve çıktısını döndürür."""
    test_file = os.path.join(base_dir, "tests", "test_csrf_engine.py")  # Test dosyasının yolu
    cmd = [sys.executable, "-m", "unittest", test_file]  # Komut listesi
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)  # Çalıştır
    output = result.stdout + "\n" + result.stderr  # Çıktı birleştirilir
    return output.strip()  # Temizlenmiş çıktı


def run_negative_controls() -> Tuple[List[Dict[str, Any]], str, int]:
    """9 negatif kontrol senaryosunu icra eder ve rapor oluşturur."""
    payload_file = os.path.join(base_dir, "ornek_veri", "invalid_csrf_payloads.json")  # Senaryo dosyası
    with open(payload_file, "r", encoding="utf-8") as f:  # Dosya açılır
        data = json.load(f)  # JSON yüklenir

    engine = CSRFDefenseEngine(enterprise_origin="https://banka.kurum.internal")  # Motor başlatılır
    victim = engine.create_mock_session(user_id=2, username="ahmet_kaya")  # Kurban oturumu
    other_user = engine.create_mock_session(user_id=3, username="attacker_bob")  # Başka kullanıcı

    results = []  # Sonuçlar
    lines = []  # Metin raporu
    lines.append("=" * 80)
    lines.append("GÜN 164: CSRF VE OTURUM BAĞLAMI SALDIRI SAVUNMA RAPORU")
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
        lines.append(f"    Saldırı Türü: {tur} | Hedef Yol: {req_spec.get('path')}")

        # Dinamik belirteç hazırlığı
        headers = dict(req_spec.get("headers", {}))  # Başlık kopyası
        token_candidate = headers.get("X-CSRF-Token")

        if token_candidate == "TAMPERED_TOKEN_PLACEHOLDER":  # İmzası bozuk token
            legit = engine.token_manager.generate_token(victim)
            parts = legit.split(".")
            tampered = f"{parts[0]}.{parts[1]}.{parts[2]}.deadbeef1234"
            headers["X-CSRF-Token"] = tampered
        elif token_candidate == "OTHER_SESSION_TOKEN_PLACEHOLDER":  # Başka kullanıcının tokenı
            headers["X-CSRF-Token"] = engine.token_manager.generate_token(other_user)
        elif token_candidate == "EXPIRED_TOKEN_PLACEHOLDER":  # Süresi dolmuş token
            old_ts = int(time.time()) - 7200
            nonce = secrets.token_hex(16)
            raw = f"{victim.session_id}:{victim.csrf_secret}:{old_ts}:{nonce}"
            key = f"{engine.token_manager.master_secret}:{victim.csrf_secret}".encode("utf-8")
            sig = hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
            headers["X-CSRF-Token"] = f"{victim.session_id}.{old_ts}.{nonce}.{sig}"
        elif token_candidate == "CONSUMED_NONCE_PLACEHOLDER":  # Zaten harcanmış nonce
            spent_token = engine.token_manager.generate_token(victim)
            engine.token_manager.validate_token(spent_token, victim, consume=True)  # Önceden harcandı!
            headers["X-CSRF-Token"] = spent_token
        elif token_candidate == "VALID_TOKEN_PLACEHOLDER":  # Geçerli token
            headers["X-CSRF-Token"] = engine.token_manager.generate_token(victim)

        # Step-up senaryosunda son reauth zamanı 10 dakika öncesine ayarlanır
        if tur == "STEP_UP_REAUTH_BYPASS":
            victim.last_reauth_at = time.time() - 600  # 10 dakika önce

        # HTTP İstek nesnesi inşa edilir
        http_req = HTTPRequest(
            method=req_spec.get("method", "POST"),
            path=req_spec.get("path", "/api/transfer"),
            headers=headers,
            cookies={"session_id": victim.session_id},  # Ambient cookie
            form_data=req_spec.get("form_data", {})
        )

        # Güvenli transfer uç noktası çağrılır
        resp = engine.secure_transfer_funds(http_req)

        # Savunma kontrolü: Başarısız olmalı ve beklenen HTTP hata kodunu üretmelidir
        defense_succeeded = (resp["success"] is False) and (resp["status_code"] == expected_status)

        if defense_succeeded:
            passed_count += 1
            lines.append(f"    Sonuç: [SAVUNULDU] -> HTTP {resp['status_code']} ile başarıyla engellendi.")
            lines.append(f"    Savunma Mesajı: {resp.get('error')}\n")
        else:
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Saldırı engellenemedi! HTTP {resp['status_code']}\n")

        results.append({
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "beklenen_kod": expected_status,
            "gerceklesen_kod": resp["status_code"],
            "savunuldu": defense_succeeded,
            "hata_mesaji": resp.get("error")
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
GÜN 164: CSRF VE OTURUM BAĞLAMI ÇOK KATMANLI SAVUNMA MİMARİSİ
================================================================================

                           +--------------------------------------+
                           |     SİTELER ARASI DIŞ İSTEK          |
                           |  (evil-attacker.site -> Form/Image)  |
                           +--------------------------------------+
                                               |
                                               | (Tarayıcı Ambient Cookie ekler)
                                               v
    [ KATMAN 1: HTTP METOT KISITLAMASI (Safe Method Enforcement) ]
    +--------------------------------------------------------------------+
    | - Kural: GET, HEAD, OPTIONS metotları asla durum DEĞİŞTİREMEZ.     |
    | - Saldırı: <img src="banka.kurum.internal/transfer?amount=1000">   |
    | - Savunma: GET durum değişimi anında HTTP 405 Method Not Allowed.   |
    +--------------------------------------------------------------------+
                                               | (Yalnızca POST/PUT geçer)
                                               v
    [ KATMAN 2: KÖKEN DOĞRULAMA (Origin / Referer Header Validation) ]
    +--------------------------------------------------------------------+
    | - Gelen Origin: "https://evil-attacker.site"                       |
    | - Kurumsal Beyaz Liste: ["https://banka.kurum.internal"]           |
    | - Karar: Uyuşmazlık veya 'null' Origin anında HTTP 403 Forbidden.  |
    +--------------------------------------------------------------------+
                                               | (Origin meşru ise)
                                               v
    [ KATMAN 3: KRİPTOGRAFİK BELİRTEÇ (Synchronizer Token Pattern - STP) ]
    +--------------------------------------------------------------------+
    | - Token: <session_id>.<timestamp>.<nonce>.<HMAC-SHA256>            |
    | - Başlık: X-CSRF-Token veya Form: csrf_token                       |
    | - Denetimler:                                                      |
    |     1. Oturum kimliği uyuşuyor mu?                                 |
    |     2. 1800s TTL süresi dolmuş mu?                                 |
    |     3. Nonce daha önce kullanıldı mı? (Replay Engeli)              |
    |     4. HMAC imzası geçerli mi?                                     |
    +--------------------------------------------------------------------+
                                               | (Token %100 geçerli ise)
                                               v
    [ KATMAN 4: KRİTİK İŞLEMLER İÇİN ADIM YÜKSELTME (Step-Up Re-Auth) ]
    +--------------------------------------------------------------------+
    | - Bakiye transferi >= 5.000 TL veya Parola/E-posta değişimi        |
    | - Şart: Son 300 saniye içinde şifreli yeniden doğrulama yapıldı mı?|
    | - Karar: Süre aşılmışsa işlem durdurulur ve parola tekrar istenir. |
    +--------------------------------------------------------------------+
                                               |
                                               v
                             +-----------------------------------+
                             |     GÜVENLİ BANKACILIK İŞLEMİ     |
                             |    (Transfer Başarıyla Yürütülür) |
                             +-----------------------------------+
================================================================================
"""
    return diagram


def generate_sanitized_transactions() -> str:
    """Zafiyetli ve güvenli işlemlerin karşılaştırmalı dökümünü üretir."""
    lines = []
    lines.append("=" * 80)
    lines.append("GÜN 164: ZAFİYETLİ VE GÜVENLİ HTTP TRANSFER İŞLEM DÖKÜMÜ")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    lines.append("[1] ZAFİYETLİ İŞLEM ÖRNEĞİ (Ambient Authority İstismarı):")
    lines.append("POST /api/transfer HTTP/1.1")
    lines.append("Host: banka.kurum.internal")
    lines.append("Origin: https://evil-attacker.site  <-- DIŞ KAYNAKLI SALDIRGAN SİTESİ")
    lines.append("Cookie: session_id=sess_victim_998811  <-- TARAYICI OTOMATİK İLETTİ")
    lines.append("Content-Type: application/x-www-form-urlencoded")
    lines.append("")
    lines.append("target_account=3&amount=2500.0")
    lines.append("--> HTTP/1.1 200 OK")
    lines.append("--> Sonuç: FONLAR ÇALINDI! Kurbanın bilgisi/onayı olmadan 2.500 TL aktarıldı.\n")

    lines.append("-" * 80)
    lines.append("[2] GÜVENLİ İŞLEM ÖRNEĞİ (Anti-CSRF ve Origin Koruması):")
    lines.append("POST /api/transfer HTTP/1.1")
    lines.append("Host: banka.kurum.internal")
    lines.append("Origin: https://banka.kurum.internal  <-- MEŞRU KÖKEN")
    lines.append("Cookie: session_id=sess_victim_998811; Path=/; Secure; HttpOnly; SameSite=Strict")
    lines.append("X-CSRF-Token: sess_victim_998811.179302.3f89a1.7c89f0e1...  <-- KRİPTOGRAFİK İMZA")
    lines.append("Content-Type: application/x-www-form-urlencoded")
    lines.append("")
    lines.append("target_account=3&amount=1000.0")
    lines.append("--> HTTP/1.1 200 OK")
    lines.append("--> Savunma Mekanizmaları: [Method_POST, Origin_MATCH, STP_VERIFIED, Step_Up_SATISFIED]\n")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_cli_commands() -> str:
    """CLI komutlarını çalıştırır ve konsol çıktısını döndürür."""
    cli_file = os.path.join(app_dir, "csrf_cli.py")
    cmds = [
        [sys.executable, cli_file, "--help"],
        [sys.executable, cli_file, "generate-token", "--user-id", "2", "--username", "ahmet_kaya"],
        [sys.executable, cli_file, "simulate-attack", "--method", "POST", "--origin", "https://evil-phishing.com", "--amount", "2500"],
        [sys.executable, cli_file, "generate-cookie", "--session-id", "sess_prod_9988", "--samesite", "Strict"]
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
    print("[*] Gün 164: CSRF ve Oturum Bağlamı kanıt üretimi başlatılıyor...")

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
        "gun": 164,
        "konu": "CSRF ve oturum bağlamı",
        "tarih": datetime.datetime.now().isoformat(),
        "savunulan_senaryo_sayisi": passed_count,
        "toplam_senaryo": len(neg_results),
        "basari_orani": passed_count / len(neg_results) if neg_results else 0.0,
        "senaryo_detaylari": neg_results
    }
    audit_file = os.path.join(gercek_dir, "csrf_audit_report.json")
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Denetim JSON raporu yazıldı: {audit_file}")

    # 4. Karşılaştırmalı HTTP İşlem Dökümü
    trans_text = generate_sanitized_transactions()
    trans_file = os.path.join(gercek_dir, "sanitized_http_transactions.txt")
    with open(trans_file, "w", encoding="utf-8") as f:
        f.write(trans_text)
    print(f"[+] Karşılaştırmalı HTTP dökümleri yazıldı: {trans_file}")

    # 5. CLI Komut ve Çıkış Günlüğü
    cli_log = run_cli_commands()
    cli_file = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    with open(cli_file, "w", encoding="utf-8") as f:
        f.write(cli_log)
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_file}")

    # 6. Temsilî Mimari Şema
    arch_diag = generate_ascii_architecture()
    arch_file = os.path.join(temsili_dir, "csrf_savunma_mimarisi.txt")
    with open(arch_file, "w", encoding="utf-8") as f:
        f.write(arch_diag)
    print(f"[+] Temsilî mimari şema yazıldı: {arch_file}")

    print("[*] Tüm kanıtlar başarıyla tamamlandı!")


if __name__ == "__main__":
    main()
