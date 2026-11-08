# -*- coding: utf-8 -*-
"""
HTTP Cookies ve Güvenlik Bayrakları Kanıt Üretici
Hafta 23 / Gün 157 - Aşama 7 (Web Güvenliği)

Bu betik; birim testleri, 9 adet negatif kontrol senaryosunu ve CLI komutlarını
yürüterek 'kanit/gercek/' ve 'kanit/temsili/' dizinlerine doğrulanabilir
çıktıları üretir.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

# Proje ana dizinini sys.path'e ekleme
CURRENT_DIR = Path(__file__).resolve().parent
PORTFOLIO_ROOT = CURRENT_DIR.parent.parent.parent
sys.path.insert(0, str(PORTFOLIO_ROOT))

# İlgili motor ve sınıfları içe aktarma
from portfolio.hafta_23.gun_157.uygulama.cookie_security_engine import (
    CookieSecurityEngine,
    HttpCookie,
    SameSitePolicy,
    CookieType,
    FleetCookieReport
)


def run_unit_tests():
    """15 birim testi çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = CURRENT_DIR / "tests" / "test_cookie_security.py"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "test_sonuclari.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "-m", "unittest", str(test_path), "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_text = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_text = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== HTTP COOKIES VE GÜVENLİK BAYRAKLARI BİRİM TESTLERİ (15/15) ===\n")
        f.write(stdout_text)
        f.write(stderr_text)
        f.write("\nDurum Kodu: " + str(res.returncode) + "\n")
    print(f"[+] Birim test kanıtı üretildi: {out_file}")


def run_negative_controls():
    """9 negatif senaryoyu çalıştırıp kanıt dosyasına kaydeder."""
    scenarios_file = CURRENT_DIR / "ornek_veri" / "invalid_cookie_scenarios.json"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "negatif_kontrol_sonuclari.txt"

    with open(scenarios_file, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    engine = CookieSecurityEngine()
    results = []

    for scn in scenarios:
        c_data = scn["cookie"]
        c_type = CookieType(c_data["cookie_type"])
        s_site = SameSitePolicy(c_data["same_site"])
        cookie = HttpCookie(
            name=c_data["name"],
            value=c_data["value"],
            secure=c_data["secure"],
            http_only=c_data["http_only"],
            same_site=s_site,
            domain=c_data.get("domain"),
            path=c_data.get("path", "/"),
            max_age=c_data.get("max_age"),
            cookie_type=c_type,
            is_encrypted_or_opaque=c_data.get("is_encrypted_or_opaque", True)
        )

        rep = engine.audit_cookie(cookie)
        target_code = scn["target_issue_code"]
        found = any(i.code == target_code for i in rep.issues)
        passed = (rep.status == "KALDI" and found)

        results.append({
            "scenario_id": scn["scenario_id"],
            "name": scn["name"],
            "target_issue": target_code,
            "security_score": rep.security_score,
            "status": rep.status,
            "issues_count": len(rep.issues),
            "validation_passed": passed
        })

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== 9 ADET ÇEREZ GÜVENLİK VE BAYRAK NEGATİF KONTROL SENARYOSU ===\n\n")
        for r in results:
            f.write(f"Senaryo: {r['scenario_id']} - {r['name']}\n")
            f.write(f"  Hedef Zafiyet Kodu: {r['target_issue']}\n")
            f.write(f"  Hesaplanan Skor   : %{r['security_score']:.1f} / 100 (Durum: {r['status']})\n")
            f.write(f"  Tespit Edilen Açık : {r['issues_count']}\n")
            f.write(f"  Negatif Doğrulama  : {'BAŞARILI (Açık Yakalandı)' if r['validation_passed'] else 'BAŞARISIZ'}\n\n")
        all_passed = all(r["validation_passed"] for r in results)
        f.write(f"ÖZET: Toplam {len(results)} senaryonun {sum(1 for r in results if r['validation_passed'])} tanesi doğrulandı. (Genel: {'100% PASS' if all_passed else 'FAIL'})\n")
    print(f"[+] Negatif kontrol kanıtı üretildi: {out_file}")


def generate_reports_and_cli_logs():
    """Kurumsal filo raporunu, sertleştirilmiş başlıkları ve CLI loglarını üretir."""
    spec_file = CURRENT_DIR / "ornek_veri" / "enterprise_cookie_spec.json"
    with open(spec_file, "r", encoding="utf-8") as f:
        spec_data = json.load(f)

    cookies = []
    for c_data in spec_data["cookies"]:
        cookies.append(HttpCookie(
            name=c_data["name"],
            value=c_data["value"],
            secure=c_data["secure"],
            http_only=c_data["http_only"],
            same_site=SameSitePolicy(c_data["same_site"]),
            domain=c_data.get("domain"),
            path=c_data.get("path", "/"),
            max_age=c_data.get("max_age"),
            cookie_type=CookieType(c_data["cookie_type"]),
            is_encrypted_or_opaque=c_data.get("is_encrypted_or_opaque", True)
        ))

    engine = CookieSecurityEngine()
    fleet_rep = engine.audit_fleet(cookies)

    # JSON Raporu kaydetme
    json_out = CURRENT_DIR / "kanit" / "gercek" / "cookie_audit_report.json"
    dict_data = engine.export_fleet_report_to_dict(fleet_rep)
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(dict_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Çerez denetim JSON raporu üretildi: {json_out}")

    # Sertleştirilmiş başlıklar listesini üretme
    scenarios_file = CURRENT_DIR / "ornek_veri" / "invalid_cookie_scenarios.json"
    with open(scenarios_file, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    hardened_out = CURRENT_DIR / "kanit" / "gercek" / "hardened_cookies.txt"
    with open(hardened_out, "w", encoding="utf-8") as f:
        f.write("=== ZAFİYETLİ ÇEREZLERİN OTOMATİK SERTLEŞTİRİLMİŞ BAŞLIKLARI ===\n\n")
        for scn in scenarios:
            c_data = scn["cookie"]
            c_type = CookieType(c_data["cookie_type"])
            s_site = SameSitePolicy(c_data["same_site"])
            raw_c = HttpCookie(
                name=c_data["name"],
                value=c_data["value"],
                secure=c_data["secure"],
                http_only=c_data["http_only"],
                same_site=s_site,
                domain=c_data.get("domain"),
                path=c_data.get("path", "/"),
                max_age=c_data.get("max_age"),
                cookie_type=c_type
            )
            hardened = engine.harden_cookie(raw_c)
            f.write(f"Senaryo: {scn['scenario_id']} ({scn['name']})\n")
            f.write(f"  Orijinal Başlık     : Set-Cookie: {raw_c.to_set_cookie_header()}\n")
            f.write(f"  Sertleştirilmiş Hal : Set-Cookie: {hardened.to_set_cookie_header()}\n\n")
    print(f"[+] Sertleştirilmiş başlıklar üretildi: {hardened_out}")

    # CLI komutlarını yürütme ve loglama
    cli_path = CURRENT_DIR / "uygulama" / "cookie_security_cli.py"
    cli_out_file = CURRENT_DIR / "kanit" / "gercek" / "komut_ve_cikis.txt"

    cmds = [
        [sys.executable, str(cli_path), "audit-header", "--header", "session_id=tok123; Path=/; Secure; HttpOnly; SameSite=Strict"],
        [sys.executable, str(cli_path), "audit-header", "--header", "bad_session=abc; Path=/; SameSite=None"],
        [sys.executable, str(cli_path), "audit-spec", "--spec", str(spec_file)],
        [sys.executable, str(cli_path), "harden", "--header", "user_auth=9928; Path=/; Domain=.example.com"],
        [sys.executable, str(cli_path), "generate-set-cookie", "--name", "secure_session", "--value", "crypto_opaque_uuid", "--max-age", "86400"]
    ]

    with open(cli_out_file, "w", encoding="utf-8") as f:
        f.write("=== HTTP COOKIES VE GÜVENLİK BAYRAKLARI CLI YÜRÜTME LOGLARI ===\n\n")
        for c in cmds:
            f.write(f"$ {' '.join(c)}\n")
            res = subprocess.run(c, capture_output=True)
            c_stdout = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
            c_stderr = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""
            f.write(c_stdout)
            if c_stderr:
                f.write("\n[STDERR]\n" + c_stderr)
            f.write("\n" + "=" * 70 + "\n\n")
    print(f"[+] CLI log kanıtı üretildi: {cli_out_file}")


def generate_representative_evidence():
    """Temsili ASCII çerez güvenlik bayrakları diyagramını üretir."""
    rep_file = CURRENT_DIR / "kanit" / "temsili" / "cookie_guvenlik_bayraklari.txt"
    rep_file.parent.mkdir(parents=True, exist_ok=True)

    content = """TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
========================================================================================================
                      HTTP ÇEREZLERİ VE GÜVENLİK BAYRAKLARI MİMARİSİ
========================================================================================================

  +----------------------------------------------------------------------------------------------------+
  |                                 HTTP YANIT BAŞLIĞI: Set-Cookie                                     |
  |  Set-Cookie: __Host-auth=e8d7a6; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400         |
  +----------------------------------------------------------------------------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
         v                            v                            v
  +--------------------+       +--------------------+       +--------------------+
  |   Secure Bayrağı   |       |  HttpOnly Bayrağı  |       |  SameSite Bayrağı  |
  +--------------------+       +--------------------+       +--------------------+
  | * Yalnızca TLS 1.3 |       | * JS document.cook |       | * Strict: Tam izole|
  |   üzerinden iletim |       |   erişimi engeller |       | * Lax: GET navigas.|
  | * Düz metin HTTP   |       | * XSS Session      |       | * None: 3. taraf   |
  |   ve MITM dinleme  |       |   Hijacking saldırı|       |   (Secure zorunlu) |
  |   sızıntısı ÖNLENİR|       |   larını SIFIRLAR  |       | * CSRF'i ENGELLER  |
  +--------------------+       +--------------------+       +--------------------+
         |                            |                            |
         +----------------------------+----------------------------+
                                      |
                                      v
  +----------------------------------------------------------------------------------------------------+
  |                             RFC 6265bis GÜVENLİK ÖNEKLERİ                                          |
  |                                                                                                    |
  |  1. __Secure- Öneki:                                                                               |
  |     - Yalnızca HTTPS üzerinden gönderilir.                                                         |
  |     - 'Secure' bayrağı İÇERMEK ZORUNDADIR.                                                         |
  |                                                                                                    |
  |  2. __Host- Öneki (EN YÜKSEK İZOLASYON):                                                           |
  |     - 'Secure' bayrağı İÇERMEK ZORUNDADIR.                                                         |
  |     - 'Path=/' KÖK DİZİN OLMAK ZORUNDADIR.                                                         |
  |     - 'Domain' ÖZNİTELİĞİ KESİNLİKLE BULUNMAMALIDIR (Host-only cookie).                            |
  |     - Alt alan adlarının (subdomain takeover) çerezi ezmesini veya sabitlemesini (fixation) ÖNLER!  |
  +----------------------------------------------------------------------------------------------------+

========================================================================================================
                                   GÜVENLİK KONTROL MATRİSİ
========================================================================================================
  Çerez Türü       Önek      Secure    HttpOnly    SameSite    Path    Domain      Max-Age Sınırı
  ------------     -------   ------    --------    --------    ----    ------      --------------
  Oturum (Auth)    __Host-    EVET       EVET       Strict       /      YASAK       <= 14 Gün
  CSRF Belirteci   __Host-    EVET       HAYIR*     Strict       /      YASAK       <= 1 Gün
  Tercih/Tema      __Secure-  EVET       HAYIR        Lax        /      Opsiyonel   <= 30 Gün
========================================================================================================
  * Not: Double-Submit CSRF modellerinde istemci JS token'ı okuyacağı için HttpOnly kapatılabilir.
========================================================================================================
"""
    with open(rep_file, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"[+] Temsili ASCII kanıtı üretildi: {rep_file}")


def main():
    """Tüm kanıt üretim adımlarını yürütür."""
    print("=== GÜN 157 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    generate_reports_and_cli_logs()
    generate_representative_evidence()
    print("=== GÜN 157 TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
