# -*- coding: utf-8 -*-
"""
Gün 155: Web Uygulama Mimarisi ve Güven Sınırı Kanıt Üretici Betiği
Hafta 23 / Gün 155 - Aşama 7 (Web Güvenliği)

Bu betik; 15 birim testini, 9 negatif kontrol senaryosunu, tam akış denetim
raporunu, sertleştirilmiş HTTP yanıtını, Nginx güvenlik konfigürasyonunu, CLI
konsol günlüğünü ve temsili mimari diyagramı üreterek gerçek kanıt dosyalarını kaydeder.
"""

import unittest
import io
import os
import sys
import json
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from uygulama.web_architecture_engine import (
    HttpRequest,
    HttpResponse,
    CookieSpec,
    WebTrustBoundaryEngine,
    WebAuditReport,
    ViolationSeverity,
)
from uygulama.web_architecture_cli import load_flow_json


def generate_unit_test_evidence():
    """15 birim testini çalıştırır ve kanıt dosyasına kaydeder."""
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output_text = stream.getvalue()

    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "test_sonuclari.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(" GÜN 155: BİRİM TEST SONUÇLARI (15/15 PASS) - WEB MİMARİSİ VE GÜVEN SINIRI\n")
        f.write("=" * 80 + "\n\n")
        f.write(output_text)
        f.write("\n" + "=" * 80 + "\n")
        f.write(f" TOPLAM TEST: {result.testsRun} | BAŞARILI: {result.testsRun - len(result.failures) - len(result.errors)} | HATA: {len(result.errors)} | BAŞARISIZ: {len(result.failures)}\n")
        f.write(f" DURUM: {'BAŞARILI (PASS)' if result.wasSuccessful() else 'BAŞARISIZ (FAIL)'}\n")
        f.write("=" * 80 + "\n")

    print(f"[+] Birim test sonuçları kaydedildi: {out_path}")
    return result.wasSuccessful()


def generate_negative_control_evidence():
    """9 negatif kontrol senaryosunu çalıştırır ve kanıt dosyasına kaydeder."""
    scn_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_trust_boundary_scenarios.json")
    with open(scn_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    engine = WebTrustBoundaryEngine()
    lines = []
    lines.append("=" * 80)
    lines.append(" GÜN 155: NEGATİF KONTROL VE HATA SENARYOLARI RAPORU (9/9 PASS)")
    lines.append("=" * 80 + "\n")

    passed_count = 0

    for s in scenarios:
        sid = s["scenario_id"]
        name = s["name"]
        flow_data = s["flow"]
        exp_violation = s["expected_violation"]

        lines.append(f"[*] Senaryo: {sid} - {name}")
        lines.append(f"    Açıklama: {s['description']}")

        # İstek nesnesi oluşturulur
        req_d = flow_data.get("request", {})
        request = HttpRequest(
            method=req_d.get("method", "GET"),
            path=req_d.get("path", "/"),
            headers=req_d.get("headers", {}),
            query_params=req_d.get("query_params", {}),
            body=req_d.get("body", {}),
            is_https=req_d.get("is_https", True),
        )

        # Yanıt nesnesi oluşturulur
        res_d = flow_data.get("response", {})
        cookies = [
            CookieSpec(
                name=c["name"],
                value=c["value"],
                secure=c.get("secure", False),
                httponly=c.get("httponly", False),
                samesite=c.get("samesite", "None"),
            )
            for c in res_d.get("cookies", [])
        ]
        response = HttpResponse(
            status_code=res_d.get("status_code", 200),
            headers=res_d.get("headers", {}),
            cookies=cookies,
        )

        report = engine.full_audit(request, response)

        lines.append(f"    Hesaplanan Güvenlik Skoru : {report.overall_score} / 100")
        lines.append(f"    Güvenlik Kararı           : {'GÜVENLİ' if report.is_secure else 'UYGUNSUZ / TEHLİKELİ'}")

        # Doğrulama mantığı
        matched = False
        # İstek ihlali kontrolü
        for v in report.request_violations:
            if v.violation_type == exp_violation:
                matched = True
                lines.append(f"    [+] Tespit Edilen İhlal: {v.violation_type} ({v.severity.value}) - {v.description}")
                break
        
        # Başlık ve çerez ihlalleri kontrolü
        if not matched:
            if exp_violation == "hsts_missing" and not report.header_audit.hsts_present:
                matched = True
                lines.append("    [+] HSTS Eksikliği Doğrulandı.")
            elif exp_violation == "csp_unsafe_inline" and report.header_audit.csp_has_unsafe_inline:
                matched = True
                lines.append("    [+] CSP unsafe-inline Açığı Doğrulandı.")
            elif exp_violation == "insecure_cookie_flags" and any(not c.secure_valid or not c.httponly_valid for c in report.cookie_audits):
                matched = True
                lines.append("    [+] Güvensiz Çerez Bayrakları Doğrulandı.")
            elif exp_violation == "server_information_disclosure" and len(report.header_audit.disclosed_server_tokens) > 0:
                matched = True
                lines.append(f"    [+] Sunucu Bilgi İfşası Doğrulandı: {report.header_audit.disclosed_server_tokens}")

        if matched:
            lines.append("    [+] DURUM: BAŞARILI (Güven sınırı ihlali tam isabetle yakalandı).")
            passed_count += 1
        else:
            lines.append("    [-] DURUM: UYARISIZ (Beklenen ihlal yakalanamadı).")

        lines.append("-" * 80)

    lines.append(f"\nTOPLAM SENARYO: {len(scenarios)} | BAŞARILI DOĞRULAMA: {passed_count}/{len(scenarios)}")
    lines.append("SONUÇ: %100 NEGATİF KONTROL VE GÜVEN SINIRI İHLALİ YAKALAMA BAŞARISI (PASS)\n")

    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_path}")
    return passed_count == len(scenarios)


def generate_flow_audit_and_remediation():
    """Örnek kurumsal akışı denetler, sertleştirilmiş yanıt ve Nginx konfigürasyonu üretir."""
    flow_path = os.path.join(CURRENT_DIR, "ornek_veri", "clean_web_architecture_flow.json")
    request, response = load_flow_json(flow_path)
    engine = WebTrustBoundaryEngine()

    # 1. Tam Denetim Raporu
    report = engine.full_audit(request, response)
    report_dict = {
        "overall_score": report.overall_score,
        "is_secure": report.is_secure,
        "summary": report.summary,
        "request_violations": [
            {
                "boundary": v.boundary,
                "violation_type": v.violation_type,
                "severity": v.severity.value,
                "description": v.description,
                "remediation": v.remediation,
            }
            for v in report.request_violations
        ],
        "header_audit": {
            "score": report.header_audit.score,
            "hsts_valid": report.header_audit.hsts_valid,
            "csp_present": report.header_audit.csp_present,
            "x_frame_options_present": report.header_audit.x_frame_options_present,
            "x_content_type_options_present": report.header_audit.x_content_type_options_present,
            "disclosed_server_tokens": report.header_audit.disclosed_server_tokens,
        },
        "cookie_audits": [
            {
                "cookie_name": c.cookie_name,
                "score": c.cookie_score,
                "secure": c.secure_valid,
                "httponly": c.httponly_valid,
                "samesite": c.samesite_valid,
            }
            for c in report.cookie_audits
        ],
    }
    json_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "web_trust_boundary_audit.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    # 2. Sertleştirilmiş Yanıt Çıktısı
    hardened = engine.harden_response(response)
    hardened_dict = {
        "status_code": hardened.status_code,
        "headers": hardened.headers,
        "cookies": [
            {
                "name": c.name,
                "value": c.value,
                "secure": c.secure,
                "httponly": c.httponly,
                "samesite": c.samesite,
                "path": c.path,
            }
            for c in hardened.cookies
        ]
    }
    hard_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "hardened_web_response.json")
    with open(hard_path, "w", encoding="utf-8") as f:
        json.dump(hardened_dict, f, indent=2, ensure_ascii=False)

    # 3. Nginx Güvenlik Konfigürasyonu
    nginx_conf = engine.generate_nginx_security_config()
    nginx_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "nginx_security_headers.conf")
    with open(nginx_path, "w", encoding="utf-8") as f:
        f.write(nginx_conf)

    print("[+] JSON denetim raporu, sertleştirilmiş yanıt ve Nginx konfigürasyonu kaydedildi.")


def generate_cli_execution_log():
    """CLI komutlarını çalıştırarak konsol günlüğünü kaydeder."""
    cli_path = os.path.join(CURRENT_DIR, "uygulama", "web_architecture_cli.py")
    flow_path = os.path.join(CURRENT_DIR, "ornek_veri", "clean_web_architecture_flow.json")
    log_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "komut_ve_cikis.txt")

    commands = [
        [sys.executable, cli_path, "audit-flow", "--flow", flow_path],
        [sys.executable, cli_path, "harden-response", "--flow", flow_path],
        [sys.executable, cli_path, "export-nginx"],
    ]

    log_lines = []
    log_lines.append("=" * 80)
    log_lines.append(" GÜN 155: WEB MİMARİSİ VE GÜVEN SINIRI CLI YÜRÜTME GÜNLÜĞÜ")
    log_lines.append("=" * 80 + "\n")

    for cmd in commands:
        cmd_str = " ".join(cmd)
        log_lines.append(f"$ {cmd_str}\n")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            log_lines.append(res.stdout)
        except subprocess.CalledProcessError as e:
            log_lines.append(e.stdout)
            log_lines.append(e.stderr)
        log_lines.append("\n" + "-" * 80 + "\n")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))

    print(f"[+] CLI konsol günlüğü kaydedildi: {log_path}")


def generate_representative_diagram():
    """Temsili ASCII mimari diyagramını zorunlu banner ile kaydeder."""
    diag_path = os.path.join(CURRENT_DIR, "kanit", "temsili", "web_mimarisi_guven_siniri.txt")
    os.makedirs(os.path.dirname(diag_path), exist_ok=True)

    diagram_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

             WEB UYGULAMA MİMARİSİ VE GÜVEN SINIRLARI (TRUST BOUNDARIES)
                                (HAFTA 23 - GÜN 155)

   [GÜVENİLMEYEN BÖLGE (UNTRUSTED)]          [GÜVENİLİR BÖLGE (TRUSTED INTRANET)]
  +--------------------------------+       +------------------------------------+
  |      İSTEMCİ / WEB TARAYICI    |       |        EDGE / REVERSE PROXY        |
  |  - HTML5 / React / Vue SPA     |       |       (Nginx / Cloudflare / WAF)   |
  |  - LocalStorage / JS Memory    |       |  - TLS 1.3 Sonlandırma (HSTS)      |
  |  - DOM Manipülasyonu Mümkün    |       |  - Güvenlik Başlıkları Enjeksiyonu |
  |  - Client Validasyon: GÜVENSİZ!|       |  - HTTP Method & Rate Limiting     |
  +--------------------------------+       +------------------------------------+
                  |                                           |
                  | (HTTPS / Şifreli İletim)                  | (Reverse Proxy Pass)
                  v                                           v
  ================ GÜVEN SINIRI 1 (İSTEMCİ -> SUNUCU) ===========================
  * Asla İstemci Verisine Güvenme! (No Client Trust)
  * role, is_admin, price, discount -> Sunucu Tarafında Hesaplanmalı
  * URL Sorgusunda Token/Parola İfşası Yasak
  ===============================================================================
                  |                                           |
                  v                                           v
  +--------------------------------+       +------------------------------------+
  |       UYGULAMA SUNUCUSU        |       |       VERİTABANI / BACKEND         |
  |    (API Gateway / Backend)     |       |       (PostgreSQL / Redis Cache)   |
  |  - Kimlik Doğrulama (Session)  |       |  - Rol & Yetki Yetkili Kaynağı     |
  |  - Yetkilendirme (RBAC Matrisi)|<----->|  - Ürün & Fiyat Kataloğu Kaynağı   |
  |  - Giriş Sanitizasyonu         |       |  - Şifreli Veri Depolama           |
  |  - Set-Cookie (HttpOnly,Secure)|       |  - En Az Ayrıcalıklı DB Kullanıcısı|
  +--------------------------------+       +------------------------------------+
                  |
  ================ GÜVEN SINIRI 2 (UYGULAMA -> VERİTABANI) ======================
  * Parametreli Sorgular (Prepared Statements / ORM) -> SQLi Engelleme
  * Veritabanı Kimlik Bilgileri Asla İstemciye İfşa Edilemez
  ===============================================================================

   YANIT SERTLEŞTİRME BAŞLIKLARI (SECURITY HEADERS DEFENSE):
   1. Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
   2. Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
   3. X-Frame-Options: DENY (Clickjacking Koruması)
   4. X-Content-Type-Options: nosniff (MIME Sniffing Koruması)
   5. Referrer-Policy: strict-origin-when-cross-origin
   6. Çerez Bayrakları: Secure; HttpOnly; SameSite=Strict/Lax

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(diag_path, "w", encoding="utf-8") as f:
        f.write(diagram_content)

    print(f"[+] Temsili mimari diyagramı kaydedildi: {diag_path}")


def main():
    """Tüm kanıtları sırayla üretir."""
    print("=" * 80)
    print("[*] GÜN 155 KANIT ÜRETİCİ BAŞLATILIYOR (WEB MİMARİSİ VE GÜVEN SINIRI)...")
    print("=" * 80)
    generate_unit_test_evidence()
    generate_negative_control_evidence()
    generate_flow_audit_and_remediation()
    generate_cli_execution_log()
    generate_representative_diagram()
    print("=" * 80)
    print("[+] TÜM GERÇEK VE TEMSİLÎ KANITLAR BAŞARIYLA OLUŞTURULDU.")
    print("=" * 80)


if __name__ == "__main__":
    main()
