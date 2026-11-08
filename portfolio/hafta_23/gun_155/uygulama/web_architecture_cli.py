# -*- coding: utf-8 -*-
"""
Web Uygulama Mimarisi ve Güven Sınırı CLI Yönetim Aracı
Hafta 23 / Gün 155 - Aşama 7 (Web Güvenliği)

Bu araç; HTTP istek ve yanıt akışlarını JSON dosyalarından okur, istemci-sunucu
güven sınırını denetler, eksik güvenlik başlıklarını ve güvensiz çerezleri
raporlar, otomatik Nginx güvenlik konfigürasyonları ve sertleştirilmiş yanıtlar üretir.
"""

import argparse
import json
import sys
import os

# Üst dizini Python arama yoluna ekler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.web_architecture_engine import (
    HttpRequest,
    HttpResponse,
    CookieSpec,
    WebTrustBoundaryEngine,
    WebAuditReport,
    ViolationSeverity,
)


def load_flow_json(file_path: str):
    """JSON dosyasından istek ve yanıt nesnelerini yükler."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Akış dosyası bulunamadı: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    req_data = data.get("request", {})
    res_data = data.get("response", {})

    request = HttpRequest(
        method=req_data.get("method", "GET"),
        path=req_data.get("path", "/"),
        headers=req_data.get("headers", {}),
        query_params=req_data.get("query_params", {}),
        body=req_data.get("body", {}),
        client_ip=req_data.get("client_ip", "127.0.0.1"),
        is_https=req_data.get("is_https", True),
        cookies=req_data.get("cookies", {}),
    )

    raw_cookies = res_data.get("cookies", [])
    cookie_objs = []
    for c in raw_cookies:
        cookie_objs.append(CookieSpec(
            name=c["name"],
            value=c["value"],
            domain=c.get("domain"),
            path=c.get("path", "/"),
            secure=c.get("secure", False),
            httponly=c.get("httponly", False),
            samesite=c.get("samesite", "None"),
            max_age=c.get("max_age"),
        ))

    response = HttpResponse(
        status_code=res_data.get("status_code", 200),
        headers=res_data.get("headers", {}),
        body=res_data.get("body", ""),
        cookies=cookie_objs,
    )

    return request, response


def handle_audit_flow(args):
    """Tüm HTTP akışını (istek + yanıt) denetler ve konsola detaylı rapor basar."""
    request, response = load_flow_json(args.flow)
    engine = WebTrustBoundaryEngine()
    report = engine.full_audit(request, response)

    print("=" * 80)
    print(" WEB UYGULAMA MİMARİSİ VE GÜVEN SINIRI DENETİM RAPORU (GÜN 155)")
    print("=" * 80)
    print(f" Genel Mimari Güvenlik Skoru : {report.overall_score} / 100")
    print(f" Güvenlik Durumu             : {'GÜVENLİ (PASS)' if report.is_secure else 'UYGUNSUZ (FAIL)'}")
    print(f" Özet                        : {report.summary}")
    print("-" * 80)
    print(f" 1. İSTEMCİ-SUNUCU GÜVEN SINIRI İHLALLERİ ({len(report.request_violations)} Adet):")
    if report.request_violations:
        for v in report.request_violations:
            print(f"   [{v.severity.value}] {v.boundary} -> {v.violation_type}: {v.description}")
            print(f"       Çözüm: {v.remediation}")
    else:
        print("   [+] İstemci tarafında herhangi bir güven sınırı ihlali saptanmadı.")

    print("-" * 80)
    print(f" 2. GÜVENLİK BAŞLIKLARI PUANI: {report.header_audit.score} / 100")
    print(f"   * HSTS Geçerli           : {'EVET' if report.header_audit.hsts_valid else 'HAYIR'}")
    print(f"   * CSP Mevcut             : {'EVET' if report.header_audit.csp_present else 'HAYIR'}")
    print(f"   * X-Frame-Options        : {'EVET' if report.header_audit.x_frame_options_present else 'HAYIR'}")
    print(f"   * X-Content-Type-Options : {'EVET' if report.header_audit.x_content_type_options_present else 'HAYIR'}")
    if report.header_audit.disclosed_server_tokens:
        print("   [-] İfşa Edilen Başlıklar : " + ", ".join(report.header_audit.disclosed_server_tokens))

    print("-" * 80)
    print(f" 3. ÇEREZ VE OTURUM GÜVENLİĞİ DENETİMİ ({len(report.cookie_audits)} Çerez):")
    for ca in report.cookie_audits:
        print(f"   * {ca.cookie_name} (Skor: {ca.cookie_score}/100) -> Secure: {ca.secure_valid}, HttpOnly: {ca.httponly_valid}, SameSite: {ca.samesite_valid}")
        for find in ca.findings:
            print(f"       [-] {find}")
    print("=" * 80)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        # Rapor sözlüğe çevrilip kaydedilir
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
                "hsts_present": report.header_audit.hsts_present,
                "hsts_valid": report.header_audit.hsts_valid,
                "csp_present": report.header_audit.csp_present,
                "x_frame_options_present": report.header_audit.x_frame_options_present,
                "disclosed_server_tokens": report.header_audit.disclosed_server_tokens,
            },
            "cookie_audits": [
                {
                    "cookie_name": c.cookie_name,
                    "score": c.cookie_score,
                    "secure": c.secure_valid,
                    "httponly": c.httponly_valid,
                    "samesite": c.samesite_valid,
                    "findings": c.findings,
                }
                for c in report.cookie_audits
            ],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Denetim raporu JSON formatında kaydedildi: {args.output}")


def handle_harden_response(args):
    """Güvensiz bir HTTP yanıtını sertleştirir ve güvenli başlıklar ekler."""
    _, response = load_flow_json(args.flow)
    engine = WebTrustBoundaryEngine()
    hardened = engine.harden_response(response)

    print("=" * 70)
    print(" SERTLEŞTİRİLMİŞ (HARDENED) HTTP YANITI")
    print("=" * 70)
    print(f" Durum Kodu: {hardened.status_code}")
    print("\n Başlıklar:")
    for k, v in hardened.headers.items():
        print(f"   {k}: {v}")
    print("\n Çerezler (Set-Cookie):")
    for c in hardened.cookies:
        print(f"   Set-Cookie: {c.name}={c.value}; Secure; HttpOnly; SameSite={c.samesite}; Path={c.path}")
    print("=" * 70)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        res_dict = {
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
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(res_dict, f, indent=2, ensure_ascii=False)
        print(f"[+] Sertleştirilmiş yanıt kaydedildi: {args.output}")


def handle_export_nginx(args):
    """Sertleştirilmiş kurumsal Nginx güvenlik yapılandırmasını dışa aktarır."""
    engine = WebTrustBoundaryEngine()
    conf = engine.generate_nginx_security_config()

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(conf)
        print(f"[+] Nginx güvenlik konfigürasyonu kaydedildi: {args.output}")
    else:
        print(conf)


def main():
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(description="Web Mimarisi ve Güven Sınırı Yönetim Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # audit-flow komutu
    audit_parser = subparsers.add_parser("audit-flow", help="HTTP istek ve yanıt akışını denetle")
    audit_parser.add_argument("--flow", required=True, help="Akış JSON dosya yolu")
    audit_parser.add_argument("--output", help="Raporun kaydedileceği JSON dosya yolu")

    # harden-response komutu
    harden_parser = subparsers.add_parser("harden-response", help="HTTP yanıtını sertleştir")
    harden_parser.add_argument("--flow", required=True, help="Akış JSON dosya yolu")
    harden_parser.add_argument("--output", help="Sertleştirilmiş yanıt JSON dosya yolu")

    # export-nginx komutu
    nginx_parser = subparsers.add_parser("export-nginx", help="Nginx güvenlik başlıkları konfigürasyonunu üret")
    nginx_parser.add_argument("--output", help="Nginx konfigürasyon dosya yolu (.conf)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit-flow":
        handle_audit_flow(args)
    elif args.command == "harden-response":
        handle_harden_response(args)
    elif args.command == "export-nginx":
        handle_export_nginx(args)


if __name__ == "__main__":
    main()
