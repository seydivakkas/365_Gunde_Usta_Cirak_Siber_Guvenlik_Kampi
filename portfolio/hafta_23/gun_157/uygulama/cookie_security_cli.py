# -*- coding: utf-8 -*-
"""
HTTP Cookies ve Güvenlik Bayrakları CLI Yönetim Aracı
Hafta 23 / Gün 157 - Aşama 7 (Web Güvenliği)

Bu araç; Set-Cookie yanıt başlıklarını veya kurumsal çerez şartnamelerini okur,
güvenlik bayraklarını (Secure, HttpOnly, SameSite, önekler) denetler,
zafiyetli çerezleri otomatik sertleştirir ve rapor üretir.
"""

import argparse
import json
import sys
import os

# Proje yolunu ekleme
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.cookie_security_engine import (
    CookieSecurityEngine,
    HttpCookie,
    SameSitePolicy,
    CookieType,
    FleetCookieReport
)


def handle_audit_header(args):
    """Tek bir Set-Cookie başlığını denetler ve sonuçları konsola basar."""
    engine = CookieSecurityEngine()
    cookie_type = CookieType(args.type) if args.type else CookieType.SESSION_AUTH
    cookie = HttpCookie.parse_set_cookie_header(args.header, cookie_type=cookie_type)
    
    rep = engine.audit_cookie(cookie)
    
    print("=" * 75)
    print(" TEKİL ÇEREZ GÜVENLİK DENETİMİ RAPORU")
    print("=" * 75)
    print(f" Çerez Adı           : {rep.cookie_name}")
    print(f" Çerez Türü          : {rep.cookie_type}")
    print(f" Güvenlik Skoru      : %{rep.security_score} / 100")
    print(f" Denetim Durumu      : [{rep.status}]")
    print(f" Orijinal Başlık     : {cookie.to_set_cookie_header()}")
    print(f" Sertleştirilmiş Öneri: {rep.hardened_header}")
    print("-" * 75)
    if rep.issues:
        print(" TESPİT EDİLEN GÜVENLİK AÇIKLARI:")
        for idx, issue in enumerate(rep.issues, 1):
            print(f"   {idx}. [{issue.severity}] {issue.code}: {issue.title}")
            print(f"      Açıklama  : {issue.description}")
            print(f"      İyileştirme: {issue.remediation}")
    else:
        print(" [BAŞARILI] Herhangi bir güvenlik açığı tespit edilmedi; çerez tam uyumludur.")
    print("=" * 75)


def handle_audit_spec(args):
    """JSON dosyasındaki çerez envanterini denetler."""
    if not os.path.exists(args.spec):
        print(f"[-] Hata: Belirtilen şartname dosyası bulunamadı: {args.spec}")
        sys.exit(1)

    with open(args.spec, "r", encoding="utf-8") as f:
        data = json.load(f)

    cookies = []
    # Liste veya sözlük formatını destekleme
    cookie_list = data if isinstance(data, list) else data.get("cookies", [])
    for c_data in cookie_list:
        c_type = CookieType(c_data.get("cookie_type", "SessionAuth"))
        s_site = SameSitePolicy(c_data.get("same_site", "Missing"))
        cookies.append(HttpCookie(
            name=c_data["name"],
            value=c_data.get("value", "dummy_token"),
            secure=c_data.get("secure", False),
            http_only=c_data.get("http_only", False),
            same_site=s_site,
            domain=c_data.get("domain"),
            path=c_data.get("path", "/"),
            max_age=c_data.get("max_age"),
            is_session_cookie=c_data.get("is_session_cookie", False),
            cookie_type=c_type,
            is_encrypted_or_opaque=c_data.get("is_encrypted_or_opaque", True)
        ))

    engine = CookieSecurityEngine()
    fleet_rep = engine.audit_fleet(cookies)

    # ASCII Çıktı
    print(engine.generate_ascii_audit(fleet_rep))

    # JSON Çıktısı istenmişse kaydetme
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        dict_data = engine.export_fleet_report_to_dict(fleet_rep)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(dict_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Filo denetim raporu JSON olarak kaydedildi: {args.output}")


def handle_harden(args):
    """Verilen Set-Cookie başlığını otomatik sertleştirerek güvenli halini basar."""
    cookie_type = CookieType(args.type) if args.type else CookieType.SESSION_AUTH
    cookie = HttpCookie.parse_set_cookie_header(args.header, cookie_type=cookie_type)
    engine = CookieSecurityEngine()
    hardened = engine.harden_cookie(cookie)
    print("=" * 75)
    print(" ORİJİNAL ÇEREZ BAŞLIĞI:")
    print(f"   {args.header}")
    print("-" * 75)
    print(" SERTLEŞTİRİLMİŞ (GÜVENLİ) ÇEREZ BAŞLIĞI:")
    print(f"   {hardened.to_set_cookie_header()}")
    print("=" * 75)


def handle_generate_set_cookie(args):
    """Parametrelerden kurumsal standartlara tam uyumlu Set-Cookie başlığı üretir."""
    name = args.name
    if args.type == "SessionAuth" and not name.startswith("__Host-") and not name.startswith("__Secure-"):
        name = f"__Host-{name}"
        
    cookie = HttpCookie(
        name=name,
        value=args.value,
        secure=True,
        http_only=True if args.type == "SessionAuth" else args.http_only,
        same_site=SameSitePolicy.STRICT if args.type == "SessionAuth" else SameSitePolicy.LAX,
        domain=None,
        path="/",
        max_age=args.max_age if args.max_age else 86400,
        cookie_type=CookieType(args.type),
        is_encrypted_or_opaque=True
    )
    print("=" * 75)
    print(" STANDARTLARA TAM UYUMLU ÜRETİLEN SET-COOKIE BAŞLIĞI:")
    print(f"   {cookie.to_set_cookie_header()}")
    print("=" * 75)


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="HTTP Cookies ve Güvenlik Bayrakları Denetim ve Sertleştirme CLI Aracı (Gün 157)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Alt komutlar")

    # 1. audit-header
    p_audit_hdr = subparsers.add_parser("audit-header", help="Tek bir Set-Cookie başlığını denetler")
    p_audit_hdr.add_argument("--header", required=True, help="Set-Cookie başlık metni")
    p_audit_hdr.add_argument("--type", default="SessionAuth", choices=["SessionAuth", "CsrfToken", "Preference", "Tracking"], help="Çerez türü")

    # 2. audit-spec
    p_audit_spec = subparsers.add_parser("audit-spec", help="JSON çerez şartnamesini denetler")
    p_audit_spec.add_argument("--spec", required=True, help="JSON çerez şartname dosya yolu")
    p_audit_spec.add_argument("--output", help="Raporun kaydedileceği JSON dosya yolu")

    # 3. harden
    p_harden = subparsers.add_parser("harden", help="Set-Cookie başlığını otomatik sertleştirir")
    p_harden.add_argument("--header", required=True, help="Orijinal Set-Cookie başlığı")
    p_harden.add_argument("--type", default="SessionAuth", choices=["SessionAuth", "CsrfToken", "Preference", "Tracking"], help="Çerez türü")

    # 4. generate-set-cookie
    p_gen = subparsers.add_parser("generate-set-cookie", help="Güvenli Set-Cookie başlığı üretir")
    p_gen.add_argument("--name", required=True, help="Çerez adı")
    p_gen.add_argument("--value", required=True, help="Çerez değeri")
    p_gen.add_argument("--type", default="SessionAuth", choices=["SessionAuth", "CsrfToken", "Preference", "Tracking"], help="Çerez türü")
    p_gen.add_argument("--max-age", type=int, default=86400, help="Saniye cinsinden çerez ömrü")
    p_gen.add_argument("--http-only", action="store_true", default=True, help="HttpOnly bayrağı")

    args = parser.parse_args()

    if args.subcommand == "audit-header":
        handle_audit_header(args)
    elif args.subcommand == "audit-spec":
        handle_audit_spec(args)
    elif args.subcommand == "harden":
        handle_harden(args)
    elif args.subcommand == "generate-set-cookie":
        handle_generate_set_cookie(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
