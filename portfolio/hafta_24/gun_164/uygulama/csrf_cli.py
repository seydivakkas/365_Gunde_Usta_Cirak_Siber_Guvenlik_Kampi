# -*- coding: utf-8 -*-
"""
Gün 164: CSRF ve Oturum Bağlamı CLI Denetim Aracı (csrf_cli.py)

Bu komut satırı aracı; Anti-CSRF belirteçlerinin üretimini, doğrulanmasını,
zafiyetli ve güvenli bankacılık transfer isteklerinin simülasyonunu ve
kurumsal çerez güvenlik başlıklarının analizini sağlar.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import sys  # Sistem argümanları ve çıkış kodları için
import json  # JSON işleme ve biçimli çıktı için
import argparse  # Komut satırı argümanlarını ayrıştırmak için
from typing import Dict, Any  # Tip ipuçları için

# Uygulama motorundan bileşenler içe aktarılır
from csrf_engine import (
    CSRFDefenseEngine,  # Merkezi CSRF savunma motoru
    HTTPRequest,  # HTTP istek veri sınıfı
    SameSiteMode,  # SameSite enum değerleri
    AntiCSRFTokenManager  # Belirteç yöneticisi
)


def handle_generate_token(args: argparse.Namespace) -> int:
    """Oturum için yeni bir kriptografik Anti-CSRF belirteci üretir."""
    # Savunma motoru örneği başlatılır
    engine = CSRFDefenseEngine()
    # Örnek kurban oturumu açılır
    session = engine.create_mock_session(user_id=args.user_id, username=args.username)
    # Belirteç üretilir
    token = engine.token_manager.generate_token(session)

    # Çıktı sözlüğü hazırlanır
    output = {
        "user_id": session.user_id,
        "username": session.username,
        "session_id": session.session_id,
        "csrf_token": token,
        "ttl_seconds": engine.token_manager.token_ttl,
        "format": "<session_id>.<timestamp>.<nonce>.<hmac_signature>"
    }
    # Ekrana JSON formatında yazdırılır
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def handle_simulate_attack(args: argparse.Namespace) -> int:
    """Zafiyetli ve güvenli transfer uç noktalarına karşı CSRF simülasyonu yürütür."""
    # Kurumsal savunma motoru başlatılır
    engine = CSRFDefenseEngine(enterprise_origin="https://banka.kurum.internal")
    # Kurban (Ahmet Kaya - ID 2, Bakiye: 15.000 TL) oturumu oluşturulur
    victim_session = engine.create_mock_session(user_id=2, username="ahmet_kaya")

    # Saldırganın sahte web sitesinden (evil-phishing.com) tetiklenen istek oluşturulur
    attack_request = HTTPRequest(
        method=args.method.upper(),
        path="/api/transfer",
        headers={
            "Host": "banka.kurum.internal",
            "Origin": args.origin,  # Saldırgan kökeni (veya meşru)
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MaliciousBrowser/1.0"
        },
        cookies={"session_id": victim_session.session_id},  # Tarayıcının gönderdiği Ambient Cookie!
        form_data={"target_account": 3, "amount": args.amount}  # Saldırgan Bob'a transfer
    )

    # 1. Zafiyetli uç noktada denenir
    vuln_resp = engine.vulnerable_transfer_funds(attack_request)

    # 2. Güvenli uç noktada denenir (Aynı istek güvenli sisteme iletilir)
    sec_resp = engine.secure_transfer_funds(attack_request)

    # Sonuç raporu derlenir
    comparison = {
        "victim_initial_balance": 15000.0,
        "transfer_amount": args.amount,
        "simulated_origin": args.origin,
        "http_method": args.method.upper(),
        "vulnerable_endpoint_result": {
            "status_code": vuln_resp["status_code"],
            "success": vuln_resp["success"],
            "outcome": "FONLAR ÇALINDI (CSRF BAŞARILI)" if vuln_resp["success"] else "İŞLEM REDDEDİLDİ",
            "victim_remaining_balance": engine.accounts[2]
        },
        "secure_endpoint_result": {
            "status_code": sec_resp["status_code"],
            "success": sec_resp["success"],
            "error_detail": sec_resp.get("error"),
            "outcome": "SALDIRI ENGELLENDİ (CSRF SAVUNULDU)" if not sec_resp["success"] else "AÇIK!"
        }
    }
    # Rapor yazdırılır
    print(json.dumps(comparison, indent=2, ensure_ascii=False))
    return 0


def handle_generate_cookie(args: argparse.Namespace) -> int:
    """Kurumsal SameSite ve güvenlik bayraklı çerez başlığı üretir."""
    # Motor örneği başlatılır
    engine = CSRFDefenseEngine()
    # Mod belirlenir
    mode = SameSiteMode(args.samesite)
    # Başlık dizesi üretilir
    header = engine.generate_cookie_header(session_id=args.session_id, samesite=mode)
    # Ekrana yazdırılır
    print(f"Set-Cookie: {header}")
    return 0


def main() -> int:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Gün 164: Anti-CSRF ve Oturum Bağlamı Denetim Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. generate-token alt komutu
    p_gen = subparsers.add_parser("generate-token", help="Oturum için Anti-CSRF belirteci üretir")
    p_gen.add_argument("--user-id", type=int, default=2, help="Kullanıcı kimlik numarası (varsayılan: 2)")
    p_gen.add_argument("--username", type=str, default="ahmet_kaya", help="Kullanıcı adı")

    # 2. simulate-attack alt komutu
    p_att = subparsers.add_parser("simulate-attack", help="CSRF saldırısı simülasyonu yürütür")
    p_att.add_argument("--method", type=str, default="POST", choices=["GET", "POST"], help="İstek yöntemi")
    p_att.add_argument("--origin", type=str, default="https://evil-attacker.site", help="Saldırgan kökeni (Origin)")
    p_att.add_argument("--amount", type=float, default=2500.0, help="Transfer edilecek bakiye miktarı")

    # 3. generate-cookie alt komutu
    p_cook = subparsers.add_parser("generate-cookie", help="SameSite çerez başlığı üretir")
    p_cook.add_argument("--session-id", type=str, default="sess_abcdef123456", help="Oturum kimliği")
    p_cook.add_argument("--samesite", type=str, choices=["Strict", "Lax", "None"], default="Strict", help="SameSite modu")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # Alt komut kontrolü
    if args.subcommand == "generate-token":
        return handle_generate_token(args)
    elif args.subcommand == "simulate-attack":
        return handle_simulate_attack(args)
    elif args.subcommand == "generate-cookie":
        return handle_generate_cookie(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
