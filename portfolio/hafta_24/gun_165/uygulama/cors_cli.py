# -*- coding: utf-8 -*-
"""
Gün 165: CORS ile Güvenlik Sınırı CLI Denetim Aracı (cors_cli.py)

Bu komut satırı aracı; gelen HTTP Origin başlıklarının kurumsal CORS politikasına
uygunluğunu denetler, Preflight (OPTIONS) isteklerini simüle eder, zafiyetli
CORS yapılandırmalarını (arbitrary reflection, null origin, regex bypass) test eder
ve kurumsal güvenlik başlıklarını raporlar.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import sys  # Sistem argümanları ve çıkış kodları için
import json  # JSON çıktısı ve yapılandırma işleme için
import argparse  # Komut satırı argümanlarını ayrıştırmak için
from typing import Dict, Any  # Tip ipuçları için

# Uygulama motorundan bileşenler içe aktarılır
from cors_engine import (
    CORSDefenseEngine,  # Merkezi savunma motoru
    CORSRequest,  # İstek nesnesi
    EnterpriseCORSPolicy  # Kurumsal politika
)


def handle_evaluate_origin(args: argparse.Namespace) -> int:
    """Belirtilen kökeni kurumsal CORS politikasına göre değerlendirir."""
    # Savunma motoru başlatılır
    engine = CORSDefenseEngine()
    # Test isteği oluşturulur
    req = CORSRequest(
        method="GET",
        path="/api/kullanici/profil",
        origin=args.origin
    )
    # Güvenli işleyici çağrılır
    resp = engine.secure_cors_handler(req)

    # Sonuç raporu derlenir
    report = {
        "candidate_origin": args.origin,
        "normalized_origin": engine.normalize_origin(args.origin),
        "status_code": resp.status_code,
        "is_cross_origin_allowed": resp.is_cross_origin_allowed,
        "returned_headers": resp.headers,
        "verdict": "ERİŞİM ONAYLANDI (ALLOW)" if resp.is_cross_origin_allowed else "ERİŞİM ENGELLENDİ (DENY)"
    }
    # Ekrana yazdırılır
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def handle_test_preflight(args: argparse.Namespace) -> int:
    """Preflight OPTIONS isteğini simüle eder ve başlıkları doğrular."""
    # Savunma motoru başlatılır
    engine = CORSDefenseEngine()
    # Preflight isteği oluşturulur
    req = CORSRequest(
        method="OPTIONS",
        path="/api/transfer",
        origin=args.origin,
        access_control_request_method=args.request_method,
        access_control_request_headers=args.request_headers
    )
    # Güvenli işleyici çalıştırılır
    resp = engine.secure_cors_handler(req)

    # Rapor hazırlanır
    report = {
        "origin": args.origin,
        "preflight_method": args.request_method,
        "preflight_headers": args.request_headers,
        "status_code": resp.status_code,
        "preflight_approved": resp.is_cross_origin_allowed,
        "returned_cors_headers": resp.headers
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def handle_simulate_misconfig(args: argparse.Namespace) -> int:
    """Zafiyetli ve güvenli sunucuların aynı saldırgan kökenine verdiği yanıtları karşılaştırır."""
    # Savunma motoru başlatılır
    engine = CORSDefenseEngine()
    # Saldırgan isteği oluşturulur
    attack_req = CORSRequest(
        method="GET",
        path="/api/gizli-finansal-rapor",
        origin=args.attacker_origin
    )

    # 1. Zafiyetli sunucuda denenir
    vuln_resp = engine.vulnerable_cors_handler(attack_req)

    # 2. Güvenli kurumsal sunucuda denenir
    sec_resp = engine.secure_cors_handler(attack_req)

    comparison = {
        "attacker_origin": args.attacker_origin,
        "target_endpoint": "/api/gizli-finansal-rapor",
        "vulnerable_server_response": {
            "status_code": vuln_resp.status_code,
            "headers": vuln_resp.headers,
            "data_leaked": vuln_resp.is_cross_origin_allowed,
            "risks_detected": [r.value for r in vuln_resp.detected_risks],
            "outcome": "VERİ SALDIRGANA SIZDIRILDI! (CORS Misconfiguration)" if vuln_resp.is_cross_origin_allowed else "Engellendi"
        },
        "secure_server_response": {
            "status_code": sec_resp.status_code,
            "headers": sec_resp.headers,
            "data_leaked": sec_resp.is_cross_origin_allowed,
            "risks_detected": [r.value for r in sec_resp.detected_risks],
            "outcome": "ERİŞİM ENGELLENDİ (403 Forbidden - CORS Güvenlik Sınırı Korundu)" if not sec_resp.is_cross_origin_allowed else "Hata"
        }
    }
    print(json.dumps(comparison, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Gün 165: CORS ile Güvenlik Sınırı Denetim ve Simülasyon Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. evaluate-origin alt komutu
    p_eval = subparsers.add_parser("evaluate-origin", help="Bir kökeni kurumsal CORS politikasına göre değerlendirir")
    p_eval.add_argument("--origin", type=str, required=True, help="Değerlendirilecek HTTP Origin başlığı")

    # 2. test-preflight alt komutu
    p_pre = subparsers.add_parser("test-preflight", help="CORS Preflight OPTIONS isteğini simüle eder")
    p_pre.add_argument("--origin", type=str, default="https://portal.kurum.internal", help="İstek kökeni")
    p_pre.add_argument("--request-method", type=str, default="POST", help="Access-Control-Request-Method")
    p_pre.add_argument("--request-headers", type=str, default="content-type,authorization,x-csrf-token", help="Access-Control-Request-Headers")

    # 3. simulate-misconfig alt komutu
    p_sim = subparsers.add_parser("simulate-misconfig", help="Zafiyetli ve güvenli sunucuları karşılaştırır")
    p_sim.add_argument("--attacker-origin", type=str, default="https://evil-attacker.com", help="Saldırgan kökeni")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # Alt komut yönlendirmesi
    if args.subcommand == "evaluate-origin":
        return handle_evaluate_origin(args)
    elif args.subcommand == "test-preflight":
        return handle_test_preflight(args)
    elif args.subcommand == "simulate-misconfig":
        return handle_simulate_misconfig(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
