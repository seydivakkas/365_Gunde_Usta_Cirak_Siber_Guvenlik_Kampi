# -*- coding: utf-8 -*-
"""
Gün 166: SSRF Savunma CLI Denetim Aracı (ssrf_defense_cli.py)

Bu komut satırı aracı; hedef URL'lerin SSRF risklerini denetler, gizlenmiş IP
biçimlerini (Integer, Hex, Octal) çözümler, güvenli ve zafiyetli HTTP getirme
işlemlerini simüle eder ve kurumsal ağ koruma raporunu üretir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import sys  # Sistem argümanları ve çıkış kodları için
import json  # JSON biçimlendirme ve yapılandırılmış çıktı için
import argparse  # Komut satırı argümanlarını ayrıştırmak için

# Uygulama motorundan bileşenler içe aktarılır
from ssrf_defense_engine import (
    SSRFDefenseEngine,  # Merkezi savunma motoru
    MockInternalNetwork,  # Sanal iç ağ
    MockSafeHTTPClient,  # Güvenli HTTP istemcisi
    EnterpriseSSRFPolicy  # Kurumsal politika
)


def handle_validate_url(args: argparse.Namespace) -> int:
    """Verilen URL'yi kurumsal SSRF politikasına göre analiz eder."""
    # Motor örneği başlatılır
    engine = SSRFDefenseEngine()
    # URL denetlenir
    res = engine.validate_url(args.url)

    # Sonuç raporu derlenir
    report = {
        "target_url": res.target_url,
        "is_safe": res.is_safe,
        "scheme": res.scheme,
        "resolved_ips": res.resolved_ips,
        "risk_type": res.risk_type.value if res.risk_type else None,
        "rejection_reason": res.rejection_reason,
        "details": res.details,
        "verdict": "GÜVENLİ (TALEP İLETİLEBİLİR)" if res.is_safe else "TEHDİT ENGELLENDİ (SSRF_BLOCKED)"
    }
    # Ekrana JSON formatında yazdırılır
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def handle_safe_fetch(args: argparse.Namespace) -> int:
    """Güvenli HTTP istemcisi üzerinden istek icra eder ve yönlendirmeleri izler."""
    engine = SSRFDefenseEngine()
    mock_net = MockInternalNetwork()
    client = MockSafeHTTPClient(engine=engine, mock_net=mock_net)

    # Güvenli getirme çağrılır
    resp = client.safe_fetch(args.url)

    output = {
        "url": args.url,
        "status_code": resp.status_code,
        "is_blocked": resp.is_blocked,
        "block_reason": resp.block_reason,
        "redirect_history": resp.redirect_history,
        "response_body_sample": resp.body[:200]
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def handle_simulate_attack(args: argparse.Namespace) -> int:
    """Zafiyetli ve güvenli istemcilerin aynı saldırgan URL'sine tepkisini kıyaslar."""
    engine = SSRFDefenseEngine()
    mock_net = MockInternalNetwork()
    client = MockSafeHTTPClient(engine=engine, mock_net=mock_net)

    # 1. Zafiyetli istemcide denenir
    vuln_resp = client.vulnerable_fetch(args.target_url)

    # 2. Güvenli istemcide denenir
    sec_resp = client.safe_fetch(args.target_url)

    comparison = {
        "attacker_target_url": args.target_url,
        "vulnerable_client_outcome": {
            "status_code": vuln_resp.status_code,
            "data_leaked": not vuln_resp.is_blocked and vuln_resp.status_code == 200,
            "response_snippet": vuln_resp.body[:150],
            "verdict": "İÇ AĞ VERİSİ SIZDIRILDI (SSRF BAŞARILI!)" if vuln_resp.status_code == 200 else "İşlem Sonlandı"
        },
        "secure_client_outcome": {
            "status_code": sec_resp.status_code,
            "is_blocked": sec_resp.is_blocked,
            "block_reason": sec_resp.block_reason,
            "verdict": "SALDIRI ENGELLENDİ (403 Forbidden - SSRF Önleme Katmanı Aktif)" if sec_resp.is_blocked else "İzin Verildi"
        }
    }
    print(json.dumps(comparison, indent=2, ensure_ascii=False))
    return 0


def handle_parse_ip(args: argparse.Namespace) -> int:
    """Gizlenmiş bir IP formatını (Integer, Hex, Octal) çözümler."""
    engine = SSRFDefenseEngine()
    parsed_ip = engine.parse_obfuscated_ip(args.host)

    result = {
        "input_host": args.host,
        "is_obfuscated_ip": parsed_ip is not None,
        "normalized_ip": str(parsed_ip) if parsed_ip else None
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Gün 166: SSRF Savunma ve Ağ Güvenliği Denetim Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. validate-url alt komutu
    p_val = subparsers.add_parser("validate-url", help="Bir URL'yi SSRF risklerine karşı inceler")
    p_val.add_argument("--url", type=str, required=True, help="İncelenecek hedef URL")

    # 2. safe-fetch alt komutu
    p_fetch = subparsers.add_parser("safe-fetch", help="Güvenli HTTP getirme işlemini simüle eder")
    p_fetch.add_argument("--url", type=str, required=True, help="Getirilecek hedef URL")

    # 3. simulate-attack alt komutu
    p_sim = subparsers.add_parser("simulate-attack", help="Zafiyetli ve güvenli motorları karşılaştırır")
    p_sim.add_argument("--target-url", type=str, default="http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role", help="Saldırı hedefi URL")

    # 4. parse-ip alt komutu
    p_ip = subparsers.add_parser("parse-ip", help="Gizlenmiş IP biçimlerini çözümler")
    p_ip.add_argument("--host", type=str, required=True, help="Çözümlenecek ana makine dizesi (örn: 2130706433)")

    args = parser.parse_args()

    if args.subcommand == "validate-url":
        return handle_validate_url(args)
    elif args.subcommand == "safe-fetch":
        return handle_safe_fetch(args)
    elif args.subcommand == "simulate-attack":
        return handle_simulate_attack(args)
    elif args.subcommand == "parse-ip":
        return handle_parse_ip(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
