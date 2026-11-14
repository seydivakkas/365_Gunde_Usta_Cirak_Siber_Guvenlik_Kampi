# -*- coding: utf-8 -*-
"""
Gün 167: Path Traversal CLI Denetim ve Test Aracı (path_traversal_cli.py)

Bu komut satırı aracı; dosya yollarının Dizin Atlama (Path Traversal) risklerini
inceler, çok geçişli URL kodlamalarını çözümler, kanonik hapis (Jail) sınırlarını
doğrular ve zafiyetli vs güvenli dosya okuma işlemlerini simüle eder.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import sys  # Sistem argümanları ve çıkış kodları için
import json  # JSON biçimlendirme ve yapılandırılmış çıktı için
import argparse  # Komut satırı argümanlarını ayrıştırmak için

# Uygulama motorundan bileşenler içe aktarılır
from path_traversal_engine import (
    PathTraversalDefenseEngine,  # Merkezi savunma motoru
    EnterpriseStoragePolicy  # Kurumsal depolama politikası
)


def handle_validate_path(args: argparse.Namespace) -> int:
    """Verilen dosya yolunu kurumsal depolama politikasına göre analiz eder."""
    # Motor örneği başlatılır
    engine = PathTraversalDefenseEngine()
    # Yol doğrulanır
    res = engine.validate_path(args.path)

    report = {
        "raw_input_path": res.raw_input,
        "is_safe": res.is_safe,
        "decoded_path": res.decoded_path,
        "canonical_path": res.canonical_path,
        "risk_type": res.risk_type.value if res.risk_type else None,
        "rejection_reason": res.rejection_reason,
        "details": res.details,
        "verdict": "GÜVENLİ (ERİŞİME İZİN VERİLDİ)" if res.is_safe else "ENGEL: DİZİN ATLAMA TEHDİDİ REDDEDİLDİ"
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def handle_read_file(args: argparse.Namespace) -> int:
    """Güvenli dosya okuma motoru üzerinden içeriği getirir."""
    engine = PathTraversalDefenseEngine()
    resp = engine.secure_read_file(args.filename)

    output = {
        "requested_filename": args.filename,
        "status_code": resp["status_code"],
        "success": resp["success"],
        "error": resp["error"],
        "reason": resp["reason"],
        "file_content_snippet": resp["content"][:200] if resp["content"] else None
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def handle_simulate_attack(args: argparse.Namespace) -> int:
    """Zafiyetli ve güvenli dosya okuyucuların aynı saldırı girdisine tepkisini kıyaslar."""
    engine = PathTraversalDefenseEngine()

    # 1. Zafiyetli okuyucuda denenir
    vuln_resp = engine.vulnerable_read_file(args.payload)

    # 2. Güvenli okuyucuda denenir
    sec_resp = engine.secure_read_file(args.payload)

    comparison = {
        "attacker_payload": args.payload,
        "vulnerable_reader_outcome": {
            "status_code": vuln_resp["status_code"],
            "leak_occurred": vuln_resp["is_vulnerable_leak"],
            "accessed_path": vuln_resp["accessed_path"],
            "content_leaked": vuln_resp["content"][:150] if vuln_resp["content"] else None,
            "verdict": "SİSTEM DOSYASI SIZDIRILDI! (Path Traversal Zafiyeti)" if vuln_resp["is_vulnerable_leak"] else "Başarısız"
        },
        "secure_reader_outcome": {
            "status_code": sec_resp["status_code"],
            "access_blocked": not sec_resp["success"],
            "risk_type": sec_resp.get("risk_type"),
            "rejection_reason": sec_resp.get("reason"),
            "verdict": "ERİŞİM ENGELLENDİ (403 Forbidden - Kanonik Depo Sınırı Korundu)" if not sec_resp["success"] else "Açık!"
        }
    }
    print(json.dumps(comparison, indent=2, ensure_ascii=False))
    return 0


def handle_decode_path(args: argparse.Namespace) -> int:
    """Çok geçişli URL kodlama çözümlemesi yaparak çift kodlamaları ortaya çıkarır."""
    engine = PathTraversalDefenseEngine()
    decoded, was_single, was_double = engine.multi_pass_url_decode(args.encoded_string)

    result = {
        "input_encoded_string": args.encoded_string,
        "fully_decoded_string": decoded,
        "was_single_url_encoded": was_single,
        "was_double_url_encoded": was_double
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Gün 167: Path Traversal ve Dosya Erişimi Denetim Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. validate-path alt komutu
    p_val = subparsers.add_parser("validate-path", help="Bir dosya yolunu Traversal risklerine karşı denetler")
    p_val.add_argument("--path", type=str, required=True, help="İncelenecek dosya yolu")

    # 2. read-file alt komutu
    p_read = subparsers.add_parser("read-file", help="Güvenli motor üzerinden dosya okur")
    p_read.add_argument("--filename", type=str, required=True, help="Okunmak istenen dosya adı")

    # 3. simulate-attack alt komutu
    p_sim = subparsers.add_parser("simulate-attack", help="Zafiyetli ve güvenli okuyucuları karşılaştırır")
    p_sim.add_argument("--payload", type=str, default="../../../../etc/passwd", help="Saldırı yolu / payloadı")

    # 4. decode-path alt komutu
    p_dec = subparsers.add_parser("decode-path", help="Çift URL kodlamasını çözümler")
    p_dec.add_argument("--encoded-string", type=str, required=True, help="URL kodlu metin (örn: %252e%252e%252f)")

    args = parser.parse_args()

    if args.subcommand == "validate-path":
        return handle_validate_path(args)
    elif args.subcommand == "read-file":
        return handle_read_file(args)
    elif args.subcommand == "simulate-attack":
        return handle_simulate_attack(args)
    elif args.subcommand == "decode-path":
        return handle_decode_path(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
