# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 126: AŞAMA 5 KALİTE DENETİMİ VE KABUL CLI ARACI
---------------------------------------------------
Bu komut satırı aracı, kurumsal bir sistemin kriptografik ve mimari şartnamesini
denetler, puanlar ve Aşama 5 Kalite Kabul Sertifikası üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü
import argparse
# Sistem çıkışları ve parametreler için sys modülü
import sys
# Dosya varlık denetimleri ve yol birleştirme için os modülü
import os
# JSON formatındaki şartnameleri okumak ve yazmak için json modülü
import json
# Tip ipuçları için typing modülü
from typing import Optional, List, Dict, Any

# Çekirdek motor sınıflarını içe aktarıyoruz
from stage5_quality_engine import (
    Stage5QualityAuditor,
    CryptographicComponentSpec,
    ArchitecturalControlSpec,
    StageAcceptanceDecision,
    Stage5QualityEngineError
)


def load_spec_from_file(file_path: str) -> Dict[str, Any]:
    """JSON dosyasından mimari şartnameyi okur."""
    # Dosyanın varlığını kontrol ediyoruz
    if not os.path.exists(file_path):
        # Dosya yoksa hata fırlatıyoruz
        raise FileNotFoundError(f"Şartname dosyası bulunamadı: {file_path}")
    # Dosyayı okuma modunda açıyoruz
    with open(file_path, "r", encoding="utf-8") as f:
        # JSON içeriğini yüklüyoruz
        return json.load(f)


def handle_audit(args: argparse.Namespace) -> int:
    """Tam Aşama 5 denetimini icra eder."""
    try:
        # Şartname dosyasını okuyoruz
        raw_data = load_spec_from_file(args.spec_file)

        # Kripto bileşenlerini dönüştürüyoruz
        crypto_components: List[CryptographicComponentSpec] = []
        # Kripto listesini dolaşıyoruz
        for c in raw_data.get("kriptografik_bilesenler", []):
            # Bileşen nesnesi oluşturuyoruz
            comp = CryptographicComponentSpec(
                component_name=c.get("component_name", "Bileşen"),
                cipher_or_hash_algorithm=c.get("algorithm", "AES-256-GCM"),
                key_or_digest_bits=int(c.get("key_bits", 256)),
                mode_of_operation=c.get("mode"),
                pbkdf2_iterations=c.get("iterations"),
                random_source=c.get("random_source", "CSPRNG"),
                uses_constant_time_compare=bool(c.get("constant_time", True))
            )
            # Listeye ekliyoruz
            crypto_components.append(comp)

        # Mimari kontrolleri alıyoruz
        arch_raw = raw_data.get("mimari_kontroller", {})
        # Mimari şartname nesnesi oluşturuyoruz
        arch_spec = ArchitecturalControlSpec(
            control_name=arch_raw.get("control_name", "Temel Güvenlik Mimarisi"),
            defense_layers_covered=arch_raw.get("layers", []),
            control_types=arch_raw.get("control_types", []),
            default_deny_enforced=bool(arch_raw.get("default_deny", True)),
            fail_secure_on_outage=bool(arch_raw.get("fail_secure", True)),
            static_sod_enforced=bool(arch_raw.get("sod_enforced", True)),
            wildcard_permissions_allowed=bool(arch_raw.get("wildcard_allowed", False)),
            log_masking_enabled=bool(arch_raw.get("log_masking", True))
        )

        # Denetçi motorunu başlatıyoruz
        auditor = Stage5QualityAuditor()
        # Tam denetimi icra ediyoruz
        result = auditor.perform_full_stage5_audit(
            target_system_name=raw_data.get("sistem_adi", "Hedef Sistem"),
            crypto_specs=crypto_components,
            arch_spec=arch_spec,
            has_executable_tests=bool(raw_data.get("birim_testler_mevcut", True)),
            has_negative_controls=bool(raw_data.get("negatif_kontroller_mevcut", True))
        )

        # Çıktı formatına göre ekrana basıyoruz
        if args.format == "markdown":
            # Markdown kalite sertifikasını basıyoruz
            print(auditor.generate_markdown_certificate(result))
        else:
            # JSON formatında basıyoruz
            output_dict = {
                "audit_id": result.audit_id,
                "timestamp": result.timestamp,
                "target_system": result.target_system_name,
                "crypto_score": result.crypto_score,
                "architecture_score": result.architecture_score,
                "governance_score": result.governance_score,
                "overall_quality_score": result.overall_quality_score,
                "decision": result.decision.value,
                "findings": result.critical_findings,
                "cwe_violations": result.cwe_violations
            }
            # Ekrana girintili JSON basıyoruz
            print(json.dumps(output_dict, ensure_ascii=False, indent=2))

        # Kabul kararına göre çıkış kodu döndürüyoruz
        return 0 if result.decision == StageAcceptanceDecision.ACCEPTED_PASS else 2

    except Exception as exc:
        # Beklenmeyen hata durumunda stderr'e yazdırıyoruz
        print(f"[-] DENETİM HATASI: {exc}", file=sys.stderr)
        # Hata kodu 1 döndürüyoruz
        return 1


def handle_verify_crypto(args: argparse.Namespace) -> int:
    """Münferit bir kriptografik algoritma ve anahtar boyutunu doğrular."""
    # Denetçi motorunu başlatıyoruz
    auditor = Stage5QualityAuditor()
    # Tek bir bileşen şartnamesi oluşturuyoruz
    comp = CryptographicComponentSpec(
        component_name="QuickCheck",
        cipher_or_hash_algorithm=args.algorithm,
        key_or_digest_bits=args.key_bits,
        mode_of_operation=args.mode,
        random_source=args.random_source
    )
    # Kripto değerlendirmesi yapıyoruz
    score, findings, cwes = auditor.evaluate_crypto_suite([comp])

    # Sonuçları ekrana basıyoruz
    print("=== Kriptografik Uyumluluk Doğrulaması ===")
    print(f"Algoritma: {args.algorithm}")
    print(f"Anahtar/Özet Boyutu: {args.key_bits} bit")
    print(f"Mod: {args.mode or 'N/A'}")
    print(f"Rastgelelik Kaynağı: {args.random_source}")
    print(f"Puan: {score} / 100")
    # Bulguları ekrana basıyoruz
    if findings:
        print("\n[!] TESPİT EDİLEN BULGULAR:")
        for f in findings:
            print(f"  - {f}")
    else:
        print("\n[+] Algoritma ve parametreler NIST SP 800-131A standartlarına tam uygundur.")

    # Puan 85 ve üzeriyse başarı dönüyoruz
    return 0 if score >= 85 else 3


def main(argv: Optional[List[str]] = None) -> None:
    """Komut satırı ana giriş noktası."""
    # Argüman ayrıştırıcıyı kuruyoruz
    parser = argparse.ArgumentParser(description="Gün 126: Aşama 5 Kalite Denetimi ve Kabul CLI Aracı")
    # Alt komut yöneticisini ekliyoruz
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 1. 'audit' komutu
    audit_parser = subparsers.add_parser("audit", help="Tam Aşama 5 denetimini icra et")
    audit_parser.add_argument("spec_file", help="JSON mimari şartname dosya yolu")
    audit_parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Çıktı formatı")

    # 2. 'verify-crypto' komutu
    crypto_parser = subparsers.add_parser("verify-crypto", help="Kriptografik algoritmayı ve parametrelerini doğrula")
    crypto_parser.add_argument("--algorithm", required=True, help="Algoritma adı (örn: AES-256-GCM, MD5)")
    crypto_parser.add_argument("--key-bits", type=int, required=True, help="Anahtar boyutu (bit)")
    crypto_parser.add_argument("--mode", default=None, help="Çalışma modu (GCM, CBC, ECB)")
    crypto_parser.add_argument("--random-source", default="CSPRNG", help="Rastgelelik kaynağı (CSPRNG, PRNG)")

    # Argümanları ayrıştırıyoruz
    args = parser.parse_args(argv)

    # Komuta göre ilgili işleyiciyi çağırıyoruz
    if args.command == "audit":
        sys.exit(handle_audit(args))
    elif args.command == "verify-crypto":
        sys.exit(handle_verify_crypto(args))
    else:
        parser.print_help()
        sys.exit(1)


# Betik doğrudan çalıştırıldığında main() çağrılır
if __name__ == "__main__":
    main()
