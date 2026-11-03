# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 123: Güvenli Varsayılanlar ve Fail-Safe CLI Aracı.
Bu araç komut satırından kaynak yapılandırmalarını CWE-1188 zaafiyetine karşı denetler,
Saltzer-Schroeder Default-Deny ve Fail-Secure mekanizmalarını test eder.
"""

# Komut satırı argümanları için argparse içe aktarılıyor
import argparse
# Sistem çıkışları ve parametreler için sys içe aktarılıyor
import sys
# JSON okuma ve yazma işlemleri için json içe aktarılıyor
import json
# Dosya varlığı kontrolleri için os modülü içe aktarılıyor
import os

# Çekirdek motor sınıfları içe aktarılıyor
from secure_defaults_failsafe_engine import (
    FailSafeSecurityManager,
    ResourceConfig,
    PolicyRule,
    AccessRequest,
    DecisionOutcome,
    FailureHandlingMode,
    FailureType,
    FailSafeEngineError
)


def load_manager_from_json(json_path: str) -> FailSafeSecurityManager:
    """JSON yapılandırma dosyasından yöneticisini yükler."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {json_path}")
    with open(json_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    fail_mode_str = data.get("failure_mode", "FAIL_SECURE")
    manager = FailSafeSecurityManager(
        system_name=data.get("system_name", "Kurumsal Sistem"),
        failure_mode=FailureHandlingMode[fail_mode_str],
        safety_override_token=data.get("safety_override_token")
    )

    for r_data in data.get("resources", []):
        res = ResourceConfig(
            resource_id=r_data["resource_id"],
            name=r_data["name"],
            default_access=r_data.get("default_access", "DENY"),
            debug_mode=bool(r_data.get("debug_mode", False)),
            enforce_tls=bool(r_data.get("enforce_tls", True)),
            is_default_credential_changed=bool(r_data.get("is_default_credential_changed", True)),
            cors_allow_all=bool(r_data.get("cors_allow_all", False)),
            storage_encrypted=bool(r_data.get("storage_encrypted", True))
        )
        manager.register_resource(res)

    for rl_data in data.get("rules", []):
        rule = PolicyRule(
            rule_id=rl_data["rule_id"],
            subject_role=rl_data["subject_role"],
            resource_id=rl_data["resource_id"],
            action=rl_data["action"],
            effect=DecisionOutcome[rl_data.get("effect", "PERMIT")]
        )
        manager.add_policy_rule(rule)

    return manager


def handle_audit(args: argparse.Namespace) -> int:
    """Güvenli varsayılanlar ve mimari uyum denetimini icra eder."""
    try:
        manager = load_manager_from_json(args.config)
        if args.format == "markdown":
            print(manager.generate_failsafe_report())
        elif args.format == "json":
            print(json.dumps(manager.export_summary_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"=== {manager.system_name} Güvenli Varsayılanlar Denetimi ===")
            passed, violations = manager.audit_secure_defaults()
            if passed:
                print("[+] MİMARİ UYUMLU: Tüm bileşenler 'Secure by Default' prensiplerine uygundur.")
            else:
                print(f"[-] DİKKAT: {len(violations)} adet güvenlik ihlali tespit edildi!")
                for v in violations:
                    print(f"  - {v}")
        if args.enforce:
            manager.enforce_secure_defaults()
        return 0
    except FailSafeEngineError as fse:
        print(f"[!] HATA: {fse}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[-] BEKLENMEYEN HATA: {exc}", file=sys.stderr)
        return 1


def handle_evaluate(args: argparse.Namespace) -> int:
    """Erişim talebini değerlendirir ve arıza durumunda Fail-Secure davranışını test eder."""
    try:
        manager = load_manager_from_json(args.config)
        req = AccessRequest(
            request_id=args.request_id,
            subject_id=args.subject_id,
            subject_role=args.role,
            resource_id=args.resource_id,
            action=args.action
        )
        sim_fail = FailureType[args.simulate_failure] if args.simulate_failure else None
        res = manager.evaluate_access(req, simulate_failure=sim_fail)

        print(f"=== Erişim Kararı: [{res.decision.value}] ===")
        print(f"Talep ID: {res.request_id}")
        print(f"Gerekçe: {res.reason}")
        if res.matched_rule_id:
            print(f"Eşleşen Kural: {res.matched_rule_id}")
        if res.is_fail_secure_intervention:
            print("[GÜVENCE] Fail-Secure mekanizması arıza anında erişimi güvenli kesti (CWE-636 Koruması).")
        return 0 if res.decision == DecisionOutcome.PERMIT else 3
    except Exception as exc:
        print(f"[-] HATA: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    """Komut satırı ana giriş noktası."""
    parser = argparse.ArgumentParser(description="Güvenli Varsayılanlar ve Fail-Safe CLI Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'audit' komutu
    audit_parser = subparsers.add_parser("audit", help="Yapılandırmayı CWE-1188 ve CWE-636 açısından denetle")
    audit_parser.add_argument("config", help="Yapılandırma JSON dosya yolu")
    audit_parser.add_argument("--format", choices=["text", "markdown", "json"], default="text", help="Çıktı formatı")
    audit_parser.add_argument("--enforce", action="store_true", help="İhlal varsa hata fırlat")

    # 2. 'evaluate' komutu
    eval_parser = subparsers.add_parser("evaluate", help="Erişim talebini değerlendir")
    eval_parser.add_argument("config", help="Yapılandırma JSON dosya yolu")
    eval_parser.add_argument("--request-id", default="REQ-001", help="Talep kimliği")
    eval_parser.add_argument("--subject-id", default="usr-101", help="Kullanıcı kimliği")
    eval_parser.add_argument("--role", required=True, help="Kullanıcı rolü")
    eval_parser.add_argument("--resource-id", required=True, help="Hedef kaynak")
    eval_parser.add_argument("--action", required=True, help="Hedef eylem (read/write vb.)")
    eval_parser.add_argument("--simulate-failure", choices=[f.name for f in FailureType], default=None,
                             help="Simüle edilecek sistem arızası tipi")

    args = parser.parse_args()
    if args.command == "audit":
        sys.exit(handle_audit(args))
    elif args.command == "evaluate":
        sys.exit(handle_evaluate(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
