# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 129: WINDOWS YEREL HESAPLAR VE UAC CLI YÖNETİM ARACI
-------------------------------------------------------
Bu CLI aracı, uç nokta hesap ve UAC yapılandırma JSON verilerini ayrıştırır,
CIS Benchmark standartlarına göre teftiş eder ve PowerShell sertleştirme betikleri üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü
import argparse
# JSON verilerini okumak ve ayrıştırmak için json modülü
import json
# Sistem çıkış kodları için sys modülü
import sys
# Dosya ve yol denetimleri için os modülü
import os

# Kök dizini sys.path'e ekleyerek bağımsız çalışmayı garantiye alıyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.uac_account_security_engine import (
        UACAccountSecurityEngine,
        LocalAccountConfig,
        UACConfig,
        LocalGroupConfig,
        EndpointAccountSpec,
        UACAuditResult
    )
except ImportError:
    from uac_account_security_engine import (
        UACAccountSecurityEngine,
        LocalAccountConfig,
        UACConfig,
        LocalGroupConfig,
        EndpointAccountSpec,
        UACAuditResult
    )


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını inşa eder."""
    parser = argparse.ArgumentParser(
        prog="uac_security_cli",
        description="Windows Yerel Hesaplar, Gruplar ve UAC CIS Sıkılaştırma Aracı"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="Hesap ve UAC yapılandırma JSON dosyasını denetler")
    audit_parser.add_argument("--spec", required=True, help="Yapılandırma JSON dosya yolu")
    audit_parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Çıktı formatı")

    # 2. 'remediate' alt komutu
    rem_parser = subparsers.add_parser("remediate", help="PowerShell sıkılaştırma betiğini ekrana veya dosyaya yazar")
    rem_parser.add_argument("--spec", required=True, help="Yapılandırma JSON dosya yolu")
    rem_parser.add_argument("--out", help="Betiğin yazılacağı dosya yolu (.ps1)")

    # 3. 'uac-inspect' alt komutu
    subparsers.add_parser("uac-inspect", help="UAC kayıt defteri değerleri ve güvenlik açıklamaları tablosunu listeler")

    return parser


def parse_spec_from_dict(data: dict) -> EndpointAccountSpec:
    """Sözlük verisini EndpointAccountSpec veri yapısına dönüştürür."""
    # Hesap ayarlarını ayrıştırıyoruz
    acc_data = data.get("accounts", {})
    accounts = LocalAccountConfig(
        guest_account_enabled=acc_data.get("guest_account_enabled", False),
        builtin_admin_name=acc_data.get("builtin_admin_name", "Administrator"),
        builtin_admin_disabled=acc_data.get("builtin_admin_disabled", True),
        account_lockout_threshold=acc_data.get("account_lockout_threshold", 5),
        account_lockout_duration_mins=acc_data.get("account_lockout_duration_mins", 15),
        reset_lockout_counter_mins=acc_data.get("reset_lockout_counter_mins", 15),
        laps_enabled=acc_data.get("laps_enabled", True)
    )

    # UAC ayarlarını ayrıştırıyoruz
    uac_data = data.get("uac", {})
    uac = UACConfig(
        enable_lua=uac_data.get("enable_lua", True),
        filter_administrator_token=uac_data.get("filter_administrator_token", True),
        consent_prompt_behavior_admin=uac_data.get("consent_prompt_behavior_admin", 2),
        consent_prompt_behavior_user=uac_data.get("consent_prompt_behavior_user", 0),
        prompt_on_secure_desktop=uac_data.get("prompt_on_secure_desktop", True),
        enable_virtualization=uac_data.get("enable_virtualization", True),
        validate_admin_code_signatures=uac_data.get("validate_admin_code_signatures", False)
    )

    # Grup ayarlarını ayrıştırıyoruz
    grp_data = data.get("groups", {})
    groups = LocalGroupConfig(
        administrators_members=grp_data.get("administrators_members", []),
        remote_desktop_members=grp_data.get("remote_desktop_members", []),
        backup_operators_members=grp_data.get("backup_operators_members", [])
    )

    target_host = data.get("target_host", "LOCAL-ENDPOINT")
    return EndpointAccountSpec(target_host=target_host, accounts=accounts, uac=uac, groups=groups)


def main() -> int:
    """CLI giriş noktası fonksiyonu."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    engine = UACAccountSecurityEngine()

    if args.command == "uac-inspect":
        print("=== WINDOWS UAC (KULLANICI HESABI DENETİMİ) KAYIT DEFTERİ DEĞERLERİ REHBERİ ===")
        print("1. EnableLUA:")
        print("   - 1 = UAC Aktif (Standart / Zorunlu)")
        print("   - 0 = UAC Devre Dışı (Kritik Zaaf / CWE-693)")
        print("2. FilterAdministratorToken:")
        print("   - 1 = Yerleşik Administrator için Yönetici Onay Modu Açık (CIS)")
        print("   - 0 = Yerleşik Administrator UAC'yi doğrudan bypass eder (CWE-250)")
        print("3. PromptOnSecureDesktop:")
        print("   - 1 = Onay Güvenli Masaüstünde Açılır (Winlogon izole / Clickjacking korumalı)")
        print("   - 0 = Normal masaüstünde açılır (Güvensiz)")
        print("4. ConsentPromptBehaviorAdmin:")
        print("   - 2 = Güvenli masaüstünde izin istemi (CIS Önerisi)")
        print("   - 1 = Parola istemi")
        print("   - 0 = İstemeden doğrudan yükselt (Aşırı Güvensiz)")
        print("   - 5 = Windows harici ikililer için istem (Varsayılan/Gevşek)")
        print("5. ConsentPromptBehaviorUser:")
        print("   - 0 = Yükseltme taleplerini otomatik reddet (CIS)")
        print("   - 3 = Güvenli masaüstünde kimlik bilgisi iste")
        return 0

    if not os.path.exists(args.spec):
        print(f"[!] HATA: Belirtilen spec dosyası bulunamadı: {args.spec}", file=sys.stderr)
        return 1

    with open(args.spec, "r", encoding="utf-8") as f:
        spec_data = json.load(f)

    spec = parse_spec_from_dict(spec_data)
    result = engine.audit_endpoint(spec)

    if args.command == "audit":
        if args.format == "markdown":
            print(engine.export_markdown_report(result))
        else:
            json_output = {
                "audit_id": result.audit_id,
                "timestamp": result.timestamp,
                "target_host": result.target_host,
                "score": result.security_score,
                "posture": result.posture_status,
                "findings": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe_id,
                        "mitre": f.mitre_technique_id,
                        "current": str(f.current_value),
                        "recommended": str(f.recommended_value),
                        "powershell": f.powershell_remediation
                    }
                    for f in result.findings
                ]
            }
            print(json.dumps(json_output, indent=2, ensure_ascii=False))
        return 0

    elif args.command == "remediate":
        if args.out:
            with open(args.out, "w", encoding="utf-8") as out_f:
                out_f.write(result.remediation_script)
            print(f"[+] PowerShell sertleştirme betiği kaydedildi: {args.out}")
        else:
            print(result.remediation_script)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
