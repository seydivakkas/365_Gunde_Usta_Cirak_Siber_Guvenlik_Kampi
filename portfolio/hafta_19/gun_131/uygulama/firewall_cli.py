# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 131: WINDOWS DEFENDER FIREWALL CLI YÖNETİM ARACI
---------------------------------------------------
Bu CLI aracı, sistem güvenlik duvarı profilleri ve kuralları JSON spesifikasyonunu
ayrıştırır, CIS standartlarına göre teftiş eder ve PowerShell/netsh sertleştirme
betikleri üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü
import argparse
# JSON verilerini okumak ve serileştirmek için json modülü
import json
# Sistem çıkış kodları için sys modülü
import sys
# Dosya ve yol denetimleri için os modülü
import os

# Kök dizini sys.path'e ekleyerek hem doğrudan hem de paket üzerinden çalışmayı garantiye alıyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from uygulama.windows_firewall_engine import (
        WindowsFirewallEngine,
        FirewallProfileType,
        FirewallAction,
        FirewallProfileConfig,
        FirewallRule,
        SystemFirewallSpec,
        FirewallAuditResult
    )
except ImportError:
    from windows_firewall_engine import (
        WindowsFirewallEngine,
        FirewallProfileType,
        FirewallAction,
        FirewallProfileConfig,
        FirewallRule,
        SystemFirewallSpec,
        FirewallAuditResult
    )


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını inşa eder."""
    parser = argparse.ArgumentParser(
        prog="firewall_cli",
        description="Windows Defender Güvenlik Duvarı CIS Sıkılaştırma Aracı"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="Güvenlik duvarı JSON spesifikasyon dosyasını denetler")
    audit_parser.add_argument("--spec", required=True, help="Yapılandırma JSON dosya yolu")
    audit_parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Çıktı formatı")

    # 2. 'remediate' alt komutu
    rem_parser = subparsers.add_parser("remediate", help="PowerShell/netsh sıkılaştırma betiğini ekrana veya dosyaya yazar")
    rem_parser.add_argument("--spec", required=True, help="Yapılandırma JSON dosya yolu")
    rem_parser.add_argument("--out", help="Betiğin yazılacağı dosya yolu (.ps1)")

    # 3. 'profiles-info' alt komutu
    subparsers.add_parser("profiles-info", help="Windows Firewall ağ profilleri (Domain/Private/Public) güvenlik standartlarını listeler")

    return parser


def parse_firewall_spec_from_dict(data: dict) -> SystemFirewallSpec:
    """Sözlük verisini SystemFirewallSpec nesnesine dönüştürür."""
    target_host = data.get("target_host", "LOCAL-ENDPOINT")
    profiles_dict: dict = {}

    for p_name, p_data in data.get("profiles", {}).items():
        # Profil türünü Enum ile eşleştiriyoruz
        p_enum = None
        for pt in FirewallProfileType:
            if pt.value.lower() == p_name.lower():
                p_enum = pt
                break

        if not p_enum:
            continue

        in_action = FirewallAction.BLOCK if p_data.get("default_inbound_action", "Block").lower() == "block" else FirewallAction.ALLOW
        out_action = FirewallAction.BLOCK if p_data.get("default_outbound_action", "Allow").lower() == "block" else FirewallAction.ALLOW

        profiles_dict[p_enum] = FirewallProfileConfig(
            profile_type=p_enum,
            enabled=p_data.get("enabled", True),
            default_inbound_action=in_action,
            default_outbound_action=out_action,
            allow_inbound_rules=p_data.get("allow_inbound_rules", True),
            allow_local_firewall_rules=p_data.get("allow_local_firewall_rules", False),
            log_blocked=p_data.get("log_blocked", True),
            log_allowed=p_data.get("log_allowed", False),
            log_file_size_kb=p_data.get("log_file_size_kb", 16384)
        )

    rules_list: list = []
    for r_data in data.get("rules", []):
        r_action = FirewallAction.BLOCK if r_data.get("action", "Allow").lower() == "block" else FirewallAction.ALLOW
        rule_profs = []
        for p_str in r_data.get("profiles", []):
            for pt in FirewallProfileType:
                if pt.value.lower() == p_str.lower():
                    rule_profs.append(pt)
                    break

        rules_list.append(FirewallRule(
            rule_name=r_data.get("rule_name", "CustomRule"),
            direction=r_data.get("direction", "Inbound"),
            action=r_action,
            enabled=r_data.get("enabled", True),
            profiles=rule_profs,
            protocol=r_data.get("protocol", "TCP"),
            local_port=r_data.get("local_port", "Any"),
            remote_address=r_data.get("remote_address", "Any")
        ))

    return SystemFirewallSpec(target_host=target_host, profiles=profiles_dict, rules=rules_list)


def main() -> int:
    """CLI giriş noktası fonksiyonu."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    engine = WindowsFirewallEngine()

    if args.command == "profiles-info":
        print("=== WINDOWS DEFENDER GÜVENLİK DUVARI AĞ PROFİLLERİ REHBERİ ===")
        print("1. Domain Profile:")
        print("   - Makine Active Directory etki alanına bağlıyken devrededir.")
        print("   - Varsayılan Gelen: Block, Giden: Allow, LogBlocked: True (16MB).")
        print("2. Private Profile:")
        print("   - Ev veya kurumsal güvenli yerel ağlarda devrededir.")
        print("   - Varsayılan Gelen: Block, Giden: Allow, Dosya paylaşımı sınırlı.")
        print("3. Public Profile:")
        print("   - Kafe, havaalanı veya doğrudan internete açık güvensiz ağlarda devrededir.")
        print("   - Varsayılan Gelen: Block, Gelen istisnalar: False, RDP/SMB portları KESİNLİKLE KAPALI.")
        return 0

    if not os.path.exists(args.spec):
        print(f"[!] HATA: Belirtilen spec dosyası bulunamadı: {args.spec}", file=sys.stderr)
        return 1

    with open(args.spec, "r", encoding="utf-8") as f:
        spec_data = json.load(f)

    spec = parse_firewall_spec_from_dict(spec_data)
    result = engine.audit_firewall(spec)

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
                        "powershell": f.powershell_remediation,
                        "netsh": f.netsh_remediation
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
