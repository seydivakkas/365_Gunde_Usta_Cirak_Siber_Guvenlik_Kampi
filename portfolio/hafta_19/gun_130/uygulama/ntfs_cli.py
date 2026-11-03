# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ CLI YÖNETİM ARACI
-------------------------------------------------------
Bu CLI aracı, sistem dosya ve dizinlerinin NTFS ACL yapılandırma JSON verilerini
ayrıştırır, CIS standartlarına göre zayıf izinleri teftiş eder ve icacls/PowerShell
sıkılaştırma betikleri üretir.
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
    from uygulama.ntfs_acl_engine import (
        NTFSACLEngine,
        NTFSSecurityDescriptor,
        NTFSACE,
        ACEType,
        NTFSPermission,
        NTFSAuditResult
    )
except ImportError:
    from ntfs_acl_engine import (
        NTFSACLEngine,
        NTFSSecurityDescriptor,
        NTFSACE,
        ACEType,
        NTFSPermission,
        NTFSAuditResult
    )


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını inşa eder."""
    parser = argparse.ArgumentParser(
        prog="ntfs_cli",
        description="Windows NTFS Erişim Kontrol Listeleri (ACL/DACL) CIS Sıkılaştırma Aracı"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="NTFS ACL spesifikasyon dosyasını denetler")
    audit_parser.add_argument("--spec", required=True, help="NTFS ACL yapılandırma JSON dosya yolu")
    audit_parser.add_argument("--system", default="LOCAL-SYSTEM", help="Hedef sistem adı")
    audit_parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Çıktı formatı")

    # 2. 'remediate' alt komutu
    rem_parser = subparsers.add_parser("remediate", help="icacls/PowerShell sıkılaştırma betiğini ekrana veya dosyaya yazar")
    rem_parser.add_argument("--spec", required=True, help="NTFS ACL yapılandırma JSON dosya yolu")
    rem_parser.add_argument("--system", default="LOCAL-SYSTEM", help="Hedef sistem adı")
    rem_parser.add_argument("--out", help="Betiğin yazılacağı dosya yolu (.ps1 veya .bat)")

    # 3. 'ace-help' alt komutu
    subparsers.add_parser("ace-help", help="icacls izin sembolleri ve miras bayrakları rehberini listeler")

    return parser


def parse_descriptors_from_dict(data: dict) -> List[NTFSSecurityDescriptor]:
    """JSON sözlük listesini NTFSSecurityDescriptor nesneleri listesine dönüştürür."""
    items = data.get("descriptors", []) if isinstance(data, dict) else data
    result: List[NTFSSecurityDescriptor] = []

    for item in items:
        # DACL kurallarını ayrıştırıyoruz
        dacl_aces: List[NTFSACE] = []
        for a in item.get("dacl", []):
            # İzin haklarını Enum listesine çeviriyoruz
            rights_enums = []
            for r_str in a.get("rights", []):
                for p in NTFSPermission:
                    if p.value.lower() == r_str.lower() or p.name.lower() == r_str.lower():
                        rights_enums.append(p)
                        break

            # ACE türünü belirliyoruz
            ace_type_val = ACEType.ACCESS_ALLOWED
            for at in ACEType:
                if at.value.lower() == a.get("ace_type", "AccessAllowed").lower():
                    ace_type_val = at
                    break

            dacl_aces.append(NTFSACE(
                identity=a.get("identity", "BUILTIN\\Users"),
                sid=a.get("sid", ""),
                ace_type=ace_type_val,
                rights=rights_enums,
                is_inherited=a.get("is_inherited", False),
                inheritance_flags=a.get("inheritance_flags", [])
            ))

        result.append(NTFSSecurityDescriptor(
            path=item.get("path", "C:\\"),
            is_directory=item.get("is_directory", False),
            owner=item.get("owner", "BUILTIN\\Administrators"),
            group=item.get("group", "BUILTIN\\Administrators"),
            are_access_rules_protected=item.get("are_access_rules_protected", False),
            dacl=dacl_aces
        ))

    return result


def main() -> int:
    """CLI giriş noktası fonksiyonu."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    engine = NTFSACLEngine()

    if args.command == "ace-help":
        print("=== WINDOWS NTFS İZİN SEMBOLLERİ VE MİRAS BAYRAKLARI (ICACLS) ===")
        print("İzin Maskeleri:")
        print("  - F  : Full Control (Tam Denetim - 0x1F01FF)")
        print("  - M  : Modify (Değiştirme - 0x1301BF)")
        print("  - RX : Read and eXecute (Okuma ve Yürütme - 0x1200A9)")
        print("  - R  : Read (Salt Okuma - 0x120089)")
        print("  - W  : Write (Salt Yazma - 0x100116)")
        print("Miras Bayrakları:")
        print("  - (OI) : Object Inherit (Alt dosyalar bu izni devralır)")
        print("  - (CI) : Container Inherit (Alt klasörler bu izni devralır)")
        print("  - (IO) : Inherit Only (İzin geçerli nesneye değil, yalnızca alt nesnelere uygulanır)")
        print("  - (NP) : Do Not Propagate (Miras yalnızca bir seviye alta geçer)")
        return 0

    if not os.path.exists(args.spec):
        print(f"[!] HATA: Belirtilen spec dosyası bulunamadı: {args.spec}", file=sys.stderr)
        return 1

    with open(args.spec, "r", encoding="utf-8") as f:
        spec_data = json.load(f)

    target_sys = spec_data.get("target_system", args.system) if isinstance(spec_data, dict) else args.system
    descriptors = parse_descriptors_from_dict(spec_data)
    result = engine.audit_security_descriptors(target_system=target_sys, descriptors=descriptors)

    if args.command == "audit":
        if args.format == "markdown":
            print(engine.export_markdown_report(result))
        else:
            json_output = {
                "audit_id": result.audit_id,
                "timestamp": result.timestamp,
                "target_system": result.target_system,
                "score": result.security_score,
                "posture": result.posture_status,
                "findings": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "cwe": f.cwe_id,
                        "mitre": f.mitre_technique_id,
                        "path": f.path,
                        "identity": f.identity,
                        "rights": f.current_rights,
                        "powershell": f.powershell_remediation,
                        "icacls": f.icacls_remediation
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
            print(f"[+] icacls/PowerShell sıkılaştırma betiği kaydedildi: {args.out}")
        else:
            print(result.remediation_script)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
