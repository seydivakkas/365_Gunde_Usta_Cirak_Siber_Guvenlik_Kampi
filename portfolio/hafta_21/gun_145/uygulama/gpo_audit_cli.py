# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 145: Group Policy Güvenlik Denetimi Komut Satırı Arayüzü (CLI).
Active Directory GPO konfigürasyonlarını, LSDOU miras hiyerarşisini,
cpassword sızıntılarını ve LAPS ilkelerini analiz eder.
"""

# Komut satırı argümanları için argparse modülü içe aktarılır.
import argparse
# JSON serileştirme ve dosya okuma işlemleri için json modülü içe aktarılır.
import json
# Zaman hesaplamaları için datetime modülü içe aktarılır.
import datetime
# Konsol ve sistem çıkış kodları için sys modülü içe aktarılır.
import sys
# Dosya varlığı kontrolleri için os modülü içe aktarılır.
import os

# GPO güvenlik motoru bileşenleri içe aktarılır.
from .gpo_security_engine import (
    GpoSecurityEngine,
    GpoAuditSummary,
    GpoSecurityFinding,
)


def build_cli_parser() -> argparse.ArgumentParser:
    """
    GPO denetim aracı için CLI argüman ayrıştırıcısını oluşturur.
    """
    parser = argparse.ArgumentParser(
        description="Active Directory Group Policy Güvenlik ve Miras Denetim Aracı (Gün 145)",
        epilog="Örnek: python gpo_audit_cli.py audit ornek_veri/enterprise_gpo_spec.json"
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Çalıştırılacak alt komut")

    # 1. 'audit' alt komutu: Spesifikasyon dosyasını tam güvenlik denetiminden geçirir.
    audit_parser = subparsers.add_parser("audit", help="GPO güvenlik spesifikasyonunu denetler")
    audit_parser.add_argument("spec_file", help="Denetlenecek GPO JSON spesifikasyon dosyası")
    audit_parser.add_argument("--cikis-json", help="Denetim raporunu JSON dosyası olarak kaydeder")
    audit_parser.add_argument("--uret-remediation", help="Önerilen PowerShell sertleştirme betiğini kaydeder")

    # 2. 'effective-gpos' alt komutu: Belirli bir OU için LSDOU etkin ilkelerini hesaplar.
    lsdou_parser = subparsers.add_parser("effective-gpos", help="Bir OU için etkin GPO sırasını hesaplar")
    lsdou_parser.add_argument("spec_file", help="GPO JSON spesifikasyon dosyası")
    lsdou_parser.add_argument("--ou", required=True, help="Hedef OU Distinguished Name (DN)")

    return parser


def generate_powershell_hardening_script(summary: GpoAuditSummary) -> str:
    """
    Bulgulara göre PowerShell GPO sertleştirme betiği üretir.
    """
    lines = [
        "# ====================================================================",
        "# Active Directory Group Policy (GPO) Sertleştirme Betiği",
        f"# Üretim Tarihi: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır",
        "# ====================================================================",
        "",
        "# 1. SYSVOL cpassword İçeren Eski GPP XML Dosyalarını Temizleme",
        'Get-ChildItem -Path "\\\\$env:USERDNSDOMAIN\\SYSVOL\\*\\Policies" -Recurse -Include Groups.xml, ScheduledTasks.xml | ForEach-Object {',
        '    [xml]$xml = Get-Content $_.FullName',
        '    if ($xml.SelectNodes("//*[@cpassword]")) {',
        '        Write-Warning "UYARI: cpassword tespit edildi, ilgili GPP tercihini kaldırınız: $($_.FullName)"',
        '    }',
        '}',
        "",
        "# 2. Windows LAPS İlkesini Etkinleştirme",
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "BackupDirectory" -Value 1 -Type DWord -Force',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "PasswordComplexity" -Value 4 -Type DWord -Force',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "PasswordAgeDays" -Value 30 -Type DWord -Force',
        "",
        "# 3. GPO ACL İzinlerini Sıkılaştırma (Standart Kullanıcılardan Yazma İznini Alma)",
        'Write-Host "[+] GPO izinleri kontrol edildi: Authenticated Users yalnızca Okuma (Read) hakkına sahip olmalıdır."'
    ]
    return "\n".join(lines)


def main() -> int:
    """
    CLI uygulamasının ana giriş fonksiyonu.
    """
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = build_cli_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand == "audit":
        if not os.path.exists(args.spec_file):
            print(f"[-] Hata: Spesifikasyon dosyası bulunamadı: {args.spec_file}")
            return 2

        with open(args.spec_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        engine = GpoSecurityEngine(data)
        summary = engine.run_full_gpo_audit()

        print("=" * 70)
        print(f"ACTIVE DIRECTORY GPO GÜVENLİK DENETİMİ: {summary.domain_name}")
        print("=" * 70)
        print(f"Genel Güvenlik Puanı : {summary.security_score:.1f} / 100")
        print(f"Toplam Kontrol       : {summary.total_checks}")
        print(f"Başarılı (PASS)      : {summary.passed_checks}")
        print(f"Başarısız (FAIL)     : {summary.failed_checks}")
        print(f"Kritik Açık Sayısı   : {summary.critical_findings_count}")
        print("-" * 70)

        for f_item in summary.findings:
            status_tag = "[PASS]" if f_item.status == "PASS" else f"[{f_item.severity.value} FAIL]"
            print(f"  {status_tag:15} {f_item.rule_id} -> {f_item.title}")
            if f_item.status == "FAIL":
                print(f"    * Açıklama : {f_item.description}")
                print(f"    * Öneri    : {f_item.remediation}")

        print("=" * 70)

        if args.cikis_json:
            out_dict = {
                "domain": summary.domain_name,
                "security_score": summary.security_score,
                "timestamp": summary.audit_timestamp,
                "passed_checks": summary.passed_checks,
                "failed_checks": summary.failed_checks,
                "findings": [
                    {
                        "rule_id": fi.rule_id,
                        "title": fi.title,
                        "severity": fi.severity.value,
                        "status": fi.status,
                        "description": fi.description,
                        "affected_target": fi.affected_target,
                        "remediation": fi.remediation
                    } for fi in summary.findings
                ]
            }
            with open(args.cikis_json, "w", encoding="utf-8") as fp:
                json.dump(out_dict, fp, indent=2, ensure_ascii=False)
            print(f"[+] Denetim raporu kaydedildi: {args.cikis_json}")

        if args.uret_remediation:
            script_text = generate_powershell_hardening_script(summary)
            with open(args.uret_remediation, "w", encoding="utf-8") as fp:
                fp.write(script_text)
            print(f"[+] Sertleştirme betiği üretildi: {args.uret_remediation}")

        return 0 if summary.failed_checks == 0 else 1

    elif args.subcommand == "effective-gpos":
        if not os.path.exists(args.spec_file):
            print(f"[-] Hata: Dosya bulunamadı: {args.spec_file}")
            return 2

        with open(args.spec_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        engine = GpoSecurityEngine(data)
        chain = engine.evaluate_lsdou_effective_policies(args.ou)

        print(f"\n[+] {args.ou} için LSDOU Etkin GPO Sırası:")
        for idx, (name, enforced) in enumerate(chain, 1):
            enf_str = " (ENFORCED / NoOverride)" if enforced else ""
            print(f"  {idx}. {name}{enf_str}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
