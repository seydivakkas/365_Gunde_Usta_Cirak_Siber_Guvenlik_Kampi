# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 143 - Active Directory Etki Alanı Güvenlik CLI Aracı.
Bu araç; sistem yöneticilerine ve Active Directory denetçilerine;
etki alanı mimarisini tarama, Kerberos/NTLM/LDAP zafiyetlerini listeleme
ve PowerShell GPO sertleştirme betiği üretme yeteneği sağlar.
"""

# İşletim sistemi dosya yolları
import os
# Sistem akışları ve argüman yönetimi
import sys
# Komut satırı argüman ayrıştırıcısı
import argparse
# JSON veri formatı
import json

# Windows konsolunda UTF-8 çıktı desteğini sağla
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Aynı paketteki motor sınıfını import et
from ad_domain_security_engine import AdDomainSecurityEngine


def run_cli() -> int:
    """
    Komut satırı argümanlarını ayrıştırır ve AD denetim fonksiyonlarını çağırır.
    """
    parser = argparse.ArgumentParser(
        description="Active Directory Etki Alanı Güvenlik ve Sertleştirme CLI Aracı (Gün 143)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="Active Directory envanterini denetle")
    audit_parser.add_argument("spec", help="Denetlenecek JSON AD spesifikasyon dosyası yolu")
    audit_parser.add_argument("--date", help="Referans tarih (YYYY-MM-DD), varsayılan: bugün")
    audit_parser.add_argument("--output", "-o", help="Oluşturulacak JSON rapor çıktısı dosya yolu")

    # 2. 'generate-powershell' alt komutu
    ps_parser = subparsers.add_parser("generate-powershell", help="PowerShell sertleştirme betiği üret (.ps1)")
    ps_parser.add_argument("spec", help="Denetlenecek JSON AD spesifikasyon dosyası yolu")
    ps_parser.add_argument("--date", help="Referans tarih (YYYY-MM-DD)")
    ps_parser.add_argument("--output", "-o", required=True, help="Oluşturulacak PowerShell dosya yolu")

    # 3. 'verify' alt komutu
    verify_parser = subparsers.add_parser("verify", help="Etki alanı güvenlik durumunu doğrula (Exit code 0 veya 1)")
    verify_parser.add_argument("spec", help="Denetlenecek JSON AD spesifikasyon dosyası yolu")
    verify_parser.add_argument("--date", help="Referans tarih (YYYY-MM-DD)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if not os.path.exists(args.spec):
        print(f"[-] Hata: Spesifikasyon dosyası bulunamadı: {args.spec}", file=sys.stderr)
        return 1

    engine = AdDomainSecurityEngine()
    engine.load_spec_from_file(args.spec)

    if args.command == "audit":
        summary = engine.run_full_ad_audit(ref_date_str=args.date)
        print("=" * 78)
        print(f" ACTIVE DIRECTORY GÜVENLİK DENETİM RAPORU — {summary.domain_name}")
        print("=" * 78)
        print(f"Orman Adı (Forest)    : {summary.forest_name}")
        print(f"Fonksiyonel Seviye    : {summary.functional_level}")
        print(f"AD Güvenlik Puanı     : {summary.ad_security_score} / 100")
        print(f"Genel Durum           : {summary.compliance_status}")
        print(f"Toplam Kontrol        : {summary.total_checks}")
        print(f"Başarılı (PASS)       : {summary.passed_checks}")
        print(f"Başarısız (FAIL)      : {summary.failed_checks}")
        print(f"Kritik Bulgu Sayısı   : {summary.critical_findings_count}")
        print("-" * 78)
        print("TESPİT EDİLEN BULGULAR:")
        print(f"{'KURAL ID':<13} | {'KATEGORİ':<14} | {'ŞİDDET':<9} | {'DURUM':<6} | {'BAŞLIK'}")
        print("-" * 78)
        for f in summary.findings:
            print(f"{f.rule_id:<13} | {f.category:<14} | {f.severity:<9} | {f.status:<6} | {f.title}")
        print("-" * 78)

        if summary.failed_checks > 0:
            print("ÖNCELİKLİ ÇÖZÜM ADIMLARI:")
            for f in summary.findings:
                if f.status == "FAIL":
                    print(f"  [-] [{f.rule_id}] {f.title}: {f.remediation}")
            print("-" * 78)

        if args.output:
            engine.export_report_json(args.output)
            print(f"[+] Detaylı denetim raporu kaydedildi: {args.output}")

        return 0

    elif args.command == "generate-powershell":
        engine.run_full_ad_audit(ref_date_str=args.date)
        script = engine.generate_powershell_hardening_script(args.output)
        print(f"[+] PowerShell sertleştirme betiği oluşturuldu: {args.output} ({len(script)} bayt)")
        return 0

    elif args.command == "verify":
        summary = engine.run_full_ad_audit(ref_date_str=args.date)
        if summary.compliance_status == "SECURE":
            print(f"[PASS] Active Directory etki alanı güvenli. Puan: {summary.ad_security_score}/100")
            return 0
        else:
            print(f"[FAIL] Active Directory güvensiz veya zafiyetli! Puan: {summary.ad_security_score}/100 (Durum: {summary.compliance_status})")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
