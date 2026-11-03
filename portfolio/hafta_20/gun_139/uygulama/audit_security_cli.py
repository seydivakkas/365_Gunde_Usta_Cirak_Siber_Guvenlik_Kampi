# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Audit ve Journal Güvenliği CLI Aracı
Bu araç, sistem yöneticilerine ve siber güvenlik denetçilerine Linux auditd ve
systemd-journald yapılandırmalarını denetleme, risk puanı hesaplama, güvenlik zafiyetlerini
listeleme ve otomatik Bash sıkılaştırma betikleri üretme imkanı sağlar.
"""

# Komut satırı argümanları için argparse dahil edilir
import argparse
# JSON işlemleri için json dahil edilir
import json
# Dosya ve sistem yolları için os dahil edilir
import os
# Program sonlandırma ve hata akışları için sys dahil edilir
import sys
# Güvenlik motoru ve veri sınıfları içe aktarılır
from linux_audit_engine import LinuxAuditJournalSecurityEngine, AuditdConfig, JournaldConfig


def handle_audit(args: argparse.Namespace) -> int:
    """
    Audit ve Journald envanterini denetler ve sonuçları raporlar.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen dosya bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxAuditJournalSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    auditd, journald = engine.parse_inventory_json(data)
    report = engine.audit_environment(auditd, journald)

    print("=" * 76)
    print("      LINUX AUDIT VE JOURNAL GÜVENLİK DENETİM VE RİSK RAPORU           ")
    print("=" * 76)
    print(f"auditd Servis Durumu     : {'AKTİF' if report['auditd_aktiflik'] else 'DEVRE DIŞI'}")
    print(f"journald Depolama Türü   : {report['journald_depolama'].upper()}")
    print(f"İzlenen Dosya Kuralı     : {report['toplam_watch_kural']}")
    print(f"İzlenen Syscall Kuralı   : {report['toplam_syscall_kural']}")
    print(f"Genel Güvenlik Skoru     : {report['guvenlik_skoru']} / 100.0")
    print(f"Sistem Değerlendirmesi   : {report['durum']}")
    print(f"Tespit Edilen Zafiyet    : {report['toplam_bulgu']} adet")
    print(f"  • Kritik Derece        : {report['kritik_bulgu_sayisi']}")
    print(f"  • Yüksek Derece        : {report['yuksek_bulgu_sayisi']}")
    print(f"  • Orta Derece          : {report['orta_bulgu_sayisi']}")
    print(f"  • Düşük Derece         : {report['dusuk_bulgu_sayisi']}")
    print("-" * 76)
    print("ÖNE ÇIKAN GÜVENLİK BULGULARI:")
    for b in report["bulgular"][:5]:
        print(f"  [{b['severity']}] {b['rule_id']}: {b['title']} -> {b['target']}")
    if len(report["bulgular"]) > 5:
        print(f"  ... ve {len(report['bulgular']) - 5} ek bulgu raporda mevcuttur.")
    print("=" * 76)

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] Detaylı denetim raporu kaydedildi: {args.output}")

    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    """
    Denetlenen sunucu için tespit edilen açıkları kapatacak Bash betiği üretir.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen dosya bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxAuditJournalSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    auditd, journald = engine.parse_inventory_json(data)
    script = engine.generate_remediation_script(auditd, journald)

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(script)
        print(f"[+] Otomatik Bash sertleştirme betiği üretildi: {args.output}")
    else:
        print(script)

    return 0


def handle_audit_rules(args: argparse.Namespace) -> int:
    """
    CIS 4.1 uyumlu kurumsal audit.rules şablonu üretir.
    """
    engine = LinuxAuditJournalSecurityEngine()
    tmpl = engine.generate_audit_rules_conf()

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(tmpl)
        print(f"[+] CIS uyumlu audit.rules şablonu üretildi: {args.output}")
    else:
        print(tmpl)

    return 0


def handle_journald_conf(args: argparse.Namespace) -> int:
    """
    CIS 4.2 uyumlu kurumsal journald.conf şablonu üretir.
    """
    engine = LinuxAuditJournalSecurityEngine()
    tmpl = engine.generate_journald_conf()

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(tmpl)
        print(f"[+] CIS uyumlu journald.conf şablonu üretildi: {args.output}")
    else:
        print(tmpl)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    CLI argüman ayrıştırıcısını yapılandırır.
    """
    parser = argparse.ArgumentParser(
        description="Linux Audit ve Journal Güvenlik Denetim Aracı (Seydi Eryılmaz)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_p = subparsers.add_parser("audit", help="Auditd ve journald envanterini denetle")
    audit_p.add_argument("-i", "--input", required=True, help="Audit envanter JSON dosyası")
    audit_p.add_argument("-o", "--output", help="Rapor çıktısı için hedef JSON dosyası")

    # 2. 'remediate' alt komutu
    remed_p = subparsers.add_parser("remediate", help="Zafiyetleri gideren Bash betiği üret")
    remed_p.add_argument("-i", "--input", required=True, help="Audit envanter JSON dosyası")
    remed_p.add_argument("-o", "--output", help="Kaydedilecek hedef .sh betik dosyası")

    # 3. 'audit-rules' alt komutu
    arules_p = subparsers.add_parser("audit-rules", help="CIS 4.1 uyumlu audit.rules şablonu üret")
    arules_p.add_argument("-o", "--output", help="Kaydedilecek hedef dosya yolu")

    # 4. 'journald-conf' alt komutu
    jconf_p = subparsers.add_parser("journald-conf", help="CIS 4.2 uyumlu journald.conf şablonu üret")
    jconf_p.add_argument("-o", "--output", help="Kaydedilecek hedef dosya yolu")

    return parser


def main() -> None:
    """
    Ana yürütme fonksiyonu.
    """
    parser = build_parser()
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(1)

    if args.subcommand == "audit":
        sys.exit(handle_audit(args))
    elif args.subcommand == "remediate":
        sys.exit(handle_remediate(args))
    elif args.subcommand == "audit-rules":
        sys.exit(handle_audit_rules(args))
    elif args.subcommand == "journald-conf":
        sys.exit(handle_journald_conf(args))


if __name__ == "__main__":
    main()
