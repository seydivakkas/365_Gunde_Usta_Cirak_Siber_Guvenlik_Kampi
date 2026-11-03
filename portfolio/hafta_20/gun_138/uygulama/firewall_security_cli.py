# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Güvenlik Duvarı (nftables/UFW) Komut Satırı Arayüzü (CLI)
Bu araç, sistem yöneticilerine ve siber güvenlik denetçilerine Linux host tabanlı
güvenlik duvarlarını (nftables ve UFW) denetleme, risk puanı hesaplama, güvenlik zafiyetlerini
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
from linux_firewall_engine import LinuxFirewallSecurityEngine, FirewallConfiguration, FirewallRule


def handle_audit(args: argparse.Namespace) -> int:
    """
    Güvenlik duvarı envanterini denetler ve sonuçları raporlar.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen dosya bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxFirewallSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    config = engine.parse_inventory_json(data)
    report = engine.audit_firewall(config)

    print("=" * 76)
    print("      LINUX GÜVENLİK DUVARI (NFTABLES / UFW) DENETİM RAPORU            ")
    print("=" * 76)
    print(f"Güvenlik Duvarı Türü     : {report['firewall_turu'].upper()}")
    print(f"Çalışma Durumu           : {'AKTİF' if report['aktiflik'] else 'DEVRE DIŞI'}")
    print(f"Toplam Kural Sayısı      : {report['toplam_kural']}")
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
    Güvenlik duvarı açıklarını kapatan otomatik Bash betiği üretir.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen dosya bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxFirewallSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    config = engine.parse_inventory_json(data)
    script = engine.generate_remediation_script(config)

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


def handle_nft_template(args: argparse.Namespace) -> int:
    """
    CIS 3.4 uyumlu örnek nftables.conf üretir.
    """
    engine = LinuxFirewallSecurityEngine()
    tmpl = engine.generate_nftables_hardening_conf()

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(tmpl)
        print(f"[+] CIS uyumlu nftables.conf şablonu üretildi: {args.output}")
    else:
        print(tmpl)

    return 0


def handle_ufw_template(args: argparse.Namespace) -> int:
    """
    CIS 3.5 uyumlu örnek UFW yapılandırma betiği üretir.
    """
    engine = LinuxFirewallSecurityEngine()
    tmpl = engine.generate_ufw_hardening_script()

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(tmpl)
        print(f"[+] CIS uyumlu UFW sertleştirme betiği üretildi: {args.output}")
    else:
        print(tmpl)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    CLI argüman ayrıştırıcısını oluşturur.
    """
    parser = argparse.ArgumentParser(
        description="Linux Güvenlik Duvarı (nftables/UFW) Denetim Aracı (Seydi Eryılmaz)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_p = subparsers.add_parser("audit", help="Güvenlik duvarı yapılandırmasını denetle ve raporla")
    audit_p.add_argument("-i", "--input", required=True, help="Firewall envanter JSON dosyası")
    audit_p.add_argument("-o", "--output", help="Rapor çıktısı için hedef JSON dosyası")

    # 2. 'remediate' alt komutu
    remed_p = subparsers.add_parser("remediate", help="Zafiyetleri gideren Bash betiği üret")
    remed_p.add_argument("-i", "--input", required=True, help="Firewall envanter JSON dosyası")
    remed_p.add_argument("-o", "--output", help="Kaydedilecek hedef .sh betik dosyası")

    # 3. 'nft-template' alt komutu
    nft_p = subparsers.add_parser("nft-template", help="CIS 3.4 uyumlu /etc/nftables.conf üret")
    nft_p.add_argument("-o", "--output", help="Kaydedilecek hedef dosya yolu")

    # 4. 'ufw-template' alt komutu
    ufw_p = subparsers.add_parser("ufw-template", help="CIS 3.5 uyumlu UFW sertleştirme betiği üret")
    ufw_p.add_argument("-o", "--output", help="Kaydedilecek hedef dosya yolu")

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
    elif args.subcommand == "nft-template":
        sys.exit(handle_nft_template(args))
    elif args.subcommand == "ufw-template":
        sys.exit(handle_ufw_template(args))


if __name__ == "__main__":
    main()
