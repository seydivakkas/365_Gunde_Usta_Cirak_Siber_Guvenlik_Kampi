# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirme CLI Aracı
Bu araç, sistem yöneticilerine ve güvenlik denetçilerine SSH anahtar izinlerini,
şifreleme kalitesini ve OpenSSH sunucu yapılandırmalarını denetleme, raporlama ve
otomatik Bash sertleştirme betiği üretme olanağı sağlar.
"""

# Komut satırı argümanları için argparse dahil edilir
import argparse
# JSON veri yönetimi için json dahil edilir
import json
# Dosya ve sistem yolları için os dahil edilir
import os
# Çıkış kodları ve hata akışı için sys dahil edilir
import sys
# SSH güvenlik motoru ve veri yapıları içe aktarılır
from linux_ssh_engine import LinuxSshSecurityEngine, SshKey, AuthorizedKeyEntry, SshdConfig


def handle_audit(args: argparse.Namespace) -> int:
    """
    SSH envanterini denetler ve sonuçları terminale ve dosyaya raporlar.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Envanter dosyası bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxSshSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    keys, auth_keys, sshd = engine.parse_inventory_json(data)
    report = engine.audit_environment(keys, auth_keys, sshd)

    print("=" * 76)
    print("         LINUX SSH ANAHTAR VE SUNUCU GÜVENLİK DENETİM RAPORU             ")
    print("=" * 76)
    print(f"Denetlenen SSH Anahtarı : {report['toplam_anahtar']}")
    print(f"Yetkili Açık Anahtar     : {report['toplam_authorized_key']}")
    print(f"Genel Sistem Güvenlik Skoru : {report['guvenlik_skoru']} / 100.0")
    print(f"Değerlendirme Durumu    : {report['durum']}")
    print(f"Tespit Edilen Zafiyet   : {report['toplam_bulgu']} adet")
    print(f"  • Kritik Bulgular     : {report['kritik_bulgu_sayisi']}")
    print(f"  • Yüksek Bulgular     : {report['yuksek_bulgu_sayisi']}")
    print(f"  • Orta Bulgular       : {report['orta_bulgu_sayisi']}")
    print(f"  • Düşük Bulgular      : {report['dusuk_bulgu_sayisi']}")
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
        print(f"[+] Detaylı JSON analiz raporu kaydedildi: {args.output}")

    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    """
    SSH zafiyetlerini gideren Bash betiği üretir.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Envanter dosyası bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxSshSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON okunamadı: {e}", file=sys.stderr)
        return 1

    keys, auth_keys, sshd = engine.parse_inventory_json(data)
    script_content = engine.generate_remediation_script(keys, auth_keys, sshd)

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(script_content)
        print(f"[+] Otomatik Bash sertleştirme betiği üretildi: {args.output}")
    else:
        print(script_content)

    return 0


def handle_sshd_config(args: argparse.Namespace) -> int:
    """
    CIS uyumlu örnek güvenli sshd_config şablonu üretir.
    """
    engine = LinuxSshSecurityEngine()
    config_content = engine.generate_hardened_sshd_config()

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(config_content)
        print(f"[+] Güvenli sshd_config şablonu oluşturuldu: {args.output}")
    else:
        print(config_content)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    Argüman ayrıştırıcıyı yapılandırır.
    """
    parser = argparse.ArgumentParser(
        description="Linux SSH Anahtar Güvenliği ve Sunucu Sertleştirme CLI Aracı (Seydi Eryılmaz)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # Audit alt komutu
    audit_parser = subparsers.add_parser("audit", help="SSH anahtarlarını ve sshd_config ayarlarını denetle")
    audit_parser.add_argument("-i", "--input", required=True, help="SSH envanter JSON dosyası")
    audit_parser.add_argument("-o", "--output", help="Analiz raporu JSON çıktısı")

    # Remediate alt komutu
    remed_parser = subparsers.add_parser("remediate", help="SSH zafiyetlerini gideren Bash betiği üret")
    remed_parser.add_argument("-i", "--input", required=True, help="SSH envanter JSON dosyası")
    remed_parser.add_argument("-o", "--output", help="Kaydedilecek Bash betik dosyası yolu")

    # Sshd-config alt komutu
    sshd_parser = subparsers.add_parser("sshd-config", help="CIS uyumlu güvenli sshd_config şablonu üret")
    sshd_parser.add_argument("-o", "--output", help="Kaydedilecek sshd_config dosyası")

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
    elif args.subcommand == "sshd-config":
        sys.exit(handle_sshd_config(args))


if __name__ == "__main__":
    main()
