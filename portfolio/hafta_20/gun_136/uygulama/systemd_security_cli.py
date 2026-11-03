# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Servisleri ve Systemd Güvenliği Komut Satırı Arayüzü (CLI)
Bu araç, sistem yöneticilerine ve siber güvenlik denetçilerine systemd servislerini
denetleme, risk puanı hesaplama, güvenlik zafiyetlerini listeleme ve otomatik
iyileştirme (remediation) betikleri üretme imkanı tanır.
"""

# Komut satırı argümanlarını ayrıştırmak için argparse modülü dahil edilir
import argparse
# JSON veri formatı işlemleri için json modülü dahil edilir
import json
# Dosya ve işletim sistemi yollarını yönetmek için os modülü dahil edilir
import os
# Program sonlandırma ve hata kodları için sys modülü dahil edilir
import sys
# Geliştirdiğimiz systemd güvenlik motoru ve veri sınıfları içe aktarılır
from linux_systemd_engine import LinuxSystemdSecurityEngine, ServiceUnit


def handle_audit(args: argparse.Namespace) -> int:
    """
    Envanter dosyasını okuyarak systemd servislerini denetler ve sonuçları raporlar.
    """
    # Girdi dosyasının mevcudiyeti kontrol edilir
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen envanter dosyası bulunamadı: {args.input}", file=sys.stderr)
        return 1

    # Güvenlik motoru örneği oluşturulur
    engine = LinuxSystemdSecurityEngine()

    try:
        # Envanter dosyası UTF-8 kodlamasıyla açılır
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON dosyası ayrıştırılamadı: {e}", file=sys.stderr)
        return 1

    # Servis birimleri JSON verisinden ayrıştırılır
    services = engine.parse_inventory_json(data)
    # Servisler güvenlik motoru ile denetlenir
    report = engine.audit_services(services)

    # Terminale didaktik ve şık bir özet başlığı yazdırılır
    print("=" * 76)
    print("        LINUX SYSTEMD SERVİS GÜVENLİK DENETİM VE MARUZİYET RAPORU        ")
    print("=" * 76)
    print(f"Toplam Denetlenen Servis : {report['toplam_servis']}")
    print(f"Genel Sistem Puanı       : {report['guvenlik_skoru']} / 100.0")
    print(f"Sistem Güvenlik Durumu   : {report['durum']}")
    print(f"Tespit Edilen Bulgu      : {report['toplam_bulgu']} adet")
    print(f"  - Kritik Derece        : {report['kritik_bulgu_sayisi']}")
    print(f"  - Yüksek Derece        : {report['yuksek_bulgu_sayisi']}")
    print(f"  - Orta Derece          : {report['orta_bulgu_sayisi']}")
    print(f"  - Düşük Derece         : {report['dusuk_bulgu_sayisi']}")
    print("-" * 76)
    print("SERVİS BAZLI EXPOSURE (MARUZİYET) PUANLARI:")
    for s_eval in report["servis_detaylari"]:
        print(f"  • {s_eval['name']:<24} Exposure: {s_eval['exposure_skoru']}/10.0 [{s_eval['exposure_seviyesi']}] - {s_eval['bulgu_sayisi']} bulgu")
    print("=" * 76)

    # Eğer çıktı dosyası belirtilmişse JSON olarak diske kaydedilir
    if args.output:
        # Hedef dizin kontrol edilir ve yoksa oluşturulur
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[+] Detaylı denetim raporu kaydedildi: {args.output}")

    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    """
    Denetlenen servislerdeki zafiyetleri giderecek Bash sertleştirme betiği üretir.
    """
    if not os.path.exists(args.input):
        print(f"[-] HATA: Belirtilen envanter dosyası bulunamadı: {args.input}", file=sys.stderr)
        return 1

    engine = LinuxSystemdSecurityEngine()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] HATA: JSON dosyası ayrıştırılamadı: {e}", file=sys.stderr)
        return 1

    services = engine.parse_inventory_json(data)
    # Bash iyileştirme betiği üretilir
    script_content = engine.generate_remediation_script(services)

    # Çıktı dosyası yolu belirlenir veya ekrana yazdırılır
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


def handle_template(args: argparse.Namespace) -> int:
    """
    CIS ve systemd sandboxing standartlarına uygun güvenli bir servis unit şablonu üretir.
    """
    engine = LinuxSystemdSecurityEngine()
    template = engine.generate_secure_unit_template(
        service_name=args.name,
        exec_path=args.exec_path,
        user=args.user
    )

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(template)
        print(f"[+] Güvenli systemd servis şablonu oluşturuldu: {args.output}")
    else:
        print(template)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    CLI argüman ayrıştırıcısını yapılandırır.
    """
    parser = argparse.ArgumentParser(
        description="Linux Servisleri ve Systemd Güvenlik Denetim Aracı (Seydi Eryılmaz)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Alt komut ayrıştırıcıları oluşturulur
    subparsers = parser.add_subparsers(dest="subcommand", help="Kullanılabilir alt komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="Systemd servis envanterini denetle ve maruziyet puanı hesapla")
    audit_parser.add_argument("-i", "--input", required=True, help="Denetlenecek JSON servis envanter dosyası yolu")
    audit_parser.add_argument("-o", "--output", help="Raporun yazılacağı hedef JSON dosyası")

    # 2. 'remediate' alt komutu
    remed_parser = subparsers.add_parser("remediate", help="Zafiyetleri gideren Bash sertleştirme betiği üret")
    remed_parser.add_argument("-i", "--input", required=True, help="Servis envanter dosyası yolu")
    remed_parser.add_argument("-o", "--output", help="Kaydedilecek hedef .sh betik dosyası yolu")

    # 3. 'template' alt komutu
    tmpl_parser = subparsers.add_parser("template", help="CIS uyumlu güvenli servis unit şablonu üret")
    tmpl_parser.add_argument("-n", "--name", default="my-service.service", help="Servis birim adı")
    tmpl_parser.add_argument("-e", "--exec-path", default="/usr/local/bin/my-app", help="ExecStart komut veya binary yolu")
    tmpl_parser.add_argument("-u", "--user", default="appuser", help="Çalıştırıcı kullanıcı adı")
    tmpl_parser.add_argument("-o", "--output", help="Kaydedilecek hedef dosya yolu")

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
    elif args.subcommand == "template":
        sys.exit(handle_template(args))


if __name__ == "__main__":
    main()
