# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Mini Proje 18: Bütünleşik Windows Güvenlik Denetim CLI Aracı.

Bu komut satırı aracı, kurumsal Windows uç noktalarını 5 temel güvenlik alanında
denetler, JSON ve Markdown formatlarında teknik raporlar üretir ve tam kapsamlı
PowerShell Master Sıkılaştırma Betiği oluşturur.
"""

# Komut satırı argüman ayrıştırıcısı için standart argparse kütüphanesi
import argparse
# JSON dosyalarını okumak ve yazmak için standart json modülü
import json
# Çıkış kodları ve yol yönetimi için sys kütüphanesi
import sys
# Dosya sistemi ve yol birleştirme işlemleri için os modülü
import os

# Doğrudan veya paket üzerinden çalıştırmada modül erişimini garanti altına almak için yol eklenir
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Denetim motorunu içe aktarır
try:
    from windows_audit_platform_engine import WindowsAuditPlatformEngine
except ImportError:
    from uygulama.windows_audit_platform_engine import WindowsAuditPlatformEngine


def load_json_spec(file_path: str) -> dict:
    """JSON spesifikasyon dosyasını güvenle yükler."""
    if not os.path.exists(file_path):
        print(f"[!] HATA: Belirtilen denetim spesifikasyon dosyası bulunamadı: {file_path}", file=sys.stderr)
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_audit(args: argparse.Namespace) -> int:
    """'audit' alt komutunu icra eder ve denetim özeti basar."""
    print(f"[*] Bütünleşik Windows Güvenlik Denetimi Yürütülüyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = WindowsAuditPlatformEngine()
    report = engine.run_full_windows_audit(spec)
    summary = report["overall_summary"]

    print("\n" + "=" * 70)
    print("           BÜTÜNLEŞİK WINDOWS GÜVENLİK DENETİM SONUÇLARI           ")
    print("=" * 70)
    print(f"Genel Güvenlik Skoru : {summary['total_score']} / {summary['max_score']}")
    print(f"Genel Uyum Durumu    : {summary['overall_status']}")
    print(f"Toplam Zafiyet       : {summary['total_vulnerabilities']}")
    print(f"Önem Dağılımı        : {summary['severity_breakdown']}")
    print("-" * 70)
    print("ALAN BAZINDA PUAN VE DURUM DAĞILIMI:")
    for _, d in report["domain_breakdown"].items():
        print(f"  * {d['domain_name']:<38} : {d['score']:>5.1f} / {d['max_score']} [{d['status']}] (Zafiyet: {d['vulnerabilities']})")
    print("=" * 70)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            json.dump(report, out_f, indent=2, ensure_ascii=False)
        print(f"[+] Detaylı denetim raporu kaydedildi: {args.output}")

    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    """'remediate' alt komutunu icra eder ve Master PowerShell betiği üretir."""
    print(f"[*] PowerShell Master Sıkılaştırma Betiği Üretiliyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = WindowsAuditPlatformEngine()
    engine.run_full_windows_audit(spec)
    ps_script = engine.generate_master_remediation_powershell()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(ps_script)
        print(f"[+] Master Sıkılaştırma Betiği başarıyla kaydedildi: {args.output}")
    else:
        print("\n" + ps_script)

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """'report' alt komutunu icra eder ve yönetici düzeyinde Markdown rapor üretir."""
    print(f"[*] Yönetici Düzeyinde Markdown Raporu Üretiliyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = WindowsAuditPlatformEngine()
    engine.run_full_windows_audit(spec)
    md_content = engine.generate_executive_markdown_report()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"[+] Markdown denetim raporu başarıyla kaydedildi: {args.output}")
    else:
        print("\n" + md_content)

    return 0


def cmd_help_info(args: argparse.Namespace) -> int:
    """Denetim standartları hakkında hızlı yardım özeti basar."""
    print("""
===================================================================
MINI PROJE 18: BÜTÜNLEŞİK WINDOWS GÜVENLİK DENETİM REHBERİ
===================================================================
Kapsanan 5 Temel Alan:
1. Windows Defender: RTP, Davranış İzleme, Tamper Protection, PUA.
2. Hesaplar & UAC: EnableLUA, ConsentPromptBehaviorAdmin, LAPS.
3. NTFS ACL: Sistem dizinlerinde kullanıcı yazma yetkisi, SACL.
4. Firewall: Domain/Private/Public profilleri, Block Inbound, Port maruziyeti.
5. Windows Services: Tırnaksız servis yolları, Zayıf DACL, Zayıf binary izinleri.

Ağırlıklandırma: Her alan 20 puan, Toplam 100.0 tam puan.
===================================================================
    """)
    return 0


def main() -> int:
    """Ana komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Platformu CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 'audit'
    p_audit = subparsers.add_parser("audit", help="Windows uç nokta spesifikasyonunu denetle")
    p_audit.add_argument("-i", "--input-file", required=True, help="Uç nokta spesifikasyon JSON dosyası")
    p_audit.add_argument("-o", "--output", help="Raporun yazılacağı JSON dosyası")

    # 'remediate'
    p_remed = subparsers.add_parser("remediate", help="Master PowerShell sıkılaştırma betiği üret")
    p_remed.add_argument("-i", "--input-file", required=True, help="Uç nokta spesifikasyon JSON dosyası")
    p_remed.add_argument("-o", "--output", help="Betiğin kaydedileceği .ps1 dosyası")

    # 'report'
    p_rep = subparsers.add_parser("report", help="Yönetici düzeyinde Markdown denetim raporu üret")
    p_rep.add_argument("-i", "--input-file", required=True, help="Uç nokta spesifikasyon JSON dosyası")
    p_rep.add_argument("-o", "--output", help="Raporun kaydedileceği .md dosyası")

    # 'audit-help'
    subparsers.add_parser("audit-help", help="Denetim platformu kılavuzunu görüntüle")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        return cmd_audit(args)
    elif args.command == "remediate":
        return cmd_remediate(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "audit-help":
        return cmd_help_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
