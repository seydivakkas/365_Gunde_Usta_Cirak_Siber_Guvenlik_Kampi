# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Sudo ve Ayrıcalık Devri Komut Satırı Arayüzü (CLI).

Bu araç; Linux sistem yöneticilerine ve denetçilerine sudoers kurallarını denetleme,
GTFOBins ve NOPASSWD açıklarını tespit etme, JSON raporları üretme ve güvenli
/etc/sudoers şablonları oluşturma olanağı tanır.
"""

# Komut satırı argümanlarını ayrıştırmak için standart argparse modülü içe aktarılıyor
import argparse
# JSON dosyalarını okumak ve yazmak için standart json modülü içe aktarılıyor
import json
# Sistem çıkış kodları ve Python arama yolları için sys modülü içe aktarılıyor
import sys
# Dosya varlığı ve dizin yolu denetimleri için os modülü içe aktarılıyor
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
    from linux_sudo_engine import LinuxSudoSecurityEngine
except ImportError:
    from uygulama.linux_sudo_engine import LinuxSudoSecurityEngine


def load_json_spec(file_path: str) -> dict:
    """JSON spesifikasyon dosyasını güvenle yükler."""
    if not os.path.exists(file_path):
        print(f"[!] HATA: Belirtilen sudo envanter dosyası bulunamadı: {file_path}", file=sys.stderr)
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_audit(args: argparse.Namespace) -> int:
    """'audit' alt komutunu çalıştırarak sudoers envanterini denetler."""
    print(f"[*] Linux Sudo ve Ayrıcalık Devri Denetimi Başlatılıyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = LinuxSudoSecurityEngine()
    report = engine.run_sudo_audit(spec)
    summary = report["summary"]

    print("\n" + "=" * 70)
    print("           LİNUX SUDO GÜVENLİK DENETİMİ RAPOR ÖZETİ           ")
    print("=" * 70)
    print(f"Genel Güvenlik Skoru : {summary['score']} / {summary['max_score']}")
    print(f"Sistem Uyum Durumu   : {summary['status']}")
    print(f"Toplam Zafiyet       : {summary['total_vulnerabilities']}")
    print(f"Önem Dağılımı        : {summary['severity_breakdown']}")
    print("-" * 70)

    if report["findings_detail"]:
        print("\n[!] TESPİT EDİLEN SUDO GÜVENLİK ZAFİYETLERİ:")
        for idx, finding in enumerate(report["findings_detail"], 1):
            print(f"\n  [{idx}] Hedef : {finding['target']} | Önem: {finding['severity']}")
            print(f"      Zafiyet     : {finding['title']} ({finding['cwe_id']} / {finding['mitre_id']})")
            print(f"      Açıklama    : {finding['description']}")
            print(f"      İyileştirme : {finding['remediation']}")
    else:
        print("\n[+] TEBRİKLER! Denetlenen hiçbir kural veya dosyada güvenlik açığı bulunamadı.")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            json.dump(report, out_f, indent=2, ensure_ascii=False)
        print(f"\n[+] Detaylı denetim raporu kaydedildi: {args.output}")

    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    """'remediate' alt komutunu çalıştırarak Bash iyileştirme betiği üretir."""
    print(f"[*] Bash Sıkılaştırma Betiği Üretiliyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = LinuxSudoSecurityEngine()
    engine.run_sudo_audit(spec)
    bash_script = engine.generate_bash_remediation_script()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(bash_script)
        print(f"[+] Bash sıkılaştırma betiği kaydedildi: {args.output}")
    else:
        print("\n" + bash_script)

    return 0


def cmd_config_template(args: argparse.Namespace) -> int:
    """Sıkılaştırılmış /etc/sudoers yapılandırma taslağını üretir."""
    print("[*] Sıkılaştırılmış /etc/sudoers Şablonu Üretiliyor...")
    engine = LinuxSudoSecurityEngine()
    template = engine.generate_hardened_sudoers_config()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(template)
        print(f"[+] Güvenli sudoers şablonu kaydedildi: {args.output}")
    else:
        print("\n" + template)

    return 0


def cmd_help_info(args: argparse.Namespace) -> int:
    """Sudo güvenlik ilkeleri hakkında hızlı bilgi verir."""
    print("""
===================================================================
LINUX SUDO VE AYRICALIK DEVRİ HIZLI BAŞVURU REHBERİ
===================================================================
1. Sudoers Dosya İzinleri (CWE-732):
   - /etc/sudoers ve /etc/sudoers.d/* daima chmod 0440 ve root:root olmalıdır.
   - Düzenlemeler MUTLAKA 'visudo' ile yapılmalıdır.

2. NOPASSWD ve Wildcard Riskleri (CWE-250 / T1548.003):
   - NOPASSWD: ALL kesinlikle verilmemelidir.
   - Wildcard (*) parametre enjeksiyonuna (argument injection) açıktır.

3. GTFOBins Zafiyetleri:
   - Sudo ile izin verilen vim, find, awk, python, less vb. araçlar
     doğrudan root kabuk kaçışına (shell escape) yol açar.

4. Defaults Sıkılaştırması:
   - Defaults env_reset (Çevre değişkenlerini temizler)
   - Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
   - Defaults use_pty (TIOCSTI ioctl enjeksiyonunu engeller)
   - Defaults logfile="/var/log/sudo.log" (Denetim günlüğü)
===================================================================
    """)
    return 0


def main() -> int:
    """Ana komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Linux Sudo ve Ayrıcalık Devri Güvenlik Denetim Aracı (Gün 134)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 'audit'
    p_audit = subparsers.add_parser("audit", help="Sudoers envanterini denetle")
    p_audit.add_argument("-i", "--input-file", required=True, help="Sudoers JSON spesifikasyon dosyası")
    p_audit.add_argument("-o", "--output", help="Raporun kaydedileceği JSON dosya yolu")

    # 'remediate'
    p_remed = subparsers.add_parser("remediate", help="Bash iyileştirme betiği üret")
    p_remed.add_argument("-i", "--input-file", required=True, help="Sudoers JSON spesifikasyon dosyası")
    p_remed.add_argument("-o", "--output", help="Betiğin kaydedileceği .sh dosya yolu")

    # 'config-template'
    p_temp = subparsers.add_parser("config-template", help="Sıkılaştırılmış /etc/sudoers şablonu üret")
    p_temp.add_argument("-o", "--output", help="Şablonun kaydedileceği dosya yolu")

    # 'sudo-help'
    subparsers.add_parser("sudo-help", help="Sudo güvenlik rehberini görüntüle")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        return cmd_audit(args)
    elif args.command == "remediate":
        return cmd_remediate(args)
    elif args.command == "config-template":
        return cmd_config_template(args)
    elif args.command == "sudo-help":
        return cmd_help_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
