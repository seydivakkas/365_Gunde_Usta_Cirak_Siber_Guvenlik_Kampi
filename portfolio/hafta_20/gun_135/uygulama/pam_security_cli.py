# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux PAM ve Oturum Politikası Komut Satırı Arayüzü (CLI).

Bu araç; Linux sistem yöneticilerine ve denetçilerine PAM modüllerini ve oturum
politikalarını denetleme, kaba kuvvet ve parola zafiyetlerini tespit etme,
JSON raporları üretme ve otomatik Bash iyileştirme betikleri oluşturma olanağı tanır.
"""

# Komut satırı argüman ayrıştırıcısı için standart argparse kütüphanesi
import argparse
# JSON dosyalarını okumak ve yazmak için standart json modülü
import json
# Sistem çıkış kodları ve Python arama yolları için sys modülü
import sys
# Dosya sistemi ve yol denetimleri için os modülü
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
    from linux_pam_security_engine import LinuxPamSecurityEngine
except ImportError:
    from uygulama.linux_pam_security_engine import LinuxPamSecurityEngine


def load_json_spec(file_path: str) -> dict:
    """JSON spesifikasyon dosyasını güvenle yükler."""
    if not os.path.exists(file_path):
        print(f"[!] HATA: Belirtilen PAM envanter dosyası bulunamadı: {file_path}", file=sys.stderr)
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_audit(args: argparse.Namespace) -> int:
    """'audit' alt komutunu çalıştırarak PAM ve oturum envanterini denetler."""
    print(f"[*] Linux PAM ve Oturum Politikası Denetimi Başlatılıyor: {args.input_file}")
    spec = load_json_spec(args.input_file)
    if not spec:
        return 1

    engine = LinuxPamSecurityEngine()
    report = engine.run_pam_audit(spec)
    summary = report["summary"]

    print("\n" + "=" * 70)
    print("           LİNUX PAM VE OTURUM POLİTİKASI DENETİM RAPORU           ")
    print("=" * 70)
    print(f"Genel Güvenlik Skoru : {summary['score']} / {summary['max_score']}")
    print(f"Sistem Uyum Durumu   : {summary['status']}")
    print(f"Toplam Zafiyet       : {summary['total_vulnerabilities']}")
    print(f"Önem Dağılımı        : {summary['severity_breakdown']}")
    print("-" * 70)

    if report["findings_detail"]:
        print("\n[!] TESPİT EDİLEN PAM VE OTURUM ZAFİYETLERİ:")
        for idx, finding in enumerate(report["findings_detail"], 1):
            print(f"\n  [{idx}] Hedef : {finding['target']} | Önem: {finding['severity']}")
            print(f"      Zafiyet     : {finding['title']} ({finding['cwe_id']} / {finding['mitre_id']})")
            print(f"      Açıklama    : {finding['description']}")
            print(f"      İyileştirme : {finding['remediation']}")
    else:
        print("\n[+] TEBRİKLER! Denetlenen hiçbir PAM kuralında veya oturum politikasında zafiyet bulunamadı.")

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

    engine = LinuxPamSecurityEngine()
    engine.run_pam_audit(spec)
    bash_script = engine.generate_bash_remediation_script()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(bash_script)
        print(f"[+] Bash sıkılaştırma betiği kaydedildi: {args.output}")
    else:
        print("\n" + bash_script)

    return 0


def cmd_help_info(args: argparse.Namespace) -> int:
    """PAM güvenlik ilkeleri hakkında hızlı başvuru özeti verir."""
    print("""
===================================================================
LINUX PAM VE OTURUM POLİTİKASI HIZLI BAŞVURU REHBERİ
===================================================================
1. Hesap Kilitleme (pam_faillock - CWE-307 / T1110.001):
   - deny = 5 (En fazla 5 başarısız deneme)
   - unlock_time = 900 (En az 15 dakika kilit)
   - even_deny_root (Root hesabını da korur)

2. Parola Karmaşıklığı (pam_pwquality - CWE-521):
   - minlen = 14 (Minimum 14 karakter)
   - dcredit = -1, ucredit = -1, lcredit = -1, ocredit = -1
   - enforce_for_root (Root kullanıcısına da uygular)

3. Parola Geçmişi (pam_pwhistory - CWE-262):
   - remember = 5 (Son 5 parolanın tekrar kullanımını engeller)

4. Boş Parola Engeli (pam_unix - CWE-258):
   - 'nullok' bayrağı tüm PAM dosyalarından kaldırılmalıdır.

5. Oturum Zaman Aşımı (TMOUT - CWE-613):
   - /etc/profile.d/timeout.sh içinde readonly TMOUT=900 tanımlanmalıdır.
===================================================================
    """)
    return 0


def main() -> int:
    """Ana komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Linux PAM ve Oturum Politikası Güvenlik Denetim Aracı (Gün 135)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 'audit'
    p_audit = subparsers.add_parser("audit", help="PAM ve oturum envanterini denetle")
    p_audit.add_argument("-i", "--input-file", required=True, help="PAM JSON spesifikasyon dosyası")
    p_audit.add_argument("-o", "--output", help="Raporun kaydedileceği JSON dosya yolu")

    # 'remediate'
    p_remed = subparsers.add_parser("remediate", help="Bash iyileştirme betiği üret")
    p_remed.add_argument("-i", "--input-file", required=True, help="PAM JSON spesifikasyon dosyası")
    p_remed.add_argument("-o", "--output", help="Betiğin kaydedileceği .sh dosya yolu")

    # 'pam-help'
    subparsers.add_parser("pam-help", help="PAM güvenlik rehberini görüntüle")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        return cmd_audit(args)
    elif args.command == "remediate":
        return cmd_remediate(args)
    elif args.command == "pam-help":
        return cmd_help_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
