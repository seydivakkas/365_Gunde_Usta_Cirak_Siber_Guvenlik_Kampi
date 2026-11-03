# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Windows Hizmet Güvenliği Komut Satırı Arayüzü (CLI).

Bu araç, sistem yöneticilerine ve siber güvenlik denetçilerine Windows hizmetlerini
denetleme, zafiyet raporları üretme ve otomatik PowerShell iyileştirme betikleri oluşturma olanağı sunar.
"""

# Komut satırı argümanlarını ayrıştırmak için standart argparse modülü içe aktarılıyor
import argparse
# JSON veri formatlama ve dosya işlemleri için standart json modülü içe aktarılıyor
import json
# Sistem çıkış kodları ve modül arama yolları için sys modülü içe aktarılıyor
import sys
# Dosya varlığı ve dizin yolları için os modülü içe aktarılıyor
import os

# Doğrudan veya paket üzerinden çalıştırmada modül erişimini garanti altına almak için yol eklenir
current_dir = os.path.dirname(os.path.abspath(__file__))
# Üst dizin de yola eklenir
parent_dir = os.path.dirname(current_dir)
# Arama yolunun başına eklenir
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Denetim motoru ve veri modelleri içe aktarılır
try:
    # Aynı dizinden doğrudan içe aktarma denenir
    from windows_service_security_engine import WindowsServiceSecurityEngine, WindowsServiceSpec
except ImportError:
    # Paket yolu üzerinden içe aktarma denenir
    from uygulama.windows_service_security_engine import WindowsServiceSecurityEngine, WindowsServiceSpec


def load_service_spec_from_file(file_path: str) -> list:
    """
    JSON dosyasından Windows servis spesifikasyon listesini yükler.
    """
    # Dosyanın varlığı kontrol edilir
    if not os.path.exists(file_path):
        # Dosya bulunamazsa hata yazdırılır ve boş liste döndürülür
        print(f"[!] HATA: Belirtilen servis envanter dosyası bulunamadı: {file_path}", file=sys.stderr)
        return []

    # Dosya güvenli şekilde UTF-8 kodlamasıyla açılır
    with open(file_path, "r", encoding="utf-8") as f:
        # JSON verisi okunur
        raw_data = json.load(f)

    # Veri bir liste değilse veya 'services' anahtarında ise ayarlanır
    if isinstance(raw_data, dict) and "services" in raw_data:
        raw_list = raw_data["services"]
    elif isinstance(raw_data, list):
        raw_list = raw_data
    else:
        raw_list = []

    # Liste nesnelerine dönüştürülür
    specs = []
    for item in raw_list:
        specs.append(
            WindowsServiceSpec(
                service_name=item.get("service_name", "UnknownService"),
                display_name=item.get("display_name", ""),
                image_path=item.get("image_path", ""),
                start_type=item.get("start_type", "Automatic"),
                run_as_account=item.get("run_as_account", "LocalSystem"),
                sddl=item.get("sddl", ""),
                binary_permissions=item.get("binary_permissions", {}),
                required_privileges=item.get("required_privileges", []),
                is_third_party=item.get("is_third_party", False),
                description=item.get("description", ""),
            )
        )
    return specs


def cmd_audit(args: argparse.Namespace) -> int:
    """
    'audit' alt komutunu çalıştırır ve servisleri güvenlik denetiminden geçirir.
    """
    print(f"[*] Windows Hizmet Güvenlik Denetimi Başlatılıyor: {args.input_file}")
    # Envanter dosyası yüklenir
    specs = load_service_spec_from_file(args.input_file)
    if not specs:
        print("[!] Denetlenecek geçerli bir servis bulunamadı.", file=sys.stderr)
        return 1

    # Denetim motoru başlatılır
    engine = WindowsServiceSecurityEngine()
    # Denetim icra edilir
    report = engine.audit_service_inventory(specs)

    # Özet konsola basılır
    print("-" * 65)
    print(f"Denetlenen Servis Sayısı : {report['total_services_audited']}")
    print(f"Genel Güvenlik Skoru     : {report['security_score']} / 100.0")
    print(f"Sistem Güvenlik Durumu   : {report['system_status']}")
    print(f"Toplam Zafiyet Sayısı    : {report['total_vulnerabilities']}")
    print(f"Önem Dağılımı            : {report['severity_breakdown']}")
    print("-" * 65)

    # Zafiyetler varsa ekrana listelenir
    if report["findings_detail"]:
        print("\n[!] TESPİT EDİLEN SERVİS GÜVENLİK ZAFİYETLERİ:")
        for idx, finding in enumerate(report["findings_detail"], 1):
            print(f"\n  [{idx}] Servis Adı : {finding['service_name']} | Önem: {finding['severity']}")
            print(f"      Zafiyet     : {finding['title']} ({finding['cwe_id']} / {finding['mitre_id']})")
            print(f"      Açıklama    : {finding['description']}")
            print(f"      İyileştirme : {finding['remediation']}")
    else:
        print("\n[+] MÜKEMMEL! Denetlenen hiçbir serviste güvenlik zafiyeti tespit edilmedi.")

    # İsteğe bağlı olarak JSON çıktısı kaydedilir
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            json.dump(report, out_f, indent=2, ensure_ascii=False)
        print(f"\n[+] Ayrıntılı denetim raporu kaydedildi: {args.output}")

    # Kritik veya yüksek zafiyet varsa 1, yoksa 0 döndürülür
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    """
    'remediate' alt komutunu çalıştırır ve PowerShell iyileştirme betiği üretir.
    """
    print(f"[*] Sıkılaştırma Betiği Üretiliyor: {args.input_file}")
    # Envanter dosyası yüklenir
    specs = load_service_spec_from_file(args.input_file)
    if not specs:
        print("[!] Geçerli bir servis envanteri bulunamadı.", file=sys.stderr)
        return 1

    # Motor başlatılır ve denetim yapılır
    engine = WindowsServiceSecurityEngine()
    engine.audit_service_inventory(specs)

    # Betik metni oluşturulur
    ps_script = engine.generate_powershell_remediation_script()

    # Dosyaya veya ekrana yazdırılır
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(ps_script)
        print(f"[+] PowerShell iyileştirme betiği başarıyla kaydedildi: {args.output}")
    else:
        print("\n" + "=" * 60)
        print(ps_script)
        print("=" * 60)

    return 0


def cmd_help_info(args: argparse.Namespace) -> int:
    """
    Windows servis güvenliği hakkında hızlı referans rehberi yazdırır.
    """
    print("""
===================================================================
WINDOWS HİZMET GÜVENLİĞİ HIZLI BAŞVURU REHBERİ
===================================================================
1. Tırnaksız Servis Yolu (CWE-428 / MITRE ATT&CK T1574.009):
   - Boşluk içeren ImagePath değerleri çift tırnak içine alınmalıdır.
   - Düzeltme: sc config "ServiceName" binPath= "\\"C:\\Program Files\\App\\svc.exe\\""

2. Zayıf Servis İzinleri (CWE-732 / MITRE ATT&CK T1543.003):
   - Standart kullanıcılar (BUILTIN\\Users) SERVICE_CHANGE_CONFIG (CC) veya
     WRITE_DAC (WD) yetkilerine sahip olmamalıdır.
   - Düzeltme: sc sdset "ServiceName" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

3. Zayıf Dosya İzinleri (CWE-732 / MITRE ATT&CK T1574.010):
   - Servisin çağırdığı .exe dosyası ve dizini Users grubuna yazma izni vermemelidir.
   - Düzeltme: icacls "C:\\Path\\To\\svc.exe" /grant:r "Users:(RX)"

4. En Az Ayrıcalık Prensibi (CWE-250):
   - Servisler zorunlu olmadıkça LocalSystem yerine LocalService, NetworkService veya gMSA ile çalışmalıdır.

5. CIS Windows Benchmark Uyarınca Kapatılması Gereken Servisler:
   - RemoteRegistry, RemoteAccess, Xbox Servisleri, TapiSrv vb.
===================================================================
    """)
    return 0


def main() -> int:
    """Ana komut satırı yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Windows Hizmet Güvenliği Denetim ve Sıkılaştırma Aracı (Gün 132)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir alt komutlar")

    # 'audit' komutu
    audit_parser = subparsers.add_parser("audit", help="Servis envanterini denetle ve güvenlik raporu üret")
    audit_parser.add_argument("-i", "--input-file", required=True, help="Servis envanteri JSON dosya yolu")
    audit_parser.add_argument("-o", "--output", help="Raporun kaydedileceği JSON dosya yolu")

    # 'remediate' komutu
    remed_parser = subparsers.add_parser("remediate", help="Zafiyetler için PowerShell sıkılaştırma betiği üret")
    remed_parser.add_argument("-i", "--input-file", required=True, help="Servis envanteri JSON dosya yolu")
    remed_parser.add_argument("-o", "--output", help="Betiğin kaydedileceği .ps1 dosya yolu")

    # 'service-help' komutu
    subparsers.add_parser("service-help", help="Windows servis güvenliği referans rehberini görüntüle")

    args = parser.parse_args()

    # Eğer komut belirtilmemişse yardım yazdırılır
    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        return cmd_audit(args)
    elif args.command == "remediate":
        return cmd_remediate(args)
    elif args.command == "service-help":
        return cmd_help_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
