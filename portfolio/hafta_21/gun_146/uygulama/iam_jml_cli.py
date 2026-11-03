"""
Gün 146: IAM JML Komut Satırı Yönetim Arayüzü (CLI)
===================================================
Bu araç; İK ve BT sistemleri arasındaki IAM yaşam döngüsü süreçlerini (Joiner,
Mover, Leaver) komut satırından yönetir, kurumsal dizin denetimini icra eder
ve otomatik PowerShell sertleştirme betikleri üretir.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import argparse
import json
import sys
import os
from typing import List

# Güvenlik motoru bileşenlerini içe aktar
from iam_jml_lifecycle_engine import (
    IAMJMLEngine,
    EmployeeRecord,
    LifecycleStatus,
    JMLAuditResult
)


def run_audit(args: argparse.Namespace) -> int:
    """Kurumsal dizin dosyasını yükler ve kapsamlı JML denetimi gerçekleştirir."""
    # Belirtilen dosya yolunun varlığını denetle
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Belirtilen dizin dosyası bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    # JSON dosyasını oku
    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    # IAM JML motorunu başlat
    engine = IAMJMLEngine(dormant_threshold_days=args.atıl_gun)
    # Verileri motora yükle
    engine.load_directory_data(raw_data)

    # Denetimi icra et
    result = engine.audit_directory()

    # Rapor başlığını ekrana yazdır
    print("=" * 70)
    print("KURUMSAL IAM YAŞAM DÖNGÜSÜ (JML) DENETİM RAPORU")
    print("=" * 70)
    print(f"Toplam Personel (İK)     : {result.total_employees}")
    print(f"Toplam Sistem Hesabı     : {result.total_accounts}")
    print(f"Yetim Hesap (Orphan)     : {result.orphan_accounts_count}")
    print(f"Yetki Birikimi (Creep)   : {result.privilege_creep_count}")
    print(f"Görevler Ayrılığı (SoD)  : {result.sod_violations_count}")
    print(f"Atıl Hesap (> {args.atıl_gun} Gün)  : {result.dormant_accounts_count}")
    print("-" * 70)
    print(f"Genel IAM Güvenlik Puanı : {result.security_score:.1f} / 100")
    durum_str = "UYUMLU (COMPLIANT)" if result.is_compliant else "UYUMSUZ / RİSKLİ (NON-COMPLIANT)"
    print(f"Uyumluluk Durumu         : {durum_str}")
    print("=" * 70)

    # Bulguları listele
    if result.findings:
        print("\n[!] TESPİT EDİLEN GÜVENLİK BULGULARI:")
        for idx, f in enumerate(result.findings, 1):
            sev_tag = f"[{f.severity.value}]"
            print(f"  {idx}. {sev_tag:<10} {f.rule_id} -> {f.title}")
            print(f"     Ayrıntı   : {f.details}")
            print(f"     Düzeltme  : {f.remediation}")
    else:
        print("\n[+] Harika! Kurumsal dizinde yetim hesap, yetki birikimi veya SoD ihlali bulunmadı.")

    # İsteğe bağlı JSON çıktı kaydetme
    if args.cikis_json:
        report_data = {
            "toplam_personel": result.total_employees,
            "toplam_hesap": result.total_accounts,
            "yetim_hesap_sayisi": result.orphan_accounts_count,
            "yetki_birikimi_sayisi": result.privilege_creep_count,
            "sod_ihlal_sayisi": result.sod_violations_count,
            "atil_hesap_sayisi": result.dormant_accounts_count,
            "guvenlik_puani": result.security_score,
            "uyumlu": result.is_compliant,
            "bulgular": [
                {
                    "kural_id": f.rule_id,
                    "baslik": f.title,
                    "onem": f.severity.value,
                    "calisan_id": f.employee_id,
                    "hesap_id": f.account_id,
                    "ayrinti": f.details,
                    "duzeltme": f.remediation
                }
                for f in result.findings
            ]
        }
        with open(args.cikis_json, "w", encoding="utf-8") as fp:
            json.dump(report_data, fp, ensure_ascii=False, indent=2)
        print(f"\n[+] Denetim JSON raporu kaydedildi: {args.cikis_json}")

    # İsteğe bağlı PowerShell düzeltme betiği üretme
    if args.uret_remediation:
        ps1_code = engine.generate_remediation_powershell(result)
        with open(args.uret_remediation, "w", encoding="utf-8") as fp:
            fp.write(ps1_code)
        print(f"[+] Otomatik PowerShell sertleştirme betiği üretildi: {args.uret_remediation}")

    return 0 if result.is_compliant else 2


def run_joiner(args: argparse.Namespace) -> int:
    """Yeni bir personel katılımını (Joiner) simüle eder."""
    # Veri dosyasını yükle
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Dosya bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    engine = IAMJMLEngine()
    engine.load_directory_data(raw_data)

    new_emp = EmployeeRecord(
        employee_id=args.emp_id,
        name=args.ad,
        department=args.departman,
        job_title=args.unvan,
        manager_id=args.yonetici_id,
        status=LifecycleStatus.PENDING_ONBOARDING,
        start_date=args.tarih
    )

    try:
        roles = [r.strip() for r in args.roller.split(",") if r.strip()]
        systems = [s.strip() for s in args.sistemler.split(",") if s.strip()]
        res = engine.process_joiner(
            employee=new_emp,
            target_systems=systems,
            birthright_roles=roles,
            approver=args.onaylayan
        )
        print("[+] JOINER İŞLEMİ BAŞARILI:")
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except Exception as e:
        print(f"[!] JOINER BAŞARISIZ: {e}", file=sys.stderr)
        return 1


def run_mover(args: argparse.Namespace) -> int:
    """Personel departman/rol transferini (Mover) simüle eder."""
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Dosya bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    engine = IAMJMLEngine()
    engine.load_directory_data(raw_data)

    try:
        new_roles = [r.strip() for r in args.roller.split(",") if r.strip()]
        res = engine.process_mover(
            employee_id=args.emp_id,
            new_department=args.yeni_departman,
            new_job_title=args.yeni_unvan,
            new_roles=new_roles,
            revoke_old_roles=(not args.eski_rolleri_tut),
            approver=args.onaylayan
        )
        print("[+] MOVER İŞLEMİ BAŞARILI:")
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except Exception as e:
        print(f"[!] MOVER BAŞARISIZ: {e}", file=sys.stderr)
        return 1


def run_leaver(args: argparse.Namespace) -> int:
    """Personel işten ayrılmasını (Leaver) ve hesap kapatmayı simüle eder."""
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Dosya bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_data = json.load(fp)

    engine = IAMJMLEngine()
    engine.load_directory_data(raw_data)

    try:
        res = engine.process_leaver(
            employee_id=args.emp_id,
            termination_date=args.tarih,
            immediate=True,
            approver=args.onaylayan
        )
        print("[+] LEAVER İŞLEMİ BAŞARILI (Tüm hesaplar kapatıldı):")
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    except Exception as e:
        print(f"[!] LEAVER BAŞARISIZ: {e}", file=sys.stderr)
        return 1


def main() -> None:
    """Ana komut satırı ayrıştırıcı ve yönlendirici."""
    parser = argparse.ArgumentParser(
        description="Gün 146: Kurumsal IAM JML (Joiner, Mover, Leaver) Yaşam Döngüsü ve Güvenlik Denetim Aracı",
        epilog="Örnek: python iam_jml_cli.py audit ornek_veri/iam_organization_directory.json"
    )

    subparsers = parser.add_subparsers(dest="command", help="Yürütülecek alt komut")

    # Audit alt komutu
    audit_parser = subparsers.add_parser("audit", help="Kurumsal dizini JML ve SoD risklerine karşı denetler")
    audit_parser.add_argument("dosya", help="Kurumsal dizin JSON dosyası yolu")
    audit_parser.add_argument("--atil-gun", type=int, default=90, help="Atıl hesap kabul eşik günü (varsayılan: 90)")
    audit_parser.add_argument("--cikis-json", help="Denetim raporunu JSON dosyası olarak kaydet")
    audit_parser.add_argument("--uret-remediation", help="Yetim hesaplar için PowerShell düzeltme betiği üret")

    # Joiner alt komutu
    joiner_parser = subparsers.add_parser("joiner", help="Yeni personel başlangıç (onboarding) sürecini yürütür")
    joiner_parser.add_argument("dosya", help="Kurumsal dizin JSON dosyası yolu")
    joiner_parser.add_argument("--emp-id", required=True, help="Personel kimlik numarası (örn: EMP-101)")
    joiner_parser.add_argument("--ad", required=True, help="Personel tam adı")
    joiner_parser.add_argument("--departman", required=True, help="Atandığı departman")
    joiner_parser.add_argument("--unvan", required=True, help="İş unvanı")
    joiner_parser.add_argument("--yonetici-id", default="MGR-001", help="Yönetici kimliği")
    joiner_parser.add_argument("--tarih", default="2026-11-03", help="İşe başlama tarihi")
    joiner_parser.add_argument("--roller", required=True, help="Virgülle ayrılmış başlangıç rolleri")
    joiner_parser.add_argument("--sistemler", default="ActiveDirectory,EntraID", help="Hesap açılacak sistemler")
    joiner_parser.add_argument("--onaylayan", required=True, help="İK onaylayıcı adı")

    # Mover alt komutu
    mover_parser = subparsers.add_parser("mover", help="Personel rol/departman değişim sürecini yürütür")
    mover_parser.add_argument("dosya", help="Kurumsal dizin JSON dosyası yolu")
    mover_parser.add_argument("--emp-id", required=True, help="Personel kimlik numarası")
    mover_parser.add_argument("--yeni-departman", required=True, help="Yeni departman adı")
    mover_parser.add_argument("--yeni-unvan", required=True, help="Yeni iş unvanı")
    mover_parser.add_argument("--roller", required=True, help="Yeni departman rolleri")
    mover_parser.add_argument("--eski-rolleri-tut", action="store_true", help="Yetki birikimi riski: Eski rolleri silme")
    mover_parser.add_argument("--onaylayan", required=True, help="Bölüm başkanı / İK onaylayıcı")

    # Leaver alt komutu
    leaver_parser = subparsers.add_parser("leaver", help="İşten ayrılma ve derhal hesap kapatma sürecini yürütür")
    leaver_parser.add_argument("dosya", help="Kurumsal dizin JSON dosyası yolu")
    leaver_parser.add_argument("--emp-id", required=True, help="Personel kimlik numarası")
    leaver_parser.add_argument("--tarih", default="2026-11-03", help="Ayrılma tarihi")
    leaver_parser.add_argument("--onaylayan", required=True, help="İK yöneticisi onaylayıcı")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        sys.exit(run_audit(args))
    elif args.command == "joiner":
        sys.exit(run_joiner(args))
    elif args.command == "mover":
        sys.exit(run_mover(args))
    elif args.command == "leaver":
        sys.exit(run_leaver(args))


if __name__ == "__main__":
    main()
