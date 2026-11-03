"""
Gün 147: Mini Proje 20 — IAM Politika Matrisi CLI Yönetim Aracı
===============================================================
Bu araç; kurumsal IAM politika matrisini denetler, kullanıcıların hedef
kaynaklara erişim izinlerini Katman (Tier 0-2) ve Sıfır Güven (ABAC) kuralları
çerçevesinde simüle eder ve PowerShell sertleştirme betikleri üretir.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

import argparse
import json
import sys
import os

# Güvenlik motoru bileşenlerini içe aktar
from iam_policy_matrix_engine import (
    IAMPolicyMatrixEngine,
    DecisionType
)


def run_audit(args: argparse.Namespace) -> int:
    """Kurumsal IAM politika matrisini yükler ve zafiyet taramasını yürütür."""
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Matris dosyası bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_spec = json.load(fp)

    engine = IAMPolicyMatrixEngine()
    engine.load_matrix_spec(raw_spec)

    audit_summary = engine.audit_entire_matrix()

    print("=" * 70)
    print("MİNİ PROJE 20: KURUMSAL IAM POLİTİKA MATRİSİ DENETİM RAPORU")
    print("=" * 70)
    print(f"Toplam Özne (Kullanıcı)  : {audit_summary.total_subjects}")
    print(f"Toplam Hedef Kaynak      : {audit_summary.total_resources}")
    print(f"Kısıtlamasız Yetki Devri : {audit_summary.unconstrained_delegation_count}")
    print(f"Yetim Hesap (Orphan)     : {audit_summary.orphan_accounts_count}")
    print(f"Görevler Ayrılığı (SoD)  : {audit_summary.sod_violations_count}")
    print(f"Aşırı Yetkili (Over-Priv): {audit_summary.overprivileged_subjects_count}")
    print("-" * 70)
    print(f"Genel IAM Matris Puanı   : {audit_summary.overall_security_score:.1f} / 100")
    durum_str = "TAM UYUMLU (PASS)" if audit_summary.is_compliant else "UYUMSUZ / RİSKLİ (NON-COMPLIANT)"
    print(f"Uyumluluk Durumu         : {durum_str}")
    print("=" * 70)

    if audit_summary.findings:
        print("\n[!] TESPİT EDİLEN GÜVENLİK BULGULARI:")
        for idx, f in enumerate(audit_summary.findings, 1):
            sev_badge = f"[{f.severity.value}]"
            print(f"  {idx}. {sev_badge:<10} {f.rule_id} -> {f.title}")
            print(f"     Etkilenen : {f.affected_entity}")
            print(f"     Ayrıntı   : {f.details}")
            print(f"     Düzeltme  : {f.remediation}")
    else:
        print("\n[+] Harika! Politika matrisinde hiçbir güvenlik açığı veya yetki ihlali bulunmadı.")

    if args.cikis_json:
        out_dict = {
            "toplam_ozne": audit_summary.total_subjects,
            "toplam_kaynak": audit_summary.total_resources,
            "unconstrained_delegation": audit_summary.unconstrained_delegation_count,
            "yetim_hesap_sayisi": audit_summary.orphan_accounts_count,
            "sod_ihlal_sayisi": audit_summary.sod_violations_count,
            "asiri_yetkili_sayisi": audit_summary.overprivileged_subjects_count,
            "guvenlik_puani": audit_summary.overall_security_score,
            "uyumlu": audit_summary.is_compliant,
            "bulgular": [
                {
                    "kural_id": f.rule_id,
                    "baslik": f.title,
                    "onem": f.severity.value,
                    "etkilenen": f.affected_entity,
                    "detay": f.details,
                    "duzeltme": f.remediation
                }
                for f in audit_summary.findings
            ]
        }
        with open(args.cikis_json, "w", encoding="utf-8") as fp:
            json.dump(out_dict, fp, ensure_ascii=False, indent=2)
        print(f"\n[+] Denetim raporu JSON olarak kaydedildi: {args.cikis_json}")

    if args.uret_remediation:
        ps1_code = engine.generate_remediation_powershell(audit_summary)
        with open(args.uret_remediation, "w", encoding="utf-8") as fp:
            fp.write(ps1_code)
        print(f"[+] Otomatik PowerShell sertleştirme betiği üretildi: {args.uret_remediation}")

    return 0 if audit_summary.is_compliant else 2


def run_simulate_access(args: argparse.Namespace) -> int:
    """Belirli bir kullanıcı ile hedef kaynak arasındaki dinamik erişim kararını simüle eder."""
    if not os.path.exists(args.dosya):
        print(f"[!] HATA: Matris dosyası bulunamadı: {args.dosya}", file=sys.stderr)
        return 1

    with open(args.dosya, "r", encoding="utf-8") as fp:
        raw_spec = json.load(fp)

    engine = IAMPolicyMatrixEngine()
    engine.load_matrix_spec(raw_spec)

    decision = engine.evaluate_access(args.user_id, args.resource_id)

    print("=" * 70)
    print("ERİŞİM TALEP DEĞERLENDİRME VE SIFIR GÜVEN (ZERO TRUST) KARARI")
    print("=" * 70)
    print(f"Kullanıcı Kimliği : {decision.subject_user}")
    print(f"Hedef Kaynak      : {decision.target_resource}")
    print(f"Zaman Damgası     : {decision.timestamp}")
    print("-" * 70)
    durum_tag = "[İZİN VERİLDİ - PERMIT]" if decision.decision == DecisionType.PERMIT else "[ENGELENDİ - DENY]"
    print(f"Karar             : {durum_tag}")
    print(f"Eşleşen Kural     : {decision.matched_rule}")
    print(f"Gerekçe           : {decision.reason}")
    print("=" * 70)

    return 0 if decision.decision == DecisionType.PERMIT else 1


def main() -> None:
    """Ana CLI komut yönlendirici."""
    parser = argparse.ArgumentParser(
        description="Gün 147: Mini Proje 20 — Kurumsal IAM Politika Matrisi Yönetim ve Denetim Aracı",
        epilog="Örnek: python iam_matrix_cli.py audit ornek_veri/enterprise_iam_policy_matrix.json"
    )

    subparsers = parser.add_subparsers(dest="command", help="Yürütülecek alt komut")

    # Audit alt komutu
    audit_parser = subparsers.add_parser("audit", help="Tüm politika matrisini denetler ve zafiyet raporu üretir")
    audit_parser.add_argument("dosya", help="IAM Politika Matrisi JSON dosyası yolu")
    audit_parser.add_argument("--cikis-json", help="Denetim raporunu JSON olarak kaydet")
    audit_parser.add_argument("--uret-remediation", help="Otomatik PowerShell düzeltme betiği üret")

    # Simulate Access alt komutu
    sim_parser = subparsers.add_parser("simulate-access", help="Kullanıcı-kaynak erişim kararını simüle eder")
    sim_parser.add_argument("dosya", help="IAM Politika Matrisi JSON dosyası yolu")
    sim_parser.add_argument("--user-id", required=True, help="Erişim talep eden kullanıcı kimliği")
    sim_parser.add_argument("--resource-id", required=True, help="Erişilmek istenen hedef kaynak kimliği")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        sys.exit(run_audit(args))
    elif args.command == "simulate-access":
        sys.exit(run_simulate_access(args))


if __name__ == "__main__":
    main()
