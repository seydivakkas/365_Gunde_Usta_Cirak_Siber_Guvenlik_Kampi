# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 141 - Yama Yönetimi ve CVE Komut Satırı Arayüzü (CLI).
Bu araç; sistem yöneticilerine ve SOC ekiplerine CVE triyajı yapma,
SLA ihlallerini tespit etme, yama planı ve geri alma betikleri üretme yeteneği sunar.
"""

# İşletim sistemi dosya yolları
import os
# Sistem akışları ve argüman yönetimi
import sys
# Komut satırı argüman ayrıştırıcısı
import argparse
# JSON veri formatı
import json

# Windows ortamında UTF-8 konsol çıktısını garantiye al
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Aynı paketteki motor sınıfını import et
from patch_cve_engine import PatchCveEngine


def run_cli() -> int:
    """
    Komut satırı argümanlarını işler ve ilgili yama operasyonlarını yürütür.
    """
    parser = argparse.ArgumentParser(
        description="Kurumsal Yama Yönetimi ve CVE Analiz CLI Aracı (Gün 141)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'scan' alt komutu
    scan_parser = subparsers.add_parser("scan", help="Sistem yama ve CVE envanterini tara")
    scan_parser.add_argument("inventory", help="Taranacak JSON envanter dosyası yolu")
    scan_parser.add_argument("--date", help="Değerlendirme tarihi (YYYY-MM-DD), varsayılan: bugün")
    scan_parser.add_argument("--output", "-o", help="Oluşturulacak JSON rapor çıktısı dosya yolu")

    # 2. 'plan' alt komutu
    plan_parser = subparsers.add_parser("plan", help="Aşamalı yama uygulama betiği üret (.sh)")
    plan_parser.add_argument("inventory", help="Taranacak JSON envanter dosyası yolu")
    plan_parser.add_argument("--date", help="Değerlendirme tarihi (YYYY-MM-DD)")
    plan_parser.add_argument("--output", "-o", required=True, help="Oluşturulacak Bash betik dosya yolu")

    # 3. 'rollback-plan' alt komutu
    roll_parser = subparsers.add_parser("rollback-plan", help="Acil durum geri alma betiği üret (.sh)")
    roll_parser.add_argument("inventory", help="Taranacak JSON envanter dosyası yolu")
    roll_parser.add_argument("--output", "-o", required=True, help="Oluşturulacak geri alma Bash betik yolu")

    # 4. 'verify' alt komutu (Hızlı denetim ve CI/CD gate kontrolü)
    verify_parser = subparsers.add_parser("verify", help="Yama hijyenini hızlıca doğrula (Exit code 0 veya 1)")
    verify_parser.add_argument("inventory", help="Taranacak JSON envanter dosyası yolu")
    verify_parser.add_argument("--date", help="Değerlendirme tarihi (YYYY-MM-DD)")

    args = parser.parse_args()

    # Argümansız çağrıda yardımı göster
    if not args.command:
        parser.print_help()
        return 1

    # Dosya mevcudiyeti kontrolü
    if not os.path.exists(args.inventory):
        print(f"[-] Hata: Envanter dosyası bulunamadı: {args.inventory}", file=sys.stderr)
        return 1

    # Motoru başlat ve envanteri yükle
    engine = PatchCveEngine()
    engine.load_inventory_from_file(args.inventory)

    if args.command == "scan":
        status = engine.evaluate_system_patch_status(current_date_str=args.date)
        print("=" * 78)
        print(f" KURUMSAL YAMA YÖNETİMİ VE CVE ANALİZ RAPORU — {status.hostname}")
        print("=" * 78)
        print(f"İşletim Sistemi       : {status.os_distribution}")
        print(f"Yama Hijyen Puanı     : {status.patch_hygiene_score} / 100")
        print(f"Uyumluluk Durumu      : {status.compliance_status}")
        print(f"Toplam Zafiyet (CVE)  : {status.total_vulnerabilities}")
        print(f"Acil Müdahale (KEV)   : {status.emergency_count}")
        print(f"SLA Süresi Aşılmış    : {status.sla_breached_count}")
        print(f"Otomatik Güncelleme   : {'Açık' if status.auto_update_enabled else 'KAPALI (Risk)'}")
        print(f"Reboot Gerekli mi?    : {'EVET (Bekliyor)' if status.reboot_required else 'Hayır'}")
        print("-" * 78)
        print("CVE TRİYAJ VE SLA TABLOSU:")
        print(f"{'CVE ID':<18} | {'ŞİDDET':<9} | {'ACİLİYET':<10} | {'SLA (GÜN)':<10} | {'GEÇEN':<6} | {'DURUM':<10}")
        print("-" * 78)
        for t in status.triage_results:
            durum_str = "SLA İHLAL!" if t.sla_breached else "OK"
            print(f"{t.cve_id:<18} | {t.severity:<9} | {t.urgency_level:<10} | {t.max_sla_days:<10} | {t.elapsed_days:<6} | {durum_str:<10}")
        print("-" * 78)

        if args.output:
            engine.export_report_json(args.output)
            print(f"[+] Detaylı JSON raporu kaydedildi: {args.output}")

        return 0

    elif args.command == "plan":
        engine.evaluate_system_patch_status(current_date_str=args.date)
        script = engine.generate_patch_execution_plan(args.output)
        print(f"[+] Yama uygulama planı oluşturuldu: {args.output} ({len(script)} bayt)")
        return 0

    elif args.command == "rollback-plan":
        engine.evaluate_system_patch_status()
        script = engine.generate_rollback_script(args.output)
        print(f"[+] Acil durum geri alma planı oluşturuldu: {args.output} ({len(script)} bayt)")
        return 0

    elif args.command == "verify":
        status = engine.evaluate_system_patch_status(current_date_str=args.date)
        if status.compliance_status == "COMPLIANT":
            print(f"[PASS] Sistem yama açısından güvenli. Hijyen Puanı: {status.patch_hygiene_score}/100")
            return 0
        else:
            print(f"[FAIL] Sistem güvensiz veya SLA ihlali var! Hijyen Puanı: {status.patch_hygiene_score}/100 (Durum: {status.compliance_status})")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
