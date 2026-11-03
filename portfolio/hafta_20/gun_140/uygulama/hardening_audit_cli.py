# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 20 / Gün 140 - Mini Proje 19: Linux Sertleştirme Kontrolü Komut Satırı Arayüzü (CLI).
Bu araç, sistem yöneticilerine ve denetçilere; Linux sistem envanterlerini denetleme,
detaylı uyumluluk raporu alma ve otomatik sıkılaştırma betiği üretme yeteneği sunar.
"""

# İşletim sistemi dosya yolu ve ortam fonksiyonları
import os
# Çıkış kodları ve akış yönetimi
import sys
# Komut satırı argümanlarını ayrıştırmak için standart argparse kütüphanesi
import argparse
# JSON veri formatı ayrıştırma
import json

# Windows konsolunda UTF-8 çıktı uyumluluğunu sağla
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Aynı paketteki denetim motorunu import et
from linux_hardening_audit_engine import LinuxHardeningAuditEngine


def run_cli() -> int:
    """
    Komut satırı argümanlarını işler ve ilgili denetim fonksiyonunu çağırır.
    """
    parser = argparse.ArgumentParser(
        description="Linux Sertleştirme Denetim ve Uyumluluk CLI Aracı (Mini Proje 19)"
    )

    # Alt komut yöneticisi (subparsers) tanımla
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'audit' alt komutu
    audit_parser = subparsers.add_parser("audit", help="Sistem envanterini denetle")
    audit_parser.add_argument("inventory", help="Denetlenecek JSON envanter dosyası yolu")
    audit_parser.add_argument("--output", "-o", help="Oluşturulacak JSON rapor çıktısı dosya yolu")

    # 2. 'generate-remediation' alt komutu
    fix_parser = subparsers.add_parser("generate-remediation", help="Otomatik düzeltme betiği üret")
    fix_parser.add_argument("inventory", help="Denetlenecek JSON envanter dosyası yolu")
    fix_parser.add_argument("--output", "-o", required=True, help="Oluşturulacak Bash betik dosya yolu (.sh)")

    # 3. 'verify' alt komutu (Hızlı başarı/başarısızlık kontrolü)
    verify_parser = subparsers.add_parser("verify", help="Uyumluluk durumunu hızlıca doğrula (Exit code 0 veya 1)")
    verify_parser.add_argument("inventory", help="Denetlenecek JSON envanter dosyası yolu")

    args = parser.parse_args()

    # Eğer hiçbir komut verilmemişse yardım ekranını göster
    if not args.command:
        parser.print_help()
        return 1

    # Envanter dosyasının varlığını kontrol et
    if not os.path.exists(args.inventory):
        print(f"[-] Hata: Envanter dosyası bulunamadı: {args.inventory}", file=sys.stderr)
        return 1

    # Denetim motorunu ilklendir
    engine = LinuxHardeningAuditEngine()
    engine.load_inventory_from_file(args.inventory)

    # Alt komut dallanması
    if args.command == "audit":
        report = engine.run_full_hardening_audit()
        print("=" * 78)
        print(f" LINUX SERTLEŞTİRME DENETİM RAPORU — HEDEF: {report.target_host}")
        print("=" * 78)
        print(f"Genel Uyumluluk Puanı : {report.compliance_score} / 100")
        print(f"Genel Uyumluluk Durumu: {report.overall_status}")
        print(f"Toplam Kontrol        : {report.summary_counts['total_checks']}")
        print(f"Başarılı (PASS)       : {report.summary_counts['passed_checks']}")
        print(f"Başarısız (FAIL)      : {report.summary_counts['failed_checks']}")
        print("-" * 78)
        print("ALAN BAZLI PUANLAR:")
        for d_key, d_res in report.domain_results.items():
            print(f"  * {d_key:<28} : %{d_res.score:>5.1f} (Başarılı: {d_res.passed_checks}/{d_res.total_checks})")
        print("-" * 78)

        if report.summary_counts["failed_checks"] > 0:
            print("BAŞARISIZ OLAN KRİTİK BULGULAR:")
            for step in report.remediation_steps:
                print(f"  [-] {step}")
            print("-" * 78)

        if args.output:
            engine.export_report_json(args.output)
            print(f"[+] Detaylı denetim raporu kaydedildi: {args.output}")

        return 0

    elif args.command == "generate-remediation":
        content = engine.generate_remediation_script(args.output)
        print(f"[+] Otomatik düzeltme betiği oluşturuldu: {args.output}")
        print(f"[+] Boyut: {len(content)} bayt. İcra etmek için: bash {args.output}")
        return 0

    elif args.command == "verify":
        report = engine.run_full_hardening_audit()
        if report.overall_status == "COMPLIANT":
            print(f"[PASS] Sistem uyumlu. Puan: {report.compliance_score}/100")
            return 0
        else:
            print(f"[FAIL] Sistem güvensiz! Puan: {report.compliance_score}/100 (Durum: {report.overall_status})")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
