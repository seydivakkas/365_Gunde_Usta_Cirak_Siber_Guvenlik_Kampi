# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 091: Çok Platformlu Sistem Raporlayıcı CLI Komut Satırı Arayüzü (reporter_cli.py).

Bu betik; Windows ve Linux telemetri girdilerini alır, argparse motoruyla parametreleri
ayrıştırır, karşılıklı dışlayan seçenekleri ve dizin atlama kontrollerini uygular,
standart POSIX çıkış kodlarıyla (0, 1, 2) güvenli raporlama sağlar.
"""

# Standart kütüphaneler
import sys
import os
import json
import argparse

# Çekirdek motoru ve istisnaları içe aktar
from cross_platform_security_reporter import (
    CrossPlatformSecurityReporter,
    ReporterSecurityError,
    PathTraversalError,
    MutuallyExclusiveViolationError
)

def create_cli_parser() -> argparse.ArgumentParser:
    """Argparse ayrıştırıcısını güvenlik kurallarına uygun şekilde yapılandırır."""
    parser = argparse.ArgumentParser(
        prog="sec-reporter",
        description="Çok Platformlu Kurumsal Sistem Güvenlik ve Uyum Raporlayıcı Aracı"
    )
    # Telemetri dosya girdisi
    parser.add_argument(
        "--telemetry-file",
        type=str,
        required=True,
        help="İncelenecek sistem telemetrisi JSON dosyası yolu"
    )
    # Platform seçimi
    parser.add_argument(
        "--platform",
        type=str,
        choices=["windows", "linux", "auto"],
        default="auto",
        help="Hedef sistem platformu (auto durumunda telemetriden okunur)"
    )
    # Çıktı formatı
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json", "html"],
        default="text",
        help="Rapor çıktı formatı (text, json, html)"
    )
    # Karşılıklı dışlayan denetim modu grubu
    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument(
        "--fast",
        action="store_true",
        help="Hızlı ve temel denetim modu"
    )
    mode_group.add_argument(
        "--deep",
        action="store_true",
        help="Derinlemesine ve kapsamlı zafiyet denetim modu"
    )
    # Çıktı dosyası yolu
    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Raporun kaydedileceği dosya yolu (verilmezse stdout basılır)"
    )
    return parser

def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = create_cli_parser()
    
    try:
        args = parser.parse_args()
    except SystemExit as se:
        # Argparse sözdizimi hatasında exit code 2 döndür
        return 2

    reporter = CrossPlatformSecurityReporter()

    # Çıktı yolu güvenlik kontrolü (Path Traversal CWE-22)
    if args.output_file:
        try:
            reporter.validate_output_path(args.output_file)
        except PathTraversalError as pte:
            print(f"[-] Güvenlik Hatası: {pte}", file=sys.stderr)
            return 2

    # Dosya varlığı kontrolü
    if not os.path.exists(args.telemetry_file):
        print(f"[-] Hata: Belirtilen telemetri dosyası bulunamadı: {args.telemetry_file}", file=sys.stderr)
        return 1

    # Telemetri dosyasını oku
    try:
        with open(args.telemetry_file, "r", encoding="utf-8") as f:
            raw_content = f.read()
    except Exception as io_err:
        print(f"[-] Giriş/Çıkış Hatası: {io_err}", file=sys.stderr)
        return 1

    # Veriyi doğrula ve analiz et
    try:
        validated_data = reporter.validate_telemetry_payload(raw_content)
        
        # Platform geçersiz kılma varsa uygula
        if args.platform != "auto":
            validated_data["platform"] = args.platform

        # Denetimi çalıştır
        report = reporter.audit_telemetry(validated_data, deep_scan=args.deep)
        formatted_output = reporter.format_report(report, format_tipi=args.format)

        # Çıktıyı dosyaya yaz veya ekrana bas
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as out_f:
                out_f.write(formatted_output)
            print(f"[+] Güvenlik raporu başarıyla kaydedildi: {args.output_file}")
        else:
            print(formatted_output)

        return 0
    except ReporterSecurityError as sec_err:
        print(f"[-] Raporlayıcı Güvenlik Hatası: {sec_err}", file=sys.stderr)
        return 2
    except Exception as unk_err:
        print(f"[-] Beklenmeyen Çalışma Zamanı Hatası: {unk_err}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
