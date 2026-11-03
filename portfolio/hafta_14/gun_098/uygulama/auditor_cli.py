# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 098: Aşama 4 Kalite Özeti — Otomasyon Denetim CLI Arayüzü.
Standart Unix ve PowerShell boru hatları (pipeline) ile tam uyumlu çalışır.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve çıkış kodları modülü
import sys
# Dosya ve dizin işlemleri
import os
# JSON veri serileştirme
import json

# Yerel modülü içe aktarabilmek için dosya yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek denetim motorunu ve istisnaları içe aktar
from uygulama.stage4_quality_auditor import (
    Stage4QualityAuditor,
    QualityScorecard,
    AuditSecurityError,
    CodeInjectionRiskError,
    HardcodedSecretDetectedError,
    BareExceptBlockError,
    LicenseComplianceError,
    QualityScoreThresholdError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """CLI argüman ayrıştırıcısını kurar."""
    parser = argparse.ArgumentParser(
        prog="auditor_cli",
        description="G098: Aşama 4 Siber Güvenlik Otomasyonu Kalite ve Yönetişim Denetçisi"
    )
    # Hedef dosya seçeneği
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Denetlenecek tekil Python betiğinin dosya yolu"
    )
    # Hedef dizin seçeneği
    parser.add_argument(
        "-d", "--dir",
        type=str,
        help="Denetlenecek tüm Python betiklerini içeren dizin yolu"
    )
    # Geçme puanı eşiği
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=80.0,
        help="Kabul edilebilir minimum kalite ve güvenlik skoru (varsayılan: 80.0)"
    )
    # Sıkı mod bayrağı
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Kritik bulgularda veya eşik altında doğrudan hata fırlatmayı zorunlu kılar"
    )
    # JSON çıktı bayrağı
    parser.add_argument(
        "--json",
        action="store_true",
        help="Denetim sonuçlarını JSON formatında stdout'a basar"
    )
    # Çıktı dosyası seçeneği
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Raporun kaydedileceği hedef dosya"
    )
    return parser


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları döner."""
    parser = build_parser()
    args = parser.parse_args()

    # Dosya veya dizin belirtilmemişse hata ver
    if not args.file and not args.dir:
        sys.stderr.write("[HATA] Lütfen denetlenecek bir dosya (--file) veya dizin (--dir) belirtin.\n")
        return 2

    # Denetçi motorunu başlat
    auditor = Stage4QualityAuditor(min_pass_score=args.threshold)
    scorecards = []

    try:
        # Tekil dosya denetimi
        if args.file:
            card = auditor.audit_file(args.file, strict_mode=args.strict)
            scorecards.append(card)
        # Dizin taraması
        elif args.dir:
            if not os.path.isdir(args.dir):
                sys.stderr.write(f"[HATA] Dizin bulunamadı: {args.dir}\n")
                return 2
            for root, _, files in os.walk(args.dir):
                for f in sorted(files):
                    if f.endswith(".py"):
                        fp = os.path.join(root, f)
                        card = auditor.audit_file(fp, strict_mode=args.strict)
                        scorecards.append(card)

        # Çıktı hazırlama
        data_to_export = [c.__dict__ for c in scorecards]

        if args.json:
            print(json.dumps(data_to_export, indent=2, ensure_ascii=False))
        else:
            print("=" * 90)
            print(f"{'HEDEF DOSYA':<35} | {'SKOR':<6} | {'GÜVENLİK':<9} | {'TEST':<6} | {'MİMARİ':<8} | {'DURUM':<6}")
            print("-" * 90)
            for c in scorecards:
                print(f"{os.path.basename(c.hedef_dosya):<35} | {c.toplam_puan:<6} | {c.kod_guvenligi_puani:<9} | {c.test_ve_dayaniklilik_puani:<6} | {c.mimari_ve_standartlar_puani:<8} | {c.durum:<6}")
            print("=" * 90)

        # Dosyaya kaydetme
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                json.dump(data_to_export, out_f, indent=2, ensure_ascii=False)
            sys.stderr.write(f"[BİLGİ] Kalite raporu kaydedildi: {args.output}\n")

        # Herhangi bir dosya FAIL aldıysa çıkış kodu 1
        if any(c.durum == "FAIL" for c in scorecards):
            return 1
        return 0

    except AuditSecurityError as sec_err:
        sys.stderr.write(f"[DENETİM İHLALİ] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
