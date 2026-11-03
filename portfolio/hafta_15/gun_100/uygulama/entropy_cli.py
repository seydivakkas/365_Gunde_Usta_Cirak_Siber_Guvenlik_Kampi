# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 100: Entropi ve Rastgelelik Analiz CLI Arayüzü.
Dosyaların ve veri akışlarının entropisini hesaplar, PRNG vs CSPRNG karşılaştırması yapar.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve standart çıkış kodları modülü
import sys
# Dosya ve dizin yol yönetimi
import os
# JSON veri serileştirme
import json
# Zaman ve tarih modülü
import time
# Standart sözde rastgele modül (sadece karşılaştırma amaçlı)
import random

# Yerel modülü içe aktarabilmek için ana yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.entropy_randomness_engine import (
    EntropyMath,
    CSPRNGGenerator,
    EntropyAuditor,
    EntropyMetrics,
    EntropyAuditReport,
    EntropySecurityError,
    WeakPRNGDetectedError,
    InsufficientEntropyError,
    PredictableSeedError,
    SmallEntropySpaceError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """CLI argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(
        prog="entropy_cli",
        description="G100: Entropi ve Kriptografik Rastgelelik Analiz Aracı"
    )
    # Hedef dosya yolu
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Entropisi analiz edilecek dosya yolu"
    )
    # Doğrudan metin girdisi
    parser.add_argument(
        "-s", "--string",
        type=str,
        help="Entropisi analiz edilecek doğrudan metin dizgisi"
    )
    # Kriptografik anahtar üretim seçeneği
    parser.add_argument(
        "-g", "--generate-key",
        action="store_true",
        help="256-bit CSPRNG kriptografik anahtar üretir ve entropisini raporlar"
    )
    # PRNG ve CSPRNG karşılaştırma testi
    parser.add_argument(
        "--compare-prng",
        action="store_true",
        help="Standart PRNG (random) ile CSPRNG (secrets) arasındaki farkı gösterir"
    )
    # Shannon kabul eşiği
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=7.0,
        help="Minimum kabul edilebilir Shannon entropisi (varsayılan: 7.0)"
    )
    # Sıkı mod
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Entropi eşiğin altındaysa çıkış kodu 1 döndürür"
    )
    # JSON çıktı bayrağı
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON formatında stdout'a yazar"
    )
    # Çıktı dosya yolu
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Raporun kaydedileceği hedef dosya"
    )
    return parser


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları üretir."""
    parser = build_parser()
    args = parser.parse_args()

    # Parametre verilmemişse yardım göster ve çık
    if not args.file and not args.string and not args.generate_key and not args.compare_prng:
        parser.print_help(sys.stderr)
        return 2

    auditor = EntropyAuditor(min_pass_shannon=args.threshold)

    try:
        # ----------------------------------------------------------------------
        # 1. PRNG VS CSPRNG KARŞILAŞTIRMA TESTİ
        # ----------------------------------------------------------------------
        if args.compare_prng:
            # 1.000 bayt zayıf PRNG (random)
            weak_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
            weak_metrics = EntropyMath.calculate_all(weak_bytes)

            # 1.000 bayt CSPRNG (secrets)
            csprng_bytes = CSPRNGGenerator.generate_key(bits=8000)
            csprng_metrics = EntropyMath.calculate_all(csprng_bytes)

            print("=" * 85)
            print("GÜN 100: PRNG (Mersenne Twister) VS CSPRNG (OS Entropi Havuzu) KARŞILAŞTIRMASI")
            print("=" * 85)
            print(f"{'METRİK':<30} | {'PRNG (random)':<22} | {'CSPRNG (secrets)':<22}")
            print("-" * 85)
            print(f"{'Shannon Entropisi (bit/bayt)':<30} | {weak_metrics.shannon_entropi:<22} | {csprng_metrics.shannon_entropi:<22}")
            print(f"{'Min-Entropi (bit/bayt)':<30} | {weak_metrics.min_entropi:<22} | {csprng_metrics.min_entropi:<22}")
            print(f"{'Ki-Kare Değeri':<30} | {weak_metrics.chi_kare:<22} | {csprng_metrics.chi_kare:<22}")
            print(f"{'Monobit Oranı (1 Oranı)':<30} | {weak_metrics.monobit_oran:<22} | {csprng_metrics.monobit_oran:<22}")
            print(f"{'Monobit p-Değeri':<30} | {weak_metrics.monobit_p_degeri:<22} | {csprng_metrics.monobit_p_degeri:<22}")
            print(f"{'Kriptografik Uygunluk':<30} | {'REDDEDİLDİ (CWE-338)':<22} | {'ONAYLANDI (CSPRNG)':<22}")
            print("=" * 85)
            return 0

        # ----------------------------------------------------------------------
        # 2. KRİPTOGRAFİK ANAHTAR ÜRETİMİ
        # ----------------------------------------------------------------------
        if args.generate_key:
            key_bytes = CSPRNGGenerator.generate_key(bits=256)
            report = auditor.audit_bytes(key_bytes, target_name="Generated_CSPRNG_256Key")
            print("=" * 80)
            print("ÜRETİLEN KRİPTOGRAFİK GÜVENLİ ANAHTAR (256-Bit CSPRNG):")
            print(f"  Hex     : {key_bytes.hex()}")
            print(f"  Entropi : {report.metrikler['shannon_entropi']} bit/bayt (Max: 8.0)")
            print(f"  Durum   : {'GÜVENLİ' if report.kriptografik_guvenli_mi else 'GÜVENSİZ'}")
            print("=" * 80)
            return 0

        # ----------------------------------------------------------------------
        # 3. DOSYA VEYA METİN ANALİZİ
        # ----------------------------------------------------------------------
        if args.file:
            report = auditor.audit_file(args.file, strict_mode=args.strict)
        elif args.string:
            report = auditor.audit_bytes(args.string.encode("utf-8"), target_name="inline_input", strict_mode=args.strict)

        res_dict = report.__dict__

        if args.json:
            print(json.dumps(res_dict, indent=2, ensure_ascii=False))
        else:
            print("=" * 80)
            print(f"GÜN 100: ENTROPİ ANALİZ RAPORU ({report.hedef_adi})")
            print("=" * 80)
            m = report.metrikler
            print(f"  Shannon Entropisi     : {m['shannon_entropi']} bit/bayt (Eşik: {args.threshold})")
            print(f"  Min-Entropi           : {m['min_entropi']} bit/bayt")
            print(f"  Ki-Kare Değeri        : {m['chi_kare']}")
            print(f"  Monobit 1 Bit Oranı   : {m['monobit_oran']}")
            print(f"  Monobit p-Değeri      : {m['monobit_p_degeri']}")
            print(f"  Toplam Bayt / Tekil   : {m['bayt_sayisi']} bayt / {m['tekil_bayt_sayisi']} tekil")
            print(f"  Güvenlik Derecesi     : {m['degerlendirme']}")
            print(f"  Kriptografik Uygunluk : {'ONAYLANDI (PASS)' if report.kriptografik_guvenli_mi else 'REDDEDİLDİ (FAIL)'}")
            if report.uyarilar:
                print("  UYARILAR:")
                for u in report.uyarilar:
                    print(f"    - {u}")
            print("=" * 80)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                json.dump(res_dict, out_f, indent=2, ensure_ascii=False)
            sys.stderr.write(f"[BİLGİ] Entropi raporu kaydedildi: {args.output}\n")

        return 0 if report.kriptografik_guvenli_mi else 1

    except EntropySecurityError as sec_err:
        sys.stderr.write(f"[GÜVENLİK İHLALİ] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
