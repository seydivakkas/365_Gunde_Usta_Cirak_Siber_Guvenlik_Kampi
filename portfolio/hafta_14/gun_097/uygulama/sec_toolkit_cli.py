# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 097: Mini Proje 13 — Çevrimdışı (Air-Gapped) Güvenlik Araç Seti CLI Arayüzü.
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

# Çekirdek modülleri ve istisnaları içe aktar
from uygulama.offline_security_toolkit import (
    run_airgap_doctor,
    validate_network_asset,
    calculate_file_hash,
    verify_file_hash,
    create_directory_baseline,
    scan_directory_fim,
    mask_sensitive_text,
    profile_execution,
    ToolkitSecurityError,
    IntegrityVerificationError,
    AssetValidationError,
    PerformanceBudgetExceededError,
    UnknownSubcommandError
)


def build_parser() -> argparse.ArgumentParser:
    """Tümleşik komut satırı ayrıştırıcısını alt komutlarla (subparsers) kurar."""
    parser = argparse.ArgumentParser(
        prog="sec_toolkit",
        description="G097: Çevrimdışı (Air-Gapped) Modüler Siber Güvenlik Araç Seti"
    )
    # Alt komut yöneticisi
    subparsers = parser.add_subparsers(dest="command", help="Yürütülecek güvenlik alt komutu")

    # 1. doctor alt komutu
    subparsers.add_parser("doctor", help="Hava boşluklu izole ortam hazır bulunuşluk taraması")

    # 2. validate alt komutu
    p_val = subparsers.add_parser("validate", help="Ağ varlığı JSON dosyasını doğrular")
    p_val.add_argument("--file", "-f", required=True, help="Doğrulanacak JSON varlık dosyası")

    # 3. hash alt komutu
    p_hash = subparsers.add_parser("hash", help="Dosyanın kriptografik özetini üretir")
    p_hash.add_argument("--file", "-f", required=True, help="Özeti alınacak dosya")
    p_hash.add_argument("--algo", "-a", default="sha256", choices=["sha256", "sha512", "blake2b"], help="Hash algoritması")

    # 4. fim alt komutu
    p_fim = subparsers.add_parser("fim", help="Dosya Bütünlük İzleme (FIM) taban çizgisi ve taraması")
    p_fim.add_argument("--dir", "-d", required=True, help="İzlenecek hedef dizin")
    p_fim.add_argument("--action", choices=["baseline", "scan"], default="baseline", help="İşlem türü")
    p_fim.add_argument("--baseline-file", "-b", default="baseline.json", help="Taban çizgisi JSON dosyası")

    # 5. mask alt komutu
    p_mask = subparsers.add_parser("mask", help="Log veya metin içerisindeki kişisel verileri maskeler")
    p_mask.add_argument("--file", "-f", help="Maskelenecek dosya")
    p_mask.add_argument("--text", "-t", help="Doğrudan metin")
    p_mask.add_argument("--style", "-s", choices=["MASK", "REDACT"], default="MASK", help="Maskeleme stili")

    # 6. bench alt komutu
    p_bench = subparsers.add_parser("bench", help="Performans ve bellek profilleme koşturur")
    p_bench.add_argument("--bytes", type=int, default=65536, help="Test veri boyutu (bayt)")
    p_bench.add_argument("--threshold-ms", type=float, default=None, help="Maksimum kabul edilebilir süre (ms)")

    return parser


def main() -> int:
    """CLI ana fonksiyonu. Standart POSIX çıkış kodları döner."""
    parser = build_parser()
    args = parser.parse_args()

    # Eğer komut belirtilmemişse yardım göster
    if not args.command:
        parser.print_help()
        return 2

    try:
        # 1. DOCTOR
        if args.command == "doctor":
            rep = run_airgap_doctor()
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0

        # 2. VALIDATE
        elif args.command == "validate":
            if not os.path.exists(args.file):
                sys.stderr.write(f"[HATA] Dosya bulunamadı: {args.file}\n")
                return 2
            with open(args.file, "r", encoding="utf-8") as f:
                data = json.load(f)
            assets = data if isinstance(data, list) else [data]
            for idx, a in enumerate(assets):
                validate_network_asset(a)
            print(f"[BAŞARILI] {len(assets)} adet ağ varlığı doğrulandı.")
            return 0

        # 3. HASH
        elif args.command == "hash":
            h_val = calculate_file_hash(args.file, algo=args.algo)
            print(f"{args.algo.upper()}: {h_val}  {args.file}")
            return 0

        # 4. FIM
        elif args.command == "fim":
            if args.action == "baseline":
                base = create_directory_baseline(args.dir)
                with open(args.baseline_file, "w", encoding="utf-8") as bf:
                    json.dump(base, bf, indent=2, ensure_ascii=False)
                print(f"[BAŞARILI] {len(base)} dosya için FIM taban çizgisi oluşturuldu: {args.baseline_file}")
                return 0
            else:
                if not os.path.exists(args.baseline_file):
                    sys.stderr.write(f"[HATA] Taban çizgisi dosyası bulunamadı: {args.baseline_file}\n")
                    return 2
                with open(args.baseline_file, "r", encoding="utf-8") as bf:
                    base = json.load(bf)
                scan_res = scan_directory_fim(args.dir, base)
                print(json.dumps(scan_res, indent=2, ensure_ascii=False))
                # Değişiklik varsa uyarı kodu 1
                if scan_res["ADDED"] or scan_res["MODIFIED"] or scan_res["REMOVED"]:
                    return 1
                return 0

        # 5. MASK
        elif args.command == "mask":
            raw_text = ""
            if args.file:
                with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                    raw_text = f.read()
            elif args.text:
                raw_text = args.text
            else:
                sys.stderr.write("[HATA] Lütfen --file veya --text belirtin.\n")
                return 2
            masked_res, stats = mask_sensitive_text(raw_text, mask_style=args.style)
            print(masked_res)
            return 0

        # 6. BENCH
        elif args.command == "bench":
            test_data = b"X" * args.bytes
            bench_res = profile_execution(
                lambda: hashlib.sha256(test_data).hexdigest(),
                threshold_ms=args.threshold_ms
            )
            print(f"SHA-256 ({args.bytes} B): {bench_res['elapsed_ms']} ms | Tepe Bellek: {bench_res['peak_memory_bytes']} B")
            return 0

        else:
            raise UnknownSubcommandError(f"Tanımsız alt komut: {args.command}")

    except IntegrityVerificationError as iv_err:
        sys.stderr.write(f"[FIM İHLALİ] {str(iv_err)}\n")
        return 1
    except PerformanceBudgetExceededError as pb_err:
        sys.stderr.write(f"[SLA İHLALİ] {str(pb_err)}\n")
        return 1
    except ToolkitSecurityError as tk_err:
        sys.stderr.write(f"[GÜVENLİK ENGELİ] {type(tk_err).__name__}: {str(tk_err)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
