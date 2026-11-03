# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 101: Kriptografik Hash ve Çakışma Analiz CLI Arayüzü.
Güvenli özet hesaplar, çığ etkisi ölçer ve Doğum Günü çakışma simülasyonu koşturur.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve standart çıkış kodları modülü
import sys
# Dosya ve dizin yol yönetimi
import os
# JSON veri serileştirme
import json
# Zaman modülü
import time

# Yerel modülü içe aktarabilmek için ana yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve istisnalarını içe aktar
from uygulama.hash_collision_engine import (
    HashAnalyzer,
    AvalancheResult,
    CollisionSimulationResult,
    HashSecurityError,
    BrokenHashAlgorithmError,
    HashCollisionDetectedError,
    AvalancheEffectFailureError,
    HashVerificationError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """CLI argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(
        prog="hash_cli",
        description="G101: Kriptografik Hash Fonksiyonları ve Çakışma Analiz Aracı"
    )
    # Metin girdisi
    parser.add_argument(
        "-s", "--string",
        type=str,
        help="Özeti hesaplanacak metin dizgisi"
    )
    # Algoritma seçeneği
    parser.add_argument(
        "-a", "--algorithm",
        type=str,
        default="sha256",
        help="Kullanılacak hash algoritması (varsayılan: sha256)"
    )
    # Güvensiz algoritmalara izin verme bayrağı
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="Kırılmış algoritmalara (MD5, SHA-1) deneysel izin verir"
    )
    # Çığ etkisi testi
    parser.add_argument(
        "--avalanche",
        action="store_true",
        help="1 bitlik girdi farkı ile Çığ Etkisini (Avalanche Effect) analiz eder"
    )
    # Doğum Günü çakışma simülasyonu
    parser.add_argument(
        "--birthday-sim",
        type=int,
        metavar="BITS",
        nargs="?",
        const=16,
        help="Doğum Günü Paradoksu çakışma simülasyonunu BITS bitiyle koşturur (varsayılan: 16)"
    )
    # Sabit zamanlı doğrulama
    parser.add_argument(
        "--verify",
        type=str,
        metavar="EXPECTED_HEX",
        help="Hesaplanan özeti beklenen özet ile sabit zamanlı doğrular"
    )
    # JSON çıktı modu
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON formatında basar"
    )
    # Çıktı dosya yolu
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Raporun kaydedileceği dosya yolu"
    )
    return parser


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları üretir."""
    parser = build_parser()
    args = parser.parse_args()

    # Hiçbir eylem seçilmemişse yardım göster
    if not args.string and not args.avalanche and args.birthday_sim is None:
        parser.print_help(sys.stderr)
        return 2

    try:
        # ----------------------------------------------------------------------
        # 1. ÇIĞ ETKİSİ (AVALANCHE EFFECT) TESTİ
        # ----------------------------------------------------------------------
        if args.avalanche:
            t1 = args.string if args.string else "SiberGuvenlik2026_Kripto_G101_A"
            t2 = t1[:-1] + ("B" if t1[-1] == "A" else "A")
            res = HashAnalyzer.calculate_avalanche_effect(t1, t2, algorithm=args.algorithm)

            if args.json:
                print(json.dumps(res.__dict__, indent=2, ensure_ascii=False))
            else:
                print("=" * 80)
                print(f"GÜN 101: ÇIĞ ETKİSİ (AVALANCHE EFFECT) ANALİZİ ({args.algorithm.upper()})")
                print("=" * 80)
                print(f"  Girdi 1           : {res.girdi_1}")
                print(f"  Girdi 2           : {res.girdi_2}")
                print(f"  Toplam Çıktı Biti : {res.toplam_bit_sayisi} bit")
                print(f"  Farklılaşan Bit   : {res.farkli_bit_sayisi} bit")
                print(f"  Değişim Oranı     : %{res.degisim_yuzdesi} (İdeal: ~%50)")
                print(f"  Değerlendirme     : {res.durum}")
                print("=" * 80)
            return 0

        # ----------------------------------------------------------------------
        # 2. DOĞUM GÜNÜ ÇAKIŞMA SİMÜLASYONU
        # ----------------------------------------------------------------------
        if args.birthday_sim is not None:
            bits = args.birthday_sim
            sim_res = HashAnalyzer.birthday_collision_simulation(bit_size=bits)

            if args.json:
                print(json.dumps(sim_res.__dict__, indent=2, ensure_ascii=False))
            else:
                print("=" * 85)
                print(f"GÜN 101: DOĞUM GÜNÜ PARADOKSU ÇAKIŞMA SİMÜLASYONU ({bits}-BİT KIRPILMIŞ HASH)")
                print("=" * 85)
                print(f"  Kırpma Boyutu             : {sim_res.kirpma_bit} bit")
                print(f"  Gerçekleşen Deneme Sayısı : {sim_res.deneme_sayisi} deneme")
                print(f"  Teorik Beklenen Deneme    : {sim_res.teorik_beklenen_deneme} deneme (O(2^(b/2)))")
                print(f"  Harcanan Süre             : {sim_res.harcanan_sure_ms} ms")
                print(f"  Çakışan Girdi 1           : {sim_res.cakisan_girdi_1}")
                print(f"  Çakışan Girdi 2           : {sim_res.cakisan_girdi_2}")
                print(f"  Ortak Çakışan Özet (Hex)  : {sim_res.ortak_ozet_hex}")
                print("=" * 85)
            return 0

        # ----------------------------------------------------------------------
        # 3. METİN ÖZETİ HESAPLAMA VE DOĞRULAMA
        # ----------------------------------------------------------------------
        if args.string:
            digest = HashAnalyzer.compute_digest(
                args.string,
                algorithm=args.algorithm,
                allow_insecure=args.allow_insecure
            )

            is_valid = True
            if args.verify:
                is_valid = HashAnalyzer.verify_digest_constant_time(digest, args.verify)

            out_data = {
                "girdi": args.string,
                "algoritma": args.algorithm,
                "ozet_hex": digest,
                "dogrulama_yapildi": bool(args.verify),
                "dogrulandi_mi": is_valid
            }

            if args.json:
                print(json.dumps(out_data, indent=2, ensure_ascii=False))
            else:
                print("=" * 80)
                print(f"GÜN 101: KRİPTOGRAFİK ÖZET ({args.algorithm.upper()})")
                print("=" * 80)
                print(f"  Girdi     : {args.string}")
                print(f"  Özet (Hex): {digest}")
                if args.verify:
                    print(f"  Beklenen  : {args.verify}")
                    print(f"  Doğrulama : {'BAŞARILI (EŞLEŞTİ)' if is_valid else 'BAŞARISIZ (TAHRİFAT)'}")
                print("=" * 80)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as out_f:
                    json.dump(out_data, out_f, indent=2, ensure_ascii=False)

            return 0 if is_valid else 1

        return 0

    except HashSecurityError as sec_err:
        sys.stderr.write(f"[GÜVENLİK İHLALİ] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
