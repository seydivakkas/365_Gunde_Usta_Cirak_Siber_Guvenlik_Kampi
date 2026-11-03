# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 104: AEAD ve Nonce Yönetimi CLI Aracı.
Bu komut satırı arayüzü; kurumsal AEAD şifreleme/çözme, Nonce tekrarı koruma denetimi,
Two-Time Pad (XOR iptali) simülasyonu ve SIV deterministik mod yönetimini sağlar.
"""

# Komut satırı argüman kütüphanesi
import argparse
# JSON veri işleme modülü
import json
# Sistem ve yol kütüphanesi
import sys
# İşletim sistemi araçları
import os

# Üst dizini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# AEAD motoru, veri modelleri ve güvenlik istisnalarını içe aktar
from uygulama.aead_nonce_engine import (
    AEADNonceEngine,
    StatefulNonceTracker,
    AEADResult,
    TwoTimePadAnalysis,
    AEADEngineError,
    NonceReuseDetectedError,
    InsecureNonceLengthError,
    PredictableNonceError,
    AuthenticationTagMismatchError,
    InvalidKeyLengthError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(
        description="Gün 104: AEAD ve Nonce Yönetimi CLI Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--encrypt", action="store_true", help="Metni AEAD standardında şifrele")
    mode_group.add_argument("--decrypt", action="store_true", help="AEAD şifreli metni doğrula ve çöz")
    mode_group.add_argument("--simulate-nonce-reuse", action="store_true", help="Two-Time Pad zafiyet simülasyonu yap")
    mode_group.add_argument("--test-tracker", action="store_true", help="Durum bilgili Nonce takip önbelleğini sına")

    # Genel parametreler
    parser.add_argument("--key", type=str, help="16 veya 32 baytlık AES anahtarı (metin veya hex)")
    parser.add_argument("--plaintext", type=str, help="Şifrelenecek düz metin")
    parser.add_argument("--ciphertext", type=str, help="Çözülecek hex formatındaki şifreli metin")
    parser.add_argument("--nonce", type=str, default=None, help="12 baytlık (96-bit) Nonce (Hex)")
    parser.add_argument("--tag", type=str, default=None, help="AEAD kimlik doğrulama etiketi (Hex)")
    parser.add_argument("--aad", type=str, default="", help="İlişkili doğrulanmış açık veri (AAD)")
    parser.add_argument("--siv", action="store_true", help="SIV (Synthetic IV) deterministik modu kullan")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında yazdır")

    return parser


def parse_bytes_input(val_str: str, expected_len: Optional[int] = None) -> bytes:
    """Metin veya hex dizesini bayta dönüştürür."""
    if expected_len and len(val_str) == expected_len * 2:
        try:
            return bytes.fromhex(val_str)
        except ValueError:
            pass
    return val_str.encode("utf-8")


def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        # 1. AEAD ŞİFRELEME
        if args.encrypt:
            if not args.key or not args.plaintext:
                sys.stderr.write("HATA: --encrypt için --key ve --plaintext zorunludur!\n")
                return 2

            k_bytes = parse_bytes_input(args.key)
            n_bytes = bytes.fromhex(args.nonce) if args.nonce else None

            res = AEADNonceEngine.encrypt_aead(
                plaintext=args.plaintext,
                key=k_bytes,
                nonce=n_bytes,
                associated_data=args.aad,
                use_siv=args.siv
            )

            if args.json:
                print(json.dumps({
                    "durum": "BASARILI",
                    "sifreli_metin_hex": res.ciphertext_hex,
                    "nonce_hex": res.nonce_hex,
                    "etiket_hex": res.tag_hex,
                    "aad": res.aad,
                    "siv_modu": res.is_siv,
                    "gecen_sure_ms": res.elapsed_ms
                }, indent=2, ensure_ascii=False))
            else:
                print("=== AEAD ŞİFRELEME BAŞARILI ===")
                print(f"Mod              : {'SIV Deterministik AEAD' if res.is_siv else 'Standart AEAD (Rastgele Nonce)'}")
                print(f"Şifreli Metin    : {res.ciphertext_hex}")
                print(f"Nonce (96-bit)   : {res.nonce_hex}")
                print(f"Doğrulama Etiketi: {res.tag_hex}")
                print(f"İlişkili Veri    : {res.aad if res.aad else '(Boş)'}")
                print(f"İşlem Süresi     : {res.elapsed_ms} ms")
            return 0

        # 2. AEAD ŞİFRE ÇÖZME
        elif args.decrypt:
            if not args.key or not args.ciphertext or not args.nonce or not args.tag:
                sys.stderr.write("HATA: --decrypt için --key, --ciphertext, --nonce ve --tag zorunludur!\n")
                return 2

            k_bytes = parse_bytes_input(args.key)
            pt_bytes, pt_str = AEADNonceEngine.decrypt_aead(
                ciphertext_hex=args.ciphertext,
                key=k_bytes,
                nonce_hex=args.nonce,
                tag_hex=args.tag,
                associated_data=args.aad
            )

            if args.json:
                print(json.dumps({
                    "durum": "BASARILI",
                    "bütünlük_onaylandi": True,
                    "cozulen_metin": pt_str
                }, indent=2, ensure_ascii=False))
            else:
                print("=== AEAD ŞİFRE ÇÖZME BAŞARILI ===")
                print("Bütünlük Durumu  : ✓ DOĞRULANDI (Kurcalama Yok)")
                print(f"Çözülen Düz Metin: {pt_str}")
            return 0

        # 3. TWO-TIME PAD ZAFİYET SİMÜLASYONU
        elif args.simulate_nonce_reuse:
            test_key = b"1234567890abcdef"
            reused_n = b"123456789012"  # 12 bayt
            p1 = "KREDI_KARTI_NO=4111222233334444_CVV=999"
            p2 = "TRANSFER_TUTAR=0000500000_TL_ALICI=AHM"

            analiz = AEADNonceEngine.simulate_two_time_pad_leakage(p1, p2, test_key, reused_n)

            if args.json:
                print(json.dumps({
                    "senaryo": "Two-Time Pad Nonce Yeniden Kullanım Saldırısı",
                    "c1_xor_c2_hex": analiz.c1_xor_c2_hex,
                    "p1_xor_p2_hex": analiz.p1_xor_p2_hex,
                    "anahtar_akisi_iptal_mi": analiz.is_identical_leakage,
                    "crib_dragging_basarili_mi": analiz.crib_drag_match,
                    "aciklama": analiz.aciklama
                }, indent=2, ensure_ascii=False))
            else:
                print("=== TWO-TIME PAD NONCE TEKRARI SİMÜLASYONU ===")
                print(f"Düz Metin 1   : {p1}")
                print(f"Düz Metin 2   : {p2}")
                print(f"C1 ⊕ C2       : {analiz.c1_xor_c2_hex}")
                print(f"P1 ⊕ P2       : {analiz.p1_xor_p2_hex}")
                print(f"Eşitlik Onayı : {'EVET (C1 ⊕ C2 == P1 ⊕ P2)' if analiz.is_identical_leakage else 'HAYIR'}")
                print(f"Crib Dragging : {'✓ Başarılı (Tahmin edilen kelime metni açığa çıkardı)' if analiz.crib_drag_match else '✗'}")
                print(f"Ustanın Dersi : {analiz.aciklama}")
            return 0

        # 4. NONCE TAKİP ÖNBELLEĞİ TESTİ
        elif args.test_tracker:
            test_tracker = StatefulNonceTracker()
            test_key = b"1234567890abcdef"
            test_nonce = b"abcdef123456"

            # 1. İlk şifreleme -> Başarılı
            res1 = AEADNonceEngine.encrypt_aead("İlk Mesaj", test_key, nonce=test_nonce, tracker=test_tracker)
            print("1. İlk Şifreleme   : BAŞARILI (Nonce kaydedildi)")

            # 2. İkinci şifreleme aynı Nonce ile -> Hata fırlatılmalı
            try:
                AEADNonceEngine.encrypt_aead("İkinci Mesaj", test_key, nonce=test_nonce, tracker=test_tracker)
                print("2. İkinci Şifreleme: BAŞARISIZ (Güvenlik zafiyeti oluştu!)")
                return 1
            except NonceReuseDetectedError as nre:
                print(f"2. İkinci Şifreleme: ✓ ENGELLENDİ ({type(nre).__name__})")
                print("   Açıklama        : StatefulNonceTracker aynı Nonce'un tekrarını yakaladı (CWE-323).")
                return 0

    except AEADEngineError as aee:
        sys.stderr.write(f"GÜVENLİK HATASI: {type(aee).__name__} - {str(aee)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"SİSTEMSEL HATA: {str(exc)}\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
