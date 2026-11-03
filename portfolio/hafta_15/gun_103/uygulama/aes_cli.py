# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 103: FIPS 197 AES ve Simetrik Şifreleme CLI Yönetim Aracı.
Bu komut satırı arayüzü; kurumsal standartlarda AES-128/256 şifreleme ve çözme,
ECB desen sızıntısı karşılaştırması ve NIST resmi test vektörü doğrulamalarını yürütür.
"""

# Argüman ayrıştırma kütüphanesi
import argparse
# JSON veri dönüştürme modülü
import json
# Sistem ve yol araçları
import sys
# Dosya ve işletim sistemi araçları
import os

# Üst dizini modül arama yoluna ekle (bağımsız çalışma)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Güvenli AES motoru ve istisnalarını içe aktar
from uygulama.aes_cipher_engine import (
    AESCipherEngine,
    AESEncryptionResult,
    AESDecryptionResult,
    AESCipherError,
    InsecureCipherModeError,
    InvalidKeyLengthError,
    PredictableIVError,
    InvalidIVLengthError,
    InvalidPaddingError,
    AuthenticationTagMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(
        description="Gün 103: FIPS 197 Uyumlu AES Simetrik Şifreleme Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Ana işlem modları için karşılıklı hariç tutulan grup
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--encrypt", action="store_true", help="Metni AES ile şifrele")
    mode_group.add_argument("--decrypt", action="store_true", help="Şifreli metni çöz")
    mode_group.add_argument("--compare-modes", action="store_true", help="ECB ve CBC modları desen sızıntısı simülasyonu yap")
    mode_group.add_argument("--verify-nist", action="store_true", help="NIST FIPS 197 ve SP 800-38A test vektörlerini doğrula")

    # Genel parametreler
    parser.add_argument("--key", type=str, help="16 veya 32 baytlık AES anahtarı (metin veya hex)")
    parser.add_argument("--plaintext", type=str, help="Şifrelenecek düz metin")
    parser.add_argument("--ciphertext", type=str, help="Çözülecek hex formatındaki şifreli metin")
    parser.add_argument("--mode", type=str, default="cbc", choices=["cbc", "ctr", "ecb", "aead"], help="Şifreleme modu (cbc, ctr, ecb, aead)")
    parser.add_argument("--iv", type=str, default=None, help="16 baytlık Başlangıç Vektörü (IV / Hex)")
    parser.add_argument("--tag", type=str, default=None, help="AEAD modu için kimlik doğrulama etiketi (Hex)")
    parser.add_argument("--mac-key", type=str, default=None, help="AEAD modu için HMAC anahtarı")
    parser.add_argument("--strict", action="store_true", help="Katı güvenlik modu (ECB reddedilir)")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında yazdır")

    return parser


def parse_key_input(key_str: str) -> bytes:
    """Anahtar girdisini hex veya düz metin olarak bayta çevirir."""
    if len(key_str) in (32, 64):
        try:
            return bytes.fromhex(key_str)
        except ValueError:
            pass
    return key_str.encode("utf-8")


def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        # 1. ŞİFRELEME MODU
        if args.encrypt:
            if not args.key or not args.plaintext:
                sys.stderr.write("HATA: --encrypt modu için --key ve --plaintext zorunludur!\n")
                return 2

            key_bytes = parse_key_input(args.key)
            mode = args.mode.lower()

            if mode == "cbc":
                res = AESCipherEngine.encrypt_cbc(args.plaintext, key_bytes, iv=args.iv)
            elif mode == "ctr":
                res = AESCipherEngine.encrypt_ctr(args.plaintext, key_bytes, initial_counter=args.iv)
            elif mode == "ecb":
                res = AESCipherEngine.encrypt_ecb(args.plaintext, key_bytes, strict_mode=args.strict)
            elif mode == "aead":
                mac_key = parse_key_input(args.mac_key) if args.mac_key else key_bytes
                res = AESCipherEngine.encrypt_aead_etm(args.plaintext, key_bytes, mac_key)
            else:
                sys.stderr.write(f"HATA: Desteklenmeyen mod: {mode}\n")
                return 2

            if args.json:
                print(json.dumps({
                    "durum": "BASARILI",
                    "mod": res.mode,
                    "anahtar_uzunlugu_bit": res.key_bits,
                    "sifreli_metin_hex": res.ciphertext_hex,
                    "iv_hex": res.iv_hex,
                    "etiket_hex": res.tag_hex,
                    "gecen_sure_ms": res.elapsed_ms
                }, indent=2, ensure_ascii=False))
            else:
                print("=== AES ŞİFRELEME BAŞARILI ===")
                print(f"İşletim Modu     : {res.mode}")
                print(f"Anahtar Boyutu   : {res.key_bits} bit")
                print(f"Şifreli Metin    : {res.ciphertext_hex}")
                print(f"Başlangıç Vektörü: {res.iv_hex if res.iv_hex else 'Kullanılmadı'}")
                print(f"AEAD Etiketi     : {res.tag_hex if res.tag_hex else 'Kullanılmadı'}")
                print(f"İşlem Süresi     : {res.elapsed_ms} ms")
            return 0

        # 2. ŞİFRE ÇÖZME MODU
        elif args.decrypt:
            if not args.key or not args.ciphertext:
                sys.stderr.write("HATA: --decrypt modu için --key ve --ciphertext zorunludur!\n")
                return 2

            key_bytes = parse_key_input(args.key)
            mode = args.mode.lower()

            if mode == "cbc":
                if not args.iv:
                    sys.stderr.write("HATA: CBC modunda şifre çözmek için --iv parametresi zorunludur!\n")
                    return 2
                dec_res = AESCipherEngine.decrypt_cbc(args.ciphertext, key_bytes, iv=args.iv)
            elif mode == "ctr":
                if not args.iv:
                    sys.stderr.write("HATA: CTR modunda şifre çözmek için --iv (sayaç) zorunludur!\n")
                    return 2
                dec_res = AESCipherEngine.decrypt_ctr(args.ciphertext, key_bytes, initial_counter=args.iv)
            elif mode == "ecb":
                dec_res = AESCipherEngine.decrypt_ecb(args.ciphertext, key_bytes, strict_mode=args.strict)
            elif mode == "aead":
                if not args.iv or not args.tag:
                    sys.stderr.write("HATA: AEAD modunda şifre çözmek için --iv ve --tag zorunludur!\n")
                    return 2
                mac_key = parse_key_input(args.mac_key) if args.mac_key else key_bytes
                dec_res = AESCipherEngine.decrypt_aead_etm(args.ciphertext, key_bytes, mac_key, iv_hex=args.iv, tag_hex=args.tag)
            else:
                sys.stderr.write(f"HATA: Desteklenmeyen mod: {mode}\n")
                return 2

            if args.json:
                print(json.dumps({
                    "durum": "BASARILI",
                    "mod": dec_res.mode,
                    "dogrulandi": dec_res.verified,
                    "cozulen_metin": dec_res.plaintext_str,
                    "gecen_sure_ms": dec_res.elapsed_ms
                }, indent=2, ensure_ascii=False))
            else:
                print("=== AES ŞİFRE ÇÖZME BAŞARILI ===")
                print(f"Mod             : {dec_res.mode}")
                print(f"Bütünlük Onayı  : {'✓ DOĞRULANDI' if dec_res.verified else '✗ DOĞRULANMADI (Güvensiz ECB)'}")
                print(f"Orijinal Metin  : {dec_res.plaintext_str}")
                print(f"İşlem Süresi    : {dec_res.elapsed_ms} ms")
            return 0

        # 3. ECB VS CBC DESEN SIZINTISI KARŞILAŞTIRMASI
        elif args.compare_modes:
            test_key = b"1234567890abcdef"  # 16 bayt
            # İki özdeş 16-baytlık blok içeren metin
            pattern_text = "GIZLI_PAROLA_123GIZLI_PAROLA_123"

            ecb_enc = AESCipherEngine.encrypt_ecb(pattern_text, test_key, strict_mode=False)
            cbc_enc = AESCipherEngine.encrypt_cbc(pattern_text, test_key)

            ecb_block1 = ecb_enc.ciphertext_hex[:32]
            ecb_block2 = ecb_enc.ciphertext_hex[32:64]
            ecb_has_pattern = (ecb_block1 == ecb_block2)

            cbc_block1 = cbc_enc.ciphertext_hex[:32]
            cbc_block2 = cbc_enc.ciphertext_hex[32:64]
            cbc_has_pattern = (cbc_block1 == cbc_block2)

            comp_result = {
                "deney": "ECB vs CBC Desen Sızıntısı (Pattern Leakage) Karşılaştırması",
                "test_metni": pattern_text,
                "ecb_sonuc": {
                    "blok_1_hex": ecb_block1,
                    "blok_2_hex": ecb_block2,
                    "bloklar_ayni_mi": ecb_has_pattern,
                    "tehlike": "CWE-327: Özdeş bloklar aynı şifreli çıktıyı üretti! Veri deseni doğrudan sızıyor (ECB Penguin etkisi)."
                },
                "cbc_sonuc": {
                    "blok_1_hex": cbc_block1,
                    "blok_2_hex": cbc_block2,
                    "bloklar_ayni_mi": cbc_has_pattern,
                    "guvenlik": "CBC zincirleme XOR sayesinde özdeş bloklar tamamen farklı ve rassal çıktılar üretti."
                },
                "ustanin_dersi": "ECB modunu kurumsal üretim sistemlerinde ASLA kullanmayın; daima rastgele IV ile CBC, CTR veya AEAD (GCM/EtM) tercih edin."
            }

            if args.json:
                print(json.dumps(comp_result, indent=2, ensure_ascii=False))
            else:
                print("=== ECB vs CBC DESEN SIZINTISI DENEYİ ===")
                print(f"Test Metni   : {pattern_text}")
                print(f"1. ECB Modu  : Blok 1 ve Blok 2 Eşit mi? -> {'EVET (DESEN SIZINTISI - KRİTİK ZAAF)' if ecb_has_pattern else 'Hayır'}")
                print(f"   Açıklama  : {comp_result['ecb_sonuc']['tehlike']}")
                print(f"2. CBC Modu  : Blok 1 ve Blok 2 Eşit mi? -> {'Evet' if cbc_has_pattern else 'HAYIR (TAM DİFÜZYON - GÜVENLİ)'}")
                print(f"   Açıklama  : {comp_result['cbc_sonuc']['guvenlik']}")
                print(f"Ustanın Dersi: {comp_result['ustanin_dersi']}")
            return 0

        # 4. NIST FIPS 197 / SP 800-38A TEST VEKTÖRLERİ DOĞRULAMASI
        elif args.verify_nist:
            vectors_file = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "aes_known_vectors.json")
            with open(vectors_file, "r", encoding="utf-8") as f:
                vdata = json.load(f)

            # 1. FIPS 197 Single Block
            fb = vdata["aes_128_fips197_single_block"]
            key_f = bytes.fromhex(fb["key_hex"])
            pt_f = bytes.fromhex(fb["plaintext_hex"])
            from uygulama.aes_cipher_engine import encrypt_block, decrypt_block, key_expansion
            w_f, nr_f = key_expansion(key_f)
            ct_f = encrypt_block(pt_f, w_f, nr_f)
            fips_pass = (ct_f.hex() == fb["expected_ciphertext_hex"])

            # 2. CBC SP 800-38A
            cb = vdata["aes_128_cbc_sp800_38a"]
            key_c = bytes.fromhex(cb["key_hex"])
            iv_c = bytes.fromhex(cb["iv_hex"])
            pt_c = bytes.fromhex(cb["plaintext_hex"])
            # Doğrudan tek blok CBC
            xored_c = bytes(a ^ b for a, b in zip(pt_c, iv_c))
            ct_c = encrypt_block(xored_c, w_f, nr_f)
            cbc_pass = (ct_c.hex() == cb["expected_ciphertext_hex"])

            # 3. CTR SP 800-38A
            ct_v = vdata["aes_128_ctr_sp800_38a"]
            key_ct = bytes.fromhex(ct_v["key_hex"])
            ctr_init = bytes.fromhex(ct_v["initial_counter_hex"])
            pt_ct = bytes.fromhex(ct_v["plaintext_hex"])
            ks = encrypt_block(ctr_init, w_f, nr_f)
            ct_res = bytes(a ^ b for a, b in zip(pt_ct, ks))
            ctr_pass = (ct_res.hex() == ct_v["expected_ciphertext_hex"])

            nist_summary = {
                "fips_197_single_block": "PASS" if fips_pass else "FAIL",
                "sp_800_38a_cbc": "PASS" if cbc_pass else "FAIL",
                "sp_800_38a_ctr": "PASS" if ctr_pass else "FAIL",
                "genel_durum": "ONAYLANDI" if (fips_pass and cbc_pass and ctr_pass) else "BASARISIZ"
            }

            if args.json:
                print(json.dumps(nist_summary, indent=2, ensure_ascii=False))
            else:
                print("=== NIST FIPS 197 / SP 800-38A TEST VEKTÖRLERİ DENETİMİ ===")
                print(f"FIPS 197 Tek Blok Doğrulaması : {nist_summary['fips_197_single_block']}")
                print(f"SP 800-38A CBC Doğrulaması    : {nist_summary['sp_800_38a_cbc']}")
                print(f"SP 800-38A CTR Doğrulaması    : {nist_summary['sp_800_38a_ctr']}")
                print(f"Standart Uyumluluk Durumu     : {nist_summary['genel_durum']}")
            return 0 if nist_summary["genel_durum"] == "ONAYLANDI" else 1

    except AESCipherError as ace:
        sys.stderr.write(f"GÜVENLİK HATASI: {type(ace).__name__} - {str(ace)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"SİSTEMSEL HATA: {str(exc)}\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
