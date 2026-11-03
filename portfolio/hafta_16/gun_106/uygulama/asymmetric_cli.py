# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 106: Asimetrik Kriptografi ve RSA Komut Satırı Arayüzü (CLI).
RSA anahtar üretimi, RSA-OAEP şifreleme/çözme, zayıf anahtar denetimi ve
textbook RSA zafiyet gösterimlerini terminal üzerinden çalıştırır.
"""

# Komut satırı argümanlarını ayrıştırmak için standart argparse modülü
import argparse
# JSON veri formatı işlemleri için
import json
# Sistem ve dosya yolu işlemleri için os ve sys
import os
import sys

# Motor modülünden gerekli sınıfları ve fonksiyonları içe aktarma
from asymmetric_crypto_engine import (
    AsymmetricCryptoEngine,
    RSAPublicKey,
    RSAPrivateKey,
    WeakKeySizeError,
    InvalidExponentError,
    OAEPPaddingError,
    MessageTooLargeError,
    TextbookRSAMalleabilityDetected
)


def run_keygen(bits: int, pub_path: str, priv_path: str) -> dict:
    """RSA Anahtar Çifti Üretir ve JSON formatında diske yazar."""
    # Anahtar çifti üretilir
    pub_key, priv_key = AsymmetricCryptoEngine.generate_keypair(bits=bits)
    # Genel anahtar dosyası kaydedilir
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump(pub_key.to_dict(), f, indent=2)
    # Özel anahtar dosyası kaydedilir
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(priv_key.to_dict(), f, indent=2)

    return {
        "status": "SUCCESS",
        "bits": bits,
        "public_key_file": pub_path,
        "private_key_file": priv_path,
        "modulus_sample": hex(pub_key.n)[:32] + "..."
    }


def run_encrypt(pub_path: str, message: str, label: str = "") -> dict:
    """Verilen metni genel anahtarla RSA-OAEP kullanarak şifreler."""
    with open(pub_path, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    pub_key = RSAPublicKey.from_dict(key_data)

    msg_bytes = message.encode("utf-8")
    label_bytes = label.encode("utf-8")
    ciphertext = pub_key.encrypt_oaep(msg_bytes, label=label_bytes)

    return {
        "status": "SUCCESS",
        "algorithm": "RSA-OAEP-SHA256",
        "message_length": len(msg_bytes),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_length_bytes": len(ciphertext)
    }


def run_decrypt(priv_path: str, cipher_hex: str, label: str = "") -> dict:
    """Hex formatındaki şifreli metni özel anahtarla çözer."""
    with open(priv_path, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    priv_key = RSAPrivateKey.from_dict(key_data)

    cipher_bytes = bytes.fromhex(cipher_hex)
    label_bytes = label.encode("utf-8")
    decrypted_bytes = priv_key.decrypt_oaep(cipher_bytes, label=label_bytes)

    return {
        "status": "SUCCESS",
        "algorithm": "RSA-OAEP-SHA256",
        "decrypted_text": decrypted_bytes.decode("utf-8")
    }


def run_demo_flaws() -> dict:
    """Textbook RSA zafiyetlerini (Homomorfizm ve Küçük e=3) simüle eder."""
    # 512 bitlik hızlı gösterim anahtarı üretilir
    pub_key, priv_key = AsymmetricCryptoEngine.generate_keypair(bits=512)
    m1 = 42
    m2 = 10

    malleability_caught = False
    try:
        AsymmetricCryptoEngine.demonstrate_textbook_rsa_malleability(pub_key, priv_key, m1, m2)
    except TextbookRSAMalleabilityDetected as ex:
        malleability_caught = True
        malleability_msg = str(ex)

    # e=3 için küçük üs zafiyeti gösterimi
    pub3, priv3 = AsymmetricCryptoEngine.generate_keypair(bits=512, public_exponent=3)
    # Küçük mesaj seçilir ki m^3 < n kalsın
    small_msg = 12345
    cube_demo = AsymmetricCryptoEngine.demonstrate_small_exponent_vulnerability(pub3, small_msg)

    return {
        "textbook_malleability_detected": malleability_caught,
        "malleability_explanation": malleability_msg if malleability_caught else "Yakalanmadı",
        "small_exponent_cube_root_vulnerability": cube_demo
    }


def main():
    """Ana komut satırı ayrıştırma ve yönlendirme fonksiyonu."""
    parser = argparse.ArgumentParser(
        description="Gün 106: Asimetrik Kriptografi, RSA ve Güvenli Dolgu (OAEP) CLI Aracı"
    )

    parser.add_argument("--keygen", action="store_true", help="Yeni RSA anahtar çifti üretir")
    parser.add_argument("--bits", type=int, default=1024, help="Anahtar bit uzunluğu (varsayılan: 1024)")
    parser.add_argument("--pub-out", type=str, default="rsa_pub.json", help="Genel anahtar çıktı dosyası")
    parser.add_argument("--priv-out", type=str, default="rsa_priv.json", help="Özel anahtar çıktı dosyası")

    parser.add_argument("--encrypt", action="store_true", help="Metni RSA-OAEP ile şifreler")
    parser.add_argument("--pubkey", type=str, help="Kullanılacak genel anahtar dosyası")
    parser.add_argument("--message", type=str, help="Şifrelenecek düz metin")

    parser.add_argument("--decrypt", action="store_true", help="Hex şifreli metni çözer")
    parser.add_argument("--privkey", type=str, help="Kullanılacak özel anahtar dosyası")
    parser.add_argument("--ciphertext", type=str, help="Çözülecek hex şifreli metin")

    parser.add_argument("--label", type=str, default="", help="İsteğe bağlı OAEP protokol etiketi")
    parser.add_argument("--demo-flaws", action="store_true", help="Textbook RSA zafiyet gösterimlerini çalıştırır")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında basar")

    args = parser.parse_args()

    try:
        if args.keygen:
            res = run_keygen(args.bits, args.pub_out, args.priv_out)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(f"[+] RSA Anahtar Çifti Üretildi ({res['bits']} bit)")
                print(f"    Genel Anahtar: {res['public_key_file']}")
                print(f"    Özel Anahtar : {res['private_key_file']}")
                print(f"    Modül Örneği : {res['modulus_sample']}")

        elif args.encrypt:
            if not args.pubkey or not args.message:
                print("[-] Hata: --encrypt için --pubkey ve --message zorunludur.", file=sys.stderr)
                sys.exit(1)
            res = run_encrypt(args.pubkey, args.message, args.label)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[+] RSA-OAEP Şifreleme Başarılı!")
                print(f"    Şifreli Metin (Hex): {res['ciphertext_hex']}")

        elif args.decrypt:
            if not args.privkey or not args.ciphertext:
                print("[-] Hata: --decrypt için --privkey ve --ciphertext zorunludur.", file=sys.stderr)
                sys.exit(1)
            res = run_decrypt(args.privkey, args.ciphertext, args.label)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[+] RSA-OAEP Çözme Başarılı!")
                print(f"    Orijinal Mesaj: {res['decrypted_text']}")

        elif args.demo_flaws:
            res = run_demo_flaws()
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[*] Textbook RSA Zafiyet Denetimi:")
                print(f"    Çarpımsal Homomorfizm (Malleability): {res['malleability_explanation']}")
                print(f"    Küçük Üs (e=3) Küp Kök Açığı Başarılı mı: {res['small_exponent_cube_root_vulnerability']['success']}")

        else:
            parser.print_help()

    except Exception as ex:
        print(f"[-] Hata: {type(ex).__name__}: {str(ex)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
