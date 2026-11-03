# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 107: Dijital İmza ve Doğrulama Komut Satırı Arayüzü (CLI).
RSA-PSS ve PKCS#1 v1.5 imzalama, doğrulama ve zafiyet simülasyonlarını
(Textbook forgery, Bleichenbacher, ECDSA nonce reuse) terminal üzerinden yürütür.
"""

# Komut satırı argümanları ayrıştırma
import argparse
# JSON serileştirme ve dosya kaydı
import json
# Sistem ve çıkış kodları
import os
import sys

# Çekirdek motor sınıfları ve istisnaları içe aktarma
from digital_signature_engine import (
    DigitalSignatureEngine,
    RSAPublicKey,
    RSAPrivateKey,
    SignatureVerificationError,
    InvalidSignatureFormatError,
    WeakKeySizeError,
    BleichenbacherVulnerabilityDetected,
    ECDSANonceReuseDetected,
    TextbookSignatureForgeryDetected
)


def run_keygen(bits: int, pub_path: str, priv_path: str) -> dict:
    """RSA Anahtar Çifti Üretir ve JSON olarak kaydeder."""
    pub, priv = DigitalSignatureEngine.generate_keypair(bits=bits)
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump(pub.to_dict(), f, indent=2)
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(priv.to_dict(), f, indent=2)
    return {
        "status": "SUCCESS",
        "bits": bits,
        "public_key_file": pub_path,
        "private_key_file": priv_path,
        "modulus_sample": hex(pub.n)[:32] + "..."
    }


def run_sign(priv_path: str, message: str, scheme: str = "pss") -> dict:
    """Verilen metni özel anahtarla imzalar (PSS veya PKCS#1 v1.5)."""
    with open(priv_path, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    priv_key = RSAPrivateKey.from_dict(key_data)

    msg_bytes = message.encode("utf-8")
    if scheme == "pss":
        sig_bytes = DigitalSignatureEngine.sign_pss(priv_key, msg_bytes)
        algo = "RSASSA-PSS-SHA256"
    elif scheme == "pkcs1":
        sig_bytes = DigitalSignatureEngine.sign_pkcs1_v1_5(priv_key, msg_bytes)
        algo = "RSASSA-PKCS1-v1_5-SHA256"
    else:
        raise ValueError(f"Bilinmeyen imza şeması: {scheme}")

    return {
        "status": "SUCCESS",
        "algorithm": algo,
        "message_length": len(msg_bytes),
        "signature_hex": sig_bytes.hex(),
        "signature_length_bytes": len(sig_bytes)
    }


def run_verify(pub_path: str, message: str, sig_hex: str, scheme: str = "pss") -> dict:
    """İmzayı genel anahtar ile doğrular."""
    with open(pub_path, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    pub_key = RSAPublicKey.from_dict(key_data)

    msg_bytes = message.encode("utf-8")
    sig_bytes = bytes.fromhex(sig_hex)

    if scheme == "pss":
        valid = DigitalSignatureEngine.verify_pss(pub_key, msg_bytes, sig_bytes)
        algo = "RSASSA-PSS-SHA256"
    elif scheme == "pkcs1":
        valid = DigitalSignatureEngine.verify_pkcs1_v1_5(pub_key, msg_bytes, sig_bytes, strict=True)
        algo = "RSASSA-PKCS1-v1_5-SHA256"
    else:
        raise ValueError(f"Bilinmeyen imza şeması: {scheme}")

    return {
        "status": "VALID" if valid else "INVALID",
        "algorithm": algo,
        "verified": valid
    }


def run_demo_flaws() -> dict:
    """Düz RSA, Bleichenbacher ve ECDSA nonce sızıntısı zafiyetlerini simüle eder."""
    pub_512, priv_512 = DigitalSignatureEngine.generate_keypair(bits=512)

    # 1. Varoluşsal Sahtecilik
    existential_caught = False
    try:
        DigitalSignatureEngine.demonstrate_textbook_existential_forgery(pub_512)
    except TextbookSignatureForgeryDetected as ex:
        existential_caught = True
        existential_msg = str(ex)

    # 2. Bleichenbacher e=3 Sahteciliği
    pub_e3, priv_e3 = DigitalSignatureEngine.generate_keypair(bits=512, public_exponent=3)
    bleichenbacher_caught = False
    try:
        DigitalSignatureEngine.demonstrate_bleichenbacher_attack(pub_e3, b"Transfer 1000000 USD to Hacker")
    except BleichenbacherVulnerabilityDetected as ex:
        bleichenbacher_caught = True
        bleichenbacher_msg = str(ex)

    # 3. ECDSA Nonce Yeniden Kullanımı
    ecdsa_caught = False
    try:
        # Örnek 256 bitlik asal alan ve parametreler
        q_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        d_secret = 9876543210123456789
        z1 = 123456789
        z2 = 987654321
        k_reused = 555555555
        DigitalSignatureEngine.demonstrate_ecdsa_nonce_reuse(q_order, d_secret, z1, z2, k_reused)
    except ECDSANonceReuseDetected as ex:
        ecdsa_caught = True
        ecdsa_msg = str(ex)

    return {
        "existential_forgery_demonstrated": existential_caught,
        "existential_forgery_message": existential_msg if existential_caught else "",
        "bleichenbacher_forgery_demonstrated": bleichenbacher_caught,
        "bleichenbacher_forgery_message": bleichenbacher_msg if bleichenbacher_caught else "",
        "ecdsa_nonce_leak_demonstrated": ecdsa_caught,
        "ecdsa_nonce_leak_message": ecdsa_msg if ecdsa_caught else ""
    }


def main():
    parser = argparse.ArgumentParser(
        description="Gün 107: Dijital İmza ve Doğrulama Motoru (CLI)"
    )
    parser.add_argument("--keygen", action="store_true", help="RSA anahtar çifti üretir")
    parser.add_argument("--bits", type=int, default=1024, help="Anahtar bit boyutu (varsayılan: 1024)")
    parser.add_argument("--pub-out", type=str, default="sig_pub.json", help="Genel anahtar kayıt yolu")
    parser.add_argument("--priv-out", type=str, default="sig_priv.json", help="Özel anahtar kayıt yolu")

    parser.add_argument("--sign", action="store_true", help="Mesajı dijital olarak imzalar")
    parser.add_argument("--privkey", type=str, help="Kullanılacak özel anahtar JSON dosyası")
    parser.add_argument("--message", type=str, help="İmzalanacak düz metin mesaj")
    parser.add_argument("--scheme", type=str, default="pss", choices=["pss", "pkcs1"], help="İmza şeması")

    parser.add_argument("--verify", action="store_true", help="Dijital imzayı doğrular")
    parser.add_argument("--pubkey", type=str, help="Kullanılacak genel anahtar JSON dosyası")
    parser.add_argument("--signature", type=str, help="Hex formatındaki imza metni")

    parser.add_argument("--demo-flaws", action="store_true", help="Kriptografik imza zafiyet gösterimlerini çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON olarak basar")

    args = parser.parse_args()

    try:
        if args.keygen:
            res = run_keygen(args.bits, args.pub_out, args.priv_out)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(f"[+] Dijital İmza Anahtar Çifti Üretildi ({res['bits']} bit)")
                print(f"    Genel Anahtar: {res['public_key_file']}")
                print(f"    Özel Anahtar : {res['private_key_file']}")

        elif args.sign:
            if not args.privkey or not args.message:
                print("[-] Hata: --sign için --privkey ve --message zorunludur.", file=sys.stderr)
                sys.exit(1)
            res = run_sign(args.privkey, args.message, args.scheme)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(f"[+] Dijital İmza Başarıyla Üretildi ({res['algorithm']})")
                print(f"    İmza (Hex): {res['signature_hex']}")

        elif args.verify:
            if not args.pubkey or not args.message or not args.signature:
                print("[-] Hata: --verify için --pubkey, --message ve --signature zorunludur.", file=sys.stderr)
                sys.exit(1)
            res = run_verify(args.pubkey, args.message, args.signature, args.scheme)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(f"[+] Doğrulama Sonucu: {res['status']} ({res['algorithm']})")

        elif args.demo_flaws:
            res = run_demo_flaws()
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[*] Dijital İmza Zafiyet Simülasyonu:")
                print(f"    1. Varoluşsal Sahtecilik (CWE-327): {res['existential_forgery_demonstrated']}")
                print(f"    2. Bleichenbacher e=3 Sahteciliği: {res['bleichenbacher_forgery_demonstrated']}")
                print(f"    3. ECDSA Nonce Sızıntısı (CWE-323): {res['ecdsa_nonce_leak_demonstrated']}")

        else:
            parser.print_help()

    except Exception as ex:
        print(f"[-] Hata: {type(ex).__name__}: {str(ex)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
