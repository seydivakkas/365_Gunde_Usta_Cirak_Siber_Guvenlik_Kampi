# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 114: Çok Faktörlü Kimlik Doğrulama (MFA) ve Oltalama Direnci CLI Aracı.

Bu araç, RFC 6238 TOTP kod üretim/doğrulama işlemlerini yürütmek,
FIDO2 / WebAuthn donanım anahtarı kayıt ve doğrulama akışlarını test etmek ve
Ters Vekil (AiTM / Evilginx) oltalama saldırı simülasyonunu koşturmak için tasarlanmıştır.
"""

# Komut satırı argümanları için argparse modülü içe aktarılır
import argparse
# JSON veri formatı işlemleri için json modülü içe aktarılır
import json
# Çıkış kodları ve akış kontrolü için sys modülü içe aktarılır
import sys
# Dosya yolları ve dizin işlemleri için os modülü içe aktarılır
import os
# Kriptografik özetleme için hashlib içe aktarılır
import hashlib
# İkili bayt paketleme için struct içe aktarılır
import struct
# Zaman işlemleri için time içe aktarılır
import time

# Bulunduğumuz dizin Python arama yoluna eklenir (bağımsız çalışma standardı)
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# mfa_phishing_resistant_engine modülünden gerekli sınıflar içe aktarılır
from mfa_phishing_resistant_engine import (
    TOTPEngine,
    WebAuthnFIDO2Engine,
    PhishingAttackSimulator,
    MFASecurityError,
    PhishingOriginMismatchError
)


def build_demo_environment() -> Tuple[TOTPEngine, WebAuthnFIDO2Engine, Dict[str, Any]]:
    """MFA CLI testleri için standart bir örnek ortam ve donanım anahtarı anahtar çifti hazırlar."""
    totp_engine = TOTPEngine(period_seconds=30, digits=6)
    fido2_engine = WebAuthnFIDO2Engine(
        relying_party_id="mevzuat.siber.local",
        relying_party_origin="https://mevzuat.siber.local"
    )

    # Örnek kullanıcı TOTP kaydı
    totp_cred = totp_engine.register_user("seydi_admin", secret_base32="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")

    # FIDO2 Asimetrik Anahtar Çifti (Simüle Edilmiş Güvenli Test Çifti)
    # 512-bit RSA test anahtarı (SHA-256 imzası için 256-bit modulus gereklidir)
    p = 79767748627722170403753678573501130792297299195379632297507984385755962539519
    q = 74423822195679822963040554606743229645699794242435226315153894989068738755257
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    cred_id = "fido2_key_yubikey_5_nfc_001"
    fido2_engine.register_credential(
        credential_id=cred_id,
        username="seydi_admin",
        public_key_n=n,
        public_key_e=e,
        initial_sign_count=100
    )

    private_context = {
        "credential_id": cred_id,
        "n": n,
        "e": e,
        "d": d,
        "totp_secret": totp_cred.secret_base32
    }

    return totp_engine, fido2_engine, private_context


def sign_webauthn_client(private_ctx: Dict[str, Any], authenticator_data: bytes, client_data_json: str) -> int:
    """Donanım anahtarının istemci tarafında asimetrik imza üretmesini simüle eder."""
    client_data_hash = hashlib.sha256(client_data_json.encode("utf-8")).digest()
    signed_data = authenticator_data + client_data_hash
    hash_to_sign = hashlib.sha256(signed_data).digest()

    n = private_ctx["n"]
    d = private_ctx["d"]
    byte_len = (n.bit_length() + 7) // 8

    # PKCS#1 v1.5 basit dolgulama
    padding = b"\x00\x01" + (b"\xFF" * (byte_len - 3 - len(hash_to_sign))) + b"\x00" + hash_to_sign
    int_to_sign = int.from_bytes(padding, byteorder="big")
    signature = pow(int_to_sign, d, n)
    return signature


def cmd_totp_uret(args, totp_engine: TOTPEngine) -> None:
    """Belirtilen kullanıcı için güncel 6-haneli TOTP kodunu üretir."""
    cred = totp_engine.get_credential(args.kullanici)
    if not cred:
        print(f"[HATA] Kullanıcı bulunamadı: {args.kullanici}")
        sys.exit(1)
    code, step = totp_engine.generate_code(cred.secret_base32)
    print(f"[BAŞARILI] Güncel TOTP Kodu: {code}")
    print(f"Kullanıcı: {args.kullanici} | Zaman Adımı: {step} | Geçerlilik: 30 saniye")


def cmd_totp_dogrula(args, totp_engine: TOTPEngine) -> None:
    """Girilen TOTP kodunu doğrular."""
    try:
        is_ok = totp_engine.verify_code(args.kullanici, args.kod)
        print(f"[BAŞARILI] TOTP Kodu Geçerli! Kimlik doğrulama onaylandı.")
    except MFASecurityError as err:
        print(f"[HATA] Doğrulama Başarısız: {err}")
        sys.exit(1)


def cmd_simulasyon_saldiri(args, totp_engine: TOTPEngine, fido2_engine: WebAuthnFIDO2Engine, priv_ctx: Dict[str, Any]) -> None:
    """Ters Vekil (AiTM / Evilginx) Oltalama Saldırısını TOTP ve FIDO2 üzerinde simüle eder."""
    print("=" * 75)
    print("GÜN 114: TERS VEKİL (AiTM) OLTALAMA SALDIRISI SİMÜLASYONU")
    print("Saldırgan Alan Adı : https://phishing-mevzuat-siber.com (Evilginx2 Proxy)")
    print("Meşru Hedef Sunucu : https://mevzuat.siber.local")
    print("=" * 75)

    # 1. Aşama: TOTP Saldırı Simülasyonu
    print("\n[TEST 1] TOTP (RFC 6238) Oltalama Direnci Sınanıyor...")
    cred = totp_engine.get_credential("seydi_admin")
    totp_code, _ = totp_engine.generate_code(cred.secret_base32)
    print(f"Kurban oltalama sitesine TOTP kodunu girdi: {totp_code}")
    print("Ters vekil bu kodu yakalayıp 1 saniye içinde gerçek sunucuya iletti...")

    totp_attack_res = PhishingAttackSimulator.simulate_totp_phishing_attack(
        totp_engine=totp_engine,
        username="seydi_admin",
        totp_code=totp_code
    )
    print(f"Sonuç: Saldırı Başarılı mı? -> {totp_attack_res['saldiri_basarili_mi']}")
    print(f"Açıklama: {totp_attack_res['aciklama']}")

    # 2. Aşama: FIDO2 WebAuthn Saldırı Simülasyonu
    print("\n[TEST 2] FIDO2 / WebAuthn Oltalama Direnci Sınanıyor...")
    challenge = fido2_engine.create_authentication_challenge("seydi_admin")
    rp_id_hash = hashlib.sha256("mevzuat.siber.local".encode("utf-8")).digest()
    flags = b"\x01" # User Present
    sign_count = 101
    auth_data = rp_id_hash + flags + struct.pack(">I", sign_count)

    # Kurban sahte oltalama sitesinde donanım anahtarına dokunur
    phishing_origin = "https://phishing-mevzuat-siber.com"
    client_data_phishing = json.dumps({
        "type": "webauthn.get",
        "challenge": challenge.challenge_hex,
        "origin": phishing_origin
    })

    # Donanım anahtarı tarayıcının bulunduğu sahte menşei imzalar
    signature = sign_webauthn_client(priv_ctx, auth_data, client_data_phishing)
    print(f"Kurban oltalama sitesinde FIDO2 anahtarına dokundu.")
    print(f"Donanım anahtarı menşei imzaladı: {phishing_origin}")
    print("Ters vekil bu imzayı gerçek sunucuya (https://mevzuat.siber.local) iletti...")

    fido_attack_res = PhishingAttackSimulator.simulate_fido2_phishing_attack(
        fido2_engine=fido2_engine,
        credential_id=priv_ctx["credential_id"],
        phishing_origin=phishing_origin,
        challenge_hex=challenge.challenge_hex,
        authenticator_data=auth_data,
        signature_int=signature
    )
    print(f"Sonuç: Saldırı Başarılı mı? -> {fido_attack_res['saldiri_basarili_mi']}")
    print(f"Engellenen Zafiyet: {fido_attack_res.get('yakalanan_zafiyet', 'YOK')}")
    print(f"Açıklama: {fido_attack_res['aciklama']}")
    print("=" * 75)


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="MFA Yöntemleri ve Oltalama (Phishing) Direnci Analiz Aracı"
    )
    subparsers = parser.add_subparsers(dest="komut", help="Yürütülecek işlem")

    # 'totp-uret' alt komutu
    p_totp_uret = subparsers.add_parser("totp-uret", help="Kullanıcı için TOTP kodu üret")
    p_totp_uret.add_argument("--kullanici", default="seydi_admin", help="Kullanıcı adı")

    # 'totp-dogrula' alt komutu
    p_totp_dogrula = subparsers.add_parser("totp-dogrula", help="TOTP kodunu doğrula")
    p_totp_dogrula.add_argument("--kullanici", default="seydi_admin", help="Kullanıcı adı")
    p_totp_dogrula.add_argument("--kod", required=True, help="6-haneli TOTP kodu")

    # 'simulasyon-saldiri' alt komutu
    subparsers.add_parser("simulasyon-saldiri", help="AiTM ters vekil oltalama saldırı simülasyonunu koştur")

    args = parser.parse_args()
    totp_engine, fido2_engine, priv_ctx = build_demo_environment()

    if args.komut == "totp-uret":
        cmd_totp_uret(args, totp_engine)
    elif args.komut == "totp-dogrula":
        cmd_totp_dogrula(args, totp_engine)
    elif args.komut == "simulasyon-saldiri":
        cmd_simulasyon_saldiri(args, totp_engine, fido2_engine, priv_ctx)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
