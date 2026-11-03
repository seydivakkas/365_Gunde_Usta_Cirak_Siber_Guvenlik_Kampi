# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 116: JSON Web Token (JWT) Komut Satırı Yönetim ve Denetim Arayüzü (JWT CLI).

Bu araç, güvenli JWT üretmek, doğrulamak, talep (claims) ayrıştırmak,
belirteç iptal etmek ve yaygın JWT saldırılarını ('alg: none', algoritma karışıklığı)
simüle etmek için geliştirilmiştir.
"""

# Komut satırı argümanları için argparse içe aktarılır
import argparse
# JSON veri dönüşümleri için json içe aktarılır
import json
# Çıkış kodları ve akış kontrolü için sys içe aktarılır
import sys
# Dosya yolları için os içe aktarılır
import os
# Kriptografik rastgele baytlar için secrets içe aktarılır
import secrets

# Bulunduğumuz dizin Python arama yoluna eklenir (bağımsız çalışma standardı)
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# jwt_security_engine modülünden gerekli sınıflar içe aktarılır
from jwt_security_engine import (
    JWTIssuerEngine,
    JWTValidatorEngine,
    JWTValidationPolicy,
    Base64URL,
    JWTSecurityError,
    AlgorithmNoneAttackError,
    AlgorithmConfusionError
)


def cmd_uret(args) -> None:
    """Komut satırından yeni bir HS256 JWT üretir."""
    claims = {
        "sub": args.kullanici,
        "rol": args.rol,
        "eposta": f"{args.kullanici}@siber.local"
    }
    token = JWTIssuerEngine.issue_token_hs256(
        claims=claims,
        secret_key=args.anahtar,
        ttl_seconds=args.ttl,
        issuer=args.issuer,
        audience=args.audience
    )
    print("=" * 70)
    print("YENİ GÜVENLİ JWT ÜRETİLDİ (HS256)")
    print("=" * 70)
    print(f"Token Dizgesi :\n{token}\n")
    print(f"Kullanıcı (sub): {args.kullanici}")
    print(f"Rol (rol)      : {args.rol}")
    print(f"Issuer (iss)   : {args.issuer}")
    print(f"Audience (aud) : {args.audience}")
    print(f"Geçerlilik     : {args.ttl} saniye")


def cmd_dogrula(args) -> None:
    """Sunulan bir JWT belirtecini katı güvenlik politikalarıyla doğrular."""
    policy = JWTValidationPolicy(
        allowed_algorithms={"HS256"},
        expected_issuer=args.issuer,
        expected_audience=args.audience,
        leeway_seconds=5,
        reject_none_algorithm=True
    )
    validator = JWTValidatorEngine(policy)
    try:
        payload = validator.validate_token(args.token, secret_key=args.anahtar)
        print("=" * 70)
        print("[BAŞARILI] JWT DOĞRULANDI! Belirteç geçerli ve güvenilirdir.")
        print("=" * 70)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    except JWTSecurityError as err:
        print("=" * 70)
        print(f"[BAŞARISIZ] JWT DOĞRULAMA HATASI: {err}")
        print("=" * 70)
        sys.exit(1)


def cmd_coz(args) -> None:
    """JWT imzasını doğrulamadan sadece başlık ve gövde içeriğini ayrıştırır (Teftiş aracı)."""
    parts = args.token.strip().split(".")
    if len(parts) != 3:
        print("[HATA] Geçersiz JWT formatı. 3 parça olmalıdır.")
        sys.exit(1)
    header = json.loads(Base64URL.decode(parts[0]).decode("utf-8"))
    payload = json.loads(Base64URL.decode(parts[1]).decode("utf-8"))
    print("=== JWT BAŞLIK (HEADER) ===")
    print(json.dumps(header, indent=2, ensure_ascii=False))
    print("\n=== JWT YÜK (PAYLOAD / CLAIMS) ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"\nİmza Parçası (Base64URL): {parts[2]}")


def cmd_saldiri_simulasyonu(args) -> None:
    """'alg: none' ve imza sahteciliği saldırılarını simüle eder."""
    secret = "GuvenliSunucuGizliAnahtari!2026"
    valid_token = JWTIssuerEngine.issue_token_hs256(
        claims={"sub": "normal_kullanici", "rol": "user"},
        secret_key=secret,
        issuer="https://idp.siber.local",
        audience="siber_api"
    )
    parts = valid_token.split(".")

    print("=" * 70)
    print("JWT SALDIRI VE SAVUNMA SİMÜLASYONU")
    print("=" * 70)

    # 1. Saldırı: 'alg: none' Saldırısı (CVE-2015-9235)
    print("\n[SALDIRI 1] 'alg: none' İmzasız Belirteç Enjeksiyonu...")
    fake_header = {"typ": "JWT", "alg": "none"}
    fake_payload = {"sub": "admin", "rol": "super_admin", "exp": 9999999999}
    h_b64 = Base64URL.encode(json.dumps(fake_header).encode("utf-8"))
    p_b64 = Base64URL.encode(json.dumps(fake_payload).encode("utf-8"))
    none_attack_token = f"{h_b64}.{p_b64}."
    print(f"Saldırgan token üretti (İmza BOŞ):\n{none_attack_token}")

    validator = JWTValidatorEngine(JWTValidationPolicy(allowed_algorithms={"HS256"}))
    try:
        validator.validate_token(none_attack_token, secret_key=secret)
        print("[KRİTİK AÇIK] Sistem imzasız 'alg: none' token'ı kabul etti!")
    except AlgorithmNoneAttackError as err:
        print(f"[BAŞARILI SAVUNMA] {err}")

    # 2. Saldırı: İmza Karalama / Sahtecilik (CWE-347)
    print("\n[SALDIRI 2] Payload Değiştirme (Tampering) ve Sahte İmza...")
    tampered_payload = {"sub": "admin", "rol": "super_admin"}
    t_b64 = Base64URL.encode(json.dumps(tampered_payload).encode("utf-8"))
    tampered_token = f"{parts[0]}.{t_b64}.{parts[2]}"

    try:
        validator.validate_token(tampered_token, secret_key=secret)
        print("[KRİTİK AÇIK] Değiştirilmiş payload kabul edildi!")
    except JWTSecurityError as err:
        print(f"[BAŞARILI SAVUNMA] {err}")
    print("=" * 70)


def main():
    """CLI giriş noktası ve alt komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="JSON Web Token (JWT) Güvenli Yönetim ve Denetim CLI Aracı"
    )
    subparsers = parser.add_subparsers(dest="komut", help="Yürütülecek işlem")

    # 'uret' alt komutu
    p_uret = subparsers.add_parser("uret", help="Yeni bir HS256 JWT üret")
    p_uret.add_argument("--kullanici", default="seydi_kullanici", help="Kullanıcı adı (sub)")
    p_uret.add_argument("--rol", default="analyst", help="Kullanıcı rolü")
    p_uret.add_argument("--anahtar", default="GizliTestAnahtari!2026", help="HMAC gizli anahtarı")
    p_uret.add_argument("--ttl", type=int, default=3600, help="Geçerlilik süresi (saniye)")
    p_uret.add_argument("--issuer", default="https://idp.siber.local", help="Issuer (iss)")
    p_uret.add_argument("--audience", default="siber_api", help="Audience (aud)")

    # 'dogrula' alt komutu
    p_dogrula = subparsers.add_parser("dogrula", help="JWT belirtecini doğrula")
    p_dogrula.add_argument("--token", required=True, help="Doğrulanacak JWT dizgesi")
    p_dogrula.add_argument("--anahtar", default="GizliTestAnahtari!2026", help="HMAC gizli anahtarı")
    p_dogrula.add_argument("--issuer", default="https://idp.siber.local", help="Beklenen Issuer")
    p_dogrula.add_argument("--audience", default="siber_api", help="Beklenen Audience")

    # 'coz' alt komutu
    p_coz = subparsers.add_parser("coz", help="JWT içeriğini imzayı doğrulamadan teftiş et")
    p_coz.add_argument("--token", required=True, help="Ayrıştırılacak JWT dizgesi")

    # 'saldiri-simulasyonu' alt komutu
    subparsers.add_parser("saldiri-simulasyonu", help="'alg: none' ve sahtecilik saldırılarını simüle et")

    args = parser.parse_args()

    if args.komut == "uret":
        cmd_uret(args)
    elif args.komut == "dogrula":
        cmd_dogrula(args)
    elif args.komut == "coz":
        cmd_coz(args)
    elif args.komut == "saldiri-simulasyonu":
        cmd_saldiri_simulasyonu(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
