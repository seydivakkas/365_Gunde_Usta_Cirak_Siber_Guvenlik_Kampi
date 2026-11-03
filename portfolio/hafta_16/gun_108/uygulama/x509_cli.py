# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 108: X.509 ve Sertifika Zinciri Komut Satırı Arayüzü (CLI).
3 Kademeli PKI inşası, sertifika zinciri doğrulama ve gerçek dünya PKI
zafiyet simülasyonlarını terminal üzerinden çalıştırır.
"""

# Komut satırı argümanları için argparse
import argparse
# JSON serileştirme
import json
# Zaman ve tarih hesaplamaları
from datetime import datetime, timezone, timedelta
# Dosya ve sistem işlemleri
import os
import sys

# Motor modülünden sınıfları içe aktarma
from x509_chain_engine import (
    X509Certificate,
    PKIBuilder,
    X509ChainValidator,
    UntrustedRootCAError,
    CertificateExpiredError,
    HostnameMismatchError,
    NonCACertificateUsedAsCAError
)


def run_build_pki(out_dir: str, domain: str = "secure.bank.com.tr") -> dict:
    """3 Kademeli PKI üretir ve dosyaları kaydeder."""
    os.makedirs(out_dir, exist_ok=True)

    # 1. Kök CA
    root_cert, root_priv = PKIBuilder.create_root_ca(cn="Global Guvenlik Root CA", bits=512)
    root_cert_path = os.path.join(out_dir, "root_ca.json")
    with open(root_cert_path, "w", encoding="utf-8") as f:
        json.dump(root_cert.to_dict(), f, indent=2)

    # 2. Ara CA
    inter_cert, inter_priv = PKIBuilder.create_intermediate_ca(root_cert, root_priv, cn="Kurumsal E-Ticaret CA", bits=512)
    inter_cert_path = os.path.join(out_dir, "intermediate_ca.json")
    with open(inter_cert_path, "w", encoding="utf-8") as f:
        json.dump(inter_cert.to_dict(), f, indent=2)

    # 3. Uç Sertifika
    leaf_cert, _ = PKIBuilder.create_leaf_certificate(inter_cert, inter_priv, domain=domain, san_list=[domain, f"api.{domain}"], bits=512)
    leaf_cert_path = os.path.join(out_dir, "leaf_cert.json")
    with open(leaf_cert_path, "w", encoding="utf-8") as f:
        json.dump(leaf_cert.to_dict(), f, indent=2)

    # 4. Güven Deposu (Trust Store)
    trust_store_path = os.path.join(out_dir, "trust_store.json")
    with open(trust_store_path, "w", encoding="utf-8") as f:
        json.dump([root_cert.to_dict()], f, indent=2)

    return {
        "status": "SUCCESS",
        "output_directory": out_dir,
        "root_ca": root_cert_path,
        "intermediate_ca": inter_cert_path,
        "leaf_cert": leaf_cert_path,
        "trust_store": trust_store_path,
        "domain": domain
    }


def run_verify_chain(leaf_path: str, inter_path: str, trust_store_path: str, domain: str = "") -> dict:
    """Sertifika zincirini doğrular."""
    with open(leaf_path, "r", encoding="utf-8") as f:
        leaf_cert = X509Certificate.from_dict(json.load(f))

    with open(inter_path, "r", encoding="utf-8") as f:
        inter_cert = X509Certificate.from_dict(json.load(f))

    with open(trust_store_path, "r", encoding="utf-8") as f:
        trust_data = json.load(f)
        trust_store = [X509Certificate.from_dict(item) for item in trust_data]

    res = X509ChainValidator.validate_chain(
        leaf=leaf_cert,
        intermediates=[inter_cert],
        trust_store=trust_store,
        target_domain=domain if domain else None
    )
    return res


def run_demo_flaws() -> dict:
    """PKI ve X.509 zafiyet senaryolarını simüle eder."""
    # Hızlı anahtarlarla PKI inşa edilir
    root, root_priv = PKIBuilder.create_root_ca(bits=512)
    inter, inter_priv = PKIBuilder.create_intermediate_ca(root, root_priv, bits=512)
    leaf, leaf_priv = PKIBuilder.create_leaf_certificate(inter, inter_priv, domain="guvenli.bank.com", bits=512)
    trust_store = [root]

    # 1. Alan Adı Uyuşmazlığı (Hostname Mismatch - CWE-297)
    mismatch_caught = False
    try:
        X509ChainValidator.validate_chain(leaf, [inter], trust_store, target_domain="sahte-phishing.com")
    except HostnameMismatchError:
        mismatch_caught = True

    # 2. Süresi Dolmuş Sertifika (Expired Certificate - CWE-298)
    expired_caught = False
    future_time = datetime.now(timezone.utc) + timedelta(days=500)
    try:
        X509ChainValidator.validate_chain(leaf, [inter], trust_store, target_domain="guvenli.bank.com", check_time=future_time)
    except CertificateExpiredError:
        expired_caught = True

    # 3. Güvensiz Yabancı Kök Otorite (Untrusted Root - CWE-295)
    untrusted_caught = False
    fake_root, _ = PKIBuilder.create_root_ca(cn="Rogue Attacker CA", bits=512)
    try:
        X509ChainValidator.validate_chain(leaf, [inter], trust_store=[fake_root], target_domain="guvenli.bank.com")
    except UntrustedRootCAError:
        untrusted_caught = True

    # 4. Yetkisiz Uç Sertifikanın CA Gibi Davranması (BasicConstraints İhlali - CWE-295)
    illegal_ca_caught = False
    try:
        # leaf_cert is_ca=False'dır, bununla alt sertifika üretmeye çalışıyoruz
        PKIBuilder.create_leaf_certificate(issuer_ca=leaf, issuer_priv=leaf_priv, domain="hacker.com")
    except NonCACertificateUsedAsCAError:
        illegal_ca_caught = True

    return {
        "hostname_mismatch_blocked": mismatch_caught,
        "expired_certificate_blocked": expired_caught,
        "untrusted_root_blocked": untrusted_caught,
        "illegal_leaf_as_ca_blocked": illegal_ca_caught
    }


def main():
    parser = argparse.ArgumentParser(
        description="Gün 108: X.509 ve Sertifika Zinciri Doğrulama CLI Aracı"
    )
    parser.add_argument("--build-pki", action="store_true", help="3 Kademeli PKI üretir ve kaydeder")
    parser.add_argument("--out-dir", type=str, default="pki_output", help="PKI çıktı klasörü")
    parser.add_argument("--domain", type=str, default="secure.bank.com.tr", help="Uç sertifika alan adı")

    parser.add_argument("--verify-chain", action="store_true", help="Sertifika zincirini doğrular")
    parser.add_argument("--leaf", type=str, help="Uç sertifika JSON yolu")
    parser.add_argument("--intermediate", type=str, help="Ara sertifika JSON yolu")
    parser.add_argument("--trust-store", type=str, help="Güven deposu JSON yolu")

    parser.add_argument("--demo-flaws", action="store_true", help="X.509 zafiyet simülasyonlarını çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında basar")

    args = parser.parse_args()

    try:
        if args.build_pki:
            res = run_build_pki(args.out_dir, args.domain)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print(f"[+] PKI Başarıyla Oluşturuldu: {res['output_directory']}")
                print(f"    Kök CA       : {res['root_ca']}")
                print(f"    Ara CA       : {res['intermediate_ca']}")
                print(f"    Uç Sertifika : {res['leaf_cert']}")
                print(f"    Güven Deposu : {res['trust_store']}")

        elif args.verify_chain:
            if not args.leaf or not args.intermediate or not args.trust_store:
                print("[-] Hata: --verify-chain için --leaf, --intermediate ve --trust-store zorunludur.", file=sys.stderr)
                sys.exit(1)
            res = run_verify_chain(args.leaf, args.intermediate, args.trust_store, args.domain)
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[+] Sertifika Zinciri Doğrulandı: VALID (RFC 5280)")
                print(f"    Uç Alan Adı    : {res['leaf_domain']}")
                print(f"    Zincir Derinliği: {res['chain_length']}")
                print(f"    Kök Dayanak    : {res['root_trust_anchor']}")

        elif args.demo_flaws:
            res = run_demo_flaws()
            if args.json:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print("[*] X.509 Zafiyet Savunma Simülasyonu:")
                print(f"    1. Alan Adı Uyuşmazlığı Engellendi (CWE-297) : {res['hostname_mismatch_blocked']}")
                print(f"    2. Süresi Dolmuş Sertifika Engellendi (CWE-298): {res['expired_certificate_blocked']}")
                print(f"    3. Güvensiz Kök Otorite Engellendi (CWE-295)  : {res['untrusted_root_blocked']}")
                print(f"    4. Yetkisiz Uç CA İhlali Engellendi (CWE-295) : {res['illegal_leaf_as_ca_blocked']}")

        else:
            parser.print_help()

    except Exception as ex:
        print(f"[-] Hata: {type(ex).__name__}: {str(ex)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
