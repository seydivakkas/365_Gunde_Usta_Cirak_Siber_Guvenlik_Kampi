# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
PKI ve Sertifika Yaşam Döngüsü CLI Aracı (pki_cli.py).

Kullanıcıların komut satırı üzerinden asimetrik anahtar türetimi, CSR başvurusu,
sertifika ihracı, CT Log tescili, CRL/OCSP iptal sorgulamaları ve ACME tabanlı
otomatik anahtar rotasyonunu uçtan uca yürütmesini ve analiz etmesini sağlar.
"""

import sys
import json
import argparse
import datetime
from typing import Dict, Any

# Aynı paket içindeki yaşam döngüsü motor bileşenlerini içeri aktar
from pki_lifecycle_engine import (
    RSAKeyPair,
    CertificateSigningRequest,
    CertificateAuthority,
    CertificateRevocationList,
    OCSPResponder,
    OCSPVerifier,
    ACMEManager,
    CertificateLifecycleOrchestrator,
    PKIError,
    CSRSignatureVerificationError,
    CertificateRevokedError,
    CertificateExpiredError,
    OCSPNonceMismatchError
)

def print_banner() -> None:
    """CLI aracının başlık afişini konsola basar."""
    print("=" * 72)
    print("  PKI VE SERTİFİKA YAŞAM DÖNGÜSÜ YÖNETİM VE DENETİM ARACI")
    print("  RFC 5280 / RFC 6960 (OCSP) / RFC 6962 (CT) / RFC 8555 (ACME)")
    print("=" * 72)

def run_lifecycle_demo(json_output: bool = False) -> Dict[str, Any]:
    """Uçtan uca sertifika yaşam döngüsünü baştan sona icra eder."""
    if not json_output:
        print("\n[*] 1. ADIM: Kök CA ve Ara CA Altyapısı Kuruluyor...")

    # Kök CA Anahtarı ve Kurulumu
    root_ca_key = RSAKeyPair.generate(bits=512)
    root_ca = CertificateAuthority(
        dn={"CN": "Ulusal Kök Sertifika Otoritesi", "O": "Akademi Siber Güvenlik", "C": "TR"},
        keypair=root_ca_key,
        is_root=True
    )

    if not json_output:
        print("[+] Kök CA aktif edildi.")
        print("\n[*] 2. ADIM: ACME Yöneticisi ve Yaşam Döngüsü Orkestratörü Başlatılıyor...")

    acme_mgr = ACMEManager(root_ca)
    orchestrator = CertificateLifecycleOrchestrator(root_ca, acme_mgr)

    # İlk sertifika ihracı (Bootstrap)
    target_domain = "guvenli.kurum.gov.tr"
    if not json_output:
        print(f"[*] {target_domain} için CSR oluşturuluyor ve ACME HTTP-01 doğrulaması başlatılıyor...")

    initial_cert, _ = orchestrator.bootstrap_certificate(target_domain)
    
    if not json_output:
        print(f"[+] Sertifika Başarıyla İhraç Edildi!")
        print(f"    - Seri No: {initial_cert.serial_number}")
        print(f"    - Konu DN: {initial_cert.subject_dn}")
        print(f"    - SAN: {initial_cert.san_names}")
        print(f"    - Bitiş Tarihi: {initial_cert.not_after}")
        print(f"    - CT SCT Log ID: {initial_cert.sct_info['log_id'] if initial_cert.sct_info else 'N/A'}")

    # OCSP Sorgusu (İptal Durumu Kontrolü)
    if not json_output:
        print("\n[*] 3. ADIM: Çevrimiçi Durum Protokolü (OCSP) Sorgulanıyor...")
    
    ocsp_responder = OCSPResponder(root_ca)
    nonce = "demo_nonce_12345"
    ocsp_resp = ocsp_responder.handle_request(initial_cert.serial_number, request_nonce=nonce)
    
    # OCSP Doğrulaması
    is_valid = OCSPVerifier.verify_response(initial_cert, ocsp_resp, expected_nonce=nonce)
    if not json_output:
        print(f"[+] OCSP Yanıtı: {ocsp_resp['response_body']['status']} (Nonce Eşleşmesi: Başarılı)")

    # Yaşam döngüsü rotasyonu (Eski sertifikanın iptali ve yeni sertifikanın atanması)
    if not json_output:
        print("\n[*] 4. ADIM: Otomatik Anahtar Rotasyonu ve Kriptografik İmha (Crypto-Shredding) Yürütülüyor...")
    
    new_cert, _ = orchestrator.auto_rotate_and_crypto_shred(target_domain)
    
    if not json_output:
        print(f"[+] Rotasyon Tamamlandı!")
        print(f"    - Eski Sertifika Seri No: {initial_cert.serial_number} (İptal Durumu: SUPERSEDED)")
        print(f"    - Yeni Sertifika Seri No: {new_cert.serial_number} (Aktif)")

    # Eski sertifikanın iptal durumunu CRL ve OCSP ile teyit et
    crl = CertificateRevocationList.generate(root_ca)
    is_revoked, reason = crl.is_revoked(initial_cert.serial_number)
    
    if not json_output:
        print(f"[+] CRL Denetimi: Eski Sertifika İptal Listesinde mi? -> {is_revoked} (Neden: {reason})")

    results = {
        "hedef_alan_adi": target_domain,
        "ilk_sertifika_seri": str(initial_cert.serial_number),
        "yeni_sertifika_seri": str(new_cert.serial_number),
        "ocsp_durumu": ocsp_resp["response_body"]["status"],
        "crl_iptal_kaydi": is_revoked,
        "iptal_nedeni": reason,
        "denetim_kayitlari_sayisi": len(orchestrator.audit_log)
    }
    return results

def run_flaw_demos(json_output: bool = False) -> Dict[str, Any]:
    """PKI yaşam döngüsü zafiyetlerini (CWE senaryoları) simüle eder."""
    flaw_results = {}
    if not json_output:
        print("\n" + "=" * 72)
        print("  GÜVENLİK ZAFİYETİ VE SALDIRI SENARYOLARI (CWE ANALİZİ)")
        print("=" * 72)

    root_key = RSAKeyPair.generate(bits=512)
    ca = CertificateAuthority({"CN": "Test Kök CA", "C": "TR"}, root_key)

    # 1. Zafiyet: Sahte Proof-of-Possession (CWE-347)
    if not json_output:
        print("\n[!] 1. Test: Sahte Proof-of-Possession İçeren CSR (CWE-347)...")
    attacker_key = RSAKeyPair.generate(bits=512)
    csr = CertificateSigningRequest.create(attacker_key, {"CN": "sahte.site.local"})
    # İmzanın üzerine tahrifat yap
    csr.signature = "deadbeef" * 8
    try:
        ca.issue_certificate(csr)
        flaw_results["CWE-347_pop_forgery"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except CSRSignatureVerificationError as e:
        flaw_results["CWE-347_pop_forgery"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 2. Zafiyet: OCSP Nonce Replay Saldırısı (CWE-294)
    if not json_output:
        print("\n[!] 2. Test: OCSP Yanıtında Nonce Manipülasyonu / Replay (CWE-294)...")
    valid_key = RSAKeyPair.generate(bits=512)
    valid_csr = CertificateSigningRequest.create(valid_key, {"CN": "ornek.local"})
    valid_cert = ca.issue_certificate(valid_csr)
    responder = OCSPResponder(ca)
    # İstek nonce'u ile yanıt nonce'u farklı
    fake_response = responder.handle_request(valid_cert.serial_number, request_nonce="eski_nonce_replay")
    try:
        OCSPVerifier.verify_response(valid_cert, fake_response, expected_nonce="yeni_istek_nonce_999")
        flaw_results["CWE-294_replay"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except OCSPNonceMismatchError as e:
        flaw_results["CWE-294_replay"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 3. Zafiyet: İptal Edilmiş Sertifikanın Kullanımı (CWE-299)
    if not json_output:
        print("\n[!] 3. Test: İptal Edilmiş Sertifikanın Doğrulanması (CWE-299)...")
    ca.revoke_certificate(valid_cert.serial_number, reason="keyCompromise")
    revoked_ocsp = responder.handle_request(valid_cert.serial_number, request_nonce="test_nonce")
    try:
        OCSPVerifier.verify_response(valid_cert, revoked_ocsp, expected_nonce="test_nonce")
        flaw_results["CWE-299_revocation"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except CertificateRevokedError as e:
        flaw_results["CWE-299_revocation"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 4. Zafiyet: Süresi Dolmuş Sertifika (CWE-298)
    if not json_output:
        print("\n[!] 4. Test: Süresi Dolmuş Sertifika Zaman Sınırı (CWE-298)...")
    future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    try:
        valid_cert.check_temporal_validity(current_time=future_time)
        flaw_results["CWE-298_expiration"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except CertificateExpiredError as e:
        flaw_results["CWE-298_expiration"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    return flaw_results

def main() -> None:
    """Komut satırı argümanlarını ayrıştırır ve ilgili fonksiyonları çağırır."""
    parser = argparse.ArgumentParser(
        description="PKI ve Sertifika Yaşam Döngüsü Denetim ve Yönetim Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--demo-lifecycle", action="store_true", help="Uçtan uca yaşam döngüsü akışını yürütür")
    parser.add_argument("--demo-flaws", action="store_true", help="PKI güvenlik zaafiyeti ve saldırı senaryolarını çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında sunar")

    args = parser.parse_args()

    # Varsayılan olarak her iki demoyu da çalıştır
    if not args.demo_lifecycle and not args.demo_flaws:
        args.demo_lifecycle = True
        args.demo_flaws = True

    if not args.json:
        print_banner()

    summary: Dict[str, Any] = {}

    if args.demo_lifecycle:
        lifecycle_data = run_lifecycle_demo(json_output=args.json)
        summary["yasam_dongusu"] = lifecycle_data

    if args.demo_flaws:
        flaw_data = run_flaw_demos(json_output=args.json)
        summary["zafiyet_savunmalari"] = flaw_data

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("\n" + "=" * 72)
        print("  TÜM YAŞAM DÖNGÜSÜ İŞLEMLERİ VE ZAFİYET SAVUNMALARI TAMAMLANDI")
        print("=" * 72)

if __name__ == "__main__":
    main()
