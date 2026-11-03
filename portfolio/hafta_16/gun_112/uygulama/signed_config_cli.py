# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
Mini Proje 15: İmzalı Yapılandırma Konsepti CLI Aracı (signed_config_cli.py).

Kullanıcıların komut satırı üzerinden kurumsal güvenlik politikalarını imzalamasını,
kanonik JSON formatında zarflamasını, çift imza (Dual Signing) eklemesini,
sistem başlangıcında imza ve epoch doğrulamasını ve tahrifat/rollback saldırılarını
test etmesini ve denetlemesini sağlar.
"""

import sys
import json
import argparse
import datetime
from typing import Dict, Any

# İmzalı yapılandırma motor bileşenlerini içeri aktar
from signed_config_engine import (
    RSAKeyPair,
    SignedConfigSigner,
    SignedConfigVerifier,
    canonicalize_json,
    SignedConfigError,
    ConfigTamperingError,
    InvalidSignatureError,
    RollbackAttackDetectedError,
    ConfigExpiredError,
    InsufficientSignaturesError,
    UntrustedSignerError
)

def print_banner() -> None:
    """CLI aracının karşılama afişini konsola basar."""
    print("=" * 72)
    print("  MİNİ PROJE 15: İMZALI YAPILANDIRMA KONSEPTİ VE DOĞRULAMA ARACI")
    print("  RFC 8785 Kanonik JSON / Asimetrik Dijital İmza / Anti-Rollback")
    print("=" * 72)

def run_project_demo(json_output: bool = False) -> Dict[str, Any]:
    """Uçtan uca imzalı yapılandırma üretim, çift imza ve doğrulama akışını icra eder."""
    if not json_output:
        print("\n[*] 1. ADIM: Güven Kökü (Trust Store) ve Yetkili İmzalayıcılar Kuruluyor...")

    # Yetkili 1: Güvenlik Mimarı (SecOps Lead)
    key_secops = RSAKeyPair.generate(key_id="secops_lead_01", bits=512)
    # Yetkili 2: Altyapı Direktörü (Infra Director)
    key_infra = RSAKeyPair.generate(key_id="infra_director_02", bits=512)

    trust_store = {
        key_secops.key_id: key_secops.public_key,
        key_infra.key_id: key_infra.public_key
    }

    if not json_output:
        print(f"[+] Güvenilen Otoriteler Kaydedildi: {list(trust_store.keys())}")
        print("\n[*] 2. ADIM: Güvenlik Duvarı Politikası İmzalanıyor (Epoch: 1)...")

    signer_secops = SignedConfigSigner(key_secops)
    policy_data = {
        "policy_name": "Prod DMZ Firewall",
        "default_action": "DROP",
        "allowed_ports": [443, 8443],
        "require_tls13": True
    }

    # 1. İmza
    envelope = signer_secops.sign_config(payload=policy_data, epoch=1, validity_days=90)
    if not json_output:
        print(f"[+] 1. İmza Atıldı: İmzalayan={key_secops.key_id}")
        print(f"    - Kanonik Hash: {envelope['payload_sha256']}")
        print(f"    - İmza: {envelope['signatures'][0]['signature_hex'][:32]}...")

    # 2. Çift İmza (Dual Signing) Ekleme
    if not json_output:
        print("\n[*] 3. ADIM: Çift İmza (Dual Signing) Politikası Gereği 2. İmza Ekleniyor...")

    signer_infra = SignedConfigSigner(key_infra)
    dual_signed_envelope = signer_infra.co_sign_envelope(envelope)
    if not json_output:
        print(f"[+] 2. İmza Eklendi: İmzalayan={key_infra.key_id}")
        print(f"    - Toplam İmza Sayısı: {len(dual_signed_envelope['signatures'])}")

    # 3. Sistem Doğrulaması (Verifier)
    if not json_output:
        print("\n[*] 4. ADIM: Sistem Doğrulayıcısı (Verifier) Tarafından Yükleme Denetleniyor...")

    verifier = SignedConfigVerifier(trust_store=trust_store, current_system_epoch=1, required_signatures=2)
    loaded_policy = verifier.verify_and_load(dual_signed_envelope)

    if not json_output:
        print(f"[+] Doğrulama Başarılı! Yapılandırma Güvenle Yüklendi:")
        print(f"    - Politika: {loaded_policy['policy_name']}")
        print(f"    - TLS 1.3 Zorunlu mu? -> {loaded_policy['require_tls13']}")

    results = {
        "durum": "BASARILI",
        "epoch": envelope["epoch"],
        "imzalayanlar": [s["signer_id"] for s in dual_signed_envelope["signatures"]],
        "payload_hash": envelope["payload_sha256"],
        "yuklenen_politika": loaded_policy["policy_name"]
    }
    return results

def run_flaw_demos(json_output: bool = False) -> Dict[str, Any]:
    """Tahrifat, Rollback ve yetkisiz imzalayıcı zafiyet senaryolarını test eder."""
    flaw_results = {}
    if not json_output:
        print("\n" + "=" * 72)
        print("  GÜVENLİK ZAFİYETİ VE SALDIRI SENARYOLARI (CWE ANALİZİ)")
        print("=" * 72)

    key_auth = RSAKeyPair.generate(key_id="authorized_admin", bits=512)
    trust_store = {key_auth.key_id: key_auth.public_key}
    signer = SignedConfigSigner(key_auth)
    verifier = SignedConfigVerifier(trust_store=trust_store, current_system_epoch=2, required_signatures=1)

    base_payload = {"admin_port": 8443, "allow_root": False}
    envelope = signer.sign_config(payload=base_payload, epoch=2, validity_days=30)

    # 1. Zafiyet: Payload Tahrifatı (CWE-353)
    if not json_output:
        print("\n[!] 1. Test: Yapılandırma Yükünde Tek Baytlık Tahrifat (CWE-353)...")
    tampered_envelope = json.loads(json.dumps(envelope))
    tampered_envelope["payload"]["allow_root"] = True # Yetkisiz değişiklik
    try:
        verifier.verify_and_load(tampered_envelope)
        flaw_results["CWE-353_tampering"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except ConfigTamperingError as e:
        flaw_results["CWE-353_tampering"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 2. Zafiyet: Rollback Saldırısı (CWE-294)
    if not json_output:
        print("\n[!] 2. Test: Düşük Epoch ile Rollback Saldırısı (CWE-294)...")
    rollback_envelope = signer.sign_config(payload=base_payload, epoch=1, validity_days=30)
    try:
        # Sistem şu an epoch=2'de, sunulan ise epoch=1
        verifier.verify_and_load(rollback_envelope)
        flaw_results["CWE-294_rollback"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except RollbackAttackDetectedError as e:
        flaw_results["CWE-294_rollback"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 3. Zafiyet: Yetkisiz İmzalayıcı (CWE-295)
    if not json_output:
        print("\n[!] 3. Test: Güven Deposunda Olmayan Yetkisiz İmza (CWE-295)...")
    attacker_key = RSAKeyPair.generate(key_id="attacker_hacker_99", bits=512)
    attacker_signer = SignedConfigSigner(attacker_key)
    untrusted_envelope = attacker_signer.sign_config(payload=base_payload, epoch=3)
    try:
        verifier.verify_and_load(untrusted_envelope)
        flaw_results["CWE-295_untrusted_signer"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except UntrustedSignerError as e:
        flaw_results["CWE-295_untrusted_signer"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    return flaw_results

def main() -> None:
    """Komut satırı argümanlarını ayrıştırır ve ilgili fonksiyonları çağırır."""
    parser = argparse.ArgumentParser(
        description="Mini Proje 15: İmzalı Yapılandırma Konsepti ve Doğrulama Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--demo-lifecycle", action="store_true", help="İmzalı yapılandırma ve çift imza akışını çalıştırır")
    parser.add_argument("--demo-flaws", action="store_true", help="Tahrifat ve rollback saldırı senaryolarını çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında sunar")

    args = parser.parse_args()

    if not args.demo_lifecycle and not args.demo_flaws:
        args.demo_lifecycle = True
        args.demo_flaws = True

    if not args.json:
        print_banner()

    summary: Dict[str, Any] = {}

    if args.demo_lifecycle:
        summary["yasam_dongusu"] = run_project_demo(json_output=args.json)

    if args.demo_flaws:
        summary["zafiyet_savunmalari"] = run_flaw_demos(json_output=args.json)

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("\n" + "=" * 72)
        print("  MİNİ PROJE 15 TÜM TEST VE DOĞRULAMA SÜREÇLERİ BAŞARIYLA TAMAMLANDI")
        print("=" * 72)

if __name__ == "__main__":
    main()
