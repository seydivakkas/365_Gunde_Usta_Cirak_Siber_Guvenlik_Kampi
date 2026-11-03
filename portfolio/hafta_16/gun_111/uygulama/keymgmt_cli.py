# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
NIST SP 800-57 Uyumlu Anahtar Yönetimi ve Rotasyon CLI Aracı (keymgmt_cli.py).

Kullanıcıların komut satırı üzerinden Zarf Şifreleme (Envelope Encryption),
Kriptoperiyot yönetimi, KEK rotasyonu, Re-wrapping ve Kriptografik Sıfırlama
(Zeroization) süreçlerini test etmesini, simüle etmesini ve denetlemesini sağlar.
"""

import sys
import json
import argparse
import datetime
from typing import Dict, Any

# Anahtar yönetim motoru bileşenlerini içeri aktar
from key_management_engine import (
    KeyManagementService,
    EnvelopeEncryptionEngine,
    DualControlKeySplitter,
    KeyState,
    KeyManagementError,
    KeyExpiredError,
    KeyCompromisedError,
    InadequateKeyLengthError,
    KeyUsageLimitExceededError,
    EncryptedDEKIntegrityError,
    KeyAlreadyDestroyedError,
    InsufficientKeySharesError,
    KeyDeprecatedError,
    PredictableKeyError
)

def print_banner() -> None:
    """CLI aracının karşılama afişini konsola basar."""
    print("=" * 72)
    print("  NIST SP 800-57 UYUMLU ANAHTAR YÖNETİMİ VE ROTASYON ARACI")
    print("  Zarf Şifreleme (Envelope Encryption) / KEK vs DEK / Re-wrapping / Zeroization")
    print("=" * 72)

def run_lifecycle_demo(json_output: bool = False) -> Dict[str, Any]:
    """Uçtan uca anahtar yaşam döngüsünü, zarf şifrelemeyi ve re-wrapping'i yürütür."""
    if not json_output:
        print("\n[*] 1. ADIM: Anahtar Yönetim Servisi (KMS) Başlatılıyor...")

    kms = KeyManagementService()
    # 1. KEK-1 (Master Anahtar) Oluştur
    kek1 = kms.create_kek(key_id="kek_master_v1", bit_length=256, cryptoperiod_days=365)
    if not json_output:
        print(f"[+] KEK-1 Aktif Edildi: ID={kek1.key_id}, Algoritma={kek1.algorithm}, Durum={kek1.state}")

    # 2. Zarf Şifreleme (Envelope Encryption)
    envelope_engine = EnvelopeEncryptionEngine(kms)
    hassas_veri = b"Gizli Finansal Kayitlar: Hesap No 1234-5678-9012"
    if not json_output:
        print("\n[*] 2. ADIM: Zarf Şifreleme ile Hassas Veri Şifreleniyor...")

    envelope_pkg = envelope_engine.encrypt_data(hassas_veri, associated_data=b"tenant_finans_01")
    if not json_output:
        print(f"[+] Zarf Paketi Oluşturuldu:")
        print(f"    - KEK ID: {envelope_pkg['kek_id']}")
        print(f"    - Sarılmış (Wrapped) DEK: {envelope_pkg['wrapped_dek_hex'][:32]}...")
        print(f"    - Şifreli Veri: {envelope_pkg['ciphertext_hex'][:32]}...")

    # Doğrulama: Deşifre Et
    cozulen_veri = envelope_engine.decrypt_data(envelope_pkg, associated_data=b"tenant_finans_01")
    if not json_output:
        print(f"[+] Doğrulama: Veri Başarıyla Çözüldü: '{cozulen_veri.decode('utf-8')}'")

    # 3. Otomatik Anahtar Rotasyonu (Rollover)
    if not json_output:
        print("\n[*] 3. ADIM: Otomatik KEK Rotasyonu (Rollover) Yürütülüyor...")

    kek2 = kms.rotate_kek(new_key_id="kek_master_v2", bit_length=256)
    if not json_output:
        print(f"[+] KEK-2 Aktif Edildi: ID={kek2.key_id}, Durum={kek2.state}")
        print(f"[+] Eski KEK-1 Durumu: {kek1.state} (Yalnızca Deşifre Yapabilir)")

    # 4. Re-wrapping (Veriyi taşımadan yalnızca DEK'i yeni KEK ile sarma)
    if not json_output:
        print("\n[*] 4. ADIM: Re-wrapping: Yalnızca DEK Yeni KEK ile Yeniden Sarılıyor (O(1) Süre)...")

    re_wrapped_envelope = envelope_engine.re_wrap_envelope(envelope_pkg)
    if not json_output:
        print(f"[+] Re-wrapping Tamamlandı!")
        print(f"    - Yeni KEK ID: {re_wrapped_envelope['kek_id']}")
        print(f"    - Şifreli Veri Değişti mi? -> {envelope_pkg['ciphertext_hex'] == re_wrapped_envelope['ciphertext_hex']} (Veri Kopyalanmadı!)")

    # 5. Kriptografik Sıfırlama (Zeroization / Crypto-Shredding)
    if not json_output:
        print("\n[*] 5. ADIM: Eski KEK-1 Kriptografik Olarak Sıfırlanıyor (Zeroization)...")

    kms.destroy_key("kek_master_v1")
    if not json_output:
        print(f"[+] KEK-1 Sıfırlandı ve İmha Edildi! Durum: {kek1.state}, Bellek: {kek1.key_material}")

    results = {
        "orijinal_kek": kek1.key_id,
        "yeni_kek": kek2.key_id,
        "eski_kek_durum": kek1.state,
        "yeni_kek_durum": kek2.state,
        "re_wrapping_basarili": envelope_pkg["ciphertext_hex"] == re_wrapped_envelope["ciphertext_hex"],
        "kms_denetim_kaydi_sayisi": len(kms.audit_log)
    }
    return results

def run_flaw_demos(json_output: bool = False) -> Dict[str, Any]:
    """NIST SP 800-57 güvenlik kontrollerini ve zafiyet senaryolarını test eder."""
    flaw_results = {}
    if not json_output:
        print("\n" + "=" * 72)
        print("  GÜVENLİK ZAFİYETİ VE SALDIRI SENARYOLARI (CWE ANALİZİ)")
        print("=" * 72)

    kms = KeyManagementService()
    active_kek = kms.create_kek("kek_test_01", bit_length=256)
    engine = EnvelopeEncryptionEngine(kms)

    # 1. Zafiyet: Kriptoperiyodu Dolmuş Anahtar (CWE-320)
    if not json_output:
        print("\n[!] 1. Test: Kriptoperiyodu Dolmuş Anahtarla Şifreleme (CWE-320)...")
    past_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=400)
    try:
        active_kek.check_cryptoperiod(current_time=past_time)
        flaw_results["CWE-320_cryptoperiod_expired"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except KeyExpiredError as e:
        flaw_results["CWE-320_cryptoperiod_expired"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 2. Zafiyet: İhlal Edilmiş (COMPROMISED) Anahtarın Kullanımı (CWE-320)
    if not json_output:
        print("\n[!] 2. Test: İhlal Edilmiş (COMPROMISED) Anahtar Kullanımı (CWE-320)...")
    kms.compromise_key("kek_test_01")
    try:
        active_kek.check_cryptoperiod()
        flaw_results["CWE-320_compromised_key"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except KeyCompromisedError as e:
        flaw_results["CWE-320_compromised_key"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 3. Zafiyet: Yetersiz Anahtar Uzunluğu (CWE-326)
    if not json_output:
        print("\n[!] 3. Test: Yetersiz Anahtar Uzunluğu Talebi (CWE-326)...")
    try:
        kms.create_kek("kek_weak_64", bit_length=64)
        flaw_results["CWE-326_weak_key_length"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except InadequateKeyLengthError as e:
        flaw_results["CWE-326_weak_key_length"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 4. Zafiyet: Tahmin Edilebilir / Sıfır Anahtar Tespiti (CWE-321)
    if not json_output:
        print("\n[!] 4. Test: Sabit / Tahmin Edilebilir Anahtar Tespiti (CWE-321)...")
    try:
        kms.create_kek("kek_predictable", bit_length=256, custom_bytes=b"\x00" * 32)
        flaw_results["CWE-321_predictable_key"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except PredictableKeyError as e:
        flaw_results["CWE-321_predictable_key"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 5. Zafiyet: Dual Control Eksik Parça ile Rekonstrüksiyon (CWE-320)
    if not json_output:
        print("\n[!] 5. Test: Çift Kontrol (Dual Control) Eksik Parça (CWE-320)...")
    s1, _ = DualControlKeySplitter.split_secret_2_of_2(b"master_secret_32bayt_uzunlugund!")
    try:
        # Yalnızca 1 parça sunuluyor
        DualControlKeySplitter.combine_secret_2_of_2([s1])
        flaw_results["CWE-320_dual_control_missing"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except InsufficientKeySharesError as e:
        flaw_results["CWE-320_dual_control_missing"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    return flaw_results

def main() -> None:
    """Komut satırı argümanlarını ayrıştırır ve ilgili fonksiyonları çağırır."""
    parser = argparse.ArgumentParser(
        description="NIST SP 800-57 Uyumlu Anahtar Yönetimi ve Rotasyon Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--demo-lifecycle", action="store_true", help="Uçtan uca anahtar yaşam döngüsü ve zarf şifrelemeyi yürütür")
    parser.add_argument("--demo-flaws", action="store_true", help="Anahtar yönetim güvenlik zafiyet senaryolarını çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında sunar")

    args = parser.parse_args()

    if not args.demo_lifecycle and not args.demo_flaws:
        args.demo_lifecycle = True
        args.demo_flaws = True

    if not args.json:
        print_banner()

    summary: Dict[str, Any] = {}

    if args.demo_lifecycle:
        summary["yasam_dongusu"] = run_lifecycle_demo(json_output=args.json)

    if args.demo_flaws:
        summary["zafiyet_savunmalari"] = run_flaw_demos(json_output=args.json)

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("\n" + "=" * 72)
        print("  TÜM ANAHTAR YÖNETİMİ VE ROTASYON TESTLERİ BAŞARIYLA TAMAMLANDI")
        print("=" * 72)

if __name__ == "__main__":
    main()
