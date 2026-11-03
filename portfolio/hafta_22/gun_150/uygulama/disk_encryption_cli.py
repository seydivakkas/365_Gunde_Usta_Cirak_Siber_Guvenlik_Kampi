"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli kütüphaneler içe aktarılır
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

# Uygulama motorundan veri sınıfları ve motor bileşenleri içe aktarılır
from disk_encryption_tpm_engine import (
    DiskEncryptionAuditor,
    VolumeEncryptionConfig,
    EncryptionAlgorithm,
    KeyProtectorType,
    KeyDerivationFunction,
    Tpm2Simulator,
    PhysicalAttackSimulator,
    DiskEncryptionRemediationGenerator
)


def load_config_from_json(json_path: str) -> VolumeEncryptionConfig:
    """JSON dosyasından VolumeEncryptionConfig veri modelini yükler."""
    p = Path(json_path)
    if not p.exists():
        raise FileNotFoundError(f"Yapılandırma dosyası bulunamadı: {json_path}")

    with open(p, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)

    # Koruyucular listesi dönüştürülür
    protectors = [KeyProtectorType(p) for p in data.get("protectors", ["TPM_ONLY"])]

    # Konfigürasyon nesnesi inşa edilir
    config = VolumeEncryptionConfig(
        volume_identifier=data.get("volume_identifier", "C:"),
        os_type=data.get("os_type", "windows"),
        cipher_algorithm=EncryptionAlgorithm(data.get("cipher_algorithm", "XTS-AES-256")),
        protectors=protectors,
        sealed_pcr_indices=data.get("sealed_pcr_indices", [0, 2, 4, 7]),
        secure_boot_enabled=data.get("secure_boot_enabled", True),
        kernel_dma_protection=data.get("kernel_dma_protection", True),
        luks_kdf=KeyDerivationFunction(data.get("luks_kdf", "Argon2id")),
        recovery_key_backed_up=data.get("recovery_key_backed_up", True),
        plaintext_recovery_key_on_disk=data.get("plaintext_recovery_key_on_disk", False),
        pin_length=data.get("pin_length", 6)
    )
    return config


def handle_audit(args: argparse.Namespace) -> int:
    """Disk şifreleme ve TPM yapılandırma denetimini icra eder."""
    config = load_config_from_json(args.config)
    auditor = DiskEncryptionAuditor(config)
    findings = auditor.audit_security()

    print("=" * 78)
    print(f"[*] DİSK ŞİFRELEME VE TPM GÜVENLİK DENETİMİ: {config.volume_identifier}")
    print(f"[*] İşletim Sistemi: {config.os_type.upper()} | Algoritma: {config.cipher_algorithm.value}")
    print(f"[*] Güvenli Önyükleme (Secure Boot): {'AKTİF' if config.secure_boot_enabled else 'DEVRE DIŞI'}")
    print(f"[*] Çekirdek DMA Koruması (IOMMU): {'AKTİF' if config.kernel_dma_protection else 'DEVRE DIŞI'}")
    print("=" * 78)

    if not findings:
        print("[+] TEBRİKLER: Disk şifreleme ve TPM yapılandırması tam uyumlu (100/100).")
        return 0

    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] [{f.severity}] {f.rule_id} - {f.title}")
        print(f"    Standart  : {f.compliance_ref}")
        print(f"    Açıklama  : {f.description}")
        print(f"    Düzeltme  : {f.remediation_step}")
        print("-" * 78)

    print(f"[-] Toplam Tespit Edilen Zafiyet/Sapma Sayısı: {len(findings)}")
    return len(findings)


def handle_simulate_attack(args: argparse.Namespace) -> int:
    """Fiziksel temas ve önyükleyici kurcalama (Evil Maid) saldırısını simüle eder."""
    print("=" * 78)
    print("[*] TPM 2.0 VE BİTLOCKER EVIL MAID SALDIRI SİMÜLASYONU BAŞLATILIYOR...")
    print("=" * 78)

    # 1. Sanal TPM başlatılır ve meşru donanım bileşenleri ölçülür
    tpm = Tpm2Simulator("PROD_SECURE_PC_TPM")
    tpm.extend_pcr(0, b"ORIGINAL_UEFI_FIRMWARE_V2.10")
    tpm.extend_pcr(2, b"ORIGINAL_PCIE_OPTION_ROM_GPU")
    tpm.extend_pcr(4, b"ORIGINAL_WINDOWS_BOOTMGR_V10.0")
    tpm.extend_pcr(7, b"SECURE_BOOT_ENABLED_MICROSOFT_CA")

    # 2. Disk anahtarı (VMK) PCR 0, 2, 4, 7 durumuna ve PIN'e mühürlenir
    vmk_master_key = "FVEK_SUPER_SECRET_AES_VOLUME_KEY_0x998877665544332211"
    pin = "123456" if args.with_pin else None
    sealed_blob = tpm.seal_key(vmk_master_key, [0, 2, 4, 7], user_pin=pin)
    print(f"[+] Disk anahtarı (VMK) TPM 2.0 yongasına mühürlendi (PCR: 0, 2, 4, 7).")

    # 3. Normal Meşru Açılış Testi
    legit_res = tpm.unseal_key(sealed_blob, user_pin=pin)
    print(f"[+] Meşru Önyükleme Doğrulaması: {legit_res.status_code} - {legit_res.detail}")

    # 4. Saldırı Simülasyonu
    if args.attack_type == "evil_maid":
        print("[!] Saldırgan cihaza fiziksel olarak ulaştı ve sahte bir bootloader yazdı (Evil Maid)!")
        attack_res = PhysicalAttackSimulator.simulate_evil_maid_bootloader_tampering(tpm, sealed_blob)
    else:
        print("[!] Saldırgan BIOS'a girip Secure Boot korumasını kapattı!")
        attack_res = PhysicalAttackSimulator.simulate_secure_boot_tampering(tpm, sealed_blob)

    print("-" * 78)
    print(f"Saldırı Sonrası TPM Durumu : {attack_res.status_code}")
    print(f"Anahtar Çözüldü mü?         : {'EVET (GÜVENLİK İHLALİ!)' if attack_res.success else 'HAYIR (BAŞARIYLA KİLİTLENDİ)'}")
    print(f"TPM Yanıt Detayı           : {attack_res.detail}")
    print(f"Bozulan PCR Kaydedicileri  : {attack_res.pcr_mismatches}")
    print("=" * 78)

    return 0 if not attack_res.success else 1


def handle_generate_remediation(args: argparse.Namespace) -> int:
    """Sertleştirme betiği üretir."""
    if args.os_type == "windows":
        content = DiskEncryptionRemediationGenerator.generate_windows_bitlocker_hardening_script(args.drive)
        ext = "ps1"
    else:
        content = DiskEncryptionRemediationGenerator.generate_linux_luks_tpm_script(args.drive)
        ext = "sh"

    out_path = Path(args.output) if args.output else Path(f"disk_encryption_hardening.{ext}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[+] {args.os_type.upper()} sertleştirme betiği başarıyla üretildi: {out_path}")
    return 0


def main() -> None:
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Disk Şifreleme (BitLocker/LUKS) ve TPM 2.0 Güvenlik Yönetim Aracı (Usta-Çırak Serisi Gün 150)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Denetim
    p_audit = subparsers.add_parser("audit", help="Disk şifreleme ve TPM politikasını denetler")
    p_audit.add_argument("--config", "-c", required=True, help="Yapılandırma JSON dosyası yolu")
    p_audit.set_defaults(func=handle_audit)

    # 2. Saldırı Simülasyonu
    p_sim = subparsers.add_parser("simulate-attack", help="Evil Maid ve Secure Boot manipülasyonu simüle eder")
    p_sim.add_argument("--attack-type", choices=["evil_maid", "disable_secure_boot"], default="evil_maid", help="Saldırı senaryosu türü")
    p_sim.add_argument("--with-pin", action="store_true", help="TPM + PIN korumasını aktif et")
    p_sim.set_defaults(func=handle_simulate_attack)

    # 3. Sertleştirme Betiği Üretimi
    p_rem = subparsers.add_parser("generate-remediation", help="Sertleştirme komut dosyası üretir")
    p_rem.add_argument("--os-type", choices=["windows", "linux"], default="windows", help="İşletim sistemi türü")
    p_rem.add_argument("--drive", default="C:", help="Birim harfi veya blok aygıtı (örn: C: veya /dev/nvme0n1p3)")
    p_rem.add_argument("--output", "-o", help="Çıktı dosya yolu")
    p_rem.set_defaults(func=handle_generate_remediation)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
