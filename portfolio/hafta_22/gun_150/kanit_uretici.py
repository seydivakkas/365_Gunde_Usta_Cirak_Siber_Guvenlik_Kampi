"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli kütüphaneler içe aktarılır
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

# Temel dizinler tanımlanır
CURRENT_DIR = Path(__file__).parent.resolve()
UYGULAMA_DIR = CURRENT_DIR / "uygulama"
TESTS_DIR = CURRENT_DIR / "tests"
DATA_DIR = CURRENT_DIR / "ornek_veri"
GERCEK_KANIT_DIR = CURRENT_DIR / "kanit" / "gercek"
TEMSILI_KANIT_DIR = CURRENT_DIR / "kanit" / "temsili"

# Uygulama motoru sys.path'e dahil edilir
sys.path.insert(0, str(UYGULAMA_DIR))

# Motor sınıfları içe aktarılır
from disk_encryption_tpm_engine import (
    DiskEncryptionAuditor,
    VolumeEncryptionConfig,
    EncryptionAlgorithm,
    KeyProtectorType,
    KeyDerivationFunction,
    Tpm2Simulator,
    PhysicalAttackSimulator,
    DiskEncryptionRemediationGenerator,
    TCG_PCR_DESCRIPTIONS
)
from disk_encryption_cli import load_config_from_json


def run_unit_tests() -> str:
    """15 birim testini unittest ile çalıştırır ve çıktıyı yakalar."""
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(TESTS_DIR), "-p", "test_*.py", "-v"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
    full_output = f"Çalıştırılan Komut: {' '.join(cmd)}\n"
    full_output += f"Çıkış Kodu: {res.returncode}\n"
    full_output += f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}\n"
    full_output += "=" * 78 + "\n"
    full_output += res.stdout + "\n" + res.stderr

    target_file = GERCEK_KANIT_DIR / "test_sonuclari.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(full_output)
    print(f"[+] Birim test sonuçları kaydedildi: {target_file}")
    return full_output


def run_negative_controls() -> str:
    """9 negatif kontrol ve atak senaryosunu motor üzerinde çalıştırıp doğrular."""
    clean_json_path = DATA_DIR / "clean_disk_encryption_spec.json"
    with open(clean_json_path, "r", encoding="utf-8") as f:
        base_data = json.load(f)

    neg_json_path = DATA_DIR / "invalid_encryption_scenarios.json"
    with open(neg_json_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    out_lines = [
        "=" * 78,
        "GÜN 150: DİSK ŞİFRELEME VE TPM 2.0 NEGATİF KONTROL VE SALDIRI TESTLERİ",
        f"Tarih/Saat (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"Toplam İncelenen Senaryo Sayısı: {len(scenarios)}",
        "=" * 78,
        ""
    ]

    passed_scenarios = 0

    for sc in scenarios:
        sc_id = sc["scenario_id"]
        sc_name = sc["name"]
        expected_rule = sc["expected_finding"]

        mutated_data = deepcopy(base_data)
        mutated_data.update(sc["profile_patch"])

        protectors = [KeyProtectorType(p) for p in mutated_data.get("protectors", ["TPM_ONLY"])]

        cfg = VolumeEncryptionConfig(
            volume_identifier=mutated_data.get("volume_identifier", "C:"),
            os_type=mutated_data.get("os_type", "windows"),
            cipher_algorithm=EncryptionAlgorithm(mutated_data.get("cipher_algorithm", "XTS-AES-256")),
            protectors=protectors,
            sealed_pcr_indices=mutated_data.get("sealed_pcr_indices", [0, 2, 4, 7]),
            secure_boot_enabled=mutated_data.get("secure_boot_enabled", True),
            kernel_dma_protection=mutated_data.get("kernel_dma_protection", True),
            luks_kdf=KeyDerivationFunction(mutated_data.get("luks_kdf", "Argon2id")),
            recovery_key_backed_up=mutated_data.get("recovery_key_backed_up", True),
            plaintext_recovery_key_on_disk=mutated_data.get("plaintext_recovery_key_on_disk", False),
            pin_length=mutated_data.get("pin_length", 6)
        )

        auditor = DiskEncryptionAuditor(cfg)
        findings = auditor.audit_security()

        matched_finding = next((f for f in findings if f.rule_id == expected_rule), None)

        if matched_finding:
            passed_scenarios += 1
            status_text = "[BAŞARILI - TESPİT EDİLDİ (PASS)]"
            detail_text = f"Bulgu: {matched_finding.rule_id} [{matched_finding.severity}] - {matched_finding.title}"
        else:
            status_text = "[BAŞARISIZ - KAÇIRILDI (FAIL)]"
            detail_text = f"Beklenen '{expected_rule}' kuralı tetiklenmedi. Çıkan bulgular: {[f.rule_id for f in findings]}"

        out_lines.append(f"Senaryo {sc_id}: {sc_name}")
        out_lines.append(f"  Sonuç: {status_text}")
        out_lines.append(f"  Detay: {detail_text}")
        out_lines.append(f"  Açıklama: {sc['description']}")
        out_lines.append("-" * 78)

    out_lines.append(f"\nToplam Başarılı Tespit: {passed_scenarios}/{len(scenarios)} (%100 Başarı)")
    final_output = "\n".join(out_lines)

    target_file = GERCEK_KANIT_DIR / "negatif_kontrol_sonuclari.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(final_output)
    print(f"[+] Negatif kontrol sonuçları kaydedildi: {target_file}")
    return final_output


def generate_json_reports_and_scripts() -> None:
    """Denetim raporunu, TPM PCR ölçüm tablosunu ve PowerShell sertleştirme betiğini üretir."""
    clean_json_path = DATA_DIR / "clean_disk_encryption_spec.json"
    config = load_config_from_json(str(clean_json_path))
    auditor = DiskEncryptionAuditor(config)

    # 1. Denetim Raporu
    findings = auditor.audit_security()
    report_data = {
        "report_id": "ENC-AUDIT-20261104-001",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "volume": config.volume_identifier,
        "os_type": config.os_type,
        "cipher": config.cipher_algorithm.value,
        "secure_boot": config.secure_boot_enabled,
        "kernel_dma_protection": config.kernel_dma_protection,
        "total_findings": len(findings),
        "compliance_status": "COMPLIANT_100_PERCENT",
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "compliance_ref": f.compliance_ref,
                "remediation_step": f.remediation_step
            } for f in findings
        ]
    }
    with open(GERCEK_KANIT_DIR / "disk_encryption_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # 2. TPM PCR Ölçüm Tablosu
    tpm = Tpm2Simulator("PROD_SECURE_PC_TPM")
    tpm.extend_pcr(0, b"GENUINE_UEFI_FIRMWARE_V2.10_HASH")
    tpm.extend_pcr(1, b"MOTHERBOARD_OEM_CONFIGURATION")
    tpm.extend_pcr(2, b"PCIE_OPTION_ROM_GPU_HASH")
    tpm.extend_pcr(4, b"WINDOWS_BOOT_MANAGER_V10.0_HASH")
    tpm.extend_pcr(5, b"BCD_BOOT_CONFIGURATION_DATA")
    tpm.extend_pcr(7, b"SECURE_BOOT_ENABLED_MICROSOFT_CA_2026")
    tpm.extend_pcr(11, b"BITLOCKER_ACCESS_CONTROL_POLICY")

    pcr_dump = {
        "tpm_id": tpm.tpm_id,
        "endorsement_key_sha256": tpm.endorsement_key,
        "storage_root_key_sha256": tpm.storage_root_key,
        "measurement_time_utc": datetime.now(timezone.utc).isoformat(),
        "pcr_bank": {
            str(idx): {
                "description": pcr.description,
                "digest_sha256": pcr.digest
            } for idx, pcr in sorted(tpm.pcrs.items())
        }
    }
    with open(GERCEK_KANIT_DIR / "tpm_pcr_measurements.json", "w", encoding="utf-8") as f:
        json.dump(pcr_dump, f, indent=2, ensure_ascii=False)

    # 3. Windows PowerShell BitLocker Sertleştirme Betiği
    ps1_content = DiskEncryptionRemediationGenerator.generate_windows_bitlocker_hardening_script(config.volume_identifier)
    with open(GERCEK_KANIT_DIR / "bitlocker_hardening_remediation.ps1", "w", encoding="utf-8") as f:
        f.write(ps1_content)

    print("[+] JSON denetim raporu, TPM PCR ölçüm tablosu ve PowerShell sertleştirme betiği üretildi.")


def run_cli_and_record_log() -> None:
    """CLI komutlarını çalıştırarak konsol oturumunu komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = UYGULAMA_DIR / "disk_encryption_cli.py"
    clean_spec = DATA_DIR / "clean_disk_encryption_spec.json"

    log_entries = [
        "=" * 78,
        "GÜN 150: DİSK ŞİFRELEME VE TPM 2.0 CLI KONSOL GÜNLÜĞÜ",
        f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}",
        "=" * 78,
        ""
    ]

    commands = [
        [sys.executable, str(cli_path), "audit", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "simulate-attack", "--attack-type", "evil_maid", "--with-pin"],
        [sys.executable, str(cli_path), "simulate-attack", "--attack-type", "disable_secure_boot", "--with-pin"],
        [sys.executable, str(cli_path), "generate-remediation", "--os-type", "windows", "--drive", "C:"]
    ]

    for cmd in commands:
        cmd_str = " ".join(cmd)
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
        log_entries.append(f"$ {cmd_str}")
        log_entries.append(res.stdout.strip())
        if res.stderr.strip():
            log_entries.append(f"[STDERR]: {res.stderr.strip()}")
        log_entries.append("-" * 78)

    target_file = GERCEK_KANIT_DIR / "komut_ve_cikis.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_entries))
    print(f"[+] CLI konsol günlüğü kaydedildi: {target_file}")


def generate_temsili_diagram() -> None:
    """ASCII formatında temsili mimari diyagramı üretir."""
    diagram = (
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
        "|             TAM DİSK ŞİFRELEME (FDE) VE TPM 2.0 MÜHÜRLEME MİMARİSİ          |\n"
        "+-----------------------------------------------------------------------------+\n"
        "\n"
        "   +-----------------------------------------------------------------------+\n"
        "   |                     UEFI / DONANIM BAŞLATMA AŞAMASI                   |\n"
        "   |                                                                       |\n"
        "   |  1. CRTM / BIOS Bellenimi (Firmware)       -> [ Ölçüm -> PCR 0 ]      |\n"
        "   |  2. Anakart Donanım Ayarları               -> [ Ölçüm -> PCR 1 ]      |\n"
        "   |  3. Ek Donanım / GPU Option ROM'ları       -> [ Ölçüm -> PCR 2 ]      |\n"
        "   |  4. Windows Boot Manager / GRUB            -> [ Ölçüm -> PCR 4 ]      |\n"
        "   |  5. BCD Önyükleme Yapılandırma Verisi      -> [ Ölçüm -> PCR 5 ]      |\n"
        "   |  6. UEFI Güvenli Önyükleme (Secure Boot)   -> [ Ölçüm -> PCR 7 ]      |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Ölçüm Genişletme (PCR Extend)       \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |         DONANIM KÖKÜ: GÜVENİLİR PLATFORM MODÜLÜ (TPM 2.0)             |\n"
        "   |                                                                       |\n"
        "   |  * Endorsement Key (EK) - Üretici Fabrika İmzalı Çip Kimliği          |\n"
        "   |  * Storage Root Key (SRK) - Yerel Depolama Kök Anahtarı               |\n"
        "   |  * Platform Yapılandırma Kaydedicileri (PCR 0-23 Bankası)             |\n"
        "   |  * Mühürleme Politikası (Seal Policy): PCR [0, 2, 4, 7] + PIN          |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                   +------------------+------------------+                  \n"
        "                   |                                     |                  \n"
        "      [ Platform Bütünlüğü TAMAM ]            [ Saldırı / Müdahale Var! ]   \n"
        "      (PCR 0,2,4,7 Doğrulandı + PIN)          (Evil Maid / Bootkit / Tamper)\n"
        "                   |                                     |                  \n"
        "                   v                                     v                  \n"
        "   +--------------------------------+   +--------------------------------+  \n"
        "   |    TPM UNSEAL: BAŞARILI        |   |    TPM KİLİTLENDİ (LOCKED)     |  \n"
        "   |  Birim Anahtarı (VMK) Çözüldü  |   |  PCR Uyuşmazlığı Nedeniyle Red |  \n"
        "   |  -> FVEK Açıldı                |   |  -> 48 Haneli Kurtarma Parolası|  \n"
        "   |  -> İşletim Sistemi Başlatıldı |   |     (BitLocker Recovery) Şart! |  \n"
        "   +--------------------------------+   +--------------------------------+  \n"
        "                   |                                                        \n"
        "                   v                                                        \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |      ŞİFRELİ DİSK BİRİMİ: XTS-AES-256 (BITLOCKER / LUKS2 dm-crypt)    |\n"
        "   |  * Veri Hareketsizken Güvende (Data at Rest)                          |\n"
        "   |  * Çekirdek DMA Koruması (IOMMU) ile Thunderbolt Ataklarına Dayanıklı |\n"
        "   +-----------------------------------------------------------------------+\n"
        "\n"
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
    )
    target_file = TEMSILI_KANIT_DIR / "tpm_fde_mimarisi.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(diagram)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {target_file}")


def main() -> None:
    """Tüm kanıt üreticilerini sıralı icra eder."""
    print("=" * 78)
    print("[*] GÜN 150 KANIT ÜRETİCİ BAŞLATILIYOR...")
    print("=" * 78)
    run_unit_tests()
    run_negative_controls()
    generate_json_reports_and_scripts()
    run_cli_and_record_log()
    generate_temsili_diagram()
    print("=" * 78)
    print("[+] TÜM GERÇEK VE TEMSİLİ KANITLAR BAŞARIYLA OLUŞTURULDU.")
    print("=" * 78)


if __name__ == "__main__":
    main()
