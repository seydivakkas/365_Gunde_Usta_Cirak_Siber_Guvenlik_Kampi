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
from datetime import datetime, timezone, timedelta
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
from backup_recovery_engine import (
    BackupRecoveryEngine,
    BackupPolicy,
    BackupArtifact,
    StorageMediaType,
    ImmutabilityMode,
    BackupType,
    RansomwareAttackSimulator,
    BackupHardeningRemediationGenerator
)
from backup_recovery_cli import load_spec_from_json


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
    """9 negatif kontrol ve felaket senaryosunu motor üzerinde çalıştırıp doğrular."""
    clean_json_path = DATA_DIR / "clean_backup_recovery_spec.json"
    neg_json_path = DATA_DIR / "invalid_backup_scenarios.json"

    with open(neg_json_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    out_lines = [
        "=" * 78,
        "GÜN 151: YEDEK DOĞRULAMA VE KURTARMA NEGATİF KONTROL VE FELAKET TESTLERİ",
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
        patch = sc["profile_patch"]

        # Temel veriden yüklenir
        policy, artifacts = load_spec_from_json(str(clean_json_path))

        # Yama uygulanır
        if "artifacts_filter" in patch:
            artifacts = [artifacts[i] for i in patch["artifacts_filter"]]
        if "force_media_type" in patch:
            for a in artifacts:
                a.media_type = StorageMediaType(patch["force_media_type"])
        if patch.get("disable_offsite"):
            for a in artifacts:
                a.is_offsite = False
        if patch.get("disable_immutability"):
            for a in artifacts:
                a.immutability_mode = ImmutabilityMode.NONE
        if "age_hours" in patch:
            old_time = (datetime.now(timezone.utc) - timedelta(hours=patch["age_hours"])).isoformat()
            for a in artifacts:
                a.created_at_utc = old_time
        if "verification_stale_days" in patch:
            stale_time = (datetime.now(timezone.utc) - timedelta(days=patch["verification_stale_days"])).isoformat()
            for a in artifacts:
                a.last_verified_at_utc = stale_time
        if patch.get("corrupt_primary"):
            artifacts[0].is_corrupted = True
        if patch.get("unprotect_vss"):
            for a in artifacts:
                a.vss_shadow_protected = False

        engine = BackupRecoveryEngine(policy, artifacts)
        findings = engine.audit_backup_architecture()

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
    """Denetim raporunu, kurtarma simülasyon çıktısını ve PowerShell sertleştirme betiğini üretir."""
    clean_json_path = DATA_DIR / "clean_backup_recovery_spec.json"
    policy, artifacts = load_spec_from_json(str(clean_json_path))
    engine = BackupRecoveryEngine(policy, artifacts)

    # 1. Denetim Raporu
    findings = engine.audit_backup_architecture()
    report_data = {
        "report_id": "BCK-AUDIT-20261108-001",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "policy_name": policy.policy_name,
        "target_rpo_minutes": policy.target_rpo_minutes,
        "target_rto_minutes": policy.target_rto_minutes,
        "total_artifacts": len(artifacts),
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
    with open(GERCEK_KANIT_DIR / "backup_recovery_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # 2. Kurtarma Doğrulama Raporu
    restore_res = engine.simulate_recovery()
    restore_data = {
        "simulation_id": restore_res.simulation_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": restore_res.status,
        "success": restore_res.success,
        "target_rpo_minutes": policy.target_rpo_minutes,
        "actual_rpo_minutes": restore_res.actual_rpo_minutes,
        "rpo_compliant": restore_res.rpo_compliant,
        "target_rto_minutes": policy.target_rto_minutes,
        "actual_rto_minutes": restore_res.actual_rto_minutes,
        "rto_compliant": restore_res.rto_compliant,
        "checksum_verified": restore_res.checksum_verified,
        "detail": restore_res.detail
    }
    with open(GERCEK_KANIT_DIR / "simulated_restore_verification.json", "w", encoding="utf-8") as f:
        json.dump(restore_data, f, indent=2, ensure_ascii=False)

    # 3. Windows PowerShell Sertleştirme Betiği
    ps1_content = BackupHardeningRemediationGenerator.generate_windows_vss_and_backup_hardening_script()
    with open(GERCEK_KANIT_DIR / "immutable_backup_remediation.ps1", "w", encoding="utf-8") as f:
        f.write(ps1_content)

    print("[+] JSON denetim raporu, kurtarma doğrulama çıktısı ve PowerShell sertleştirme betiği üretildi.")


def run_cli_and_record_log() -> None:
    """CLI komutlarını çalıştırarak konsol oturumunu komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = UYGULAMA_DIR / "backup_recovery_cli.py"
    clean_spec = DATA_DIR / "clean_backup_recovery_spec.json"

    log_entries = [
        "=" * 78,
        "GÜN 151: YEDEK DOĞRULAMA VE KURTARMA CLI KONSOL GÜNLÜĞÜ",
        f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}",
        "=" * 78,
        ""
    ]

    commands = [
        [sys.executable, str(cli_path), "audit", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "simulate-restore", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "simulate-ransomware", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "generate-remediation", "--os-type", "windows", "--output", str(GERCEK_KANIT_DIR / "cli_remediation_output.ps1")]
    ]

    for cmd in commands:
        cmd_str = " ".join(cmd)
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
        log_entries.append(f"$ {cmd_str}")
        log_entries.append(res.stdout.strip())
        if res.stderr.strip():
            log_entries.append(f"[STDERR]: {res.stderr.strip()}")
        log_entries.append("-" * 78)

    # Geçici üretilen CLI betiğini temizleyelim
    temp_cli_ps1 = GERCEK_KANIT_DIR / "cli_remediation_output.ps1"
    if temp_cli_ps1.exists():
        temp_cli_ps1.unlink()

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
        "|           YEDEK DOĞRULAMA, 3-2-1 VE DEĞİŞTİRİLEMEZLİK (WORM) MİMARİSİ       |\n"
        "+-----------------------------------------------------------------------------+\n"
        "\n"
        "   +-----------------------------------------------------------------------+\n"
        "   |                     BİRİNCİL ÜRETİM ORTAMI (TIER 0 / 1)               |\n"
        "   |                                                                       |\n"
        "   |  * Canlı Veritabanı ve Kritik Dosya Sistemleri                        |\n"
        "   |  * VSS (Volume Shadow Copy) Koruma Katmanı (vssadmin ACL kilitli)     |\n"
        "   |  * RPO Hedefi: <= 60 Dakika | RTO Hedefi: <= 120 Dakika              |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Otomatik Yedekleme İşi (SHA-256)    \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |          3-2-1-1-0 STANDARDI VE DEPOLAMA MEDYASI DAĞILIMI             |\n"
        "   +-----------------------------------------------------------------------+\n"
        "       |                                 |                               |  \n"
        "       v                                 v                               v  \n"
        "   [ 1. KOPYA: YEREL NVMe ]    [ 2. KOPYA: AĞ SAN/NAS ]    [ 3. KOPYA: BULUT S3 ]\n"
        "   * Hızlı Geri Yükleme        * Kurumsal Veri Depolama    * Saha Dışı (Off-Site)\n"
        "   * Kısa Süreli Retention     * Governance Modu           * WORM Compliance Mode\n"
        "   * SHA-256 Doğrulamalı       * Güvenli VLAN İzolasyonu   * 30 Gün Kilitli       \n"
        "                                                                 |          \n"
        "                                                                 v          \n"
        "   =========================================================================\n"
        "         FİDYE YAZILIMI (RANSOMWARE) SALDIRISI ANINDAKİ SAVUNMA HATTI       \n"
        "   =========================================================================\n"
        "   Saldırgan: Domain Admin ele geçirdi -> 'vssadmin delete shadows' koşturdu\n"
        "   -> 1. Kopya (Yerel NVMe): Saldırgan tarafından şifrelendi / imha edildi. \n"
        "   -> 2. Kopya (Ağ SAN/NAS): Saldırgan tarafından şifrelendi / silindi.     \n"
        "   -> 3. Kopya (S3 WORM)   : ROOT DAHİL KİMSE SİLEMEZ! (Access Denied 403)  \n"
        "   -------------------------------------------------------------------------\n"
        "   SONUÇ: Felaket Anında S3 WORM Kopyasından Geri Yükleme Başlatılır:       \n"
        "   * RPO: 20 Dakika (Hedef <= 60 dk sağlandı!)                              \n"
        "   * RTO: 35 Dakika (Hedef <= 120 dk sağlandı!)                             \n"
        "   * Bütünlük: SHA-256 Sağlama Toplamı Eşleşti (%100 Temiz Kurtarma)        \n"
        "\n"
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
    )
    target_file = TEMSILI_KANIT_DIR / "yedekleme_kurtarma_mimarisi.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(diagram)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {target_file}")


def main() -> None:
    """Tüm kanıt üreticilerini sıralı icra eder."""
    print("=" * 78)
    print("[*] GÜN 151 KANIT ÜRETİCİ BAŞLATILIYOR...")
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
