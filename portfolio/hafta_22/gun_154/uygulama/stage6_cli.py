# -*- coding: utf-8 -*-
"""
Aşama 6 Kalite Özeti ve Kabul CLI Yönetim Aracı
Hafta 22 / Gün 154

Bu araç; Aşama 6 kurumsal mimari şartnamelerini okur, 6 kalite kapısını denetler,
terminalde kabul sertifikası çizer ve başarısız kapılar için otomatik PowerShell
iyileştirme betikleri üretir.
"""

import argparse
import json
import sys
import os

# Üst dizindeki paketleri içe aktarmak için sistem yoluna eklenir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.stage6_quality_engine import (
    Stage6QualityEngine,
    Stage6ArchitectureSpec,
    Stage6AuditReport,
    GateStatus,
)


def load_architecture_spec(file_path: str) -> Stage6ArchitectureSpec:
    """JSON dosyasından Aşama 6 mimari şartnamesini yükler."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Aşama 6 şartname dosyası bulunamadı: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return Stage6ArchitectureSpec(
        organization_name=data["organization_name"],
        mfa_enforced=data["mfa_enforced"],
        allowed_mfa_methods=data["allowed_mfa_methods"],
        password_hashing_algorithm=data["password_hashing_algorithm"],
        ntlmv1_disabled=data["ntlmv1_disabled"],
        kerberos_rc4_disabled=data["kerberos_rc4_disabled"],
        access_control_model=data["access_control_model"],
        stale_accounts_deprovisioning_hours=data["stale_accounts_deprovisioning_hours"],
        orphaned_accounts_count=data["orphaned_accounts_count"],
        gmsa_used_for_services=data["gmsa_used_for_services"],
        standing_domain_admin_accounts=data["standing_domain_admin_accounts"],
        jit_elevation_enabled=data["jit_elevation_enabled"],
        max_elevation_duration_hours=data["max_elevation_duration_hours"],
        session_recording_active=data["session_recording_active"],
        edr_fleet_coverage_percent=float(data["edr_fleet_coverage_percent"]),
        tamper_protection_enforced=data["tamper_protection_enforced"],
        edr_signatures_max_age_hours=data["edr_signatures_max_age_hours"],
        full_disk_encryption_percent=float(data["full_disk_encryption_percent"]),
        tpm2_pcr_binding_verified=data["tpm2_pcr_binding_verified"],
        app_whitelisting_mode=data["app_whitelisting_mode"],
        lsa_protection_ppl_enabled=data["lsa_protection_ppl_enabled"],
        backup_rule_32110_compliant=data["backup_rule_32110_compliant"],
        worm_immutable_storage_active=data["worm_immutable_storage_active"],
        last_restore_drill_days_ago=data["last_restore_drill_days_ago"],
        auto_remediation_drift_active=data["auto_remediation_drift_active"],
    )


def handle_audit(args):
    """Tüm 6 kalite kapısını denetler ve kabul sonucunu konsola basar."""
    spec = load_architecture_spec(args.spec)
    engine = Stage6QualityEngine()
    report = engine.audit_stage_6(spec)

    cert_text = engine.generate_ascii_certificate(report)
    print(cert_text)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        dict_data = engine.export_report_to_dict(report)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(dict_data, f, indent=2, ensure_ascii=False)
        print(f"[+] Denetim raporu JSON formatında kaydedildi: {args.output}")


def handle_verify_gate(args):
    """Tek bir kalite kapısının detaylı test ve bulgu dökümünü yapar."""
    spec = load_architecture_spec(args.spec)
    engine = Stage6QualityEngine()
    gate_id = int(args.gate)

    gate_map = {
        1: engine.evaluate_gate_1_authentication,
        2: engine.evaluate_gate_2_least_privilege,
        3: engine.evaluate_gate_3_pam_jit,
        4: engine.evaluate_gate_4_edr_telemetry,
        5: engine.evaluate_gate_5_hardware_and_sandbox,
        6: engine.evaluate_gate_6_resilience_and_drift,
    }

    if gate_id not in gate_map:
        print(f"[-] Hata: Geçersiz kapı ID: {gate_id}. Geçerli değerler 1 ile 6 arasındadır.")
        sys.exit(1)

    result = gate_map[gate_id](spec)
    print("=" * 70)
    print(f" KALİTE KAPISI {result.gate_id}: {result.name}")
    print("=" * 70)
    print(f" Puan / Eşik : {result.score} / {result.threshold}")
    print(f" Durum       : {result.status.value}")
    print("-" * 70)
    print(" BAŞARILI KONTROLLER:")
    for chk in result.passed_checks:
        print(f"   [+] {chk}")
    print("-" * 70)
    print(" TESPİT EDİLEN UYGUNSUZLUKLAR:")
    if result.violations:
        for viol in result.violations:
            print(f"   [-] {viol}")
    else:
        print("   [+] Bu kapıda hiçbir uygunsuzluk bulunamadı.")
    print("=" * 70)


def handle_remediation(args):
    """Aşama 6 ihlalleri için PowerShell iyileştirme betiği üretir."""
    spec = load_architecture_spec(args.spec)
    engine = Stage6QualityEngine()
    report = engine.audit_stage_6(spec)

    lines = [
        "# PowerShell Aşama 6 Kalite İyileştirme Betiği",
        f"# Hedef Organizasyon: {spec.organization_name}",
        f"# Genel Kalite Skoru: {report.overall_score}/100",
        "$ErrorActionPreference = 'Stop'",
        "",
        "Write-Host '[*] Aşama 6 Uç Nokta ve IAM İyileştirmeleri Başlatılıyor...' -ForegroundColor Cyan",
        "",
    ]

    # Başarısız kapılara göre komutlar üretilir
    for g in report.gate_results:
        if g.status == GateStatus.FAIL or g.violations:
            lines.append(f"# --- Kapı {g.gate_id}: {g.name} İyileştirmeleri ---")
            for v in g.violations:
                if "MFA" in v:
                    lines.append("# MFA Zorunluluğu Politikası")
                    lines.append("Set-MsolCompanySettings -UsersMustCompleteMfaRegistration $true")
                elif "NTLMv1" in v:
                    lines.append("# NTLMv1 Devre Dışı Bırakma (LMCompatibilityLevel=5)")
                    lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5")
                elif "Kalıcı" in v or "Domain Admin" in v:
                    lines.append("# Kalıcı Domain Admin Üyelerini Temizleme")
                    lines.append("Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.SamAccountName -ne 'Administrator'} | Remove-ADGroupMember -Identity 'Domain Admins' -Confirm:$false")
                elif "Tamper Protection" in v:
                    lines.append("# Microsoft Defender Kurcalamaya Karşı Koruma Açma")
                    lines.append("Set-MpPreference -DisableRealtimeMonitoring $false")
                elif "LSA" in v:
                    lines.append("# LSA Koruması (RunAsPPL) Aktifleştirme")
                    lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1")
            lines.append("")

    lines.append("Write-Host '[+] Aşama 6 kurumsal iyileştirme komutları tamamlandı.' -ForegroundColor Green")
    script_content = "\n".join(lines)

    if args.output_script:
        os.makedirs(os.path.dirname(os.path.abspath(args.output_script)), exist_ok=True)
        with open(args.output_script, "w", encoding="utf-8") as f:
            f.write(script_content)
        print(f"[+] İyileştirme betiği üretildi: {args.output_script}")
    else:
        print(script_content)


def main():
    """Aşama 6 CLI giriş noktası."""
    parser = argparse.ArgumentParser(description="Aşama 6 Kalite Özeti ve Kabul Yönetim Aracı")
    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # audit komutu
    audit_parser = subparsers.add_parser("audit", help="Tüm 6 kapıyı denetle ve kabul raporu üret")
    audit_parser.add_argument("--spec", required=True, help="Aşama 6 şartname JSON dosyası")
    audit_parser.add_argument("--output", help="Raporun kaydedileceği JSON dosya yolu")

    # verify-gate komutu
    gate_parser = subparsers.add_parser("verify-gate", help="Tek bir kalite kapısını doğrula")
    gate_parser.add_argument("--spec", required=True, help="Aşama 6 şartname JSON dosyası")
    gate_parser.add_argument("--gate", required=True, choices=["1", "2", "3", "4", "5", "6"], help="Kapı numarası (1-6)")

    # remediation komutu
    rem_parser = subparsers.add_parser("remediation", help="Başarısız kontroller için PowerShell iyileştirme betiği üret")
    rem_parser.add_argument("--spec", required=True, help="Aşama 6 şartname JSON dosyası")
    rem_parser.add_argument("--output-script", help="Kaydedilecek PowerShell betik dosyası (.ps1)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        handle_audit(args)
    elif args.command == "verify-gate":
        handle_verify_gate(args)
    elif args.command == "remediation":
        handle_remediation(args)


if __name__ == "__main__":
    main()
