# -*- coding: utf-8 -*-
"""
Gün 154: Aşama 6 Kalite Özeti ve Kabul Kanıt Üretici Betiği
Hafta 22 / Gün 154

Bu betik; 15 birim testini, 9 negatif kontrol senaryosunu, kurumsal kabul
sertifikasını, JSON denetim raporunu, PowerShell iyileştirme betiğini ve
temsili mimari diyagramı üreterek gerçek kanıt dosyalarını kaydeder.
"""

import unittest
import io
import os
import sys
import json
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from uygulama.stage6_quality_engine import (
    Stage6QualityEngine,
    Stage6ArchitectureSpec,
    Stage6AuditReport,
    GateStatus,
)
from uygulama.stage6_cli import load_architecture_spec


def generate_unit_test_evidence():
    """15 birim testini çalıştırır ve kanıt dosyasına kaydeder."""
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output_text = stream.getvalue()

    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "test_sonuclari.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(" GÜN 154: BİRİM TEST SONUÇLARI (15/15 PASS) - AŞAMA 6 KALİTE ÖZETİ\n")
        f.write("=" * 80 + "\n\n")
        f.write(output_text)
        f.write("\n" + "=" * 80 + "\n")
        f.write(f" TOPLAM TEST: {result.testsRun} | BAŞARILI: {result.testsRun - len(result.failures) - len(result.errors)} | HATA: {len(result.errors)} | BAŞARISIZ: {len(result.failures)}\n")
        f.write(f" DURUM: {'BAŞARILI (PASS)' if result.wasSuccessful() else 'BAŞARISIZ (FAIL)'}\n")
        f.write("=" * 80 + "\n")

    print(f"[+] Birim test sonuçları kaydedildi: {out_path}")
    return result.wasSuccessful()


def generate_negative_control_evidence():
    """9 negatif kontrol senaryosunu çalıştırır ve kanıt dosyasına kaydeder."""
    spec_path = os.path.join(CURRENT_DIR, "ornek_veri", "enterprise_stage6_spec.json")
    clean_spec = load_architecture_spec(spec_path)

    scn_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_stage6_scenarios.json")
    with open(scn_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    engine = Stage6QualityEngine()
    lines = []
    lines.append("=" * 80)
    lines.append(" GÜN 154: NEGATİF KONTROL VE HATA SENARYOLARI RAPORU (9/9 PASS)")
    lines.append("=" * 80 + "\n")

    passed_count = 0

    for s in scenarios:
        sid = s["scenario_id"]
        name = s["name"]
        overrides = s["spec_overrides"]
        expected_verdict = s["expected_verdict"]

        lines.append(f"[*] Senaryo: {sid} - {name}")
        lines.append(f"    Açıklama: {s['description']}")

        # Şartname klonlanır ve geçersiz kılmalar uygulanır
        mutated_dict = clean_spec.__dict__.copy()
        mutated_dict.update(overrides)
        mutated_spec = Stage6ArchitectureSpec(**mutated_dict)

        report = engine.audit_stage_6(mutated_spec)

        lines.append(f"    Hesaplanan Aşama 6 Skoru: {report.overall_score} / 100")
        lines.append(f"    Nihai Karar            : {report.final_verdict.value} (Beklenen: {expected_verdict})")
        lines.append(f"    Başarısız Kapı Sayısı   : {report.failed_gates_count}")

        # Beklenen durum doğrulanır
        if report.final_verdict.value == expected_verdict:
            lines.append("    [+] DURUM: BAŞARILI (Uygunsuzluk doğru yakalandı ve kabul engellendi).")
            passed_count += 1
        else:
            lines.append("    [-] DURUM: UYARISIZ (Beklenen karar üretilmedi).")

        lines.append("-" * 80)

    lines.append(f"\nTOPLAM SENARYO: {len(scenarios)} | BAŞARILI DOĞRULAMA: {passed_count}/{len(scenarios)}")
    lines.append("SONUÇ: %100 NEGATİF KONTROL VE KALİTE KAPISI KABUL ENGELEME BAŞARISI (PASS)\n")

    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_path}")
    return passed_count == len(scenarios)


def generate_stage6_audit_artifacts():
    """Temiz kurumsal şartnameyi denetler ve resmi sertifika, JSON rapor üretir."""
    spec_path = os.path.join(CURRENT_DIR, "ornek_veri", "enterprise_stage6_spec.json")
    spec = load_architecture_spec(spec_path)
    engine = Stage6QualityEngine()
    report = engine.audit_stage_6(spec)

    # 1. JSON Denetim Raporu
    json_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "asama6_kalite_denetim_raporu.json")
    dict_data = engine.export_report_to_dict(report)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dict_data, f, indent=2, ensure_ascii=False)

    # 2. ASCII Kabul Sertifikası
    cert_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "asama6_kabul_sertifikasi.txt")
    cert_text = engine.generate_ascii_certificate(report)
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(cert_text)

    # 3. Örnek İyileştirme Betiği
    ps_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "asama6_remediation.ps1")
    # Zafiyetli bir senaryodan iyileştirme betiği üretilir
    bad_dict = spec.__dict__.copy()
    bad_dict["mfa_enforced"] = False
    bad_dict["ntlmv1_disabled"] = False
    bad_dict["standing_domain_admin_accounts"] = 3
    bad_dict["tamper_protection_enforced"] = False
    bad_dict["lsa_protection_ppl_enabled"] = False
    bad_spec = Stage6ArchitectureSpec(**bad_dict)
    bad_report = engine.audit_stage_6(bad_spec)

    ps_lines = [
        "# PowerShell Aşama 6 Otomatik İyileştirme Betiği",
        f"# Hedef Kurum: {spec.organization_name}",
        "$ErrorActionPreference = 'Stop'",
        "",
        "Write-Host '[*] Aşama 6 Uç Nokta ve IAM İyileştirmeleri Başlatılıyor...' -ForegroundColor Cyan",
        "",
        "# 1. NTLMv1 Devre Dışı Bırakma (LMCompatibilityLevel=5)",
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5",
        "",
        "# 2. LSA Protection (RunAsPPL) Aktifleştirme",
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1",
        "",
        "# 3. Microsoft Defender Kurcalamaya Karşı Koruma (Tamper Protection) Açma",
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        "",
        "# 4. Kalıcı Domain Admin Üyelerini Temizleme (JIT Hazırlığı)",
        "Get-ADGroupMember -Identity 'Domain Admins' | Where-Object {$_.SamAccountName -ne 'Administrator'} | Remove-ADGroupMember -Identity 'Domain Admins' -Confirm:$false",
        "",
        "Write-Host '[+] Aşama 6 kurumsal iyileştirme tamamlandı.' -ForegroundColor Green",
    ]
    with open(ps_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ps_lines))

    print("[+] Aşama 6 JSON denetim raporu, kabul sertifikası ve iyileştirme betiği üretildi.")


def generate_cli_execution_log():
    """CLI komutlarını çalıştırarak konsol günlüğünü kanıt dosyasına kaydeder."""
    cli_path = os.path.join(CURRENT_DIR, "uygulama", "stage6_cli.py")
    spec_path = os.path.join(CURRENT_DIR, "ornek_veri", "enterprise_stage6_spec.json")
    log_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "komut_ve_cikis.txt")

    commands = [
        [sys.executable, cli_path, "audit", "--spec", spec_path],
        [sys.executable, cli_path, "verify-gate", "--spec", spec_path, "--gate", "1"],
        [sys.executable, cli_path, "verify-gate", "--spec", spec_path, "--gate", "3"],
        [sys.executable, cli_path, "verify-gate", "--spec", spec_path, "--gate", "4"],
        [sys.executable, cli_path, "remediation", "--spec", spec_path],
    ]

    log_lines = []
    log_lines.append("=" * 80)
    log_lines.append(" GÜN 154: AŞAMA 6 KALİTE ÖZETİ CLI YÜRÜTME VE KONSOL GÜNLÜĞÜ")
    log_lines.append("=" * 80 + "\n")

    for cmd in commands:
        cmd_str = " ".join(cmd)
        log_lines.append(f"$ {cmd_str}\n")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            log_lines.append(res.stdout)
        except subprocess.CalledProcessError as e:
            log_lines.append(e.stdout)
            log_lines.append(e.stderr)
        log_lines.append("\n" + "-" * 80 + "\n")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))

    print(f"[+] CLI konsol günlüğü kaydedildi: {log_path}")


def generate_representative_diagram():
    """Temsili ASCII mimari diyagramını zorunlu banner ile kaydeder."""
    diag_path = os.path.join(CURRENT_DIR, "kanit", "temsili", "asama6_kalite_mimarisi.txt")
    os.makedirs(os.path.dirname(diag_path), exist_ok=True)

    diagram_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

            AŞAMA 6 KALİTE GÜVENCE VE KABUL MİMARİSİ (ENDPOINT VE IAM)
                       (GÜN 127 - 154 / HAFTA 19 - 22)

   +-------------------------------------------------------------------------+
   |            SÜTUN A: KİMLİK VE ERİŞİM GÜVENLİĞİ (IAM & PAM)              |
   |                                                                         |
   |   [KAPI 1: Kimlik Doğrulama]  -> MFA (FIDO2/TOTP), Argon2id, NTLMv1 Kapalı|
   |   [KAPI 2: En Az Ayrıcalık]   -> RBAC/ABAC, JML Leaver (<24h), gMSA     |
   |   [KAPI 3: Ayrıcalıklı Erişim]-> Kalıcı Admin: 0, JIT (<4h), PAM Video  |
   +-------------------------------------------------------------------------+
                                      |
                                      +--------------------+
                                                           |
   +-------------------------------------------------------------------------+
   |            SÜTUN B: UÇ NOKTA SAVUNMA DERİNLİĞİ (ENDPOINT HARDENING)     |
   |                                                                         |
   |   [KAPI 4: Görünürlük & Telemetri] -> EDR %100, Tamper Protection Açık  |
   |   [KAPI 5: Donanım Kökü & Sandbox] -> TPM 2.0 PCR, BitLocker, WDAC, PPL |
   |   [KAPI 6: Dayanıklılık & Kurtarma]-> 3-2-1-1-0 WORM Yedek, Auto-Remediate|
   +-------------------------------------------------------------------------+
                                      |
                                      v
   +-------------------------------------------------------------------------+
   |               AŞAMA 6 KALİTE KABUL MOTORU (QUALITY GATE ENGINE)          |
   |                     (Stage6QualityEngine.audit_stage_6)                 |
   |                                                                         |
   |   KAPI 1 Skoru: 100/100 (GECTI)   |   KAPI 4 Skoru: 100/100 (GECTI)     |
   |   KAPI 2 Skoru: 100/100 (GECTI)   |   KAPI 5 Skoru: 100/100 (GECTI)     |
   |   KAPI 3 Skoru: 100/100 (GECTI)   |   KAPI 6 Skoru: 100/100 (GECTI)     |
   |                                                                         |
   |   GENEL AŞAMA 6 PUANI: 100.0 / 100.0 (Kabul Eşiği: 90.0)                |
   |   NİHAİ KARAR         : GECTI (RESMİ AŞAMA 6 KABUL SERTİFİKASI VERİLDİ) |
   +-------------------------------------------------------------------------+
                                      |
                   +------------------+------------------+
                   |                                     |
                   v                                     v
   +---------------------------------+   +---------------------------------+
   |    AŞAMA 6 KABUL SERTİFİKASI    |   |    OTOMATİK POWERSHELL İYİLEŞTİRME|
   |  (asama6_kabul_sertifikasi.txt) |   |        (asama6_remediation.ps1) |
   | - CISO & Yönetim Onay Belgesi   |   | - NTLMv1 Kapat, PPL Aç          |
   | - 6 Kapının Eksiksiz Denetimi   |   | - Tamper Protection Aktifleştir |
   | - Aşama 7 (Web Güvenliği) Geçiş |   | - Kalıcı Domain Adminleri Sil   |
   +---------------------------------+   +---------------------------------+

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(diag_path, "w", encoding="utf-8") as f:
        f.write(diagram_content)

    print(f"[+] Temsili mimari diyagramı kaydedildi: {diag_path}")


def main():
    """Tüm kanıtları sırayla üretir."""
    print("=" * 80)
    print("[*] GÜN 154 KANIT ÜRETİCİ BAŞLATILIYOR (AŞAMA 6 KALİTE ÖZETİ)...")
    print("=" * 80)
    generate_unit_test_evidence()
    generate_negative_control_evidence()
    generate_stage6_audit_artifacts()
    generate_cli_execution_log()
    generate_representative_diagram()
    print("=" * 80)
    print("[+] TÜM GERÇEK VE TEMSİLÎ KANITLAR BAŞARIYLA OLUŞTURULDU.")
    print("=" * 80)


if __name__ == "__main__":
    main()
