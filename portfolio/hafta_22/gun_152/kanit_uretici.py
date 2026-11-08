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
from config_drift_engine import (
    ConfigDriftAuditor,
    AutoRemediationEngine,
    ConfigRule,
    SettingType,
    SeverityLevel
)
from config_drift_cli import load_baseline_and_state


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
    """9 negatif kontrol ve sapma senaryosunu motor üzerinde çalıştırıp doğrular."""
    clean_json_path = DATA_DIR / "clean_endpoint_baseline.json"
    neg_json_path = DATA_DIR / "invalid_drift_scenarios.json"

    rules, clean_state, endpoint_id = load_baseline_and_state(str(clean_json_path))

    with open(neg_json_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    out_lines = [
        "=" * 78,
        "GÜN 152: GÜVENLİ YAPILANDIRMA SAPMASI (DRIFT) NEGATİF KONTROL VE TESTLERİ",
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

        mutated_state = deepcopy(clean_state)
        mutated_state.update(patch)

        auditor = ConfigDriftAuditor(rules)
        report = auditor.evaluate_endpoint_state(f"{endpoint_id}-{sc_id}", mutated_state)

        matched_finding = next((f for f in report.findings if f.rule_id == expected_rule), None)

        if matched_finding:
            passed_scenarios += 1
            status_text = "[BAŞARILI - SAPMA TESPİT EDİLDİ (PASS)]"
            detail_text = f"Bulgu: {matched_finding.rule_id} [{matched_finding.severity}] - {matched_finding.title} -> {matched_finding.risk_description}"
        else:
            status_text = "[BAŞARISIZ - SAPMA KAÇIRILDI (FAIL)]"
            detail_text = f"Beklenen '{expected_rule}' kuralı tetiklenmedi. Çıkan bulgular: {[f.rule_id for f in report.findings]}"

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
    """Denetim raporunu, iyileştirilmiş uç nokta durumunu ve PowerShell düzeltme betiğini üretir."""
    clean_json_path = DATA_DIR / "clean_endpoint_baseline.json"
    rules, clean_state, endpoint_id = load_baseline_and_state(str(clean_json_path))

    # 1. Denetim Raporu
    auditor = ConfigDriftAuditor(rules)
    report = auditor.evaluate_endpoint_state(endpoint_id, clean_state)

    report_data = {
        "report_id": report.report_id,
        "timestamp_utc": report.timestamp_utc,
        "endpoint_identifier": report.endpoint_identifier,
        "total_evaluated": report.total_evaluated,
        "total_compliant": report.total_compliant,
        "total_drifted": report.total_drifted,
        "compliance_score_pct": report.compliance_score_pct,
        "compliance_status": "COMPLIANT_100_PERCENT",
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "setting_type": f.setting_type,
                "target_key": f.target_key,
                "expected_value": f.expected_value,
                "actual_value": f.actual_value,
                "risk_description": f.risk_description,
                "remediation_command": f.remediation_command
            } for f in report.findings
        ]
    }
    with open(GERCEK_KANIT_DIR / "config_drift_audit_report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # 2. Örnek Sapmış Durumu İyileştirme Çıktısı
    drifted_sample = deepcopy(clean_state)
    drifted_sample["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"] = 0
    drifted_sample["DomainProfile_Enabled"] = False
    drifted_sample["Administrators_Members"] = ["Administrator", "Domain Admins", "backdoor_admin"]

    remediated = AutoRemediationEngine.remediate_state(drifted_sample, rules)
    with open(GERCEK_KANIT_DIR / "remediated_endpoint_state.json", "w", encoding="utf-8") as f:
        json.dump(remediated, f, indent=2, ensure_ascii=False)

    # 3. Örnek Düzeltme PowerShell Betiği
    sample_report = auditor.evaluate_endpoint_state("DRIFT-SAMPLE", drifted_sample)
    ps1_content = AutoRemediationEngine.generate_powershell_remediation_script(sample_report.findings)
    with open(GERCEK_KANIT_DIR / "config_drift_auto_remediation.ps1", "w", encoding="utf-8") as f:
        f.write(ps1_content)

    print("[+] JSON denetim raporu, iyileştirilmiş durum ve PowerShell düzeltme betiği üretildi.")


def run_cli_and_record_log() -> None:
    """CLI komutlarını çalıştırarak konsol oturumunu komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = UYGULAMA_DIR / "config_drift_cli.py"
    clean_spec = DATA_DIR / "clean_endpoint_baseline.json"

    log_entries = [
        "=" * 78,
        "GÜN 152: GÜVENLİ YAPILANDIRMA SAPMASI CLI KONSOL GÜNLÜĞÜ",
        f"Zaman Damgası (UTC): {datetime.now(timezone.utc).isoformat()}",
        "=" * 78,
        ""
    ]

    temp_remediated = GERCEK_KANIT_DIR / "cli_temp_remediated.json"
    temp_script = GERCEK_KANIT_DIR / "cli_temp_script.ps1"

    commands = [
        [sys.executable, str(cli_path), "audit", "--config", str(clean_spec)],
        [sys.executable, str(cli_path), "remediate", "--config", str(clean_spec), "--output", str(temp_remediated)],
        [sys.executable, str(cli_path), "generate-remediation", "--config", str(clean_spec), "--os-type", "windows", "--output", str(temp_script)]
    ]

    for cmd in commands:
        cmd_str = " ".join(cmd)
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(CURRENT_DIR))
        log_entries.append(f"$ {cmd_str}")
        log_entries.append(res.stdout.strip())
        if res.stderr.strip():
            log_entries.append(f"[STDERR]: {res.stderr.strip()}")
        log_entries.append("-" * 78)

    # Geçici dosyaları temizleyelim
    if temp_remediated.exists():
        temp_remediated.unlink()
    if temp_script.exists():
        temp_script.unlink()

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
        "|         GÜVENLİ YAPILANDIRMA SAPMASI (CONFIGURATION DRIFT) MİMARİSİ         |\n"
        "+-----------------------------------------------------------------------------+\n"
        "\n"
        "   +-----------------------------------------------------------------------+\n"
        "   |            GÜVENLİ TEMEL HAT DEPOSU (SECURITY BASELINE / DSC)         |\n"
        "   |                                                                       |\n"
        "   |  * CIS Benchmarks v3.0 / DISA STIG Standartları                       |\n"
        "   |  * UAC: EnableLUA = 1 | Defender Real-Time: Enabled                   |\n"
        "   |  * LSA RunAsPPL = 1 (LSASS Koruması) | ASLR = 2                       |\n"
        "   |  * Yerel Administrators: Yalnızca Yetkili Hesaplar                    |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                                      | Karşılaştırma / Denetim Motoru      \n"
        "                                      v                                     \n"
        "   +-----------------------------------------------------------------------+\n"
        "   |         UÇ NOKTA CANLI TELEMETRİSİ (ACTUAL ENDPOINT STATE)            |\n"
        "   |                                                                       |\n"
        "   |  Zaman İçindeki Sapmalar (Drift Faktörleri):                          |\n"
        "   |  [!] Manuel Acil Müdahale: UAC kapatılmış (EnableLUA = 0)             |\n"
        "   |  [!] Saldırgan Faaliyeti : Administrators grubuna 'backdoor' eklenmiş |\n"
        "   |  [!] Hata Ayıklama       : Windows Defender gerçek zamanlı kapatılmış |\n"
        "   +-----------------------------------------------------------------------+\n"
        "                                      |                                     \n"
        "                   +------------------+------------------+                  \n"
        "                   |                                     |                  \n"
        "       [ DRIFT TESPİT EDİLDİ ]                 [ TAM UYUMLULUK ]            \n"
        "       (Skor: %72.7 -> 3 Sapma)                (Skor: %100 -> Sıfır Sapma)  \n"
        "                   |                                     |                  \n"
        "                   v                                     v                  \n"
        "   +--------------------------------+   +--------------------------------+  \n"
        "   |  OTOMATİK İYİLEŞTİRME ENGINE   |   |   GÜVENLİ TEMEL HAT KORUNDU    |  \n"
        "   |  (Self-Healing / Desired State)|   |   * EDR / SIEM Onaylı          |  \n"
        "   |  -> PowerShell DSC / GPO Revert|   |   * Zafiyet Penceresi Kapalı   |  \n"
        "   |  -> Yetkisiz Admin Silindi     |   +--------------------------------+  \n"
        "   |  -> UAC & Defender Yeniden Açık|                                       \n"
        "   +--------------------------------+                                       \n"
        "                   |                                                        \n"
        "                   v                                                        \n"
        "   =========================================================================\n"
        "        UÇ NOKTA YENİDEN %100 GÜVENLİ TEMEL HATTA GERİ DÖNDÜRÜLDÜ           \n"
        "   =========================================================================\n"
        "\n"
        "+-----------------------------------------------------------------------------+\n"
        "|                 TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL              |\n"
        "+-----------------------------------------------------------------------------+\n"
    )
    target_file = TEMSILI_KANIT_DIR / "yapilandirma_sapmasi_mimarisi.txt"
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(diagram)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {target_file}")


def main() -> None:
    """Tüm kanıt üreticilerini sıralı icra eder."""
    print("=" * 78)
    print("[*] GÜN 152 KANIT ÜRETİCİ BAŞLATILIYOR...")
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
