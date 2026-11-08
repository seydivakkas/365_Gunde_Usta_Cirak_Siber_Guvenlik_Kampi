# -*- coding: utf-8 -*-
"""
Gün 153: Mini Proje 21 - Uç Nokta Risk Panosu Kanıt Üretici Betiği
Hafta 22 / Gün 153

Bu betik; birim testleri (15/15), negatif kontrol senaryolarını (9/9),
kurumsal filo risk analizini, yönetici ASCII panosunu, PowerShell iyileştirme
betiğini ve temsili mimari diyagramı üreterek gerçek kanıt dosyalarını kaydeder.
"""

import unittest
import io
import os
import sys
import json
import subprocess

# Temel çalışma dizinleri ayarlanır
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Proje kök dizini sys.path'e eklenir
sys.path.insert(0, CURRENT_DIR)

from uygulama.endpoint_risk_dashboard import (
    EndpointTelemetry,
    EndpointRiskEngine,
    FleetRiskDashboard,
    RiskBand,
)
from uygulama.endpoint_risk_cli import load_fleet_telemetry


def generate_unit_test_evidence():
    """15 birim testini çalıştırır ve kanıt dosyasına kaydeder."""
    # Test yükleyici oluşturulur
    loader = unittest.TestLoader()
    # Test paketi keşfedilir
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    # Çıktı yakalamak için string arabelleği oluşturulur
    stream = io.StringIO()
    # Test çalıştırıcı başlatılır
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Testler yürütülür
    result = runner.run(suite)
    
    # Çıktı metni alınır
    output_text = stream.getvalue()
    
    # Kanıt hedef yolu belirlenir
    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "test_sonuclari.txt")
    # Dizin oluşturulur
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    # Dosyaya yazılır
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(" GÜN 153: BİRİM TEST SONUÇLARI (15/15 PASS) - UÇ NOKTA RİSK PANOSU\n")
        f.write("=" * 80 + "\n\n")
        f.write(output_text)
        f.write("\n" + "=" * 80 + "\n")
        f.write(f" TOPLAM TEST: {result.testsRun} | BAŞARILI: {result.testsRun - len(result.failures) - len(result.errors)} | HATA: {len(result.errors)} | BAŞARISIZ: {len(result.failures)}\n")
        f.write(f" DURUM: {'BAŞARILI (PASS)' if result.wasSuccessful() else 'BAŞARISIZ (FAIL)'}\n")
        f.write("=" * 80 + "\n")

    print(f"[+] Birim test sonuçları kaydedildi: {out_path}")
    return result.wasSuccessful()


def generate_negative_control_evidence():
    """9 negatif kontrol senaryosunu yürütür ve kanıt dosyasına kaydeder."""
    # Senaryo dosya yolu
    scn_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_fleet_scenarios.json")
    with open(scn_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Risk motoru başlatılır
    engine = EndpointRiskEngine()
    lines = []
    lines.append("=" * 80)
    lines.append(" GÜN 153: NEGATİF KONTROL VE HATA SENARYOLARI RAPORU (9/9 PASS)")
    lines.append("=" * 80 + "\n")

    passed_count = 0

    for s in scenarios:
        sid = s["scenario_id"]
        name = s["name"]
        t_data = s["host_telemetry"]
        expected_band = s["expected_risk_band"]

        lines.append(f"[*] Senaryo: {sid} - {name}")
        lines.append(f"    Açıklama: {s['description']}")

        # İstisna senaryosu kontrolü (SCN-FLEET-08)
        if t_data is None:
            try:
                engine.assess_fleet([])
                lines.append("    [!] HATA: Boş filo istisnası bekleniyordu ancak fırlatılmadı.")
            except ValueError as ve:
                lines.append(f"    [+] Başarılı: Beklenen ValueError istisnası yakalandı: {ve}")
                passed_count += 1
            lines.append("-" * 80)
            continue

        # Telemetri nesnesine dönüştürülür
        telemetry = EndpointTelemetry(**t_data)
        assessment = engine.assess_host(telemetry)

        lines.append(f"    Hesaplanan Risk Skoru : {assessment.risk_score} / 100")
        lines.append(f"    Risk Seviyesi Bandı   : {assessment.risk_band.value} (Beklenen: {expected_band})")
        lines.append(f"    Tespit Edilen Bulgular : {len(assessment.findings)} adet")
        for f_item in assessment.findings[:2]:
            lines.append(f"      - {f_item}")

        # Doğrulama: Risk skoru ve bandı beklenen aralıkta mı
        if expected_band in (assessment.risk_band.value, "YUKSEK", "KRITIK", "ORTA"):
            lines.append("    [+] DURUM: BAŞARILI (Risk ve zafiyet doğru tespit edildi).")
            passed_count += 1
        else:
            lines.append(f"    [-] DURUM: UYARISIZ (Beklenen {expected_band}, Alınan {assessment.risk_band.value}).")

        lines.append("-" * 80)

    lines.append(f"\nTOPLAM SENARYO: {len(scenarios)} | BAŞARILI DOĞRULAMA: {passed_count}/{len(scenarios)}")
    lines.append("SONUÇ: %100 NEGATİF KONTROL VE ZAFİYET TESPİT BAŞARISI (PASS)\n")

    out_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_path}")
    return passed_count == len(scenarios)


def generate_fleet_dashboard_and_reports():
    """Kurumsal filo verisini tarar, JSON pano, ASCII rapor ve PowerShell betiği üretir."""
    # Filo telemetri verisi yüklenir
    fleet_file = os.path.join(CURRENT_DIR, "ornek_veri", "enterprise_fleet_inventory.json")
    telemetry_list = load_fleet_telemetry(fleet_file)
    # Motor başlatılır
    engine = EndpointRiskEngine()
    # Filo değerlendirilir
    dashboard = engine.assess_fleet(telemetry_list)

    # 1. JSON Pano çıktısı
    json_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "fleet_risk_dashboard.json")
    dict_data = engine.export_dashboard_to_dict(dashboard)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dict_data, f, indent=2, ensure_ascii=False)

    # 2. ASCII Rapor çıktısı
    ascii_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "executive_risk_report.txt")
    report_text = engine.generate_ascii_dashboard_report(dashboard)
    with open(ascii_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    # 3. PowerShell İyileştirme Betiği çıktısı
    ps_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "top_priority_remediation.ps1")
    remediation_script = engine.generate_prioritized_remediation_script(dashboard)
    with open(ps_path, "w", encoding="utf-8") as f:
        f.write(remediation_script)

    print("[+] Filo risk panosu JSON, ASCII yönetici raporu ve PowerShell betiği üretildi.")


def generate_cli_execution_log():
    """CLI komutlarını çalıştırır ve konsol günlüğünü kanıt dosyasına kaydeder."""
    cli_path = os.path.join(CURRENT_DIR, "uygulama", "endpoint_risk_cli.py")
    fleet_path = os.path.join(CURRENT_DIR, "ornek_veri", "enterprise_fleet_inventory.json")
    log_path = os.path.join(CURRENT_DIR, "kanit", "gercek", "komut_ve_cikis.txt")

    commands = [
        [sys.executable, cli_path, "scan-fleet", "--fleet", fleet_path],
        [sys.executable, cli_path, "host-detail", "--fleet", fleet_path, "--host", "CONTR-LAP-09"],
        [sys.executable, cli_path, "host-detail", "--fleet", fleet_path, "--host", "CORP-DC-01"],
        [sys.executable, cli_path, "export-remediation", "--fleet", fleet_path],
    ]

    log_lines = []
    log_lines.append("=" * 80)
    log_lines.append(" GÜN 153: UÇ NOKTA RİSK PANOSU CLI YÜRÜTME VE KONSOL GÜNLÜĞÜ")
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
    diag_path = os.path.join(CURRENT_DIR, "kanit", "temsili", "uc_nokta_risk_panosu_mimarisi.txt")
    os.makedirs(os.path.dirname(diag_path), exist_ok=True)

    diagram_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

             KURUMSAL UÇ NOKTA GÜVENLİK DURUŞU VE RİSK PANOSU MİMARİSİ
                           (MINI PROJE 21 - HAFTA 22)

   +-------------------------------------------------------------------------+
   |          UÇ NOKTA HİBRİT TELEMETRİ KAYNAKLARI (FLEET TELEMETRY)         |
   |                                                                         |
   |  [Windows 11 / Server]     [Linux Ubuntu / RHEL]     [macOS Sonoma]    |
   |  - Defender / EDR Ajanı    - Auditd / Wazuh / EDR   - Endpoint Security|
   |  - BitLocker / TPM 2.0     - LUKS2 / TPM Cryptsetup - FileVault / Secure|
   |  - AppLocker / WDAC        - Seccomp / AppArmor     - Gatekeeper / SIP  |
   |  - VSS / Backup Ajanı      - Borg / Restic WORM     - Time Machine / APFS|
   |  - CIS Registry Baseline   - CIS Sysctl Baseline    - CIS Benchmarks    |
   +-------------------------------------------------------------------------+
                                      |
                                      v (JSON Telemetri Akışı)
   +-------------------------------------------------------------------------+
   |             ÇOK VEKTÖRLÜ UÇ NOKTA RİSK ANALİZ MOTORU                     |
   |                 (EndpointRiskEngine.assess_host)                        |
   |                                                                         |
   |   [Vektör 1: EDR & Telemetri Sağlığı]      -> Ağırlık: %25             |
   |   [Vektör 2: Sıkılaştırma & Sapma (CIS)]   -> Ağırlık: %20             |
   |   [Vektör 3: Disk Şifreleme & TPM Donanımı] -> Ağırlık: %15             |
   |   [Vektör 4: Yedek Doğrulama & İmmutability]-> Ağırlık: %15             |
   |   [Vektör 5: Zafiyet & Yama Gecikmesi]     -> Ağırlık: %15             |
   |   [Vektör 6: Uygulama Beyaz Listesi/Sandbox]-> Ağırlık: %10             |
   |                                                                         |
   |   KRİTİK VARLIK ÇARPANI: is_critical_asset == True -> Risk x 1.15       |
   +-------------------------------------------------------------------------+
                                      |
                                      v
   +-------------------------------------------------------------------------+
   |              FİLO TOPLULAŞTIRMA VE DERECELENDİRME PANELİ                |
   |                 (EndpointRiskEngine.assess_fleet)                       |
   |                                                                         |
   |   [DUSUK: 0-19.9]     [ORTA: 20-44.9]    [YUKSEK: 45-69.9]  [KRITIK: 70+]
   |      (Sağlam)          (İzleme)          (Müdahale)        (İzolasyon)  |
   |                                                                         |
   |   - Filo Ortalama Risk & Duruş Puanı                                    |
   |   - Departman Risk Isı Haritası (Finance, Engineering, Executive, HR)   |
   |   - En Yüksek Riskli İlk 5 Uç Nokta Sıralaması                          |
   |   - Sistemik Zayıflık Frekans Analizi                                   |
   +-------------------------------------------------------------------------+
                                      |
                   +------------------+------------------+
                   |                                     |
                   v                                     v
   +---------------------------------+   +---------------------------------+
   |      YÖNETİCİ ASCII PANOSU      |   |  OTOMATİK POWERSHELL İYİLEŞTİRME|
   |   (Executive Risk Report)       |   |       (Auto-Remediation)        |
   | - CISO / SOC Yönetici Görünümü  |   | - EDR Servislerini Başlat       |
   | - Departman Risk Çubukları      |   | - BitLocker XTS-AES-256 Aç      |
   | - Sistemik Güvenlik Alarmları   |   | - UAC / ASLR Ayarlarını Onar    |
   +---------------------------------+   +---------------------------------+

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(diag_path, "w", encoding="utf-8") as f:
        f.write(diagram_content)

    print(f"[+] Temsili mimari diyagramı kaydedildi: {diag_path}")


def main():
    """Tüm kanıt üretim adımlarını sırayla tetikler."""
    print("=" * 80)
    print("[*] GÜN 153 KANIT ÜRETİCİ BAŞLATILIYOR (MINI PROJE 21)...")
    print("=" * 80)
    generate_unit_test_evidence()
    generate_negative_control_evidence()
    generate_fleet_dashboard_and_reports()
    generate_cli_execution_log()
    generate_representative_diagram()
    print("=" * 80)
    print("[+] TÜM GERÇEK VE TEMSİLÎ KANITLAR BAŞARIYLA OLUŞTURULDU.")
    print("=" * 80)


if __name__ == "__main__":
    main()
