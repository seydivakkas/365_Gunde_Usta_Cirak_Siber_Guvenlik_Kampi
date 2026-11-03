# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 127 KANIT ÜRETİCİ (Uç Nokta Tehdit Modeli Kanıt Üreticisi)
--------------------------------------------------------------
Bu betik; Gün 127 kapsamındaki uç nokta tehdit modelleme birim testlerini,
9 negatif sınır senaryosunu, CLI etkileşimlerini ve mimari şemaları
çalıştırarak kanıt dosyalarını üretir.
"""

# İşletim sistemi ve dizin işlemleri için os modülü
import os
# Sistem parametreleri ve arama yolu için sys modülü
import sys
# JSON verilerini okumak ve yazmak için json modülü
import json
# Zaman damgaları için datetime modülü
from datetime import datetime
# Testleri otomasyon ile çalıştırmak için unittest modülü
import unittest
# Test çıktılarını bellekte yakalamak için io modülü
import io

# Betiğin bulunduğu dizini alıyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Modül arama yoluna dahil ediyoruz
if CURRENT_DIR not in sys.path:
    # Arama yolunun başına ekliyoruz
    sys.path.insert(0, CURRENT_DIR)

# Uygulama dizinini de modül arama yoluna ekliyoruz
APP_DIR = os.path.join(CURRENT_DIR, "uygulama")
# Eğer yolda yoksa ekliyoruz
if APP_DIR not in sys.path:
    # Uygulama klasörünü ekliyoruz
    sys.path.insert(0, APP_DIR)

# Çekirdek motor sınıflarını içe aktarıyoruz
from endpoint_threat_model_engine import (
    EndpointThreatModelEngine,
    OperatingSystemFamily,
    EndpointRole,
    EndpointControlStatus
)


def run_unit_tests(output_path: str) -> bool:
    """15 Birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    # Test yükleyicisini kuruyoruz
    loader = unittest.TestLoader()
    # tests klasöründeki testleri keşfediyoruz
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    # Çıktıyı yakalamak için metin tamponu oluşturuyoruz
    stream = io.StringIO()
    # Ayrıntılı koşucuyu yapılandırıyoruz
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Test paketini yürütüyoruz
    result = runner.run(suite)
    # Koşu çıktısını metin olarak alıyoruz
    output_text = stream.getvalue()

    # Rapor metnini biçimlendiriyoruz
    report = (
        "======================================================================\n"
        "GÜN 127: UÇ NOKTA TEHDİT MODELİ - BİRİM TEST RAPORU\n"
        f"Tarih/Saat: {datetime.now().isoformat()}\n"
        "Standartlar: MITRE ATT&CK for Enterprise, CIS Benchmarks, Microsoft Security Baselines\n"
        "======================================================================\n\n"
        f"Çalıştırılan Test Sayısı: {result.testsRun}\n"
        f"Hata Sayısı (Errors): {len(result.errors)}\n"
        f"Başarısızlık Sayısı (Failures): {len(result.failures)}\n"
        f"Genel Durum: {'BAŞARILI (100% PASS)' if result.wasSuccessful() else 'BAŞARISIZ'}\n\n"
        "------------------- AYRINTILI TEST ÇIKTISI -------------------\n"
        f"{output_text}\n"
    )

    # Kanıt dosyasına UTF-8 olarak yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write(report)

    # Başarı durumunu döndürüyoruz
    return result.wasSuccessful()


def run_negative_controls(output_path: str) -> int:
    """9 Negatif kontrol senaryosunu çalıştırır ve kanıt kaydeder."""
    # Senaryo dosyasının yolunu belirliyoruz
    scenarios_file = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_endpoint_scenarios.json")
    # Dosyayı okuyoruz
    with open(scenarios_file, "r", encoding="utf-8") as f:
        # JSON verisini yüklüyoruz
        scenarios_data = json.load(f)

    # Senaryolar listesini alıyoruz
    scenarios = scenarios_data.get("senaryolar", [])
    # Kanıt tamponunu oluşturuyoruz
    lines = [
        "======================================================================",
        "GÜN 127: UÇ NOKTA TEHDİT MODELİ NEGATİF KONTROL TESTLERİ",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        f"Toplam Senaryo: {len(scenarios)}",
        "======================================================================\n"
    ]

    # Başarılı senaryo sayacı
    passed_count = 0
    # Motoru başlatıyoruz
    engine = EndpointThreatModelEngine("Negatif Test Motoru")

    # Her senaryoyu sırayla inceliyoruz
    for sc in scenarios:
        # Senaryo kimliği
        sid = sc.get("id")
        # Senaryo başlığı
        title = sc.get("baslik")
        # Beklenen CWE kodu
        expected_cwe = sc.get("beklenen_cwe")
        # Beklenen MITRE kodu
        expected_mitre = sc.get("beklenen_mitre")
        # İşletim sistemi
        os_fam = OperatingSystemFamily[sc.get("os", "WINDOWS")]
        # Uç nokta rolü
        ep_role = EndpointRole[sc.get("role", "WORKSTATION")]
        # Kontroller sözlüğü
        k = sc.get("kontroller", {})

        # Kontrol nesnesini kuruyoruz
        controls = EndpointControlStatus(
            edr_active=bool(k.get("edr_active", True)),
            tamper_protection_active=bool(k.get("tamper_protection_active", True)),
            telemetry_active=bool(k.get("telemetry_active", True)),
            credential_guard_active=bool(k.get("credential_guard_active", True)),
            disk_encryption_active=bool(k.get("disk_encryption_active", True)),
            strict_uac_active=bool(k.get("strict_uac_active", True)),
            app_whitelisting_active=bool(k.get("app_whitelisting_active", True)),
            powershell_clm_active=bool(k.get("powershell_clm_active", True)),
            unquoted_service_paths_count=int(k.get("unquoted_service_paths_count", 0)),
            suid_misconfigurations_count=int(k.get("suid_misconfigurations_count", 0)),
            insecure_open_ports=list(k.get("insecure_open_ports", [])),
            weak_registry_autoruns_count=int(k.get("weak_registry_autoruns_count", 0))
        )

        # Analizi yürütüyoruz
        report = engine.model_endpoint_threats(title, os_fam, ep_role, controls)

        # Beklenen CWE ve MITRE kodunu arıyoruz
        found_cwe = any(f.cwe_id == expected_cwe for f in report.findings)
        found_mitre = any(expected_mitre in f.mitre_technique_id for f in report.findings)

        # Her iki kod da tespit edilmişse başarılı sayıyoruz
        if found_cwe and found_mitre:
            # Sayacı artırıyoruz
            passed_count += 1
            # Bulgu nesnesini alıyoruz
            matching_f = next(f for f in report.findings if f.cwe_id == expected_cwe and expected_mitre in f.mitre_technique_id)
            # Başarılı satırı ekliyoruz
            lines.append(f"[{sid}] {title} ({expected_cwe} / {expected_mitre}) -> PASS")
            # Ayrıntıyı ekliyoruz
            lines.append(f"   Ayrıntı: Tespit Edildi: [{matching_f.severity.value}] {matching_f.title} (Tehdit Skoru: {report.threat_index_score}/100)\n")
        else:
            # Başarısız satırı ekliyoruz
            lines.append(f"[{sid}] {title} ({expected_cwe} / {expected_mitre}) -> FAIL")
            # Hata ayrıntısını ekliyoruz
            lines.append(f"   Hata: Beklenen kodlar tespit edilemedi! Mevcut CWE'ler: {[f.cwe_id for f in report.findings]}\n")

    # Genel özet bilgilerini ekliyoruz
    lines.append("----------------------------------------------------------------------")
    lines.append(f"TOPLAM: {len(scenarios)} | BAŞARILI: {passed_count} | BAŞARISIZ: {len(scenarios) - passed_count}")
    lines.append(f"SONUÇ: {'100% PASS' if passed_count == len(scenarios) else 'BAŞARISIZLIK MEVCUT'}")
    lines.append("======================================================================")

    # Kanıt dosyasına kaydediyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni yazıyoruz
        f.write("\n".join(lines))

    # Başarılı sayısını döndürüyoruz
    return passed_count


def generate_architecture_diagram(output_path: str):
    """ASCII formatında temsili uç nokta tehdit mimarisi şemasını üretir (Zorunlu banner ile)."""
    # Diyagram metnini hazırlıyoruz
    diagram = (
        "======================================================================\n"
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "======================================================================\n"
        "GÜN 127: UÇ NOKTA TEHDİT MODELİ VE SALDIRI YÜZEYİ MİMARİSİ\n"
        "Standartlar: MITRE ATT&CK for Enterprise, CIS Benchmarks, Microsoft Security Baselines\n"
        "----------------------------------------------------------------------\n\n"
        "   +-----------------------------------------------------------------+\n"
        "   |                     UÇ NOKTA SALDIRGAN GİRDİSİ                  |\n"
        "   |      [Phishing]      [Malicious USB]      [Network Exploit]     |\n"
        "   +-----------------------------------------------------------------+\n"
        "                                    |\n"
        "                                    v\n"
        "   +-----------------------------------------------------------------+\n"
        "   |                 UÇ NOKTA SALDIRI YÜZEYLERİ (SURFACES)           |\n"
        "   +-----------------------------------------------------------------+\n"
        "        |                    |                    |                |\n"
        "        | 1. Kimlik Belleği  | 2. Süreç/Servis    | 3. Kalıcılık   | 4. Ağ/Port\n"
        "        v                    v                    v                v\n"
        "   +------------+       +------------+       +------------+   +------------+\n"
        "   | LSASS / SAM|       | Unquoted   |       | Registry   |   | SMBv1, RDP |\n"
        "   | Memory Dump|       | Path, SUID |       | Run, Task  |   | Açık Port  |\n"
        "   | (T1003.001)|       | (T1574.009)|       | (T1547.001)|   | (T1021)    |\n"
        "   +------------+       +------------+       +------------+   +------------+\n"
        "        |                    |                    |                |\n"
        "        +--------------------+--------------------+----------------+\n"
        "                                    |\n"
        "                                    v\n"
        "   +-----------------------------------------------------------------+\n"
        "   |             UÇ NOKTA KORUMA VE TESPİT KATMANI (EDR / PPL)       |\n"
        "   |   - Credential Guard (RunAsPPL)  - Tamper Protection            |\n"
        "   |   - AppLocker / WDAC             - Sysmon / Auditd Telemetrisi  |\n"
        "   |   - BitLocker / LUKS Şifreleme   - PowerShell CLM (Constrained) |\n"
        "   +-----------------------------------------------------------------+\n"
        "                                    |\n"
        "                                    v\n"
        "   +-----------------------------------------------------------------+\n"
        "   |                TEHDİT ENDEKSİ VE HARDENING PLANI                |\n"
        "   |   - Tehdit Skoru (0-100)        - CIS Benchmark Eylem Planı     |\n"
        "   |   - Duruş Seviyesi (PASS/HOLD)  - Öncelikli Sıkılaştırma        |\n"
        "   +-----------------------------------------------------------------+\n"
    )

    # Dosyaya yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write(diagram)


def generate_analysis_report(output_path: str):
    """Kapsamlı uç nokta tehdit modelleme raporunu JSON olarak üretir."""
    # Şartname dosyasını okuyoruz
    spec_path = os.path.join(CURRENT_DIR, "ornek_veri", "endpoint_baseline_spec.json")
    # Dosyayı açıyoruz
    with open(spec_path, "r", encoding="utf-8") as f:
        # Veriyi yüklüyoruz
        data = json.load(f)

    # Kontrol nesnesini kuruyoruz
    k = data.get("kontroller", {})
    controls = EndpointControlStatus(
        edr_active=k.get("edr_active", True),
        tamper_protection_active=k.get("tamper_protection_active", True),
        telemetry_active=k.get("telemetry_active", True),
        credential_guard_active=k.get("credential_guard_active", True),
        disk_encryption_active=k.get("disk_encryption_active", True),
        strict_uac_active=k.get("strict_uac_active", True),
        app_whitelisting_active=k.get("app_whitelisting_active", True),
        powershell_clm_active=k.get("powershell_clm_active", True),
        unquoted_service_paths_count=k.get("unquoted_service_paths_count", 0),
        suid_misconfigurations_count=k.get("suid_misconfigurations_count", 0),
        insecure_open_ports=k.get("insecure_open_ports", []),
        weak_registry_autoruns_count=k.get("weak_registry_autoruns_count", 0)
    )

    # Motoru başlatıyoruz
    engine = EndpointThreatModelEngine("Raporlama Motoru")
    # Analizi yürütüyoruz
    rep = engine.model_endpoint_threats(
        endpoint_name=data.get("endpoint_name", "Test-PC"),
        os_family=OperatingSystemFamily[data.get("os_family", "WINDOWS")],
        role=EndpointRole[data.get("role", "WORKSTATION")],
        controls=controls
    )

    # JSON rapor içeriğini biçimlendiriyoruz
    report_dict = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Görüntüleme ve eğitim amaçlıdır.",
        "rapor_tarihi": datetime.now().isoformat(),
        "report_id": rep.report_id,
        "endpoint_name": rep.endpoint_name,
        "os_family": rep.os_family.value,
        "role": rep.role.value,
        "threat_index_score": rep.threat_index_score,
        "security_posture_level": rep.security_posture_level,
        "threats_count": len(rep.findings),
        "threats": [
            {
                "id": f.finding_id,
                "title": f.title,
                "surface_area": f.surface_area.value,
                "severity": f.severity.value,
                "cwe": f.cwe_id,
                "mitre": f.mitre_technique_id,
                "description": f.description,
                "remediation": f.remediation
            }
            for f in rep.findings
        ],
        "hardening_roadmap": rep.hardening_roadmap,
        "standart_referanslari": [
            "MITRE ATT&CK for Enterprise Matrix v14",
            "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
            "CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0",
            "Microsoft Security Baselines for Windows 11 and Windows Server"
        ]
    }

    # Dosyaya JSON olarak yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Girintili ve UTF-8 formatında kaydediyoruz
        json.dump(report_dict, f, ensure_ascii=False, indent=2)


def run_cli_commands(output_path: str):
    """CLI komutlarını çalıştırır ve çıktısını komut_ve_cikis.txt dosyasına kaydeder."""
    # CLI betiğini içe aktarıyoruz
    from endpoint_threat_cli import main as cli_main

    # Şartname dosyasının yolunu alıyoruz
    spec_file = os.path.join(CURRENT_DIR, "ornek_veri", "endpoint_baseline_spec.json")

    # Çıktı tamponunu hazırlıyoruz
    cli_outputs = [
        "======================================================================",
        "GÜN 127: CLI ETKİLEŞİM VE YÖNETİM KOMUTLARI KANITI",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        "======================================================================\n"
    ]

    # Komut senaryoları
    commands = [
        ("Hızlı Uç Nokta Denetimi (Güvenli PC)", ["quick-check", "--name", "Quick-Safe-PC", "--os", "WINDOWS", "--role", "WORKSTATION", "--edr", "--tamper-protection", "--credential-guard", "--disk-encryption"]),
        ("Hızlı Uç Nokta Denetimi (Savunmasız Sunucu)", ["quick-check", "--name", "Vulnerable-DC", "--os", "WINDOWS", "--role", "DOMAIN_CONTROLLER", "--unquoted-paths", "2"]),
        ("Tam Şartname Modellemesi ve Markdown Rapor", ["model", spec_file, "--format", "markdown"])
    ]

    # Her komutu çalıştırıp çıktıyı yakalıyoruz
    for desc, args in commands:
        # Başlık ekliyoruz
        cli_outputs.append(f"--- KOMUT: python endpoint_threat_cli.py {' '.join(args)} ({desc}) ---")
        # Tamponları oluşturuyoruz
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        # Akışları saklıyoruz
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        # Yeni tamponlara yönlendiriyoruz
        sys.stdout = stdout_buf
        sys.stderr = stderr_buf
        try:
            # CLI komutunu çalıştırıyoruz
            cli_main(args)
        except SystemExit:
            # sys.exit yakalanır
            pass
        finally:
            # Eski akışları geri yüklüyoruz
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        # Çıktıyı alıyoruz
        cmd_out = stdout_buf.getvalue() + stderr_buf.getvalue()
        # Çıktı satırlarına ekliyoruz
        cli_outputs.append(cmd_out)
        # Ayraç ekliyoruz
        cli_outputs.append("----------------------------------------------------------------------\n")

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write("\n".join(cli_outputs))


def main():
    """Ana kanıt üretici akışı."""
    # Gerçek ve temsili kanıt klasörleri
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    temsili_dir = os.path.join(CURRENT_DIR, "kanit", "temsili")

    # Klasörlerin varlığını garanti ediyoruz
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim testleri çalıştırıyoruz
    unit_ok = run_unit_tests(os.path.join(gercek_dir, "test_sonuclari.txt"))
    print(f"[+] Birim Testler Tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontrol senaryolarını yürütüyoruz
    neg_passed = run_negative_controls(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"))
    print(f"[+] Negatif Kontrol Senaryoları Tamamlandı: {neg_passed}/9 Senaryo Başarılı")

    # 3. Temsili mimari diyagramını oluşturuyoruz
    generate_architecture_diagram(os.path.join(temsili_dir, "uc_nokta_tehdit_mimarisi.txt"))
    print("[+] Temsili Mimari Diyagramı Oluşturuldu.")

    # 4. Kapsamlı analiz raporunu oluşturuyoruz
    generate_analysis_report(os.path.join(gercek_dir, "uc_nokta_tehdit_analiz_raporu.json"))
    print("[+] Uç Nokta Tehdit Analiz Raporu Oluşturuldu.")

    # 5. CLI etkileşimlerini kaydediyoruz
    run_cli_commands(os.path.join(gercek_dir, "komut_ve_cikis.txt"))
    print("[+] CLI Çıktıları Kaydedildi.")

    # Bitiş bildirimi
    print("[***] GÜN 127 TÜM KANIT DOSYALARI BAŞARIYLA ÜRETİLDİ! [***]")


# Betik doğrudan çalıştırıldığında main çağrılır
if __name__ == "__main__":
    main()
