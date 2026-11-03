# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Windows Hizmet Güvenliği Kanıt Üretici Betiği (Gün 132).

Bu betik, otomatik olarak birim testleri, 9 adet negatif kontrol senaryosunu,
CLI denetim ve iyileştirme komutlarını çalıştırarak 'kanit/gercek/' dizinine
gerçek çalışma çıktılarını ve 'kanit/temsili/' dizinine mimari görselini kaydeder.
"""

# İşletim sistemi ve dosya yolu işlemleri için standart os modülü
import os
# Harici komut ve süreçleri çalıştırmak için standart subprocess modülü
import subprocess
# Sistem arama yolları ve Python yorumlayıcısı için sys modülü
import sys
# JSON ayrıştırma ve biçimlendirme işlemleri için json modülü
import json
# Zaman damgası üretimi için datetime modülü
from datetime import datetime, timezone

# Çalışma dizini tespiti
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GERCEK_DIR = os.path.join(BASE_DIR, "kanit", "gercek")
TEMSILI_DIR = os.path.join(BASE_DIR, "kanit", "temsili")

# Çıktı dizinlerinin varlığı garantiye alınır
os.makedirs(GERCEK_DIR, exist_ok=True)
os.makedirs(TEMSILI_DIR, exist_ok=True)


def run_unit_tests() -> None:
    """Birim testleri çalıştırır ve çıktısını test_sonuclari.txt dosyasına yazar."""
    print("[*] Birim testler çalıştırılıyor...")
    # Testleri unittest ile çalıştıracak komut listesi
    cmd = [sys.executable, "-m", "unittest", "discover", "tests/"]
    # Süreç çalıştırılır ve çıktısı yakalanır
    res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")
    # Dosya yolu belirlenir
    out_file = os.path.join(GERCEK_DIR, "test_sonuclari.txt")
    # Dosyaya yazılır
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== WINDOWS HİZMET GÜVENLİĞİ BİRİM TEST SONUÇLARI (GÜN 132) ===\n")
        f.write(f"Tarih / Saat : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Komut        : {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu   : {res.returncode}\n")
        f.write("-" * 65 + "\n")
        f.write(res.stdout + "\n")
        f.write(res.stderr + "\n")
    print(f"[+] Birim test sonuçları kaydedildi: {out_file}")


def run_negative_controls() -> None:
    """9 adet negatif test senaryosunu çalıştırır ve doğrular."""
    print("[*] Negatif kontrol senaryoları çalıştırılıyor...")
    # Negatif senaryo dosyası yolu
    neg_file = os.path.join(BASE_DIR, "ornek_veri", "invalid_service_scenarios.json")
    with open(neg_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Uygulama motoru doğrudan içe aktarılır
    sys.path.insert(0, os.path.join(BASE_DIR, "uygulama"))
    from windows_service_security_engine import WindowsServiceSecurityEngine, WindowsServiceSpec

    engine = WindowsServiceSecurityEngine()
    results = []
    all_passed = True

    # Her bir negatif senaryo taranır
    for sc in data.get("scenarios", []):
        sc_id = sc["scenario_id"]
        sc_name = sc["test_name"]
        svc_dict = sc["service"]
        expected_cwe = sc["expected_vulnerability"]
        expected_mitre = sc["expected_mitre"]

        spec = WindowsServiceSpec(
            service_name=svc_dict["service_name"],
            display_name=svc_dict.get("display_name", ""),
            image_path=svc_dict.get("image_path", ""),
            start_type=svc_dict.get("start_type", "Automatic"),
            run_as_account=svc_dict.get("run_as_account", "LocalSystem"),
            sddl=svc_dict.get("sddl", ""),
            binary_permissions=svc_dict.get("binary_permissions", {}),
            required_privileges=svc_dict.get("required_privileges", []),
            is_third_party=svc_dict.get("is_third_party", False),
        )

        vulns = engine.evaluate_service(spec)
        detected_cwes = [v.cwe_id for v in vulns]
        detected_mitres = [v.mitre_id for v in vulns]

        cwe_match = expected_cwe in detected_cwes
        mitre_match = expected_mitre in detected_mitres
        is_pass = cwe_match and mitre_match

        if not is_pass:
            all_passed = False

        results.append({
            "scenario_id": sc_id,
            "test_name": sc_name,
            "expected_cwe": expected_cwe,
            "detected_cwes": detected_cwes,
            "expected_mitre": expected_mitre,
            "detected_mitres": detected_mitres,
            "status": "PASS" if is_pass else "FAIL"
        })

    # Dosyaya yazdırılır
    out_file = os.path.join(GERCEK_DIR, "negatif_kontrol_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== WINDOWS HİZMET GÜVENLİĞİ NEGATİF KONTROL VE SINIR DURUM SONUÇLARI ===\n")
        f.write(f"Tarih / Saat       : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Toplam Senaryo     : {len(results)}\n")
        f.write(f"Genel Başarı Durumu: {'BAŞARILI (100% PASS)' if all_passed else 'BAŞARISIZ'}\n")
        f.write("=" * 70 + "\n\n")

        for r in results:
            f.write(f"[{r['status']}] {r['scenario_id']}: {r['test_name']}\n")
            f.write(f"    Beklenen CWE   : {r['expected_cwe']} | Tespit: {r['detected_cwes']}\n")
            f.write(f"    Beklenen MITRE : {r['expected_mitre']} | Tespit: {r['detected_mitres']}\n")
            f.write("-" * 70 + "\n")

    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_file}")


def run_cli_and_generate_reports() -> None:
    """CLI aracını çalıştırarak JSON analiz raporunu ve komut çıktılarını üretir."""
    print("[*] CLI komutları çalıştırılıyor ve analiz raporu üretiliyor...")
    spec_file = os.path.join(BASE_DIR, "ornek_veri", "service_inventory_spec.json")
    report_file = os.path.join(GERCEK_DIR, "servis_guvenlik_analiz_raporu.json")
    script_file = os.path.join(GERCEK_DIR, "otomatik_sikilastirma.ps1")
    komut_file = os.path.join(GERCEK_DIR, "komut_ve_cikis.txt")

    # 1. 'audit' komutu
    cmd_audit = [
        sys.executable,
        os.path.join("uygulama", "service_security_cli.py"),
        "audit",
        "-i",
        spec_file,
        "-o",
        report_file,
    ]
    res_audit = subprocess.run(cmd_audit, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 2. 'remediate' komutu
    cmd_remed = [
        sys.executable,
        os.path.join("uygulama", "service_security_cli.py"),
        "remediate",
        "-i",
        spec_file,
        "-o",
        script_file,
    ]
    res_remed = subprocess.run(cmd_remed, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 3. 'service-help' komutu
    cmd_help = [
        sys.executable,
        os.path.join("uygulama", "service_security_cli.py"),
        "service-help",
    ]
    res_help = subprocess.run(cmd_help, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # Komut ve çıktıları tek dosyada toplanır
    with open(komut_file, "w", encoding="utf-8") as f:
        f.write("=== WINDOWS HİZMET GÜVENLİĞİ CLI ÇALIŞTIRMA VE KANIT KAYITLARI ===\n")
        f.write(f"Tarih / Saat : {datetime.now(timezone.utc).isoformat()}\n\n")

        f.write("[KOMUT 1] " + " ".join(cmd_audit) + "\n")
        f.write(res_audit.stdout + "\n")
        f.write("-" * 65 + "\n\n")

        f.write("[KOMUT 2] " + " ".join(cmd_remed) + "\n")
        f.write(res_remed.stdout + "\n")
        f.write("-" * 65 + "\n\n")

        f.write("[KOMUT 3] " + " ".join(cmd_help) + "\n")
        f.write(res_help.stdout + "\n")
        f.write("-" * 65 + "\n")

    print(f"[+] CLI raporları ve komut çıktıları kaydedildi: {komut_file}")


def generate_architecture_ascii() -> None:
    """Temsili mimari diyagramını standart başlık ile kaydeder."""
    ascii_content = """# TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
# =========================================================================
# Windows Service Control Manager (SCM) ve Hizmet Güvenlik Mimarisi
# =========================================================================

+-------------------------------------------------------------------------+
|                  KULLANICI ALANI (USER MODE)                            |
+-------------------------------------------------------------------------+
|  [Standart Kullanıcı / Saldırgan]        [Yönetici / Güvenlik Uzmanı]   |
|         |                                              |                |
|         v                                              v                |
|  sc.exe / Set-Service                        sc.exe sdset / icacls      |
|         |                                              |                |
+---------+----------------------------------------------+----------------+
          | RPC / LPC                                    |
          v                                              v
+-------------------------------------------------------------------------+
|             SERVICE CONTROL MANAGER (services.exe)                      |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Güvenlik Tanımlayıcısı (Service DACL / SDDL) Kontrolü             |  |
|  | - SERVICE_CHANGE_CONFIG (DC) -> Yetkisiz kullanıcı engellenir!   |  |
|  | - SERVICE_START / STOP (RP/WP)                                    |  |
|  | - WRITE_DAC (WD) / WRITE_OWNER (WO) -> Sadece SYSTEM & Admin      |  |
|  +-------------------------------------------------------------------+  |
|                                 |                                       |
|  +------------------------------v------------------------------------+  |
|  | Servis Başlatma ve Süreç Yürütme Motoru (CreateProcessAsUserW)    |  |
|  +-------------------------------------------------------------------+  |
+---------------------------------+---------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------------+
|        KAYIT DEFTERİ & DOSYA SİSTEMİ GÜVENLİK SINIRLARI                 |
|                                                                         |
|  [HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>]               |
|  - ImagePath : Tırnak Koruması -> "C:\\Program Files\\App\\service.exe" |
|    (Zafiyet: Tırnaksız ise C:\\Program.exe hijacking - CWE-428)         |
|                                                                         |
|  [Dosya Sistemi ACL - icacls]                                           |
|  - service.exe İzinleri: SYSTEM (F), Administrators (F), Users (RX)    |
|    (Zafiyet: Users grubuna Modify/Write verilirse binary değişir)       |
|                                                                         |
|  [Çalışma Kimliği & Ayrıcalık Kapsamı (RunAs / Least Privilege)]        |
|  - LocalService / NetworkService / Virtual Account (NT SERVICE)        |
|  - gMSA (Group Managed Service Account)                                 |
|  - RequiredPrivileges Sıkılaştırma (SeDebug vb. kaldırılması)           |
+-------------------------------------------------------------------------+
"""
    out_file = os.path.join(TEMSILI_DIR, "service_mimarisi.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(ascii_content)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {out_file}")


def main() -> None:
    """Tüm kanıt üretim adımlarını sırayla tetikler."""
    print("=== GÜN 132 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    run_cli_and_generate_reports()
    generate_architecture_ascii()
    print("=== TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
