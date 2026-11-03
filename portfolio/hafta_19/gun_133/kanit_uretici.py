# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Mini Proje 18: Kanıt Üretici Betiği (Gün 133).

Bu betik; birim testleri, 9 adet negatif kontrol senaryosunu, CLI analiz,
remediation ve markdown raporlama işlemlerini çalıştırarak gerçek ve temsili
kanıt dosyalarını üretir.
"""

# Dosya ve dizin yolu manipülasyonu için standart os kütüphanesi
import os
# Süreçleri ve harici Python komutlarını çalıştırmak için subprocess kütüphanesi
import subprocess
# Sistem arama yolları ve yorumlayıcı için sys kütüphanesi
import sys
# JSON verilerini yüklemek ve ayrıştırmak için standart json kütüphanesi
import json
# Zaman damgası oluşturmak için datetime kütüphanesi
from datetime import datetime, timezone

# Temel çalışma yolları belirlenir
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GERCEK_DIR = os.path.join(BASE_DIR, "kanit", "gercek")
TEMSILI_DIR = os.path.join(BASE_DIR, "kanit", "temsili")

# Kanıt dizinleri oluşturulur
os.makedirs(GERCEK_DIR, exist_ok=True)
os.makedirs(TEMSILI_DIR, exist_ok=True)


def run_unit_tests() -> None:
    """Birim testleri yürütür ve çıktısını kanit/gercek/test_sonuclari.txt dosyasına kaydeder."""
    print("[*] Birim testler yürütülüyor...")
    cmd = [sys.executable, "-m", "unittest", "discover", "tests/"]
    res = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    out_file = os.path.join(GERCEK_DIR, "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== MINI PROJE 18: BÜTÜNLEŞİK WINDOWS GÜVENLİK DENETİMİ BİRİM TEST SONUÇLARI ===\n")
        f.write(f"Tarih / Saat : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Komut        : {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu   : {res.returncode}\n")
        f.write("-" * 75 + "\n")
        f.write(res.stdout + "\n")
        f.write(res.stderr + "\n")
    print(f"[+] Birim test sonuçları kaydedildi: {out_file}")


def run_negative_controls() -> None:
    """9 adet negatif kontrol senaryosunu denetler ve sonuçları belgeler."""
    print("[*] Negatif kontrol senaryoları yürütülüyor...")
    neg_file = os.path.join(BASE_DIR, "ornek_veri", "invalid_audit_scenarios.json")
    with open(neg_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Denetim motoru doğrudan içe aktarılır
    sys.path.insert(0, os.path.join(BASE_DIR, "uygulama"))
    from windows_audit_platform_engine import WindowsAuditPlatformEngine

    engine = WindowsAuditPlatformEngine()
    results = []
    all_passed = True

    for sc in data.get("scenarios", []):
        sc_id = sc["scenario_id"]
        sc_name = sc["test_name"]
        domain = sc["domain"]
        payload = sc["payload"]
        expected_cwe = sc["expected_cwe"]
        expected_mitre = sc["expected_mitre"]

        # İlgili alan çağrılır
        findings = []
        if domain == "DEFENDER":
            _, findings = engine.audit_defender_domain(payload)
        elif domain == "UAC":
            _, findings = engine.audit_uac_domain(payload)
        elif domain == "NTFS":
            _, findings = engine.audit_ntfs_domain(payload)
        elif domain == "FIREWALL":
            _, findings = engine.audit_firewall_domain(payload)
        elif domain == "SERVICE":
            _, findings = engine.audit_services_domain(payload)

        detected_cwes = [f.cwe_id for f in findings]
        detected_mitres = [f.mitre_id for f in findings]

        cwe_ok = expected_cwe in detected_cwes
        mitre_ok = expected_mitre in detected_mitres
        is_pass = cwe_ok and mitre_ok

        if not is_pass:
            all_passed = False

        results.append({
            "scenario_id": sc_id,
            "test_name": sc_name,
            "domain": domain,
            "expected_cwe": expected_cwe,
            "detected_cwes": detected_cwes,
            "expected_mitre": expected_mitre,
            "detected_mitres": detected_mitres,
            "status": "PASS" if is_pass else "FAIL",
        })

    out_file = os.path.join(GERCEK_DIR, "negatif_kontrol_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== MINI PROJE 18: NEGATİF KONTROL VE SINIR DURUM TEST SONUÇLARI ===\n")
        f.write(f"Tarih / Saat       : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Toplam Senaryo     : {len(results)}\n")
        f.write(f"Genel Başarı Durumu: {'BAŞARILI (100% PASS)' if all_passed else 'BAŞARISIZ'}\n")
        f.write("=" * 75 + "\n\n")

        for r in results:
            f.write(f"[{r['status']}] {r['scenario_id']} ({r['domain']}): {r['test_name']}\n")
            f.write(f"    Beklenen CWE   : {r['expected_cwe']} | Tespit: {r['detected_cwes']}\n")
            f.write(f"    Beklenen MITRE : {r['expected_mitre']} | Tespit: {r['detected_mitres']}\n")
            f.write("-" * 75 + "\n")

    print(f"[+] Negatif kontrol sonuçları kaydedildi: {out_file}")


def run_cli_and_generate_artifacts() -> None:
    """CLI aracını çalıştırarak JSON, Markdown raporları ve Master PowerShell betiğini üretir."""
    print("[*] CLI komutları yürütülüyor...")
    spec_file = os.path.join(BASE_DIR, "ornek_veri", "enterprise_windows_spec.json")
    json_report = os.path.join(GERCEK_DIR, "windows_denetim_raporu.json")
    ps_master = os.path.join(GERCEK_DIR, "master_remediation.ps1")
    md_report = os.path.join(GERCEK_DIR, "windows_denetim_raporu.md")
    komut_file = os.path.join(GERCEK_DIR, "komut_ve_cikis.txt")

    # 1. Audit
    cmd_audit = [
        sys.executable,
        os.path.join("uygulama", "windows_audit_cli.py"),
        "audit",
        "-i",
        spec_file,
        "-o",
        json_report,
    ]
    res_audit = subprocess.run(cmd_audit, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 2. Remediate
    cmd_remed = [
        sys.executable,
        os.path.join("uygulama", "windows_audit_cli.py"),
        "remediate",
        "-i",
        spec_file,
        "-o",
        ps_master,
    ]
    res_remed = subprocess.run(cmd_remed, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 3. Report (Markdown)
    cmd_rep = [
        sys.executable,
        os.path.join("uygulama", "windows_audit_cli.py"),
        "report",
        "-i",
        spec_file,
        "-o",
        md_report,
    ]
    res_rep = subprocess.run(cmd_rep, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 4. Help
    cmd_help = [
        sys.executable,
        os.path.join("uygulama", "windows_audit_cli.py"),
        "audit-help",
    ]
    res_help = subprocess.run(cmd_help, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # Komut ve çıktıları tek dosyada toplanır
    with open(komut_file, "w", encoding="utf-8") as f:
        f.write("=== MINI PROJE 18: CLI ÇALIŞTIRMA VE KANIT KAYITLARI ===\n")
        f.write(f"Tarih / Saat : {datetime.now(timezone.utc).isoformat()}\n\n")

        f.write("[KOMUT 1] " + " ".join(cmd_audit) + "\n")
        f.write(res_audit.stdout + "\n")
        f.write("-" * 75 + "\n\n")

        f.write("[KOMUT 2] " + " ".join(cmd_remed) + "\n")
        f.write(res_remed.stdout + "\n")
        f.write("-" * 75 + "\n\n")

        f.write("[KOMUT 3] " + " ".join(cmd_rep) + "\n")
        f.write(res_rep.stdout + "\n")
        f.write("-" * 75 + "\n\n")

        f.write("[KOMUT 4] " + " ".join(cmd_help) + "\n")
        f.write(res_help.stdout + "\n")
        f.write("-" * 75 + "\n")

    print(f"[+] CLI raporları ve komut çıktıları kaydedildi: {komut_file}")


def generate_architecture_ascii() -> None:
    """Temsili mimari diyagramını standart başlık ile kaydeder."""
    ascii_content = """# TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
# =========================================================================
# Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Mimarisi
# =========================================================================

+-------------------------------------------------------------------------+
|      BÜTÜNLEŞİK WINDOWS GÜVENLİK DENETİM VE RAPORLAMA PLATFORMU         |
|      (Mini Proje 18 - Hafta 19 Windows Güvenliği Kapanış Projesi)       |
+-------------------------------------------------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
          v                                                   v
+-----------------------+                           +---------------------+
| GİRDİ: SİSTEM METAVERİ |                           | ÇIKTI: RAPORLAR VE  |
| - Registry Değerleri  |                           |        SIKILAŞTIRMA |
| - SCM & Servis DACL   |                           | - JSON Denetim Veri |
| - NTFS Dosya ACL      |                           | - Markdown Rapor    |
| - WFAS Firewall Rule  |                           | - Master PS Betiği  |
+-----------------------+                           +---------------------+
          |                                                   ^
          |                                                   |
          v                                                   |
+-------------------------------------------------------------------------+
|                  5 ALANLI DENETİM VE PUANLAMA MOTORU                    |
|                                                                         |
|  [Alan 1: Defender & Uç Nokta Koruması]             (Ağırlık: 20 Puan) |
|   * RTP, Davranış İzleme, Tamper Protection, PUA                        |
|                                                                         |
|  [Alan 2: Yerel Hesaplar, Gruplar ve UAC]            (Ağırlık: 20 Puan) |
|   * EnableLUA, Admin Onay Modu, Secure Desktop, Guest Hesabı            |
|                                                                         |
|  [Alan 3: NTFS Erişim Kontrol Listeleri]             (Ağırlık: 20 Puan) |
|   * Sistem Dizin Yazma Hakları, Kalıtım Bütünlüğü, SACL Denetimi        |
|                                                                         |
|  [Alan 4: Windows Firewall Profilleri]               (Ağırlık: 20 Puan) |
|   * Domain / Private / Public Profilleri, Default Block, Port Maruziyeti|
|                                                                         |
|  [Alan 5: Windows Hizmet Güvenliği]                  (Ağırlık: 20 Puan) |
|   * Tırnaksız Servis Yolları (CWE-428), Zayıf DACL, Zayıf Binary İzni  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|               KURUMSAL UYUM VE SKOR KARTI BELİRLEME                     |
|                                                                         |
|   Toplam Puan : 100.0 Üzerinden Ağırlıklı Toplam                        |
|   Uyum Durumu : >= 85.0 COMPLIANT | 60 - 84 WARNING | < 60 CRITICAL     |
+-------------------------------------------------------------------------+
"""
    out_file = os.path.join(TEMSILI_DIR, "windows_denetim_mimarisi.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(ascii_content)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {out_file}")


def main() -> None:
    """Tüm kanıtları sırayla üretir."""
    print("=== GÜN 133 MINI PROJE 18 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    run_cli_and_generate_artifacts()
    generate_architecture_ascii()
    print("=== TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
