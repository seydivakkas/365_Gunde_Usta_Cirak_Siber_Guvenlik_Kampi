# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux PAM ve Oturum Politikası Kanıt Üretici Betiği (Gün 135).

Bu betik; birim testleri, 9 adet negatif kontrol senaryosunu, CLI analiz,
remediation ve yardım işlemlerini çalıştırarak gerçek ve temsili kanıt dosyalarını üretir.
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
        f.write("=== GÜN 135: LINUX PAM VE OTURUM POLİTİKASI BİRİM TEST SONUÇLARI ===\n")
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
    neg_file = os.path.join(BASE_DIR, "ornek_veri", "invalid_pam_scenarios.json")
    with open(neg_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Denetim motoru doğrudan içe aktarılır
    sys.path.insert(0, os.path.join(BASE_DIR, "uygulama"))
    from linux_pam_security_engine import LinuxPamSecurityEngine

    engine = LinuxPamSecurityEngine()
    results = []
    all_passed = True

    for sc in data.get("scenarios", []):
        sc_id = sc["scenario_id"]
        sc_name = sc["test_name"]
        domain = sc["domain"]
        payload = sc["payload"]
        expected_cwe = sc["expected_cwe"]
        expected_mitre = sc["expected_mitre"]

        report = engine.run_pam_audit(payload)
        detected_cwes = [f["cwe_id"] for f in report["findings_detail"]]
        detected_mitres = [f["mitre_id"] for f in report["findings_detail"]]

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
        f.write("=== GÜN 135: LINUX PAM VE OTURUM NEGATİF KONTROL VE SINIR DURUM SONUÇLARI ===\n")
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
    """CLI aracını çalıştırarak JSON denetim raporu ve Bash iyileştirme betiği üretir."""
    print("[*] CLI komutları yürütülüyor...")
    spec_file = os.path.join(BASE_DIR, "ornek_veri", "pam_inventory_spec.json")
    json_report = os.path.join(GERCEK_DIR, "pam_guvenlik_analiz_raporu.json")
    bash_remed = os.path.join(GERCEK_DIR, "otomatik_sikilastirma.sh")
    komut_file = os.path.join(GERCEK_DIR, "komut_ve_cikis.txt")

    # 1. Audit
    cmd_audit = [
        sys.executable,
        os.path.join("uygulama", "pam_security_cli.py"),
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
        os.path.join("uygulama", "pam_security_cli.py"),
        "remediate",
        "-i",
        spec_file,
        "-o",
        bash_remed,
    ]
    res_remed = subprocess.run(cmd_remed, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # 3. Help
    cmd_help = [
        sys.executable,
        os.path.join("uygulama", "pam_security_cli.py"),
        "pam-help",
    ]
    res_help = subprocess.run(cmd_help, cwd=BASE_DIR, capture_output=True, text=True, encoding="utf-8", errors="replace")

    # Komut ve çıktıları tek dosyada toplanır
    with open(komut_file, "w", encoding="utf-8") as f:
        f.write("=== GÜN 135: CLI ÇALIŞTIRMA VE KANIT KAYITLARI ===\n")
        f.write(f"Tarih / Saat : {datetime.now(timezone.utc).isoformat()}\n\n")

        f.write("[KOMUT 1] " + " ".join(cmd_audit) + "\n")
        f.write(res_audit.stdout + "\n")
        f.write("-" * 75 + "\n\n")

        f.write("[KOMUT 2] " + " ".join(cmd_remed) + "\n")
        f.write(res_remed.stdout + "\n")
        f.write("-" * 75 + "\n\n")

        f.write("[KOMUT 3] " + " ".join(cmd_help) + "\n")
        f.write(res_help.stdout + "\n")
        f.write("-" * 75 + "\n")

    print(f"[+] CLI raporları ve komut çıktıları kaydedildi: {komut_file}")


def generate_architecture_ascii() -> None:
    """Temsili mimari diyagramını standart başlık ile kaydeder."""
    ascii_content = """# TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
# =========================================================================
# Linux PAM (Pluggable Authentication Modules) ve Oturum Politikası Mimarisi
# =========================================================================

+-------------------------------------------------------------------------+
|                  UYGULAMA KATMANI (APPLICATIONS)                        |
|  [login]       [sshd]       [sudo]       [su]       [gdm/gui]           |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                    PAM KÜTÜPHANESİ (libpam.so)                          |
|                                                                         |
|  Yapılandırma Dosyaları: /etc/pam.d/<servis_adi>                         |
|  (Örn: /etc/pam.d/sshd, /etc/pam.d/system-auth, /etc/pam.d/sudo)        |
+------------------------------------+------------------------------------+
                                     |
    +--------------------------------+--------------------------------+
    |                                |                                |
    v                                v                                v
+------------------+       +------------------+       +------------------+
| 1. AUTH          |       | 2. ACCOUNT       |       | 3. PASSWORD      |
| Kimlik Doğrulama |       | Hesap Geçerliliği|       | Şifre Yönetimi   |
+------------------+       +------------------+       +------------------+
| * pam_faillock.so|       | * pam_faillock.so|       | * pam_pwquality  |
|   (deny=5, 900s) |       |   (Kilit kontrol)|       |   (minlen=14,    |
| * pam_unix.so    |       | * pam_time.so    |       |    krediler: -1) |
|   (!nullok)      |       | * pam_access.so  |       | * pam_pwhistory  |
| * pam_2fa/duo.so |       |                  |       |   (remember=5)   |
+------------------+       +------------------+       +------------------+
                                                              |
                                                              v
                                                   +---------------------+
                                                   | 4. SESSION          |
                                                   | Ortam & Limitler    |
                                                   +---------------------+
                                                   | * pam_limits.so     |
                                                   |   (/etc/security/)  |
                                                   | * TMOUT=900 (15 dk) |
                                                   | * pam_mkhomedir.so  |
                                                   +---------------------+

+-------------------------------------------------------------------------+
|              KONTROL BAYRAKLARI VE YÜRÜTME MANTIĞI                      |
|                                                                         |
|  - required  : Başarısız olsa bile zincir sürer; sonuç mutlaka FAIL olur|
|  - requisite : Başarısız olduğu anda zincir derhal kesilir (FAIL)       |
|  - sufficient: Öncekiler başarılıysa ve bu modül OK ise anında PASS    |
|  - optional  : Sadece tek modülse veya ek bilgi amaçlı kullanılır      |
+-------------------------------------------------------------------------+
"""
    out_file = os.path.join(TEMSILI_DIR, "pam_mimarisi.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(ascii_content)
    print(f"[+] Temsili mimari diyagramı kaydedildi: {out_file}")


def main() -> None:
    """Tüm kanıtları sırayla üretir."""
    print("=== GÜN 135 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    run_cli_and_generate_artifacts()
    generate_architecture_ascii()
    print("=== TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
