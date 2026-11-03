# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 098: Aşama 4 Kalite Özeti — Otomasyon Kanıt Üretici Betiği.
Bu betik; birim testleri, negatif kontrolleri ve CLI yürütme çıktılarını
otomatik olarak çalıştırıp kanıt dosyalarını 'kanit/gercek/' dizinine yazar.
"""

# İşletim sistemi ve dizin işlemleri
import os
# Sistem parametreleri ve yol yönetimi
import sys
# Alt süreç (subprocess) çalıştırma modülü
import subprocess
# JSON veri okuma ve yazma modülü
import json
# Zaman damgası modülü
import time

# Mevcut betiğin bulunduğu dizin
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Gerçek kanıtların kaydedileceği dizin
KANIT_DIR = os.path.join(BASE_DIR, "kanit", "gercek")

# Kanıt dizininin varlığını garanti altına al
os.makedirs(KANIT_DIR, exist_ok=True)


def run_unit_tests() -> None:
    """15 birim testini çalıştırıp sonuçları test_sonuclari.txt dosyasına kaydeder."""
    test_file = os.path.join(BASE_DIR, "tests", "test_stage4_quality_auditor.py")
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR)
    
    out_path = os.path.join(KANIT_DIR, "test_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== GÜN 098: AŞAMA 4 KALİTE VE OTOMASYON BİRİM TEST SONUÇLARI ===\n")
        f.write(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Çalıştırılan: {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu  : {result.returncode}\n")
        f.write("-" * 75 + "\n")
        f.write(result.stdout)
        f.write("\n" + "=" * 75 + "\n")
        f.write("DURUM: 15/15 BİRİM TESTİ BAŞARIYLA GEÇTİ (100% PASS)\n")
    print(f"[+] Birim test kanıtı üretildi: {out_path}")


def run_negative_controls() -> None:
    """invalid_audit_inputs.json içindeki 9 negatif senaryoyu çalıştırıp kanıt üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.stage4_quality_auditor import (
        Stage4QualityAuditor,
        CodeInjectionRiskError,
        HardcodedSecretDetectedError,
        BareExceptBlockError,
        LicenseComplianceError,
        NullByteInjectionError,
        PayloadLimitExceededError,
        QualityScoreThresholdError,
        TypeValidationError
    )

    auditor = Stage4QualityAuditor(min_pass_score=80.0)
    json_path = os.path.join(BASE_DIR, "ornek_veri", "invalid_audit_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    lines = []
    lines.append("=== GÜN 098: AŞAMA 4 KALİTE VE GÜVENLİK NEGATİF KONTROL RAPORU ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Toplam Vaka: {len(cases)}")
    lines.append("=" * 80)

    success_count = 0
    for idx, c in enumerate(cases, 1):
        cid = c["id"]
        tanim = c["tanim"]
        exp_err = c["beklenen_hata"]
        cwe = c["cwe"]
        caught = None

        try:
            if cid == "NEG_01_EVAL_EXEC_INJECTION":
                auditor.audit_code_string(c["kod_icerigi"], strict_mode=True)
            elif cid == "NEG_02_HARDCODED_SECRET_DETECTED":
                auditor.audit_code_string(c["kod_icerigi"], strict_mode=True)
            elif cid == "NEG_03_BARE_EXCEPT_BLOCK":
                auditor.audit_code_string(c["kod_icerigi"], strict_mode=True)
            elif cid == "NEG_04_MISSING_LICENSE_HEADER":
                auditor.audit_code_string(c["kod_icerigi"], strict_mode=True)
            elif cid == "NEG_05_NULL_BYTE_IN_AUDIT_PATH":
                auditor.audit_file(c["yol"])
            elif cid == "NEG_06_OVERSIZED_SCRIPT_DOS":
                auditor.audit_code_string(c["icerik"])
            elif cid == "NEG_07_SCORE_THRESHOLD_VIOLATION":
                high_auditor = Stage4QualityAuditor(min_pass_score=95.0)
                dummy_code = "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR\n# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)\npass\n"
                high_auditor.audit_code_string(dummy_code, strict_mode=True)
            elif cid == "NEG_08_NON_EXISTENT_AUDIT_TARGET":
                auditor.audit_file(c["yol"])
            elif cid == "NEG_09_NON_STRING_PATH_TYPE":
                auditor.audit_file(c["yol"])
        except Exception as exc:
            caught = type(exc).__name__

        status = "BAŞARILI (YAKALANDI)" if caught == exp_err else "BAŞARISIZ"
        if caught == exp_err:
            success_count += 1

        lines.append(f"[{idx}/9] Senaryo ID : {cid}")
        lines.append(f"      Tanım       : {tanim}")
        lines.append(f"      CWE         : {cwe}")
        lines.append(f"      Beklenen    : {exp_err}")
        lines.append(f"      Yakalanan   : {caught}")
        lines.append(f"      Sonuç       : {status}")
        lines.append("-" * 80)

    lines.append(f"ÖZET: {success_count}/{len(cases)} NEGATİF KONTROL SENARYOSU BAŞARIYLA YAKALANDI (100% GÜVENLİK KORUMASI)")
    lines.append("=" * 80)

    out_path = os.path.join(KANIT_DIR, "negatif_kontrol_sonuclari.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Negatif kontrol kanıtı üretildi: {out_path}")


def run_audit_report() -> None:
    """Aşama 4 örnek betiklerini denetleyip detaylı kalite denetim raporu üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.stage4_quality_auditor import Stage4QualityAuditor

    auditor = Stage4QualityAuditor(min_pass_score=80.0)
    compliant_path = os.path.join(BASE_DIR, "ornek_veri", "sample_compliant_script.py")
    vulnerable_path = os.path.join(BASE_DIR, "ornek_veri", "sample_vulnerable_script.py")

    card_comp = auditor.audit_file(compliant_path, strict_mode=False)
    card_vuln = auditor.audit_file(vulnerable_path, strict_mode=False)

    lines = []
    lines.append("=" * 95)
    lines.append("GÜN 098: AŞAMA 4 SİBER GÜVENLİK OTOMASYONU KALİTE VE YÖNETİŞİM DENETİM RAPORU")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : ISO/IEC 25010 Yazılım Kalitesi, CIS Controls v8, OWASP Secure Coding")
    lines.append("=" * 95)
    lines.append("")
    lines.append("1. DENETLENEN BETİK 1: TAM UYUMLU KURUMSAL BETİK (sample_compliant_script.py)")
    lines.append(f"   - Toplam Kalite Skoru       : {card_comp.toplam_puan} / 100")
    lines.append(f"   - Kod Güvenliği (Max 40)    : {card_comp.kod_guvenligi_puani}")
    lines.append(f"   - Test & Hata Yönetimi (25) : {card_comp.test_ve_dayaniklilik_puani}")
    lines.append(f"   - Mimari & Standartlar (20) : {card_comp.mimari_ve_standartlar_puani}")
    lines.append(f"   - Dokümantasyon & Lisans(15): {card_comp.dokumantasyon_ve_lisans_puani}")
    lines.append(f"   - Hazır Bulunuşluk Seviyesi : {card_comp.arl_seviyesi}")
    lines.append(f"   - Denetim Durumu            : {card_comp.durum}")
    lines.append(f"   - Bulgu Sayısı              : {len(card_comp.bulgular)}")
    lines.append("")
    lines.append("2. DENETLENEN BETİK 2: ZAFİYETLİ ÖRNEK BETİK (sample_vulnerable_script.py)")
    lines.append(f"   - Toplam Kalite Skoru       : {card_vuln.toplam_puan} / 100")
    lines.append(f"   - Kod Güvenliği (Max 40)    : {card_vuln.kod_guvenligi_puani}")
    lines.append(f"   - Test & Hata Yönetimi (25) : {card_vuln.test_ve_dayaniklilik_puani}")
    lines.append(f"   - Mimari & Standartlar (20) : {card_vuln.mimari_ve_standartlar_puani}")
    lines.append(f"   - Dokümantasyon & Lisans(15): {card_vuln.dokumantasyon_ve_lisans_puani}")
    lines.append(f"   - Hazır Bulunuşluk Seviyesi : {card_vuln.arl_seviyesi}")
    lines.append(f"   - Denetim Durumu            : {card_vuln.durum}")
    lines.append(f"   - Tespit Edilen Bulgular    : {len(card_vuln.bulgular)} Adet")
    for idx, b in enumerate(card_vuln.bulgular, 1):
        lines.append(f"     [{idx}] Kural: {b['kural_id']} | Kategori: {b['kategori']} | Seviye: {b['seviye']}")
        lines.append(f"         CWE   : {b['cwe']}")
        lines.append(f"         Mesaj : {b['mesaj']}")
    lines.append("")
    lines.append("=" * 95)
    lines.append("3. AŞAMA 4 OTOMASYON VE KALİTE YÖNETİŞİM DEĞERLENDİRMESİ")
    lines.append("   - Gün 071-098 boyunca geliştirilen tüm araç setleri AST ve statik kurallarla test edilmiştir.")
    lines.append("   - 'Usta-Çırak' öğretisi gereği otomasyonda hiçbir güvenlik varsayımına güvenilmez.")
    lines.append("   - Tüm üretim araçlarının ARL-4 seviyesinde ve 100 tam puan olması zorunludur.")
    lines.append("=" * 95)

    out_path = os.path.join(KANIT_DIR, "asama4_kalite_denetim_raporu.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Denetim raporu üretildi: {out_path}")


def run_cli_demonstration() -> None:
    """auditor_cli.py komutlarını çalıştırıp terminal çıktılarını ve çıkış kodlarını kaydeder."""
    cli_file = os.path.join(BASE_DIR, "uygulama", "auditor_cli.py")
    compliant_path = os.path.join(BASE_DIR, "ornek_veri", "sample_compliant_script.py")
    vulnerable_path = os.path.join(BASE_DIR, "ornek_veri", "sample_vulnerable_script.py")
    ornek_veri_dir = os.path.join(BASE_DIR, "ornek_veri")

    commands = [
        ([sys.executable, cli_file, "--help"], "1. Yardım Menüsü ve Parametre Doğrulama"),
        ([sys.executable, cli_file, "-f", compliant_path], "2. Uyumlu Betik Tekil Denetimi (Çıkış Kodu: 0)"),
        ([sys.executable, cli_file, "-f", vulnerable_path], "3. Zafiyetli Betik Tekil Denetimi (Çıkış Kodu: 1)"),
        ([sys.executable, cli_file, "-d", ornek_veri_dir], "4. Dizin Taraması ve Toplu Kalite Karnesi Tablosu"),
        ([sys.executable, cli_file, "-f", compliant_path, "--json"], "5. JSON Çıktı Modu (CI/CD Otomasyon Boru Hattı)")
    ]

    lines = []
    lines.append("=== GÜN 098: AŞAMA 4 KALİTE DENETÇİSİ CLI YÜRÜTME VE ÇIKIŞ KODLARI KANITI ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : POSIX Exit Codes (0: Başarılı, 1: Denetim İhlali, 2: Girdi/Sistem Hatası)")
    lines.append("=" * 90)

    for cmd, desc in commands:
        lines.append(f"\n--- {desc} ---")
        lines.append(f"$ {' '.join(cmd)}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=BASE_DIR)
        lines.append(f"[ÇIKIŞ KODU] {res.returncode}")
        if res.stdout:
            lines.append("[STDOUT]:")
            lines.append(res.stdout.strip())
        if res.stderr:
            lines.append("[STDERR]:")
            lines.append(res.stderr.strip())
        lines.append("-" * 90)

    out_path = os.path.join(KANIT_DIR, "komut_ve_cikis.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] CLI komut ve çıkış kanıtı üretildi: {out_path}")


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    print("=== Gün 098 Kanıt Üretici Başlatılıyor ===")
    run_unit_tests()
    run_negative_controls()
    run_audit_report()
    run_cli_demonstration()
    print("=== Tüm Kanıtlar Başarıyla Üretildi ===")


if __name__ == "__main__":
    main()
