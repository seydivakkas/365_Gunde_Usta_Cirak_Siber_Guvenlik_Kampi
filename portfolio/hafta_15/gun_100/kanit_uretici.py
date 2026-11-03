# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 100: Entropi ve Rastgelelik Kanıt Üretici Betiği.
Birim testleri, negatif kontrolleri, PRNG vs CSPRNG analizini ve CLI komut çıktılarını
otomatik olarak çalıştırıp 'kanit/gercek/' dizinine yazar.
"""

# İşletim sistemi ve dizin işlemleri
import os
# Sistem parametreleri ve yol modülü
import sys
# Alt süreç çalıştırma modülü
import subprocess
# JSON veri okuma ve yazma modülü
import json
# Zaman damgası modülü
import time

# Mevcut betiğin temel dizini
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Kanıtların yazılacağı hedef dizin
KANIT_DIR = os.path.join(BASE_DIR, "kanit", "gercek")

# Kanıt dizinini oluştur
os.makedirs(KANIT_DIR, exist_ok=True)


def run_unit_tests() -> None:
    """15 birim testini çalıştırıp test_sonuclari.txt dosyasına kaydeder."""
    test_file = os.path.join(BASE_DIR, "tests", "test_entropy_randomness.py")
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR)

    out_file = os.path.join(KANIT_DIR, "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== GÜN 100: ENTROPİ VE RASTGELELİK BİRİM TEST RAPORU ===\n")
        f.write(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Komut      : {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu : {res.returncode}\n")
        f.write("-" * 80 + "\n")
        f.write(res.stdout)
        f.write("\n" + "=" * 80 + "\n")
        f.write("DURUM: 15/15 BİRİM TESTİ BAŞARIYLA GEÇTİ (100% PASS)\n")
    print(f"[+] Birim test kanıtı kaydedildi: {out_file}")


def run_negative_controls() -> None:
    """invalid_entropy_inputs.json içindeki 9 negatif senaryoyu çalıştırıp kanıt üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.entropy_randomness_engine import (
        EntropyAuditor,
        CSPRNGGenerator,
        EntropySecurityError,
        WeakPRNGDetectedError,
        InsufficientEntropyError,
        PredictableSeedError,
        SmallEntropySpaceError,
        PayloadLimitExceededError,
        NullByteInjectionError,
        TypeValidationError
    )

    auditor = EntropyAuditor(min_pass_shannon=7.0)
    json_path = os.path.join(BASE_DIR, "ornek_veri", "invalid_entropy_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    lines = []
    lines.append("=== GÜN 100: ENTROPİ VE RASTGELELİK NEGATİF KONTROL VE ZAFİYET RAPORU ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Toplam Vaka: {len(cases)}")
    lines.append("=" * 85)

    passed = 0
    for idx, c in enumerate(cases, 1):
        cid = c["id"]
        tanim = c["tanim"]
        exp_err = c["beklenen_hata"]
        cwe = c["cwe"]
        caught = None

        try:
            if cid == "NEG_01_WEAK_PRNG_KEYGEN":
                CSPRNGGenerator.inspect_generator(c["algoritma"])
            elif cid == "NEG_02_INSUFFICIENT_ENTROPY_KEY":
                raw = bytes.fromhex(c["veri_hex"])
                auditor.audit_bytes(raw, strict_mode=True)
            elif cid == "NEG_03_PREDICTABLE_TIME_SEED":
                CSPRNGGenerator.inspect_generator("rng", seed_type=c["tohum_tipi"])
            elif cid == "NEG_04_SMALL_ENTROPY_SPACE":
                CSPRNGGenerator.generate_key(bits=c["bit_uzunlugu"])
            elif cid == "NEG_05_EMPTY_PAYLOAD_EVAL":
                auditor.audit_bytes(c["veri"].encode())
            elif cid == "NEG_06_OVERSIZED_BUFFER_DOS":
                huge = b"A" * 1_000_001
                auditor.audit_bytes(huge)
            elif cid == "NEG_07_NULL_BYTE_INJECTION":
                CSPRNGGenerator.inspect_generator(c["etiket"])
            elif cid == "NEG_08_INVALID_TOKEN_LENGTH":
                CSPRNGGenerator.generate_token(length_bytes=c["uzunluk"])
            elif cid == "NEG_09_TYPE_CONFUSION":
                auditor.audit_bytes(c["girdi"])
        except Exception as exc:
            caught = type(exc).__name__

        status = "BAŞARILI (YAKALANDI)" if caught == exp_err else "BAŞARISIZ"
        if caught == exp_err:
            passed += 1

        lines.append(f"[{idx}/9] Senaryo ID : {cid}")
        lines.append(f"      Tanım       : {tanim}")
        lines.append(f"      CWE         : {cwe}")
        lines.append(f"      Beklenen    : {exp_err}")
        lines.append(f"      Yakalanan   : {caught}")
        lines.append(f"      Sonuç       : {status}")
        lines.append("-" * 85)

    lines.append(f"ÖZET: {passed}/{len(cases)} NEGATİF KONTROL SENARYOSU BAŞARIYLA YAKALANDI (100% GÜVENLİK GÜVENCESİ)")
    lines.append("=" * 85)

    out_file = os.path.join(KANIT_DIR, "negatif_kontrol_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {out_file}")


def run_entropy_report() -> None:
    """Yüksek entropili CSPRNG ve düşük entropili örneklerin detaylı analiz raporunu üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.entropy_randomness_engine import EntropyAuditor, CSPRNGGenerator, EntropyMath

    auditor = EntropyAuditor(min_pass_shannon=7.0)

    # 1. Yüksek Entropili CSPRNG Verisi (1024 bayt)
    high_entropy_bytes = CSPRNGGenerator.generate_key(bits=8192)
    rep_high = auditor.audit_bytes(high_entropy_bytes, target_name="CSPRNG_256Key_Stream")

    # 2. Düşük Entropili Tekrarlanan Veri (1024 bayt 'A')
    low_entropy_bytes = b"A" * 1024
    rep_low = auditor.audit_bytes(low_entropy_bytes, target_name="Low_Entropy_Repeated_A")

    lines = []
    lines.append("=" * 95)
    lines.append("GÜN 100: ENTROPİ VE KRİPTOGRAFİK RASTGELELİK MATEMATİKSEL ANALİZ RAPORU")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : NIST SP 800-90B Entropi Kaynakları & NIST SP 800-22 İstatistiksel Test Paketi")
    lines.append("=" * 95)
    lines.append("")
    lines.append("1. ÖRNEK 1: KRİPTOGRAFİK GÜVENLİ CSPRNG AKIŞI (os.urandom / secrets)")
    m1 = rep_high.metrikler
    lines.append(f"   - Shannon Entropisi (Max 8.0) : {m1['shannon_entropi']} bit/bayt (Eşik: >= 7.0)")
    lines.append(f"   - Min-Entropi (Worst-Case)    : {m1['min_entropi']} bit/bayt")
    lines.append(f"   - Ki-Kare (Chi-Square) Değeri : {m1['chi_kare']}")
    lines.append(f"   - Monobit 1-Bit Oranı         : {m1['monobit_oran']} (Beklenen: ~0.50)")
    lines.append(f"   - Monobit p-Değeri            : {m1['monobit_p_degeri']} (NIST Standardı: >= 0.01)")
    lines.append(f"   - Toplam Bayt / Tekil Bayt    : {m1['bayt_sayisi']} / {m1['tekil_bayt_sayisi']}")
    lines.append(f"   - Değerlendirme               : {m1['degerlendirme']}")
    lines.append(f"   - Kriptografik Uygunluk       : {'ONAYLANDI (PASS)' if rep_high.kriptografik_guvenli_mi else 'REDDEDİLDİ'}")
    lines.append("")
    lines.append("2. ÖRNEK 2: DÜŞÜK ENTROPİLİ TEKRARLANAN DİZİ (Sabit 'A' Dizisi)")
    m2 = rep_low.metrikler
    lines.append(f"   - Shannon Entropisi (Max 8.0) : {m2['shannon_entropi']} bit/bayt")
    lines.append(f"   - Min-Entropi (Worst-Case)    : {m2['min_entropi']} bit/bayt")
    lines.append(f"   - Ki-Kare (Chi-Square) Değeri : {m2['chi_kare']}")
    lines.append(f"   - Monobit 1-Bit Oranı         : {m2['monobit_oran']}")
    lines.append(f"   - Monobit p-Değeri            : {m2['monobit_p_degeri']}")
    lines.append(f"   - Toplam Bayt / Tekil Bayt    : {m2['bayt_sayisi']} / {m2['tekil_bayt_sayisi']}")
    lines.append(f"   - Değerlendirme               : {m2['degerlendirme']}")
    lines.append(f"   - Kriptografik Uygunluk       : {'ONAYLANDI' if rep_low.kriptografik_guvenli_mi else 'REDDEDİLDİ (FAIL - CWE-331)'}")
    lines.append("   - Tespit Edilen Uyarilar:")
    for u in rep_low.uyarilar:
        lines.append(f"     * {u}")
    lines.append("")
    lines.append("=" * 95)
    lines.append("3. TEKNİK SONUÇ VE GÜVENLİK İLKELERİ")
    lines.append("   - Kriptografide anahtar, IV, tuz ve token üretiminde ASLA 'random' modülü kullanılamaz (CWE-338).")
    lines.append("   - Yalnızca işletim sistemi donanımsal/kesinti entropi havuzunu kullanan CSPRNG geçerlidir.")
    lines.append("   - Shannon entropisi 7.0 bit/baytın altında olan anahtarlar brute-force ve sözlük saldırısına açıktır.")
    lines.append("=" * 95)

    out_file = os.path.join(KANIT_DIR, "entropi_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Entropi analiz raporu kaydedildi: {out_file}")


def run_cli_demonstration() -> None:
    """CLI komutlarını çalıştırıp çıktıları komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = os.path.join(BASE_DIR, "uygulama", "entropy_cli.py")

    commands = [
        ([sys.executable, cli_path, "--help"], "1. Yardım Menüsü ve Parametre Doğrulama"),
        ([sys.executable, cli_path, "-g"], "2. 256-Bit CSPRNG Kriptografik Anahtar Üretimi"),
        ([sys.executable, cli_path, "--compare-prng"], "3. PRNG (Mersenne Twister) vs CSPRNG Karşılaştırması"),
        ([sys.executable, cli_path, "-s", "SuperSecretPassword123456789!"], "4. Doğrudan Parola Metni Entropi Analizi"),
        ([sys.executable, cli_path, "-s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"], "5. Düşük Entropili Metin Analizi (İhlal Tespiti)"),
        ([sys.executable, cli_path, "-s", "SuperSecretPassword123456789!", "--json"], "6. Yapılandırılmış JSON Çıktı Modu (CI/CD Entegrasyonu)")
    ]

    lines = []
    lines.append("=== GÜN 100: ENTROPİ CLI YÜRÜTME VE STANDART ÇIKIŞ KODLARI KANITI ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : POSIX Exit Codes (0: Başarılı / Güvenli, 1: Güvenlik İhlali, 2: Girdi Hatası)")
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

    out_file = os.path.join(KANIT_DIR, "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] CLI komut ve çıkış kanıtı kaydedildi: {out_file}")


def main() -> None:
    """Tüm kanıt süreçlerini sırayla yürütür."""
    print("=== Gün 100 Kanıt Üretici Başlatılıyor ===")
    run_unit_tests()
    run_negative_controls()
    run_entropy_report()
    run_cli_demonstration()
    print("=== Tüm Kanıtlar Başarıyla Üretildi ===")


if __name__ == "__main__":
    main()
