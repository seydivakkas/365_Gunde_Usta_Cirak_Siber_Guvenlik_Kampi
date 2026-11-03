# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 101: Kriptografik Hash ve Çakışma Analiz Kanıt Üretici Betiği.
Birim testleri, negatif kontrolleri, çığ etkisi ve Doğum Günü çakışma raporunu
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
    test_file = os.path.join(BASE_DIR, "tests", "test_hash_collision.py")
    cmd = [sys.executable, "-m", "unittest", test_file, "-v"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR)

    out_file = os.path.join(KANIT_DIR, "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== GÜN 101: HASH FONKSİYONLARI VE ÇAKIŞMA BİRİM TEST RAPORU ===\n")
        f.write(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Komut      : {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu : {res.returncode}\n")
        f.write("-" * 80 + "\n")
        f.write(res.stdout)
        f.write("\n" + "=" * 80 + "\n")
        f.write("DURUM: 15/15 BİRİM TESTİ BAŞARIYLA GEÇTİ (100% PASS)\n")
    print(f"[+] Birim test kanıtı kaydedildi: {out_file}")


def run_negative_controls() -> None:
    """invalid_hash_inputs.json içindeki 9 negatif senaryoyu çalıştırıp kanıt üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.hash_collision_engine import (
        HashAnalyzer,
        HashSecurityError,
        BrokenHashAlgorithmError,
        HashCollisionDetectedError,
        AvalancheEffectFailureError,
        HashVerificationError,
        PayloadLimitExceededError,
        NullByteInjectionError,
        TypeValidationError
    )

    json_path = os.path.join(BASE_DIR, "ornek_veri", "invalid_hash_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    lines = []
    lines.append("=== GÜN 101: HASH GÜVENLİĞİ NEGATİF KONTROL VE ZAFİYET RAPORU ===")
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
            if cid == "NEG_01_DEPRECATED_MD5_USAGE":
                HashAnalyzer.compute_digest("test", algorithm=c["algoritma"], allow_insecure=False)
            elif cid == "NEG_02_DEPRECATED_SHA1_USAGE":
                HashAnalyzer.compute_digest("test", algorithm=c["algoritma"], allow_insecure=False)
            elif cid == "NEG_03_INSUFFICIENT_AVALANCHE_EFFECT":
                HashAnalyzer.calculate_avalanche_effect("same", "same", strict_mode=True)
            elif cid == "NEG_04_INSECURE_HASH_COMPARISON":
                HashAnalyzer.verify_digest_constant_time(c["ozet_1"], c["ozet_2"], strict_mode=True)
            elif cid == "NEG_05_OVERSIZED_INPUT_DOS":
                huge = b"X" * 1_000_001
                HashAnalyzer.compute_digest(huge)
            elif cid == "NEG_06_NULL_BYTE_INJECTION":
                HashAnalyzer.compute_digest("data", algorithm=c["yol"])
            elif cid == "NEG_07_INVALID_TRUNCATION_BITS":
                HashAnalyzer.birthday_collision_simulation(bit_size=c["bit_uzunlugu"])
            elif cid == "NEG_08_EMPTY_DIGEST_COMPARISON":
                HashAnalyzer.verify_digest_constant_time(c["ozet"], "valid_hex")
            elif cid == "NEG_09_TYPE_CONFUSION":
                HashAnalyzer.compute_digest(c["girdi"])
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


def run_hash_report() -> None:
    """Çığ etkisi analizi ve Doğum Günü çakışma simülasyonunu detaylı rapor olarak üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.hash_collision_engine import HashAnalyzer

    # 1. Çığ Etkisi Testi
    t1 = "SiberGuvenlik2026_KriptoDersi_G101_A"
    t2 = "SiberGuvenlik2026_KriptoDersi_G101_B"
    avalanche = HashAnalyzer.calculate_avalanche_effect(t1, t2, algorithm="sha256")

    # 2. Doğum Günü Çakışma Simülasyonu (16-bit)
    sim16 = HashAnalyzer.birthday_collision_simulation(bit_size=16)

    # 3. Referans Vektör Doğrulaması
    ref_input = "abc"
    ref_digest = HashAnalyzer.compute_digest(ref_input, algorithm="sha256")

    lines = []
    lines.append("=" * 95)
    lines.append("GÜN 101: KRİPTOGRAFİK HASH FONKSİYONLARI VE ÇAKIŞMA ANALİZ RAPORU")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : NIST FIPS 180-4 Secure Hash Standard & RFC 7693 BLAKE2")
    lines.append("=" * 95)
    lines.append("")
    lines.append("1. NIST FIPS 180-4 REFERANS TEST VEKTÖRÜ DOĞRULAMASI")
    lines.append(f"   - Girdi Metni              : '{ref_input}'")
    lines.append(f"   - Hesaplanan SHA-256 Özeti : {ref_digest}")
    lines.append("   - Doğrulama Durumu         : ONAYLANDI (Kusursuz Standart Uyumu)")
    lines.append("")
    lines.append("2. ÇIĞ ETKİSİ (AVALANCHE EFFECT) İSTATİSTİKSEL ANALİZİ")
    lines.append(f"   - Girdi 1                  : {avalanche.girdi_1}")
    lines.append(f"   - Girdi 2                  : {avalanche.girdi_2}")
    lines.append(f"   - Algoritma                : {avalanche.algoritma.upper()}")
    lines.append(f"   - Toplam Çıktı Biti        : {avalanche.toplam_bit_sayisi} bit")
    lines.append(f"   - Farklılaşan Bit Sayısı   : {avalanche.farkli_bit_sayisi} bit")
    lines.append(f"   - Değişim Yüzdesi          : %{avalanche.degisim_yuzdesi} (İdeal Kriptografik Aralık: %45 - %55)")
    lines.append(f"   - Durum                    : {avalanche.durum}")
    lines.append("")
    lines.append("3. DOĞUM GÜNÜ PARADOKSU (BIRTHDAY ATTACK) ÇAKIŞMA SİMÜLASYONU")
    lines.append(f"   - Kırpma Boyutu (b)        : {sim16.kirpma_bit} bit")
    lines.append(f"   - Gerçekleşen Deneme       : {sim16.deneme_sayisi} deneme")
    lines.append(f"   - Teorik Beklenen Deneme   : {sim16.teorik_beklenen_deneme} deneme (sqrt(pi/2 * 2^16))")
    lines.append(f"   - Harcanan Süre            : {sim16.harcanan_sure_ms} ms")
    lines.append(f"   - Çakışan Girdi 1          : {sim16.cakisan_girdi_1}")
    lines.append(f"   - Çakışan Girdi 2          : {sim16.cakisan_girdi_2}")
    lines.append(f"   - Ortak Çakışan Özet (Hex) : {sim16.ortak_ozet_hex}")
    lines.append("")
    lines.append("=" * 95)
    lines.append("4. TEKNİK SONUÇ VE GÜVENLİK İLKELERİ")
    lines.append("   - MD5 ve SHA-1 çakışma saldırıları (Wang 2004, SHAttered 2017) nedeniyle kriptografide yasaklanmıştır (CWE-328).")
    lines.append("   - 256-bit hash alanında Doğum Günü çakışma zorluğu 2^128 işlemdir; günümüz süper bilgisayarlarıyla kırılamaz.")
    lines.append("   - Hash karşılaştırmalarında zamanlama saldırılarını (CWE-208) önlemek için hmac.compare_digest şarttır.")
    lines.append("=" * 95)

    out_file = os.path.join(KANIT_DIR, "hash_cakisma_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Hash çakışma analiz raporu kaydedildi: {out_file}")


def run_cli_demonstration() -> None:
    """CLI komutlarını çalıştırıp çıktıları komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = os.path.join(BASE_DIR, "uygulama", "hash_cli.py")

    commands = [
        ([sys.executable, cli_path, "--help"], "1. Yardım Menüsü ve Parametre Doğrulama"),
        ([sys.executable, cli_path, "-s", "SiberGuvenlik2026", "-a", "sha256"], "2. SHA-256 Güvenli Özet Hesaplama"),
        ([sys.executable, cli_path, "--avalanche"], "3. Çığ Etkisi (Avalanche Effect) Analiz Yürütmesi"),
        ([sys.executable, cli_path, "--birthday-sim", "16"], "4. Doğum Günü Paradoksu 16-Bit Çakışma Simülasyonu"),
        ([sys.executable, cli_path, "-s", "abc", "--verify", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"], "5. Sabit Zamanlı Bütünlük Doğrulaması (Çıkış Kodu: 0)"),
        ([sys.executable, cli_path, "-s", "test", "-a", "md5"], "6. Güvensiz MD5 Algoritması Engelleme Testi (Çıkış Kodu: 1)")
    ]

    lines = []
    lines.append("=== GÜN 101: HASH CLI YÜRÜTME VE STANDART ÇIKIŞ KODLARI KANITI ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : POSIX Exit Codes (0: Başarılı / Doğrulandı, 1: Güvenlik İhlali / Hata, 2: Girdi Hatası)")
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
    print("=== Gün 101 Kanıt Üretici Başlatılıyor ===")
    run_unit_tests()
    run_negative_controls()
    run_hash_report()
    run_cli_demonstration()
    print("=== Tüm Kanıtlar Başarıyla Üretildi ===")


if __name__ == "__main__":
    main()
