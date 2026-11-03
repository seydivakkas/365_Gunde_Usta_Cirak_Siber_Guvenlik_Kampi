# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Kanıt Üretici.
Birim testleri, negatif kontrolleri ve CLI senaryolarını çalıştırıp
gerçek adli kanıt dosyalarını `kanit/gercek/` altına üretir.
"""

# Birim test çerçevesi
import unittest
# Sistem ve dizin işlemleri
import os
import sys
# JSON veri işleme
import json
# Süre ölçümü
import time
# Giriş/çıkış tamponu
import io
# Alt süreç çalıştırma
import subprocess

# Ana çalışma dizinini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Çekirdek motoru ve istisnaları içe aktar
from uygulama.pii_masker import (
    PIIMaskerEngine,
    PIISecurityError,
    verify_luhn,
    verify_tckn,
    verify_iban_tr
)


def run_unit_tests(out_path: str) -> bool:
    """14 birim testini çalıştırır ve çıktısını kanıt dosyasına kaydeder."""
    # Test yükleyicisini hazırla
    loader = unittest.TestLoader()
    # Test paketini tests modülünden keşfet
    suite = loader.discover("tests", pattern="test_*.py")
    # Metin akışı için string tamponu aç
    stream = io.StringIO()
    # Test koşucusunu başlat
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Testleri yürüt
    result = runner.run(suite)

    # Test çıktısını UTF-8 olarak dosyaya yaz
    with open(out_path, "w", encoding="utf-8") as f:
        # Başlık yaz
        f.write("=== G094 BİRİM TEST SONUÇLARI (14 SENARYO) ===\n")
        # Koşum zamanını yaz
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        # Çıktıyı dosyaya dök
        f.write(stream.getvalue())
        # Özet satırı
        f.write(f"\nToplam: {result.testsRun}, Başarılı: {result.testsRun - len(result.failures) - len(result.errors)}, Hata: {len(result.errors)}, Başarısız: {len(result.failures)}\n")

    # Başarı durumunu döndür
    return result.wasSuccessful()


def run_negative_controls(in_json: str, out_path: str) -> bool:
    """9 negatif kontrol senaryosunu test eder ve kanıt dosyasına kaydeder."""
    # Negatif senaryolar dosyasını oku
    with open(in_json, "r", encoding="utf-8") as f:
        # JSON'dan senaryo listesini al
        scenarios = json.load(f)

    # Motor nesnesini oluştur
    engine = PIIMaskerEngine(mask_style="MASK")
    # Başarı durum bayrağı
    all_passed = True
    # Rapor satırları listesi
    report_lines = []

    # Başlıkları ekle
    report_lines.append("=== G094 NEGATİF KONTROL VE ENJEKSİYON SAVUNMA KANITLARI (9 SENARYO) ===")
    report_lines.append(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Her senaryoyu sırayla dene
    for sc in scenarios:
        # Senaryo kimliği ve tanımı
        sc_id = sc["id"]
        # Tanım
        desc = sc["tanim"]
        # Girdi verisi
        inp = sc["girdi"]
        # Beklenen hata tipi adı
        expected_err = sc["beklenen_hata"]
        # Eşleşen CWE kodu
        cwe = sc["cwe"]

        # Hata yakalandı mı bayrağı
        caught = False
        # Gerçekleşen hata nesnesi
        actual_err_name = ""

        try:
            # Senaryo özelinde doğrulamayı dene
            if sc_id == "NEG_01_LUHN_CHECKSUM_FAILURE":
                # Luhn zorlaması ile çağır
                engine.process_text(inp, rules=["credit_card"], strict_validation=True)
            elif sc_id in ["NEG_02_TCKN_CHECKSUM_FAILURE", "NEG_03_TCKN_LEADING_ZERO"]:
                # TCKN algoritmik kontrolü ile çağır
                engine.process_text(inp, rules=["tckn"], strict_validation=True)
            elif sc_id == "NEG_04_IBAN_MOD97_FAILURE":
                # IBAN kontrolü ile çağır
                engine.process_text(inp, rules=["iban"], strict_validation=True)
            elif sc_id == "NEG_08_INVALID_RULE_TYPE":
                # Geçersiz kural ile çağır
                engine.process_text(inp, rules=[sc["gecersiz_kural"]])
            else:
                # Genel metin işleme
                engine.process_text(inp)
        except Exception as ex:
            # İstisna türünü al
            actual_err_name = type(ex).__name__
            # Beklenen istisna ile eşleşiyor mu kontrol et
            if actual_err_name == expected_err or isinstance(ex, PIISecurityError):
                # Başarılı savunma
                caught = True

        # Sonucu kaydet
        status_str = "BAŞARILI (ENGELLEDİ)" if caught else "BAŞARISIZ (ENGELLEMEDİ)"
        # Rapor satırını biçimlendir
        report_lines.append(f"[{status_str}] {sc_id}")
        report_lines.append(f"  Tanım: {desc}")
        report_lines.append(f"  CWE: {cwe}")
        report_lines.append(f"  Beklenen: {expected_err} | Alınan: {actual_err_name}\n")

        # Eğer yakalanamadıysa genel bayrağı false yap
        if not caught:
            # Hata var
            all_passed = False

    # Kanıt dosyasına yaz
    with open(out_path, "w", encoding="utf-8") as out_f:
        # Tüm satırları birleştirip yaz
        out_f.write("\n".join(report_lines))

    # Tüm negatif kontroller geçti mi döndür
    return all_passed


def generate_masking_evidence(out_path: str) -> None:
    """Örnek telemetri loglarını ve GDPR verilerini maskeleyip tam kanıt raporu üretir."""
    # Log dosyasını oku
    with open("ornek_veri/raw_telemetry_logs.log", "r", encoding="utf-8") as f:
        # Ham logları al
        raw_logs = f.read()

    # JSON dosyasını oku
    with open("ornek_veri/sample_gdpr_records.json", "r", encoding="utf-8") as f:
        # Ham JSON al
        raw_json = f.read()

    # Farklı stillerde motorları oluştur
    mask_engine = PIIMaskerEngine(mask_style="MASK")
    redact_engine = PIIMaskerEngine(mask_style="REDACT")
    hash_engine = PIIMaskerEngine(mask_style="HASH")

    # Ham logları maskele
    masked_logs, log_stats = mask_engine.process_text(raw_logs, rules=["all"])
    # JSON verisini maskele
    masked_json, json_stats = mask_engine.process_text(raw_json, rules=["all"])
    # Logları tamamen redact et
    redacted_logs, _ = redact_engine.process_text(raw_logs, rules=["all"])
    # Logları hash pseudonymize et
    hashed_logs, _ = hash_engine.process_text(raw_logs, rules=["all"])

    # Rapor dosyasını hazırla
    with open(out_path, "w", encoding="utf-8") as f:
        # Başlık
        f.write("=== G094 KURUMSAL KİŞİSEL VERİ MASKELEME VE DLP DENETİM RAPORU ===\n")
        f.write(f"Denetim Zamanı: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("--- 1. HAM TELEMETRİ GİRDİSİ (HASSAS VERİLER İÇERİR) ---\n")
        f.write(raw_logs.strip() + "\n\n")

        f.write("--- 2. MASKELEME SONUCU (STİL: MASK - KISMİ YILDIZLAMA) ---\n")
        f.write(masked_logs.strip() + "\n\n")

        f.write("--- 3. TAM GİZLEME SONUCU (STİL: REDACT - ETİKETLEME) ---\n")
        f.write(redacted_logs.strip() + "\n\n")

        f.write("--- 4. KRİPTOGRAFİK ÖZET SONUCU (STİL: HASH - PSEUDONYM) ---\n")
        f.write(hashed_logs.strip() + "\n\n")

        f.write("--- 5. YAPILANDIRILMIŞ JSON VERİSİ MASKELEME ÇIKTISI ---\n")
        f.write(masked_json.strip() + "\n\n")

        f.write("--- 6. DLP İSTATİSTİK VE TESPİT METRİKLERİ ---\n")
        f.write(json.dumps(log_stats, indent=2, ensure_ascii=False) + "\n")


def run_cli_tests(out_path: str) -> None:
    """CLI betiğini (`masker_cli.py`) komut satırından koşturup çıktıları kaydeder."""
    # Çalıştırılacak CLI test komutları
    commands = [
        [sys.executable, "uygulama/masker_cli.py", "--text", "Test tckn=12345678950 pan=4532015112830366", "--json"],
        [sys.executable, "uygulama/masker_cli.py", "--file", "ornek_veri/raw_telemetry_logs.log", "--style", "MASK"],
        [sys.executable, "uygulama/masker_cli.py", "--file", "ornek_veri/raw_telemetry_logs.log", "--style", "REDACT"],
        [sys.executable, "uygulama/masker_cli.py", "--text", "email=test@example.com phone=05321112233", "--rules", "email,phone"]
    ]

    # Çıktı dosyasını aç
    with open(out_path, "w", encoding="utf-8") as f:
        # Başlık yaz
        f.write("=== G094 CLI KOMUT KOŞUMLARI VE ÇIKIŞLARI ===\n")
        f.write(f"Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Her komutu yürüt
        for cmd in commands:
            # Komut başlığı yaz
            f.write(f"$ {' '.join(cmd)}\n")
            # Alt süreç olarak çalıştır
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Çıkış kodunu yaz
            f.write(f"[Çıkış Kodu: {proc.returncode}]\n")
            # Standart çıktıyı yaz
            if proc.stdout:
                # Ekle
                f.write("[STDOUT]\n" + proc.stdout + "\n")
            # Standart hatayı yaz
            if proc.stderr:
                # Ekle
                f.write("[STDERR]\n" + proc.stderr + "\n")
            # Ayırıcı
            f.write("-" * 70 + "\n")


def main():
    """Tüm kanıt üretim akışını orkestre eder."""
    # Kanıt klasörünün varlığını doğrula
    os.makedirs("kanit/gercek", exist_ok=True)

    # 1. Birim testleri koş ve kaydet
    print("[1/4] 14 Birim testi yürütülüyor...")
    unit_ok = run_unit_tests("kanit/gercek/test_sonuclari.txt")
    print(f"      Birim testleri tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontrolleri koş ve kaydet
    print("[2/4] 9 Negatif kontrol yürütülüyor...")
    neg_ok = run_negative_controls("ornek_veri/invalid_pii_inputs.json", "kanit/gercek/negatif_kontrol_sonuclari.txt")
    print(f"      Negatif kontroller tamamlandı: {'BAŞARILI' if neg_ok else 'BAŞARISIZ'}")

    # 3. Maskeleme ve DLP rapor kanıtı üret
    print("[3/4] Telemetri maskeleme denetim raporu üretiliyor...")
    generate_masking_evidence("kanit/gercek/kisisel_veri_maskeleme_raporu.txt")
    print("      Maskeleme raporu üretildi: kanit/gercek/kisisel_veri_maskeleme_raporu.txt")

    # 4. CLI testlerini koştur
    print("[4/4] CLI yürütme çıktıları kaydediliyor...")
    run_cli_tests("kanit/gercek/komut_ve_cikis.txt")
    print("      CLI çıktıları kaydedildi: kanit/gercek/komut_ve_cikis.txt")

    # Özet durum
    if unit_ok and neg_ok:
        # Başarı mesajı
        print("\n>>> GÜN 094 TÜM TESTLER VE KANITLAR %100 BAŞARIYLA TAMAMLANDI! <<<")
        # 0 dön
        return 0
    else:
        # Hata mesajı
        print("\n[HATA] Bazı testler veya negatif kontroller başarısız oldu!")
        # 1 dön
        return 1


if __name__ == "__main__":
    # Ana fonksiyonu çalıştır
    sys.exit(main())
