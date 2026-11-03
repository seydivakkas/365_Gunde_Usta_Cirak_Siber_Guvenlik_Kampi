# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 090: Kanıt Üretici ve Doğrulama Otomasyonu (Evidence Generator).

Bu betik; birim testleri (14/14), negatif kontrolleri (9/9) ve gerçek CLI çalıştırma
senaryolarını icra ederek somut adli bilişim ve log analiz kanıt dosyalarını üretir.
"""

# Standart kütüphaneler
import os
import sys
import json
import time
import unittest
import io
import subprocess
from datetime import datetime, timezone

# Uygulama modülünü dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "uygulama")))

from utc_timezone_forensic_normalizer import (
    UtcTimezoneForensicNormalizer,
    TimestampSecurityError,
    NaiveTimestampError,
    InvalidTimeRangeError,
    InvalidCalendarDateError,
    InvalidEpochValueError,
    UnreasonableDateRangeError,
    ClockSkewExceededError,
    MalformedTimestampError,
    PayloadTooLargeError,
    InvalidFileTimeError
)

def kanitlari_uret() -> None:
    """Tüm kanıtları sırasıyla üretir ve kanit/gercek dizinine kaydeder."""
    # Temel dizin yollarını belirle
    ana_dizin = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dizini = os.path.join(ana_dizin, "kanit", "gercek")
    os.makedirs(gercek_kanit_dizini, exist_ok=True)

    print("[*] 1. Aşama: Birim testler (unittest) çalıştırılıyor...")
    # Test yükleyicisini hazırla
    test_loader = unittest.TestLoader()
    suite = test_loader.discover(os.path.join(ana_dizin, "tests"), pattern="test_*.py")

    # Çıktıyı yakalamak için io.StringIO kullan
    test_cikti_yakalayici = io.StringIO()
    test_runner = unittest.TextTestRunner(stream=test_cikti_yakalayici, verbosity=2)
    test_sonucu = test_runner.run(suite)

    # Test sonuçlarını kanıt dosyasına kaydet
    test_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "test_sonuclari.txt")
    with open(test_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("GÜN 090: BİRİM TEST SONUÇLARI (UNIT TEST EVIDENCE)\n")
        f.write(f"Tarih (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write("=" * 70 + "\n\n")
        f.write(test_cikti_yakalayici.getvalue())
        f.write("\n" + "=" * 70 + "\n")
        f.write(f"Toplam Test: {test_sonucu.testsRun}\n")
        f.write(f"Başarılı: {test_sonucu.testsRun - len(test_sonucu.failures) - len(test_sonucu.errors)}\n")
        f.write(f"Hatalar: {len(test_sonucu.errors)}\n")
        f.write(f"Başarısızlıklar: {len(test_sonucu.failures)}\n")
        f.write(f"Genel Durum: {'PASS (BAŞARILI)' if test_sonucu.wasSuccessful() else 'FAIL'}\n")
    print(f"[+] Birim test kanıtı kaydedildi: {test_sonuc_dosyasi}")

    print("[*] 2. Aşama: 9 Negatif kontrol senaryosu çalıştırılıyor...")
    # Negatif senaryo JSON dosyasını oku
    negatif_json_yolu = os.path.join(ana_dizin, "ornek_veri", "invalid_timestamp_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_senaryolar = json.load(f)

    normalizer = UtcTimezoneForensicNormalizer(varsayilan_maks_sapma=300)
    negatif_rapor_satirlari = [
        "=" * 80,
        "GÜN 090: NEGATİF KONTROL VE ZAMAN GÜVENLİK SINIR TESTLERİ",
        f"Çalıştırma Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 80,
        f"{'SENARYO ID':<10} | {'BEKLENEN HATA':<25} | {'DURUM':<10} | {'CWE KODU'}",
        "-" * 80
    ]

    basarili_negatif = 0
    for senaryo in negatif_senaryolar:
        s_id = senaryo["id"]
        beklenen_hata_adi = senaryo["beklenen_hata"]
        girdi = senaryo["girdi"]
        cwe = senaryo["cwe_kodu"]

        yakalanan_hata = None
        try:
            if s_id in ("NEG_01", "NEG_02", "NEG_03", "NEG_05", "NEG_07", "NEG_08"):
                normalizer.parse_iso_with_strict_tz(girdi)
            elif s_id == "NEG_04":
                normalizer.convert_epoch_to_utc(girdi)
            elif s_id == "NEG_06":
                # Saat sapması denetimi
                ist = girdi["istemci_zamani"]
                ref = girdi["referans_zamani"]
                maks_s = girdi["maks_sapma_saniye"]
                res = normalizer.audit_clock_skew(ist, ref, maks_sapma_saniye=maks_s)
                if not res.sapma_guvenli_mi:
                    yakalanan_hata = "ClockSkewExceededError"
            elif s_id == "NEG_09":
                normalizer.convert_filetime_to_utc(girdi)
        except Exception as e:
            yakalanan_hata = type(e).__name__

        if yakalanan_hata == beklenen_hata_adi:
            durum_str = "ENGELLENDİ"
            basarili_negatif += 1
        else:
            durum_str = f"HATA ({yakalanan_hata})"

        negatif_rapor_satirlari.append(
            f"{s_id:<10} | {beklenen_hata_adi:<25} | {durum_str:<10} | {cwe}"
        )

    negatif_rapor_satirlari.append("=" * 80)
    negatif_rapor_satirlari.append(f"Toplam Negatif Senaryo: {len(negatif_senaryolar)}")
    negatif_rapor_satirlari.append(f"Başarıyla Engellenen / Tespit Edilen: {basarili_negatif}")
    negatif_rapor_satirlari.append(f"Negatif Başarı Oranı: %{(basarili_negatif / len(negatif_senaryolar)) * 100:.1f}")

    negatif_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "negatif_kontrol_sonuclari.txt")
    with open(negatif_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor_satirlari) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {negatif_sonuc_dosyasi}")

    print("[*] 3. Aşama: Heterojen loglar normalize edilip adli analiz raporu oluşturuluyor...")
    sample_logs_path = os.path.join(ana_dizin, "ornek_veri", "sample_multisource_logs.json")
    with open(sample_logs_path, "r", encoding="utf-8") as f:
        raw_logs = json.load(f)

    timeline = normalizer.build_forensic_timeline(raw_logs)
    adli_rapor_metni = normalizer.generate_forensic_report(timeline)

    adli_rapor_dosyasi = os.path.join(gercek_kanit_dizini, "adli_zaman_analiz_raporu.txt")
    with open(adli_rapor_dosyasi, "w", encoding="utf-8") as f:
        f.write(adli_rapor_metni + "\n")
    print(f"[+] Adli zaman analiz raporu kaydedildi: {adli_rapor_dosyasi}")

    print("[*] 4. Aşama: Terminal CLI komut ve çıktı kanıtları üretiliyor...")
    runner_path = os.path.join(ana_dizin, "uygulama", "forensic_timeline_runner.py")

    komutlar = [
        # 1. Varsayılan metin tablosu raporu
        [sys.executable, runner_path, "--input-logs", sample_logs_path],
        # 2. JSON çıktısı
        [sys.executable, runner_path, "--input-logs", sample_logs_path, "--json-output"],
        # 3. Saat sapması (Clock Skew) denetimi
        [sys.executable, runner_path, "--audit-skew"]
    ]

    komut_cikti_satirlari = [
        "=" * 80,
        "GÜN 090: ADLİ BİLİŞİM VE ZAMAN NORMALİZASYON CLI KOMUT VE ÇIKTILARI",
        f"Kayıt Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 80,
        ""
    ]

    for k in komutlar:
        komut_metni = " ".join(k)
        komut_cikti_satirlari.append(f"$ {komut_metni}")
        proc = subprocess.run(k, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ana_dizin)
        komut_cikti_satirlari.append(f"[Çıkış Kodu: {proc.returncode}]")
        if proc.stdout:
            komut_cikti_satirlari.append("[STDOUT]:")
            komut_cikti_satirlari.append(proc.stdout.strip())
        if proc.stderr:
            komut_cikti_satirlari.append("[STDERR]:")
            komut_cikti_satirlari.append(proc.stderr.strip())
        komut_cikti_satirlari.append("-" * 80)

    komut_dosyasi = os.path.join(gercek_kanit_dizini, "komut_ve_cikis.txt")
    with open(komut_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(komut_cikti_satirlari) + "\n")
    print(f"[+] Komut ve çıktı kanıtı kaydedildi: {komut_dosyasi}")
    print("[+] TÜM KANITLAR BAŞARIYLA ÜRETİLDİ!")

if __name__ == "__main__":
    kanitlari_uret()
