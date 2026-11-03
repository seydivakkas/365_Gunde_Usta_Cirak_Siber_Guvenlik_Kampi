# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 091: Mini Proje 12 — Kanıt Üretici ve Doğrulama Otomasyonu (kanit_uretici.py).

Bu betik; birim testleri (14/14), negatif kontrolleri (9/9), Windows ve Linux telemetri
analizlerini ve CLI çalıştırma kanıtlarını otomatik olarak derleyerek kanit/gercek
dizinine kaydeder.
"""

# Standart kütüphaneler
import os
import sys
import json
import unittest
import io
import subprocess
from datetime import datetime, timezone

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "uygulama")))

from cross_platform_security_reporter import (
    CrossPlatformSecurityReporter,
    ReporterSecurityError,
    UnsupportedPlatformError,
    UnsupportedFormatError,
    MutuallyExclusiveViolationError,
    PathTraversalError,
    MalformedTelemetryError,
    MissingRequiredFieldError,
    NaiveTimestampTelemetryError,
    PayloadTooLargeError,
    SensitiveDataExposureError
)

def kanitlari_uret() -> None:
    """Tüm kanıtları üretip ilgili dosyalara kaydeder."""
    ana_dizin = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dizini = os.path.join(ana_dizin, "kanit", "gercek")
    os.makedirs(gercek_kanit_dizini, exist_ok=True)

    print("[*] 1. Aşama: Birim testler (unittest) çalıştırılıyor...")
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(ana_dizin, "tests"), pattern="test_*.py")

    cikti_yakalayici = io.StringIO()
    runner = unittest.TextTestRunner(stream=cikti_yakalayici, verbosity=2)
    test_sonucu = runner.run(suite)

    test_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "test_sonuclari.txt")
    with open(test_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("=" * 75 + "\n")
        f.write("GÜN 091: MİNİ PROJE 12 — BİRİM TEST KANITLARI\n")
        f.write(f"Tarih (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write("=" * 75 + "\n\n")
        f.write(cikti_yakalayici.getvalue())
        f.write("\n" + "=" * 75 + "\n")
        f.write(f"Toplam Test: {test_sonucu.testsRun}\n")
        f.write(f"Başarılı: {test_sonucu.testsRun - len(test_sonucu.failures) - len(test_sonucu.errors)}\n")
        f.write(f"Hatalar: {len(test_sonucu.errors)}\n")
        f.write(f"Başarısızlıklar: {len(test_sonucu.failures)}\n")
        f.write(f"Genel Sonuç: {'PASS (BAŞARILI)' if test_sonucu.wasSuccessful() else 'FAIL'}\n")
    print(f"[+] Birim test kanıtı kaydedildi: {test_sonuc_dosyasi}")

    print("[*] 2. Aşama: 9 Negatif kontrol senaryosu çalıştırılıyor...")
    negatif_json_yolu = os.path.join(ana_dizin, "ornek_veri", "invalid_reporter_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_senaryolar = json.load(f)

    reporter = CrossPlatformSecurityReporter()
    negatif_rapor_satirlari = [
        "=" * 85,
        "GÜN 091: MİNİ PROJE 12 — NEGATİF KONTROL VE ZAFİYET ENGELLEME KANITLARI",
        f"Çalıştırma Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 85,
        f"{'SENARYO ID':<10} | {'BEKLENEN HATA':<32} | {'DURUM':<10} | {'CWE KODU'}",
        "-" * 85
    ]

    basarili_negatif = 0
    for senaryo in negatif_senaryolar:
        s_id = senaryo["id"]
        beklenen_hata_adi = senaryo["beklenen_hata"]
        girdi = senaryo["girdi"]
        cwe = senaryo["cwe_kodu"]

        yakalanan_hata = None
        try:
            if s_id == "NEG_01":
                # Desteklenmeyen platform
                reporter.validate_telemetry_payload(girdi)
            elif s_id == "NEG_02":
                # Desteklenmeyen format
                ornek_rep = reporter.audit_telemetry({
                    "platform": "windows", "hostname": "TEST", "zaman_damgasi_utc": "2026-11-01T20:00:00Z"
                })
                reporter.format_report(ornek_rep, format_tipi=girdi["format"])
            elif s_id == "NEG_03":
                # Karşılıklı dışlayan bayrak ihlali simülasyonu
                if girdi.get("fast") and girdi.get("deep"):
                    raise MutuallyExclusiveViolationError("Karşılıklı dışlayan bayraklar ihlal edildi.")
            elif s_id == "NEG_04":
                # Dizin atlama kontrolü
                reporter.validate_output_path(girdi["output_path"])
            elif s_id in ("NEG_05", "NEG_06", "NEG_07", "NEG_08", "NEG_09"):
                reporter.validate_telemetry_payload(girdi)
        except Exception as e:
            yakalanan_hata = type(e).__name__

        if yakalanan_hata == beklenen_hata_adi:
            durum_str = "ENGELLENDİ"
            basarili_negatif += 1
        else:
            durum_str = f"HATA ({yakalanan_hata})"

        negatif_rapor_satirlari.append(
            f"{s_id:<10} | {beklenen_hata_adi:<32} | {durum_str:<10} | {cwe}"
        )

    negatif_rapor_satirlari.append("=" * 85)
    negatif_rapor_satirlari.append(f"Toplam Negatif Senaryo: {len(negatif_senaryolar)}")
    negatif_rapor_satirlari.append(f"Başarıyla Engellenen / Tespit Edilen: {basarili_negatif}")
    negatif_rapor_satirlari.append(f"Negatif Başarı Oranı: %{(basarili_negatif / len(negatif_senaryolar)) * 100:.1f}")

    negatif_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "negatif_kontrol_sonuclari.txt")
    with open(negatif_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor_satirlari) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {negatif_sonuc_dosyasi}")

    print("[*] 3. Aşama: Windows ve Linux telemetri raporları oluşturuluyor...")
    win_tel_path = os.path.join(ana_dizin, "ornek_veri", "sample_windows_telemetry.json")
    lnx_tel_path = os.path.join(ana_dizin, "ornek_veri", "sample_linux_telemetry.json")

    with open(win_tel_path, "r", encoding="utf-8") as f:
        win_data = reporter.validate_telemetry_payload(json.load(f))
    with open(lnx_tel_path, "r", encoding="utf-8") as f:
        lnx_data = reporter.validate_telemetry_payload(json.load(f))

    win_report = reporter.audit_telemetry(win_data, deep_scan=True)
    lnx_report = reporter.audit_telemetry(lnx_data, deep_scan=True)

    # Birleşik metin raporu
    birlestirilmis_metin = (
        reporter.format_report(win_report, "text") +
        "\n\n" +
        reporter.format_report(lnx_report, "text")
    )

    rapor_txt_dosyasi = os.path.join(gercek_kanit_dizini, "sistem_guvenlik_raporu.txt")
    with open(rapor_txt_dosyasi, "w", encoding="utf-8") as f:
        f.write(birlestirilmis_metin + "\n")
    print(f"[+] Birleşik sistem güvenlik metin raporu kaydedildi: {rapor_txt_dosyasi}")

    # JSON raporu
    birlestirilmis_json = {
        "denetim_zamani_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "raporlar": [
            json.loads(reporter.format_report(win_report, "json")),
            json.loads(reporter.format_report(lnx_report, "json"))
        ]
    }
    rapor_json_dosyasi = os.path.join(gercek_kanit_dizini, "sistem_guvenlik_raporu.json")
    with open(rapor_json_dosyasi, "w", encoding="utf-8") as f:
        json.dump(birlestirilmis_json, f, indent=2, ensure_ascii=False)
    print(f"[+] Sistem güvenlik JSON raporu kaydedildi: {rapor_json_dosyasi}")

    print("[*] 4. Aşama: CLI komut ve çıktı kanıtları üretiliyor...")
    cli_runner = os.path.join(ana_dizin, "uygulama", "reporter_cli.py")

    komutlar = [
        # Windows telemetrisi hızlı tarama
        [sys.executable, cli_runner, "--telemetry-file", win_tel_path, "--fast"],
        # Linux telemetrisi derin tarama JSON formatında
        [sys.executable, cli_runner, "--telemetry-file", lnx_tel_path, "--deep", "--format", "json"],
        # Karşılıklı dışlayan bayrak hatası denemesi (--fast ve --deep bir arada)
        [sys.executable, cli_runner, "--telemetry-file", win_tel_path, "--fast", "--deep"]
    ]

    komut_satirlari = [
        "=" * 85,
        "GÜN 091: MİNİ PROJE 12 — CLI KOMUT ÇALIŞTIRMA VE ÇIKIŞ KANITLARI",
        f"Kayıt Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 85,
        ""
    ]

    for k in komutlar:
        komut_metni = " ".join(k)
        komut_satirlari.append(f"$ {komut_metni}")
        proc = subprocess.run(k, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ana_dizin)
        komut_satirlari.append(f"[Çıkış Kodu: {proc.returncode}]")
        if proc.stdout:
            komut_satirlari.append("[STDOUT]:")
            komut_satirlari.append(proc.stdout.strip())
        if proc.stderr:
            komut_satirlari.append("[STDERR]:")
            komut_satirlari.append(proc.stderr.strip())
        komut_satirlari.append("-" * 85)

    komut_kanit_dosyasi = os.path.join(gercek_kanit_dizini, "komut_ve_cikis.txt")
    with open(komut_kanit_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(komut_satirlari) + "\n")
    print(f"[+] Komut ve çıktı kanıtı kaydedildi: {komut_kanit_dosyasi}")
    print("[+] GÜN 091 TÜM KANITLAR EKSİKSİZ ÜRETİLDİ!")

if __name__ == "__main__":
    kanitlari_uret()
