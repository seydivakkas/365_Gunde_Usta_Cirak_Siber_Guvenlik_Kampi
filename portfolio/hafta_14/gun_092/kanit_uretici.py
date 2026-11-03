# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 092: Kanıt Üretici ve Doğrulama Otomasyonu (kanit_uretici.py).

Bu betik; birim testleri (14/14), negatif kontrolleri (9/9), geçerli varlık doğrulamalarını
ve CLI komut çalıştırma kanıtlarını otomatik olarak derleyerek kanit/gercek dizinine kaydeder.
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

from security_data_validator import (
    SecurityDataValidator,
    SecurityValidationError,
    TypeValidationError,
    InvalidIpAddressError,
    PortRangeError,
    InvalidMacAddressError,
    InvalidHostnameError,
    NullByteInjectionError,
    InvalidHashChecksumError,
    ValueRangeError,
    PayloadTooLargeError
)

def kanitlari_uret() -> None:
    """Tüm kanıt dosyalarını üretir ve kaydeder."""
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
        f.write("GÜN 092: VERİ DOĞRULAMA VE TİP GÜVENLİĞİ — BİRİM TEST KANITLARI\n")
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
    negatif_json_yolu = os.path.join(ana_dizin, "ornek_veri", "invalid_security_assets.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_senaryolar = json.load(f)

    validator = SecurityDataValidator()
    negatif_rapor_satirlari = [
        "=" * 85,
        "GÜN 092: NEGATİF KONTROL VE TİP GÜVENLİĞİ ZAFİYET ENGELLEME KANITLARI",
        f"Çalıştırma Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 85,
        f"{'SENARYO ID':<10} | {'BEKLENEN HATA':<25} | {'DURUM':<10} | {'CWE KODU'}",
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
            validator.validate_asset_payload(girdi)
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

    negatif_rapor_satirlari.append("=" * 85)
    negatif_rapor_satirlari.append(f"Toplam Negatif Senaryo: {len(negatif_senaryolar)}")
    negatif_rapor_satirlari.append(f"Başarıyla Engellenen / Tespit Edilen: {basarili_negatif}")
    negatif_rapor_satirlari.append(f"Negatif Başarı Oranı: %{(basarili_negatif / len(negatif_senaryolar)) * 100:.1f}")

    negatif_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "negatif_kontrol_sonuclari.txt")
    with open(negatif_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor_satirlari) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {negatif_sonuc_dosyasi}")

    print("[*] 3. Aşama: Geçerli varlıklar doğrulanıp rapor üretiliyor...")
    valid_assets_path = os.path.join(ana_dizin, "ornek_veri", "valid_security_assets.json")
    with open(valid_assets_path, "r", encoding="utf-8") as f:
        raw_assets = json.load(f)

    valid_list, errors = validator.batch_validate(raw_assets)

    rapor_satirlari = [
        "=" * 85,
        "GÜN 092: DOĞRULANMIŞ GÜVENLİK VARLIKLARI VE TİP GÜVENLİĞİ DENETİM RAPORU",
        f"Rapor Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 85,
        f"Toplam İncelenen Varlık: {len(raw_assets)}",
        f"Geçerli Varlık Sayısı:   {len(valid_list)}",
        f"Hata / Reddedilen:       {len(errors)}",
        "-" * 85,
        f"{'VARLIK ID':<12} | {'IP ADRESİ':<15} | {'PORT':<6} | {'MAC ADRESİ':<18} | {'HOSTNAME'}",
        "-" * 85
    ]

    for v in valid_list:
        rapor_satirlari.append(
            f"{v.asset_id:<12} | {v.ipv4_address:<15} | {v.port:<6} | {v.mac_address:<18} | {v.hostname}"
        )

    rapor_satirlari.append("=" * 85)
    rapor_txt_dosyasi = os.path.join(gercek_kanit_dizini, "veri_dogrulama_raporu.txt")
    with open(rapor_txt_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(rapor_satirlari) + "\n")
    print(f"[+] Veri doğrulama raporu kaydedildi: {rapor_txt_dosyasi}")

    print("[*] 4. Aşama: CLI komut ve çıktı kanıtları üretiliyor...")
    cli_script = os.path.join(ana_dizin, "uygulama", "validator_cli.py")

    komutlar = [
        # Geçerli varlıkların konsol çıktısı
        [sys.executable, cli_script, "--input-file", valid_assets_path],
        # Geçerli varlıkların JSON çıktısı
        [sys.executable, cli_script, "--input-file", valid_assets_path, "--json-output"],
        # Geçersiz verilerle sıkı modda test (Exit Code 2 beklenir)
        [sys.executable, cli_script, "--input-file", negatif_json_yolu, "--strict"]
    ]

    komut_satirlari = [
        "=" * 85,
        "GÜN 092: VERİ DOĞRULAMA VE TİP GÜVENLİĞİ — CLI KOMUT VE ÇIKTILARI",
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
    print("[+] GÜN 092 TÜM KANITLAR BAŞARIYLA ÜRETİLDİ!")

if __name__ == "__main__":
    kanitlari_uret()
