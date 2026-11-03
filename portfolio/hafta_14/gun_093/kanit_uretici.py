# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 093: Kanıt Üretici ve Doğrulama Otomasyonu (kanit_uretici.py).

Bu betik; birim testleri (14/14), negatif kontrolleri (9/9), dosya bütünlüğü
doğrulamalarını ve CLI komut çalıştırma çıktılarını derleyerek kanit/gercek dizinine kaydeder.
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

from file_integrity_verifier import (
    FileIntegrityVerifier,
    HashSecurityError,
    WeakHashAlgorithmError,
    UnsupportedAlgorithmError,
    TargetFileNotFoundError,
    PathTraversalError,
    InvalidChecksumFormatError,
    IntegrityMismatchError,
    NullBytePathError,
    PathTooLongError
)

def kanitlari_uret() -> None:
    """Tüm kanıt dosyalarını üretir ve kaydeder."""
    ana_dizin = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dizini = os.path.join(ana_dizin, "kanit", "gercek")
    corpus_dizini = os.path.join(ana_dizin, "ornek_veri", "test_corpus")
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
        f.write("GÜN 093: HASHLIB İLE DOSYA DOĞRULAMA — BİRİM TEST KANITLARI\n")
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
    negatif_json_yolu = os.path.join(ana_dizin, "ornek_veri", "invalid_hash_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_senaryolar = json.load(f)

    verifier = FileIntegrityVerifier()
    negatif_rapor_satirlari = [
        "=" * 85,
        "GÜN 093: NEGATİF KONTROL VE KRİPTOGRAFİK BÜTÜNLÜK ZAFİYET ENGELLEME KANITLARI",
        f"Çalıştırma Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 85,
        f"{'SENARYO ID':<10} | {'BEKLENEN HATA':<28} | {'DURUM':<10} | {'CWE KODU'}",
        "-" * 85
    ]

    basarili_negatif = 0
    for senaryo in negatif_senaryolar:
        s_id = senaryo["id"]
        beklenen_hata_adi = senaryo["beklenen_hata"]
        girdi = senaryo["girdi"]
        cwe = senaryo["cwe_kodu"]

        dosya_adi = girdi.get("dosya_adi", "")
        # Gerçek korpus yoluyla eşleştir
        if dosya_adi == "DOS_PATH_OVERSIZED_TRIGGER":
            hedef_yol = "DOS_PATH_OVERSIZED_TRIGGER"
        elif "\x00" in dosya_adi or ".." in dosya_adi or "var_olmayan" in dosya_adi:
            hedef_yol = dosya_adi
        else:
            hedef_yol = os.path.join(corpus_dizini, dosya_adi)

        algo = girdi.get("algoritma", "sha256")
        strict = girdi.get("strict_mode", True)
        beklenen_hash = girdi.get("beklenen_hash")

        yakalanan_hata = None
        try:
            if beklenen_hash is not None:
                verifier.verify_file_integrity(hedef_yol, beklenen_hash=beklenen_hash, algoritma=algo, strict_mode=strict)
            else:
                verifier.compute_file_hash(hedef_yol, algoritma=algo, strict_mode=strict)
        except Exception as e:
            yakalanan_hata = type(e).__name__

        if yakalanan_hata == beklenen_hata_adi:
            durum_str = "ENGELLENDİ"
            basarili_negatif += 1
        else:
            durum_str = f"HATA ({yakalanan_hata})"

        negatif_rapor_satirlari.append(
            f"{s_id:<10} | {beklenen_hata_adi:<28} | {durum_str:<10} | {cwe}"
        )

    negatif_rapor_satirlari.append("=" * 85)
    negatif_rapor_satirlari.append(f"Toplam Negatif Senaryo: {len(negatif_senaryolar)}")
    negatif_rapor_satirlari.append(f"Başarıyla Engellenen / Tespit Edilen: {basarili_negatif}")
    negatif_rapor_satirlari.append(f"Negatif Başarı Oranı: %{(basarili_negatif / len(negatif_senaryolar)) * 100:.1f}")

    negatif_sonuc_dosyasi = os.path.join(gercek_kanit_dizini, "negatif_kontrol_sonuclari.txt")
    with open(negatif_sonuc_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor_satirlari) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {negatif_sonuc_dosyasi}")

    print("[*] 3. Aşama: Dosya bütünlük denetim raporu oluşturuluyor...")
    checksums_path = os.path.join(ana_dizin, "ornek_veri", "known_checksums.json")
    with open(checksums_path, "r", encoding="utf-8") as f:
        known_map = json.load(f)

    rapor_satirlari = [
        "=" * 95,
        "GÜN 093: KRİPTOGRAFİK DOSYA BÜTÜNLÜĞÜ VE SAĞLAMA TOPLAMI DENETİM RAPORU",
        f"Rapor Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "=" * 95,
        f"{'DOSYA ADI':<22} | {'BOYUT':<8} | {'DURUM':<10} | {'SHA-256 HESAPLANAN ÖZET'}",
        "-" * 95
    ]

    for fname, meta in known_map.items():
        fpath = os.path.join(corpus_dizini, fname)
        beklenen_sha = meta["sha256"]
        audit = verifier.verify_file_integrity(fpath, beklenen_hash=beklenen_sha, algoritma="sha256")
        durum_etiketi = "DOĞRULANDI" if audit.butunluk_dogrulandi_mi else "İHLAL"
        rapor_satirlari.append(
            f"{fname:<22} | {meta['size_bytes']:<8} | {durum_etiketi:<10} | {audit.hesaplanan_hash}"
        )

    rapor_satirlari.append("=" * 95)
    rapor_txt_dosyasi = os.path.join(gercek_kanit_dizini, "butunluk_denetim_raporu.txt")
    with open(rapor_txt_dosyasi, "w", encoding="utf-8") as f:
        f.write("\n".join(rapor_satirlari) + "\n")
    print(f"[+] Bütünlük denetim raporu kaydedildi: {rapor_txt_dosyasi}")

    print("[*] 4. Aşama: CLI komut ve çıktı kanıtları üretiliyor...")
    cli_script = os.path.join(ana_dizin, "uygulama", "fim_runner.py")
    test_conf_path = os.path.join(corpus_dizini, "secure_config.conf")
    known_conf_hash = known_map["secure_config.conf"]["sha256"]

    komutlar = [
        # 1. Tekil dosya SHA-256 hesaplama
        [sys.executable, cli_script, "--file", test_conf_path, "--algo", "sha256"],
        # 2. Doğrulama başarılı senaryosu (Exit Code 0)
        [sys.executable, cli_script, "--file", test_conf_path, "--expected-hash", known_conf_hash],
        # 3. Bütünlük uyuşmazlığı / Kurcalanma tespiti (Exit Code 2)
        [sys.executable, cli_script, "--file", test_conf_path, "--expected-hash", "0" * 64]
    ]

    komut_satirlari = [
        "=" * 85,
        "GÜN 093: HASHLIB VE FIM — CLI KOMUT ÇALIŞTIRMA VE ÇIKIŞ KANITLARI",
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
    print("[+] GÜN 093 TÜM KANITLAR BAŞARIYLA ÜRETİLDİ!")

if __name__ == "__main__":
    kanitlari_uret()
