# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 105: Kanıt Üretici ve Doğrulama Otomasyonu.
Bu betik; birim testleri, 9 negatif kontrol senaryosunu, bütünlük manifestosu
üretimini ve CLI komut çıktılarını çalıştırarak 'kanit/gercek/' dizini altına
denetlenebilir kanıt dosyaları olarak kaydeder.
"""

# Birim test çalıştırma kütüphanesi
import unittest
# Metin akışı yöneticisi
import io
# Sistem ve yol araçları
import sys
# Dosya ve dizin işlemleri
import os
# JSON işleme modülü
import json
# Zaman damgası ve süre ölçümü
import datetime
# Süreç çalıştırma modülü
import subprocess

# Ana dizini modül arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Bütünlük motoru bileşenlerini içe aktar
from uygulama.hash_manifest_engine import (
    HashManifestEngine,
    safe_resolve_path,
    compute_streaming_hash,
    ManifestAuditScorecard,
    ManifestEngineError,
    BrokenHashAlgorithmError,
    ManifestTamperingError,
    PathTraversalError,
    SymlinkEscapeError,
    DirectoryNotFoundError,
    FileIntegrityMismatchError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)
# Test sınıfını içe aktar
from tests.test_hash_manifest import TestHashManifestEngine


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dir = os.path.join(base_dir, "kanit", "gercek")
    os.makedirs(gercek_kanit_dir, exist_ok=True)

    simdi = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ==========================================================================
    # 1. BİRİM TESTLERİNİN ÇALIŞTIRILMASI VE KANIT KAYDI
    # ==========================================================================
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestHashManifestEngine)
    test_stream = io.StringIO()
    test_runner = unittest.TextTestRunner(stream=test_stream, verbosity=2)
    test_result = test_runner.run(test_suite)

    test_kanit_metni = (
        f"===============================================================================\n"
        f"GÜN 105: BİRİM TEST SONUÇLARI RAPORU\n"
        f"Tarih/Saat: {simdi}\n"
        f"Konu: Mini Proje 14 - Kriptografik Hash Bütünlük Manifesti Motoru\n"
        f"Çalıştırılan Test Sayısı: {test_result.testsRun}\n"
        f"Hata / Başarısızlık: {len(test_result.errors)} / {len(test_result.failures)}\n"
        f"Durum: {'100/100 PASS (BAŞARILI)' if test_result.wasSuccessful() else 'FAIL'}\n"
        f"===============================================================================\n\n"
        f"{test_stream.getvalue()}\n"
    )

    with open(os.path.join(gercek_kanit_dir, "test_sonuclari.txt"), "w", encoding="utf-8") as f:
        f.write(test_kanit_metni)

    # ==========================================================================
    # 2. NEGATİF KONTROL SENARYOLARININ KANIT KAYDI
    # ==========================================================================
    negatif_json_yolu = os.path.join(base_dir, "ornek_veri", "invalid_manifest_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_vakalar = json.load(f)

    test_dir = os.path.join(base_dir, "ornek_veri", "sample_project_tree")
    test_key = "MASTER_INTEGRITY_KEY_2026"

    negatif_rapor = [
        f"===============================================================================",
        f"GÜN 105: NEGATİF KONTROL VE ZAFİYET ENGELLEME KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"Toplam Negatif Senaryo: {len(negatif_vakalar)}",
        f"Standart: OWASP Cryptographic Storage & FIPS 180-4 / NIST SP 800-38D",
        f"===============================================================================\n"
    ]

    basarili_negatifler = 0

    for vaka in negatif_vakalar:
        vid = vaka["id"]
        tanim = vaka["tanim"]
        cwe = vaka["cwe"]
        beklenen = vaka["beklenen_hata"]
        firlatilan = None
        durum = "FAIL"

        try:
            if vid == "NEG_01_BROKEN_HASH_ALGORITHM":
                HashManifestEngine.create_manifest(test_dir, algo=vaka["algoritma"])
            elif vid == "NEG_02_HMAC_SEAL_FORGERY":
                m = HashManifestEngine.create_manifest(test_dir, signing_key=test_key)
                m["hmac_muhru"] = vaka["sahte_muhur"]
                HashManifestEngine.verify_manifest(test_dir, m, signing_key=test_key, strict_mode=True)
            elif vid == "NEG_03_PATH_TRAVERSAL_IN_MANIFEST":
                safe_resolve_path(test_dir, vaka["zararli_yol"])
            elif vid == "NEG_04_SYMLINK_ESCAPE_ATTEMPT":
                safe_resolve_path(test_dir, vaka["zararli_yol"])
            elif vid == "NEG_05_EMPTY_ROOT_DIRECTORY":
                HashManifestEngine.create_manifest(vaka["gecersiz_dizin"])
            elif vid == "NEG_06_CORRUPTED_FILE_HASH":
                m = HashManifestEngine.create_manifest(test_dir)
                m["dosyalar"][0]["hash"] = "9999999999999999999999999999999999999999999999999999999999999999"
                HashManifestEngine.verify_manifest(test_dir, m, strict_mode=True)
            elif vid == "NEG_07_NULL_BYTE_PATH_INJECTION":
                safe_resolve_path(test_dir, vaka["zararli_yol"])
            elif vid == "NEG_08_OVERSIZED_FILE_READ_DOS":
                temp_big = os.path.join(test_dir, "temp_big_run.bin")
                try:
                    with open(temp_big, "wb") as f:
                        f.write(b"0" * vaka["boyut_bayt"])
                    compute_streaming_hash(temp_big, "sha256")
                finally:
                    if os.path.exists(temp_big):
                        os.remove(temp_big)
            elif vid == "NEG_09_TYPE_CONFUSION":
                HashManifestEngine.create_manifest(vaka["hatali_girdi"])
        except Exception as exc:
            firlatilan = type(exc).__name__
            if firlatilan == beklenen:
                durum = "PASS (ENGELLENDİ)"
                basarili_negatifler += 1
            else:
                durum = f"FAIL (Beklenen: {beklenen}, Fırlatılan: {firlatilan})"

        negatif_rapor.append(f"[{vid}]")
        negatif_rapor.append(f"  Tanım         : {tanim}")
        negatif_rapor.append(f"  Güvenlik Eşiği: {cwe}")
        negatif_rapor.append(f"  Beklenen Hata : {beklenen}")
        negatif_rapor.append(f"  Yakalana Hata : {firlatilan}")
        negatif_rapor.append(f"  Sonuç         : {durum}\n")

    negatif_rapor.append(f"ÖZET: {basarili_negatifler}/{len(negatif_vakalar)} Negatif Kontrol Başarıyla Doğrulandı.")
    with open(os.path.join(gercek_kanit_dir, "negatif_kontrol_sonuclari.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor))

    # ==========================================================================
    # 3. GÜVENLİK ANALİZİ VE DENETİM RAPORU
    # ==========================================================================
    analiz_raporu = [
        f"===============================================================================",
        f"GÜN 105: MİNİ PROJE 14 - KRİPTOGRAFİK BÜTÜNLÜK MANİFESTİ DENETİM RAPORU",
        f"Tarih/Saat: {simdi}",
        f"Denetçi: Seydi Eryılmaz (@seydivakkas)",
        f"===============================================================================\n",
        f"1. PROJE MİMARİSİ VE FONKSİYONEL YETENEKLER:",
        f"-------------------------------------------------------------------------------",
        f"- Kapsam: Dosya sistemi seviyesinde yetkisiz dosya değişimlerini (FIM - File Integrity Monitoring)",
        f"  tespit eden kurumsal manifest motoru (Tripwire / AIDE / dm-verity modeli).",
        f"- Akışlı Okuma (Streaming Hash): 64 KB bloklar halinde okuma yapılarak bellek tüketimi (DoS) önlenir.",
        f"- Çift Hash Koruması: SHA-256 ve BLAKE2b özetleri bağımsız olarak hesaplanır.",
        f"- Kurcalanmaz Mühür (HMAC-SHA256 Seal): Manifest içeriği gizli bir anahtar ile imzalanır.",
        f"  Saldırgan dosyaları ve manifestoyu değiştirse bile anahtar olmadan geçerli mühür üretemez (CWE-353).\n",
        f"2. GÜVENLİK BİLEŞENLERİ VE CWE SAVUNMALARI:",
        f"-------------------------------------------------------------------------------",
        f"A. Path Traversal Savunması (CWE-22):",
        f"   - safe_resolve_path fonksiyonu ile her dosya yolu kök dizin sınırları içinde denetlenir.",
        f"   - '../../etc/shadow' veya '..\\windows\\system32' gibi kaçış denemeleri engellenir.",
        f"B. Sembolik Bağ Kaçış Koruması (CWE-59):",
        f"   - os.islink denetimi ile kök dışına yönlendirilen symlink'ler yakalanır.",
        f"C. Kırılmış Algoritma Engeli (CWE-328):",
        f"   - MD5 ve SHA-1 algoritmaları kesinlikle yasaklanmış ve engellenmiştir.",
        f"D. Sabit Zamanlı Kıyaslama (CWE-208):",
        f"   - hmac.compare_digest ile hem HMAC mührü hem dosya özetleri sabit zamanda karşılaştırılır.\n",
        f"3. HAFTA 15 AŞAMA 05 ENTEGRASYON VE BAŞARI DURUMU:",
        f"-------------------------------------------------------------------------------",
        f"- Hafta 15 boyunca öğrenilen CIA Triad (G99), Entropi (G100), Hash Çakışmaları (G101),",
        f"  Salt/Pepper/KDF (G102), Simetrik AES (G103) ve AEAD (G104) yetkinlikleri bu mini projede",
        f"  bütüncül bir güvenlik yazılımı olarak bir araya getirilmiştir.\n"
    ]

    with open(os.path.join(gercek_kanit_dir, "manifest_denetim_raporu.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(analiz_raporu))

    # ==========================================================================
    # 4. CLI KOMUTLARI VE ÇIKIŞLARI KANIT KAYDI
    # ==========================================================================
    cli_path = os.path.join(base_dir, "uygulama", "manifest_cli.py")
    manifest_out = os.path.join(base_dir, "ornek_veri", "sample_project_manifest.json")

    komut_kanit = [
        f"===============================================================================",
        f"GÜN 105: CLI KOMUT VE ÇIKIŞ KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"===============================================================================\n"
    ]

    # Komut 1: Manifest oluşturma ve mühürleme
    cmd1 = [sys.executable, cli_path, "--create", "--dir", test_dir, "--manifest", manifest_out, "--key", test_key, "--algo", "sha256"]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd1)}\nÇıkış Kodu: {res1.returncode}\n{res1.stdout}")

    # Komut 2: Manifest doğrulama (Temiz disk)
    cmd2 = [sys.executable, cli_path, "--verify", "--dir", test_dir, "--manifest", manifest_out, "--key", test_key]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd2)}\nÇıkış Kodu: {res2.returncode}\n{res2.stdout}")

    # Komut 3: Tahrifat simülasyonu
    cmd3 = [sys.executable, cli_path, "--tamper-sim"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd3)}\nÇıkış Kodu: {res3.returncode}\n{res3.stdout}")

    with open(os.path.join(gercek_kanit_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(komut_kanit))

    print(f"Gün 105 Gerçek Kanıtları Başarıyla Üretildi: {gercek_kanit_dir}")


if __name__ == "__main__":
    main()
