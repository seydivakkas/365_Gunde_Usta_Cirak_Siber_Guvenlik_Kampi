# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 102: Kanıt Üretici ve Doğrulama Otomasyonu.
Bu betik; birim testleri, negatif kontrol senaryolarını, CLI komutlarını
ve güvenlik analizlerini yürüterek 'kanit/gercek/' dizini altına
resmî denetim kanıtlarını kaydeder.
"""

# Birim test çalıştırma kütüphanesi
import unittest
# Metin akışı yönetimi
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

# Ana çalışma dizinini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Parola saklama motoru bileşenlerini içe aktar
from uygulama.secure_password_vault import (
    PasswordHasher,
    PasswordSecurityConfig,
    PasswordVaultError,
    UnsaltedHashError,
    InsufficientIterationsError,
    InsecureSaltLengthError,
    PredictableSaltError,
    PasswordVerificationMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)
# Test sınıfını içe aktar
from tests.test_secure_password_vault import TestSecurePasswordVault


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    # Temel dizin yollarını belirle
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Gerçek kanıt dizini
    gercek_kanit_dir = os.path.join(base_dir, "kanit", "gercek")
    # Dizin yoksa oluştur
    os.makedirs(gercek_kanit_dir, exist_ok=True)

    # Güncel zaman damgası al
    simdi = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ==========================================================================
    # 1. BİRİM TESTLERİNİN ÇALIŞTIRILMASI VE KANIT KAYDI
    # ==========================================================================
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurePasswordVault)
    test_stream = io.StringIO()
    test_runner = unittest.TextTestRunner(stream=test_stream, verbosity=2)
    test_result = test_runner.run(test_suite)

    test_kanit_metni = (
        f"===============================================================================\n"
        f"GÜN 102: BİRİM TEST SONUÇLARI RAPORU\n"
        f"Tarih/Saat: {simdi}\n"
        f"Konu: Salt, Pepper ve KDF Tabanlı Güvenli Parola Saklama\n"
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
    negatif_json_yolu = os.path.join(base_dir, "ornek_veri", "invalid_password_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_vakalar = json.load(f)

    negatif_rapor = [
        f"===============================================================================",
        f"GÜN 102: NEGATİF KONTROL VE ZAFİYET ENGELLEME KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"Toplam Negatif Senaryo: {len(negatif_vakalar)}",
        f"Standart: OWASP Password Storage Cheat Sheet & NIST SP 800-132",
        f"===============================================================================\n"
    ]

    basarili_negatifler = 0
    for vaka in negatif_vakalar:
        vaka_id = vaka["id"]
        tanim = vaka["tanim"]
        cwe = vaka["cwe"]
        beklenen = vaka["beklenen_hata"]
        firlatilan = None
        durum = "FAIL"

        try:
            if vaka_id == "NEG_01_UNSALTED_HASH_STORAGE":
                PasswordHasher.parse_record(vaka["hash_formati"])
            elif vaka_id == "NEG_02_INSUFFICIENT_ITERATIONS":
                PasswordHasher.hash_password("parola123", iterations=vaka["iterasyon"])
            elif vaka_id == "NEG_03_SHORT_SALT_LENGTH":
                PasswordHasher.generate_salt(vaka["salt_bayt"])
            elif vaka_id == "NEG_04_PREDICTABLE_SALT_VALUE":
                PasswordHasher.hash_password("parola123", salt=vaka["salt_degeri"].encode("utf-8"))
            elif vaka_id == "NEG_05_PEPPER_MISMATCH_VERIFY":
                kayit = PasswordHasher.hash_password("parola123", pepper=b"DOGRU_BIBER")
                PasswordHasher.verify_password("parola123", kayit.tam_format, pepper=vaka["sahte_pepper"].encode("utf-8"), strict_mode=True)
            elif vaka_id == "NEG_06_PASSWORD_MISMATCH_VERIFY":
                kayit = PasswordHasher.hash_password("DogruParola2026!")
                PasswordHasher.verify_password(vaka["yanlis_parola"], kayit.tam_format, strict_mode=True)
            elif vaka_id == "NEG_07_NULL_BYTE_INJECTION":
                PasswordHasher.hash_password(vaka["parola"])
            elif vaka_id == "NEG_08_OVERSIZED_PASSWORD_DOS":
                buyuk = "Z" * vaka["boyut_bayt"]
                PasswordHasher.hash_password(buyuk)
            elif vaka_id == "NEG_09_TYPE_CONFUSION":
                PasswordHasher.hash_password(vaka["parola"])
        except Exception as exc:
            firlatilan = type(exc).__name__
            if firlatilan == beklenen:
                durum = "PASS (ENGELLENDİ)"
                basarili_negatifler += 1
            else:
                durum = f"FAIL (Beklenen: {beklenen}, Fırlatılan: {firlatilan})"

        negatif_rapor.append(f"[{vaka_id}]")
        negatif_rapor.append(f"  Tanım         : {tanim}")
        negatif_rapor.append(f"  Güvenlik Eşiği: {cwe}")
        negatif_rapor.append(f"  Beklenen Hata : {beklenen}")
        negatif_rapor.append(f"  Yakalana Hata : {firlatilan}")
        negatif_rapor.append(f"  Sonuç         : {durum}\n")

    negatif_rapor.append(f"ÖZET: {basarili_negatifler}/{len(negatif_vakalar)} Negatif Kontrol Başarıyla Doğrulandı.")
    with open(os.path.join(gercek_kanit_dir, "negatif_kontrol_sonuclari.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(negatif_rapor))

    # ==========================================================================
    # 3. GÜVENLİK ANALİZİ VE SIZINTI DEĞERLENDİRME RAPORU
    # ==========================================================================
    analiz_raporu = [
        f"===============================================================================",
        f"GÜN 102: KURUMSAL PAROLA SAKLAMA GÜVENLİK VE TEHDİT ANALİZİ RAPORU",
        f"Tarih/Saat: {simdi}",
        f"Analist: Seydi Eryılmaz (@seydivakkas)",
        f"===============================================================================\n",
        f"1. TEHDİT MODELİ VE SAVUNMA MEKANİZMALARI:",
        f"-------------------------------------------------------------------------------",
        f"A. Gökkuşağı Tabloları (Rainbow Tables) Savunması: [TUZ (SALT)]",
        f"   - Mekanizma: 128-bit (16 bayt) kriptografik rastgele tuz secrets.token_bytes() ile üretilir.",
        f"   - Etki: İki kullanıcı aynı parolayı kullansa bile hash özetleri tamamen farklıdır.",
        f"   - Önlenen Zafiyet: CWE-759 (Use of a One-Way Hash without a Salt).",
        f"   - Önceden hesaplanmış tersine çevirme tablolarını (precomputed hashes) geçersiz kılar.\n",
        f"B. Çevrimdışı Kaba Kuvvet ve GPU Kırma Savunması: [KDF İTERASYONU]",
        f"   - Mekanizma: PBKDF2-HMAC-SHA256 algoritması ve minimum 100.000 iterasyon.",
        f"   - Etki: Tek bir parola denemesinin işlemci maliyeti ~40-60 ms seviyesine çıkarılır.",
        f"   - Önlenen Zafiyet: CWE-916 (Insufficient Computational Effort).",
        f"   - GPU kümelerinin saniyede milyarlarca parola deneme kabiliyeti boğulur.\n",
        f"C. Veritabanı Sızıntısında Çevrimdışı Sözlük Koruması: [BİBER (PEPPER)]",
        f"   - Mekanizma: Biber veritabanında ASLA saklanmaz. HSM/KMS veya izole ortamda tutulur.",
        f"   - Etki: SQL Injection veya disk hırsızlığı ile veritabanı sızsa dahi, saldırgan",
        f"     biber anahtarını bilmediği için tuzlu hashleri kırmak üzere çevrimdışı iş başlatamaz.",
        f"   - Önlenen Zafiyet: CWE-345 / Sistem İzolasyonu Güvencesi.\n",
        f"D. Zamanlama Analizi Saldırıları (Timing Attacks): [SABİT ZAMANLI KIYAS]",
        f"   - Mekanizma: hmac.compare_digest() ile sabit zamanlı doğrulama.",
        f"   - Etki: İlk byte uyuşmazlığında hemen dönen '==' işleci engellenir; süre sabittir.",
        f"   - Önlenen Zafiyet: CWE-208 (Observable Timing Discrepancy).\n",
        f"2. ESKİ HASH FORMATLARI RİSK TABLOSU:",
        f"-------------------------------------------------------------------------------",
        f"MD5 (32 hex)        : KRİTİK GÜVENSİZ -> Saniyede 100+ milyar deneme -> DERHAL TERK EDİLMELİ",
        f"SHA-1 (40 hex)      : KRİTİK GÜVENSİZ -> LinkedIn 2012 sızıntısı örneği -> TERK EDİLMELİ",
        f"Düz SHA-256 (64 hex): YÜKSEK RİSKLİ   -> Hızlı hash KDF değildir, GPU ile kırılabilir",
        f"PBKDF2-HMAC-SHA256  : GÜVENLİ (NIST SP 800-132, RFC 8018) -> TAVSİYE EDİLEN KURUMSAL MİMARİ\n"
    ]

    with open(os.path.join(gercek_kanit_dir, "parola_guvenlik_analiz_raporu.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(analiz_raporu))

    # ==========================================================================
    # 4. CLI KOMUTLARI VE ÇIKIŞLARI KANIT KAYDI
    # ==========================================================================
    cli_path = os.path.join(base_dir, "uygulama", "vault_cli.py")
    komut_kanit = [
        f"===============================================================================",
        f"GÜN 102: CLI KOMUT VE ÇIKIŞ KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"===============================================================================\n"
    ]

    # Komut 1: Hash üretimi
    cmd1 = [sys.executable, cli_path, "--hash", "--password", "SuperGuvenli2026!", "--pepper", "HSM_KMS_BIBER_ANAHTARI", "--iterations", "100000"]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd1)}\nÇıkış Kodu: {res1.returncode}\n{res1.stdout}")

    # Hash kaydını yakala
    record_line = ""
    for line in res1.stdout.splitlines():
        if line.startswith("Tam Kayıt"):
            record_line = line.split(":", 1)[1].strip()

    # Komut 2: Doğrulama
    if record_line:
        cmd2 = [sys.executable, cli_path, "--verify", "--password", "SuperGuvenli2026!", "--record", record_line, "--pepper", "HSM_KMS_BIBER_ANAHTARI"]
        res2 = subprocess.run(cmd2, capture_output=True, text=True)
        komut_kanit.append(f"$ {' '.join(cmd2)}\nÇıkış Kodu: {res2.returncode}\n{res2.stdout}")

    # Komut 3: Eski hash tespiti (MD5)
    cmd3 = [sys.executable, cli_path, "--detect-legacy", "--hash-str", "5d41402abc4b2a76b9719d911017c592"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd3)}\nÇıkış Kodu: {res3.returncode}\n{res3.stdout}")

    # Komut 4: Veritabanı sızıntısı simülasyonu
    cmd4 = [sys.executable, cli_path, "--leak-test"]
    res4 = subprocess.run(cmd4, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd4)}\nÇıkış Kodu: {res4.returncode}\n{res4.stdout}")

    with open(os.path.join(gercek_kanit_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(komut_kanit))

    print(f"Gün 102 Gerçek Kanıtları Başarıyla Üretildi: {gercek_kanit_dir}")


if __name__ == "__main__":
    main()
