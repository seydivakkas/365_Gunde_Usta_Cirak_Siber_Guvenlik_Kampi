# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 104: Kanıt Üretici ve Doğrulama Otomasyonu.
Bu betik; birim testleri, 9 negatif kontrol senaryosunu, Two-Time Pad simülasyonunu
ve CLI komut çıktılarını çalıştırarak 'kanit/gercek/' dizini altına
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

# AEAD motoru, durum takipçisi ve güvenlik istisnalarını içe aktar
from uygulama.aead_nonce_engine import (
    AEADNonceEngine,
    StatefulNonceTracker,
    AEADEngineError,
    NonceReuseDetectedError,
    InsecureNonceLengthError,
    PredictableNonceError,
    AuthenticationTagMismatchError,
    InvalidKeyLengthError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)
# Test sınıfını içe aktar
from tests.test_aead_nonce import TestAEADNonceEngine


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dir = os.path.join(base_dir, "kanit", "gercek")
    os.makedirs(gercek_kanit_dir, exist_ok=True)

    simdi = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ==========================================================================
    # 1. BİRİM TESTLERİNİN ÇALIŞTIRILMASI VE KANIT KAYDI
    # ==========================================================================
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAEADNonceEngine)
    test_stream = io.StringIO()
    test_runner = unittest.TextTestRunner(stream=test_stream, verbosity=2)
    test_result = test_runner.run(test_suite)

    test_kanit_metni = (
        f"===============================================================================\n"
        f"GÜN 104: BİRİM TEST SONUÇLARI RAPORU\n"
        f"Tarih/Saat: {simdi}\n"
        f"Konu: AEAD (Authenticated Encryption with Associated Data) ve Nonce Yönetimi\n"
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
    negatif_json_yolu = os.path.join(base_dir, "ornek_veri", "invalid_aead_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_vakalar = json.load(f)

    negatif_rapor = [
        f"===============================================================================",
        f"GÜN 104: NEGATİF KONTROL VE ZAFİYET ENGELLEME KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"Toplam Negatif Senaryo: {len(negatif_vakalar)}",
        f"Standart: NIST SP 800-38D & RFC 5116 / RFC 5297",
        f"===============================================================================\n"
    ]

    basarili_negatifler = 0
    test_key_16 = b"1234567890abcdef"
    test_nonce_12 = b"abcdef123456"

    for vaka in negatif_vakalar:
        vid = vaka["id"]
        tanim = vaka["tanim"]
        cwe = vaka["cwe"]
        beklenen = vaka["beklenen_hata"]
        firlatilan = None
        durum = "FAIL"

        try:
            if vid == "NEG_01_NONCE_REUSE_DETECTED":
                local_tr = StatefulNonceTracker()
                AEADNonceEngine.encrypt_aead("test1", test_key_16, nonce=test_nonce_12, tracker=local_tr)
                AEADNonceEngine.encrypt_aead("test2", test_key_16, nonce=test_nonce_12, tracker=local_tr)
            elif vid == "NEG_02_INSUFFICIENT_NONCE_LENGTH":
                AEADNonceEngine.encrypt_aead("test", test_key_16, nonce=bytes(vaka["nonce_boyut"]))
            elif vid == "NEG_03_PREDICTABLE_STATIC_NONCE":
                AEADNonceEngine.encrypt_aead("test", test_key_16, nonce=bytes.fromhex(vaka["nonce_hex"]))
            elif vid == "NEG_04_AUTH_TAG_FORGERY":
                res = AEADNonceEngine.encrypt_aead("test", test_key_16)
                sahte_tag = bytes.fromhex(res.tag_hex)
                sahte_tag_bytes = bytes([sahte_tag[0] ^ 0xFF]) + sahte_tag[1:]
                AEADNonceEngine.decrypt_aead(res.ciphertext_hex, test_key_16, res.nonce_hex, sahte_tag_bytes.hex())
            elif vid == "NEG_05_AAD_METADATA_MANIPULATION":
                res = AEADNonceEngine.encrypt_aead("test", test_key_16, associated_data="admin=false")
                AEADNonceEngine.decrypt_aead(res.ciphertext_hex, test_key_16, res.nonce_hex, res.tag_hex, associated_data=vaka["sahte_aad"])
            elif vid == "NEG_06_KEY_LENGTH_INVALID":
                AEADNonceEngine.encrypt_aead("test", bytes(vaka["key_boyut"]))
            elif vid == "NEG_07_NULL_BYTE_INJECTION":
                AEADNonceEngine.encrypt_aead(vaka["zararli_veri"], test_key_16)
            elif vid == "NEG_08_OVERSIZED_PAYLOAD_DOS":
                AEADNonceEngine.encrypt_aead("Y" * vaka["boyut_bayt"], test_key_16)
            elif vid == "NEG_09_TYPE_CONFUSION":
                AEADNonceEngine.encrypt_aead("test", vaka["hatali_girdi"])
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
    # 3. GÜVENLİK ANALİZİ VE TEHDİT RAPORU
    # ==========================================================================
    analiz_raporu = [
        f"===============================================================================",
        f"GÜN 104: AEAD VE NONCE TEKRARI GÜVENLİK ANALİZİ RAPORU",
        f"Tarih/Saat: {simdi}",
        f"Analist: Seydi Eryılmaz (@seydivakkas)",
        f"===============================================================================\n",
        f"1. AEAD (AUTHENTICATED ENCRYPTION) VE AAD MİMARİSİ:",
        f"-------------------------------------------------------------------------------",
        f"- AEAD, Gizlilik (Confidentiality), Bütünlük (Integrity) ve Orijinalliği (Authenticity)",
        f"  tek bir atomik kriptografik işlemde birleştirir.",
        f"- AAD (Associated Authenticated Data): Şifrelenmeyen ancak kimlik doğrulamasına",
        f"  mühürlenen metaveridir (Paket başlıkları, kullanıcı kimlikleri, oturum numaraları).",
        f"- Saldırgan şifreli metni veya AAD'yi değiştirdiğinde HMAC/GHASH etiketi tutmaz",
        f"  ve veri çözülmeden anında reddedilir (CWE-353, CWE-345).\n",
        f"2. TWO-TIME PAD FELAKETİ (CWE-323):",
        f"-------------------------------------------------------------------------------",
        f"- CTR veya akış şifresi tabanlı modlarda (AES-GCM, ChaCha20-Poly1305), aynı anahtar",
        f"  ve aynı Nonce kullanıldığında aynı anahtar akışı (Keystream Ks) üretilir.",
        f"- C1 = P1 ⊕ Ks  ve  C2 = P2 ⊕ Ks",
        f"- C1 ⊕ C2 = (P1 ⊕ Ks) ⊕ (P2 ⊕ Ks) = P1 ⊕ P2 (Ks tamamen yok olur!)",
        f"- İki şifreli metnin XOR'u doğrudan düz metinlerin XOR'unu verir.",
        f"- Saldırgan dildeki yaygın kelimeleri (crib dragging) kaydırarak her iki metni",
        f"  anahtara hiç ihtiyaç duymadan dakikalar içinde deşifre eder.\n",
        f"3. NONCE YÖNETİMİ VE SAVUNMA STRATEJİLERİ:",
        f"-------------------------------------------------------------------------------",
        f"A. CSPRNG Rastgele Üretim (96-bit Nonce):",
        f"   - 2^96 olasılık sunar. Ancak doğum günü paradoksu (Birthday Paradox) gereği,",
        f"     aynı anahtarla ~2^48 mesaj şifrelendiğinde çakışma riski belirir. Bu nedenle anahtar rotasyonu şarttır.",
        f"B. Durum Bilgili Takip (Stateful Nonce Tracking):",
        f"   - StatefulNonceTracker mimarisi, bellekteki anahtar özeti altında kullanılan Nonce'ları",
        f"     kaydeder. Tekrar denemelerinde anında NonceReuseDetectedError fırlatır (CWE-323).",
        f"C. Deterministik SIV Modu (Synthetic IV - RFC 5297):",
        f"   - Nonce = HMAC(Key, Düz Metin || AAD)[:12]",
        f"   - Nonce rastgele üretilmez; verinin içeriğine bağlanır. Böylece Nonce asla kazara tekrar etmez;\n"
        f"     aynı metin aynı şifreyi üretir ama farklı metinler tamamen farklı anahtar akışları kullanır.\n"
    ]

    with open(os.path.join(gercek_kanit_dir, "aead_nonce_analiz_raporu.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(analiz_raporu))

    # ==========================================================================
    # 4. CLI KOMUTLARI VE ÇIKIŞLARI KANIT KAYDI
    # ==========================================================================
    cli_path = os.path.join(base_dir, "uygulama", "aead_cli.py")
    komut_kanit = [
        f"===============================================================================",
        f"GÜN 104: CLI KOMUT VE ÇIKIŞ KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"===============================================================================\n"
    ]

    # Komut 1: Nonce Takip Önbelleği Testi (CWE-323 Engeli)
    cmd1 = [sys.executable, cli_path, "--test-tracker"]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd1)}\nÇıkış Kodu: {res1.returncode}\n{res1.stdout}")

    # Komut 2: Two-Time Pad Zafiyet Simülasyonu
    cmd2 = [sys.executable, cli_path, "--simulate-nonce-reuse"]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd2)}\nÇıkış Kodu: {res2.returncode}\n{res2.stdout}")

    # Komut 3: Standart AEAD Şifreleme (AAD ile)
    cmd3 = [sys.executable, cli_path, "--encrypt", "--plaintext", "GizliFinansalVeri2026", "--key", "2b7e151628aed2a6abf7158809cf4f3c", "--aad", "user_id=104;role=auditor"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd3)}\nÇıkış Kodu: {res3.returncode}\n{res3.stdout}")

    # Çıktıdan bilgileri ayrıştır
    ct_val, n_val, tag_val = "", "", ""
    for line in res3.stdout.splitlines():
        if line.startswith("Şifreli Metin"):
            ct_val = line.split(":", 1)[1].strip()
        elif line.startswith("Nonce"):
            n_val = line.split(":", 1)[1].strip()
        elif line.startswith("Doğrulama Etiketi"):
            tag_val = line.split(":", 1)[1].strip()

    # Komut 4: Standart AEAD Şifre Çözme
    if ct_val and n_val and tag_val:
        cmd4 = [sys.executable, cli_path, "--decrypt", "--ciphertext", ct_val, "--key", "2b7e151628aed2a6abf7158809cf4f3c", "--nonce", n_val, "--tag", tag_val, "--aad", "user_id=104;role=auditor"]
        res4 = subprocess.run(cmd4, capture_output=True, text=True)
        komut_kanit.append(f"$ {' '.join(cmd4)}\nÇıkış Kodu: {res4.returncode}\n{res4.stdout}")

    # Komut 5: SIV Deterministik Mod Şifreleme
    cmd5 = [sys.executable, cli_path, "--encrypt", "--plaintext", "DeterministikGuvenlik", "--key", "2b7e151628aed2a6abf7158809cf4f3c", "--siv"]
    res5 = subprocess.run(cmd5, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd5)}\nÇıkış Kodu: {res5.returncode}\n{res5.stdout}")

    with open(os.path.join(gercek_kanit_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(komut_kanit))

    print(f"Gün 104 Gerçek Kanıtları Başarıyla Üretildi: {gercek_kanit_dir}")


if __name__ == "__main__":
    main()
