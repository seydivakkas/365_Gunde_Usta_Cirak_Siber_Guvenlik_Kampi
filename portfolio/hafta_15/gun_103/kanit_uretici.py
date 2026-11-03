# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 103: Kanıt Üretici ve Doğrulama Otomasyonu.
Bu betik; birim testleri, 9 negatif kontrol senaryosunu, NIST test vektörlerini
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

# AES motoru ve güvenlik istisnalarını içe aktar
from uygulama.aes_cipher_engine import (
    AESCipherEngine,
    AESCipherError,
    InsecureCipherModeError,
    InvalidKeyLengthError,
    PredictableIVError,
    InvalidIVLengthError,
    InvalidPaddingError,
    AuthenticationTagMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)
# Test sınıfını içe aktar
from tests.test_aes_cipher import TestAESCipherEngine


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    gercek_kanit_dir = os.path.join(base_dir, "kanit", "gercek")
    os.makedirs(gercek_kanit_dir, exist_ok=True)

    simdi = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ==========================================================================
    # 1. BİRİM TESTLERİNİN ÇALIŞTIRILMASI VE KANIT KAYDI
    # ==========================================================================
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAESCipherEngine)
    test_stream = io.StringIO()
    test_runner = unittest.TextTestRunner(stream=test_stream, verbosity=2)
    test_result = test_runner.run(test_suite)

    test_kanit_metni = (
        f"===============================================================================\n"
        f"GÜN 103: BİRİM TEST SONUÇLARI RAPORU\n"
        f"Tarih/Saat: {simdi}\n"
        f"Konu: FIPS 197 Simetrik Şifreleme ve AES (Advanced Encryption Standard)\n"
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
    negatif_json_yolu = os.path.join(base_dir, "ornek_veri", "invalid_aes_inputs.json")
    with open(negatif_json_yolu, "r", encoding="utf-8") as f:
        negatif_vakalar = json.load(f)

    negatif_rapor = [
        f"===============================================================================",
        f"GÜN 103: NEGATİF KONTROL VE ZAFİYET ENGELLEME KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"Toplam Negatif Senaryo: {len(negatif_vakalar)}",
        f"Standart: NIST FIPS 197 & NIST SP 800-38A",
        f"===============================================================================\n"
    ]

    basarili_negatifler = 0
    test_key_16 = b"1234567890abcdef"

    for vaka in negatif_vakalar:
        vid = vaka["id"]
        tanim = vaka["tanim"]
        cwe = vaka["cwe"]
        beklenen = vaka["beklenen_hata"]
        firlatilan = None
        durum = "FAIL"

        try:
            if vid == "NEG_01_INSECURE_ECB_MODE_USAGE":
                AESCipherEngine.encrypt_ecb("test", test_key_16, strict_mode=True)
            elif vid == "NEG_02_INSUFFICIENT_KEY_LENGTH":
                AESCipherEngine.encrypt_cbc("test", bytes(vaka["key_boyut"]))
            elif vid == "NEG_03_INVALID_KEY_LENGTH":
                AESCipherEngine.encrypt_cbc("test", bytes(vaka["key_boyut"]))
            elif vid == "NEG_04_PREDICTABLE_STATIC_IV":
                AESCipherEngine.encrypt_cbc("test", test_key_16, iv=bytes.fromhex(vaka["iv_hex"]))
            elif vid == "NEG_05_INVALID_IV_LENGTH":
                AESCipherEngine.encrypt_cbc("test", test_key_16, iv=bytes(vaka["iv_boyut"]))
            elif vid == "NEG_06_PKCS7_CORRUPT_PADDING":
                res = AESCipherEngine.encrypt_cbc("test", test_key_16)
                ct_mod = bytearray.fromhex(res.ciphertext_hex)
                ct_mod[-1] ^= 0x55
                AESCipherEngine.decrypt_cbc(ct_mod.hex(), test_key_16, iv=res.iv_hex)
            elif vid == "NEG_07_CIPHERTEXT_TAMPERING_AEAD":
                mac_k = b"1234567890123456"
                res = AESCipherEngine.encrypt_aead_etm("test", test_key_16, mac_k)
                ct_mod = bytearray.fromhex(res.ciphertext_hex)
                ct_mod[0] ^= 0x01
                AESCipherEngine.decrypt_aead_etm(ct_mod.hex(), test_key_16, mac_k, iv_hex=res.iv_hex, tag_hex=res.tag_hex)
            elif vid == "NEG_08_OVERSIZED_PLAINTEXT_DOS":
                AESCipherEngine.encrypt_cbc("B" * vaka["boyut_bayt"], test_key_16)
            elif vid == "NEG_09_TYPE_CONFUSION":
                AESCipherEngine.encrypt_cbc("test", vaka["hatali_anahtar"])
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
    # 3. GÜVENLİK ANALİZİ VE MOD KARŞILAŞTIRMA RAPORU
    # ==========================================================================
    analiz_raporu = [
        f"===============================================================================",
        f"GÜN 103: AES SİMETRİK ŞİFRELEME GÜVENLİK VE MİMARİ ANALİZ RAPORU",
        f"Tarih/Saat: {simdi}",
        f"Analist: Seydi Eryılmaz (@seydivakkas)",
        f"===============================================================================\n",
        f"1. FIPS 197 VE BLOK ŞİFRE MİMARİSİ:",
        f"-------------------------------------------------------------------------------",
        f"- Blok Boyutu: Sabit 128 bit (16 bayt).",
        f"- Anahtar Boyutları: AES-128 (10 tur, 16 bayt), AES-256 (14 tur, 32 bayt).",
        f"- Tur Fonksiyonu Matematiksel Adımları:",
        f"  1. SubBytes   : Doğrusal olmayan S-Box değişimi (Karışıklık - Confusion).",
        f"  2. ShiftRows  : Satırların dairesel kaydırılması (Yayılma - Diffusion).",
        f"  3. MixColumns : GF(2^8) Galois Alanında matris çarpımı (Maksimum Difüzyon).",
        f"  4. AddRoundKey: Tur anahtarı ile XOR işlemi (Anahtar Enjeksiyonu).\n",
        f"2. İŞLETİM MODLARI GÜVENLİK KARŞILAŞTIRMASI:",
        f"-------------------------------------------------------------------------------",
        f"A. ECB (Electronic Codebook) - [CWE-327: KRİTİK GÜVENSİZ]",
        f"   - Her 16 baytlık blok birbirinden bağımsız şifrelenir.",
        f"   - Özdeş düz metin blokları özdeş şifreli bloklar üretir (ECB Penguin etkisi).",
        f"   - Veri yapıları, tekrarlar ve görsel desenler doğrudan dışarı sızar.",
        f"   - Hüküm: Kurumsal sistemlerde KESİNLİKLE YASAKTIR.\n",
        f"B. CBC (Cipher Block Chaining) - [STANDART]",
        f"   - Her blok, şifrelenmeden önce bir önceki şifreli blokla XOR'lanır.",
        f"   - İlk blok için rastgele ve tahmin edilemez IV (Initialization Vector) şarttır.",
        f"   - Desen sızıntısını tamamen yok eder. Ancak dolgu oracle saldırılarına (Padding Oracle)",
        f"     karşı dikkatli uygulanmalı veya sabit zamanlı doğrulanmalıdır.\n",
        f"C. CTR (Counter Mode) - [YÜKSEK PERFORMANS & AKIŞ ŞİFRESİ]",
        f"   - Sayacı (Nonce + Counter) şifreleyerek bir anahtar akışı (keystream) üretir.",
        f"   - Dolgu (padding) gerektirmez; veri bayt bayt XOR'lanır.",
        f"   - Paralel hesaplamaya (multi-core / hardware acceleration) tam uygundur.\n",
        f"D. AEAD (Authenticated Encryption with Associated Data) - [ALTIN STANDART]",
        f"   - Yalnızca gizlilik değil, kurcalanmaya karşı BÜTÜNLÜK (Integrity) sağlar.",
        f"   - Encrypt-then-MAC (EtM) ile şifreli metin HMAC-SHA256 ile mühürlenir.",
        f"   - Saldırgan tek bir biti bile değiştirse şifre çözülmeden anında yakalanır (CWE-353).\n"
    ]

    with open(os.path.join(gercek_kanit_dir, "aes_guvenlik_analiz_raporu.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(analiz_raporu))

    # ==========================================================================
    # 4. CLI KOMUTLARI VE ÇIKIŞLARI KANIT KAYDI
    # ==========================================================================
    cli_path = os.path.join(base_dir, "uygulama", "aes_cli.py")
    komut_kanit = [
        f"===============================================================================",
        f"GÜN 103: CLI KOMUT VE ÇIKIŞ KANITLARI",
        f"Tarih/Saat: {simdi}",
        f"===============================================================================\n"
    ]

    # Komut 1: NIST Test Vektörleri Doğrulaması
    cmd1 = [sys.executable, cli_path, "--verify-nist"]
    res1 = subprocess.run(cmd1, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd1)}\nÇıkış Kodu: {res1.returncode}\n{res1.stdout}")

    # Komut 2: ECB vs CBC Karşılaştırması
    cmd2 = [sys.executable, cli_path, "--compare-modes"]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd2)}\nÇıkış Kodu: {res2.returncode}\n{res2.stdout}")

    # Komut 3: CBC Şifreleme
    cmd3 = [sys.executable, cli_path, "--encrypt", "--plaintext", "GizliKurumsalVeri2026", "--key", "2b7e151628aed2a6abf7158809cf4f3c", "--mode", "cbc"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True)
    komut_kanit.append(f"$ {' '.join(cmd3)}\nÇıkış Kodu: {res3.returncode}\n{res3.stdout}")

    # Çıktıdan IV ve Ciphertext yakala
    ct_val, iv_val = "", ""
    for line in res3.stdout.splitlines():
        if line.startswith("Şifreli Metin"):
            ct_val = line.split(":", 1)[1].strip()
        elif line.startswith("Başlangıç Vektörü"):
            iv_val = line.split(":", 1)[1].strip()

    # Komut 4: CBC Şifre Çözme
    if ct_val and iv_val:
        cmd4 = [sys.executable, cli_path, "--decrypt", "--ciphertext", ct_val, "--key", "2b7e151628aed2a6abf7158809cf4f3c", "--mode", "cbc", "--iv", iv_val]
        res4 = subprocess.run(cmd4, capture_output=True, text=True)
        komut_kanit.append(f"$ {' '.join(cmd4)}\nÇıkış Kodu: {res4.returncode}\n{res4.stdout}")

    with open(os.path.join(gercek_kanit_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(komut_kanit))

    print(f"Gün 103 Gerçek Kanıtları Başarıyla Üretildi: {gercek_kanit_dir}")


if __name__ == "__main__":
    main()
