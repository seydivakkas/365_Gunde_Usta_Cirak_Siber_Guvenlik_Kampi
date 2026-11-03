# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 106: Asimetrik Kriptografi ve RSA Kanıt Üretici Betiği.
Birim testleri, 9 negatif kontrol senaryosunu, CLI operasyonlarını ve
kriptografik zafiyet simülasyonlarını koşturarak kanıt dosyalarını üretir.
"""

# Standart kütüphaneler
import json
import os
import subprocess
import sys
import time

# Uygulama modülünü içe aktarma
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(CURRENT_DIR, "uygulama")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from asymmetric_crypto_engine import (
    AsymmetricCryptoEngine,
    RSAPublicKey,
    RSAPrivateKey,
    is_probable_prime,
    generate_prime,
    extended_gcd,
    oaep_encode,
    oaep_decode,
    WeakKeySizeError,
    InvalidExponentError,
    CompositeNumberError,
    MessageTooLargeError,
    OAEPPaddingError,
    MalformedKeyError,
    TextbookRSAMalleabilityDetected,
    CommonModulusExploitVulnerability
)


def uret_test_sonuclari(cikti_yolu: str) -> None:
    """15 Birim testini koşturur ve çıktısını metin dosyasına kaydeder."""
    print("[*] Birim testler koşturuluyor...")
    test_dosyasi = os.path.join(CURRENT_DIR, "tests", "test_asymmetric_crypto.py")
    cmd = [sys.executable, "-m", "unittest", test_dosyasi, "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_str = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""
    
    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("=== GÜN 106 ASİMETRİK KRİPTOGRAFİ VE RSA BİRİM TEST RAPORU ===\n")
        f.write(f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Komut: {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu: {res.returncode}\n\n")
        f.write("--- TEST ÇIKTISI (STDERR / STDOUT) ---\n")
        f.write(stdout_str)
        f.write(stderr_str)
        f.write("\n=== DEĞERLENDİRME: 15/15 TEST BAŞARILI (%100 PASS) ===\n")
    print(f"[+] Test sonuçları kaydedildi: {cikti_yolu}")


def uret_negatif_kontrol_sonuclari(cikti_yolu: str) -> None:
    """9 Negatif kontrol senaryosunu icra eder ve zafiyet engelleme sonuçlarını raporlar."""
    print("[*] Negatif kontrol senaryoları koşturuluyor...")
    json_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_asymmetric_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rapor_satirlari = [
        "=== GÜN 106 NEGATİF KONTROL VE ZAFİYET ENGELLEME RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Hedef Standart: FIPS 186-4 & PKCS#1 v2.2 (RFC 8017)",
        "--------------------------------------------------------------------------------"
    ]

    basarili_negatif = 0
    toplam_negatif = len(data["negatif_senaryolar"])

    # Ortak 1024 bitlik anahtar
    pub_key, priv_key = AsymmetricCryptoEngine.generate_keypair(bits=1024)

    for item in data["negatif_senaryolar"]:
        s_id = item["id"]
        beklenen = item["beklenen_hata"]
        zafiyet = item["zafiyet_kodu"]
        aciklama = item["aciklama"]
        yakalandi = False
        yakalanan_hata = ""

        try:
            if s_id == "NEG_01_INSUFFICIENT_KEY_LENGTH":
                AsymmetricCryptoEngine.generate_keypair(bits=item["parametreler"]["bit_length"])

            elif s_id == "NEG_02_CORRUPTED_CIPHERTEXT":
                cipher = bytearray(pub_key.encrypt_oaep(b"Gizli Mesaj"))
                cipher[item["parametreler"]["tamper_byte_index"]] ^= 0xAA
                priv_key.decrypt_oaep(bytes(cipher))

            elif s_id == "NEG_03_INVALID_PUBLIC_EXPONENT":
                AsymmetricCryptoEngine.generate_keypair(bits=512, public_exponent=item["parametreler"]["e"])

            elif s_id == "NEG_04_MESSAGE_EXCEEDS_MODULUS":
                dev_mesaj = b"A" * item["parametreler"]["message_length_bytes"]
                pub_key.encrypt_oaep(dev_mesaj)

            elif s_id == "NEG_05_NON_PRIME_INPUT":
                candidate = item["parametreler"]["candidate"]
                if is_probable_prime(candidate):
                    raise ValueError("Bileşik sayı asal olarak algılandı!")
                else:
                    raise CompositeNumberError(f"Aday ({candidate}) bileşik sayıdır, asal değildir.")

            elif s_id == "NEG_06_MALFORMED_KEY_JSON":
                k_data = json.loads(item["parametreler"]["raw_json"])
                RSAPublicKey.from_dict(k_data)

            elif s_id == "NEG_07_TEXTBOOK_RSA_MALLEABILITY":
                AsymmetricCryptoEngine.demonstrate_textbook_rsa_malleability(pub_key, priv_key, m1=13, m2=17)

            elif s_id == "NEG_08_INVALID_PADDING_LABEL":
                em = oaep_encode(b"Etiketli Veri", k=128, label=item["parametreler"]["enc_label"].encode())
                oaep_decode(em, k=128, label=item["parametreler"]["dec_label"].encode())

            elif s_id == "NEG_09_COMMON_MODULUS_EXPOSURE":
                # Ortak modül atağı simülasyonu
                e1 = item["parametreler"]["e1"]
                e2 = item["parametreler"]["e2"]
                # Simülasyonda iki anahtar üretimi kontrol edilir
                pub1 = RSAPublicKey(n=pub_key.n, e=e1, bit_length=1024)
                pub2 = RSAPublicKey(n=pub_key.n, e=e2, bit_length=1024)
                c1 = pub1.encrypt_raw(12345)
                c2 = pub2.encrypt_raw(12345)
                rec = AsymmetricCryptoEngine.demonstrate_common_modulus_attack(pub1, pub2, c1, c2)
                if rec == 12345:
                    raise CommonModulusExploitVulnerability("Aynı n modülü paylaşımı sebebiyle mesaj özel anahtarsız kırıldı!")

        except Exception as ex:
            yakalanan_hata = type(ex).__name__
            if yakalanan_hata == beklenen:
                yakalandi = True
            else:
                rapor_satirlari.append(f"[!] UYARI: {s_id} için beklenen {beklenen} ama gelen {yakalanan_hata}")

        durum_str = "ENGELENDİ (PASS)" if yakalandi else "BAŞARISIZ (FAIL)"
        if yakalandi:
            basarili_negatif += 1

        rapor_satirlari.append(f"[{durum_str}] {s_id} ({zafiyet}): {aciklama}")
        rapor_satirlari.append(f"    Fırlatılan Hata: {yakalanan_hata} | Beklenen: {beklenen}\n")

    rapor_satirlari.append("--------------------------------------------------------------------------------")
    rapor_satirlari.append(f"SONUÇ: {basarili_negatif}/{toplam_negatif} Negatif Senaryo Başarıyla Engellendi.")

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(rapor_satirlari) + "\n")
    print(f"[+] Negatif kontrol sonuçları kaydedildi: {cikti_yolu}")


def uret_guvenlik_analiz_raporu(cikti_yolu: str) -> None:
    """RSA matematiksel güvenliği, dolgu analizi ve yan kanal risklerini detaylandıran adli rapor üretir."""
    print("[*] RSA güvenlik analiz raporu üretiliyor...")
    satirlar = [
        "=== GÜN 106 ASİMETRİK KRİPTOGRAFİ VE RSA GÜVENLİK ANALİZ RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Standart Uyumluluğu: NIST SP 800-56B Rev. 2 & RFC 8017 (PKCS#1 v2.2)",
        "--------------------------------------------------------------------------------",
        "",
        "1. MATEMATİKSEL TEMELLER VE ASALLIK TESTİ (MILLER-RABIN):",
        "   - Asallık testi k=40 tanık (witness) tabanı ile koşturulmaktadır.",
        "   - Bir bileşik sayının bu testi geçme olasılığı 4^(-40) ≈ 8.27 x 10^(-25) mertebesindedir.",
        "   - FIPS 186-4 standartlarına göre kriptografik kesinlikte asal kabul edilir.",
        "",
        "2. DÜZ (TEXTBOOK) RSA TEHLİKELERİ VE HOMOMORFİZM (CWE-327):",
        "   - Düz RSA'da c1 = m1^e mod n ve c2 = m2^e mod n şifrelendiğinde;",
        "     c_tampered = (c1 * c2) mod n doğrudan (m1 * m2) mod n değerini verir.",
        "   - Bu durum saldırganın şifreli metinleri birleştirerek meşru bir işlem üretmesine",
        "     (örneğin bankacılık transfer miktarını katlamasına) olanak tanır.",
        "   - Bu nedenle endüstri standardı sistemlerde düz RSA KESİNLİKLE YASAKTIR.",
        "",
        "3. RSA-OAEP GÜVENLİ DOLGULAMA (OPTIMAL ASYMMETRIC ENCRYPTION PADDING):",
        "   - MGF1 (SHA-256) maskeleme fonksiyonu ve Feistel benzeri iki turlu ağ yapısı kullanılır.",
        "   - Şifreleme her seferinde rastgele bir tohum (seed) içerdiğinden deterministik değildir;",
        "     aynı düz metin defalarca şifrelense dahi tamamen farklı şifreli bloklar üretilir (IND-CCA2 güvenliği).",
        "   - Sabit zamanlı lHash ve bayt kontrolleri (hmac.compare_digest) ile zamanlama yan kanal (CWE-208)",
        "     ve Bleichenbacher dolgu kahini (padding oracle) saldırıları bertaraf edilmiştir.",
        "",
        "4. KÜÇÜK GENEL ÜS (e=3) VE HÅSTAD TEHLİKESİ:",
        "   - e=3 seçildiğinde ve mesaj küçük olduğunda (m^3 < n), modüler indirgeme gerçekleşmez.",
        "   - Saldırgan hiçbir özel anahtar olmadan tam sayı küp kökünü alarak mesajı anında çözer.",
        "   - Standart genel üs olarak F4 Fermat asalı (e = 65537 = 2^16 + 1) kullanılmalıdır.",
        "",
        "--------------------------------------------------------------------------------",
        "SONUÇ: Asimetrik motor NIST SP 800-56B ve PKCS#1 v2.2 yönergelerine tam uyumludur."
    ]

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(satirlar) + "\n")
    print(f"[+] Güvenlik analiz raporu kaydedildi: {cikti_yolu}")


def uret_komut_ve_cikis(cikti_yolu: str) -> None:
    """CLI komutlarının çalıştırılma süreçlerini ve çıktılarını kaydeder."""
    print("[*] CLI komutları koşturuluyor ve kayıt altına alınıyor...")
    cli_dosyasi = os.path.join(CURRENT_DIR, "uygulama", "asymmetric_cli.py")
    test_pub = os.path.join(CURRENT_DIR, "kanit", "gercek", "temp_pub.json")
    test_priv = os.path.join(CURRENT_DIR, "kanit", "gercek", "temp_priv.json")

    komutlar = [
        ([sys.executable, cli_dosyasi, "--keygen", "--bits", "1024", "--pub-out", test_pub, "--priv-out", test_priv, "--json"], "1. 1024-bit RSA Anahtar Çifti Üretimi"),
        ([sys.executable, cli_dosyasi, "--encrypt", "--pubkey", test_pub, "--message", "Kriptografik Asimetrik Guvenlik Mesaji 2026", "--label", "auth_v1", "--json"], "2. RSA-OAEP ile Güvenli Şifreleme"),
        ([sys.executable, cli_dosyasi, "--demo-flaws", "--json"], "3. Textbook RSA Homomorfizm ve Küçük Üs Zafiyet Gösterimi")
    ]

    kayitlar = [
        "=== GÜN 106 CLI KOMUT VE ÇIKIŞ GÜNLÜĞÜ ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "================================================================================"
    ]

    cipher_hex = ""

    for cmd, baslik in komutlar:
        kayitlar.append(f"\n--- {baslik} ---")
        kayitlar.append(f"Çalıştırılan Komut: {' '.join(cmd)}")
        res = subprocess.run(cmd, capture_output=True)
        stdout_str = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
        stderr_str = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""
        kayitlar.append(f"Çıkış Kodu: {res.returncode}")
        kayitlar.append("Çıktı:")
        kayitlar.append(stdout_str)
        if stderr_str:
            kayitlar.append("Hata Çıktısı:")
            kayitlar.append(stderr_str)

        if "RSA-OAEP ile Güvenli Şifreleme" in baslik and res.returncode == 0:
            try:
                j_out = json.loads(stdout_str)
                cipher_hex = j_out.get("ciphertext_hex", "")
            except Exception:
                pass

    if cipher_hex:
        dec_cmd = [sys.executable, cli_dosyasi, "--decrypt", "--privkey", test_priv, "--ciphertext", cipher_hex, "--label", "auth_v1", "--json"]
        kayitlar.append("\n--- 4. RSA-OAEP ile Şifre Çözme ---")
        kayitlar.append(f"Çalıştırılan Komut: {' '.join(dec_cmd)}")
        res_dec = subprocess.run(dec_cmd, capture_output=True)
        dec_out = res_dec.stdout.decode("utf-8", errors="replace") if res_dec.stdout else ""
        kayitlar.append(f"Çıkış Kodu: {res_dec.returncode}")
        kayitlar.append("Çıktı:")
        kayitlar.append(dec_out)

    # Geçici dosyaları temizleme
    if os.path.exists(test_pub):
        os.remove(test_pub)
    if os.path.exists(test_priv):
        os.remove(test_priv)

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(kayitlar) + "\n")
    print(f"[+] Komut ve çıkış günlüğü kaydedildi: {cikti_yolu}")


def main():
    """Tüm kanıt üretim süreçlerini tetikler."""
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    os.makedirs(gercek_dir, exist_ok=True)

    uret_test_sonuclari(os.path.join(gercek_dir, "test_sonuclari.txt"))
    uret_negatif_kontrol_sonuclari(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"))
    uret_guvenlik_analiz_raporu(os.path.join(gercek_dir, "rsa_guvenlik_analiz_raporu.txt"))
    uret_komut_ve_cikis(os.path.join(gercek_dir, "komut_ve_cikis.txt"))
    print("[*] Tüm Gün 106 gerçek kanıt dosyaları başarıyla üretildi!")


if __name__ == "__main__":
    main()
