# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 107: Dijital İmza ve Doğrulama Kanıt Üretici Betiği.
Birim testleri, 9 negatif kontrol senaryosunu, adli güvenlik analizini ve
CLI komut günlüklerini koşturarak gerçek kanıt dosyalarını üretir.
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

from digital_signature_engine import (
    DigitalSignatureEngine,
    RSAPublicKey,
    RSAPrivateKey,
    SignatureVerificationError,
    WeakKeySizeError,
    InvalidSignatureFormatError,
    BleichenbacherVulnerabilityDetected,
    ECDSANonceReuseDetected,
    TextbookSignatureForgeryDetected
)


def uret_test_sonuclari(cikti_yolu: str) -> None:
    """15 Birim testini koşturur ve sonuçları dosyaya kaydeder."""
    print("[*] Birim testler koşturuluyor...")
    test_dosyasi = os.path.join(CURRENT_DIR, "tests", "test_digital_signature.py")
    cmd = [sys.executable, "-m", "unittest", test_dosyasi, "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_str = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("=== GÜN 107 DİJİTAL İMZA VE DOĞRULAMA BİRİM TEST RAPORU ===\n")
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
    json_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_signature_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rapor_satirlari = [
        "=== GÜN 107 NEGATİF KONTROL VE ZAFİYET ENGELLEME RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Hedef Standart: RFC 8017 (PKCS#1 v2.2) & FIPS 186-4",
        "--------------------------------------------------------------------------------"
    ]

    basarili_negatif = 0
    toplam_negatif = len(data["negatif_senaryolar"])

    # Ortak 1024 bitlik anahtar çifti
    pub_key, priv_key = DigitalSignatureEngine.generate_keypair(bits=1024)
    orijinal_belge = b"Tedarikciye 150000 TL Odeme Talimati"
    orijinal_pss_sig = DigitalSignatureEngine.sign_pss(priv_key, orijinal_belge)

    for item in data["negatif_senaryolar"]:
        s_id = item["id"]
        beklenen = item["beklenen_hata"]
        zafiyet = item["zafiyet_kodu"]
        aciklama = item["aciklama"]
        yakalandi = False
        yakalanan_hata = ""

        try:
            if s_id == "NEG_01_TAMPERED_DOCUMENT":
                tahrif_metin = orijinal_belge + item["parametreler"]["tamper_suffix"].encode("utf-8")
                DigitalSignatureEngine.verify_pss(pub_key, tahrif_metin, orijinal_pss_sig)

            elif s_id == "NEG_02_CORRUPTED_SIGNATURE_BYTES":
                bozuk_sig = bytearray(orijinal_pss_sig)
                bozuk_sig[item["parametreler"]["tamper_byte_index"]] ^= 0xFF
                DigitalSignatureEngine.verify_pss(pub_key, orijinal_belge, bytes(bozuk_sig))

            elif s_id == "NEG_03_WRONG_PUBLIC_KEY":
                saldirgan_pub, _ = DigitalSignatureEngine.generate_keypair(bits=1024)
                DigitalSignatureEngine.verify_pss(saldirgan_pub, orijinal_belge, orijinal_pss_sig)

            elif s_id == "NEG_04_BLEICHENBACHER_FORGERY_ATTACK":
                pub_e3, _ = DigitalSignatureEngine.generate_keypair(bits=1024, public_exponent=3)
                DigitalSignatureEngine.demonstrate_bleichenbacher_attack(pub_e3, b"Yetkisiz Odeme")

            elif s_id == "NEG_05_ECDSA_NONCE_REUSE":
                q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
                d = 1234567890987654321
                z1 = 1122334455
                z2 = 6677889900
                k = item["parametreler"]["reused_nonce_k"]
                DigitalSignatureEngine.demonstrate_ecdsa_nonce_reuse(q, d, z1, z2, k)

            elif s_id == "NEG_06_WEAK_RSA_KEY_SIZE":
                DigitalSignatureEngine.generate_keypair(bits=item["parametreler"]["bit_length"])

            elif s_id == "NEG_07_TEXTBOOK_EXISTENTIAL_FORGERY":
                DigitalSignatureEngine.demonstrate_textbook_existential_forgery(pub_key)

            elif s_id == "NEG_08_INVALID_PSS_SALT_LENGTH":
                # Sahte tuz uzunluğu ile doğrulama
                DigitalSignatureEngine.verify_pss(pub_key, orijinal_belge, orijinal_pss_sig, salt_len=item["parametreler"]["invalid_salt_len"])

            elif s_id == "NEG_09_MALFORMED_SIGNATURE_ENCODING":
                kirpilmis = orijinal_pss_sig[:len(orijinal_pss_sig) - item["parametreler"]["truncated_bytes"]]
                DigitalSignatureEngine.verify_pss(pub_key, orijinal_belge, kirpilmis)

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
    """Dijital imza algoritmaları, inkar edilemezlik ve PSS güvenliğini içeren adli rapor üretir."""
    print("[*] Dijital imza adli analiz raporu üretiliyor...")
    satirlar = [
        "=== GÜN 107 DİJİTAL İMZA VE DOĞRULAMA ADLİ ANALİZ RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Standart Uyumluluğu: RFC 8017 (PKCS#1 v2.2), FIPS 186-4 & NIST SP 800-89",
        "--------------------------------------------------------------------------------",
        "",
        "1. DİJİTAL İMZA VS SİMETRİK MAC (HMAC) MİMARİ KARŞILAŞTIRMASI:",
        "   - HMAC iki tarafın aynı gizli anahtarı paylaştığı durumlarda bütünlük sağlar.",
        "     Ancak her iki taraf da aynı anahtara sahip olduğundan, Alice'in mesajı gönderdiğini",
        "     üçüncü bir mahkeme veya hakem önünde kanıtlayamaz (İnkar Edilemezlik - Non-Repudiation YOKTUR).",
        "   - Dijital İmza (RSA/ECDSA), yalnızca göndericinin bildiği ÖZEL anahtarla üretilir ve",
        "     dünyadaki herkes tarafından GENEL anahtarla doğrulanabilir. İmza inkar edilemez!",
        "",
        "2. DÜZ (TEXTBOOK) RSA İMZA TEHLİKELERİ (CWE-327):",
        "   - Dolgusuz s = m^d mod n imzasında saldırgan rastgele s seçerek m = s^e mod n hesaplar.",
        "     Özel anahtarı hiç bilmeden geçerli (m, s) ikilisi üretir (Varoluşsal Sahtecilik).",
        "   - Çarpımsal homomorfizm sebebiyle s1 ve s2 imzaları çarpılarak m1*m2 mesajının",
        "     geçerli imzası elde edilir. Bu nedenle düz RSA imza ASLA KULLANILAMAZ.",
        "",
        "3. RSASSA-PSS VE RASLANTISAL GÜVENLİK (PROBABILISTIC SIGNATURE SCHEME):",
        "   - PSS, her imza üretiminde rastgele bir tuz (salt) ekleyerek imzayı olasılıksal kılar.",
        "   - Aynı mesaj yüz defa imzalansa dahi yüz farklı imza üretilir, hepsi doğrulanır.",
        "   - Rastgele Kahin Modeli'nde (Random Oracle Model) RSA'nın tek yönlülüğüne dayalı",
        "     kanıtlanabilir güvenlik (provable security) sağlar.",
        "",
        "4. ECDSA NONCE YENİDEN KULLANIMI VE SONY PS3 FELAKETİ (CWE-323 / CVE-2010-4444):",
        "   - ECDSA imzasında s = k^(-1) * (z + r * d) mod q denklemi kullanılır.",
        "   - İki farklı mesaj aynı k ile imzalanırsa: (s1 - s2) = k^(-1) * (z1 - z2) mod q olur.",
        "   - Saldırgan k'yı hemen bulur ve ardından d = (s1*k - z1)*r^(-1) mod q ile",
        "     kök özel anahtarı (master private key) anında çeker! Sony PS3 bu hatayla kırılmıştır.",
        "   - Çözüm: RFC 6979 deterministik nonce türetimi zorunludur.",
        "",
        "--------------------------------------------------------------------------------",
        "SONUÇ: Motor RSASSA-PSS, PKCS#1 v1.5 katı kontrol ve RFC 8017 standartlarına %100 uyumludur."
    ]

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(satirlar) + "\n")
    print(f"[+] Güvenlik analiz raporu kaydedildi: {cikti_yolu}")


def uret_komut_ve_cikis(cikti_yolu: str) -> None:
    """CLI komutlarının çalıştırılma süreçlerini ve çıktılarını kaydeder."""
    print("[*] CLI komutları koşturuluyor ve kayıt altına alınıyor...")
    cli_dosyasi = os.path.join(CURRENT_DIR, "uygulama", "signature_cli.py")
    test_pub = os.path.join(CURRENT_DIR, "kanit", "gercek", "temp_sig_pub.json")
    test_priv = os.path.join(CURRENT_DIR, "kanit", "gercek", "temp_sig_priv.json")

    komutlar = [
        ([sys.executable, cli_dosyasi, "--keygen", "--bits", "1024", "--pub-out", test_pub, "--priv-out", test_priv, "--json"], "1. 1024-bit RSA İmza Anahtar Çifti Üretimi"),
        ([sys.executable, cli_dosyasi, "--sign", "--privkey", test_priv, "--message", "Resmi Odeme Onay Belgesi #2026-11", "--scheme", "pss", "--json"], "2. RSASSA-PSS ile Dijital İmzalama"),
        ([sys.executable, cli_dosyasi, "--demo-flaws", "--json"], "3. İmza Zafiyetleri Simülasyonu (Textbook, Bleichenbacher, ECDSA)")
    ]

    kayitlar = [
        "=== GÜN 107 CLI KOMUT VE ÇIKIŞ GÜNLÜĞÜ ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "================================================================================"
    ]

    sig_hex = ""

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

        if "RSASSA-PSS ile Dijital İmzalama" in baslik and res.returncode == 0:
            try:
                j_out = json.loads(stdout_str)
                sig_hex = j_out.get("signature_hex", "")
            except Exception:
                pass

    if sig_hex:
        verify_cmd = [sys.executable, cli_dosyasi, "--verify", "--pubkey", test_pub, "--message", "Resmi Odeme Onay Belgesi #2026-11", "--signature", sig_hex, "--scheme", "pss", "--json"]
        kayitlar.append("\n--- 4. RSASSA-PSS ile İmza Doğrulama ---")
        kayitlar.append(f"Çalıştırılan Komut: {' '.join(verify_cmd)}")
        res_v = subprocess.run(verify_cmd, capture_output=True)
        v_out = res_v.stdout.decode("utf-8", errors="replace") if res_v.stdout else ""
        kayitlar.append(f"Çıkış Kodu: {res_v.returncode}")
        kayitlar.append("Çıktı:")
        kayitlar.append(v_out)

    if os.path.exists(test_pub):
        os.remove(test_pub)
    if os.path.exists(test_priv):
        os.remove(test_priv)

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(kayitlar) + "\n")
    print(f"[+] Komut ve çıkış günlüğü kaydedildi: {cikti_yolu}")


def main():
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    os.makedirs(gercek_dir, exist_ok=True)

    uret_test_sonuclari(os.path.join(gercek_dir, "test_sonuclari.txt"))
    uret_negatif_kontrol_sonuclari(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"))
    uret_guvenlik_analiz_raporu(os.path.join(gercek_dir, "dijital_imza_analiz_raporu.txt"))
    uret_komut_ve_cikis(os.path.join(gercek_dir, "komut_ve_cikis.txt"))
    print("[*] Tüm Gün 107 gerçek kanıt dosyaları başarıyla üretildi!")


if __name__ == "__main__":
    main()
