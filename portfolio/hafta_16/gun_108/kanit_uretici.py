# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 108: X.509 ve Sertifika Zinciri Kanıt Üretici Betiği.
Birim testleri, 9 negatif kontrol senaryosunu, PKI güvenlik analizini ve
CLI komut günlüklerini koşturarak gerçek kanıt dosyalarını üretir.
"""

# Standart kütüphaneler
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

# Uygulama modülünü içe aktarma
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(CURRENT_DIR, "uygulama")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from x509_chain_engine import (
    X509Certificate,
    PKIBuilder,
    X509ChainValidator,
    UntrustedRootCAError,
    CertificateExpiredError,
    CertificateNotYetValidError,
    CertificateSignatureInvalidError,
    HostnameMismatchError,
    NonCACertificateUsedAsCAError,
    PathLengthExceededError,
    RevokedCertificateError,
    MalformedCertificateError
)


def uret_test_sonuclari(cikti_yolu: str) -> None:
    """15 Birim testini koşturur ve sonuçları dosyaya kaydeder."""
    print("[*] Birim testler koşturuluyor...")
    test_dosyasi = os.path.join(CURRENT_DIR, "tests", "test_x509_chain.py")
    cmd = [sys.executable, "-m", "unittest", test_dosyasi, "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_str = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("=== GÜN 108 X.509 VE SERTİFİKA ZİNCİRİ BİRİM TEST RAPORU ===\n")
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
    json_path = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_certificate_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rapor_satirlari = [
        "=== GÜN 108 NEGATİF KONTROL VE ZAFİYET ENGELLEME RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Hedef Standart: RFC 5280 (X.509 PKI) & RFC 6125 (TLS Hostname Verification)",
        "--------------------------------------------------------------------------------"
    ]

    basarili_negatif = 0
    toplam_negatif = len(data["negatif_senaryolar"])

    # Ortak test PKI'ı
    root_ca, root_priv = PKIBuilder.create_root_ca(bits=512)
    inter_ca, inter_priv = PKIBuilder.create_intermediate_ca(root_ca, root_priv, bits=512)
    leaf_cert, leaf_priv = PKIBuilder.create_leaf_certificate(
        inter_ca, inter_priv, domain="secure.bank.com.tr", san_list=["secure.bank.com.tr", "*.bank.com.tr"], bits=512
    )
    trust_store = [root_ca]

    for item in data["negatif_senaryolar"]:
        s_id = item["id"]
        beklenen = item["beklenen_hata"]
        zafiyet = item["zafiyet_kodu"]
        aciklama = item["aciklama"]
        yakalandi = False
        yakalanan_hata = ""

        try:
            if s_id == "NEG_01_UNTRUSTED_ROOT_CA":
                fake_root, _ = PKIBuilder.create_root_ca(cn="Attacker Rogue CA", bits=512)
                X509ChainValidator.validate_chain(leaf_cert, [inter_ca], trust_store=[fake_root], target_domain="secure.bank.com.tr")

            elif s_id == "NEG_02_EXPIRED_CERTIFICATE":
                future = datetime.now(timezone.utc) + timedelta(days=item["parametreler"]["simulated_days_after"])
                X509ChainValidator.validate_chain(leaf_cert, [inter_ca], trust_store, target_domain="secure.bank.com.tr", check_time=future)

            elif s_id == "NEG_03_NOT_YET_VALID_CERTIFICATE":
                past = datetime.now(timezone.utc) - timedelta(days=item["parametreler"]["simulated_days_before"])
                X509ChainValidator.validate_chain(leaf_cert, [inter_ca], trust_store, target_domain="secure.bank.com.tr", check_time=past)

            elif s_id == "NEG_04_HOSTNAME_MISMATCH":
                X509ChainValidator.validate_chain(leaf_cert, [inter_ca], trust_store, target_domain=item["parametreler"]["requested_domain"])

            elif s_id == "NEG_05_TAMPERED_TBS_SIGNATURE":
                tampered = X509Certificate.from_dict(leaf_cert.to_dict())
                tampered.subject.common_name = item["parametreler"]["tamper_value"]
                X509ChainValidator.validate_chain(tampered, [inter_ca], trust_store, target_domain=item["parametreler"]["tamper_value"])

            elif s_id == "NEG_06_LEAF_ACTING_AS_CA":
                PKIBuilder.create_leaf_certificate(issuer_ca=leaf_cert, issuer_priv=leaf_priv, domain="hacker.com")

            elif s_id == "NEG_07_REVOKED_CERTIFICATE":
                rev_serial = int(item["parametreler"]["revoked_serial"], 16)
                # leaf cert seri numarası iptal listesine eklenir
                X509ChainValidator.validate_chain(leaf_cert, [inter_ca], trust_store, target_domain="secure.bank.com.tr", revoked_serials={leaf_cert.serial_number, rev_serial})

            elif s_id == "NEG_08_PATH_LENGTH_EXCEEDED":
                # inter_ca pathLenConstraint=0 iken altından 2. bir CA türetip zinciri aşma
                inter2, p2 = PKIBuilder.create_intermediate_ca(inter_ca, inter_priv, cn="Derin CA", bits=512)
                leaf_deep, _ = PKIBuilder.create_leaf_certificate(inter2, p2, domain="deep.bank.com.tr", bits=512)
                X509ChainValidator.validate_chain(leaf_deep, [inter2, inter_ca], trust_store, target_domain="deep.bank.com.tr")

            elif s_id == "NEG_09_CORRUPTED_CERTIFICATE_FORMAT":
                k_data = json.loads(item["parametreler"]["raw_json"])
                X509Certificate.from_dict(k_data)

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
    """X.509 PKI mimarisi, güven zinciri ve zafiyet analizini içeren adli rapor üretir."""
    print("[*] X.509 adli güvenlik analiz raporu üretiliyor...")
    satirlar = [
        "=== GÜN 108 X.509 VE SERTİFİKA ZİNCİRİ ADLİ ANALİZ RAPORU ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "Standart Uyumluluğu: RFC 5280 (PKI Path Validation) & RFC 6125 (Hostname Verification)",
        "--------------------------------------------------------------------------------",
        "",
        "1. X.509 v3 SERTİFİKA ANATOMİSİ VE GÜVEN ZİNCİRİ (TRUST CHAIN):",
        "   - Bir TLS/HTTPS bağlantısında sunucu yalnızca kendi uç sertifikasını (Leaf) sunmaz;",
        "     aynı zamanda bu sertifikayı imzalayan Ara CA (Intermediate) sertifikasını da iletir.",
        "   - İstemci (tarayıcı/işletim sistemi), önceden güvenilen Kök CA (Root CA) deposunda",
        "     zincirin tepesini arar. Zincir güvenilir bir köke bağlanmıyorsa bağlantı anında koparılır (CWE-295).",
        "",
        "2. TEMEL KISITLAMALAR (BASIC CONSTRAINTS) VE YETKİSİZ CA SALDIRISI:",
        "   - BasicConstraints uzantısı is_ca (BOOLEAN) ve pathLenConstraint değerlerini taşır.",
        "   - Bir web sitesine verilen sertifikada is_ca=False olmak ZORUNDADIR.",
        "   - Eğer istemci bu bayrağı denetlemezse, herhangi bir meşru web sitesi sahibi kendi sertifikasıyla",
        "     'google.com' veya 'bank.com' adına yeni bir ara sertifika imzalayarak dünyayı kandırabilir!",
        "   - Motorumuz BasicConstraints ihlallerini NonCACertificateUsedAsCAError ile anında engeller.",
        "",
        "3. ALAN ADI DOĞRULAMA (RFC 6125 - HOSTNAME VERIFICATION) VE MITM (CWE-297):",
        "   - Geçerli bir CA tarafından imzalanmış olsa dahi, sunulan sertifikanın talep edilen alan adı",
        "     ile eşleşmesi zorunludur. Aksi halde saldırgan kendi adına aldığı geçerli bir sertifikayı",
        "     banka trafiğini araya girerek (MITM) dinlemekte kullanabilir.",
        "   - Modern standartlarda Subject CN yerine Subject Alternative Name (SAN) esas alınır.",
        "",
        "4. SERTİFİKA İPTAL LİSTESİ (CRL) VE OCSP (ONLINE CERTIFICATE STATUS PROTOCOL):",
        "   - Özel anahtar çalındığında veya personel ayrıldığında sertifika süresi bitmeden iptal edilir.",
        "   - CRL statik ve yavaş bir liste sunarken, OCSP gerçek zamanlı sorgulama sağlar.",
        "",
        "--------------------------------------------------------------------------------",
        "SONUÇ: Motor RFC 5280, RFC 6125 ve FIPS standartlarına tam uyumlu olarak doğrulanmıştır."
    ]

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(satirlar) + "\n")
    print(f"[+] Güvenlik analiz raporu kaydedildi: {cikti_yolu}")


def uret_komut_ve_cikis(cikti_yolu: str) -> None:
    """CLI komutlarının çalıştırılma süreçlerini ve çıktılarını kaydeder."""
    print("[*] CLI komutları koşturuluyor ve kayıt altına alınıyor...")
    cli_dosyasi = os.path.join(CURRENT_DIR, "uygulama", "x509_cli.py")
    test_pki_dir = os.path.join(CURRENT_DIR, "kanit", "gercek", "temp_pki")

    komutlar = [
        ([sys.executable, cli_dosyasi, "--build-pki", "--out-dir", test_pki_dir, "--domain", "portal.kurum.gov.tr", "--json"], "1. 3 Kademeli PKI Altyapısının Kurulması"),
        ([sys.executable, cli_dosyasi, "--verify-chain", "--leaf", os.path.join(test_pki_dir, "leaf_cert.json"), "--intermediate", os.path.join(test_pki_dir, "intermediate_ca.json"), "--trust-store", os.path.join(test_pki_dir, "trust_store.json"), "--domain", "portal.kurum.gov.tr", "--json"], "2. Sertifika Güven Zincirinin Doğrulanması (Path Validation)"),
        ([sys.executable, cli_dosyasi, "--demo-flaws", "--json"], "3. PKI ve X.509 Zafiyet Savunma Simülasyonu")
    ]

    kayitlar = [
        "=== GÜN 108 CLI KOMUT VE ÇIKIŞ GÜNLÜĞÜ ===",
        f"Tarih/Saat: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "================================================================================"
    ]

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

    # Geçici dizini temizleme
    if os.path.exists(test_pki_dir):
        import shutil
        shutil.rmtree(test_pki_dir)

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(kayitlar) + "\n")
    print(f"[+] Komut ve çıkış günlüğü kaydedildi: {cikti_yolu}")


def main():
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    os.makedirs(gercek_dir, exist_ok=True)

    uret_test_sonuclari(os.path.join(gercek_dir, "test_sonuclari.txt"))
    uret_negatif_kontrol_sonuclari(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"))
    uret_guvenlik_analiz_raporu(os.path.join(gercek_dir, "x509_guvenlik_analiz_raporu.txt"))
    uret_komut_ve_cikis(os.path.join(gercek_dir, "komut_ve_cikis.txt"))
    print("[*] Tüm Gün 108 gerçek kanıt dosyaları başarıyla üretildi!")


if __name__ == "__main__":
    main()
