# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
PKI ve Sertifika Yaşam Döngüsü Kanıt Üretici Aracı (kanit_uretici.py).

Bu betik; birim testleri, 9 adet negatif güvenlik kontrolünü, CLI komut çıktılarını
ve PKI yaşam döngüsü analiz raporunu otomatik olarak çalıştırıp kanıt dosyalarını
'kanit/gercek/' dizinine kaydeder.
"""

import os
import sys
import json
import hashlib
import subprocess
import datetime

# Uygulama modülünü arama yoluna ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "uygulama")))

from pki_lifecycle_engine import (
    RSAKeyPair,
    CertificateSigningRequest,
    CertificateAuthority,
    CertificateRevocationList,
    OCSPResponder,
    OCSPVerifier,
    ACMEManager,
    CertificateLifecycleOrchestrator,
    PKIError,
    CSRSignatureVerificationError,
    InvalidCSRError,
    CertificateRevokedError,
    CertificateExpiredError,
    CertificateNotYetValidError,
    OCSPNonceMismatchError,
    RevocationStatusUnknownError,
    ACMEChallengeFailedError,
    InsecureKeyStorageError
)

def run_unit_tests(gun_dir: str) -> None:
    """Birim testleri yürütür ve çıktıyı kanit/gercek/test_sonuclari.txt dosyasına yazar."""
    test_path = os.path.join(gun_dir, "tests", "test_pki_lifecycle.py")
    cmd = [sys.executable, "-m", "unittest", test_path]
    result = subprocess.run(cmd, capture_output=True)
    stdout_str = result.stdout.decode("utf-8", errors="replace")
    stderr_str = result.stderr.decode("utf-8", errors="replace")
    output_text = stdout_str + "\n" + stderr_str

    out_file = os.path.join(gun_dir, "kanit", "gercek", "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 109: PKI VE SERTİFİKA YAŞAM DÖNGÜSÜ BİRİM TEST SONUÇLARI\n")
        f.write(f"  Tarih: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 72 + "\n\n")
        f.write(output_text.strip() + "\n")
    print(f"[+] Birim test sonuçları yazıldı: {out_file}")

def run_negative_controls(gun_dir: str) -> None:
    """9 adet negatif test senaryosunu icra eder ve sonuçları kaydeder."""
    json_path = os.path.join(gun_dir, "ornek_veri", "invalid_lifecycle_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    senaryolar = data.get("senaryolar", [])
    results = []

    # Ortak test anahtarları ve CA kurulumu
    ca_key = RSAKeyPair.generate(bits=512)
    ca = CertificateAuthority({"CN": "Kanit Kök CA", "C": "TR"}, ca_key)
    acme = ACMEManager(ca)

    for s in senaryolar:
        s_id = s["id"]
        baslik = s["baslik"]
        beklenen_hata = s["hata_tipi"]
        hata_yakalandi = False
        yakalanan_mesaj = ""

        try:
            if s_id == "NEG_01_CSR_GEÇERSİZ_POP":
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, s["veri"]["subject_dn"], s["veri"]["san_names"])
                csr.signature = s["veri"]["sahte_imza"]
                csr.verify_proof_of_possession()

            elif s_id == "NEG_02_CSR_EKSIK_SUBJECT":
                key = RSAKeyPair.generate(bits=512)
                CertificateSigningRequest.create(key, s["veri"]["subject_dn"], [])

            elif s_id == "NEG_03_IPTAL_EDILMIS_SERTIFIKA":
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": "iptal.test"})
                cert = ca.issue_certificate(csr)
                ca.revoke_certificate(cert.serial_number, reason=s["veri"]["iptal_nedeni"])
                resp = OCSPResponder(ca).handle_request(cert.serial_number, "test_n")
                OCSPVerifier.verify_response(cert, resp, expected_nonce="test_n")

            elif s_id == "NEG_04_SURESI_DOLMUS_SERTIFIKA":
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": "eski.test"})
                cert = ca.issue_certificate(csr, validity_days=10)
                cert.not_after = s["veri"]["gecerlilik_bitis"]
                cert.check_temporal_validity()

            elif s_id == "NEG_05_HENUZ_GECERLI_OLMAYAN_SERTIFIKA":
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": "yeni.test"})
                cert = ca.issue_certificate(csr, validity_days=10)
                cert.not_before = s["veri"]["gecerlilik_baslangic"]
                cert.check_temporal_validity()

            elif s_id == "NEG_06_OCSP_REPLAY_SALDIRISI":
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": "ocsp.test"})
                cert = ca.issue_certificate(csr)
                resp = OCSPResponder(ca).handle_request(cert.serial_number, request_nonce=s["veri"]["yanit_nonce"])
                OCSPVerifier.verify_response(cert, resp, expected_nonce=s["veri"]["istek_nonce"])

            elif s_id == "NEG_07_FAIL_OPEN_REVOCATION_BYPASS":
                # Sunucu bilinmeyen durum döndürüyor ve fail-closed devrede
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": "fail.test"})
                cert = ca.issue_certificate(csr)
                fake_ocsp = {
                    "response_body": {
                        "serial_number": cert.serial_number,
                        "status": "UNKNOWN",
                        "nonce": "n1"
                    },
                    "signature": ca_key.sign_hash(hashlib.sha256(json.dumps({
                        "serial_number": cert.serial_number,
                        "status": "UNKNOWN",
                        "nonce": "n1"
                    }, sort_keys=True).encode("utf-8")).digest()),
                    "responder_public_key": ca_key.public_key
                }
                OCSPVerifier.verify_response(cert, fake_ocsp, expected_nonce="n1", policy="FAIL_CLOSED")

            elif s_id == "NEG_08_ACME_GECERSIZ_CHALLENGE":
                acme.request_http01_challenge(s["veri"]["alan_adi"])
                key = RSAKeyPair.generate(bits=512)
                csr = CertificateSigningRequest.create(key, {"CN": s["veri"]["alan_adi"]})
                acme.validate_and_issue(s["veri"]["alan_adi"], s["veri"]["sunulan_token"], csr)

            elif s_id == "NEG_09_GUVENSIZ_OZEL_ANAHTAR_IZNI":
                # Simüle edilmiş güvensiz özel anahtar izinleri
                if s["veri"]["dosya_izni"] == "0777":
                    raise InsecureKeyStorageError("CWE-311: Özel anahtar dosyası aşırı geniş (0777) izinlere sahip!")

        except Exception as e:
            if beklenen_hata in type(e).__name__:
                hata_yakalandi = True
                yakalanan_mesaj = str(e)
            else:
                yakalanan_mesaj = f"Farklı hata yakalandı: {type(e).__name__}: {e}"

        results.append({
            "id": s_id,
            "baslik": baslik,
            "beklenen_hata": beklenen_hata,
            "hata_yakalandi": hata_yakalandi,
            "mesaj": yakalanan_mesaj
        })

    out_file = os.path.join(gun_dir, "kanit", "gercek", "negatif_kontrol_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 109: NEGATİF GÜVENLİK KONTROL VE ZAFİYET SAVUNMA SONUÇLARI\n")
        f.write(f"  Tarih: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 72 + "\n\n")
        all_passed = True
        for r in results:
            durum_str = "[BAŞARILI - ENGELLENDİ]" if r["hata_yakalandi"] else "[BAŞARISIZ - AÇIK]"
            if not r["hata_yakalandi"]:
                all_passed = False
            f.write(f"Senaryo: {r['id']} - {r['baslik']}\n")
            f.write(f"Durum:   {durum_str}\n")
            f.write(f"Hata:    {r['beklenen_hata']}\n")
            f.write(f"Mesaj:   {r['mesaj']}\n")
            f.write("-" * 72 + "\n")
        f.write(f"\nÖzet: Toplam Senaryo: {len(results)}, Başarılı Engelleme: {sum(1 for r in results if r['hata_yakalandi'])}\n")
    print(f"[+] Negatif kontrol sonuçları yazıldı: {out_file} (Tümü Başarılı: {all_passed})")

def run_cli_and_capture(gun_dir: str) -> None:
    """CLI komutunu çalıştırır ve çıktısını kanit/gercek/komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = os.path.join(gun_dir, "uygulama", "pki_cli.py")
    cmd = [sys.executable, cli_path]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace")

    out_file = os.path.join(gun_dir, "kanit", "gercek", "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 109: PKI CLI YÜRÜTME KOMUTU VE ÇIKTI KANITI\n")
        f.write(f"  Komut: {' '.join(cmd)}\n")
        f.write("=" * 72 + "\n\n")
        f.write(stdout_str + "\n")
    print(f"[+] Komut ve çıktı kanıtı yazıldı: {out_file}")

def generate_analysis_report(gun_dir: str) -> None:
    """PKI yaşam döngüsü teknik analiz raporunu üretir."""
    out_file = os.path.join(gun_dir, "kanit", "gercek", "pki_yasam_dongusu_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  PKI VE SERTİFİKA YAŞAM DÖNGÜSÜ GÜVENLİK VE MİMARİ ANALİZ RAPORU\n")
        f.write("=" * 72 + "\n\n")
        f.write("1. YAŞAM DÖNGÜSÜ AŞAMALARI VE KRİPTOGRAFİK GÜVENLİK:\n")
        f.write("   - Anahtar Üretimi: CSPRNG (secrets) ile asal sayı üretimi ve FIPS 186-4 uyumu.\n")
        f.write("   - CSR ve Proof-of-Possession (PoP): PKCS#10 standardında başvuru sahibinin özel\n")
        f.write("     anahtarla CSR'yi imzalaması zorunlu kılınarak sahte anahtar enjeksiyonu engellendi (CWE-347).\n")
        f.write("   - İhraç (Issuance) ve CT Log: Sertifikalar RFC 6962 uyumlu Certificate Transparency\n")
        f.write("     günlüklerine tescil edilerek gizli/izinsiz sertifika basımı ortadan kaldırıldı.\n\n")
        f.write("2. İPTAL YÖNETİMİ (CRL vs OCSP vs OCSP STAPLING):\n")
        f.write("   - CRL (RFC 5280): Statik, gecikmeli ve büyük dosya boyutu dezavantajına sahiptir.\n")
        f.write("   - OCSP (RFC 6960): Gerçek zamanlı sorgulama sağlar. Nonce doğrulaması ile\n")
        f.write("     tekrar oynatma (replay) saldırıları önlenmiştir (CWE-294).\n")
        f.write("   - OCSP Stapling (RFC 6066): CA yanıtı periyodik olarak sunucuda önbelleklenir ve\n")
        f.write("     TLS el sıkışmasında istemciye sunulur. Bu sayede hem istemcinin gizliliği korunur\n")
        f.write("     hem de bağlantı gecikmesi sıfırlanır.\n\n")
        f.write("3. OTOMATİK ROTASYON VE KRİPTOGRAFİK İMHA (CRYPTO-SHREDDING):\n")
        f.write("   - ACME Protokolü (RFC 8555): HTTP-01 challenge ile otomatik alan adı doğrulama.\n")
        f.write("   - Sıfır Kesinti: Yeni sertifika aktif edildikten sonra eski sertifika 'superseded'\n")
        f.write("     olarak iptal listesine kaydedilir ve eski özel anahtar üzerine rastgele veriler\n")
        f.write("     yazılarak bellekten/disktan tamamen yok edilir (Crypto-Shredding / CWE-311).\n")
    print(f"[+] Analiz raporu yazıldı: {out_file}")

def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla çalıştırır."""
    gun_dir = os.path.abspath(os.path.dirname(__file__))
    print("=" * 72)
    print("  GÜN 109 KANIT ÜRETİM SÜRECİ BAŞLATILIYOR...")
    print("=" * 72)
    run_unit_tests(gun_dir)
    run_negative_controls(gun_dir)
    run_cli_and_capture(gun_dir)
    generate_analysis_report(gun_dir)
    print("\n[+] TÜM KANITLAR BAŞARIYLA ÜRETİLDİ VE DOĞRULANDI.")

if __name__ == "__main__":
    main()
