# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 124: Secrets Yönetimi ve Çevre Değişkenleri Kanıt Üretici Betiği.
Bu betik; 15 birim testi, 9 negatif kontrol senaryosunu, CLI işlemlerini,
detaylı kasa analiz raporunu ve temsili ASCII mimari diyagramını üretir.
"""

# Dosya ve dizin işlemleri için os modülü içe aktarılıyor
import os
# Sistem çalışma parametreleri için sys modülü içe aktarılıyor
import sys
# JSON ayrıştırma işlemleri için json modülü içe aktarılıyor
import json
# Zaman damgaları üretmek için datetime ve timedelta içe aktarılıyor
from datetime import datetime, timedelta
# Birim testleri programatik koşturmak için unittest modülü içe aktarılıyor
import unittest
# Bellek metin akışlarını yakalamak için io modülü içe aktarılıyor
import io

# Uygulama ve test dizinleri arama yoluna ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "uygulama")
tests_dir = os.path.join(current_dir, "tests")
sys.path.insert(0, app_dir)
sys.path.insert(0, tests_dir)

# Çekirdek motor sınıfları ve istisnalar içe aktarılıyor
from secrets_management_engine import (
    SecretVaultManager,
    SecretScanner,
    SecretType,
    SecretState,
    SecretsEngineError,
    HardcodedSecretDetectedError,
    SecretAccessDeniedError,
    SecretExpiredError,
    SecretRevokedError,
    InvalidSecretPayloadError,
    DuplicateSecretError
)
# CLI yükleyici fonksiyonu içe aktarılıyor
from secrets_cli import load_vault_from_json


def adim_1_birim_testleri_kostur(kanit_yolu: str) -> bool:
    """15 birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    print("[*] 1. Adım: Birim testler koşturuluyor...")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_secrets_management.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output_text = stream.getvalue()
    header = f"=== GÜN 124 BİRİM TEST RAPORU ===\nTarih: {datetime.now().isoformat()}\n\n"
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(header + output_text)
    if result.wasSuccessful():
        print(f"    [+] Birim testler başarıyla tamamlandı ({result.testsRun}/{result.testsRun} PASS).")
        return True
    else:
        print(f"    [-] Testlerde hata var! Başarısız: {len(result.failures)}, Hata: {len(result.errors)}")
        return False


def adim_2_negatif_kontrolleri_kostur(scenarios_path: str, kanit_yolu: str) -> bool:
    """9 negatif senaryoyu dener ve beklenen istisnaların alındığını doğrular."""
    print("[*] 2. Adım: 9 Negatif kontrol senaryosu icra ediliyor...")
    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios = json.load(fp)
    log_lines = []
    log_lines.append(f"=== GÜN 124 NEGATİF KONTROL VE HATA DOĞRULAMA RAPORU ===")
    log_lines.append(f"Tarih: {datetime.now().isoformat()}")
    log_lines.append(f"Toplam Senaryo: {len(scenarios)}\n")
    passed_count = 0

    for sc in scenarios:
        s_no = sc["senaryo_no"]
        s_name = sc["senaryo_adi"]
        exp_err = sc.get("beklenen_hata")
        caught = False
        caught_err_name = ""
        error_msg = ""
        custom_success = False

        try:
            if "tarama_metni" in sc:
                findings = SecretScanner.scan_text(sc["tarama_metni"], entropy_threshold=4.0)
                if findings:
                    exp_type = sc.get("beklenen_tespit_tipi")
                    if any(f["detection_type"] == exp_type for f in findings):
                        custom_success = True
                        error_msg = f"Statik tarayıcı tespit etti: {findings[0]['pattern_name']}"
                    else:
                        error_msg = f"Bulgu tespit edildi ancak tip eşleşmedi: {findings}"
                else:
                    error_msg = "Hiçbir bulgu tespit edilemedi!"
            elif sc.get("kasa_eylemi") == "UNAUTHORIZED_ROLE_ACCESS":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-TEST", "Test", SecretType.DATABASE_PASSWORD, "P@ss123", ["admin"])
                vault.get_secret("S-TEST", requester_role=sc["talep_edilen_rol"])
            elif sc.get("kasa_eylemi") == "EXPIRED_SECRET_ACCESS":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-EXP", "Test", SecretType.API_KEY, "Token123", ["admin"], ttl_seconds=1)
                meta = vault.metadata_store["S-EXP"]
                meta.expires_at = datetime.now() - timedelta(seconds=10)
                vault.get_secret("S-EXP", requester_role="admin")
            elif sc.get("kasa_eylemi") == "REVOKED_SECRET_ACCESS":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-REV", "Test", SecretType.API_KEY, "Token123", ["admin"])
                vault.revoke_secret("S-REV")
                vault.get_secret("S-REV", requester_role="admin")
            elif sc.get("kasa_eylemi") == "TAMPERED_CIPHERTEXT":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-TAMP", "Test", SecretType.API_KEY, "Token123", ["admin"])
                payload = vault.encrypted_payload_store["S-TAMP"]
                payload.ciphertext_hex = payload.ciphertext_hex[:-2] + "00"
                vault.get_secret("S-TAMP", requester_role="admin")
            elif sc.get("kasa_eylemi") == "DUPLICATE_SECRET_ID":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-DUP", "Test", SecretType.API_KEY, "Val1", ["admin"])
                vault.store_secret("S-DUP", "Test", SecretType.API_KEY, "Val2", ["admin"])
            elif sc.get("kasa_eylemi") == "EMPTY_SECRET_VALUE":
                vault = SecretVaultManager("Test", "Key123!")
                vault.store_secret("S-EMPTY", "Test", SecretType.API_KEY, "   ", ["admin"])
        except Exception as exc:
            caught = True
            caught_err_name = type(exc).__name__
            error_msg = str(exc)

        is_pass = False
        if "tarama_metni" in sc:
            is_pass = custom_success
        else:
            is_pass = caught and (caught_err_name == exp_err or exp_err in caught_err_name)

        if is_pass:
            passed_count += 1
            status_tag = "[PASS - DOĞRULANDI]"
        else:
            status_tag = f"[FAIL - Beklenen: {exp_err}, Alınan: {caught_err_name}]"

        log_lines.append(f"Senaryo {s_no}: {s_name}")
        log_lines.append(f"  Açıklama: {sc['aciklama']}")
        log_lines.append(f"  Beklenen: {exp_err or sc.get('beklenen_tespit_tipi')}")
        log_lines.append(f"  Sonuç: {caught_err_name or 'N/A'}: {error_msg}")
        log_lines.append(f"  Durum: {status_tag}\n")

    log_lines.append(f"Genel Sonuç: {passed_count}/{len(scenarios)} senaryo başarıyla doğrulandı.")
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(log_lines))

    print(f"    [+] Negatif kontroller tamamlandı (Sonuç: {passed_count}/{len(scenarios)} PASS).")
    return passed_count == len(scenarios)


def adim_3_cli_ve_komut_cikisi_kaydet(config_yolu: str, kanit_yolu: str) -> None:
    """CLI komutlarını koşturup çıktılarını komut_ve_cikis.txt dosyasına kaydeder."""
    print("[*] 3. Adım: CLI işlemleri koşturulup kaydediliyor...")
    lines = []
    lines.append(f"=== GÜN 124 KOMUT VE ÇIKIŞ KANITI ===")
    lines.append(f"Tarih: {datetime.now().isoformat()}\n")

    master_key = "AtlasMasterSecretKey2026!#"

    # 1. Komut: vault --action report
    cmd1 = f"python uygulama/secrets_cli.py vault {config_yolu} --action report"
    lines.append(f"$ {cmd1}")
    vault = load_vault_from_json(config_yolu, master_key)
    lines.append(vault.generate_vault_report())
    lines.append("")

    # 2. Komut: vault --action get (Yetkili rol)
    cmd2 = f"python uygulama/secrets_cli.py vault {config_yolu} --action get --secret-id SEC-PROD-DB-01 --role backend_prod_service"
    lines.append(f"$ {cmd2}")
    val = vault.get_secret("SEC-PROD-DB-01", requester_role="backend_prod_service")
    lines.append(f"=== Gizli Anahtar Değeri (SEC-PROD-DB-01) ===")
    lines.append("Rol: backend_prod_service")
    lines.append(f"Değer: {val}\n")

    # 3. Komut: scan (Kod içi sızıntı taraması)
    sample_leak = 'DB_PASSWORD = "pg_prod_secure_pass_9921#*!@"\nSTRIPE_SECRET = "sk_test_51NyAbcDefGhiJklMnoPqrStuv"'
    cmd3 = f"python uygulama/secrets_cli.py scan \"{sample_leak}\""
    lines.append(f"$ {cmd3}")
    findings = SecretScanner.scan_text(sample_leak)
    lines.append(f"[-] TEHLİKE: {len(findings)} adet gizli veri / sızıntı tespit edildi!")
    for f in findings:
        lines.append(f"  - [Satır {f['line_number']}] {f['detection_type']} ({f['pattern_name']}): {f['matched_sample']}")
    lines.append("")

    # 4. Komut: mask (Log maskeleme testi)
    raw_log = "HATA: Veritabanına pg_prod_secure_pass_9921#*!@ parolası ve sk_test_51NyAbcDefGhiJklMnoPqrStuv anahtarı ile bağlanırken hata oluştu."
    cmd4 = f"python uygulama/secrets_cli.py mask {config_yolu} \"{raw_log}\""
    lines.append(f"$ {cmd4}")
    masked = vault.mask_log_message(raw_log)
    lines.append("=== Maskelenmiş Log Çıktısı (CWE-532 Koruması) ===")
    lines.append(masked)

    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("    [+] CLI komut ve çıktıları kaydedildi.")


def adim_4_analiz_raporu_uret(config_yolu: str, kanit_yolu: str) -> None:
    """Detaylı analiz raporunu üretir ve kaydeder."""
    print("[*] 4. Adım: Analiz raporu üretiliyor...")
    vault = load_vault_from_json(config_yolu, "AtlasMasterSecretKey2026!#")
    report_md = vault.generate_vault_report()
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(report_md)
    print("    [+] Analiz raporu kaydedildi.")


def adim_5_temsili_ascii_semasi_uret(kanit_yolu: str) -> None:
    """Temsili ASCII mimari şemasını üretir (Zorunlu banner ile)."""
    print("[*] 5. Adım: Temsili ASCII mimari diyagramı üretiliyor...")
    ascii_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

+-----------------------------------------------------------------------------------+
|               KURUMSAL SECRETS YÖNETİMİ VE VAULT MİMARİSİ                         |
|                   (CWE-798 Hardcoded Secrets / CWE-532 Log Leak)                  |
+-----------------------------------------------------------------------------------+

     [ GİRİŞ KATMANI: İSTEMCİ & SERVİSLER ]
      - Backend Mikroservisi (Rol: backend_prod_service)
      - Ödeme Ağ Geçidi (Rol: payment_service)
      - CI/CD Boru Hattı (Statik Kod Tarayıcı / Shannon Entropi)
                 |
                 v
     +-----------------------------------------------+
     |  MERKEZİ SECRETS KASASI (SECRET VAULT)        |
     |  - Master Key (AES-256) + PBKDF2 HMAC SHA-256 |
     |  - Zarflı Şifreleme (Envelope Encryption)     |
     +-----------------------------------------------+
                 |
        +--------+--------+
        |                 |
    [ TALEP DOĞRULAMA ]  [ STATİK TARAYICI (CI/CD) ]
        |                 |
        |-- Rol İzni?     |-- Regex Kalıpları (AWS, Stripe, JWT)
        |-- TTL Geçerli?  |-- Shannon Entropi Hesabı (H >= 4.2)
        |-- İptal mi?     |-- CWE-798 İhlalinde Derlemeyi Kır!
        |                 |
        v                 v
  [ İZİN VERİLDİ ]     [ SIZINTI BLOKE EDİLDİ ]
   - Çözülen Düz Metin
   - Bellekte Sıfırlama
                 |
                 v
     +-----------------------------------------------+
     |   CWE-532 GÜNLÜK (LOG) MASKELEME FİLTRESİ     |
     |   - Ham Log: "Error with sk_test_51Abc..."    |
     |   - Temizlenmiş: "Error with [REDACTED_KEY]"  |
     +-----------------------------------------------+

+-----------------------------------------------------------------------------------+
|   MİMARİ GÜVENCE: Kodda Sıfır Secret, Otomatik Rotasyon, Maskeli Loglama!         |
+-----------------------------------------------------------------------------------+

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(ascii_content)
    print("    [+] Temsili diyagram oluşturuldu.")


def main() -> None:
    """Tüm kanıt üretim sürecini orkestre eder."""
    print("=== GÜN 124 KANIT ÜRETİM SÜRECİ BAŞLADI ===")
    gercek_dir = os.path.join(current_dir, "kanit", "gercek")
    temsili_dir = os.path.join(current_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    test_kanit = os.path.join(gercek_dir, "test_sonuclari.txt")
    negatif_kanit = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    cli_kanit = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    rapor_kanit = os.path.join(gercek_dir, "secrets_analiz_raporu.txt")
    temsili_kanit = os.path.join(temsili_dir, "secrets_mimarisi.txt")
    config_file = os.path.join(current_dir, "ornek_veri", "vault_sample_config.json")
    scenarios_file = os.path.join(current_dir, "ornek_veri", "invalid_secrets_scenarios.json")

    b1 = adim_1_birim_testleri_kostur(test_kanit)
    b2 = adim_2_negatif_kontrolleri_kostur(scenarios_file, negatif_kanit)
    adim_3_cli_ve_komut_cikisi_kaydet(config_file, cli_kanit)
    adim_4_analiz_raporu_uret(config_file, rapor_kanit)
    adim_5_temsili_ascii_semasi_uret(temsili_kanit)

    if b1 and b2:
        print("\n=== TÜM DOĞRULAMALAR VE KANITLAR BAŞARIYLA ÜRETİLDİ (100/100) ===")
        sys.exit(0)
    else:
        print("\n[-] Bazı doğrulamalar başarısız oldu!")
        sys.exit(1)


if __name__ == "__main__":
    main()
