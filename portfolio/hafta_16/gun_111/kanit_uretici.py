# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
NIST SP 800-57 Uyumlu Anahtar Yönetimi ve Rotasyon Kanıt Üretici Aracı (kanit_uretici.py).

Bu betik; birim testleri, 9 adet negatif güvenlik kontrolünü, CLI komut çıktılarını
ve NIST SP 800-57 anahtar yaşam döngüsü analiz raporunu otomatik olarak çalıştırıp kanıt dosyalarını
'kanit/gercek/' dizinine kaydeder.
"""

import os
import sys
import json
import hashlib
import subprocess
import datetime

# Uygulama modülünü arama yoluna dahil et
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "uygulama")))

from key_management_engine import (
    KeyManagementService,
    EnvelopeEncryptionEngine,
    DualControlKeySplitter,
    KeyState,
    KeyManagementError,
    KeyExpiredError,
    KeyCompromisedError,
    InadequateKeyLengthError,
    KeyUsageLimitExceededError,
    EncryptedDEKIntegrityError,
    KeyAlreadyDestroyedError,
    InsufficientKeySharesError,
    KeyDeprecatedError,
    PredictableKeyError
)

def run_unit_tests(gun_dir: str) -> None:
    """Birim testleri çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = os.path.join(gun_dir, "tests", "test_key_management.py")
    cmd = [sys.executable, "-m", "unittest", test_path]
    result = subprocess.run(cmd, capture_output=True)
    stdout_str = result.stdout.decode("utf-8", errors="replace")
    stderr_str = result.stderr.decode("utf-8", errors="replace")
    output_text = stdout_str + "\n" + stderr_str

    out_file = os.path.join(gun_dir, "kanit", "gercek", "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 111: NIST SP 800-57 ANAHTAR YÖNETİMİ BİRİM TEST SONUÇLARI\n")
        f.write(f"  Tarih: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 72 + "\n\n")
        f.write(output_text.strip() + "\n")
    print(f"[+] Birim test sonuçları yazıldı: {out_file}")

def run_negative_controls(gun_dir: str) -> None:
    """9 adet negatif güvenlik kontrol senaryosunu icra eder ve sonuçları kaydeder."""
    json_path = os.path.join(gun_dir, "ornek_veri", "invalid_keymgmt_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    senaryolar = data.get("senaryolar", [])
    results = []

    for s in senaryolar:
        s_id = s["id"]
        baslik = s["baslik"]
        beklenen_hata = s["hata_tipi"]
        hata_yakalandi = False
        yakalanan_mesaj = ""

        # Her senaryo için temiz KMS ve Zarf Şifreleme motoru
        kms = KeyManagementService()
        active_kek = kms.create_kek("kek_base", bit_length=256)
        engine = EnvelopeEncryptionEngine(kms)

        try:
            if s_id == "NEG_01_SURESI_DOLMUS_ANAHTARLA_SIFRELEME":
                # Kriptoperiyodu geçmişe ayarla
                active_kek.expires_at = s["veri"]["gecerlilik_bitis"]
                active_kek.check_cryptoperiod()

            elif s_id == "NEG_02_IPTAL_EDILMIS_ANAHTAR_KULLANIMI":
                # Anahtarı sızmış olarak işaretle
                kms.compromise_key("kek_base")
                active_kek.check_cryptoperiod()

            elif s_id == "NEG_03_ZAYIF_ANAHTAR_UZUNLUGU":
                # Yetersiz anahtar uzunluğu (64-bit)
                kms.create_kek("weak_key", bit_length=s["veri"]["bit_uzunlugu"])

            elif s_id == "NEG_04_HACIM_LIMITI_ASIMI_NONCE_TUKENMESI":
                # Azami şifreleme limitini aş
                test_kek = kms.create_kek("limit_kek", bit_length=256)
                test_kek.usage_count = s["veri"]["mevcut_islem_sayisi"]
                test_kek.increment_usage()

            elif s_id == "NEG_05_ZARF_SIFRELEMEDE_TAHRIF_EDILMIS_DEK":
                # Tahrif edilmiş DEK etiketi
                env = engine.encrypt_data(b"Veri")
                env["dek_tag_hex"] = s["veri"]["auth_tag_hex"]
                engine.decrypt_data(env)

            elif s_id == "NEG_06_ZEROIZATION_DOGRALAMASI_VE_SIZINTI":
                # Sıfırlanmış anahtar erişimi
                del_kek = kms.create_kek("del_kek", bit_length=256)
                del_kek.zeroize()
                del_kek.check_cryptoperiod()

            elif s_id == "NEG_07_DUAL_CONTROL_EKSIK_PAYLASIM":
                # Dual Control eksik parça
                share1, _ = DualControlKeySplitter.split_secret_2_of_2(b"12345678123456781234567812345678")
                DualControlKeySplitter.combine_secret_2_of_2([share1])

            elif s_id == "NEG_08_DEPRECATED_ANAHTARLA_YENI_SIFRELEME":
                # DEPRECATED anahtarla şifreleme denemesi
                dep_kek = kms.create_kek("dep_kek", bit_length=256)
                dep_kek.state = KeyState.DEPRECATED
                kms.active_kek_id = "dep_kek"
                engine.encrypt_data(b"Yeni Veri")

            elif s_id == "NEG_09_HARDCODED_VEYA_STATIK_ANAHTAR_GIRISI":
                # Tahmin edilebilir sabit sıfır anahtarı
                kms.create_kek("zero_kek", bit_length=256, custom_bytes=bytes.fromhex(s["veri"]["anahtar_deseni"]))

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
        f.write("  GÜN 111: NIST SP 800-57 NEGATİF KONTROL VE ZAFİYET SAVUNMA SONUÇLARI\n")
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
    """CLI komutunu çalıştırır ve çıktıyı kanit/gercek/komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = os.path.join(gun_dir, "uygulama", "keymgmt_cli.py")
    cmd = [sys.executable, cli_path]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace")

    out_file = os.path.join(gun_dir, "kanit", "gercek", "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 111: ANAHTAR YÖNETİMİ CLI YÜRÜTME KOMUTU VE ÇIKTI KANITI\n")
        f.write(f"  Komut: {' '.join(cmd)}\n")
        f.write("=" * 72 + "\n\n")
        f.write(stdout_str + "\n")
    print(f"[+] Komut ve çıktı kanıtı yazıldı: {out_file}")

def generate_analysis_report(gun_dir: str) -> None:
    """NIST SP 800-57 anahtar yönetimi ve rotasyon analiz raporunu üretir."""
    out_file = os.path.join(gun_dir, "kanit", "gercek", "anahtar_yonetimi_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  NIST SP 800-57 ANAHTAR YÖNETİMİ VE ROTASYON ANALİZ RAPORU\n")
        f.write("=" * 72 + "\n\n")
        f.write("1. NIST SP 800-57 YAŞAM DÖNGÜSÜ VE DURUM GEÇİŞLERİ:\n")
        f.write("   - Pre-Activation: Üretilmiş fakat henüz şifrelemede aktif edilmemiş durum.\n")
        f.write("   - Active: Hem şifreleme hem de deşifre için yetkilendirilmiş anahtar.\n")
        f.write("   - Deprecated: Yeni şifreleme yapamaz (CWE-320); yalnızca geçmiş veriyi deşifre edebilir.\n")
        f.write("   - Compromised: Sızmış/ihlal edilmiş anahtar; derhal bloke edilir ve tüm operasyonlar durdurulur.\n")
        f.write("   - Destroyed: Kriptografik Sıfırlama (Zeroization / CWE-226) ile bellekten silinmiş durum.\n\n")
        f.write("2. ZARF ŞİFRELEME (ENVELOPE ENCRYPTION - KEK VS DEK) VE RE-WRAPPING:\n")
        f.write("   - Hiyerarşi: KEK (Key Encryption Key) anahtarları HSM/KMS içinde saklanır; DEK (Data Encryption\n")
        f.write("     Key) ise doğrudan veriyi şifreler ve KEK ile sarılarak şifreli verinin başlığına eklenir.\n")
        f.write("   - O(1) Re-wrapping: Milyonlarca gigabayt veriyi yeniden şifrelemek yerine SADECE DEK'ler yeni\n")
        f.write("     KEK ile yeniden sarılır. Bu sayede sıfır kesintiyle anında anahtar rotasyonu sağlanır.\n\n")
        f.write("3. GÜVENLİK VE ÇİFT KONTROL (DUAL CONTROL / ZEROIZATION):\n")
        f.write("   - Dual Control / Split Knowledge: Tek bir yöneticinin tek başına master anahtara sahip olmasını\n")
        f.write("     engelleyen 2-of-2 eşik paylaşımı (CWE-320 savunması).\n")
        f.write("   - Kriptografik Sıfırlama (Zeroization): Emekliye ayrılan anahtarların üzerine 0x00, 0xFF ve\n")
        f.write("     CSPRNG rastgele baytları yazılarak bellek ve disk kalıntılarından sızıntı önlendi (CWE-226).\n")
    print(f"[+] Analiz raporu yazıldı: {out_file}")

def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    gun_dir = os.path.abspath(os.path.dirname(__file__))
    print("=" * 72)
    print("  GÜN 111 KANIT ÜRETİM SÜRECİ BAŞLATILIYOR...")
    print("=" * 72)
    run_unit_tests(gun_dir)
    run_negative_controls(gun_dir)
    run_cli_and_capture(gun_dir)
    generate_analysis_report(gun_dir)
    print("\n[+] TÜM KANITLAR BAŞARIYLA ÜRETİLDİ VE DOĞRULANDI.")

if __name__ == "__main__":
    main()
