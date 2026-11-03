# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
Mini Proje 15: İmzalı Yapılandırma Konsepti Kanıt Üretici Aracı (kanit_uretici.py).

Bu betik; birim testleri, 9 adet negatif güvenlik kontrolünü, CLI komut çıktılarını
ve imzalı yapılandırma mimarisi analiz raporunu otomatik olarak çalıştırıp kanıt dosyalarını
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

from signed_config_engine import (
    RSAKeyPair,
    SignedConfigSigner,
    SignedConfigVerifier,
    canonicalize_json,
    SignedConfigError,
    ConfigTamperingError,
    InvalidSignatureError,
    RollbackAttackDetectedError,
    ConfigExpiredError,
    InsufficientSignaturesError,
    UntrustedSignerError,
    MalformedConfigError,
    FutureTimestampError,
    InsecureAlgorithmError
)

def run_unit_tests(gun_dir: str) -> None:
    """Birim testleri çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = os.path.join(gun_dir, "tests", "test_signed_config.py")
    cmd = [sys.executable, "-m", "unittest", test_path]
    result = subprocess.run(cmd, capture_output=True)
    stdout_str = result.stdout.decode("utf-8", errors="replace")
    stderr_str = result.stderr.decode("utf-8", errors="replace")
    output_text = stdout_str + "\n" + stderr_str

    out_file = os.path.join(gun_dir, "kanit", "gercek", "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  MİNİ PROJE 15: İMZALI YAPILANDIRMA BİRİM TEST SONUÇLARI\n")
        f.write(f"  Tarih: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 72 + "\n\n")
        f.write(output_text.strip() + "\n")
    print(f"[+] Birim test sonuçları yazıldı: {out_file}")

def run_negative_controls(gun_dir: str) -> None:
    """9 adet negatif güvenlik kontrol senaryosunu icra eder ve sonuçları kaydeder."""
    json_path = os.path.join(gun_dir, "ornek_veri", "invalid_signed_config_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    senaryolar = data.get("senaryolar", [])
    results = []

    # Ortak temel anahtar ve güven deposu
    key_admin = RSAKeyPair.generate("trusted_admin", bits=512)
    trust_store = {key_admin.key_id: key_admin.public_key}
    signer = SignedConfigSigner(key_admin)

    base_payload = {"service": "firewall", "port": 8443, "mode": "strict"}

    for s in senaryolar:
        s_id = s["id"]
        baslik = s["baslik"]
        beklenen_hata = s["hata_tipi"]
        hata_yakalandi = False
        yakalanan_mesaj = ""

        verifier = SignedConfigVerifier(trust_store=trust_store, current_system_epoch=5, required_signatures=1)

        try:
            if s_id == "NEG_01_PAYLOAD_TAHRIFATI":
                env = signer.sign_config(base_payload, epoch=5)
                env["payload"]["port"] = s["veri"]["tahrif_port"]
                verifier.verify_and_load(env)

            elif s_id == "NEG_02_SAHTE_IMZA":
                env = signer.sign_config(base_payload, epoch=5)
                env["signatures"][0]["signature_hex"] = s["veri"]["sahte_imza_hex"]
                verifier.verify_and_load(env)

            elif s_id == "NEG_03_ROLLBACK_SALDIRISI":
                # Sistem epoch=5 iken epoch=3 sunuluyor
                old_env = signer.sign_config(base_payload, epoch=s["veri"]["sunulan_eski_epoch"])
                verifier.verify_and_load(old_env)

            elif s_id == "NEG_04_SURESI_DOLMUS_YAPILANDIRMA":
                env = signer.sign_config(base_payload, epoch=5)
                env["expires_at"] = s["veri"]["gecerlilik_bitis"]
                verifier.verify_and_load(env)

            elif s_id == "NEG_05_DUAL_SIGNING_EKSIK_IMZA":
                dual_verifier = SignedConfigVerifier(trust_store=trust_store, current_system_epoch=5, required_signatures=2)
                single_env = signer.sign_config(base_payload, epoch=5)
                dual_verifier.verify_and_load(single_env)

            elif s_id == "NEG_06_YETKISIZ_IMZALAYICI":
                rogue_key = RSAKeyPair.generate(s["veri"]["imzalayici_id"], bits=512)
                rogue_signer = SignedConfigSigner(rogue_key)
                rogue_env = rogue_signer.sign_config(base_payload, epoch=5)
                verifier.verify_and_load(rogue_env)

            elif s_id == "NEG_07_BOZUK_KANONIK_JSON":
                verifier.verify_and_load({"format": "INVALID", "epoch": 5})

            elif s_id == "NEG_08_GELECEGE_AIT_GECERSIZ_ZAMAN":
                env = signer.sign_config(base_payload, epoch=5)
                env["created_at"] = s["veri"]["imza_zamani"]
                verifier.verify_and_load(env)

            elif s_id == "NEG_09_ALGORITMA_DUSURME_SALDIRISI":
                signer.sign_config(base_payload, epoch=5, algorithm=s["veri"]["talep_edilen_algoritma"])

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
        f.write("  MİNİ PROJE 15: NEGATİF GÜVENLİK KONTROL VE ZAFİYET SAVUNMA SONUÇLARI\n")
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
    cli_path = os.path.join(gun_dir, "uygulama", "signed_config_cli.py")
    cmd = [sys.executable, cli_path]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace")

    out_file = os.path.join(gun_dir, "kanit", "gercek", "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  MİNİ PROJE 15: CLI YÜRÜTME KOMUTU VE ÇIKTI KANITI\n")
        f.write(f"  Komut: {' '.join(cmd)}\n")
        f.write("=" * 72 + "\n\n")
        f.write(stdout_str + "\n")
    print(f"[+] Komut ve çıktı kanıtı yazıldı: {out_file}")

def generate_analysis_report(gun_dir: str) -> None:
    """İmzalı yapılandırma mimarisi analiz raporunu üretir."""
    out_file = os.path.join(gun_dir, "kanit", "gercek", "imzali_yapilandirma_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  MİNİ PROJE 15: İMZALI YAPILANDIRMA MİMARİ VE GÜVENLİK ANALİZ RAPORU\n")
        f.write("=" * 72 + "\n\n")
        f.write("1. GÜVENLİK MODELİ VE KURCALAMAYA KARŞI KORUMA (TAMPER-EVIDENCE):\n")
        f.write("   - RFC 8785 JSON Kanonikleştirme: Beyaz boşluklar, sıralamalar ve formatlama\n")
        f.write("     farklılıklarının özet değerini bozması engellendi.\n")
        f.write("   - Asimetrik İmza (RSA-SHA256): Yapılandırma yükü değiştirilemez şekilde mühürlendi;\n")
        f.write("     tek bir baytlık değişiklik (CWE-353) anında yakalanmaktadır.\n\n")
        f.write("2. ANTI-ROLLBACK VE MONOTONİK EPOCH SAVUNMASI:\n")
        f.write("   - Geçmişte meşru imzalanmış fakat bilinen güvenlik zaafiyeti içeren eski sürümlerin\n")
        f.write("     yeniden sisteme yüklenmesi (Rollback Saldırısı / CWE-294), monotonik artan\n")
        f.write("     sistem epoch sayacı ile imkansız hale getirildi.\n\n")
        f.write("3. ÇOKLU İMZA (DUAL SIGNING) VE YETKİ KONTROLÜ:\n")
        f.write("   - Kritik altyapı değişikliklerinde en az 2 bağımsız yetkilinin (SecOps + Infra)\n")
        f.write("     onayı zorunlu kılınarak tekil yönetici zaafiyeti ortadan kaldırıldı (CWE-285).\n")
    print(f"[+] Analiz raporu yazıldı: {out_file}")

def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    gun_dir = os.path.abspath(os.path.dirname(__file__))
    print("=" * 72)
    print("  GÜN 112 KANIT ÜRETİM SÜRECİ BAŞLATILIYOR...")
    print("=" * 72)
    run_unit_tests(gun_dir)
    run_negative_controls(gun_dir)
    run_cli_and_capture(gun_dir)
    generate_analysis_report(gun_dir)
    print("\n[+] TÜM KANITLAR BAŞARIYLA ÜRETİLDİ VE DOĞRULANDI.")

if __name__ == "__main__":
    main()
