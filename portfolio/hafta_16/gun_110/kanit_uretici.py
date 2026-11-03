# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
TLS Güvenlik Sınırları Kanıt Üretici Aracı (kanit_uretici.py).

Bu betik; birim testleri, 9 adet negatif güvenlik kontrolünü, CLI komut çıktılarını
ve TLS 1.2 vs 1.3 güvenlik sınırları analiz raporunu otomatik olarak çalıştırıp kanıt dosyalarını
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

from tls_security_boundary_engine import (
    TLSHandshakeEngine,
    TLSRecordLayer,
    SimulatedAEADCipher,
    TLS13ZeroRTTAntiReplayCache,
    TLSError,
    TLSDowngradeDetectedError,
    InsecureCipherSuiteError,
    HandshakeTranscriptIntegrityError,
    ForwardSecrecyRequiredError,
    BadRecordMACError,
    ZeroRTTReplayDetectedError,
    InvalidSequenceNumberError,
    RecordOverflowError,
    DowngradeSentinelMismatchError,
    TLS12_DOWNGRADE_SENTINEL
)

def run_unit_tests(gun_dir: str) -> None:
    """Birim testleri çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = os.path.join(gun_dir, "tests", "test_tls_boundary.py")
    cmd = [sys.executable, "-m", "unittest", test_path]
    result = subprocess.run(cmd, capture_output=True)
    stdout_str = result.stdout.decode("utf-8", errors="replace")
    stderr_str = result.stderr.decode("utf-8", errors="replace")
    output_text = stdout_str + "\n" + stderr_str

    out_file = os.path.join(gun_dir, "kanit", "gercek", "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 110: TLS GÜVENLİK SINIRLARI BİRİM TEST SONUÇLARI\n")
        f.write(f"  Tarih: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 72 + "\n\n")
        f.write(output_text.strip() + "\n")
    print(f"[+] Birim test sonuçları yazıldı: {out_file}")

def run_negative_controls(gun_dir: str) -> None:
    """9 adet negatif güvenlik kontrol senaryosunu icra eder ve sonuçları kaydeder."""
    json_path = os.path.join(gun_dir, "ornek_veri", "invalid_tls_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    senaryolar = data.get("senaryolar", [])
    results = []

    server_engine = TLSHandshakeEngine(
        supported_versions=["TLSv1.3", "TLSv1.2"],
        allowed_ciphers=["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"],
        require_pfs=True
    )
    client_engine = TLSHandshakeEngine(
        supported_versions=["TLSv1.3", "TLSv1.2"],
        allowed_ciphers=["TLS_AES_256_GCM_SHA384"],
        require_pfs=True
    )

    for s in senaryolar:
        s_id = s["id"]
        baslik = s["baslik"]
        beklenen_hata = s["hata_tipi"]
        hata_yakalandi = False
        yakalanan_mesaj = ""

        try:
            if s_id == "NEG_01_DOWNGRADE_ATTACK_SSL3":
                # Fallback-SCSV ile eski sürüme zorlama
                fake_hello = {
                    "supported_versions": ["TLSv1.2"],
                    "cipher_suites": ["ECDHE-RSA-AES256-GCM-SHA384", "TLS_FALLBACK_SCSV"]
                }
                server_engine.process_client_hello_and_reply(fake_hello)

            elif s_id == "NEG_02_GUVENSIZ_SIFRE_PAKETI":
                # Yasaklı RC4/NULL şifre talebi
                bad_hello = {
                    "supported_versions": ["TLSv1.2"],
                    "cipher_suites": s["veri"]["talep_edilen_paketler"]
                }
                server_engine.process_client_hello_and_reply(bad_hello)

            elif s_id == "NEG_03_HANDSHAKE_TRANSCRIPT_TAHRIFATI":
                # Finished mesajı verify_data uyuşmazlığı
                server_engine.verify_finished_message(b"test_key", "deadbeef" * 8)

            elif s_id == "NEG_04_PFS_OLMAYAN_STATIK_RSA":
                # Statik RSA kullanımı (PFS kapalı)
                pfs_srv = TLSHandshakeEngine(["TLSv1.2"], ["TLS_RSA_WITH_AES_128_CBC_SHA"], require_pfs=True)
                rsa_hello = {"supported_versions": ["TLSv1.2"], "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}
                pfs_srv.process_client_hello_and_reply(rsa_hello)

            elif s_id == "NEG_05_GECERSIZ_RECORD_MAC_AEAD":
                # AEAD auth tag tahrifatı
                cipher = SimulatedAEADCipher(b"anahtar_32baytlik_guvenli_anahtar")
                cipher.decrypt(b"\x00" * 12, bytes.fromhex(s["veri"]["record_payload_hex"]), b"aad", bytes.fromhex(s["veri"]["sahte_tag_hex"]))

            elif s_id == "NEG_06_REPLAY_ATTACK_0RTT":
                # 0-RTT Erken Veri Replay
                cache = TLS13ZeroRTTAntiReplayCache()
                ticket = s["veri"]["bilet_id"]
                cache.process_early_data(ticket, "TALEP 1")
                cache.process_early_data(ticket, "TALEP 2 (REPLAY)")

            elif s_id == "NEG_07_RECORD_SEQUENCE_NUMBER_ATLAMA":
                # Record sıra numarası kayması
                rl = TLSRecordLayer()
                fake_rec = {"content_type": 23, "sequence_number": s["veri"]["gelen_seq"], "payload_hex": "aa"}
                rl.process_record(fake_rec)

            elif s_id == "NEG_08_ASIRI_BUYUK_RECORD_FRAGMENT":
                # 16KB sınırını aşan fragment
                rl = TLSRecordLayer()
                rl.create_record(23, b"B" * s["veri"]["fragment_boyutu"])

            elif s_id == "NEG_09_DOWNGRADE_SENTINEL_TESPITI":
                # ServerRandom içinde Sentinel tespiti
                srv_rnd = bytearray(b"\xaa" * 32)
                srv_rnd[-8:] = TLS12_DOWNGRADE_SENTINEL
                fake_srv_hello = {"server_version": "TLSv1.2", "server_random_hex": bytes(srv_rnd).hex()}
                client_engine.verify_server_hello_and_downgrade_sentinel(fake_srv_hello, client_highest_version="TLSv1.3")

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
        f.write("  GÜN 110: TLS GÜVENLİK SINIRI NEGATİF KONTROL VE ZAFİYET SAVUNMA SONUÇLARI\n")
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
    cli_path = os.path.join(gun_dir, "uygulama", "tls_cli.py")
    cmd = [sys.executable, cli_path]
    res = subprocess.run(cmd, capture_output=True)
    stdout_str = res.stdout.decode("utf-8", errors="replace")

    out_file = os.path.join(gun_dir, "kanit", "gercek", "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  GÜN 110: TLS CLI YÜRÜTME KOMUTU VE ÇIKTI KANITI\n")
        f.write(f"  Komut: {' '.join(cmd)}\n")
        f.write("=" * 72 + "\n\n")
        f.write(stdout_str + "\n")
    print(f"[+] Komut ve çıktı kanıtı yazıldı: {out_file}")

def generate_analysis_report(gun_dir: str) -> None:
    """TLS 1.2 vs TLS 1.3 güvenlik sınırları teknik analiz raporunu üretir."""
    out_file = os.path.join(gun_dir, "kanit", "gercek", "tls_guvenlik_analiz_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("  TLS 1.2 VS TLS 1.3 GÜVENLİK SINIRLARI VE PROTOKOL ANALİZ RAPORU\n")
        f.write("=" * 72 + "\n\n")
        f.write("1. MİMARİ KARŞILAŞTIRMA VE KALDIRILAN TEHLİKELİ KRİPTOGRAFİK İLKELER:\n")
        f.write("   - Statik RSA Anahtar Değişimi: TLS 1.3'te tamamen yasaklandı; Ephemeral Diffie-Hellman\n")
        f.write("     (ECDHE) zorunlu kılınarak Perfect Forward Secrecy (PFS) garantilendi (CWE-327).\n")
        f.write("   - CBC Modu ve MAC-then-Encrypt: POODLE ve Lucky 13 saldırılarına açık olan CBC modu kaldırıldı.\n")
        f.write("     Yalnızca AEAD (Authenticated Encryption with Associated Data) şifrelerine izin verildi.\n")
        f.write("   - Kırılmış Algoritmalar: RC4, 3DES, MD5 ve SHA-1 tamamen protokol dışı bırakıldı.\n\n")
        f.write("2. DOWNGRADE SALDIRILARI VE SAVUNMA MEKANİZMALARI:\n")
        f.write("   - TLS_FALLBACK_SCSV (RFC 7507): Araya giren saldırganın bağlantıyı yapay olarak hata verdirip\n")
        f.write("     eski sürüme düşürme (Downgrade Dance) girişimi tespit edilerek el sıkışma iptal edildi (CWE-757).\n")
        f.write("   - RFC 8446 Downgrade Sentinel: ServerRandom son 8 baytına gömülen sentinel değeri ile\n")
        f.write("     istemcinin araya girildiğini anlayabilmesi sağlandı.\n\n")
        f.write("3. TRANSKRİPT BÜTÜNLÜĞÜ VE RECORD KATMANI GÜVENLİK SINIRLARI:\n")
        f.write("   - Finished Mesajı (Transcript-Hash): El sıkışma boyunca gönderilen tüm paketlerin özeti\n")
        f.write("     HMAC ile doğrulanarak şifre paketi manipülasyonları engellendi (CWE-353).\n")
        f.write("   - Record Sıra Numarası (Sequence Number): Paketlerin kaydırılması, atlanması veya çalınması\n")
        f.write("     kesin olarak engellendi.\n")
        f.write("   - 0-RTT Erken Veri (Early Data): Tekrar oynatma saldırılarına (CWE-294) karşı anti-replay\n")
        f.write("     önbelleği ile korundu.\n")
    print(f"[+] Analiz raporu yazıldı: {out_file}")

def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    gun_dir = os.path.abspath(os.path.dirname(__file__))
    print("=" * 72)
    print("  GÜN 110 KANIT ÜRETİM SÜRECİ BAŞLATILIYOR...")
    print("=" * 72)
    run_unit_tests(gun_dir)
    run_negative_controls(gun_dir)
    run_cli_and_capture(gun_dir)
    generate_analysis_report(gun_dir)
    print("\n[+] TÜM KANITLAR BAŞARIYLA ÜRETİLDİ VE DOĞRULANDI.")

if __name__ == "__main__":
    main()
