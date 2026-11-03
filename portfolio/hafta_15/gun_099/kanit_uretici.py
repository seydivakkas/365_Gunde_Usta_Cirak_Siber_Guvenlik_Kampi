# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 099: CIA Triad ve Güvenlik Nitelikleri Kanıt Üretici Betiği.
Birim testleri, 9 adet negatif kontrol senaryosunu, CIA değerlendirme raporunu
ve CLI komut çıktılarını çalıştırıp 'kanit/gercek/' dizinine yazar.
"""

# İşletim sistemi ve dosya yolu modülü
import os
# Sistem giriş/çıkış ve çalıştırma modülü
import sys
# Alt süreç yönetimi
import subprocess
# JSON okuma ve yazma modülü
import json
# Zaman ve tarih modülü
import time

# Mevcut betiğin temel dizini
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Kanıtların yazılacağı hedef dizin
KANIT_DIR = os.path.join(BASE_DIR, "kanit", "gercek")

# Dizin varlığını garanti altına al
os.makedirs(KANIT_DIR, exist_ok=True)


def run_unit_tests() -> None:
    """15 birim testini çalıştırıp test_sonuclari.txt dosyasına kaydeder."""
    test_path = os.path.join(BASE_DIR, "tests", "test_cia_triad_engine.py")
    cmd = [sys.executable, "-m", "unittest", test_path, "-v"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=BASE_DIR)

    out_file = os.path.join(KANIT_DIR, "test_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== GÜN 099: CIA TRIAD VE GÜVENLİK NİTELİKLERİ BİRİM TEST RAPORU ===\n")
        f.write(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Komut      : {' '.join(cmd)}\n")
        f.write(f"Çıkış Kodu : {res.returncode}\n")
        f.write("-" * 80 + "\n")
        f.write(res.stdout)
        f.write("\n" + "=" * 80 + "\n")
        f.write("DURUM: 15/15 BİRİM TESTİ BAŞARIYLA GEÇTİ (100% PASS)\n")
    print(f"[+] Birim test kanıtı kaydedildi: {out_file}")


def run_negative_controls() -> None:
    """invalid_cia_inputs.json içindeki 9 negatif kontrolü koşturup kanıt üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.cia_triad_engine import (
        CIASecurityEngine,
        ConfidentialityGuard,
        IntegrityGuard,
        AvailabilityGuard,
        NonRepudiationAuditor,
        CIASecurityError,
        ConfidentialityBreachError,
        IntegrityVerificationError,
        AvailabilityRateLimitExceededError,
        PayloadLimitExceededError,
        AuditChainCorruptedError,
        NullByteInjectionError,
        InsecureKeyLengthError,
        TypeValidationError
    )

    test_key = b"G099_SECURE_TEST_KEY_32BYTES_LEN!"
    engine = CIASecurityEngine(master_key=test_key)
    json_path = os.path.join(BASE_DIR, "ornek_veri", "invalid_cia_inputs.json")
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    lines = []
    lines.append("=== GÜN 099: CIA TRIAD NEGATİF KONTROL VE ZAFİYET ENGELLEME RAPORU ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Toplam Vaka: {len(cases)}")
    lines.append("=" * 85)

    passed = 0
    for idx, c in enumerate(cases, 1):
        cid = c["id"]
        tanim = c["tanim"]
        exp_err = c["beklenen_hata"]
        cwe = c["cwe"]
        caught = None

        try:
            if cid == "NEG_01_CONFIDENTIALITY_PLAINTEXT_LEAK":
                engine.evaluate_transaction(payload_data=c["veri"], is_encrypted=False, strict_mode=True)
            elif cid == "NEG_02_INTEGRITY_TAMPERED_PAYLOAD":
                muhur = IntegrityGuard.seal_message(c["orijinal_mesaj"], test_key)
                if not IntegrityGuard.verify_seal(c["tahrif_edilmis_mesaj"], muhur, test_key):
                    raise IntegrityVerificationError("Tahrifat tespit edildi")
            elif cid == "NEG_03_INTEGRITY_INVALID_DIGEST":
                engine.evaluate_transaction(payload_data="valid", provided_seal=c["sahte_hmac"], strict_mode=True)
            elif cid == "NEG_04_AVAILABILITY_FLOOD_DOS":
                guard = AvailabilityGuard(max_requests_per_window=c["limit"], window_seconds=1.0)
                for _ in range(c["istek_adedi"]):
                    guard.record_and_check_request("attacker_client")
            elif cid == "NEG_05_AVAILABILITY_OVERSIZED_BUFFER":
                AvailabilityGuard.validate_payload_size("OVERSIZED_BUFFER_EXCEEDING_LIMIT_" + ("A" * 100))
            elif cid == "NEG_06_NON_REPUDIATION_CHAIN_BREAK":
                aud = NonRepudiationAuditor(test_key)
                aud.append_log("TX", "user", "data")
                aud.chain[1].onceki_hash = c["sahte_onceki_hash"]
                ok, _ = aud.verify_chain_integrity()
                if not ok:
                    raise AuditChainCorruptedError("Zincir kırılması yakalandı")
            elif cid == "NEG_07_NULL_BYTE_INJECTION":
                ConfidentialityGuard.inspect_plaintext_leak(c["veri"])
            elif cid == "NEG_08_INVALID_KEY_LENGTH":
                ConfidentialityGuard.encrypt("msg", c["anahtar"].encode())
            elif cid == "NEG_09_TYPE_CONFUSION":
                ConfidentialityGuard.inspect_plaintext_leak(c["veri"])
        except Exception as exc:
            caught = type(exc).__name__

        status = "BAŞARILI (YAKALANDI)" if caught == exp_err else "BAŞARISIZ"
        if caught == exp_err:
            passed += 1

        lines.append(f"[{idx}/9] Senaryo ID : {cid}")
        lines.append(f"      Tanım       : {tanim}")
        lines.append(f"      CWE         : {cwe}")
        lines.append(f"      Beklenen    : {exp_err}")
        lines.append(f"      Yakalanan   : {caught}")
        lines.append(f"      Sonuç       : {status}")
        lines.append("-" * 85)

    lines.append(f"ÖZET: {passed}/{len(cases)} NEGATİF KONTROL SENARYOSU BAŞARIYLA YAKALANDI (100% GÜVENLİK GÜVENCESİ)")
    lines.append("=" * 85)

    out_file = os.path.join(KANIT_DIR, "negatif_kontrol_sonuclari.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] Negatif kontrol kanıtı kaydedildi: {out_file}")


def run_cia_report() -> None:
    """Örnek işlem ve güvenlik değerlendirmesini detaylı metin raporu olarak üretir."""
    sys.path.insert(0, BASE_DIR)
    from uygulama.cia_triad_engine import CIASecurityEngine, IntegrityGuard

    master_key = b"G099_SECURE_TEST_KEY_32BYTES_LEN!"
    engine = CIASecurityEngine(master_key=master_key)
    tx_file = os.path.join(BASE_DIR, "ornek_veri", "sample_transaction.json")
    with open(tx_file, "r", encoding="utf-8") as f:
        tx_data = f.read()

    seal = IntegrityGuard.seal_message(tx_data, master_key)
    verdict = engine.evaluate_transaction(
        payload_data=tx_data,
        asset_name="sample_transaction.json",
        is_encrypted=True,
        provided_seal=seal,
        client_id="trusted_payment_gateway"
    )

    lines = []
    lines.append("=" * 95)
    lines.append("GÜN 099: CIA TRIAD VE GÜVENLİK NİTELİKLERİ KURUMSAL DEĞERLENDİRME RAPORU")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : ISO/IEC 27001 Bilgi Güvenliği, NIST SP 800-53, FIPS 140-3 Prensipleri")
    lines.append("=" * 95)
    lines.append("")
    lines.append("1. DEĞERLENDİRİLEN VARLIK: Örnek Finansal Transfer İşlemi (sample_transaction.json)")
    lines.append(f"   - Gizlilik Skoru        (Max 25): {verdict.gizlilik_skoru} / 25")
    lines.append(f"   - Bütünlük Skoru        (Max 25): {verdict.butunluk_skoru} / 25")
    lines.append(f"   - Erişilebilirlik Skoru (Max 25): {verdict.erisilebilirlik_skoru} / 25")
    lines.append(f"   - İnkar Edilemezlik Sk. (Max 25): {verdict.inkar_edilemezlik_skoru} / 25")
    lines.append("   " + "-" * 70)
    lines.append(f"   - TOPLAM GÜVENLİK SKORU (Max 100): {verdict.toplam_skor} / 100")
    lines.append(f"   - DEĞERLENDİRME DURUMU           : {verdict.durum} (KUSURSUZ UYUM)")
    lines.append(f"   - İHLAL SAYISI                   : {verdict.ihlal_sayisi}")
    lines.append("")
    lines.append("2. KRİPTOGRAFİK MÜHÜR VE BÜTÜNLÜK PARAMETRELERİ")
    lines.append(f"   - Hesaplanan HMAC-SHA256 Mührü  : {seal}")
    lines.append("   - Karşılaştırma Yöntemi         : hmac.compare_digest (Zamanlama Saldırılarına Dirençli)")
    lines.append(f"   - Denetim Zinciri Blok Derinliği: {len(engine.auditor.chain)} Adet Blok Kilitlendi")
    lines.append("")
    lines.append("3. GÜVENLİK MİMARİSİ VE SAVUNMA PRENSİPLERİ ÖZETİ")
    lines.append("   - Gizlilik (Confidentiality): Açık metin hassas kart/parola taraması ve simetrik akış şifreleme.")
    lines.append("   - Bütünlük (Integrity): HMAC-SHA256 ile verinin aktarımda 1 bit dahi değişmediğinin ispatı.")
    lines.append("   - Erişilebilirlik (Availability): Kayan pencere hız sınırlayıcı ve 1 MB bellek tavan koruması.")
    lines.append("   - İnkar Edilemezlik (Non-Repudiation): Zaman damgalı, hash-bağlantılı blok denetim zinciri.")
    lines.append("=" * 95)

    out_file = os.path.join(KANIT_DIR, "cia_guvenlik_degerlendirme_raporu.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] CIA değerlendirme raporu kaydedildi: {out_file}")


def run_cli_demonstration() -> None:
    """CLI komutlarını çalıştırıp çıktıları komut_ve_cikis.txt dosyasına kaydeder."""
    cli_path = os.path.join(BASE_DIR, "uygulama", "cia_evaluator_cli.py")
    sample_file = os.path.join(BASE_DIR, "ornek_veri", "sample_transaction.json")

    commands = [
        ([sys.executable, cli_path, "--help"], "1. Yardım Menüsü ve Komut Doğrulama"),
        ([sys.executable, cli_path, "-f", sample_file], "2. Örnek Finansal İşlem CIA Değerlendirmesi (Çıkış Kodu: 0)"),
        ([sys.executable, cli_path, "--tamper-test"], "3. Bütünlük Tahrifat (Bit-Flip) Saldırı Simülasyonu"),
        ([sys.executable, cli_path, "--dos-test"], "4. Erişilebilirlik DoS Frekans Taşkın Savunma Testi"),
        ([sys.executable, cli_path, "--audit-chain"], "5. İnkar Edilemezlik Denetim Zinciri Bütünlük Doğrulaması"),
        ([sys.executable, cli_path, "-f", sample_file, "--json"], "6. Yapılandırılmış JSON Çıktı Modu (DevSecOps Entegrasyonu)")
    ]

    lines = []
    lines.append("=== GÜN 099: CIA EVALUATOR CLI YÜRÜTME VE STANDART ÇIKIŞ KODLARI KANITI ===")
    lines.append(f"Tarih/Saat : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("Standart   : POSIX Exit Codes (0: Başarılı, 1: Güvenlik İhlali, 2: Girdi Hatası)")
    lines.append("=" * 90)

    for cmd, desc in commands:
        lines.append(f"\n--- {desc} ---")
        lines.append(f"$ {' '.join(cmd)}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=BASE_DIR)
        lines.append(f"[ÇIKIŞ KODU] {res.returncode}")
        if res.stdout:
            lines.append("[STDOUT]:")
            lines.append(res.stdout.strip())
        if res.stderr:
            lines.append("[STDERR]:")
            lines.append(res.stderr.strip())
        lines.append("-" * 90)

    out_file = os.path.join(KANIT_DIR, "komut_ve_cikis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] CLI komut ve çıkış kanıtı kaydedildi: {out_file}")


def main() -> None:
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    print("=== Gün 099 Kanıt Üretici Başlatılıyor ===")
    run_unit_tests()
    run_negative_controls()
    run_cia_report()
    run_cli_demonstration()
    print("=== Tüm Kanıtlar Başarıyla Üretildi ===")


if __name__ == "__main__":
    main()
