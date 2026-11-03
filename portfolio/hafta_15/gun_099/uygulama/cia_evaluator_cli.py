# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 099: CIA Triad ve Güvenlik Nitelikleri Değerlendirme CLI Arayüzü.
Komut satırından işlem paketlerini denetler, tahrifat ve DoS testlerini simüle eder.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve standart çıkış kodları modülü
import sys
# Dosya ve dizin yol yönetimi
import os
# JSON serileştirme ve biçimlendirme
import json
# Zaman modülü
import time

# Yerel modülü içe aktarabilmek için yolu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor bileşenlerini içe aktar
from uygulama.cia_triad_engine import (
    CIASecurityEngine,
    ConfidentialityGuard,
    IntegrityGuard,
    AvailabilityGuard,
    NonRepudiationAuditor,
    CIASecurityVerdict,
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


def build_parser() -> argparse.ArgumentParser:
    """CLI argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(
        prog="cia_evaluator_cli",
        description="G099: CIA Triad ve Güvenlik Nitelikleri Değerlendirme ve Simülasyon Aracı"
    )
    # Hedef dosya yolu
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Değerlendirilecek işlem (JSON veya metin) dosya yolu"
    )
    # Tahrifat (tampering) simülasyon testi
    parser.add_argument(
        "--tamper-test",
        action="store_true",
        help="İletim sırasında 1 baytlık tahrifat (bit-flip) saldırısını simüle eder"
    )
    # DoS (Hizmet Engelleme) frekans testi
    parser.add_argument(
        "--dos-test",
        action="store_true",
        help="Hız limiti aşımı ve DoS saldırı savunmasını simüle eder"
    )
    # Denetim zinciri doğrulama testi
    parser.add_argument(
        "--audit-chain",
        action="store_true",
        help="İnkar edilemezlik denetim zincirinin kriptografik bütünlüğünü doğrular"
    )
    # JSON çıktı modu
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON formatında stdout'a yazar"
    )
    # Çıktı dosya yolu
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Raporun kaydedileceği dosya yolu"
    )
    return parser


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları üretir."""
    parser = build_parser()
    args = parser.parse_args()

    # Hiçbir eylem seçilmemişse yardım göster ve çık
    if not args.file and not args.tamper_test and not args.dos_test and not args.audit_chain:
        parser.print_help(sys.stderr)
        return 2

    # Sabit test anahtarı (32 bayt)
    test_key = b"G099_SECURE_MASTER_KEY_2026_TEST"
    engine = CIASecurityEngine(master_key=test_key)

    try:
        # ----------------------------------------------------------------------
        # 1. TAHRİFAT (TAMPER) TESTİ SİMÜLASYONU
        # ----------------------------------------------------------------------
        if args.tamper_test:
            orijinal = "TRANSFER=5000_TL&ALICI=TR1000&ZAMAN=20261102"
            muhur = IntegrityGuard.seal_message(orijinal, test_key)
            # Saldırgan tutarı 5000 yerine 9000 yapar
            tahrif_edilmis = "TRANSFER=9000_TL&ALICI=TR1000&ZAMAN=20261102"
            dogrulandi = IntegrityGuard.verify_seal(tahrif_edilmis, muhur, test_key)

            if not dogrulandi:
                sys.stdout.write("[GÜVENLİK ALARMI] Tahrifat Başarıyla Tespit Edildi! (CWE-345/CWE-353)\n")
                sys.stdout.write(f"  Orijinal Veri : {orijinal}\n")
                sys.stdout.write(f"  Tahrif Veri   : {tahrif_edilmis}\n")
                sys.stdout.write(f"  Orijinal Mühür: {muhur}\n")
                sys.stdout.write("  Sonuç         : SAHTE İŞLEM REDDEDİLDİ (Bütünlük Korundu)\n")
                return 0
            else:
                sys.stderr.write("[HATA] Tahrifat tespit edilemedi!\n")
                return 1

        # ----------------------------------------------------------------------
        # 2. HİZMET ENGELLEME (DOS) SAVUNMA TESTİ
        # ----------------------------------------------------------------------
        if args.dos_test:
            guard = AvailabilityGuard(max_requests_per_window=10, window_seconds=1.0)
            sys.stdout.write("[BİLGİ] DoS Savunma Testi: 1 saniyede 15 istek gönderiliyor (Limit: 10)\n")
            engellendi = False
            for i in range(1, 16):
                try:
                    guard.record_and_check_request("saldirgan_ip_192.168.1.100")
                except AvailabilityRateLimitExceededError:
                    sys.stdout.write(f"  -> İstek {i}: HIZ LİMİTİ TETİKLENDİ! İstek engellendi. (CWE-770)\n")
                    engellendi = True
                    break

            if engellendi:
                sys.stdout.write("[BAŞARILI] DoS Saldırısı Hız Limitleyici Tarafından Bertaraf Edildi.\n")
                return 0
            else:
                sys.stderr.write("[HATA] İstek limiti aşılamadı!\n")
                return 1

        # ----------------------------------------------------------------------
        # 3. İNKAR EDİLEMEZLİK DENETİM ZİNCİRİ TESTİ
        # ----------------------------------------------------------------------
        if args.audit_chain:
            auditor = NonRepudiationAuditor(test_key)
            auditor.append_log("LOGIN", "admin", "Oturum açıldı")
            auditor.append_log("TRANSFER", "user_1", "1000 TL transfer")
            auditor.append_log("LOGOUT", "admin", "Oturum kapatıldı")

            ok, bad = auditor.verify_chain_integrity()
            sys.stdout.write(f"[BİLGİ] Denetim Zinciri Blok Sayısı: {len(auditor.chain)}\n")
            if ok:
                sys.stdout.write("[BAŞARILI] Tüm bloklar kriptografik olarak doğrulandı. İnkar Edilemezlik Tam.\n")
                return 0
            else:
                sys.stderr.write(f"[HATA] {bad}. blokta zincir bozulması tespit edildi!\n")
                return 1

        # ----------------------------------------------------------------------
        # 4. TEKİL DOSYA CIA DEĞERLENDİRMESİ
        # ----------------------------------------------------------------------
        if args.file:
            if not os.path.exists(args.file):
                sys.stderr.write(f"[HATA] Dosya bulunamadı: {args.file}\n")
                return 2

            with open(args.file, "r", encoding="utf-8") as f:
                content = f.read()

            # Mühür oluştur ve değerlendir
            seal = IntegrityGuard.seal_message(content, test_key)
            verdict = engine.evaluate_transaction(
                payload_data=content,
                asset_name=os.path.basename(args.file),
                is_encrypted=True,
                provided_seal=seal,
                client_id="authorized_client"
            )

            res_dict = verdict.__dict__

            if args.json:
                print(json.dumps(res_dict, indent=2, ensure_ascii=False))
            else:
                print("=" * 80)
                print(f"GÜN 099: CIA GÜVENLİK DEĞERLENDİRME KARNESİ ({verdict.hedef_adi})")
                print("=" * 80)
                print(f"  Gizlilik Skoru        (Max 25): {verdict.gizlilik_skoru}")
                print(f"  Bütünlük Skoru        (Max 25): {verdict.butunluk_skoru}")
                print(f"  Erişilebilirlik Skoru (Max 25): {verdict.erisilebilirlik_skoru}")
                print(f"  İnkar Edilemezlik Sk. (Max 25): {verdict.inkar_edilemezlik_skoru}")
                print("-" * 80)
                print(f"  TOPLAM SKOR           (Max 100): {verdict.toplam_skor}")
                print(f"  DURUM                          : {verdict.durum}")
                print(f"  İhlal Sayısı                   : {verdict.ihlal_sayisi}")
                print("=" * 80)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as out_f:
                    json.dump(res_dict, out_f, indent=2, ensure_ascii=False)
                sys.stderr.write(f"[BİLGİ] Karne kaydedildi: {args.output}\n")

            return 0 if verdict.durum == "PASS" else 1

        return 0

    except CIASecurityError as sec_err:
        sys.stderr.write(f"[GÜVENLİK İHLALİ] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
