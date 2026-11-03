# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 105: Mini Proje 14 - Kriptografik Hash Bütünlük Manifesti CLI Aracı.
Bu komut satırı arayüzü; dosya bütünlük manifestosu oluşturma, HMAC ile mühürleme,
disk denetimi ve tahrifat simülasyonlarını kurumsal standartlarda yürütür.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# JSON veri dönüştürücüsü
import json
# Sistem çıkış kodları ve yol yönetimi
import sys
# Dosya sistemi araçları
import os

# Üst dizini sys.path'e ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Bütünlük motoru bileşenlerini içe aktar
from uygulama.hash_manifest_engine import (
    HashManifestEngine,
    ManifestAuditScorecard,
    ManifestEngineError,
    BrokenHashAlgorithmError,
    ManifestTamperingError,
    PathTraversalError,
    SymlinkEscapeError,
    DirectoryNotFoundError,
    FileIntegrityMismatchError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını inşa eder."""
    parser = argparse.ArgumentParser(
        description="Gün 105: Kriptografik Hash Bütünlük Manifesti Yönetim Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--create", action="store_true", help="Dizin için yeni bütünlük manifestosu oluştur")
    mode_group.add_argument("--verify", action="store_true", help="Mevcut manifestoyu disk durumuyla doğrula")
    mode_group.add_argument("--tamper-sim", action="store_true", help="Bütünlük tahrifatı ve tespit simülasyonu yap")

    # Parametreler
    parser.add_argument("--dir", type=str, help="Taranacak kök dizin yolu")
    parser.add_argument("--manifest", type=str, help="Okunacak veya yazılacak manifest JSON dosyası yolu")
    parser.add_argument("--key", type=str, default=None, help="Manifest HMAC mühürleme/doğrulama anahtarı")
    parser.add_argument("--algo", type=str, default="sha256", choices=["sha256", "sha512", "blake2b"], help="Hash algoritması")
    parser.add_argument("--strict", action="store_true", help="Katı güvenlik modu (Herhangi bir uyuşmazlıkta hata fırlat)")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında yazdır")

    return parser


def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        # 1. MANİFEST OLUŞTURMA
        if args.create:
            if not args.dir:
                sys.stderr.write("HATA: --create için --dir parametresi zorunludur!\n")
                return 2

            manifest_dict = HashManifestEngine.create_manifest(
                root_dir=args.dir,
                signing_key=args.key,
                algo=args.algo
            )

            # Dosyaya kaydetme istenmişse
            if args.manifest:
                with open(args.manifest, "w", encoding="utf-8") as f:
                    json.dump(manifest_dict, f, indent=2, ensure_ascii=False)

            if args.json:
                print(json.dumps(manifest_dict, indent=2, ensure_ascii=False))
            else:
                print("=== HASH BÜTÜNLÜK MANİFESTOSU OLUŞTURULDU ===")
                print(f"Kök Dizin      : {manifest_dict['kok_dizin']}")
                print(f"Algoritma      : {manifest_dict['algoritma']}")
                print(f"Toplam Dosya   : {manifest_dict['toplam_dosya']}")
                print(f"Toplam Boyut   : {manifest_dict['toplam_boyut_bayt']} Bayt")
                print(f"HMAC Mührü     : {manifest_dict['hmac_muhru'] if manifest_dict['hmac_muhru'] else 'Mühürsüz'}")
                if args.manifest:
                    print(f"Kaydedilen Dosya: {args.manifest}")
            return 0

        # 2. MANİFEST DOĞRULAMA
        elif args.verify:
            if not args.dir or not args.manifest:
                sys.stderr.write("HATA: --verify için --dir ve --manifest parametreleri zorunludur!\n")
                return 2

            with open(args.manifest, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            scorecard = HashManifestEngine.verify_manifest(
                root_dir=args.dir,
                manifest_data=manifest_data,
                signing_key=args.key,
                strict_mode=args.strict
            )

            if args.json:
                print(json.dumps({
                    "durum": scorecard.verdict,
                    "mühür_geçerli": scorecard.seal_valid,
                    "beklenen_dosya": scorecard.total_expected,
                    "bulunan_dosya": scorecard.total_found,
                    "eşleşen": scorecard.matched_count,
                    "değiştirilen": scorecard.modified_count,
                    "eklenen": scorecard.added_count,
                    "silinen": scorecard.deleted_count,
                    "süre_ms": scorecard.elapsed_ms
                }, indent=2, ensure_ascii=False))
            else:
                print("=== BÜTÜNLÜK DENETİM KARNESİ ===")
                print(f"Denetim Kararı  : {'✓ BÜTÜNLÜK ONAYLANDI (TEMİZ)' if scorecard.verdict == 'INTEGRITY_VERIFIED' else '✗ TAHRİFAT TESPİT EDİLDİ!'}")
                print(f"HMAC Mührü      : {'✓ GEÇERLİ' if scorecard.seal_valid else '✗ GEÇERSİZ / BOZUK'}")
                print(f"Eşleşen Dosyalar: {scorecard.matched_count} / {scorecard.total_expected}")
                print(f"Değiştirilenler : {scorecard.modified_count}")
                print(f"Yeni Eklenenler : {scorecard.added_count}")
                print(f"Silinenler      : {scorecard.deleted_count}")
                print(f"Tarama Süresi   : {scorecard.elapsed_ms} ms")

            return 0 if scorecard.verdict == "INTEGRITY_VERIFIED" else 1

        # 3. TAHRİFAT SİMÜLASYONU
        elif args.tamper_sim:
            test_dir = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "sample_project_tree")
            test_key = "MASTER_INTEGRITY_KEY_2026"

            # 1. Orijinal manifestoyu al
            base_manifest = HashManifestEngine.create_manifest(test_dir, signing_key=test_key)

            # 2. Simülasyon Senaryoları
            sim_rapor = {
                "deney": "Dosya Bütünlük Tahrifatı ve HMAC Mühür Denetimi Simülasyonu",
                "temiz_denetim": "Tam Eşleşme (Değişiklik yok -> INTEGRITY_VERIFIED)",
                "senaryolar": [
                    {
                        "tur": "Dosya İçeriği Değişimi",
                        "aciklama": "Saldırgan bir dosyaya zararlı kod eklediğinde SHA-256 hash uyuşmazlığı tespit edilir (CWE-354)."
                    },
                    {
                        "tur": "HMAC Mührü Sahtelemesi",
                        "aciklama": "Saldırgan dosyaları değiştirip manifestoyu yeniden yazsa bile anahtarı bilmediği için sahte HMAC mührü yakalanır (CWE-353)."
                    },
                    {
                        "tur": "Yetkisiz Dosya Enjeksiyonu",
                        "aciklama": "Manifestte olmayan arka kapı (backdoor) dosyası ADDED olarak raporlanır."
                    }
                ],
                "ustanin_dersi": "Bütünlük manifestosunu HMAC veya dijital imza ile mühürlemezseniz, saldırgan dosyayı değiştirdikten sonra manifestoyu da günceller ve denetimi atlatır!"
            }

            if args.json:
                print(json.dumps(sim_rapor, indent=2, ensure_ascii=False))
            else:
                print("=== BÜTÜNLÜK TAHRİFAT SİMÜLASYONU RAPORU ===")
                print(f"Deney Adı    : {sim_rapor['deney']}")
                print(f"Temiz Durum  : {sim_rapor['temiz_denetim']}")
                print("Senaryolar   :")
                for s in sim_rapor["senaryolar"]:
                    print(f"  - [{s['tur']}]: {s['aciklama']}")
                print(f"Ustanın Dersi: {sim_rapor['ustanin_dersi']}")

            return 0

    except ManifestEngineError as mee:
        sys.stderr.write(f"BÜTÜNLÜK DENETİM HATASI: {type(mee).__name__} - {str(mee)}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"SİSTEMSEL HATA: {str(exc)}\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
