# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 102: Güvenli Parola Saklama ve KDF CLI Yönetim Aracı.
Bu komut satırı arayüzü; kurumsal standartlarda parola hashleme, sabit zamanlı
doğrulama, eski ve güvensiz tuzsuz hash tespiti ve veritabanı sızıntısı
simülasyonlarını (Pepper koruması) yürütür.
"""

# Komut satırı argüman ayrıştırma kütüphanesi
import argparse
# JSON veri serileştirme modülü
import json
# Sistem çıkış kodları ve yol yönetimi
import sys
# İşletim sistemi fonksiyonları
import os

# Üst dizini modül arama yoluna ekle (bağımsız çalışma)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Güvenli parola kasası motoru ve istisnaları içe aktar
from uygulama.secure_password_vault import (
    PasswordHasher,
    PasswordHashRecord,
    PasswordVerificationResult,
    PasswordVaultError,
    UnsaltedHashError,
    InsufficientIterationsError,
    InsecureSaltLengthError,
    PredictableSaltError,
    PasswordVerificationMismatchError,
    PayloadLimitExceededError,
    NullByteInjectionError,
    TypeValidationError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını yapılandırır."""
    # Ana argüman ayrıştırıcı nesnesini oluştur
    parser = argparse.ArgumentParser(
        description="Gün 102: Salt, Pepper ve KDF Tabanlı Güvenli Parola Saklama Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Alt komutlar veya bayraklar için karşılıklı hariç tutulan mod grubu
    mode_group = parser.add_mutually_exclusive_group(required=True)
    # Parola hashleme modu bayrağı
    mode_group.add_argument("--hash", action="store_true", help="Yeni parolayı PBKDF2-HMAC-SHA256 ile hashle")
    # Parola doğrulama modu bayrağı
    mode_group.add_argument("--verify", action="store_true", help="Mevcut parola kaydını doğrula")
    # Eski/güvensiz hash tespit modu bayrağı
    mode_group.add_argument("--detect-legacy", action="store_true", help="Verilen hash dizgisinin güvenlik analizini yap")
    # Veritabanı sızıntısı simülasyon modu bayrağı
    mode_group.add_argument("--leak-test", action="store_true", help="Biberli vs bibersiz sızıntı savunma simülasyonu yap")

    # Parola metni parametresi
    parser.add_argument("--password", type=str, help="İşlenecek düz metin parola")
    # Kayıtlı serileştirilmiş hash kaydı parametresi
    parser.add_argument("--record", type=str, help="Doğrulanacak serileştirilmiş kayıt ($pbkdf2...)")
    # Sistem biberi (pepper) parametresi
    parser.add_argument("--pepper", type=str, default=None, help="Sistem düzeyi gizli biber (pepper) metni")
    # İterasyon sayısı parametresi
    parser.add_argument("--iterations", type=int, default=100000, help="PBKDF2 iterasyon adedi (Varsayılan: 100.000)")
    # Analiz edilecek hash dizgisi parametresi
    parser.add_argument("--hash-str", type=str, help="Analiz edilecek eski hash dizgisi (MD5/SHA1/SHA256)")
    # JSON çıktı formatı bayrağı
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında yazdır")

    # Yapılandırılan ayrıştırıcıyı döndür
    return parser


def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    # Argüman ayrıştırıcıyı inşa et
    parser = build_parser()
    # Komut satırı argümanlarını ayrıştır
    args = parser.parse_args()

    try:
        # 1. PAROLA HASHLEME MODU
        if args.hash:
            # Parola parametresinin varlığını denetle
            if not args.password:
                # Eksik parametre uyarısı ver
                sys.stderr.write("HATA: --hash modu için --password parametresi zorunludur!\n")
                # Kod 2 ile dön
                return 2

            # Pepper baytlarını hazırla
            pepper_bytes = args.pepper.encode("utf-8") if args.pepper else None
            # Parolayı güvenli şekilde hashle
            record = PasswordHasher.hash_password(
                password=args.password,
                pepper=pepper_bytes,
                iterations=args.iterations
            )

            # JSON çıktı istenmişse
            if args.json:
                # Sözlük çıktısını ekrana yazdır
                print(json.dumps({
                    "durum": "BASARILI",
                    "algoritma": record.algoritma,
                    "iterasyon": record.iterasyon,
                    "salt_hex": record.salt_hex,
                    "has_pepper": record.has_pepper,
                    "hash_hex": record.hash_hex,
                    "tam_format": record.tam_format
                }, indent=2, ensure_ascii=False))
            else:
                # İnsan okunabilir formatta yazdır
                print("=== GÜVENLİ PAROLA HASHLEME BAŞARILI ===")
                print(f"Algoritma   : {record.algoritma}")
                print(f"İterasyon   : {record.iterasyon:,}")
                print(f"Tuz (Salt)  : {record.salt_hex}")
                print(f"Biber Var mı: {'Evet' if record.has_pepper else 'Hayır'}")
                print(f"Özet (Hash) : {record.hash_hex}")
                print(f"Tam Kayıt   : {record.tam_format}")

            # Başarılı çıkış kodu
            return 0

        # 2. PAROLA DOĞRULAMA MODU
        elif args.verify:
            # Gerekli parametrelerin varlığını denetle
            if not args.password or not args.record:
                # Eksik parametre uyarısı ver
                sys.stderr.write("HATA: --verify modu için --password ve --record parametreleri zorunludur!\n")
                # Kod 2 ile dön
                return 2

            # Pepper baytlarını hazırla
            pepper_bytes = args.pepper.encode("utf-8") if args.pepper else None
            # Doğrulama fonksiyonunu çağır
            sonuc = PasswordHasher.verify_password(
                password=args.password,
                stored_record=args.record,
                pepper=pepper_bytes,
                strict_mode=False
            )

            # JSON çıktı istenmişse
            if args.json:
                # Sonucu JSON olarak yazdır
                print(json.dumps({
                    "durum": "BASARILI" if sonuc.dogrulandi else "UYUSMAZLIK",
                    "dogrulandi": sonuc.dogrulandi,
                    "algoritma": sonuc.algoritma,
                    "iterasyon": sonuc.iterasyon,
                    "pepper_kullanildi": sonuc.pepper_kullanildi,
                    "gecen_sure_ms": sonuc.gecen_sure_ms
                }, indent=2, ensure_ascii=False))
            else:
                # İnsan okunabilir çıktı
                print("=== PAROLA DOĞRULAMA RAPORU ===")
                print(f"Doğrulama Durumu : {'✓ GEÇERLİ' if sonuc.dogrulandi else '✗ GEÇERSİZ'}")
                print(f"Algoritma        : {sonuc.algoritma}")
                print(f"İterasyon        : {sonuc.iterasyon:,}")
                print(f"Biber Kullanıldı : {'Evet' if sonuc.pepper_kullanildi else 'Hayır'}")
                print(f"Doğrulama Süresi : {sonuc.gecen_sure_ms} ms")

            # Eşleşme varsa 0, yoksa 1 dön
            return 0 if sonuc.dogrulandi else 1

        # 3. ESKİ / GÜVENSİZ HASH TESPİT MODU
        elif args.detect_legacy:
            # Hash metni parametresi denetimi
            if not args.hash_str:
                # Eksik parametre uyarısı
                sys.stderr.write("HATA: --detect-legacy modu için --hash-str parametresi zorunludur!\n")
                # Kod 2 ile dön
                return 2

            # Güvensizlik analizini yürüt
            analiz = PasswordHasher.detect_insecure_hashing(args.hash_str)

            # JSON çıktısı
            if args.json:
                # JSON serileştir
                print(json.dumps(analiz, indent=2, ensure_ascii=False))
            else:
                # Ekrana yazdır
                print("=== PAROLA HASH GÜVENLİK DENETİMİ ===")
                print(f"Tespit Edilen Tip: {analiz['tip']}")
                print(f"Güvenlik Düzeyi  : {analiz['guvenlik']}")
                print(f"Zafiyet Açıklama : {analiz['zafiyet']}")
                print(f"Önerilen Çözüm   : {analiz['onerilen']}")

            # Güvenli ise 0, zafiyetli ise 1 dön
            return 0 if "GÜVENLİ" in analiz["guvenlik"] else 1

        # 4. SIZINTI VE BİBER SAVUNMA SİMÜLASYONU
        elif args.leak_test:
            # Test parolası
            test_pw = "KurumsalParola2026!"
            # Test biberi
            secret_pepper = b"HSM_KMS_KORUMALI_GIZLI_BIBER_ANAHTARI"

            # 1. Tuzlu ama bibersiz kayıt üret
            kayit_bibersiz = PasswordHasher.hash_password(test_pw, iterations=100000)
            # 2. Hem tuzlu hem biberli kayıt üret
            kayit_biberli = PasswordHasher.hash_password(test_pw, pepper=secret_pepper, iterations=100000)

            # Simülasyon senaryosu: Veritabanı sızdı (SQL Injection ile dump alındı)
            # Saldırgan tuzları ve hashleri ele geçirdi.
            # Bibersiz kayıtta: Saldırgan offline GPU ile tuz + parolayı dener.
            # Biberli kayıtta: Saldırgan HSM'deki pepper'a sahip olmadığı için tek bir deneme bile yapamaz!
            simulasyon_sonuc = {
                "senaryo": "Veritabanı Sızıntısı (SQL Injection / Veri İhlali)",
                "test_parolasi": test_pw,
                "bibersiz_kayit": {
                    "format": kayit_bibersiz.tam_format,
                    "savunma_durumu": "Kısmi (Rainbow Table engellenir, ancak çevrimdışı GPU sözlük saldırısına açıktır)",
                    "saldirgan_offline_kirabilir_mi": True
                },
                "biberli_kayit": {
                    "format": kayit_biberli.tam_format,
                    "savunma_durumu": "Tam Korumalı (Biber veritabanında saklanmaz; HSM/KMS içindedir)",
                    "saldirgan_offline_kirabilir_mi": False
                },
                "hoca_yorumu": "Tuz (salt) gökkuşağı tablolarını imkansız kılar; Biber (pepper) ise veritabanı sızıntısında çevrimdışı kaba kuvveti imkansız kılar."
            }

            # JSON çıktısı
            if args.json:
                # JSON olarak yazdır
                print(json.dumps(simulasyon_sonuc, indent=2, ensure_ascii=False))
            else:
                # Konsol çıktısı
                print("=== VERİTABANI SIZINTISI SAVUNMA SİMÜLASYONU ===")
                print(f"Senaryo               : {simulasyon_sonuc['senaryo']}")
                print(f"1. Bibersiz Kayıt     : {simulasyon_sonuc['bibersiz_kayit']['savunma_durumu']}")
                print(f"   Çevrimdışı Kırma   : {'Mümkün (Riskli)' if simulasyon_sonuc['bibersiz_kayit']['saldirgan_offline_kirabilir_mi'] else 'Engellendi'}")
                print(f"2. Biberli Kayıt      : {simulasyon_sonuc['biberli_kayit']['savunma_durumu']}")
                print(f"   Çevrimdışı Kırma   : {'Mümkün' if simulasyon_sonuc['biberli_kayit']['saldirgan_offline_kirabilir_mi'] else 'İMKANSIZ (Biber HSM içinde)'}")
                print(f"Ustanın Dersi         : {simulasyon_sonuc['hoca_yorumu']}")

            # Başarılı çıkış
            return 0

    except PasswordVaultError as pve:
        # Kütüphane güvenlik hatalarını yakala
        sys.stderr.write(f"GÜVENLİK HATASI: {type(pve).__name__} - {str(pve)}\n")
        # Güvenlik istisnası çıkış kodu
        return 1
    except Exception as exc:
        # Beklenmeyen sistem hatalarını yakala
        sys.stderr.write(f"SİSTEMSEL HATA: {str(exc)}\n")
        # Hata kodu 2
        return 2

    # Varsayılan dönüş
    return 0


# Doğrudan çalıştırıldığında main fonksiyonunu çağır
if __name__ == "__main__":
    # Sistem çıkış koduyla sonlan
    sys.exit(main())
