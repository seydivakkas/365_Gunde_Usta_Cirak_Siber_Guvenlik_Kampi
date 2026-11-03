# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 094: Regex ile Kişisel Veri Maskeleme ve DLP Komut Satırı Arayüzü (CLI).
Standart Unix ve PowerShell boru hatları (pipeline) ile tam uyumlu çalışır.
"""

# Komut satırı argüman ayrıştırma modülü
import argparse
# Sistem giriş/çıkış ve çıkış kodları modülü
import sys
# Dosya ve dizin işlemleri
import os
# JSON veri serileştirme
import json

# Yerel modülü içe aktarabilmek için dosya yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek maskeleme motorunu ve özel hata sınıflarını içe aktar
from uygulama.pii_masker import (
    PIIMaskerEngine,
    PIISecurityError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    ReDoSProtectionTriggered,
    TypeValidationError,
    InvalidRuleError
)


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını yapılandırır ve döndürür."""
    # Ayrıştırıcı nesnesini oluştur
    parser = argparse.ArgumentParser(
        prog="masker_cli",
        description="G094: Kurumsal Kişisel Veri Maskeleme ve DLP Güvenlik Aracı"
    )
    # Girdi dosyası argümanı
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Maskelenecek hedef dosyanın yolu"
    )
    # Doğrudan metin argümanı
    parser.add_argument(
        "-t", "--text",
        type=str,
        help="Doğrudan komut satırından maskelenecek metin"
    )
    # Çıktı dosyası argümanı
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Maskelenmiş metnin yazılacağı çıktı dosyasının yolu"
    )
    # Maskeleme stili seçeneği
    parser.add_argument(
        "-s", "--style",
        choices=["MASK", "REDACT", "HASH"],
        default="MASK",
        help="Maskeleme yöntemi (MASK: Kısmi yıldızlama, REDACT: Tam gizleme, HASH: Kriptografik özet)"
    )
    # Uygulanacak kurallar listesi
    parser.add_argument(
        "-r", "--rules",
        type=str,
        default="all",
        help="Virgülle ayrılmış kural listesi (tckn,credit_card,email,iban,phone,secret,all)"
    )
    # Sıkı doğrulama anahtarı
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Sahte veya algoritması tutmayan verilerde hata fırlatmayı zorunlu kılar"
    )
    # JSON raporlama seçeneği
    parser.add_argument(
        "--json",
        action="store_true",
        help="İşlem sonuç metriklerini JSON formatında ekrana yazar"
    )
    # Yapılandırılmış ayrıştırıcıyı döndür
    return parser


def main() -> int:
    """CLI ana yürütme fonksiyonu. Standart POSIX çıkış kodları döner."""
    # Argüman ayrıştırıcıyı kur
    parser = build_parser()
    # Argümanları ayrıştır
    args = parser.parse_args()

    # Eğer hem dosya hem metin verilmemişse hata ver
    if not args.file and not args.text:
        # Standart hata akışına yazdır
        sys.stderr.write("[HATA] Lütfen maskelenecek bir dosya (--file) veya metin (--text) belirtin.\n")
        # Girdi hatası kodu ile çık
        return 2

    # Maskelenecek ham içeriği belirle
    raw_content = ""
    # Dosya belirtilmişse dosyadan oku
    if args.file:
        # Dosyanın varlığını kontrol et
        if not os.path.exists(args.file):
            # Dosya bulunamadı uyarısı ver
            sys.stderr.write(f"[HATA] Dosya bulunamadı: {args.file}\n")
            # Çıkış kodu dön
            return 2
        # Dosyayı UTF-8 formatında oku
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            # İçeriği değişkene aktar
            raw_content = f.read()
    else:
        # Doğrudan metin argümanını al
        raw_content = args.text

    # Kuralları liste haline getir
    rules_list = [r.strip() for r in args.rules.split(",") if r.strip()]

    try:
        # Maskeleme motorunu başlat
        engine = PIIMaskerEngine(mask_style=args.style)
        # Metni kurallara göre işle
        masked_content, report = engine.process_text(
            raw_text=raw_content,
            rules=rules_list,
            strict_validation=args.strict
        )

        # Eğer çıktı dosyası belirtilmişse yaz
        if args.output:
            # Dosyaya kaydet
            with open(args.output, "w", encoding="utf-8") as out_f:
                # Maskelenmiş metni yaz
                out_f.write(masked_content)
            # Bilgi mesajı yazdır
            sys.stderr.write(f"[BİLGİ] Maskelenmiş çıktı başarıyla kaydedildi: {args.output}\n")
        else:
            # JSON bayrağı aktif değilse maskelenmiş metni ekrana yaz
            if not args.json:
                # Ekrana bas
                print(masked_content)

        # Eğer JSON rapor istenmişse ekrana yazdır
        if args.json:
            # JSON formatında yaz
            print(json.dumps(report, indent=2, ensure_ascii=False))

        # Başarılı çıkış kodu
        return 0

    except PIISecurityError as pii_err:
        # Güvenlik istisnasını yakala
        sys.stderr.write(f"[GÜVENLİK ENGELİ] {type(pii_err).__name__}: {str(pii_err)}\n")
        # Güvenlik engeli kodu ile çık
        return 1
    except Exception as exc:
        # Beklenmeyen sistem hatası
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        # Sistem hatası kodu ile çık
        return 2


if __name__ == "__main__":
    # Betik doğrudan çalıştırıldığında çıkış kodunu döndür
    sys.exit(main())
