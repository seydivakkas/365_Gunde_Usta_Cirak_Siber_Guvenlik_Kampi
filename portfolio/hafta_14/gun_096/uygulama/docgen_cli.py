# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 096: Güvenli Betik Kullanım Belgeleri Komut Satırı Arayüzü (CLI).
Standart Unix ve PowerShell boru hatları (pipeline) ile tam uyumlu çalışır.
"""

# Komut satırı argüman ayrıştırıcısı
import argparse
# Sistem giriş/çıkış ve çıkış kodları modülü
import sys
# Dosya ve dizin işlemleri
import os
# JSON veri serileştirme
import json

# Yerel modülü içe aktarabilmek için dosya yolunu ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Çekirdek motor sınıflarını ve hata türlerini içe aktar
from uygulama.security_doc_generator import (
    SecurityScriptDoc,
    DocGenerator,
    SecurityDocLinter,
    DocSecurityError,
    MissingMandatoryDocumentationError,
    MissingExitCodesDocumentationError,
    UndocumentedArgumentError,
    NullByteInjectionError,
    PayloadLimitExceededError,
    InvalidFormatError,
    InvalidPrivilegeLevelError,
    TypeValidationError,
    MissingLicenseHeaderError
)


def build_parser() -> argparse.ArgumentParser:
    """Argüman ayrıştırıcıyı kurar."""
    parser = argparse.ArgumentParser(
        prog="docgen_cli",
        description="G096: Güvenlik Betikleri Belge Üretici ve Dokümantasyon Linter Aracı"
    )
    # Şema dosyası yolu
    parser.add_argument(
        "-s", "--schema",
        type=str,
        required=True,
        help="Güvenlik betiği JSON şema dosyasının yolu"
    )
    # Kaynak betik yolu (Linter için)
    parser.add_argument(
        "-c", "--source",
        type=str,
        default=None,
        help="Denetlenecek Python kaynak betiğinin yolu"
    )
    # Çıktı formatı seçimi
    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "help", "man", "json"],
        default="markdown",
        help="Üretilecek belgenin formatı (markdown, help, man, json)"
    )
    # Linter çalıştırma bayrağı
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Kaynak kod ile belge şeması arasındaki senkronizasyonu ve lisansı denetler"
    )
    # Çıktı dosyası yolu
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Üretilen belgenin yazılacağı çıktı dosyası"
    )
    return parser


def main() -> int:
    """CLI ana fonksiyonu. Standart POSIX çıkış kodları döner."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        # Şema dosyasını yükle
        doc = SecurityScriptDoc.from_json_file(args.schema)

        # Eğer linter istenmişse
        if args.lint:
            if not args.source:
                sys.stderr.write("[HATA] Linter (--lint) çalıştırmak için kaynak betik (--source) belirtilmelidir.\n")
                return 2

            # Linter çalıştır
            lint_res = SecurityDocLinter.lint(args.source, doc)
            sys.stderr.write(f"[LINTER BAŞARILI] {doc.betik_adi} için tüm parametreler ve lisans doğrulandı.\n")

        # Belge üreticiyi başlat
        generator = DocGenerator(doc)

        # Format seçimine göre belge üret
        if args.format == "markdown":
            output_content = generator.generate_markdown()
        elif args.format == "help":
            output_content = generator.generate_help_text()
        elif args.format == "man":
            output_content = generator.generate_man_page()
        elif args.format == "json":
            output_content = json.dumps(doc.raw_data, indent=2, ensure_ascii=False)
        else:
            raise InvalidFormatError(f"Desteklenmeyen format: {args.format}")

        # Eğer çıktı dosyası belirtilmişse kaydet
        if args.output:
            with open(args.output, "w", encoding="utf-8") as out_f:
                out_f.write(output_content)
            sys.stderr.write(f"[BİLGİ] Belge başarıyla kaydedildi: {args.output}\n")
        else:
            # Standart çıktıya yaz
            print(output_content)

        return 0

    except (UndocumentedArgumentError, MissingLicenseHeaderError) as lint_err:
        sys.stderr.write(f"[LINTER İHLALİ] {type(lint_err).__name__}: {str(lint_err)}\n")
        return 1
    except DocSecurityError as sec_err:
        sys.stderr.write(f"[ŞEMA / GÜVENLİK HATASI] {type(sec_err).__name__}: {str(sec_err)}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"[SİSTEM HATASI] {str(exc)}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
