# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Örnek Standartlara Tam Uyumlu Güvenlik Otomasyonu Betiği.
Aşama 4'ün tüm kodlama, güvenlik ve mimari standartlarını eksiksiz karşılar.
"""

# Argüman ayrıştırıcı modülü
import argparse
# Sistem giriş/çıkış ve çıkış kodları modülü
import sys
# Dosya ve dizin işlemleri modülü
import os


def build_parser() -> argparse.ArgumentParser:
    """Argüman ayrıştırıcıyı kurar."""
    # Ayrıştırıcı nesnesi oluştur
    parser = argparse.ArgumentParser(
        prog="compliant_tool",
        description="Örnek Tam Uyumlu Güvenlik Otomasyon Betiği"
    )
    # Hedef dosya parametresi
    parser.add_argument(
        "-f", "--file",
        type=str,
        required=True,
        help="İşlenecek dosya yolu"
    )
    # Güvenli işlem modu parametresi
    parser.add_argument(
        "-m", "--mode",
        choices=["audit", "enforce"],
        default="audit",
        help="Çalışma modu"
    )
    # Ayrıştırıcıyı döndür
    return parser


def main() -> int:
    """Ana yürütme fonksiyonu. Standart POSIX çıkış kodları döner."""
    # Argümanları ayrıştır
    parser = build_parser()
    args = parser.parse_args()

    # Dosya varlığı kontrolü (CWE-20)
    if not os.path.exists(args.file):
        # Hata akışına yazdır
        sys.stderr.write(f"[HATA] Dosya bulunamadı: {args.file}\n")
        # Girdi hatası kodu (2)
        return 2

    # Başarılı tamamlama kodu (0)
    return 0


if __name__ == "__main__":
    # Çıkış kodunu sisteme ilet
    sys.exit(main())
