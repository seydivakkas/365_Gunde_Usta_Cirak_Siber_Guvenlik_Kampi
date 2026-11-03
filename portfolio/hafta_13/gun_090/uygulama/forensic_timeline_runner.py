# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 090: Adli Bilişim Zaman Çizgisi Terminal Çalıştırıcısı (CLI Runner).

Bu betik; heterojen sunucu loglarını okur, UTC zaman normalizasyonu gerçekleştirir,
saat sapması kontrollerini yapar ve adli bilişim zaman çizelgesi çıktısını üretir.
"""

# Standart sistem ve argüman modüllerini içe aktar
import sys
import os
import json
import argparse
from dataclasses import asdict

# Çekirdek adli bilişim motorunu içe aktar
from utc_timezone_forensic_normalizer import (
    UtcTimezoneForensicNormalizer,
    TimestampSecurityError,
    ClockSkewAuditResult
)

def main() -> int:
    """Terminal giriş noktası ve CLI koordinatörü."""
    # Argüman ayrıştırıcıyı yapılandır
    parser = argparse.ArgumentParser(
        prog="forensic-timeline",
        description="Heterojen Log Zaman Damgası Normalizasyon ve Adli Bilişim Aracı"
    )
    # Log dosyası girdi yolu parametresi
    parser.add_argument(
        "--input-logs",
        type=str,
        default="ornek_veri/sample_multisource_logs.json",
        help="İncelenecek JSON formatındaki log dosyası yolu"
    )
    # JSON çıktısı üretme bayrağı
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Çıktıyı yapısal JSON formatında döndürür"
    )
    # Saat sapması denetim bayrağı
    parser.add_argument(
        "--audit-skew",
        action="store_true",
        help="Kerberos/OAuth saat sapması (Clock Skew) testini yürütür"
    )

    # Argümanları ayrıştır
    args = parser.parse_args()

    # Normalizasyon motorunu başlat
    normalizer = UtcTimezoneForensicNormalizer(varsayilan_maks_sapma=300)

    # Saat sapması testi talep edildiyse
    if args.audit_skew:
        # Örnek istemci ve sunucu zamanlarını tanımla
        istemci_ornek = "2026-11-01T14:32:10Z"
        referans_ornek = "2026-11-01T14:30:00Z"
        # Denetimi çalıştır
        skew_res = normalizer.audit_clock_skew(istemci_ornek, referans_ornek)
        # JSON isteniyorsa
        if args.json_output:
            print(json.dumps(asdict(skew_res), indent=2, ensure_ascii=False))
        else:
            print("[+] Saat Sapması (Clock Skew) Denetim Raporu:")
            print(f"    - İstemci Zamanı:   {skew_res.istemci_zamani_utc}")
            print(f"    - Referans Zamanı:  {skew_res.referans_zamani_utc}")
            print(f"    - Sapma Farkı:      {skew_res.sapma_saniyesi} saniye")
            print(f"    - Güvenli mi?:      {skew_res.sapma_guvenli_mi}")
            print(f"    - Hüküm:            {skew_res.hukum}")
        return 0

    # Log dosyasının varlığını denetle
    if not os.path.exists(args.input_logs):
        print(f"[-] Hata: Belirtilen log dosyası bulunamadı: {args.input_logs}", file=sys.stderr)
        return 1

    # Log dosyasını oku
    with open(args.input_logs, "r", encoding="utf-8") as f:
        ham_loglar = json.load(f)

    try:
        # Adli zaman çizgisini inşa et
        zaman_cizgisi = normalizer.build_forensic_timeline(ham_loglar)

        # JSON formatında çıktı isteniyorsa
        if args.json_output:
            cikti_listesi = [asdict(olay) for olay in zaman_cizgisi]
            print(json.dumps(cikti_listesi, indent=2, ensure_ascii=False))
        else:
            # Metin formatında rapor üret
            rapor = normalizer.generate_forensic_report(zaman_cizgisi)
            print(rapor)

        return 0
    except TimestampSecurityError as err:
        print(f"[-] Güvenlik ve Zaman Damgası Hatası: {err}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    # Betik doğrudan çağrıldığında çalıştır ve çıkış kodunu döndür
    sys.exit(main())
