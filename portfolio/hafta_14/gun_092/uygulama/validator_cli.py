# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 092: Veri Doğrulama ve Tip Güvenliği Terminal Çalıştırıcısı (validator_cli.py).

Bu betik; güvenlik varlıklarının JSON dosyalarını okur, doğrulama motorundan geçirir
ve standart POSIX çıkış kodlarıyla (0, 1, 2) durum raporu sunar.
"""

# Standart sistem modülleri
import sys
import os
import json
import argparse
from dataclasses import asdict

# Çekirdek doğrulama modülünü içe aktar
from security_data_validator import (
    SecurityDataValidator,
    SecurityValidationError
)

def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = argparse.ArgumentParser(
        prog="sec-validator",
        description="Siber Güvenlik Varlıkları ve Ağ Yapılandırması Tip Güvenliği Doğrulayıcı"
    )
    # Girdi dosya yolu
    parser.add_argument(
        "--input-file",
        type=str,
        default="ornek_veri/valid_security_assets.json",
        help="Doğrulanacak JSON dosya yolu"
    )
    # JSON çıktısı üretme seçeneği
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Çıktıyı yapısal JSON formatında döndürür"
    )
    # Sıkı mod bayrağı (herhangi bir hata durumunda exit 2)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Herhangi bir doğrulama hatasında işlemi durdurur ve çıkış kodu 2 döndürür"
    )

    args = parser.parse_args()

    # Dosya varlığı kontrolü
    if not os.path.exists(args.input_file):
        print(f"[-] Hata: Girdi dosyası bulunamadı: {args.input_file}", file=sys.stderr)
        return 1

    # Dosyayı oku
    try:
        with open(args.input_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as io_err:
        print(f"[-] JSON okuma hatası: {io_err}", file=sys.stderr)
        return 1

    # Liste formatına emin ol
    if isinstance(raw_data, dict):
        assets_list = [raw_data]
    elif isinstance(raw_data, list):
        assets_list = raw_data
    else:
        print("[-] Hata: JSON içeriği sözlük veya liste olmalıdır.", file=sys.stderr)
        return 2

    validator = SecurityDataValidator()
    valid_assets, errors = validator.batch_validate(assets_list)

    if args.json_output:
        sonuc_ozeti = {
            "toplam_kayit": len(assets_list),
            "gecerli_kayit_sayisi": len(valid_assets),
            "hatali_kayit_sayisi": len(errors),
            "gecerli_varliklar": [asdict(a) for a in valid_assets],
            "hatalar": errors
        }
        print(json.dumps(sonuc_ozeti, indent=2, ensure_ascii=False))
    else:
        print("=" * 75)
        print("SİBER GÜVENLİK VERİ DOĞRULAMA VE TİP GÜVENLİĞİ RAPORU")
        print("=" * 75)
        print(f"Toplam İncelenen Kayıt: {len(assets_list)}")
        print(f"Başarıyla Doğrulanan:  {len(valid_assets)}")
        print(f"Hatalı Kayıt Sayısı:   {len(errors)}")
        print("-" * 75)
        if errors:
            print("[!] TESPİT EDİLEN DOĞRULAMA HATALARI:")
            for e in errors:
                print(f"    - Kayıt #{e['indis']}: [{e['hata_tipi']}] {e['mesaj']}")
        else:
            print("[+] Tüm varlıklar tip güvenliği ve sınır denetimlerinden başarıyla geçti.")
        print("=" * 75)

    # Sıkı modda hata varsa 2 döndür
    if args.strict and errors:
        return 2

    return 0

if __name__ == "__main__":
    sys.exit(main())
