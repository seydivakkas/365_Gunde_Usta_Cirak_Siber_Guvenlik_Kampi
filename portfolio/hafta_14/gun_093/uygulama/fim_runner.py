# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 093: Dosya Bütünlüğü ve FIM Terminal Çalıştırıcısı (fim_runner.py).

Bu betik; tekil dosyaların özetlerini hesaplar, beklenen sağlama toplamları ile
karşılaştırır ve dizin bazlı taban çizgisi (baseline) denetimleri yürütür.
"""

# Standart kütüphaneler
import sys
import os
import json
import argparse
from dataclasses import asdict

# Çekirdek bütünlük modülünü içe aktar
from file_integrity_verifier import (
    FileIntegrityVerifier,
    HashSecurityError,
    IntegrityMismatchError
)

def main() -> int:
    """CLI giriş noktası ve yürütme mantığı."""
    parser = argparse.ArgumentParser(
        prog="sec-fim",
        description="Kriptografik Dosya Bütünlüğü Doğrulama ve FIM Aracı"
    )
    # İşlem modu
    parser.add_argument(
        "--file",
        type=str,
        help="Özeti hesaplanacak veya doğrulanacak dosya yolu"
    )
    parser.add_argument(
        "--expected-hash",
        type=str,
        help="Bütünlük doğrulaması için beklenen referans sağlama toplamı"
    )
    parser.add_argument(
        "--algo",
        type=str,
        default="sha256",
        choices=["sha256", "sha512", "sha3_256", "blake2b", "md5", "sha1"],
        help="Kullanılacak özetleme algoritması (Varsayılan: sha256)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Katı güvenlik modu (Zayıf algoritmaları ve bütünlük uyuşmazlıklarını doğrudan engeller)"
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Çıktıyı yapısal JSON formatında döndürür"
    )

    args = parser.parse_args()

    verifier = FileIntegrityVerifier()

    if not args.file:
        print("[-] Hata: Lütfen işlem yapılacak dosyayı --file ile belirtin.", file=sys.stderr)
        return 2

    try:
        # Eğer beklenen hash verildiyse doğrulama yap
        if args.expected_hash:
            res = verifier.verify_file_integrity(
                args.file,
                expected_hash=args.expected_hash,
                algoritma=args.algo,
                strict_mode=args.strict
            )
            if args.json_output:
                print(json.dumps(asdict(res), indent=2, ensure_ascii=False))
            else:
                print("[+] " + res.durum_mesaji)
                print(f"    - Dosya:     {res.dosya_yolu}")
                print(f"    - Algoritma: {res.algoritma.upper()}")
                print(f"    - Hash:      {res.hesaplanan_hash}")
            return 0 if res.butunluk_dogrulandi_mi else 2
        else:
            # Yalnızca hash hesapla
            res = verifier.compute_file_hash(
                args.file,
                algoritma=args.algo,
                strict_mode=args.strict
            )
            if args.json_output:
                print(json.dumps(asdict(res), indent=2, ensure_ascii=False))
            else:
                print(f"[+] Dosya Özeti Hesaplandı ({res.algoritma.upper()}):")
                print(f"    - Dosya:  {res.dosya_yolu}")
                print(f"    - Boyut:  {res.boyut_bayt} bayt")
                print(f"    - Özet:   {res.hesaplanan_hash}")
                print(f"    - Zaman:  {res.zaman_damgasi_utc}")
            return 0

    except IntegrityMismatchError as ime:
        print(f"[-] Bütünlük İhlali: {ime}", file=sys.stderr)
        return 2
    except HashSecurityError as hse:
        print(f"[-] Güvenlik Hatası: {hse}", file=sys.stderr)
        return 2
    except Exception as unk_err:
        print(f"[-] Çalışma Zamanı Hatası: {unk_err}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
