# portfolio/hafta_24/gun_168/uygulama/secure_file_service_cli.py
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

"""
Mini Proje 23: Güvenli Dosya Servisi Komut Satırı Arayüzü (CLI).
Güvenli dosya yükleme, indirme, zararlı kod tarama, SSRF-güvenli getirme ve denetim raporu işlemlerini yönetir.
"""

import sys
import json
import argparse
from typing import List, Optional
from secure_file_service_engine import SecureFileService, SecurityException


def build_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını oluşturur."""
    # Ana argüman ayrıştırıcı tanımlanır
    parser = argparse.ArgumentParser(
        prog="secure_file_service_cli",
        description="Kurumsal Güvenli Dosya Servisi ve İndirme Ağ Geçidi Yönetim Aracı"
    )

    # Alt komut ayrıştırıcı kümesi eklenir
    subparsers = parser.add_subparsers(dest="command", required=True, help="Çalıştırılacak alt komut")

    # 1. upload alt komutu
    upload_parser = subparsers.add_parser("upload", help="Güvenli depoya yeni bir dosya yükler")
    # Dosya adı parametresi
    upload_parser.add_argument("--filename", required=True, help="Yüklenecek dosyanın adı")
    # Dosya içeriği (metin olarak) parametresi
    upload_parser.add_argument("--content", required=False, default="%PDF-1.4\nTest Content\n%%EOF", help="Dosya içeriği")
    # Kullanıcı kimliği
    upload_parser.add_argument("--user-id", required=False, default="user_101", help="Yükleyen kullanıcı ID")
    # Kiracı kimliği
    upload_parser.add_argument("--tenant-id", required=False, default="tenant_alpha", help="Kurum/Kiracı ID")

    # 2. download alt komutu
    download_parser = subparsers.add_parser("download", help="UUID ile güvenli depodan dosya indirir")
    # Dosya UUID'si
    download_parser.add_argument("--file-id", required=True, help="İndirilecek dosyanın benzersiz UUID'si")
    # Talep eden kullanıcı ID
    download_parser.add_argument("--user-id", required=False, default="user_101", help="Talep eden kullanıcı ID")
    # Talep eden kiracı ID
    download_parser.add_argument("--tenant-id", required=False, default="tenant_alpha", help="Talep eden kiracı ID")
    # Kullanıcı rolü
    download_parser.add_argument("--role", required=False, default="user", choices=["user", "admin"], help="Kullanıcı rolü")

    # 3. scan alt komutu
    scan_parser = subparsers.add_parser("scan", help="Dosya adını ve içeriğini zararlı kalıplara karşı tarar")
    # Taranacak dosya adı
    scan_parser.add_argument("--filename", required=True, help="Taranacak dosya adı")
    # Taranacak içerik
    scan_parser.add_argument("--content", required=False, default="", help="Taranacak metin içeriği")

    # 4. fetch-remote alt komutu
    fetch_parser = subparsers.add_parser("fetch-remote", help="Uzak adresten SSRF-güvenli dosya indirir")
    # Hedef URL
    fetch_parser.add_argument("--url", required=True, help="İndirilecek hedef URL")
    # Kullanıcı ID
    fetch_parser.add_argument("--user-id", required=False, default="user_101", help="Talep eden kullanıcı ID")
    # Kiracı ID
    fetch_parser.add_argument("--tenant-id", required=False, default="tenant_alpha", help="Talep eden kiracı ID")

    # 5. audit-report alt komutu
    subparsers.add_parser("audit-report", help="Güvenlik denetim ve olay raporunu görüntüler")

    # Ayrıştırıcı nesnesi döndürülür
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI giriş noktası ve komut yönlendiricisi."""
    # Ayrıştırıcı oluşturulur
    parser = build_parser()
    # Argümanlar ayrıştırılır
    args = parser.parse_args(argv)

    # Dosya servisi başlatılır (geçici depo simülasyonu)
    service = SecureFileService(base_storage_dir="temp_storage_cli")

    try:
        # upload komutu işletilir
        if args.command == "upload":
            # İçerik baytlara çevrilir
            content_bytes = args.content.encode("utf-8")
            # Dosya kaydedilir
            meta = service.store_file(args.filename, content_bytes, args.user_id, args.tenant_id)
            # Başarılı sonuç yazdırılır
            print(json.dumps({
                "durum": "BASARILI",
                "mesaj": "Dosya güvenle yüklendi ve UUID atandı.",
                "dosya": meta.to_dict()
            }, indent=2, ensure_ascii=False))
            return 0

        # download komutu işletilir
        elif args.command == "download":
            # Test amaçlı varsayılan bir dosya depoya yüklenir (file-id bulunabilsin diye)
            test_meta = service.store_file("test_doc.pdf", b"%PDF-1.4\nTest\n%%EOF", args.user_id, args.tenant_id)
            # İstenen ID test ID ise kullanılır
            target_id = args.file_id if args.file_id != "auto" else test_meta.file_id
            # Dosya çekilir
            meta, content, headers = service.retrieve_file(target_id, args.user_id, args.tenant_id, args.role)
            # İndirme sonucu yazdırılır
            print(json.dumps({
                "durum": "BASARILI",
                "mesaj": "Dosya güvenli HTTP başlıklarıyla çekildi.",
                "meta": meta.to_dict(),
                "guvenlik_basliklari": headers,
                "icerik_uzunlugu": len(content)
            }, indent=2, ensure_ascii=False))
            return 0

        # scan komutu işletilir
        elif args.command == "scan":
            # Dosya adı temizlenir
            clean_name = service.sanitize_filename(args.filename)
            # İçerik taranır
            content_bytes = args.content.encode("utf-8")
            # Zararlı içerik kontrolü
            service.scan_for_malicious_content(content_bytes)
            # Temiz rapor yazdırılır
            print(json.dumps({
                "durum": "TEMIZ",
                "temizlenmis_ad": clean_name,
                "analiz": "Dosya adı ve içeriği güvenlik denetimlerinden başarıyla geçti."
            }, indent=2, ensure_ascii=False))
            return 0

        # fetch-remote komutu işletilir
        elif args.command == "fetch-remote":
            # SSRF güvenli getirme çalıştırılır
            meta = service.fetch_remote_file_safe(args.url, args.user_id, args.tenant_id)
            # Sonuç yazdırılır
            print(json.dumps({
                "durum": "BASARILI",
                "mesaj": "Uzak dosya SSRF korumalı kanaldan getirildi ve izole depolandı.",
                "dosya": meta.to_dict()
            }, indent=2, ensure_ascii=False))
            return 0

        # audit-report komutu işletilir
        elif args.command == "audit-report":
            # Denetim özeti alınır
            summary = service.get_audit_summary()
            # JSON olarak yazdırılır
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0

    except SecurityException as se:
        # Güvenlik hatası JSON formatında ekrana yazdırılır
        print(json.dumps({
            "durum": "ENGELLENDI",
            "hata_kodu": se.code,
            "hata_mesaji": str(se)
        }, indent=2, ensure_ascii=False))
        # Hata kodu 1 ile dönülür
        return 1

    return 0


if __name__ == "__main__":
    # Ana fonksiyon çalıştırılır ve çıkış kodu sisteme iletilir
    sys.exit(main())
