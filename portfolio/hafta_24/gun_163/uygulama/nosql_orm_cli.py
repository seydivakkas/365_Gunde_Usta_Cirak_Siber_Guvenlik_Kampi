# -*- coding: utf-8 -*-
"""
Gün 163: NoSQL ve ORM Sınırları CLI Aracı (nosql_orm_cli.py)

Bu komut satırı aracı; NoSQL sorgu operatörü enjeksiyonlarını tarama,
zafiyetli vs. güvenli NoSQL sorgu yürütmelerini simüle etme ve ORM Mass Assignment
(Kütlesel Atama) zafiyetlerini güvenli DTO filtresiyle doğrulamayı sağlar.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import sys  # Sistem parametreleri ve çıkış kodları için sys modülü dahil edilir
import json  # JSON formatında girdi/çıktı ayrıştırma için json modülü dahil edilir
import argparse  # Komut satırı argüman yönetimi için argparse modülü dahil edilir
from typing import List, Optional  # Tip ipuçları için typing modülü dahil edilir

# Motor sınıflarının içe aktarılması
from nosql_orm_engine import (  # nosql_orm_engine modülünden gerekli sınıflar çağrılır
    NoSQLORMDefenseEngine,  # Merkezi savunma motoru
    NoSQLThreatDetector  # Tehdit tarayıcısı
)


def create_argument_parser() -> argparse.ArgumentParser:
    """CLI komut satırı argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(  # Parser nesnesi oluşturulur
        description="NoSQL Injection ve ORM Sınırları Güvenlik Yönetim Aracı (Gün 163)"  # Açıklama
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Çalıştırılacak alt komut")  # Alt komut ayrıştırıcı
    
    # 1. scan-query alt komutu
    scan_parser = subparsers.add_parser("scan-query", help="JSON NoSQL sorgusunu zararlı operatörlere karşı tara")  # scan-query
    scan_parser.add_argument("--query-json", type=str, required=True, help="Taranacak sorgu JSON metni")  # query-json
    
    # 2. simulate-nosqli alt komutu
    sim_nosql = subparsers.add_parser("simulate-nosqli", help="Zafiyetli ve güvenli NoSQL find() karşılaştırması yap")  # simulate-nosqli
    sim_nosql.add_argument("--query-json", type=str, required=True, help="Test edilecek sorgu JSON metni")  # query-json
    
    # 3. simulate-mass-assignment alt komutu
    sim_mass = subparsers.add_parser("simulate-mass-assignment", help="ORM Mass Assignment zafiyetini simüle et")  # simulate-mass-assignment
    sim_mass.add_argument("--user-id", type=int, default=2, help="Güncellenecek kullanıcı ID (varsayılan: 2 - ahmet_kaya)")  # user-id
    sim_mass.add_argument("--payload-json", type=str, required=True, help="Gönderilen güncelleme JSON gövdesi")  # payload-json
    
    return parser  # Yapılandırılmış parser döndürülür


def main(args: Optional[List[str]] = None) -> int:
    """CLI giriş noktası ve alt komut yönlendirici fonksiyonu."""
    parser = create_argument_parser()  # Parser oluşturulur
    parsed_args = parser.parse_args(args)  # Argümanlar taranır
    
    if not parsed_args.command:  # Komut belirtilmediyse
        parser.print_help()  # Yardım metni basılır
        return 1  # Hata koduyla çıkılır
        
    engine = NoSQLORMDefenseEngine()  # Ana savunma motoru başlatılır
    
    if parsed_args.command == "scan-query":  # scan-query seçildiyse
        try:  # JSON ayrıştırma denenir
            query = json.loads(parsed_args.query_json)  # JSON nesneye çevrilir
        except json.JSONDecodeError as err:  # Hatalı JSON durumunda
            print(f"Hata: Geçersiz JSON formatı - {err}")  # Hata basılır
            return 1  # Hata ile çıkılır
            
        detector = NoSQLThreatDetector()  # Dedektör oluşturulur
        findings = detector.scan_query_dict(query)  # Tarama yapılır
        out = {  # Çıktı sözlüğü
            "query_analyzed": query,  # İncelenen sorgu
            "threat_detected": len(findings) > 0,  # Tehdit durumu
            "findings_count": len(findings),  # Bulgu adedi
            "findings": [f.to_dict() for f in findings]  # Detaylar
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON yazdırılır
        return 0  # Başarılı
        
    elif parsed_args.command == "simulate-nosqli":  # simulate-nosqli seçildiyse
        try:  # JSON ayrıştırma denenir
            query = json.loads(parsed_args.query_json)  # JSON çevrilir
        except json.JSONDecodeError as err:  # Hatalı JSON
            print(f"Hata: Geçersiz JSON formatı - {err}")  # Hata basılır
            return 1  # Hata dönüşü
            
        res = engine.inspect_and_test_nosqli(query)  # Karşılaştırma çalıştırılır
        print(json.dumps(res, indent=2, ensure_ascii=False))  # JSON basılır
        return 0  # Başarılı
        
    elif parsed_args.command == "simulate-mass-assignment":  # simulate-mass-assignment seçildiyse
        try:  # JSON ayrıştırma denenir
            payload = json.loads(parsed_args.payload_json)  # JSON çevrilir
        except json.JSONDecodeError as err:  # Hatalı JSON
            print(f"Hata: Geçersiz JSON formatı - {err}")  # Hata basılır
            return 1  # Hata dönüşü
            
        res = engine.inspect_and_test_mass_assignment(parsed_args.user_id, payload)  # Analiz çalıştırılır
        print(json.dumps(res, indent=2, ensure_ascii=False))  # JSON basılır
        return 0  # Başarılı
        
    return 0  # Varsayılan dönüş


if __name__ == "__main__":  # Doğrudan çağrıldığında
    sys.exit(main())  # Ana fonksiyon çalıştırılarak dönen kod ile çıkılır
