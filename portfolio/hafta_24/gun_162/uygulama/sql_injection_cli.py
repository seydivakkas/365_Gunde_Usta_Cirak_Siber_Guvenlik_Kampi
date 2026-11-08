# -*- coding: utf-8 -*-
"""
Gün 162: SQL Injection Neden Oluşur CLI Aracı (sql_injection_cli.py)

Bu komut satırı aracı; SQLi saldırı yüklerini tarama, güvensiz dinamik dize birleştirme
ile güvenli parametrik sorgu yürütme farklarını simüle etme ve dinamik tablo/kolon
belirteç güvenliğini test etme yeteneklerini sağlar.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import sys  # Çıkış kodları ve komut satırı argümanları için sys modülü dahil edilir
import json  # JSON formatında girdi/çıktı işleme için json modülü dahil edilir
import argparse  # Komut satırı argüman yönetimi için argparse modülü dahil edilir
from typing import List, Optional  # Tip ipuçları için typing modülü dahil edilir

# Motor sınıflarının içe aktarılması
from sql_injection_engine import (  # sql_injection_engine modülünden gerekli sınıflar çağrılır
    SQLInjectionDefenseEngine,  # Savunma ve karşılaştırma motoru
    SQLiThreatSensor,  # Tehdit sensörü
    MockDatabaseEngine  # SQLite test veritabanı motoru
)


def create_argument_parser() -> argparse.ArgumentParser:
    """CLI komut satırı argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(  # Parser nesnesi oluşturulur
        description="SQL Injection Kök Neden Analizi ve Savunma Aracı (Gün 162)"  # Açıklama
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Çalıştırılacak alt komut")  # Alt komutlar
    
    # 1. Scan alt komutu
    scan_parser = subparsers.add_parser("scan", help="Girdi metnini SQLi tehdit imzalarına karşı tara")  # scan komutu
    scan_parser.add_argument("--input", type=str, required=True, help="Taranacak ham metin")  # input argümanı
    
    # 2. Simulate alt komutu
    sim_parser = subparsers.add_parser("simulate", help="Zafiyetli ve güvenli sorgu yürütmesini karşılaştır")  # simulate komutu
    sim_parser.add_argument("--username", type=str, required=True, help="Kullanıcı adı girdisi")  # username
    sim_parser.add_argument("--password", type=str, default="", help="Parola girdisi")  # password
    
    # 3. Dynamic Identifier alt komutu
    dyn_parser = subparsers.add_parser("dynamic-identifier", help="Tablo/kolon belirteç güvenliğini test et")  # dynamic-identifier komutu
    dyn_parser.add_argument("--table", type=str, default="users", help="Sorgulanacak tablo adı")  # table
    dyn_parser.add_argument("--sort-by", type=str, default="id", help="Sıralama kolonu adı")  # sort-by
    
    return parser  # Yapılandırılmış parser döndürülür


def main(args: Optional[List[str]] = None) -> int:
    """CLI giriş noktası ve alt komut yönlendirici fonksiyonu."""
    parser = create_argument_parser()  # Parser oluşturulur
    parsed_args = parser.parse_args(args)  # Argümanlar işlenir
    
    if not parsed_args.command:  # Komut seçilmediyse
        parser.print_help()  # Yardım metni basılır
        return 1  # Hata dönüşü
        
    engine = SQLInjectionDefenseEngine()  # Ana motor başlatılır
    
    if parsed_args.command == "scan":  # scan komutu
        sensor = SQLiThreatSensor()  # Sensör oluşturulur
        findings = sensor.scan_input(parsed_args.input)  # Tarama yapılır
        out = {  # Çıktı sözlüğü
            "input_text": parsed_args.input,  # Girdi
            "is_threat_detected": len(findings) > 0,  # Tehdit var mı
            "findings_count": len(findings),  # Bulgu adedi
            "findings": [f.to_dict() for f in findings]  # Detaylar
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON yazdırılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "simulate":  # simulate komutu
        result = engine.analyze_and_compare(parsed_args.username, parsed_args.password)  # Karşılaştırma çalıştırılır
        print(json.dumps(result, indent=2, ensure_ascii=False))  # JSON basılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "dynamic-identifier":  # dynamic-identifier komutu
        db = MockDatabaseEngine()  # Veritabanı motoru
        try:  # Güvenli yürütme denenir
            ok, rows, sql = db.execute_secure_dynamic_identifier(parsed_args.table, parsed_args.sort_by)  # Çalıştırılır
            out = {  # Çıktı sözlüğü
                "success": True,  # Başarılı
                "executed_sql": sql,  # Üretilen SQL
                "rows_returned": len(rows),  # Kayıt sayısı
                "data_preview": rows[:2]  # Önizleme
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON yazdırılır
            return 0  # Başarılı
        except ValueError as err:  # Allowlist hatası yakalanırsa
            out = {  # Hata çıktısı
                "success": False,  # Başarısız
                "error": str(err)  # Hata detayı
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON basılır
            return 1  # Hata dönüşü
            
    return 0  # Varsayılan dönüş


if __name__ == "__main__":  # Doğrudan çalıştırıldığında
    sys.exit(main())  # Ana fonksiyon çalıştırılarak dönen kod ile sistemden çıkılır
