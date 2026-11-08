# -*- coding: utf-8 -*-
"""
Gün 160: XSS Savunma Komut Satırı Arayüzü (xss_defense_cli.py)

Bu CLI aracı, XSS yüklerinin analizini, istemci tarafı JavaScript betiklerinde
DOM XSS akışlarının tespitini, HTML arındırma işlemlerini ve CSP başlık üretimini sağlar.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import sys  # Sistem parametreleri ve çıkış kodları için sys modülü dahil edilir
import json  # JSON formatında çıktı ve raporlama için json modülü dahil edilir
import argparse  # Komut satırı argümanlarını ayrıştırmak için argparse modülü dahil edilir
from typing import List, Optional  # Tip ipuçları için typing modülü dahil edilir

# Motor sınıflarının içe aktarılması
from xss_defense_engine import (  # xss_defense_engine modülünden gerekli sınıflar çağrılır
    XSSDefenseEngine,  # Merkezi savunma motoru sınıfı
    DOMXSSAnalyzer,  # DOM XSS analizcisi
    CSPPolicyBuilder,  # CSP politika derleyicisi
    StrictHTMLSanitizer,  # Katı HTML temizleyicisi
    ContextAwareEncoder  # Bağlama duyarlı kodlayıcı
)


def create_argument_parser() -> argparse.ArgumentParser:
    """Komut satırı argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(  # Argüman ayrıştırıcı nesnesi oluşturulur
        description="XSS Türleri ve Çok Katmanlı Savunma Yönetim Aracı (Gün 160)"  # Açıklama metni
    )
    
    # Alt komutlar için alt ayrıştırıcı oluşturulur
    subparsers = parser.add_subparsers(dest="command", help="Çalıştırılacak alt komut")  # Alt komut yapısı
    
    # 1. Payload inceleme komutu
    inspect_parser = subparsers.add_parser("inspect", help="XSS yükünü analiz et ve zafiyet raporla")  # inspect alt komutu
    inspect_parser.add_argument("--payload", type=str, required=True, help="İncelenecek ham girdi metni")  # payload argümanı
    inspect_parser.add_argument("--context", type=str, default="html_body", choices=["html_body", "html_attribute", "javascript", "uri_param"], help="Hedef bağlam")  # context seçeneği
    
    # 2. DOM akış analizi komutu
    dom_parser = subparsers.add_parser("analyze-dom", help="JavaScript kodundaki Source-Sink akışlarını analiz et")  # analyze-dom alt komutu
    dom_parser.add_argument("--script", type=str, required=True, help="İncelenecek JavaScript kod parçası")  # script argümanı
    
    # 3. HTML temizleme komutu
    sanitize_parser = subparsers.add_parser("sanitize", help="Ham HTML girdisini katı allowlist ile arındır")  # sanitize alt komutu
    sanitize_parser.add_argument("--html-input", type=str, required=True, help="Temizlenecek HTML metni")  # html-input argümanı
    
    # 4. CSP üretme ve denetleme komutu
    csp_parser = subparsers.add_parser("csp", help="CSP Seviye 3 başlığı üret veya var olanı denetle")  # csp alt komutu
    csp_parser.add_argument("--generate", action="store_true", help="Nonce tabanlı katı CSP üret")  # generate bayrağı
    csp_parser.add_argument("--audit", type=str, help="Denetlenecek mevcut CSP başlığı dizesi")  # audit argümanı
    
    # 5. Bağlamsal kodlama komutu
    encode_parser = subparsers.add_parser("encode", help="Girdiyi seçilen bağlama göre güvenli kodla")  # encode alt komutu
    encode_parser.add_argument("--value", type=str, required=True, help="Kodlanacak girdi değeri")  # value argümanı
    encode_parser.add_argument("--target-context", type=str, required=True, choices=["html_body", "html_attribute", "javascript", "uri_param"], help="Hedef bağlam türü")  # target-context seçeneği
    
    return parser  # Yapılandırılmış parser döndürülür


def main(args: Optional[List[str]] = None) -> int:
    """CLI giriş noktası ve komut yönlendirici fonksiyonu."""
    parser = create_argument_parser()  # Ayrıştırıcı başlatılır
    parsed_args = parser.parse_args(args)  # Argümanlar işlenir
    
    if not parsed_args.command:  # Herhangi bir alt komut verilmemişse
        parser.print_help()  # Yardım metni ekrana yazdırılır
        return 1  # Hata koduyla çıkış yapılır
        
    engine = XSSDefenseEngine()  # Savunma motoru örneği oluşturulur
    
    if parsed_args.command == "inspect":  # inspect komutu seçildiyse
        result = engine.inspect_and_defend(parsed_args.payload, parsed_args.context)  # Analiz ve savunma çalıştırılır
        print(json.dumps(result, indent=2, ensure_ascii=False))  # Sonuç JSON formatında basılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "analyze-dom":  # analyze-dom seçildiyse
        analyzer = DOMXSSAnalyzer()  # DOM analizci nesnesi oluşturulur
        flows = analyzer.analyze_script(parsed_args.script)  # Betik analiz edilir
        report = {  # Rapor sözlüğü hazırlanır
            "script_length": len(parsed_args.script),  # Kod boyutu
            "flows_detected": len(flows),  # Tespit edilen akış sayısı
            "flows": flows  # Akış detayları
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))  # JSON çıktısı yazdırılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "sanitize":  # sanitize komutu seçildiyse
        sanitizer = StrictHTMLSanitizer()  # Temizleyici nesnesi oluşturulur
        sanitizer.feed(parsed_args.html_input)  # Girdi beslenir
        clean_html = sanitizer.get_clean_html()  # Temiz çıktı alınır
        res = {  # Sonuç yapısı
            "raw_input": parsed_args.html_input,  # Ham metin
            "sanitized_html": clean_html,  # Temiz metin
            "stripped_tags": sanitizer.stripped_tags_count,  # Ayıklanan etiketler
            "stripped_attrs": sanitizer.stripped_attrs_count  # Ayıklanan nitelikler
        }
        print(json.dumps(res, indent=2, ensure_ascii=False))  # JSON formatında basılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "csp":  # csp komutu seçildiyse
        builder = CSPPolicyBuilder()  # CSP üretici nesnesi oluşturulur
        if parsed_args.generate:  # Üretim istenmişse
            nonce = builder.generate_nonce()  # Nonce üretilir
            header = builder.build_header(nonce)  # Başlık derlenir
            out = {  # Çıktı sözlüğü
                "nonce": nonce,  # Üretilen nonce
                "content_security_policy": header  # Başlık değeri
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON basılır
            return 0  # Başarılı çıkış
        elif parsed_args.audit:  # Denetim istenmişse
            weaknesses = builder.audit_policy(parsed_args.audit)  # Politika denetlenir
            audit_res = {  # Denetim sonuç yapısı
                "policy": parsed_args.audit,  # Denetlenen politika
                "is_secure": len(weaknesses) == 0,  # Güvenlik durumu
                "weaknesses_count": len(weaknesses),  # Zayıflık adedi
                "weaknesses": weaknesses  # Zayıflıklar listesi
            }
            print(json.dumps(audit_res, indent=2, ensure_ascii=False))  # JSON basılır
            return 0  # Başarılı çıkış
        else:  # Hiçbir bayrak verilmediyse
            print("Lütfen --generate veya --audit parametrelerinden birini belirtin.")  # Uyarı metni
            return 1  # Hata dönüşü
            
    elif parsed_args.command == "encode":  # encode komutu seçildiyse
        target = parsed_args.target_context  # Hedef bağlam
        val = parsed_args.value  # Kodlanacak değer
        if target == "html_body":  # HTML gövde
            encoded = ContextAwareEncoder.encode_for_html_body(val)  # Gövde kodlaması
        elif target == "html_attribute":  # HTML nitelik
            encoded = ContextAwareEncoder.encode_for_html_attribute(val)  # Nitelik kodlaması
        elif target == "javascript":  # JS dize
            encoded = ContextAwareEncoder.encode_for_javascript_string(val)  # JS Unicode kodlaması
        else:  # URL bileşeni
            encoded = ContextAwareEncoder.encode_for_uri_component(val)  # Percent encoding
        print(json.dumps({"input": val, "context": target, "encoded": encoded}, indent=2, ensure_ascii=False))  # Sonuç yazdırılır
        return 0  # Başarılı çıkış

    return 0  # Varsayılan başarılı çıkış


if __name__ == "__main__":  # Doğrudan çalıştırıldığında
    sys.exit(main())  # Ana fonksiyon çalıştırılarak dönen kod ile sistemden çıkılır
