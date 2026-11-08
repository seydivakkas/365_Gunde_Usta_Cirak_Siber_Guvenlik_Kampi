# -*- coding: utf-8 -*-
"""
Gün 161: Mini Proje 22 - Güvenli Form Arayüzü CLI Yönetim Aracı (secure_form_cli.py)

Bu komut satırı aracı; güvenli form oluşturma (render), CSRF token üretimi ve denetimi,
kullanıcı girdisi doğrulama ve form gönderim simülasyonlarını yürütür.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import sys  # Çıkış kodları ve komut satırı parametreleri için sys modülü dahil edilir
import json  # JSON formatında girdi alma ve raporlama için json modülü dahil edilir
import argparse  # Komut satırı argüman ayrıştırıcısı için argparse dahil edilir
from typing import List, Optional  # Tip ipuçları için typing modülü dahil edilir

# Motor sınıflarının içe aktarılması
from secure_form_engine import (  # secure_form_engine modülünden gerekli sınıflar çağrılır
    SecureFormEngine,  # Güvenli form motoru
    CSRFProtectionManager  # CSRF koruma yöneticisi
)


def create_argument_parser() -> argparse.ArgumentParser:
    """CLI argüman ayrıştırıcısını yapılandırır."""
    parser = argparse.ArgumentParser(  # Parser nesnesi oluşturulur
        description="Mini Proje 22: Güvenli Form Arayüzü Yönetim ve Test Aracı (Gün 161)"  # Açıklama
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Çalıştırılacak alt komut")  # Alt komut ayrıştırıcı
    
    # 1. Render alt komutu
    render_parser = subparsers.add_parser("render", help="Güvenli form HTML şablonu ve başlıklarını üret")  # render komutu
    render_parser.add_argument("--session-id", type=str, default="sess_user_demo_123", help="Kullanıcı oturum kimliği")  # session-id
    
    # 2. Submit alt komutu
    submit_parser = subparsers.add_parser("submit", help="Form gönderimini güvenlik denetimlerinden geçir")  # submit komutu
    submit_parser.add_argument("--json-data", type=str, required=True, help="Gönderilen form verisi (JSON dizesi)")  # json-data
    submit_parser.add_argument("--session-id", type=str, default="sess_user_demo_123", help="Oturum kimliği")  # session-id
    submit_parser.add_argument("--client-ip", type=str, default="192.168.1.50", help="İstemci IP adresi")  # client-ip
    submit_parser.add_argument("--origin", type=str, default="https://banka.kurum.internal", help="İstek kökeni (Origin)")  # origin
    
    # 3. Generate CSRF alt komutu
    csrf_gen_parser = subparsers.add_parser("generate-csrf", help="Oturum için yeni CSRF tokenı üret")  # generate-csrf
    csrf_gen_parser.add_argument("--session-id", type=str, required=True, help="Hedef oturum kimliği")  # session-id
    
    # 4. Validate CSRF alt komutu
    csrf_val_parser = subparsers.add_parser("validate-csrf", help="CSRF token geçerliliğini denetle")  # validate-csrf
    csrf_val_parser.add_argument("--token", type=str, required=True, help="Denetlenecek token")  # token
    csrf_val_parser.add_argument("--session-id", type=str, required=True, help="Oturum kimliği")  # session-id
    
    return parser  # Yapılandırılmış parser döndürülür


def main(args: Optional[List[str]] = None) -> int:
    """CLI giriş noktası ve komut yönlendirme mekanizması."""
    parser = create_argument_parser()  # Parser oluşturulur
    parsed_args = parser.parse_args(args)  # Argümanlar taranır
    
    if not parsed_args.command:  # Alt komut seçilmediyse
        parser.print_help()  # Yardım metni yazdırılır
        return 1  # Hata dönüşü
        
    engine = SecureFormEngine()  # Motor başlatılır
    
    if parsed_args.command == "render":  # render seçildiyse
        form_html, token, headers = engine.render_form_html(parsed_args.session_id)  # Form üretilir
        out = {  # Çıktı sözlüğü
            "session_id": parsed_args.session_id,  # Oturum
            "csrf_token": token,  # Üretilen token
            "security_headers": headers,  # Başlıklar
            "html_preview": form_html[:300] + "... [KIRPILDI]"  # Önizleme
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))  # JSON basılır
        return 0  # Başarılı çıkış
        
    elif parsed_args.command == "submit":  # submit seçildiyse
        try:  # JSON çözümleme denenir
            data = json.loads(parsed_args.json_data)  # JSON verisi okunur
        except json.JSONDecodeError as err:  # Hatalı JSON durumunda
            print(f"Hata: Geçersiz JSON formatı - {err}")  # Hata yazdırılır
            return 1  # Hata koduyla çıkılır
            
        result = engine.process_submission(  # Gönderim işlenir
            post_data=data,  # Form verisi
            session_id=parsed_args.session_id,  # Oturum
            client_ip=parsed_args.client_ip,  # İstemci IP
            origin_header=parsed_args.origin  # Köken başlığı
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))  # Sonuç basılır
        return 0 if result["success"] else 1  # Başarı durumuna göre kod dönülür
        
    elif parsed_args.command == "generate-csrf":  # generate-csrf seçildiyse
        mgr = CSRFProtectionManager()  # CSRF yöneticisi başlatılır
        token = mgr.generate_token(parsed_args.session_id)  # Token üretilir
        print(json.dumps({"session_id": parsed_args.session_id, "csrf_token": token}, indent=2))  # Yazdırılır
        return 0  # Başarılı
        
    elif parsed_args.command == "validate-csrf":  # validate-csrf seçildiyse
        mgr = CSRFProtectionManager()  # CSRF yöneticisi başlatılır
        is_valid, msg = mgr.validate_token(parsed_args.token, parsed_args.session_id)  # Doğrulama yapılır
        print(json.dumps({"is_valid": is_valid, "message": msg}, indent=2, ensure_ascii=False))  # Yazdırılır
        return 0 if is_valid else 1  # Durum kodu döner
        
    return 0  # Varsayılan başarılı çıkış


if __name__ == "__main__":  # Doğrudan çağrıldığında
    sys.exit(main())  # Ana fonksiyon çalıştırılır
