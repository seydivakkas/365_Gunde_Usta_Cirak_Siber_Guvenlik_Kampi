# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G089: CLI Yürütücü ve Terminal Giriş Noktası (cli_runner.py).
Komut satırından gelen parametreleri karşılar, SecurityCliEngine üzerinden
doğrular ve yapılandırılmış çıktıları terminale sunar.
"""

import json  # JSON formati icin json modulu
import sys  # Sistem argumanlari icin sys modulu

from portfolio.hafta_13.gun_089.uygulama.security_cli_engine import (  # Uygulama motoru
    CliAuditorException,  # Temel CLI istisnasi
    SecurityCliEngine,  # Façade motor sinifi
)


def main() -> None:
    """CLI aracinin ana giris noktasi."""
    raw_args = sys.argv[1:]  # Komut satiri parametreleri alinir
    engine = SecurityCliEngine()  # Guvenlik motoru ornegi olusturulur

    try:
        parsed_ns = engine.parse_arguments(raw_args)  # Parametreler ayrastirilir
        result = engine.execute_cli_action(parsed_ns)  # Eylem yurutulur

        if getattr(parsed_ns, "json_output", False):  # JSON ciktisi istenmisse
            print(json.dumps(result, indent=2, ensure_ascii=False))  # JSON basilir
        else:  # Standart metin ciktisi
            print(f"[BAŞARILI] Eylem: {result.get('action')} | Durum: {result.get('status')}")
            for key, val in result.items():
                if key not in ("action", "status"):
                    print(f"  - {key}: {val}")
        sys.exit(0)  # Basariyla cikilir

    except CliAuditorException as err:  # Yakalanan guvenlik istisnasi
        print(f"[GÜVENLİK HATASI] {type(err).__name__}: {err}", file=sys.stderr)  # Hata akisina basilir
        sys.exit(2)  # CLI hata kodu 2 ile cikilir
    except Exception as err:  # Beklenmeyen genel hata
        print(f"[KRİTİK SİSTEM HATASI] {err}", file=sys.stderr)  # stderr yazilir
        sys.exit(1)  # Genel hata kodu 1 ile cikilir


if __name__ == "__main__":
    main()  # Ana fonksiyon calistirilir
