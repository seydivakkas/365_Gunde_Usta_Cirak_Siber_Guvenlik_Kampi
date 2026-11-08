# -*- coding: utf-8 -*-
"""
Girdi Doğrulama ve Çıktı Kodlama CLI Yönetim Aracı
Hafta 23 / Gün 159 - Aşama 7 (Web Güvenliği)

Bu araç; gelen girdi değerlerini kanonikleştirir, pozitif izin listesine (Allowlist)
göre doğrular, enjeksiyon saldırılarını tespit eder ve bağlama duyarlı olarak
(HTML Gövdesi, Özniteliği, JavaScript, URL, CSS) çıktı kodlama gerçekleştirir.
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.input_validator_encoder_engine import (
    InputValidatorEncoderEngine,
    ValidationType,
    EncodingContext
)


def handle_validate_field(args):
    """Tek bir alan girdisini doğrular."""
    engine = InputValidatorEncoderEngine()
    val_type = ValidationType(args.type)
    res = engine.validate_field(
        field_name=args.name,
        value=args.value,
        val_type=val_type,
        min_length=args.min_len,
        max_length=args.max_len
    )

    print("=" * 75)
    print(" TEKİL ALAN GİRDİ DOĞRULAMA RAPORU")
    print("=" * 75)
    print(f" Alan Adı            : {res.field_name}")
    print(f" Orijinal Girdi      : {res.raw_value}")
    print(f" Kanonikleştirilmiş  : {res.canonical_value}")
    print(f" Hedef Veri Tipi     : {val_type.value}")
    print(f" Doğrulama Durumu    : {'[GEÇERLİ - GECTI]' if res.is_valid else '[GEÇERSİZ - KALDI]'}")
    if res.error_message:
        print(f" Hata Açıklaması     : {res.error_message}")
    if res.detected_threats:
        print(f" TESPİT EDİLEN TEHDİT: {', '.join(res.detected_threats)}")
    print("=" * 75)


def handle_encode_output(args):
    """Metni hedef yorumlayıcı bağlamına göre kodlar."""
    engine = InputValidatorEncoderEngine()
    context = EncodingContext(args.context)
    encoded = engine.encode_for_context(args.value, context=context)

    print("=" * 75)
    print(" BAĞLAMA DUYARLI ÇIKTI KODLAMA (CONTEXT-AWARE ENCODING)")
    print("=" * 75)
    print(f" Hedef Bağlam        : {context.value}")
    print(f" Orijinal Ham Metin  : {args.value}")
    print(f" Güvenli Çıktı Metni : {encoded}")
    print("=" * 75)


def handle_validate_payload(args):
    """JSON istek gövdesini şemaya göre toplu doğrular."""
    if not os.path.exists(args.payload):
        print(f"[-] Hata: Payload dosyası bulunamadı: {args.payload}")
        sys.exit(1)
    if not os.path.exists(args.schema):
        print(f"[-] Hata: Schema dosyası bulunamadı: {args.schema}")
        sys.exit(1)

    with open(args.payload, "r", encoding="utf-8") as f:
        payload = json.load(f)
    with open(args.schema, "r", encoding="utf-8") as f:
        schema = json.load(f)

    engine = InputValidatorEncoderEngine()
    report = engine.validate_and_sanitize_payload(payload, schema)

    print("=" * 75)
    print(" JSON İSTEK GÖVDESİ TOPLU DOĞRULAMA RAPORU")
    print("=" * 75)
    print(f" Genel Sonuç         : {'[TÜM ALANLAR GEÇERLİ]' if report['all_valid'] else '[GÜVENLİK İHLALİ / HATA]'}")
    print(f" Hata Sayısı         : {len(report['errors'])}")
    print(f" Tehdit Sayısı       : {len(report['detected_threats'])}")
    if report["errors"]:
        print("\n ALAN HATALARI:")
        for f_name, err in report["errors"].items():
            print(f"   - {f_name}: {err}")
    if report["detected_threats"]:
        print(f"\n TESPİT EDİLEN SİBER TEHDİTLER: {', '.join(report['detected_threats'])}")
    print("=" * 75)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Rapor JSON olarak kaydedildi: {args.output}")


def handle_pipeline(args):
    """Boru hattı mimarisini ekrana basar."""
    engine = InputValidatorEncoderEngine()
    print(engine.generate_ascii_pipeline())


def main():
    """CLI giriş noktası ve komut yönlendiricisi."""
    parser = argparse.ArgumentParser(
        description="Girdi Doğrulama ve Çıktı Kodlama CLI Aracı (Gün 159)"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Alt komutlar")

    # 1. validate-field
    p_field = subparsers.add_parser("validate-field", help="Tek bir alan girdisini doğrular")
    p_field.add_argument("--name", default="username", help="Alan adı")
    p_field.add_argument("--value", required=True, help="Doğrulanacak değer")
    p_field.add_argument("--type", default="TextAlphanumeric", help="Veri tipi")
    p_field.add_argument("--min-len", type=int, default=1, help="Asgari uzunluk")
    p_field.add_argument("--max-len", type=int, default=50, help="Azami uzunluk")

    # 2. encode-output
    p_enc = subparsers.add_parser("encode-output", help="Bağlama duyarlı çıktı kodlama yapar")
    p_enc.add_argument("--value", required=True, help="Kodlanacak değer")
    p_enc.add_argument("--context", default="HtmlBody", choices=["HtmlBody", "HtmlAttribute", "JavaScript", "UrlParam", "CssString"], help="Hedef bağlam")

    # 3. validate-payload
    p_pay = subparsers.add_parser("validate-payload", help="JSON payload doğrular")
    p_pay.add_argument("--payload", required=True, help="JSON payload dosyası")
    p_pay.add_argument("--schema", required=True, help="JSON şema dosyası")
    p_pay.add_argument("--output", help="Çıktı JSON rapor dosyası")

    # 4. pipeline
    subparsers.add_parser("pipeline", help="Güvenlik boru hattı şemasını görüntüler")

    args = parser.parse_args()

    if args.subcommand == "validate-field":
        handle_validate_field(args)
    elif args.subcommand == "encode-output":
        handle_encode_output(args)
    elif args.subcommand == "validate-payload":
        handle_validate_payload(args)
    elif args.subcommand == "pipeline":
        handle_pipeline(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
