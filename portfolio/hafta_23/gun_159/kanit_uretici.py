# -*- coding: utf-8 -*-
"""
Girdi Doğrulama ve Çıktı Kodlama Kanıt Üretici
Hafta 23 / Gün 159 - Aşama 7 (Web Güvenliği)

Bu betik; birim testleri, 9 adet negatif kontrol senaryosunu ve CLI komutlarını
yürüterek 'kanit/gercek/' ve 'kanit/temsili/' dizinlerine doğrulanabilir
çıktıları üretir.
"""

import os
import sys
import json
import subprocess
from pathlib import Path

# Proje ana dizinini sys.path'e ekleme
CURRENT_DIR = Path(__file__).resolve().parent
PORTFOLIO_ROOT = CURRENT_DIR.parent.parent.parent
sys.path.insert(0, str(PORTFOLIO_ROOT))

# İlgili motor ve sınıfları içe aktarma
from portfolio.hafta_23.gun_159.uygulama.input_validator_encoder_engine import (
    InputValidatorEncoderEngine,
    ValidationType,
    EncodingContext
)


def run_unit_tests():
    """15 birim testi çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = CURRENT_DIR / "tests" / "test_input_validator_encoder.py"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "test_sonuclari.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "-m", "unittest", str(test_path), "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_text = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_text = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== GİRDİ DOĞRULAMA VE ÇIKTI KODLAMA BİRİM TESTLERİ (15/15) ===\n")
        f.write(stdout_text)
        f.write(stderr_text)
        f.write("\nDurum Kodu: " + str(res.returncode) + "\n")
    print(f"[+] Birim test kanıtı üretildi: {out_file}")


def run_negative_controls():
    """9 negatif kontrol senaryosunu çalıştırıp kanıt dosyasına kaydeder."""
    scenarios_file = CURRENT_DIR / "ornek_veri" / "invalid_input_payloads.json"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "negatif_kontrol_sonuclari.txt"

    with open(scenarios_file, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    schema_file = CURRENT_DIR / "ornek_veri" / "enterprise_input_schemas.json"
    with open(schema_file, "r", encoding="utf-8") as f:
        schema_data = json.load(f)["schema"]

    engine = InputValidatorEncoderEngine()
    results = []

    for scn in scenarios:
        field_name = scn["field"]
        raw_val = scn["value"]
        rule = schema_data.get(field_name, {"type": "TextAlphanumeric", "min_length": 3, "max_length": 30})
        val_type = ValidationType(rule.get("type", "TextAlphanumeric"))
        min_len = rule.get("min_length", 0)
        max_len = rule.get("max_length", 255)

        res = engine.validate_field(
            field_name=field_name,
            value=raw_val,
            val_type=val_type,
            min_length=min_len,
            max_length=max_len
        )

        # Doğrulama başarılı mı (yani tehdit yakalandı ve is_valid=False mı?)
        passed = (not res.is_valid)

        results.append({
            "scenario_id": scn["scenario_id"],
            "name": scn["name"],
            "field": field_name,
            "detected_threats": res.detected_threats,
            "error_message": res.error_message,
            "is_valid": res.is_valid,
            "validation_passed": passed
        })

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== 9 ADET GİRDİ DOĞRULAMA VE ENJEKSİYON NEGATİF KONTROL SENARYOSU ===\n\n")
        for r in results:
            f.write(f"Senaryo: {r['scenario_id']} - {r['name']}\n")
            f.write(f"  Hedef Alan         : {r['field']}\n")
            f.write(f"  Geçerlilik Durumu  : {'GEÇERLİ (Kabul Edildi)' if r['is_valid'] else 'GEÇERSİZ (Reddedildi)'}\n")
            f.write(f"  Tespit Edilen Tehdit: {', '.join(r['detected_threats']) if r['detected_threats'] else 'Format / Sınır İhlali'}\n")
            f.write(f"  Hata Açıklaması    : {r['error_message']}\n")
            f.write(f"  Negatif Doğrulama  : {'BAŞARILI (Zararlı Girdi Engellendi)' if r['validation_passed'] else 'BAŞARISIZ'}\n\n")
        all_passed = all(r["validation_passed"] for r in results)
        f.write(f"ÖZET: Toplam {len(results)} senaryonun {sum(1 for r in results if r['validation_passed'])} tanesi engellendi. (Genel: {'100% PASS' if all_passed else 'FAIL'})\n")
    print(f"[+] Negatif kontrol kanıtı üretildi: {out_file}")


def generate_reports_and_cli_logs():
    """Kurumsal şema doğrulama raporunu, bağlam kodlama örneklerini ve CLI loglarını üretir."""
    schema_file = CURRENT_DIR / "ornek_veri" / "enterprise_input_schemas.json"
    with open(schema_file, "r", encoding="utf-8") as f:
        s_data = json.load(f)

    schema = s_data["schema"]
    valid_payload = s_data["valid_sample_payload"]

    engine = InputValidatorEncoderEngine()
    batch_report = engine.validate_and_sanitize_payload(valid_payload, schema)

    # JSON Raporu kaydetme
    json_out = CURRENT_DIR / "kanit" / "gercek" / "validation_encoding_report.json"
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(batch_report, f, indent=2, ensure_ascii=False)
    print(f"[+] Şema doğrulama JSON raporu üretildi: {json_out}")

    # Farklı Bağlamlarda Çıktı Kodlama Örnekleri
    samples_out = CURRENT_DIR / "kanit" / "gercek" / "sanitized_output_samples.txt"
    test_payload = "<script>alert('XSS & Breakout')</script>"
    with open(samples_out, "w", encoding="utf-8") as f:
        f.write("=== BAĞLAMA DUYARLI ÇIKTI KODLAMA (CONTEXT-AWARE ENCODING) ÖRNEKLERİ ===\n\n")
        f.write(f"Ham Güvenilmeyen Veri: {test_payload}\n\n")
        for ctx in EncodingContext:
            encoded = engine.encode_for_context(test_payload, ctx)
            f.write(f"1. Bağlam: {ctx.value}\n")
            f.write(f"   Güvenli Çıktı: {encoded}\n\n")
    print(f"[+] Bağlam kodlama örnekleri üretildi: {samples_out}")

    # CLI Komutlarını yürütme ve loglama
    cli_path = CURRENT_DIR / "uygulama" / "input_validation_cli.py"
    cli_out_file = CURRENT_DIR / "kanit" / "gercek" / "komut_ve_cikis.txt"

    cmds = [
        [sys.executable, str(cli_path), "validate-field", "--name", "username", "--value", "Seydi_Eryilmaz", "--type", "TextAlphanumeric"],
        [sys.executable, str(cli_path), "validate-field", "--name", "query", "--value", "' OR 1=1 --", "--type", "TextAlphanumeric"],
        [sys.executable, str(cli_path), "encode-output", "--value", "<script>alert('test')</script>", "--context", "HtmlBody"],
        [sys.executable, str(cli_path), "encode-output", "--value", "\"><script>alert(1)</script>", "--context", "HtmlAttribute"],
        [sys.executable, str(cli_path), "encode-output", "--value", "'; alert('xss'); //", "--context", "JavaScript"],
        [sys.executable, str(cli_path), "pipeline"]
    ]

    with open(cli_out_file, "w", encoding="utf-8") as f:
        f.write("=== GİRDİ DOĞRULAMA VE ÇIKTI KODLAMA CLI YÜRÜTME LOGLARI ===\n\n")
        for c in cmds:
            f.write(f"$ {' '.join(c)}\n")
            res = subprocess.run(c, capture_output=True)
            c_stdout = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
            c_stderr = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""
            f.write(c_stdout)
            if c_stderr:
                f.write("\n[STDERR]\n" + c_stderr)
            f.write("\n" + "=" * 70 + "\n\n")
    print(f"[+] CLI log kanıtı üretildi: {cli_out_file}")


def generate_representative_evidence():
    """Temsili ASCII girdi doğrulama ve çıktı kodlama mimari diyagramını üretir."""
    rep_file = CURRENT_DIR / "kanit" / "temsili" / "girdi_cikti_guvenlik_borusu.txt"
    rep_file.parent.mkdir(parents=True, exist_ok=True)

    content = """TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
========================================================================================================
                      GİRDİ DOĞRULAMA VE ÇIKTI KODLAMA ÇİFT SAVUNMA HATTI
========================================================================================================

  [ DIŞ İSTEKLER / GÜVENİLMEYEN GİRDİ ] (HTTP GET/POST, JSON Payload, Query Parameters)
                          |
                          v
  +----------------------------------------------------------------------------------------------------+
  | 1. KANONİKLEŞTİRME VE TEMİZLİK (Boundary Sanitization)                                             |
  |    - Çift URL Decoding (%252e%252e%252f -> ../)                                                   |
  |    - Unicode NFKC Normalizasyonu (Homoglyph & Görsel Karakter Çözümü)                              |
  |    - Null Byte (\\x00, %00) Temizliği                                                              |
  +----------------------------------------------------------------------------------------------------+
                          |
                          v
  +----------------------------------------------------------------------------------------------------+
  | 2. GİRDİ DOĞRULAMA (Pozitif İzin Listesi / Allowlist)                                              |
  |    - Veri Tipi Sözleşmesi (TextAlpha, Email, NumericInt, UuidV4 vb.)                               |
  |    - Uzunluk ve Sınır Kontrolü (Min/Max Length)                                                    |
  |    - Enjeksiyon İmzası Taraması (SQLi, XSS, Path Traversal, Command Injection)                     |
  +----------------------------------------------------------------------------------------------------+
                          |
                          +---> Geçersizse: [ HTTP 400 Bad Request - Reddedildi ]
                          |
                          v (Geçerliyse)
  +----------------------------------------------------------------------------------------------------+
  | 3. GÜVENLİ İÇ İŞLEME & SORGULAMA                                                                   |
  |    - Parametreli Veritabanı Sorguları (Prepared Statements / ORM)                                  |
  |    - Sistem Komutlarında execFile / Argüman Dizisi (Shell yok!)                                    |
  +----------------------------------------------------------------------------------------------------+
                          |
                          v
  +----------------------------------------------------------------------------------------------------+
  | 4. BAĞLAMA DUYARLI ÇIKTI KODLAMA (Context-Aware Output Encoding - OWASP C-03)                      |
  |    +-------------------------+-----------------------------------+-------------------------------+ |
  |    | Hedef Bağlam            | Güvenlik Kaçış Yöntemi            | Örnek Dönüşüm                 | |
  |    +-------------------------+-----------------------------------+-------------------------------+ |
  |    | HTML Body               | HTML Varlık Kodlama               | <script> -> &lt;script&gt;    | |
  |    | HTML Attribute          | Hex Entity Kodlama (&#xHH;)       | " -> &#x22;                   | |
  |    | JavaScript Değişkeni    | Unicode Escape (\\u00XX)          | ' -> \\u0027                   | |
  |    | URL Parametresi         | RFC 3986 Percent-Encoding         | boşluk -> %20, & -> %26       | |
  |    | CSS Stili               | Hex CSS Escape (\\HH )            | " -> \\22                     | |
  |    +-------------------------+-----------------------------------+-------------------------------+ |
  +----------------------------------------------------------------------------------------------------+
                          |
                          v
  [ İSTEMCİ YORUMLAYICISI / TARAYICI ] (Kod Olarak Çalıştırılamaz, Yalnızca Güvenli Metin Görünür)

========================================================================================================
                                   GÜVENLİK SÖZLEŞMESİ MATRİSİ
========================================================================================================
  Alan Adı     İzin Verilen Format       Sınırlar    Zafiyet Kalkanı         Kaçış Bağlamı
  ----------   -----------------------   ---------   ---------------------   -----------------
  username     Alfanümerik + Türkçe      3-30 Kar.   SQLi & Path Traversal   HTML Attribute
  full_name    Yalnızca Harfler          2-60 Kar.   XSS & Komut Enjeksiyonu HTML Body
  email        RFC 5322 Regex            5-100 Kar.  Header Injection        HTML Body
  comment      Çok Satırlı Güvenli Metin 0-500 Kar.  XSS & Script Injection  HTML Body / JS Var
========================================================================================================
"""
    with open(rep_file, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"[+] Temsili ASCII kanıtı üretildi: {rep_file}")


def main():
    """Tüm kanıt üretim süreçlerini sırayla yürütür."""
    print("=== GÜN 159 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    generate_reports_and_cli_logs()
    generate_representative_evidence()
    print("=== GÜN 159 TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
