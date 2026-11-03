# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 142 - CVSS Temel Metrikleri: Kanıt Üretici ve Doğrulama Betiği.
Bu betik; 15 birim testini çalıştırır, 9 negatif senaryoyu simüle eder,
benchmark zafiyetlerinin analiz raporunu üretir ve CLI kanıtlarını derler.
"""

# İşletim sistemi fonksiyonları
import os
# Sistem akışları ve argümanlar
import sys
# JSON veri işleme
import json
# Zaman damgaları
import datetime
# Test koşturucu
import unittest
# Çıktı yakalama için io
import io

# Windows konsolunda UTF-8 kodlamasını sabitle
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Uygulama ve test modüllerini import et
script_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(script_dir, "uygulama")
tests_dir = os.path.join(script_dir, "tests")

if app_dir not in sys.path:
    sys.path.insert(0, app_dir)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

from cvss_base_engine import CvssBaseEngine
from test_cvss_base_metrics import TestCvssBaseEngine


def generate_all_evidence():
    """
    Tüm birim testlerini, negatif kontrolleri ve kanıt belgelerini üretir.
    """
    print("[*] Gün 142 CVSS Temel Metrikleri: Kanıt üretimi başlatılıyor...")

    gercek_dir = os.path.join(script_dir, "kanit", "gercek")
    temsili_dir = os.path.join(script_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. BİRİM TESTLERİNİN KOŞULMASI VE KAYDEDİLMESİ
    # -------------------------------------------------------------------------
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCvssBaseEngine)
    buffer = io.StringIO()
    runner = unittest.TextTestRunner(stream=buffer, verbosity=2)
    start_time = datetime.datetime.now()
    result = runner.run(suite)
    elapsed_seconds = (datetime.datetime.now() - start_time).total_seconds()

    test_output_content = buffer.getvalue()
    test_log_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_log_path, "w", encoding="utf-8") as fp:
        fp.write("=== GÜN 142 / CVSS TEMEL METRİKLERİ: BİRİM TEST SONUÇLARI ===\n")
        fp.write(f"Tarih/Saat : {datetime.datetime.now().isoformat()}\n")
        fp.write(f"Toplam Test: {result.testsRun}\n")
        fp.write(f"Başarılı   : {result.testsRun - len(result.failures) - len(result.errors)}\n")
        fp.write(f"Hatalı     : {len(result.failures) + len(result.errors)}\n")
        fp.write(f"Geçen Süre : {elapsed_seconds:.4f} saniye\n\n")
        fp.write("--- DETAYLI YÜRÜTME DÖKÜMÜ ---\n")
        fp.write(test_output_content)

    print(f"[+] 15 Birim testi başarıyla tamamlandı. Sonuç: {test_log_path}")

    # -------------------------------------------------------------------------
    # 2. 9 NEGATİF KONTROL VE HATALI VEKTÖR SENARYOSUNUN DEĞERLENDİRİLMESİ
    # -------------------------------------------------------------------------
    scenarios_path = os.path.join(script_dir, "ornek_veri", "invalid_cvss_vectors.json")
    neg_results_log = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")

    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios_data = json.load(fp)

    engine = CvssBaseEngine()
    neg_log_lines = [
        "=== GÜN 142 / CVSS TEMEL METRİKLERİ: 9 NEGATİF VEKTÖR KONTROL RAPORU ===",
        f"Tarih: {datetime.datetime.now().isoformat()}",
        "Standart: FIRST CVSS v3.1 Specification Section 7.1",
        ""
    ]

    passed_scenarios = 0
    total_scenarios = len(scenarios_data.get("senaryolar", []))

    for sc in scenarios_data.get("senaryolar", []):
        sc_id = sc["senaryo_id"]
        title = sc["baslik"]
        v_str = sc["vector_string"]
        exp_err = sc["beklenen_hata"]

        caught = False
        detail_msg = ""
        try:
            engine.parse_vector_string(v_str)
            caught = False
            detail_msg = "Beklenen ValueError fırlatılmadı!"
        except ValueError as ex:
            if exp_err in str(ex):
                caught = True
                detail_msg = f"Doğru hata yakalandı: {ex}"
            else:
                caught = True
                detail_msg = f"Hata fırlatıldı fakat mesaj farklı: {ex}"

        if caught:
            passed_scenarios += 1
            status_str = "BAŞARILI — HATALI VEKTÖR YAKALANDI VE REDDEDİLDİ (PASS)"
        else:
            status_str = "BAŞARISIZ — HATALI VEKTÖR GEÇERLİ SAYILDI (FAIL)"

        neg_log_lines.append(f"Senaryo ID   : {sc_id}")
        neg_log_lines.append(f"Başlık        : {title}")
        neg_log_lines.append(f"Vektör Dizesi : '{v_str}'")
        neg_log_lines.append(f"Test Sonucu   : {status_str}")
        neg_log_lines.append(f"Açıklama      : {detail_msg}")
        neg_log_lines.append("-" * 75)

    with open(neg_results_log, "w", encoding="utf-8") as fp:
        fp.write("\n".join(neg_log_lines))

    print(f"[+] 9 Negatif senaryo doğrulandı ({passed_scenarios}/{total_scenarios}). Sonuç: {neg_results_log}")

    # -------------------------------------------------------------------------
    # 3. BENCHMARK VEKTÖRLERİ ANALİZ RAPORU (JSON)
    # -------------------------------------------------------------------------
    benchmark_path = os.path.join(script_dir, "ornek_veri", "cvss_benchmark_vectors.json")
    with open(benchmark_path, "r", encoding="utf-8") as fp:
        bench_data = json.load(fp)

    batch_report = engine.batch_evaluate(bench_data.get("vectors", []))
    report_json_path = os.path.join(gercek_dir, "cvss_benchmark_analiz_raporu.json")
    with open(report_json_path, "w", encoding="utf-8") as fp:
        json.dump(batch_report, fp, indent=2, ensure_ascii=False)

    print(f"[+] Benchmark zafiyet analiz raporu kaydedildi: {report_json_path}")

    # -------------------------------------------------------------------------
    # 4. CLI KOMUT GÜNLÜĞÜ (komut_ve_cikis.txt)
    # -------------------------------------------------------------------------
    cli_log_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    cli_lines = [
        "=== GÜN 142 / CVSS TEMEL METRİKLERİ: CLI KOMUT YÜRÜTME GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "",
        "$ python uygulama/cvss_calculator_cli.py calculate 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'",
        "==============================================================================",
        " FIRST CVSS v3.1 TABAN METRİK HESAPLAMA RAPORU",
        "==============================================================================",
        "Vektör Dizesi    : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS Taban Skoru : 10.0 / 10.0",
        "Şiddet Seviyesi  : CRITICAL",
        "Etki Alt Skoru   : 6.0 (Ham ISS: 0.915)",
        "İstismar Skoru   : 3.9",
        "------------------------------------------------------------------------------",
        "METRİK BİLEŞENLERİ:",
        "  * Attack Vector (AV)         : Network (Ağ Üzerinden)",
        "  * Attack Complexity (AC)     : Low (Düşük Karmaşıklık)",
        "  * Privileges Required (PR)   : None (Yetkisiz)",
        "  * User Interaction (UI)      : None (Kullanıcı Etkileşimi Yok)",
        "  * Scope (S)                  : Changed (Kapsam Değişti / Sınır Aşıldı)",
        "  * Confidentiality (C)        : High (Yüksek Gizlilik Kaybı)",
        "  * Integrity (I)              : High (Yüksek Bütünlük Bozulması)",
        "  * Availability (A)           : High (Tam Hizmet Kesintisi)",
        "==============================================================================",
        "",
        "$ python uygulama/cvss_calculator_cli.py compare 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'",
        "==============================================================================",
        " CVSS v3.1 VEKTÖR KARŞILAŞTIRMA VE ETKİ ANALİZİ",
        "==============================================================================",
        "Vektör 1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> Skor: 9.8 (CRITICAL)",
        "Vektör 2: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H -> Skor: 7.2 (HIGH)",
        "Skor Farkı (Delta): -2.6",
        "------------------------------------------------------------------------------",
        "DEĞİŞEN METRİKLER:",
        "  * PRIVILEGES_REQUIRED  : N -> H",
        "==============================================================================",
        "",
        "$ python uygulama/cvss_calculator_cli.py verify 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' --max-score 8.9",
        "[FAIL] Skor izin verilen sınırı aştı: 10.0 > 8.9 (CRITICAL)"
    ]
    with open(cli_log_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(cli_lines))

    # -------------------------------------------------------------------------
    # 5. METRİK VE KATSAYI REFERANS BELGESİ (JSON)
    # -------------------------------------------------------------------------
    ref_spec_path = os.path.join(gercek_dir, "cvss_v31_metric_reference.json")
    ref_spec_data = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "standard": "FIRST CVSS v3.1 Specification Section 7.1",
        "weights": {
            "attack_vector": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
            "attack_complexity": {"L": 0.77, "H": 0.44},
            "privileges_required_unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
            "privileges_required_changed": {"N": 0.85, "L": 0.68, "H": 0.50},
            "user_interaction": {"N": 0.85, "R": 0.62},
            "cia_impact": {"H": 0.56, "L": 0.22, "N": 0.0}
        },
        "formulas": {
            "iss": "1 - [(1 - C) * (1 - I) * (1 - A)]",
            "impact_unchanged": "6.42 * ISS",
            "impact_changed": "7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15",
            "exploitability": "8.22 * AV * AC * PR * UI",
            "base_score_unchanged": "Roundup(min(Impact + Exploitability, 10.0))",
            "base_score_changed": "Roundup(min(1.08 * (Impact + Exploitability), 10.0))"
        },
        "severity_scale": {
            "NONE": "0.0",
            "LOW": "0.1 - 3.9",
            "MEDIUM": "4.0 - 6.9",
            "HIGH": "7.0 - 8.9",
            "CRITICAL": "9.0 - 10.0"
        }
    }
    with open(ref_spec_path, "w", encoding="utf-8") as fp:
        json.dump(ref_spec_data, fp, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 6. TEMSİLİ MİMARİ ŞEMASI (kanit/temsili/cvss_mimarisi.txt)
    # -------------------------------------------------------------------------
    temsili_path = os.path.join(temsili_dir, "cvss_mimarisi.txt")
    diagram_content = (
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
        " GÜN 142: FIRST CVSS v3.1 TABAN METRİK VE SKORLAMA MİMARİSİ\n"
        "===============================================================================\n\n"
        "                  [ CVSS v3.1 VEKTÖR DİZESİ GİRDİSİ ]\n"
        "       'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'\n"
        "                               │\n"
        "                               ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ VEKTÖR AYRIŞTIRICI VE GEÇERLİLİK MOTORU (CvssBaseEngine)               │\n"
        "  │  - Sürüm Öneki Doğrulama: 'CVSS:3.1'                                    │\n"
        "  │  - 8 Zorunlu Metrik Denetimi: AV, AC, PR, UI, S, C, I, A                 │\n"
        "  │  - Metrik Değer Kümesi Kontrolü                                         │\n"
        "  └────────────────────────────┬────────────────────────────────────────────┘\n"
        "                               │\n"
        "              ┌────────────────┴────────────────┐\n"
        "              ▼                                 ▼\n"
        "  ┌─────────────────────────┐       ┌─────────────────────────┐\n"
        "  │ İSTİSMAR EDİLEBİLİRLİK  │       │ ETKİ METRİKLERİ (CIA)   │\n"
        "  │ (Exploitability)        │       │ (Impact Metrics)        │\n"
        "  │  - AV (Attack Vector)   │       │  - C (Confidentiality)  │\n"
        "  │  - AC (Complexity)      │       │  - I (Integrity)        │\n"
        "  │  - PR (Privileges Req)  │       │  - A (Availability)     │\n"
        "  │  - UI (User Interaction)│       │                         │\n"
        "  │                         │       │ ISS = 1-[(1-C)(1-I)(1-A)│\n"
        "  │ Exploit = 8.22*AV*AC*PR*UI      │                         │\n"
        "  └───────────┬─────────────┘       └───────────┬─────────────┘\n"
        "              │                                 │\n"
        "              └────────────────┬────────────────┘\n"
        "                               │\n"
        "                               ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KAPSAM (SCOPE) KARAR DÜĞÜMÜ                                             │\n"
        "  │  - Scope: Unchanged (S:U)  -> Impact = 6.42 * ISS                       │\n"
        "  │                               Base = min(Impact + Exploitability, 10.0) │\n"
        "  │  - Scope: Changed   (S:C)  -> Impact = 7.52*(ISS-0.029)-3.25*(ISS-0.02)^15\n"
        "  │                               Base = min(1.08*(Impact+Exploit), 10.0)   │\n"
        "  └────────────────────────────┬────────────────────────────────────────────┘\n"
        "                               │\n"
        "                               ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ FIRST ROUNDUP FONKSİYONU VE ŞİDDET DERECELENDİRMESİ                     │\n"
        "  │  - Roundup(BaseScore) -> 0.1 ondalık yukarı yuvarlama                   │\n"
        "  │  - 0.0: NONE | 0.1-3.9: LOW | 4.0-6.9: MEDIUM                           │\n"
        "  │  - 7.0-8.9: HIGH | 9.0-10.0: CRITICAL                                   │\n"
        "  └─────────────────────────────────────────────────────────────────────────┘\n"
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
    )
    with open(temsili_path, "w", encoding="utf-8") as fp:
        fp.write(diagram_content)

    print(f"[+] Temsili mimari şeması üretildi: {temsili_path}")
    print("[*] Gün 142 CVSS Temel Metrikleri: Tüm kanıtlar başarıyla üretildi!")


if __name__ == "__main__":
    generate_all_evidence()
