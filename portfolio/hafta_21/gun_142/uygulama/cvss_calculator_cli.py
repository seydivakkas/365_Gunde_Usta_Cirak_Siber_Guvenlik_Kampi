# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 142 - CVSS Taban Metrikleri Hesaplayıcı Komut Satırı Arayüzü (CLI).
Bu araç; güvenlik analistlerine CVSS v3.1 vektörlerini ayrıştırma, taban skorları
hesaplama, zafiyetleri karşılaştırma ve toplu analiz yapma imkanı sunar.
"""

# İşletim sistemi dosya yolları
import os
# Sistem akışları ve argüman yönetimi
import sys
# Komut satırı argüman ayrıştırıcısı
import argparse
# JSON veri formatı
import json

# Windows ortamında UTF-8 konsol çıktısını garantiye al
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Aynı paketteki motor sınıfını import et
from cvss_base_engine import CvssBaseEngine


def run_cli() -> int:
    """
    Komut satırı argümanlarını işler ve ilgili CVSS operasyonlarını yürütür.
    """
    parser = argparse.ArgumentParser(
        description="FIRST CVSS v3.1 Taban Metrikleri Hesaplayıcı ve Analiz Aracı (Gün 142)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. 'calculate' alt komutu
    calc_parser = subparsers.add_parser("calculate", help="CVSS vektör dizesini ayrıştır ve hesapla")
    calc_parser.add_argument("vector", help="Hesaplanacak CVSS v3.1 vektör dizesi")
    calc_parser.add_argument("--output", "-o", help="Oluşturulacak JSON rapor çıktısı dosya yolu")

    # 2. 'compare' alt komutu
    comp_parser = subparsers.add_parser("compare", help="İki CVSS vektörünü karşılaştır")
    comp_parser.add_argument("vector1", help="İlk referans vektör dizesi")
    comp_parser.add_argument("vector2", help="İkinci karşılaştırma vektör dizesi")
    comp_parser.add_argument("--output", "-o", help="Oluşturulacak JSON fark çıktısı dosya yolu")

    # 3. 'batch' alt komutu
    batch_parser = subparsers.add_parser("batch", help="JSON dosyasındaki toplu vektörleri hesapla")
    batch_parser.add_argument("file", help="Vektör listesi içeren JSON dosya yolu")
    batch_parser.add_argument("--output", "-o", help="Oluşturulacak toplu analiz JSON dosya yolu")

    # 4. 'verify' alt komutu
    verify_parser = subparsers.add_parser("verify", help="Vektörün geçerliliğini ve skorunu doğrula")
    verify_parser.add_argument("vector", help="Doğrulanacak CVSS v3.1 vektör dizesi")
    verify_parser.add_argument("--max-score", type=float, default=8.9, help="Kabul edilebilir maksimum skor (varsayılan: 8.9)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    engine = CvssBaseEngine()

    if args.command == "calculate":
        try:
            res = engine.calculate_from_vector(args.vector)
            print("=" * 78)
            print(" FIRST CVSS v3.1 TABAN METRİK HESAPLAMA RAPORU")
            print("=" * 78)
            print(f"Vektör Dizesi    : {res.vector_string}")
            print(f"CVSS Taban Skoru : {res.base_score} / 10.0")
            print(f"Şiddet Seviyesi  : {res.severity}")
            print(f"Etki Alt Skoru   : {res.impact_subscore} (Ham ISS: {res.iss})")
            print(f"İstismar Skoru   : {res.exploitability_subscore}")
            print("-" * 78)
            print("METRİK BİLEŞENLERİ:")
            for m_key, m_desc in res.metric_breakdown.items():
                print(f"  * {m_key:<26} : {m_desc}")
            print("=" * 78)

            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as fp:
                    json.dump({
                        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz.",
                        "vector": res.vector_string,
                        "base_score": res.base_score,
                        "severity": res.severity,
                        "impact": res.impact_subscore,
                        "exploitability": res.exploitability_subscore,
                        "breakdown": res.metric_breakdown
                    }, fp, indent=2, ensure_ascii=False)
                print(f"[+] Detaylı hesaplama raporu kaydedildi: {args.output}")

            return 0
        except Exception as ex:
            print(f"[-] Hata: {ex}", file=sys.stderr)
            return 1

    elif args.command == "compare":
        try:
            comp = engine.compare_vectors(args.vector1, args.vector2)
            print("=" * 78)
            print(" CVSS v3.1 VEKTÖR KARŞILAŞTIRMA VE ETKİ ANALİZİ")
            print("=" * 78)
            print(f"Vektör 1: {comp['vector1']} -> Skor: {comp['score1']} ({comp['severity1']})")
            print(f"Vektör 2: {comp['vector2']} -> Skor: {comp['score2']} ({comp['severity2']})")
            print(f"Skor Farkı (Delta): {comp['score_diff']:+0.1f}")
            print("-" * 78)
            print("DEĞİŞEN METRİKLER:")
            for k, diff in comp["changed_metrics"].items():
                print(f"  * {k.upper():<20} : {diff['v1']} -> {diff['v2']}")
            print("=" * 78)

            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as fp:
                    json.dump(comp, fp, indent=2, ensure_ascii=False)
                print(f"[+] Karşılaştırma raporu kaydedildi: {args.output}")

            return 0
        except Exception as ex:
            print(f"[-] Hata: {ex}", file=sys.stderr)
            return 1

    elif args.command == "batch":
        try:
            if not os.path.exists(args.file):
                print(f"[-] Dosya bulunamadı: {args.file}", file=sys.stderr)
                return 1
            with open(args.file, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            v_list = data.get("vectors", [])
            report = engine.batch_evaluate(v_list)
            print("=" * 78)
            print(f" TOPLU CVSS ANALİZ RAPORU — TOPLAM {report['total_evaluated']} VEKTÖR")
            print("=" * 78)
            print(f"Ortalama Taban Skor: {report['average_base_score']} / 10.0")
            print("Şiddet Dağılımı:")
            for sev, cnt in report["severity_distribution"].items():
                print(f"  * {sev:<10}: {cnt}")
            print("=" * 78)

            if args.output:
                os.makedirs(os.path.dirname(args.output), exist_ok=True)
                with open(args.output, "w", encoding="utf-8") as fp:
                    json.dump(report, fp, indent=2, ensure_ascii=False)
                print(f"[+] Toplu analiz raporu kaydedildi: {args.output}")

            return 0
        except Exception as ex:
            print(f"[-] Hata: {ex}", file=sys.stderr)
            return 1

    elif args.command == "verify":
        try:
            res = engine.calculate_from_vector(args.vector)
            if res.base_score <= args.max_score:
                print(f"[PASS] Skor kabul edilebilir sınırda: {res.base_score} <= {args.max_score} ({res.severity})")
                return 0
            else:
                print(f"[FAIL] Skor izin verilen sınırı aştı: {res.base_score} > {args.max_score} ({res.severity})")
                return 1
        except Exception as ex:
            print(f"[-] Vektör doğrulama hatası: {ex}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_cli())
