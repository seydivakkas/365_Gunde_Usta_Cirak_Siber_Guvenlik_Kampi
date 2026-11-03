"""
Tehdit, Zafiyet, Olay ve Risk Matrisi Değerlendiricisi
===================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu uygulama, siber güvenlikte Tehdit, Zafiyet, Olay ve Risk kavramlarını
matematiksel risk matrisi (5x5) ve NIST CSF/ISO 27005 metodolojisiyle
modeller, önlem öncesi ve sonrası artık riski (residual risk) hesaplar.

Kullanım:
    python risk_matrix_evaluator.py --eval
    python risk_matrix_evaluator.py --table
    python risk_matrix_evaluator.py --scenario SCN-01
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Tuple, Any


class RiskEvaluationException(Exception):
    """Risk değerlendirme temel istisnası."""
    pass


class InvalidRiskParameterError(RiskEvaluationException):
    """Geçersiz olasılık, etki veya varlık değeri (1-5 aralığı dışında)."""
    pass


class MissingScenarioFieldError(RiskEvaluationException):
    """Senaryoda zorunlu alanlardan biri eksik."""
    pass


class UnrealisticSecurityClaimError(RiskEvaluationException):
    """Yanılgı Tespiti: Tek bir önlemle riskin sıfırlandığı iddiası."""
    pass


class RiskMatrixEvaluator:
    """
    Tehdit-Zafiyet-Etki matrisi hesaplayıcısı ve senaryo denetleyicisi.
    """

    SEVİYELER = {
        (1, 4): "DÜŞÜK",
        (5, 9): "ORTA",
        (10, 16): "YÜKSEK",
        (17, 25): "KRİTİK"
    }

    REQUIRED_FIELDS = [
        "id", "baslik", "varlik", "tehdit", "zafiyet", "olay",
        "olasilik", "etki", "onlem"
    ]

    def __init__(self, scenarios_path: str):
        self.scenarios_path = os.path.abspath(scenarios_path)
        self.scenarios: List[Dict[str, Any]] = []
        self.load_scenarios()

    def load_scenarios(self):
        """Senaryo JSON dosyasını okur ve yükler."""
        if not os.path.exists(self.scenarios_path):
            raise FileNotFoundError(f"Senaryo dosyası bulunamadı: {self.scenarios_path}")
        with open(self.scenarios_path, "r", encoding="utf-8") as f:
            self.scenarios = json.load(f)

    @classmethod
    def calculate_score_and_level(cls, olasilik: int, etki: int) -> Tuple[int, str]:
        """
        Risk Skoru = Olasılık (1-5) * Etki (1-5)
        Skor 1-25 arasındadır.
        """
        if not (isinstance(olasilik, int) and 1 <= olasilik <= 5):
            raise InvalidRiskParameterError(f"Olasılık 1 ile 5 arasında tam sayı olmalıdır! Verilen: {olasilik}")
        if not (isinstance(etki, int) and 1 <= etki <= 5):
            raise InvalidRiskParameterError(f"Etki 1 ile 5 arasında tam sayı olmalıdır! Verilen: {etki}")

        score = olasilik * etki
        for (low, high), level in cls.SEVİYELER.items():
            if low <= score <= high:
                return score, level
        return score, "BİLİNMİYOR"

    @classmethod
    def evaluate_mitigation(cls, initial_score: int, post_olasilik: int, post_etki: int) -> Tuple[int, str, float]:
        """
        Önlem sonrası Artık Risk (Residual Risk) hesaplar.
        Ölümcül yanılgı kontrolü: Risk asla 0 olamaz (mutlak güvenlik imkansızdır).
        """
        if post_olasilik == 0 or post_etki == 0:
            raise UnrealisticSecurityClaimError(
                "ÖLÜMCÜL YANILGI TESPİT EDİLDİ: Tek bir önlemle riskin 0'a indirildiği iddia edilemez! "
                "Siber güvenlikte artık risk daima mevcuttur."
            )

        post_score, post_level = cls.calculate_score_and_level(post_olasilik, post_etki)
        reduction_percentage = ((initial_score - post_score) / initial_score) * 100.0
        return post_score, post_level, round(reduction_percentage, 1)

    def validate_scenario(self, scn: Dict[str, Any]) -> bool:
        """Bir senaryonun tüm zorunlu alanlarını ve parametre sınırlarını doğrular."""
        for field in self.REQUIRED_FIELDS:
            if field not in scn or scn[field] is None:
                raise MissingScenarioFieldError(f"Senaryoda zorunlu alan eksik: '{field}' (ID: {scn.get('id', 'Bilinmiyor')})")

        # Aralık kontrolü (Negatif Kontrol)
        self.calculate_score_and_level(scn["olasilik"], scn["etki"])
        return True

    def run_full_evaluation(self) -> List[Dict[str, Any]]:
        """Tüm senaryoları değerlendirir, risk puanlarını doğrular ve raporlar."""
        results = []
        for scn in self.scenarios:
            self.validate_scenario(scn)
            score, level = self.calculate_score_and_level(scn["olasilik"], scn["etki"])
            
            post_o = scn.get("onlem_sonrasi_olasilik", scn["olasilik"])
            post_e = scn.get("onlem_sonrasi_etki", scn["etki"])
            post_score, post_level, reduction = self.evaluate_mitigation(score, post_o, post_e)

            results.append({
                "id": scn["id"],
                "baslik": scn["baslik"],
                "varlik": scn["varlik"],
                "tehdit": scn["tehdit"],
                "zafiyet": scn["zafiyet"],
                "olay": scn["olay"],
                "onlem": scn["onlem"],
                "inherent_score": score,
                "inherent_level": level,
                "residual_score": post_score,
                "residual_level": post_level,
                "risk_reduction_pct": reduction
            })
        return results


def print_formatted_table(results: List[Dict[str, Any]]):
    """Senaryoları terminale profesyonel bir matris olarak basar."""
    print("=" * 95)
    print("SİBER GÜVENLİK 365: GÜN 002 — TEHDİT / ZAFİYET / OLAY / RİSK MATRİSİ")
    print("=" * 95)
    header = f"{'ID':<8} | {'BAŞLIK':<35} | {'DOĞAL RİSK':<14} | {'ARTIK RİSK':<14} | {'AZALMA':<8}"
    print(header)
    print("-" * 95)
    for r in results:
        inh = f"{r['inherent_score']} ({r['inherent_level']})"
        res = f"{r['residual_score']} ({r['residual_level']})"
        red = f"%{r['risk_reduction_pct']}"
        print(f"{r['id']:<8} | {r['baslik'][:35]:<35} | {inh:<14} | {res:<14} | {red:<8}")
    print("-" * 95)

    print("\nAYRINTILI SENARYO ANALİZLERİ:\n")
    for r in results:
        print(f"[{r['id']}] {r['baslik']}")
        print(f"  * Varlık  : {r['varlik']}")
        print(f"  * Tehdit  : {r['tehdit']}")
        print(f"  * Zafiyet : {r['zafiyet']}")
        print(f"  * Olay    : {r['olay']}")
        print(f"  * Önlem   : {r['onlem']}")
        print(f"  * Risk Analizi: Doğal Risk = {r['inherent_score']} ({r['inherent_level']}) -> Artık Risk = {r['residual_score']} ({r['residual_level']}) [Risk Azalma: %{r['risk_reduction_pct']}]\n")


def main():
    default_path = os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "senaryolar.json")
    parser = argparse.ArgumentParser(description="Tehdit, Zafiyet, Olay ve Risk Değerlendiricisi (Gün 002)")
    parser.add_argument("--scenarios", default=default_path, help="Senaryolar JSON dosyası")
    parser.add_argument("--eval", action="store_true", help="Tüm senaryoları doğrula ve değerlendir")
    parser.add_argument("--table", action="store_true", help="Formatlı özet tablosunu bas")
    parser.add_argument("--scenario", type=str, help="Tek bir senaryo ID'sini ayrıntılı incele")

    args = parser.parse_args()
    evaluator = RiskMatrixEvaluator(args.scenarios)

    if args.eval or args.table:
        results = evaluator.run_full_evaluation()
        print_formatted_table(results)
        print("[BAŞARILI] 3 senaryonun tamamı eksiksiz doğrulandı ve risk matrisi hesaplandı.")
        sys.exit(0)

    elif args.scenario:
        results = evaluator.run_full_evaluation()
        match = [r for r in results if r["id"].upper() == args.scenario.upper()]
        if not match:
            print(f"[!] HATA: '{args.scenario}' ID'li senaryo bulunamadı.")
            sys.exit(1)
        r = match[0]
        print(f"Senaryo Detayı: {r['id']} - {r['baslik']}")
        for k, v in r.items():
            print(f"  {k}: {v}")

    else:
        # Varsayılan olarak değerlendirmeyi çalıştır
        results = evaluator.run_full_evaluation()
        print_formatted_table(results)


if __name__ == "__main__":
    main()
