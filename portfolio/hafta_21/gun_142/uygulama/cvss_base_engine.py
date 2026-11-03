# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 142 - CVSS Temel Metrikleri Hesaplama ve Ayrıştırma Motoru.
Bu modül, FIRST (Forum of Incident Response and Security Teams) CVSS v3.1
resmî şartnamesine uygun olarak; İstismar Edilebilirlik (Exploitability),
Kapsam (Scope) ve Etki (Impact) metriklerini matematiksel olarak hesaplayan,
vektör dizelerini doğrulayan ve zafiyet şiddetini derecelendiren kurumsal motordur.
"""

# İşletim sistemi dosya yolu ve ortam fonksiyonları
import os
# Sistem akışları ve argüman kontrolü
import sys
# Yapılandırılmış JSON verisi işleme
import json
# Düzenli ifadeler ile metin ayrıştırma
import re
# Matematiksel yuvarlama ve üs alma fonksiyonları
import math
# Veri yapılarını nesne yönelimli temsil etmek için dataclass modülü
from dataclasses import dataclass, field, asdict
# Tip ipuçları ve statik analiz desteği
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class CvssBaseMetrics:
    """
    CVSS v3.1 Taban Metrikleri Veri Modeli (8 Zorunlu Bileşen).
    """
    attack_vector: str           # AV: N (Network), A (Adjacent), L (Local), P (Physical)
    attack_complexity: str       # AC: L (Low), H (High)
    privileges_required: str     # PR: N (None), L (Low), H (High)
    user_interaction: str        # UI: N (None), R (Required)
    scope: str                   # S:  U (Unchanged), C (Changed)
    confidentiality: str         # C:  H (High), L (Low), N (None)
    integrity: str               # I:  H (High), L (Low), N (None)
    availability: str            # A:  H (High), L (Low), N (None)


@dataclass
class CvssCalculationResult:
    """
    CVSS v3.1 Taban Hesaplama ve Skorlama Çıktısı.
    """
    vector_string: str                   # Resmî vektör dizesi (örn: CVSS:3.1/AV:N/AC:L/...)
    base_score: float                    # Hesaplanmış CVSS Taban Skoru (0.0 - 10.0)
    severity: str                        # Niteliksel Şiddet: NONE, LOW, MEDIUM, HIGH, CRITICAL
    impact_subscore: float               # Etki alt skoru (Impact)
    exploitability_subscore: float       # İstismar edilebilirlik alt skoru (Exploitability)
    iss: float                           # Ham Etki Alt Skoru (Impact Sub-Score)
    metric_breakdown: Dict[str, str]     # İnsan tarafından okunabilir metrik dökümü


class CvssBaseEngine:
    """
    FIRST CVSS v3.1 Resmî Standartlarında Taban Metrik Hesaplama Motoru.
    """

    # Vektör öneki ve sürüm doğrulaması
    VECTOR_PREFIX = "CVSS:3.1"

    # Zorunlu metrik anahtarları sırası
    REQUIRED_METRIC_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

    # İzin verilen metrik değerleri ve katsayıları
    WEIGHTS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    WEIGHTS_AC = {"L": 0.77, "H": 0.44}
    WEIGHTS_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    WEIGHTS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    WEIGHTS_UI = {"N": 0.85, "R": 0.62}
    WEIGHTS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

    # İnsan tarafından okunabilir açıklamalar
    DESCRIPTIONS = {
        "AV": {"N": "Network (Ağ Üzerinden)", "A": "Adjacent (Bitişik Ağ)", "L": "Local (Yerel)", "P": "Physical (Fiziksel)"},
        "AC": {"L": "Low (Düşük Karmaşıklık)", "H": "High (Yüksek Karmaşıklık)"},
        "PR": {"N": "None (Yetkisiz)", "L": "Low (Düşük Yetki)", "H": "High (Yüksek/Root Yetki)"},
        "UI": {"N": "None (Kullanıcı Etkileşimi Yok)", "R": "Required (Kullanıcı Etkileşimi Gerekli)"},
        "S":  {"U": "Unchanged (Kapsam Değişmedi)", "C": "Changed (Kapsam Değişti / Sınır Aşıldı)"},
        "C":  {"H": "High (Yüksek Gizlilik Kaybı)", "L": "Low (Düşük Gizlilik Kaybı)", "N": "None (Gizlilik Etkisi Yok)"},
        "I":  {"H": "High (Yüksek Bütünlük Bozulması)", "L": "Low (Düşük Bütünlük Bozulması)", "N": "None (Bütünlük Etkisi Yok)"},
        "A":  {"H": "High (Tam Hizmet Kesintisi)", "L": "Low (Düşük Performans Kaybı)", "N": "None (Erişilebilirlik Etkisi Yok)"}
    }

    @staticmethod
    def roundup(value: float) -> float:
        """
        FIRST CVSS v3.1 resmî şartnamesinde tanımlanan Roundup algoritması.
        Değeri bir üst ondalık basamağa yuvarlar (örn: 4.02 -> 4.1, 4.00 -> 4.0).
        """
        int_input = round(value * 100000)
        if int_input % 10000 == 0:
            return round(int_input / 100000.0, 1)
        else:
            return round((math.floor(int_input / 10000) + 1) / 10.0, 1)

    def parse_vector_string(self, vector_str: str) -> CvssBaseMetrics:
        """
        CVSS v3.1 vektör dizesini doğrular ve CvssBaseMetrics nesnesine ayrıştırır.
        Örnek: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        """
        if not vector_str or not isinstance(vector_str, str):
            raise ValueError("Geçersiz veya boş CVSS vektör dizesi.")

        parts = vector_str.strip().split("/")
        # İlk parça CVSS:3.1 olmalıdır
        if parts[0] != self.VECTOR_PREFIX:
            raise ValueError(f"Hatalı CVSS sürüm öneki: '{parts[0]}'. Beklenen: '{self.VECTOR_PREFIX}'")

        metrics_map: Dict[str, str] = {}
        for token in parts[1:]:
            if ":" not in token:
                raise ValueError(f"Bozuk vektör bileşeni: '{token}'. 'ANAHTAR:DEĞER' biçiminde olmalı.")
            k, v = token.split(":", 1)
            k, v = k.strip().upper(), v.strip().upper()
            metrics_map[k] = v

        # 8 zorunlu metriğin eksiksiz varlığını denetle
        for req in self.REQUIRED_METRIC_KEYS:
            if req not in metrics_map:
                raise ValueError(f"Eksik zorunlu CVSS metriği tespit edildi: '{req}'")

        # Metrik değerlerinin geçerlilik kontrolü
        av = metrics_map["AV"]
        if av not in self.WEIGHTS_AV:
            raise ValueError(f"Geçersiz AV (Attack Vector) değeri: '{av}'. İzin verilenler: N, A, L, P")

        ac = metrics_map["AC"]
        if ac not in self.WEIGHTS_AC:
            raise ValueError(f"Geçersiz AC (Attack Complexity) değeri: '{ac}'. İzin verilenler: L, H")

        pr = metrics_map["PR"]
        if pr not in ["N", "L", "H"]:
            raise ValueError(f"Geçersiz PR (Privileges Required) değeri: '{pr}'. İzin verilenler: N, L, H")

        ui = metrics_map["UI"]
        if ui not in self.WEIGHTS_UI:
            raise ValueError(f"Geçersiz UI (User Interaction) değeri: '{ui}'. İzin verilenler: N, R")

        s = metrics_map["S"]
        if s not in ["U", "C"]:
            raise ValueError(f"Geçersiz S (Scope) değeri: '{s}'. İzin verilenler: U, C")

        c = metrics_map["C"]
        if c not in self.WEIGHTS_CIA:
            raise ValueError(f"Geçersiz C (Confidentiality) değeri: '{c}'. İzin verilenler: H, L, N")

        i = metrics_map["I"]
        if i not in self.WEIGHTS_CIA:
            raise ValueError(f"Geçersiz I (Integrity) değeri: '{i}'. İzin verilenler: H, L, N")

        a = metrics_map["A"]
        if a not in self.WEIGHTS_CIA:
            raise ValueError(f"Geçersiz A (Availability) değeri: '{a}'. İzin verilenler: H, L, N")

        return CvssBaseMetrics(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a
        )

    def calculate_base_score(self, metrics: CvssBaseMetrics) -> CvssCalculationResult:
        """
        FIRST CVSS v3.1 resmî formülü ile taban skoru hesaplar.
        """
        # Katsayıları sözlüklerden al
        w_av = self.WEIGHTS_AV[metrics.attack_vector]
        w_ac = self.WEIGHTS_AC[metrics.attack_complexity]

        # Scope'a bağlı PR katsayısı
        if metrics.scope == "U":
            w_pr = self.WEIGHTS_PR_UNCHANGED[metrics.privileges_required]
        else:
            w_pr = self.WEIGHTS_PR_CHANGED[metrics.privileges_required]

        w_ui = self.WEIGHTS_UI[metrics.user_interaction]

        w_c = self.WEIGHTS_CIA[metrics.confidentiality]
        w_i = self.WEIGHTS_CIA[metrics.integrity]
        w_a = self.WEIGHTS_CIA[metrics.availability]

        # 1. Ham Etki Alt Skoru (ISS - Impact Sub-Score)
        iss = 1.0 - ((1.0 - w_c) * (1.0 - w_i) * (1.0 - w_a))

        # 2. Etki Skoru (Impact)
        if metrics.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. İstismar Edilebilirlik Skoru (Exploitability)
        exploitability = 8.22 * w_av * w_ac * w_pr * w_ui

        # 4. Taban Skor (BaseScore)
        if impact <= 0:
            base_score = 0.0
        elif metrics.scope == "U":
            base_score = self.roundup(min(impact + exploitability, 10.0))
        else:
            base_score = self.roundup(min(1.08 * (impact + exploitability), 10.0))

        # 5. Niteliksel Şiddet Derecesi
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        elif base_score > 0.0:
            severity = "LOW"
        else:
            severity = "NONE"

        # Vektör dizesini standart sırada yeniden oluştur
        vector_str = (
            f"CVSS:3.1/AV:{metrics.attack_vector}/AC:{metrics.attack_complexity}/"
            f"PR:{metrics.privileges_required}/UI:{metrics.user_interaction}/"
            f"S:{metrics.scope}/C:{metrics.confidentiality}/"
            f"I:{metrics.integrity}/A:{metrics.availability}"
        )

        # İnsan tarafından okunabilir açıklamalar
        breakdown = {
            "Attack Vector (AV)": self.DESCRIPTIONS["AV"][metrics.attack_vector],
            "Attack Complexity (AC)": self.DESCRIPTIONS["AC"][metrics.attack_complexity],
            "Privileges Required (PR)": self.DESCRIPTIONS["PR"][metrics.privileges_required],
            "User Interaction (UI)": self.DESCRIPTIONS["UI"][metrics.user_interaction],
            "Scope (S)": self.DESCRIPTIONS["S"][metrics.scope],
            "Confidentiality (C)": self.DESCRIPTIONS["C"][metrics.confidentiality],
            "Integrity (I)": self.DESCRIPTIONS["I"][metrics.integrity],
            "Availability (A)": self.DESCRIPTIONS["A"][metrics.availability]
        }

        return CvssCalculationResult(
            vector_string=vector_str,
            base_score=base_score,
            severity=severity,
            impact_subscore=round(impact, 1),
            exploitability_subscore=round(exploitability, 1),
            iss=round(iss, 3),
            metric_breakdown=breakdown
        )

    def calculate_from_vector(self, vector_str: str) -> CvssCalculationResult:
        """
        Vektör dizesini ayrıştırır ve doğrudan hesaplama sonucunu döner.
        """
        metrics = self.parse_vector_string(vector_str)
        return self.calculate_base_score(metrics)

    def compare_vectors(self, vector1: str, vector2: str) -> Dict[str, Any]:
        """
        İki CVSS vektörünü karşılaştırır ve değişen metrikler ile puan farkını analiz eder.
        """
        res1 = self.calculate_from_vector(vector1)
        res2 = self.calculate_from_vector(vector2)

        m1 = self.parse_vector_string(vector1)
        m2 = self.parse_vector_string(vector2)

        d1 = asdict(m1)
        d2 = asdict(m2)

        differences = {}
        for k in d1:
            if d1[k] != d2[k]:
                differences[k] = {"v1": d1[k], "v2": d2[k]}

        return {
            "vector1": res1.vector_string,
            "vector2": res2.vector_string,
            "score1": res1.base_score,
            "score2": res2.base_score,
            "score_diff": round(res2.base_score - res1.base_score, 1),
            "severity1": res1.severity,
            "severity2": res2.severity,
            "changed_metrics": differences
        }

    def batch_evaluate(self, vector_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Toplu vektör listesini hesaplar ve istatistiksel dağılım raporu üretir.
        """
        evaluated = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}

        for item in vector_list:
            v_str = item.get("vector_string", "")
            cve_id = item.get("cve_id", "UNKNOWN")
            title = item.get("title", "")

            calc = self.calculate_from_vector(v_str)
            severity_counts[calc.severity] += 1

            evaluated.append({
                "cve_id": cve_id,
                "title": title,
                "vector_string": calc.vector_string,
                "base_score": calc.base_score,
                "severity": calc.severity,
                "impact": calc.impact_subscore,
                "exploitability": calc.exploitability_subscore
            })

        total = len(evaluated)
        avg_score = round(sum(e["base_score"] for e in evaluated) / total, 2) if total > 0 else 0.0

        return {
            "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
            "total_evaluated": total,
            "average_base_score": avg_score,
            "severity_distribution": severity_counts,
            "results": evaluated
        }
