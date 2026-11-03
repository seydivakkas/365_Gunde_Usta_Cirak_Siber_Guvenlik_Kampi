# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 121: Risk Skorlama ve Kontrol Seçimi Çekirdek Motoru.
Bu modül; NIST SP 800-30 ve ISO 27005 standartlarına uygun nitel ve nicel risk analizi,
SLE/ARO/ALE hesaplaması, CIS/NIST kontrol eşleştirmesi, ROSI (Return on Security Investment)
ve kurumsal risk iştahı doğrulaması (CWE-1025) gerçekleştirir.
"""

# Standart kütüphane enum modülü içe aktarılıyor
from enum import Enum
# Veri yapılarını tanımlamak için dataclass ve field içe aktarılıyor
from dataclasses import dataclass, field
# Tip ipuçları için gerekli tipler içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any
# Zaman damgaları üretmek için datetime modülü içe aktarılıyor
from datetime import datetime
# JSON serileştirme ve dışa aktarım için json modülü içe aktarılıyor
import json


# ============================================================================
# ÖZEL HATA SINIFLARI (CUSTOM EXCEPTIONS)
# ============================================================================

class RiskEngineError(Exception):
    """Risk yönetim motoru temel istisna sınıfı."""
    pass


class InvalidRiskScoreError(RiskEngineError):
    """Risk skorlama parametreleri (olasılık veya etki) geçerli aralıkta olmadığında fırlatılır."""
    pass


class RiskAppetiteExceededError(RiskEngineError):
    """Artık risk veya kabul edilen risk, kurumsal risk iştahı sınırını aştığında fırlatılır (CWE-1025)."""
    pass


class InvalidControlSelectionError(RiskEngineError):
    """Seçilen güvenlik kontrolü geçersiz, uyumsuz veya bulunamadığında fırlatılır."""
    pass


class MissingRiskTreatmentError(RiskEngineError):
    """Azaltma (mitigate) stratejisi seçilip hiçbir kontrol atanmadığında fırlatılır."""
    pass


class DuplicateRiskError(RiskEngineError):
    """Aynı kimliğe (ID) sahip mükerrer risk tanımlanmaya çalışıldığında fırlatılır."""
    pass


class DuplicateControlError(RiskEngineError):
    """Aynı kimliğe (ID) sahip mükerrer kontrol tanımlanmaya çalışıldığında fırlatılır."""
    pass


class InvalidFinancialMetricError(RiskEngineError):
    """Varlık değeri, maruz kalma faktörü (EF) veya ARO negatif ya da mantıksız olduğunda fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class RiskLevel(Enum):
    """Nitel risk seviyeleri ve dereceleri."""
    LOW = "DÜŞÜK"             # Skor 1 - 5 arası
    MEDIUM = "ORTA"           # Skor 6 - 11 arası
    HIGH = "YÜKSEK"           # Skor 12 - 19 arası
    CRITICAL = "KRİTİK"       # Skor 20 - 25 arası


class RiskTreatmentStrategy(Enum):
    """ISO 27005 ve NIST SP 800-30 Risk İyileştirme / Yanıt Stratejileri."""
    MITIGATE = "AZALT"        # Kontroller uygulayarak riski kabul edilebilir seviyeye düşürme
    AVOID = "KAÇIN"           # Riski doğuran iş veya teknolojiyi tamamen terk etme
    TRANSFER = "DEVRET"       # Riski üçüncü tarafa (siber sigorta, bulut sağlayıcı) devretme
    ACCEPT = "KABUL_ET"       # Riski mevcut haliyle üstlenme (onay zorunludur)


class ControlFamily(Enum):
    """NIST SP 800-53 Rev 5 ve CIS Controls Güvenlik Kontrol Aileleri."""
    AC = "Access Control (Erişim Kontrolü)"
    IA = "Identification and Authentication (Kimlik Doğrulama)"
    SC = "System and Communications Protection (İletişim ve Sistem Koruması)"
    SI = "System and Information Integrity (Sistem ve Bilgi Bütünlüğü)"
    AU = "Audit and Accountability (Denetim ve Hesap Verebilirlik)"
    CP = "Contingency Planning (İş Sürekliliği ve Felaket Kurtarma)"
    RA = "Risk Assessment (Risk Değerlendirme)"


class ControlType(Enum):
    """Güvenlik kontrolünün icra edilme karakteristiği."""
    PREVENTIVE = "Önleyici (Preventive)"
    DETECTIVE = "Tespit Edici (Detective)"
    CORRECTIVE = "Düzeltici (Corrective)"
    COMPENSATING = "Telafi Edici (Compensating)"


@dataclass
class SecurityControl:
    """NIST SP 800-53 veya CIS standardında güvenlik kontrolü modeli."""
    control_id: str                      # Kontrol benzersiz kimliği (örn: 'NIST-AC-2')
    name: str                            # Kontrol adı
    family: ControlFamily                # Kontrol ailesi
    control_type: ControlType            # Kontrolün tipi (Önleyici, Tespit edici vb.)
    annual_cost: float                   # Yıllık lisans/işletme maliyeti (USD)
    implementation_cost: float           # İlk kurulum/proje maliyeti (USD)
    effectiveness_ratio: float           # Tehdidin başarı şansını veya etkisini azaltma oranı (0.01 - 0.99)
    lifecycle_years: int = 3             # Kontrolün amortisman/yaşam döngüsü yılı

    def get_annualized_cost(self) -> float:
        """İlk yatırım ve yıllık işletme maliyetini yıllıklandırılmış olarak hesaplar."""
        # İlk kurulum maliyeti yaşam döngüsüne bölünür ve yıllık idame maliyetine eklenir
        return (self.implementation_cost / max(1, self.lifecycle_years)) + self.annual_cost


@dataclass
class RiskItem:
    """Varlık odaklı siber güvenlik risk öğesi modeli."""
    risk_id: str                         # Risk benzersiz kimliği (örn: 'RSK-001')
    title: str                           # Risk başlığı
    description: str                     # Risk detay açıklaması
    asset_name: str                      # Risk altındaki varlığın adı
    asset_value: float                   # Varlık değeri (USD)
    exposure_factor: float               # Maruz kalma faktörü (EF: 0.0 - 1.0)
    annualized_rate_of_occurrence: float # Yıllık gerçekleşme sıklığı (ARO: örn 0.5 veya 2.0)
    likelihood: int                      # Doğal olasılık derecesi (1 - 5)
    impact: int                          # Doğal etki derecesi (1 - 5)
    treatment_strategy: RiskTreatmentStrategy = RiskTreatmentStrategy.MITIGATE
    applied_controls: List[SecurityControl] = field(default_factory=list)
    executive_sign_off: bool = False     # Üst yönetim onay bayrağı
    sign_off_notes: str = ""             # Onay gerekçesi

    def validate_inputs(self) -> None:
        """Risk parametrelerinin matematiksel ve mantıksal geçerliliğini denetler."""
        # Olasılık değeri 1 ile 5 arasında tam sayı olmalıdır
        if not (1 <= self.likelihood <= 5):
            # Geçersiz olasılık hatası fırlatılır
            raise InvalidRiskScoreError(f"Olasılık puanı 1 ile 5 arasında olmalıdır. Verilen: {self.likelihood}")
        # Etki değeri 1 ile 5 arasında tam sayı olmalıdır
        if not (1 <= self.impact <= 5):
            # Geçersiz etki hatası fırlatılır
            raise InvalidRiskScoreError(f"Etki puanı 1 ile 5 arasında olmalıdır. Verilen: {self.impact}")
        # Varlık değeri sıfırdan küçük olamaz
        if self.asset_value < 0:
            # Finansal metrik hatası fırlatılır
            raise InvalidFinancialMetricError(f"Varlık değeri negatif olamaz: {self.asset_value}")
        # Maruz kalma faktörü 0.0 ile 1.0 arasında olmalıdır
        if not (0.0 <= self.exposure_factor <= 1.0):
            # Maruz kalma faktörü hatası fırlatılır
            raise InvalidFinancialMetricError(f"Maruz kalma faktörü (EF) 0.0-1.0 aralığında olmalıdır: {self.exposure_factor}")
        # ARO sıfırdan küçük olamaz
        if self.annualized_rate_of_occurrence < 0:
            # ARO hatası fırlatılır
            raise InvalidFinancialMetricError(f"Yıllık gerçekleşme oranı (ARO) negatif olamaz: {self.annualized_rate_of_occurrence}")

    def calculate_sle(self) -> float:
        """Tekil Kayıp Beklentisi (Single Loss Expectancy - SLE) hesaplar."""
        # SLE = Varlık Değeri * Maruz Kalma Faktörü
        return self.asset_value * self.exposure_factor

    def calculate_inherent_ale(self) -> float:
        """Kontrolsüz Doğal Yıllık Kayıp Beklentisi (Inherent ALE) hesaplar."""
        # Inherent ALE = SLE * ARO
        return self.calculate_sle() * self.annualized_rate_of_occurrence

    def get_inherent_score(self) -> int:
        """Doğal (kontrolsüz) nitel risk skorunu hesaplar (1 - 25)."""
        # Skor = Olasılık * Etki
        return self.likelihood * self.impact

    def get_inherent_level(self) -> RiskLevel:
        """Doğal risk skoruna karşılık gelen nitel risk seviyesini döndürür."""
        # Hesaplanan doğal skor alınır
        score = self.get_inherent_score()
        # 20 ve üzeri kritik risk seviyesidir
        if score >= 20:
            # Kritik seviye döndürülür
            return RiskLevel.CRITICAL
        # 12 ile 19 arası yüksek risk seviyesidir
        elif score >= 12:
            # Yüksek seviye döndürülür
            return RiskLevel.HIGH
        # 6 ile 11 arası orta risk seviyesidir
        elif score >= 6:
            # Orta seviye döndürülür
            return RiskLevel.MEDIUM
        # 5 ve altı düşük risk seviyesidir
        else:
            # Düşük seviye döndürülür
            return RiskLevel.LOW

    def get_total_control_effectiveness(self) -> float:
        """Uygulanan tüm kontrollerin birleşik etkinlik oranını hesaplar."""
        # Eğer hiçbir kontrol uygulanmadıysa etkinlik sıfırdır
        if not self.applied_controls:
            # 0.0 döndürülür
            return 0.0
        # Kontrollerin bağımsız kalıntı risk çarpanı 1.0 olarak başlatılır
        remaining_risk_ratio = 1.0
        # Her bir güvenlik kontrolü üzerinden döngü kurulur
        for ctrl in self.applied_controls:
            # Kalan risk çarpanı her kontrolün etkinlik oranı kadar azaltılır
            remaining_risk_ratio *= (1.0 - ctrl.effectiveness_ratio)
        # Toplam etkinlik 1.0'dan kalan risk oranının çıkarılmasıyla bulunur (en fazla 0.98 ile sınırlandırılır)
        total_eff = 1.0 - remaining_risk_ratio
        # Hiçbir zaman %100 mutlak güvenlik olamayacağından 0.98 tavanı uygulanır
        return min(0.98, max(0.0, total_eff))

    def calculate_residual_ale(self) -> float:
        """Kontroller uygulandıktan sonraki Artık Yıllık Kayıp Beklentisini (Residual ALE) hesaplar."""
        # Eğer kaçınma stratejisi seçildiyse risk tamamen sonlandırılmıştır
        if self.treatment_strategy == RiskTreatmentStrategy.AVOID:
            # Risk tamamen sıfırlanır
            return 0.0
        # Doğal yıllık kayıp beklentisi hesaplanır
        inherent_ale = self.calculate_inherent_ale()
        # Uygulanan kontrollerin birleşik etkinliği alınır
        effectiveness = self.get_total_control_effectiveness()
        # Eğer devretme stratejisi seçildiyse (sigorta vb.) kayıp beklentisi %80 oranında devredilir
        if self.treatment_strategy == RiskTreatmentStrategy.TRANSFER:
            # Sigorta teminatı sonrası %20 muafiyet payı kalır
            return inherent_ale * 0.20
        # Artık ALE = Doğal ALE * (1 - Kontrol Etkinliği)
        return inherent_ale * (1.0 - effectiveness)

    def get_residual_likelihood(self) -> int:
        """Kontroller sonrası geriye kalan artık olasılık puanını hesaplar (1 - 5)."""
        # Kaçınma stratejisinde olasılık taban seviye 1'e iner
        if self.treatment_strategy == RiskTreatmentStrategy.AVOID:
            # 1 puan döndürülür
            return 1
        # Uygulanan kontrollerin etkinliği alınır
        eff = self.get_total_control_effectiveness()
        # Yeni olasılık hesaplanır ve yuvarlanır
        new_likelihood = round(self.likelihood * (1.0 - (eff * 0.7)))
        # Minimum 1 ve maksimum mevcut olasılık aralığında sınırlandırılır
        return max(1, min(self.likelihood, new_likelihood))

    def get_residual_impact(self) -> int:
        """Kontroller sonrası geriye kalan artık etki puanını hesaplar (1 - 5)."""
        # Kaçınma stratejisinde etki taban seviye 1'e iner
        if self.treatment_strategy == RiskTreatmentStrategy.AVOID:
            # 1 puan döndürülür
            return 1
        # Uygulanan kontrollerin etkinliği alınır
        eff = self.get_total_control_effectiveness()
        # Yeni etki hesaplanır ve yuvarlanır
        new_impact = round(self.impact * (1.0 - (eff * 0.6)))
        # Minimum 1 ve maksimum mevcut etki aralığında sınırlandırılır
        return max(1, min(self.impact, new_impact))

    def get_residual_score(self) -> int:
        """Artık nitel risk skorunu hesaplar (1 - 25)."""
        # Artık olasılık ile artık etkinin çarpımı hesaplanır
        return self.get_residual_likelihood() * self.get_residual_impact()

    def get_residual_level(self) -> RiskLevel:
        """Artık risk skoruna karşılık gelen nitel risk seviyesini döndürür."""
        # Artık skor hesaplanır
        score = self.get_residual_score()
        # 20 ve üzeri kritik kabul edilir
        if score >= 20:
            # Kritik seviye döndürülür
            return RiskLevel.CRITICAL
        # 12 ile 19 arası yüksek risk seviyesidir
        elif score >= 12:
            # Yüksek seviye döndürülür
            return RiskLevel.HIGH
        # 6 ile 11 arası orta risk seviyesidir
        elif score >= 6:
            # Orta seviye döndürülür
            return RiskLevel.MEDIUM
        # 5 ve altı düşük risk seviyesidir
        else:
            # Düşük seviye döndürülür
            return RiskLevel.LOW

    def calculate_total_annual_control_cost(self) -> float:
        """Bu riske atanan kontrollerin toplam yıllık maliyetini hesaplar."""
        # Tüm kontrollerin yıllık maliyetlerinin toplamı hesaplanır
        return sum(ctrl.get_annualized_cost() for ctrl in self.applied_controls)

    def calculate_rosi(self) -> float:
        """
        Siber Güvenlik Yatırımı Getirisi (Return on Security Investment - ROSI) hesaplar.
        Formül: ROSI = [ (Inherent_ALE - Residual_ALE) - Control_Cost ] / Control_Cost * 100
        """
        # Atanan kontrollerin yıllık toplam maliyeti alınır
        cost = self.calculate_total_annual_control_cost()
        # Eğer kontrol maliyeti sıfır veya negatifse tanımsız olacağından 0.0 döndürülür
        if cost <= 0:
            # 0.0 değeri döndürülür
            return 0.0
        # Doğal yıllık kayıp beklentisi alınır
        inherent_ale = self.calculate_inherent_ale()
        # Artık yıllık kayıp beklentisi alınır
        residual_ale = self.calculate_residual_ale()
        # Önlenen risk değeri (maddi fayda) hesaplanır
        risk_mitigated = inherent_ale - residual_ale
        # Net finansal getiri hesaplanır
        net_benefit = risk_mitigated - cost
        # Yüzdelik getiri oranı hesaplanır
        return (net_benefit / cost) * 100.0


# ============================================================================
# KURUMSAL RİSK YÖNETİCİSİ (RISK ASSESSMENT MANAGER)
# ============================================================================

class RiskAssessmentManager:
    """
    Kurumsal düzeyde risk envanterini yöneten, kontrolleri eşleyen,
    risk iştahı sınırlarını denetleyen ve raporlayan ana orkestrasyon sınıfı.
    """

    def __init__(self, organization_name: str, risk_appetite_score: int = 10, max_acceptable_ale: float = 50000.0):
        """
        Risk yöneticisini kurumsal parametrelerle başlatır.
        
        Args:
            organization_name: Şirket veya kurum adı.
            risk_appetite_score: Kabul edilebilir azami nitel risk puanı eşiği (örn: 10 / 25).
            max_acceptable_ale: Kabul edilebilir azami yıllık finansal kayıp beklentisi (USD).
        """
        # Kurum adı kaydedilir
        self.organization_name = organization_name
        # Kurumsal nitel risk iştahı kaydedilir
        self.risk_appetite_score = risk_appetite_score
        # Kurumsal finansal kayıp toleransı kaydedilir
        self.max_acceptable_ale = max_acceptable_ale
        # Tanımlı güvenlik kontrolleri sözlüğü başlatılır
        self.controls_catalog: Dict[str, SecurityControl] = {}
        # Tanımlı riskler sözlüğü başlatılır
        self.risks: Dict[str, RiskItem] = {}
        # Yapılan işlemlerin denetim günlüğü listesi başlatılır
        self.audit_log: List[Dict[str, Any]] = []

    def _log_event(self, action: str, details: Dict[str, Any]) -> None:
        """Denetim izi için yapısal olay kaydeder."""
        # Güncel zaman damgasıyla olay nesnesi oluşturulur
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        # Olay listeye eklenir
        self.audit_log.append(event)

    def register_control(self, control: SecurityControl) -> None:
        """Kataloğa yeni bir güvenlik kontrolü ekler."""
        # Kontrol kimliği katalogda zaten varsa mükerrerlik hatası fırlatılır
        if control.control_id in self.controls_catalog:
            # Mükerrer kontrol hatası fırlatılır
            raise DuplicateControlError(f"Bu ID ile bir kontrol zaten mevcut: {control.control_id}")
        # Kontrol etkinlik oranı 0 ile 1 aralığında doğrulanır
        if not (0.01 <= control.effectiveness_ratio <= 0.99):
            # Geçersiz kontrol seçim hatası fırlatılır
            raise InvalidControlSelectionError(f"Kontrol etkinlik oranı 0.01 ile 0.99 arasında olmalıdır: {control.effectiveness_ratio}")
        # Kontrol kataloğa eklenir
        self.controls_catalog[control.control_id] = control
        # İşlem denetim kütüğüne kaydedilir
        self._log_event("CONTROL_REGISTERED", {"control_id": control.control_id, "name": control.name})

    def register_risk(self, risk: RiskItem) -> None:
        """Envantere yeni bir risk öğesi ekler ve doğrular."""
        # Risk kimliği mevcutsa mükerrerlik hatası fırlatılır
        if risk.risk_id in self.risks:
            # Mükerrer risk hatası fırlatılır
            raise DuplicateRiskError(f"Bu ID ile bir risk zaten mevcut: {risk.risk_id}")
        # Risk parametreleri matematiksel olarak doğrulanır
        risk.validate_inputs()
        # Risk envantere eklenir
        self.risks[risk.risk_id] = risk
        # İşlem denetim kütüğüne kaydedilir
        self._log_event("RISK_REGISTERED", {"risk_id": risk.risk_id, "title": risk.title, "asset": risk.asset_name})

    def assign_control_to_risk(self, risk_id: str, control_id: str) -> None:
        """Katalogdaki bir güvenlik kontrolünü belirli bir riske atar."""
        # Risk mevcut değilse hata fırlatılır
        if risk_id not in self.risks:
            # Risk bulunamadı hatası fırlatılır
            raise RiskEngineError(f"Risk kaydı bulunamadı: {risk_id}")
        # Kontrol katalogda yoksa hata fırlatılır
        if control_id not in self.controls_catalog:
            # Kontrol bulunamadı hatası fırlatılır
            raise InvalidControlSelectionError(f"Kontrol katalogda bulunamadı: {control_id}")
        # İlgili risk ve kontrol nesneleri alınır
        risk = self.risks[risk_id]
        control = self.controls_catalog[control_id]
        # Aynı kontrolün mükerrer atanması engellenir
        if any(c.control_id == control_id for c in risk.applied_controls):
            # Mükerrer atama hatası fırlatılır
            raise DuplicateControlError(f"Kontrol '{control_id}' zaten '{risk_id}' riskine atanmış.")
        # Kontrol riskin uygulanan kontroller listesine eklenir
        risk.applied_controls.append(control)
        # Denetim kütüğüne kaydedilir
        self._log_event("CONTROL_ASSIGNED", {"risk_id": risk_id, "control_id": control_id})

    def validate_corporate_risk_governance(self) -> Tuple[bool, List[str]]:
        """
        Tüm risk envanterini kurumsal yönetim kurallarına ve risk iştahına göre denetler (CWE-1025).
        
        Returns:
            Tuple[bool, List[str]]: Doğrulama sonucu (True/False) ve tespit edilen ihlaller listesi.
        """
        # Tespit edilen politika ihlalleri listesi başlatılır
        violations: List[str] = []
        # Envanter tamamen boşsa doğrulama yapılamaz
        if not self.risks:
            # Hata listesine eklenir
            violations.append("Risk envanteri boş, değerlendirilecek risk bulunmuyor.")
            # Başarısız olarak döndürülür
            return False, violations
        # Her bir risk öğesi tek tek denetlenir
        for r_id, risk in self.risks.items():
            # 1. Kontrol: AZALT (MITIGATE) stratejisi seçilip hiç kontrol atanmamış mı?
            if risk.treatment_strategy == RiskTreatmentStrategy.MITIGATE and not risk.applied_controls:
                # İhlal mesajı oluşturulur
                violations.append(f"Risk [{r_id}] '{risk.title}': Azaltma stratejisi seçilmiş ancak hiçbir güvenlik kontrolü atanmamış.")
            # 2. Kontrol: KABUL_ET (ACCEPT) stratejisinde risk iştahı aşıldı mı ve üst yönetim onayı var mı?
            if risk.treatment_strategy == RiskTreatmentStrategy.ACCEPT:
                # Doğal risk skoru iştah eşiğinden büyükse
                if risk.get_inherent_score() > self.risk_appetite_score:
                    # Üst yönetim onayı (executive sign-off) yoksa kabul edilemez
                    if not risk.executive_sign_off:
                        # İhlal mesajı eklenir (CWE-1025)
                        violations.append(
                            f"Risk [{r_id}] '{risk.title}': Skor ({risk.get_inherent_score()}) kurum iştahını ({self.risk_appetite_score}) aşıyor. "
                            f"Üst yönetim (C-Level) resmi onayı olmaksızın kabul edilemez."
                        )
            # 3. Kontrol: Kontroller uygulandıktan sonraki Artık Risk (Residual Risk) iştahı aşıyor mu?
            residual_score = risk.get_residual_score()
            # Eğer artık skor kabul edilebilir eşikten büyükse ve yönetim istisna onayı yoksa
            if residual_score > self.risk_appetite_score and not risk.executive_sign_off:
                # İhlal mesajı eklenir
                violations.append(
                    f"Risk [{r_id}] '{risk.title}': Uygulanan kontroller sonrası artık risk skoru ({residual_score}), "
                    f"kurum iştahını ({self.risk_appetite_score}) aşmaya devam ediyor. İlave kontrol veya kaçınma gereklidir."
                )
            # 4. Kontrol: Artık Yıllık Finansal Kayıp (Residual ALE) finansal toleransı aşıyor mu?
            residual_ale = risk.calculate_residual_ale()
            # Finansal limit aşıldıysa ve onay yoksa
            if residual_ale > self.max_acceptable_ale and not risk.executive_sign_off:
                # İhlal mesajı eklenir
                violations.append(
                    f"Risk [{r_id}] '{risk.title}': Artık yıllık kayıp beklentisi (${residual_ale:,.2f}), "
                    f"kurumsal finansal limit olan ${self.max_acceptable_ale:,.2f} tutarını aşıyor."
                )
        # Eğer ihlal varsa doğrulama başarısızdır
        is_compliant = len(violations) == 0
        # Sonuç ve ihlaller döndürülür
        return is_compliant, violations

    def enforce_readiness(self) -> None:
        """
        Yönetişim denetimini icra eder; herhangi bir kural ihlali varsa RiskAppetiteExceededError fırlatır.
        """
        # Yönetişim kuralları çalıştırılır
        passed, violations = self.validate_corporate_risk_governance()
        # Eğer kurallar geçilemediyse
        if not passed:
            # İhlaller birleştirilerek açıklayıcı hata fırlatılır (CWE-1025)
            raise RiskAppetiteExceededError(
                f"Kurumsal Risk Yönetişim İhlali ({len(violations)} adet):\n" + "\n".join(f" - {v}" for v in violations)
            )

    def generate_executive_report(self) -> str:
        """Üst yönetim ve denetçiler için detaylı Markdown formatında Risk ve Kontrol Değerlendirme Raporu üretir."""
        # Rapor satırları listesi başlatılır
        lines: List[str] = []
        # Başlık ve meta bilgiler eklenir
        lines.append(f"# {self.organization_name} — Kurumsal Risk Skorlama ve Kontrol Seçimi Raporu")
        lines.append(f"**Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Risk İştahı Eşik Skoru:** {self.risk_appetite_score} / 25")
        lines.append(f"**Maksimum Finansal Tolerans:** ${self.max_acceptable_ale:,.2f} Yıllık Kayıp")
        lines.append("")
        # Yönetici özeti tablosu başlığı
        lines.append("## 1. Risk ve Kontrol Genel Matrisi")
        lines.append("| Risk ID | Risk Başlığı | Varlık | Doğal Skor | Doğal ALE | Strateji | Kontrol Sayısı | Artık Skor | Artık ALE | Yıllık Maliyet | ROSI (%) |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        # Genel finansal toplamlar için sayaçlar başlatılır
        total_inherent_ale = 0.0
        total_residual_ale = 0.0
        total_controls_cost = 0.0
        # Her bir risk matrise eklenir
        for r_id, risk in self.risks.items():
            # Doğal değerler hesaplanır
            inh_score = risk.get_inherent_score()
            inh_ale = risk.calculate_inherent_ale()
            # Artık değerler hesaplanır
            res_score = risk.get_residual_score()
            res_ale = risk.calculate_residual_ale()
            cost = risk.calculate_total_annual_control_cost()
            rosi = risk.calculate_rosi()
            # Toplamlara eklenir
            total_inherent_ale += inh_ale
            total_residual_ale += res_ale
            total_controls_cost += cost
            # Tablo satırı biçimlendirilir
            lines.append(
                f"| {r_id} | {risk.title} | {risk.asset_name} | {inh_score} ({risk.get_inherent_level().value}) | "
                f"${inh_ale:,.0f} | {risk.treatment_strategy.value} | {len(risk.applied_controls)} | "
                f"{res_score} ({risk.get_residual_level().value}) | ${res_ale:,.0f} | ${cost:,.0f} | %{rosi:,.1f} |"
            )
        lines.append("")
        # Finansal genel toplam bölümü eklenir
        lines.append("## 2. Finansal Etki ve Siber Yatırım Getirisi (ROSI) Özeti")
        # Toplam önlenen kayıp hesaplanır
        total_mitigated = total_inherent_ale - total_residual_ale
        # Net finansal tasarruf hesaplanır
        net_savings = total_mitigated - total_controls_cost
        # Birleşik kurumsal ROSI hesaplanır
        portfolio_rosi = (net_savings / total_controls_cost * 100.0) if total_controls_cost > 0 else 0.0
        lines.append(f"- **Toplam Doğal Kayıp Beklentisi (Inherent ALE):** ${total_inherent_ale:,.2f}")
        lines.append(f"- **Kontroller Sonrası Artık Kayıp (Residual ALE):** ${total_residual_ale:,.2f}")
        lines.append(f"- **Önlenen Yıllık Finansal Kayıp:** ${total_mitigated:,.2f}")
        lines.append(f"- **Yıllık Toplam Güvenlik Kontrol Harcaması:** ${total_controls_cost:,.2f}")
        lines.append(f"- **Net Yıllık Finansal Tasarruf / Değer:** ${net_savings:,.2f}")
        lines.append(f"- **Kurumsal Güvenlik Yatırımı Getirisi (ROSI):** %{portfolio_rosi:,.2f}")
        lines.append("")
        # Yönetişim uyumluluk bölümü eklenir
        lines.append("## 3. Kurumsal Yönetişim ve Risk İştahı Uyumluluğu")
        passed, violations = self.validate_corporate_risk_governance()
        if passed:
            lines.append("> [!NOTE]\n> **UYUMLU:** Tüm riskler ve artık risk seviyeleri kurumsal risk iştahı ve finansal tolerans sınırları dahilindedir.")
        else:
            lines.append(f"> [!WARNING]\n> **RİSK İŞTAHI AŞIMI ({len(violations)} İhlal):**")
            for v in violations:
                lines.append(f"> - {v}")
        lines.append("")
        # Satırlar birleştirilip metin olarak döndürülür
        return "\n".join(lines)

    def export_summary_dict(self) -> Dict[str, Any]:
        """Tüm analizi JSON serileştirilebilir bir sözlük olarak döndürür."""
        # Sözlük yapısı kurulur
        return {
            "organization": self.organization_name,
            "risk_appetite_score": self.risk_appetite_score,
            "max_acceptable_ale": self.max_acceptable_ale,
            "total_risks_count": len(self.risks),
            "total_controls_catalog_count": len(self.controls_catalog),
            "risks": [
                {
                    "risk_id": r.risk_id,
                    "title": r.title,
                    "asset": r.asset_name,
                    "asset_value": r.asset_value,
                    "inherent_score": r.get_inherent_score(),
                    "inherent_level": r.get_inherent_level().name,
                    "inherent_ale": r.calculate_inherent_ale(),
                    "treatment_strategy": r.treatment_strategy.name,
                    "applied_controls": [c.control_id for c in r.applied_controls],
                    "residual_score": r.get_residual_score(),
                    "residual_level": r.get_residual_level().name,
                    "residual_ale": r.calculate_residual_ale(),
                    "total_control_cost": r.calculate_total_annual_control_cost(),
                    "rosi": r.calculate_rosi()
                }
                for r in self.risks.values()
            ]
        }
