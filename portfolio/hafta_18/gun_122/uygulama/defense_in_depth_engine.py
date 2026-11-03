# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 122: Savunma Derinliği (Defense-in-Depth) ve Güvenlik Kontrol Tipleri Motoru.
Bu modül; 7 katmanlı savunma mimarisini modeller (Fiziksel, Çevre, İç Ağ, Sunucu, Uygulama, Veri, Kimlik),
kontrol tiplerini (Önleyici, Tespit Edici, Düzeltici, Telafi Edici, Caydırıcı) yönetir,
saldırı zinciri simülasyonu yapar, tek hata noktalarını (CWE-1008 SPoF) ve
katman boşluklarını (CWE-653 Defense Gap) tespit eder.
"""

# Standart kütüphane enum modülü içe aktarılıyor
from enum import Enum
# Veri yapılarını tanımlamak için dataclass ve field içe aktarılıyor
from dataclasses import dataclass, field
# Tip ipuçları için gerekli tipler içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any, Set
# Zaman damgaları üretmek için datetime modülü içe aktarılıyor
from datetime import datetime
# JSON serileştirme işlemleri için json modülü içe aktarılıyor
import json


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class DefenseInDepthError(Exception):
    """Savunma derinliği motoru temel istisna sınıfı."""
    pass


class DefenseGapError(DefenseInDepthError):
    """Bir savunma katmanında hiçbir kontrol bulunmadığında fırlatılır (CWE-653)."""
    pass


class SinglePointOfFailureError(DefenseInDepthError):
    """Kritik bir saldırı vektöründe tek hata noktası (SPoF) tespit edildiğinde fırlatılır (CWE-1008)."""
    pass


class UnmonitoredLayerError(DefenseInDepthError):
    """Bir katmanda önleyici kontrol varken tespit edici (monitoring/logging) kontrol olmadığında fırlatılır."""
    pass


class DefenseInDepthBreachError(DefenseInDepthError):
    """Bir saldırı tüm savunma katmanlarını aşarak hassas veriye ulaştığında fırlatılır."""
    pass


class InvalidControlConfigurationError(DefenseInDepthError):
    """Kontrol etkinliği veya parametreleri geçersiz yapılandırıldığında fırlatılır."""
    pass


class DuplicateControlError(DefenseInDepthError):
    """Aynı kimliğe sahip mükerrer kontrol kaydedilmeye çalışıldığında fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class DefenseLayer(Enum):
    """Savunma Derinliği (Defense-in-Depth) 7 Temel Güvenlik Katmanı."""
    PHYSICAL = "1_Fiziksel_Guvenlik"                 # Veri merkezi, kamera, biyometrik kilit, çevre çiti
    PERIMETER = "2_Cevre_ve_Dis_Ag"                  # Dış Güvenlik Duvarı (Firewall), DDoS Koruması, WAF, DMZ
    INTERNAL_NETWORK = "3_Ic_Ag_ve_Segmentasyon"     # VLAN, Mikro-segmentasyon, ZTNA, İç Güvenlik Duvarı, mTLS
    HOST = "4_Uc_Nokta_ve_Sunucu"                    # EDR/XDR, Antivirüs, Host IPS, İşletim Sistemi Sıkılaştırma
    APPLICATION = "5_Uygulama_ve_API"                # API Gateway, Girdi Doğrulama, SAST/DAST, CSRF/XSS Koruması
    DATA = "6_Veri_ve_Depolama"                      # AES-256 Depolama Şifrelemesi, TLS 1.3, DLP, Veri Maskeleme
    IDENTITY = "7_Kimlik_ve_Insan"                   # IAM, MFA, Least Privilege, Farkındalık Eğitimi, PAM


class ControlType(Enum):
    """Güvenlik Kontrolünün İcra Edilme Fonksiyonu ve Niteliği."""
    PREVENTIVE = "Önleyici"                          # Saldırıyı oluşmadan önce durduran bariyer
    DETECTIVE = "Tespit Edici"                       # Saldırıyı veya anomalileri gerçek zamanlı yakalayan izleme
    CORRECTIVE = "Düzeltici"                         # Saldırı sonrası hasarı onaran, sistemi kurtaran mekanizma
    COMPENSATING = "Telafi Edici"                    # Asıl kontrolün yokluğunda riski azaltan alternatif bariyer
    DETERRENT = "Caydırıcı"                          # Hukuki uyarı, oturum açma banner'ı, caydırıcı politika


class AttackCategory(Enum):
    """Siber Saldırı Vektörleri ve Senaryoları."""
    SQL_INJECTION = "SQL Injection (Veri Tabanı İhlali)"
    RANSOMWARE = "Ransomware (Fidye Yazılımı ve Yayılma)"
    CREDENTIAL_STUFFING = "Credential Stuffing (Kaba Kuvvet ve Hesap Hırsızlığı)"
    INSIDER_THREAT = "İç Tehdit (Yetki İstismarı ve Sabotaj)"
    DATA_EXFILTRATION = "Hassas Veri Sızıntısı (Ağ Üzerinden Veri Çıkarma)"


@dataclass
class LayerControl:
    """Savunma derinliği katmanına konuşlandırılan güvenlik kontrolü modeli."""
    control_id: str                      # Benzersiz kontrol kimliği (örn: 'CTRL-WAF-01')
    name: str                            # Kontrol adı
    layer: DefenseLayer                  # Yer aldığı savunma katmanı
    control_type: ControlType            # Kontrol fonksiyon tipi
    effectiveness: float                 # Engelleme veya tespit etkinliği oranı (0.01 - 0.99)
    supported_attacks: List[AttackCategory] = field(default_factory=list) # Mücadele ettiği saldırı tipleri
    is_active: bool = True               # Kontrolün aktif çalışma durumu

    def validate(self) -> None:
        """Kontrol parametrelerinin doğruluğunu denetler."""
        # Etkinlik oranı 0.01 ile 0.99 arasında olmalıdır
        if not (0.01 <= self.effectiveness <= 0.99):
            # Geçersiz kontrol yapılandırma hatası fırlatılır
            raise InvalidControlConfigurationError(
                f"Kontrol etkinliği 0.01 ile 0.99 arasında olmalıdır. Verilen: {self.effectiveness}"
            )
        # Kontrol adı boş olamaz
        if not self.name or not self.name.strip():
            # Geçersiz isim hatası fırlatılır
            raise InvalidControlConfigurationError("Kontrol adı boş bırakılamaz.")


@dataclass
class AttackStep:
    """Bir saldırı zincirinin (Kill Chain) belirli bir katmanı hedef alan adımı."""
    step_number: int                     # Adım numarası
    target_layer: DefenseLayer           # Hedef alınan savunma katmanı
    technique: str                       # Kullanılan teknik / sömürü yöntemi
    evasion_power: float                 # Saldırganın kontrol atlatma yeteneği (0.0 - 1.0)


@dataclass
class AttackScenario:
    """Uçtan uca modellenmiş saldırı senaryosu modeli."""
    scenario_id: str                     # Senaryo kimliği (örn: 'SCN-RANSOM-01')
    name: str                            # Senaryo başlığı
    category: AttackCategory             # Saldırı sınıfı
    steps: List[AttackStep]              # Katman katman saldırı adımları


@dataclass
class LayerSimulationResult:
    """Saldırının tek bir savunma katmanındaki simülasyon çıktısı."""
    layer: DefenseLayer                  # Değerlendirilen katman
    prevented: bool = False              # Saldırı bu katmanda önlendi mi?
    prevented_by_control: Optional[str] = None # Önleyen kontrol adı
    detected: bool = False               # Saldırı bu katmanda tespit edildi mi?
    detected_by_control: Optional[str] = None # Tespit eden kontrol adı
    corrected: bool = False              # Düzeltici aksiyon tetiklendi mi?
    corrected_by_control: Optional[str] = None # Düzeltici kontrol adı
    penetrated: bool = False             # Saldırgan bu katmanı delip geçti mi?
    log_messages: List[str] = field(default_factory=list) # Denetim kayıtları


@dataclass
class AttackSimulationOutcome:
    """Tüm saldırı zincirinin simülasyon nihai neticesi."""
    scenario_id: str                     # Senaryo kimliği
    stopped: bool                        # Saldırı durduruldu mu?
    stopped_at_layer: Optional[DefenseLayer] # Saldırının püskürtüldüğü katman
    total_layers_penetrated: int         # Saldırganın delebildiği toplam katman sayısı
    data_compromised: bool               # Nihai veri katmanı ihlal edildi mi?
    layer_results: List[LayerSimulationResult] = field(default_factory=list)


# ============================================================================
# SAVUNMA DERİNLİĞİ YÖNETİCİSİ (DEFENSE IN DEPTH MANAGER)
# ============================================================================

class DefenseInDepthManager:
    """
    7 katmanlı savunma mimarisini yöneten, kontrolleri denetleyen,
    saldırı zincirlerini koşturan ve katman dayanıklılığını doğrulayan ana motor.
    """

    def __init__(self, architecture_name: str):
        """Yöneticiyi mimari adı ile başlatır."""
        # Mimari adı saklanır
        self.architecture_name = architecture_name
        # Katman bazında kontroller haritası başlatılır
        self.controls_by_layer: Dict[DefenseLayer, List[LayerControl]] = {layer: [] for layer in DefenseLayer}
        # Benzersiz kontrol kimlikleri kümesi
        self.control_ids: Set[str] = set()
        # Kayıtlı saldırı senaryoları sözlüğü
        self.scenarios: Dict[str, AttackScenario] = {}
        # Olay günlüğü listesi
        self.audit_log: List[Dict[str, Any]] = []

    def _log_event(self, action: str, details: Dict[str, Any]) -> None:
        """Yapısal olay kaydı oluşturur."""
        # Olay nesnesi hazırlanır
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        # Listeye eklenir
        self.audit_log.append(event)

    def add_control(self, control: LayerControl) -> None:
        """Belirli bir katmana yeni güvenlik kontrolü ekler."""
        # Kontrol geçerliliği denetlenir
        control.validate()
        # Kontrol kimliği mükerrer mi denetlenir
        if control.control_id in self.control_ids:
            # Mükerrer kontrol hatası fırlatılır
            raise DuplicateControlError(f"Bu ID ile bir kontrol zaten mevcut: {control.control_id}")
        # Kontrol listeye eklenir
        self.controls_by_layer[control.layer].append(control)
        # ID kümesine dahil edilir
        self.control_ids.add(control.control_id)
        # Olay kaydedilir
        self._log_event("CONTROL_ADDED", {"control_id": control.control_id, "layer": control.layer.value})

    def add_scenario(self, scenario: AttackScenario) -> None:
        """Yeni bir saldırı simülasyon senaryosu kaydeder."""
        # Senaryo sözlüğe kaydedilir
        self.scenarios[scenario.scenario_id] = scenario
        # Olay kaydedilir
        self._log_event("SCENARIO_ADDED", {"scenario_id": scenario.scenario_id, "name": scenario.name})

    def audit_architecture_resilience(self) -> Tuple[bool, List[str]]:
        """
        Mimariyi katman boşlukları (CWE-653), tek hata noktaları (CWE-1008)
        ve gözetimsiz katmanlar açısından denetler.
        
        Returns:
            Tuple[bool, List[str]]: Uyum durumu ve tespit edilen zaafiyetlerin listesi.
        """
        # Zaafiyet listesi başlatılır
        flaws: List[str] = []
        # Her bir savunma katmanı taranır
        for layer in DefenseLayer:
            # Katmandaki aktif kontroller alınır
            active_ctrls = [c for c in self.controls_by_layer[layer] if c.is_active]
            # 1. KONTROL: Katman Boşluğu (CWE-653) — Katmanda hiç kontrol yok mu?
            if not active_ctrls:
                # Katman boşluğu zaafiyeti eklenir
                flaws.append(f"KATMAN BOŞLUĞU (CWE-653): '{layer.value}' katmanında hiçbir aktif güvenlik kontrolü bulunmuyor!")
                continue
            # Katmandaki kontrol tipleri ayrıştırılır
            preventive = [c for c in active_ctrls if c.control_type == ControlType.PREVENTIVE]
            detective = [c for c in active_ctrls if c.control_type == ControlType.DETECTIVE]
            # 2. KONTROL: Gözetimsiz Katman (Blind Spot) — Önleyici var ama Tespit Edici yok
            if preventive and not detective:
                # Gözetimsiz katman uyarısı eklenir
                flaws.append(
                    f"GÖZETİMSİZ KATMAN (Blind Spot): '{layer.value}' katmanında önleyici kontrol mevcut ancak izleme/tespit edici (Detective) kontrol yok!"
                )
            # 3. KONTROL: Önleyici Bariyer Eksikliği — Sadece tespit edici var ama önleme yok
            if not preventive and detective:
                # Pasif katman uyarısı eklenir
                flaws.append(
                    f"PASİF KATMAN: '{layer.value}' katmanında yalnızca tespit edici kontroller var, saldırıyı durduracak önleyici bariyer bulunmuyor."
                )
        # 4. KONTROL: Kritik Saldırı Vektörleri için Tek Hata Noktası (CWE-1008 SPoF) Denetimi
        for cat in AttackCategory:
            # Bu saldırı kategorisini destekleyen tüm aktif önleyici kontroller toplanır
            protecting_ctrls = [
                c for layer in DefenseLayer
                for c in self.controls_by_layer[layer]
                if c.is_active and c.control_type == ControlType.PREVENTIVE and cat in c.supported_attacks
            ]
            # Eğer bu saldırıya karşı toplamda sadece 1 adet önleyici kontrol varsa SPoF riskidir
            if len(protecting_ctrls) == 1:
                # Tek hata noktası uyarısı eklenir
                ctrl = protecting_ctrls[0]
                flaws.append(
                    f"TEK HATA NOKTASI / SPoF (CWE-1008): '{cat.value}' saldırısına karşı tüm mimaride yalnızca 1 önleyici kontrol ('{ctrl.name}') mevcut! O aşılırsa savunma çöker."
                )
            # Eğer hiç önleyici kontrol yoksa kritik zaafiyettir
            elif len(protecting_ctrls) == 0:
                # Savunmasız saldırı vektörü eklenir
                flaws.append(
                    f"SAVUNMASIZ VEKTÖR (CWE-653): '{cat.value}' saldırısına karşı mimaride hiçbir aktif önleyici kontrol tanımlanmamış!"
                )
        # Zaafiyet yoksa mimari dayanıklıdır
        is_resilient = len(flaws) == 0
        # Netice döndürülür
        return is_resilient, flaws

    def enforce_resilience(self) -> None:
        """
        Mimari denetimini çalıştırır; katman boşluğu veya SPoF varsa uygun istisnayı fırlatır.
        """
        # Mimari denetlenir
        passed, flaws = self.audit_architecture_resilience()
        # Eğer mimaride zaafiyet varsa
        if not passed:
            # Katman boşluğu varsa DefenseGapError fırlatılır
            if any("KATMAN BOŞLUĞU" in f for f in flaws):
                raise DefenseGapError(f"Mimari Katman Boşluğu İhlali (CWE-653):\n" + "\n".join(flaws))
            # Tek hata noktası varsa SinglePointOfFailureError fırlatılır
            if any("TEK HATA NOKTASI" in f for f in flaws):
                raise SinglePointOfFailureError(f"Tek Hata Noktası İhlali (CWE-1008):\n" + "\n".join(flaws))
            # Gözetimsiz katman varsa UnmonitoredLayerError fırlatılır
            if any("GÖZETİMSİZ KATMAN" in f for f in flaws):
                raise UnmonitoredLayerError(f"Gözetimsiz Katman İhlali:\n" + "\n".join(flaws))
            # Diğer genel zaafiyetler için temel hata fırlatılır
            raise DefenseInDepthError(f"Savunma Derinliği Politikası İhlali:\n" + "\n".join(flaws))

    def simulate_attack(self, scenario_id: str) -> AttackSimulationOutcome:
        """
        Belirtilen saldırı senaryosunu çok katmanlı savunma mimarisi üzerinde simüle eder.
        
        Args:
            scenario_id: Çalıştırılacak kayıtlı senaryo kimliği.
            
        Returns:
            AttackSimulationOutcome: Simülasyon detayları, durdurulma katmanı ve delinme durumu.
        """
        # Senaryo kontrol edilir
        if scenario_id not in self.scenarios:
            # Senaryo bulunamadı hatası fırlatılır
            raise DefenseInDepthError(f"Saldırı senaryosu bulunamadı: {scenario_id}")
        # Senaryo nesnesi alınır
        scenario = self.scenarios[scenario_id]
        # Katman simülasyon sonuçları listesi başlatılır
        layer_results: List[LayerSimulationResult] = []
        # Saldırganın başarıyla delip geçtiği katman sayısı
        penetrated_layers_count = 0
        # Saldırı durduruldu mu bayrağı
        attack_stopped = False
        # Saldırının durdurulduğu katman
        stopped_layer: Optional[DefenseLayer] = None
        # Hassas veri katmanı ihlal edildi mi bayrağı
        data_breached = False

        # Senaryodaki her bir adım sırayla simüle edilir
        for step in scenario.steps:
            # Hedef katman belirlenir
            target = step.target_layer
            # Katmandaki aktif kontroller alınır
            controls = [c for c in self.controls_by_layer[target] if c.is_active]
            # Katman sonuç nesnesi oluşturulur
            res = LayerSimulationResult(layer=target)

            # 1. Aşama: Tespit Kontrolleri (Detective)
            detectives = [c for c in controls if c.control_type == ControlType.DETECTIVE]
            for d in detectives:
                # Tespit etkinliği saldırganın atlatma yeteneğinden yüksekse alarm üretilir
                if d.effectiveness >= (step.evasion_power * 0.8):
                    res.detected = True
                    res.detected_by_control = d.name
                    res.log_messages.append(f"[ALARM] '{d.name}' kontrolü şüpheli saldırıyı tespit etti ({step.technique}).")
                    break

            # 2. Aşama: Önleyici Kontroller (Preventive)
            preventives = [c for c in controls if c.control_type in (ControlType.PREVENTIVE, ControlType.COMPENSATING)]
            layer_prevented = False
            for p in preventives:
                # Eğer kontrol bu saldırı kategorisini destekliyorsa ve etkinliği atlatma gücünü aşıyorsa
                if (scenario.category in p.supported_attacks) and (p.effectiveness > step.evasion_power):
                    layer_prevented = True
                    res.prevented = True
                    res.prevented_by_control = p.name
                    res.log_messages.append(f"[ENGELLEME] '{p.name}' kontrolü saldırıyı başarıyla bloke etti.")
                    break

            # 3. Aşama: Düzeltici Kontroller (Corrective)
            correctives = [c for c in controls if c.control_type == ControlType.CORRECTIVE]
            if layer_prevented and correctives:
                corr = correctives[0]
                res.corrected = True
                res.corrected_by_control = corr.name
                res.log_messages.append(f"[DÜZELTME] '{corr.name}' kontrolü sistem durumunu normale döndürdü.")

            # Katman sonucu netleştirilir
            if layer_prevented:
                # Saldırı bu katmanda püskürtüldü
                res.penetrated = False
                attack_stopped = True
                stopped_layer = target
                layer_results.append(res)
                # Saldırı zinciri kırıldı, sonraki adımlara geçilemez
                break
            else:
                # Saldırgan bu katmanı deldi geçti
                res.penetrated = True
                penetrated_layers_count += 1
                res.log_messages.append(f"[UYARI] '{target.value}' katmanı saldırgan tarafından delindi!")
                layer_results.append(res)
                # Eğer ihlal edilen katman VERİ katmanı ise veri sızdırılmıştır
                if target == DefenseLayer.DATA:
                    data_breached = True

        # Nihai netice nesnesi oluşturulur
        outcome = AttackSimulationOutcome(
            scenario_id=scenario.scenario_id,
            stopped=attack_stopped,
            stopped_at_layer=stopped_layer,
            total_layers_penetrated=penetrated_layers_count,
            data_compromised=data_breached,
            layer_results=layer_results
        )
        # Denetim izi kaydedilir
        self._log_event(
            "SIMULATION_COMPLETED",
            {
                "scenario_id": scenario.scenario_id,
                "stopped": attack_stopped,
                "stopped_layer": stopped_layer.value if stopped_layer else None,
                "data_breached": data_breached
            }
        )
        # Netice döndürülür
        return outcome

    def generate_defense_matrix_report(self) -> str:
        """Mimari için Markdown formatında detaylı Savunma Derinliği Raporu üretir."""
        # Rapor satırları listesi başlatılır
        lines: List[str] = []
        lines.append(f"# {self.architecture_name} — Savunma Derinliği ve Kontrol Tipleri Raporu")
        lines.append(f"**Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        # Katman bazlı envanter tablosu
        lines.append("## 1. Katman Bazlı Güvenlik Kontrol Matrisi")
        lines.append("| Katman No ve Adı | Kontrol ID | Kontrol Adı | Kontrol Tipi | Etkinlik | Desteklenen Saldırılar | Durum |")
        lines.append("|---|---|---|---|---|---|---|")
        for layer in DefenseLayer:
            ctrls = self.controls_by_layer[layer]
            if not ctrls:
                lines.append(f"| **{layer.value}** | - | *(HİÇBİR KONTROL YOK - KATMAN BOŞLUĞU)* | - | - | - | ❌ BOŞ |")
            else:
                for c in ctrls:
                    attacks_str = ", ".join(a.name for a in c.supported_attacks) if c.supported_attacks else "Genel"
                    status_str = "✅ Aktif" if c.is_active else "⏸️ Pasif"
                    lines.append(
                        f"| {layer.value} | {c.control_id} | {c.name} | {c.control_type.value} | %{c.effectiveness*100:.0f} | {attacks_str} | {status_str} |"
                    )
        lines.append("")
        # Mimari dayanıklılık analizi
        lines.append("## 2. Mimari Dayanıklılık ve Boşluk Analizi")
        passed, flaws = self.audit_architecture_resilience()
        if passed:
            lines.append("> [!NOTE]\n> **MİMARİ SAĞLAM:** 7 katmanda da gerekli önleyici ve tespit edici kontroller mevcuttur. Tek hata noktası (SPoF) tespit edilmemiştir.")
        else:
            lines.append(f"> [!WARNING]\n> **MİMARİ ZAAFİYETLER TESPİT EDİLDİ ({len(flaws)} Adet):**")
            for flaw in flaws:
                lines.append(f"> - {flaw}")
        lines.append("")
        # Kayıtlı senaryolar özeti
        lines.append("## 3. Modellenen Saldırı Senaryoları")
        lines.append("| Senaryo ID | Senaryo Adı | Saldırı Kategorisi | Hedef Katman Sayısı |")
        lines.append("|---|---|---|---|")
        for s_id, sc in self.scenarios.items():
            lines.append(f"| {s_id} | {sc.name} | {sc.category.value} | {len(sc.steps)} |")
        lines.append("")
        # Metin birleştirilip döndürülür
        return "\n".join(lines)

    def export_summary_dict(self) -> Dict[str, Any]:
        """Tüm mimariyi JSON sözlük formatında dışa aktarır."""
        return {
            "architecture_name": self.architecture_name,
            "total_controls_count": len(self.control_ids),
            "layers": {
                layer.name: [
                    {
                        "control_id": c.control_id,
                        "name": c.name,
                        "control_type": c.control_type.name,
                        "effectiveness": c.effectiveness,
                        "is_active": c.is_active
                    }
                    for c in self.controls_by_layer[layer]
                ]
                for layer in DefenseLayer
            },
            "total_scenarios_count": len(self.scenarios)
        }
