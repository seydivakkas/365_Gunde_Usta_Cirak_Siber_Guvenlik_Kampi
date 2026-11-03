# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 18 / Gün 120: STRIDE Tehdit Modelleme ve DREAD Risk Değerlendirme Motoru.
(Microsoft STRIDE & Loren Kohnfelder / Praerit Garg / Adam Shostack Metodolojisi).

Bu modül; Veri Akış Diyagramı (DFD) modelleme, güven sınırları (Trust Boundaries) geçiş analizi,
STRIDE kategorilerine göre otomatik tehdit türetimi, DREAD risk puanlaması ve
güvenlik tedbiri (Mitigation) doğrulamasını saf Python kütüphanesi ile sunar.
"""

# JSON yapılandırma ve model dışa aktarma işlemleri için json modülü
import json
# Zaman damgaları ve rapor tarihleri için datetime modülü
import datetime
# Benzersiz takip kimlikleri üretimi için uuid modülü
import uuid
# Numaralandırma (Enum) tanımları için enum modülü
from enum import Enum
# Veri yapılarını tip güvenli tanımlamak için dataclass
from dataclasses import dataclass, field
# Tip ipuçları ve statik analiz desteği için typing modülü
from typing import Dict, List, Set, Optional, Any, Tuple


# ==============================================================================
# 1. GÜVENLİK İSTİSNALARI HİYERARŞİSİ (CWE MAPPING)
# ==============================================================================

class STRIDEModelingSecurityError(Exception):
    """STRIDE tehdit modelleme altyapısı temel güvenlik istisnası."""
    pass


class UnmitigatedThreatSecurityError(STRIDEModelingSecurityError):
    """CWE-1025: Yüksek veya kritik riskli bir tehdidin tedbirsiz (unmitigated) kalması."""
    pass


class InvalidDREADScoreError(STRIDEModelingSecurityError):
    """CWE-20: DREAD risk puanlarının geçerli aralık (1-10) dışında olması durumu."""
    pass


class UndefinedTrustBoundaryCrossingError(STRIDEModelingSecurityError):
    """CWE-284: Güven sınırı aşan akışta uç noktaların tanımlı olmaması durumu."""
    pass


class MissingDataFlowEndpointError(STRIDEModelingSecurityError):
    """CWE-20: Veri akışında kaynak veya hedef elemanın modelde bulunamaması."""
    pass


class IncompleteThreatCoverageError(STRIDEModelingSecurityError):
    """CWE-1025: DFD eleman türünün zorunlu STRIDE kategorilerinin eksik incelenmesi."""
    pass


# ==============================================================================
# 2. NUMARALANDIRMALAR VE VERİ MODELLERİ
# ==============================================================================

class ElementType(str, Enum):
    """DFD (Data Flow Diagram) standart eleman türleri."""
    # Dış Varlık: Kullanıcı, tarayıcı, harici üçüncü parti API (Tehditler: S, R)
    EXTERNAL_ENTITY = "EXTERNAL_ENTITY"
    # Süreç: Web sunucusu, arka uç API servisi, mikroservis (Tehditler: S, T, R, I, D, E)
    PROCESS = "PROCESS"
    # Veri Deposu: Veritabanı, dosya sistemi, bellek içi önbellek (Tehditler: T, R, I, D)
    DATA_STORE = "DATA_STORE"
    # Veri Akışı: Ağ bağlantısı, RPC, REST çağrısı, mesaj kuyruğu (Tehditler: T, I, D)
    DATA_FLOW = "DATA_FLOW"


class STRIDECategory(str, Enum):
    """STRIDE tehdit kategorileri ve tehdit edilen güvenlik özellikleri."""
    # S - Spoofing (Kimlik Sahteciliği) -> Tehdit Ettiği Hedef: Kimlik Doğrulama (Authenticity)
    SPOOFING = "SPOOFING"
    # T - Tampering (Veri Tahrifatı) -> Tehdit Ettiği Hedef: Bütünlük (Integrity)
    TAMPERING = "TAMPERING"
    # R - Repudiation (İnkar Edilebilirlik) -> Tehdit Ettiği Hedef: İnkar Edilemezlik (Non-Repudiation)
    REPUDIATION = "REPUDIATION"
    # I - Information Disclosure (Bilgi İfşası) -> Tehdit Ettiği Hedef: Gizlilik (Confidentiality)
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    # D - Denial of Service (Hizmet Engelleme) -> Tehdit Ettiği Hedef: Erişilebilirlik (Availability)
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    # E - Elevation of Privilege (Ayrıcalık Yükseltme) -> Tehdit Ettiği Hedef: Yetkilendirme (Authorization)
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"


# Her DFD eleman türüne standart olarak uygulanabilir STRIDE tehdit kümesi eşleşmesi
DFD_STRIDE_MATRIX: Dict[ElementType, Set[STRIDECategory]] = {
    ElementType.EXTERNAL_ENTITY: {STRIDECategory.SPOOFING, STRIDECategory.REPUDIATION},
    ElementType.PROCESS: {
        STRIDECategory.SPOOFING,
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
        STRIDECategory.ELEVATION_OF_PRIVILEGE,
    },
    ElementType.DATA_STORE: {
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    },
    ElementType.DATA_FLOW: {
        STRIDECategory.TAMPERING,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    },
}


@dataclass
class DREADScore:
    """
    Microsoft DREAD Risk Değerlendirme Modeli (Her metrik 1 ile 10 arası puanlanır).
    - Damage (Hasar Potansiyeli): Saldırı başarılı olursa verilecek zarar.
    - Reproducibility (Tekrarlanabilirlik): Saldırının kolayca yinelenme durumu.
    - Exploitability (İstismar Edilebilirlik): Saldırı için gereken teknik zorluk derecesi.
    - Affected Users (Etkilenen Kullanıcı Oranı): Kapsanan kullanıcı yüzdesi.
    - Discoverability (Keşfedilebilirlik): Açığın saldırganlarca bulunma kolaylığı.
    """
    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int

    def __post_init__(self):
        """Metriklerin 1 ile 10 arasında olduğunu doğrular."""
        for name, val in [
            ("damage", self.damage),
            ("reproducibility", self.reproducibility),
            ("exploitability", self.exploitability),
            ("affected_users", self.affected_users),
            ("discoverability", self.discoverability)
        ]:
            if not isinstance(val, int) or val < 1 or val > 10:
                raise InvalidDREADScoreError(f"DREAD puanı '{name}' 1 ile 10 arasında tam sayı olmalıdır (Verilen: {val}).")

    def calculate_risk_score(self) -> float:
        """DREAD aritmetik ortalamasını (1.0 - 10.0) hesaplar."""
        return (self.damage + self.reproducibility + self.exploitability + self.affected_users + self.discoverability) / 5.0

    def get_severity(self) -> str:
        """Risk puanına göre ciddiyet derecesini döner."""
        score = self.calculate_risk_score()
        if score >= 8.5:
            return "CRITICAL"
        elif score >= 6.5:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class DFDElement:
    """Veri Akış Diyagramı (DFD) temel mimari bileşeni."""
    element_id: str
    name: str
    element_type: ElementType
    trust_zone: str # Bulunduğu güven bölgesi (örn: 'Internet', 'DMZ', 'Intranet', 'Secure_Core')


@dataclass
class DFDDataFlow:
    """İki DFD bileşeni arasındaki veri akışı."""
    flow_id: str
    name: str
    source_element_id: str
    target_element_id: str
    protocol: str # İletişim protokolü (örn: 'HTTP', 'HTTPS/TLS1.3', 'gRPC', 'SQL')
    crosses_trust_boundary: bool = False


@dataclass
class ThreatRecord:
    """STRIDE analiziyle saptanan yapılandırılmış tehdit kaydı."""
    threat_id: str
    element_id: str
    element_name: str
    element_type: ElementType
    category: STRIDECategory
    title: str
    description: str
    cwe_mapping: str
    dread: DREADScore
    mitigations: List[str] = field(default_factory=list)
    is_mitigated: bool = False


# ==============================================================================
# 3. STRIDE TEHDİT MODELLEME VE ANALİZ MOTORU
# ==============================================================================

class STRIDEThreatEngine:
    """
    Microsoft STRIDE Standartlarına Uyumlu Tehdit Modelleme ve
    DREAD Risk Analiz Motoru.
    """

    # STRIDE Kategorilerinin CWE karşılıkları
    CWE_MAP: Dict[STRIDECategory, str] = {
        STRIDECategory.SPOOFING: "CWE-290: Authentication Bypass by Spoofing",
        STRIDECategory.TAMPERING: "CWE-353: Missing Support for Integrity Check",
        STRIDECategory.REPUDIATION: "CWE-778: Insufficient Logging and Non-repudiation",
        STRIDECategory.INFORMATION_DISCLOSURE: "CWE-200: Exposure of Sensitive Information",
        STRIDECategory.DENIAL_OF_SERVICE: "CWE-400: Uncontrolled Resource Consumption",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "CWE-250: Execution with Unnecessary Privileges"
    }

    # Standart önerilen güvenlik tedbirleri (Mitigations)
    DEFAULT_MITIGATIONS: Dict[STRIDECategory, List[str]] = {
        STRIDECategory.SPOOFING: ["X.509 Karşılıklı TLS (mTLS)", "FIDO2 / WebAuthn MFA", "JWT Dijital İmza Doğrulaması"],
        STRIDECategory.TAMPERING: ["HMAC-SHA256 Mesaj Bütünlük Kontrolü", "Dijital İmza", "TLS 1.3 Taşıma Güvenliği"],
        STRIDECategory.REPUDIATION: ["Zaman Damgalı İmzalı Denetim Kütüğü (Audit Log)", "WORM (Write Once Read Many) Depo"],
        STRIDECategory.INFORMATION_DISCLOSURE: ["AES-256-GCM Veri Şifreleme", "TLS Taşıma Şifrelemesi", "Maskeleme ve Tokenizasyon"],
        STRIDECategory.DENIAL_OF_SERVICE: ["Token Bucket Hız Sınırlama (Rate Limiting)", "Kaynak Kotası ve Zaman Aşımı (Timeout)"],
        STRIDECategory.ELEVATION_OF_PRIVILEGE: ["NIST RBAC & ABAC Yetkilendirme Kapısı", "En Az Ayrıcalık (PoLP) ve JIT"]
    }

    def __init__(self, system_name: str = "Enterprise Architecture"):
        self.system_name = system_name
        # DFD Elemanları: element_id -> DFDElement
        self.elements: Dict[str, DFDElement] = {}
        # Veri Akışları: flow_id -> DFDDataFlow
        self.data_flows: Dict[str, DFDDataFlow] = {}
        # Türetilen Tehditler: threat_id -> ThreatRecord
        self.threats: Dict[str, ThreatRecord] = {}
        # Denetim izi günlüğü
        self.audit_log: List[Dict[str, Any]] = []

    def add_element(self, element_id: str, name: str, element_type: ElementType, trust_zone: str) -> DFDElement:
        """Sisteme yeni bir DFD bileşeni kaydeder."""
        elem = DFDElement(element_id=element_id, name=name, element_type=element_type, trust_zone=trust_zone)
        self.elements[element_id] = elem
        self._log_audit("ELEMENT_ADDED", {"id": element_id, "name": name, "type": element_type.value})
        return elem

    def add_data_flow(
        self,
        flow_id: str,
        name: str,
        source_id: str,
        target_id: str,
        protocol: str,
        crosses_boundary: Optional[bool] = None
    ) -> DFDDataFlow:
        """
        İki bileşen arasına veri akışı ekler.
        Kaynak veya hedef tanımlı değilse hata fırlatır (CWE-20).
        """
        if source_id not in self.elements:
            raise MissingDataFlowEndpointError(f"Veri akışı kaynağı bulunamadı: {source_id}")
        if target_id not in self.elements:
            raise MissingDataFlowEndpointError(f"Veri akışı hedefi bulunamadı: {target_id}")

        src_zone = self.elements[source_id].trust_zone
        tgt_zone = self.elements[target_id].trust_zone

        # Güven sınırı aşımı otomatik tespit edilir (Farklı güven bölgeleri arası)
        is_crossing = (src_zone != tgt_zone) if crosses_boundary is None else crosses_boundary

        flow = DFDDataFlow(
            flow_id=flow_id,
            name=name,
            source_element_id=source_id,
            target_element_id=target_id,
            protocol=protocol,
            crosses_trust_boundary=is_crossing
        )
        self.data_flows[flow_id] = flow
        self._log_audit("FLOW_ADDED", {"id": flow_id, "source": source_id, "target": target_id, "boundary_cross": is_crossing})
        return flow

    def generate_threats_for_element(
        self,
        element_id: str,
        default_dread: Optional[DREADScore] = None
    ) -> List[ThreatRecord]:
        """
        Belirtilen DFD elemanı için eleman türünün zorunlu kıldığı
        tüm STRIDE kategorilerini otomatik türetir.
        """
        if element_id not in self.elements:
            raise MissingDataFlowEndpointError(f"Eleman bulunamadı: {element_id}")

        elem = self.elements[element_id]
        applicable_categories = DFD_STRIDE_MATRIX.get(elem.element_type, set())
        generated: List[ThreatRecord] = []

        dread_base = default_dread or DREADScore(damage=7, reproducibility=7, exploitability=6, affected_users=8, discoverability=6)

        for cat in sorted(applicable_categories, key=lambda x: x.value):
            threat_id = f"THREAT-{elem.element_id}-{cat.name[:3]}"
            title = f"{cat.value} Tehdidi — {elem.name}"
            desc = (
                f"{elem.name} ({elem.element_type.value}) bileşeni üzerinde "
                f"{cat.value} kategorisinde olası siber saldırı riski."
            )
            cwe = self.CWE_MAP[cat]

            rec = ThreatRecord(
                threat_id=threat_id,
                element_id=elem.element_id,
                element_name=elem.name,
                element_type=elem.element_type,
                category=cat,
                title=title,
                description=desc,
                cwe_mapping=cwe,
                dread=dread_base,
                mitigations=[],
                is_mitigated=False
            )
            self.threats[threat_id] = rec
            generated.append(rec)

        self._log_audit("THREATS_GENERATED", {"element_id": element_id, "threat_count": len(generated)})
        return generated

    def analyze_trust_boundary_flows(self) -> List[ThreatRecord]:
        """Güven sınırı aşan (Trust Boundary Crossing) tüm veri akışları için STRIDE tehditleri türetir."""
        boundary_threats: List[ThreatRecord] = []

        for flow in self.data_flows.values():
            if flow.crosses_trust_boundary:
                # Veri akışları T, I, D tehditlerine açıktır
                for cat in [STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.DENIAL_OF_SERVICE]:
                    t_id = f"THREAT-FLOW-{flow.flow_id}-{cat.name[:3]}"
                    # Sınır aşımında risk daha yüksektir
                    dread = DREADScore(damage=8, reproducibility=8, exploitability=7, affected_users=9, discoverability=7)
                    title = f"Güven Sınırı Aşımı {cat.value} — {flow.name}"
                    desc = (
                        f"'{flow.name}' akışı farklı güven bölgeleri arasında "
                        f"({flow.protocol}) iletim yaparken {cat.value} riskine maruz kalmaktadır."
                    )
                    cwe = self.CWE_MAP[cat]

                    rec = ThreatRecord(
                        threat_id=t_id,
                        element_id=flow.flow_id,
                        element_name=flow.name,
                        element_type=ElementType.DATA_FLOW,
                        category=cat,
                        title=title,
                        description=desc,
                        cwe_mapping=cwe,
                        dread=dread,
                        mitigations=[],
                        is_mitigated=False
                    )
                    self.threats[t_id] = rec
                    boundary_threats.append(rec)

        return boundary_threats

    def apply_mitigation(self, threat_id: str, mitigation_description: str, residual_dread: Optional[DREADScore] = None) -> None:
        """Tehdide güvenlik tedbiri uygular ve artık risk (residual risk) puanını günceller."""
        if threat_id not in self.threats:
            raise STRIDEModelingSecurityError(f"Tehdit kaydı bulunamadı: {threat_id}")

        threat = self.threats[threat_id]
        threat.mitigations.append(mitigation_description)
        threat.is_mitigated = True

        # Eğer tedbir sonrası yeni DREAD skoru verilmişse güncellenir
        if residual_dread:
            threat.dread = residual_dread
        else:
            # Varsayılan olarak tedbir uygulandığında hasar ve istismar puanı düşürülür
            threat.dread = DREADScore(
                damage=max(1, threat.dread.damage - 4),
                reproducibility=max(1, threat.dread.reproducibility - 4),
                exploitability=max(1, threat.dread.exploitability - 4),
                affected_users=max(1, threat.dread.affected_users - 3),
                discoverability=max(1, threat.dread.discoverability - 3)
            )

        self._log_audit("MITIGATION_APPLIED", {"threat_id": threat_id, "mitigation": mitigation_description, "new_score": threat.dread.calculate_risk_score()})

    def validate_security_readiness(self) -> Tuple[bool, List[str]]:
        """
        Sistemin canlıya geçiş (Production Readiness) güvenlik denetimini yapar.
        Yüksek veya kritik seviyede tedbirsiz (unmitigated) tehdit varsa
        UnmitigatedThreatSecurityError fırlatır (CWE-1025).
        """
        unmitigated_critical: List[str] = []

        for threat in self.threats.values():
            severity = threat.dread.get_severity()
            if not threat.is_mitigated and severity in ("HIGH", "CRITICAL"):
                unmitigated_critical.append(
                    f"[{threat.threat_id}] {threat.title} (Risk: {severity}, Skor: {threat.dread.calculate_risk_score():.1f}) tedbirsiz bırakılmıştır!"
                )

        if unmitigated_critical:
            raise UnmitigatedThreatSecurityError(
                f"Kritik Güvenlik Tedbiri Eksikliği (CWE-1025): Toplam {len(unmitigated_critical)} "
                f"yüksek/kritik tehdit çözülmemiştir:\n" + "\n".join(unmitigated_critical)
            )

        return True, ["Tüm yüksek ve kritik tehditler için onaylı güvenlik tedbirleri (Mitigations) uygulanmıştır."]

    def export_threat_report_markdown(self) -> str:
        """STRIDE Tehdit Analiz Raporunu Markdown formatında üretir."""
        lines = [
            f"# {self.system_name} — STRIDE Tehdit Modelleme Raporu",
            f"**Tarih:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Toplam DFD Elemanı:** {len(self.elements)} | **Veri Akışı:** {len(self.data_flows)} | **Saptanan Tehdit:** {len(self.threats)}",
            "",
            "## Tehdit Envanteri ve DREAD Risk Karnesi",
            "",
            "| Tehdit ID | Kategori | Eleman | DREAD Skoru | Seviye | Durum | Tedbirler |",
            "|---|---|---|---|---|---|---|"
        ]

        for t in self.threats.values():
            status = "MITIGATED" if t.is_mitigated else "OPEN"
            mit_str = "; ".join(t.mitigations) if t.mitigations else "Yok"
            lines.append(
                f"| `{t.threat_id}` | {t.category.value} | {t.element_name} | {t.dread.calculate_risk_score():.1f} | {t.dread.get_severity()} | {status} | {mit_str} |"
            )

        return "\n".join(lines)

    def _log_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        """Zaman damgalı denetim günlüğü kaydı oluşturur."""
        self.audit_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "event": event_type,
            "details": details
        })
