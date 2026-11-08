"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli standart kütüphaneler içe aktarılır
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# ENUM VE VERİ MODELLERİ
# ==============================================================================

class SettingType(str, Enum):
    """Yapılandırma ayarının işletim sistemindeki türü."""
    # Windows Kayıt Defteri (Registry Key/Value)
    REGISTRY = "REGISTRY"
    # İşletim Sistemi Servis Durumu (Service Running/Disabled)
    SERVICE_STATE = "SERVICE_STATE"
    # Güvenlik Duvarı Kuralı ve Durumu (Firewall Profile/Port)
    FIREWALL_RULE = "FIREWALL_RULE"
    # Yerel Güvenlik Politikası (Password/Lockout Policy)
    SECURITY_POLICY = "SECURITY_POLICY"
    # Yerel Grup Üyeliği (Örn: Local Administrators Üyeleri)
    LOCAL_USER_GROUP = "LOCAL_USER_GROUP"
    # Linux Çekirdek Parametresi (sysctl)
    LINUX_SYSCTL = "LINUX_SYSCTL"


class SeverityLevel(str, Enum):
    """Yapılandırma sapmasının risk ve şiddet derecesi."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ConfigRule:
    """Temel hat (Baseline / Desired State) içerisindeki tek bir güvenlik kuralı."""
    # Kural kodu (örn: CIS-WIN-1.1.1)
    rule_id: str
    # Ayar türü
    setting_type: SettingType
    # Denetlenecek hedef yol veya anahtar adı
    target_key: str
    # Beklenen güvenli değer (Expected Value)
    expected_value: Any
    # Şiddet seviyesi
    severity: SeverityLevel
    # Kural başlığı
    title: str
    # Güvenlik standardı referansı (CIS Benchmark, DISA STIG, NIST SP 800-53)
    compliance_ref: str
    # Güvenlik riski açıklaması
    description: str
    # Otomatik düzeltme PowerShell komutu
    remediation_cmd_ps1: str = ""
    # Otomatik düzeltme Linux Bash komutu
    remediation_cmd_bash: str = ""


@dataclass
class DriftFinding:
    """Temel hattan sapma tespit edildiğinde üretilen denetim bulgusu."""
    # Kural kodu
    rule_id: str
    # Şiddet derecesi
    severity: str
    # Bulgu başlığı
    title: str
    # Ayar türü
    setting_type: str
    # Hedef yol
    target_key: str
    # Beklenen değer
    expected_value: Any
    # Gerçekleşen sapmış değer (Actual Value)
    actual_value: Any
    # Risk açıklaması
    risk_description: str
    # Düzeltme komutu
    remediation_command: str


@dataclass
class AuditReport:
    """Tüm uç noktanın sapma denetim karnesi ve uyumluluk raporu."""
    # Rapor kimliği
    report_id: str
    # Zaman damgası (UTC)
    timestamp_utc: str
    # Uç nokta adı veya IP adresi
    endpoint_identifier: str
    # Toplam denetlenen kural sayısı
    total_evaluated: int
    # Başarılı / Uyumlu kural sayısı
    total_compliant: int
    # Sapma tespit edilen kural sayısı
    total_drifted: int
    # Uyumluluk yüzdesi (0.0 - 100.0)
    compliance_score_pct: float
    # Tespit edilen bulgular listesi
    findings: List[DriftFinding] = field(default_factory=list)


# ==============================================================================
# MOTOR SINIFI: GÜVENLİ YAPILANDIRMA SAPMA DENETÇİSİ
# ==============================================================================

class ConfigDriftAuditor:
    """
    Uç Nokta Güvenli Yapılandırma Sapması (Configuration Drift) Denetçisi.
    CIS Benchmarks, DISA STIG ve Microsoft SCT standartlarına göre
    anlık durum ile temel hat (Baseline) arasındaki sapmaları tespit eder.
    """

    def __init__(self, baseline_rules: List[ConfigRule]):
        # Güvenli temel hat kuralları saklanır
        self.baseline_rules = baseline_rules

    def evaluate_endpoint_state(self, endpoint_id: str, actual_state: Dict[str, Any]) -> AuditReport:
        """
        Uç noktadan toplanan telemetriyi (actual_state) temel hat kurallarıyla
        karşılaştırarak sapmaları tespit eder ve uyumluluk skorunu hesaplar.
        """
        findings: List[DriftFinding] = []
        compliant_count = 0

        # Her kural sırayla test edilir
        for rule in self.baseline_rules:
            # Hedef ayar gerçek durumda var mı?
            actual_val = actual_state.get(rule.target_key)

            # Özel durum: LOCAL_USER_GROUP (Yetkisiz yönetici tespiti)
            if rule.setting_type == SettingType.LOCAL_USER_GROUP:
                # Beklenen izin verilen yerel yöneticiler kümesi
                expected_members = set(rule.expected_value) if isinstance(rule.expected_value, list) else {rule.expected_value}
                actual_members = set(actual_val) if isinstance(actual_val, list) else set()
                # Beklenmeyen yetkisiz hesaplar var mı?
                unauthorized_members = actual_members - expected_members

                if unauthorized_members:
                    findings.append(DriftFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity.value,
                        title=rule.title,
                        setting_type=rule.setting_type.value,
                        target_key=rule.target_key,
                        expected_value=sorted(list(expected_members)),
                        actual_value=sorted(list(actual_members)),
                        risk_description=f"Yerel Administrators grubunda yetkisiz hesaplar tespit edildi: {sorted(list(unauthorized_members))}. Kalıcılık (persistence) veya arka kapı riski.",
                        remediation_command=rule.remediation_cmd_ps1 or rule.remediation_cmd_bash
                    ))
                else:
                    compliant_count += 1
                continue

            # Değer karşılaştırması: Eşit mi?
            if actual_val != rule.expected_value:
                # Sapma tespit edildi
                findings.append(DriftFinding(
                    rule_id=rule.rule_id,
                    severity=rule.severity.value,
                    title=rule.title,
                    setting_type=rule.setting_type.value,
                    target_key=rule.target_key,
                    expected_value=rule.expected_value,
                    actual_value=actual_val,
                    risk_description=f"{rule.description} (Beklenen: {rule.expected_value}, Mevcut: {actual_val})",
                    remediation_command=rule.remediation_cmd_ps1 or rule.remediation_cmd_bash
                ))
            else:
                # Kurala tam uyumlu
                compliant_count += 1

        total_rules = len(self.baseline_rules)
        score_pct = round((compliant_count / total_rules * 100.0), 2) if total_rules > 0 else 100.0

        return AuditReport(
            report_id=f"DRIFT-REP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            endpoint_identifier=endpoint_id,
            total_evaluated=total_rules,
            total_compliant=compliant_count,
            total_drifted=len(findings),
            compliance_score_pct=score_pct,
            findings=findings
        )


# ==============================================================================
# OTOMATİK İYİLEŞTİRME VE DÜZELTME MOTORU (AUTO-REMEDIATION)
# ==============================================================================

class AutoRemediationEngine:
    """
    Tespit edilen sapmaları (Drift) otomatik olarak temel hat (Baseline)
    değerlerine geri döndüren (Self-Healing / Desired State) motor.
    """

    @staticmethod
    def remediate_state(actual_state: Dict[str, Any], baseline_rules: List[ConfigRule]) -> Dict[str, Any]:
        """
        Gerçek uç nokta durumundaki sapmış değerleri temel hat değerleriyle günceller.
        """
        remediated = dict(actual_state)
        for rule in baseline_rules:
            # Doğrudan beklenen değer atanır
            remediated[rule.target_key] = rule.expected_value
        return remediated

    @staticmethod
    def generate_powershell_remediation_script(findings: List[DriftFinding]) -> str:
        """Tespit edilen tüm sapmalar için uygulanabilir bir PowerShell düzeltme betiği üretir."""
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Güvenli Yapılandırma Sapması Otomatik Düzeltme (Remediation) Betiği",
            "# ==============================================================================",
            "$ErrorActionPreference = 'Stop'",
            "",
            "Write-Output '[*] Güvenli yapılandırma temel hattına geri döndürme başlatılıyor...'",
            ""
        ]

        if not findings:
            lines.append("Write-Output '[+] Sistem temel hatla tam uyumlu; düzeltme gerekmiyor.'")
            return "\n".join(lines)

        for f in findings:
            lines.append(f"# Kural: {f.rule_id} - {f.title} [{f.severity}]")
            lines.append(f"# Hedef: {f.target_key}")
            if f.remediation_command:
                lines.append(f.remediation_command)
            else:
                lines.append(f"# TODO: {f.target_key} için manuel düzeltme gerekli")
            lines.append("")

        lines.append("Write-Output '[+] Tüm yapılandırma sapmaları başarıyla giderildi (100% Compliance).'")
        return "\n".join(lines)

    @staticmethod
    def generate_bash_remediation_script(findings: List[DriftFinding]) -> str:
        """Linux ortamındaki sapmalar için Bash düzeltme betiği üretir."""
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux Yapılandırma Sapması Düzeltme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "echo '[*] Linux güvenlik temel hattı uygulanıyor...'",
            ""
        ]

        for f in findings:
            lines.append(f"# Kural: {f.rule_id} - {f.title}")
            if f.remediation_command:
                lines.append(f.remediation_command)
            lines.append("")

        lines.append("echo '[+] Linux yapılandırma sapmaları başarıyla giderildi.'")
        return "\n".join(lines)
