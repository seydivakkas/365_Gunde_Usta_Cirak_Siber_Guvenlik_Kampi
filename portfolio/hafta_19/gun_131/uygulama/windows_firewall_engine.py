# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 131: WINDOWS DEFENDER GÜVENLİK DUVARI (FIREWALL) SERTLEŞTİRME MOTORU
-----------------------------------------------------------------------
Bu motor; Windows Defender Gelişmiş Güvenlikli Güvenlik Duvarı (WFAS) Domain,
Private ve Public profillerini, varsayılan gelen/giden eylemlerini, kütükleme
(logging) ayarlarını ve açık gelen (inbound) kurallarını CIS Microsoft Windows
Benchmark (Bölüm 9) standartlarına göre denetler, güvenlik açığı puanını hesaplar
ve PowerShell/netsh sertleştirme betikleri derler.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem parametreleri ve çıkış kodları için sys modülü
import sys
# JSON verilerini okumak ve serileştirmek için json modülü
import json
# Zaman damgaları için datetime modülü
from datetime import datetime
# Kriptografik güvenli rastgele belirteç üretimi için secrets modülü
import secrets
# Veri yapılarını tanımlamak için dataclass ve field modülü
from dataclasses import dataclass, field
# Tip ipuçları için typing modülü
from typing import Dict, List, Set, Any, Optional, Tuple
# Sabitler ve numaralandırmalar için Enum modülü
from enum import Enum


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class FirewallAuditEngineError(Exception):
    """Windows Firewall denetim motoru temel istisna sınıfı."""
    pass


class InvalidFirewallConfigError(FirewallAuditEngineError):
    """Geçersiz veya bozuk güvenlik duvarı yapılandırması girildiğinde fırlatılır."""
    pass


class CriticalFirewallDisabledError(FirewallAuditEngineError):
    """Güvenlik duvarı profillerinin tamamen kapatıldığı tespit edildiğinde fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class AuditSeverity(Enum):
    """Bulgu ciddiyet derecesi."""
    CRITICAL = "Kritik"
    HIGH = "Yüksek"
    MEDIUM = "Orta"
    LOW = "Düşük"
    INFO = "Bilgilendirme"


class FirewallProfileType(Enum):
    """Windows Güvenlik Duvarı Ağ Profilleri."""
    DOMAIN = "Domain"
    PRIVATE = "Private"
    PUBLIC = "Public"


class FirewallAction(Enum):
    """Güvenlik Duvarı Paket Eylemi."""
    BLOCK = "Block"
    ALLOW = "Allow"


@dataclass
class FirewallProfileConfig:
    """Tek bir ağ profili (Domain/Private/Public) yapılandırma modeli."""
    profile_type: FirewallProfileType              # Profil türü
    enabled: bool = True                           # Güvenlik duvarı açık mı? (CIS: True)
    default_inbound_action: FirewallAction = FirewallAction.BLOCK  # Varsayılan gelen eylem (CIS: Block)
    default_outbound_action: FirewallAction = FirewallAction.ALLOW # Varsayılan giden eylem (CIS: Allow)
    allow_inbound_rules: bool = True               # Gelen kural istisnalarına izin verilsin mi? (Public'te False)
    allow_local_firewall_rules: bool = False       # Yerel yöneticilerin kural eklemesi birleştirilsin mi? (CIS: False)
    log_blocked: bool = True                       # Engellenen paketler kütüklensin mi? (CIS: True)
    log_allowed: bool = False                      # İzin verilen paketler kütüklensin mi?
    log_file_size_kb: int = 16384                  # Kütük dosya boyutu (CIS: >= 16384 KB)


@dataclass
class FirewallRule:
    """Münferit bir Güvenlik Duvarı Kuralı modeli."""
    rule_name: str                                 # Kural adı
    direction: str = "Inbound"                     # 'Inbound' veya 'Outbound'
    action: FirewallAction = FirewallAction.ALLOW  # 'Allow' veya 'Block'
    enabled: bool = True                           # Kural aktif mi?
    profiles: List[FirewallProfileType] = field(default_factory=list) # Etkili olduğu profiller
    protocol: str = "TCP"                          # 'TCP', 'UDP', 'Any'
    local_port: str = "Any"                        # Hedef yerel port (örn: '3389', '445', 'Any')
    remote_address: str = "Any"                    # Kaynak IP/Ağ (örn: 'Any', 'LocalSubnet')


@dataclass
class SystemFirewallSpec:
    """Bir sistemin tüm güvenlik duvarı profilleri ve kuralları spesifikasyonu."""
    target_host: str                               # Hedef makine adı
    profiles: Dict[FirewallProfileType, FirewallProfileConfig] = field(default_factory=dict)
    rules: List[FirewallRule] = field(default_factory=list)


@dataclass
class FirewallAuditFinding:
    """Tespit edilen münferit güvenlik duvarı açığı bulgusu."""
    finding_id: str                      # Benzersiz bulgu kimliği
    title: str                           # Zafiyet başlığı
    severity: AuditSeverity              # Ciddiyet seviyesi
    cwe_id: str                          # İlgili CWE kodu
    mitre_technique_id: str              # MITRE ATT&CK tekniği
    current_value: Any                   # Mevcut zayıf değer
    recommended_value: Any               # Önerilen CIS değeri
    description: str                     # Zafiyet ayrıntısı
    powershell_remediation: str          # PowerShell düzeltme komutu
    netsh_remediation: str               # netsh komutu ile düzeltme


@dataclass
class FirewallAuditResult:
    """Güvenlik duvarı denetimi nihai sonuç karnesi."""
    audit_id: str                        # Denetim kimliği
    timestamp: str                       # Denetim zaman damgası
    target_host: str                     # Hedef makine adı
    security_score: float                # 0-100 Güvenlik Skoru (100 = Kusursuz CIS Uyumu)
    posture_status: str                  # 'SIKILAŞTIRILMIŞ (PASS)', 'ORTA_RİSK', 'KRİTİK_ZAFİYET'
    findings: List[FirewallAuditFinding] # Bulgular listesi
    remediation_script: str              # PowerShell ve netsh sıkılaştırma betiği


# ============================================================================
# ÇEKİRDEK GÜVENLİK DUVARI DENETİM VE SERTLEŞTİRME MOTORU
# ============================================================================

class WindowsFirewallEngine:
    """
    Windows Defender Gelişmiş Güvenlikli Güvenlik Duvarı Denetim Motoru.
    CIS Microsoft Windows 11 / Server Benchmark (Bölüm 9) standartlarına göre
    Domain, Private ve Public ağ profillerini ve gelen kuralları teftiş eder.
    """

    # Açık internete (Public Profile) açılması son derece tehlikeli yönetim portları
    HIGH_RISK_PUBLIC_PORTS: Dict[str, Tuple[str, str, str]] = {
        "3389": ("RDP (Uzak Masaüstü)", "T1021.001", "CWE-284"),
        "445":  ("SMB / Dosya Paylaşımı", "T1021.002", "CWE-284"),
        "139":  ("NetBIOS SMB", "T1021.002", "CWE-284"),
        "5985": ("WinRM HTTP", "T1021.006", "CWE-284"),
        "5986": ("WinRM HTTPS", "T1021.006", "CWE-284"),
        "135":  ("RPC Endpoint Mapper", "T1021.003", "CWE-284")
    }

    def __init__(self, auditor_name: str = "Enterprise Windows Firewall Auditor"):
        """Motoru başlatır."""
        self.auditor_name = auditor_name
        self.audit_log: List[Dict[str, Any]] = []

    def audit_firewall(self, spec: SystemFirewallSpec) -> FirewallAuditResult:
        """
        Sistemin güvenlik duvarı profillerini ve kurallarını teftiş eder,
        bulguları üretir ve CIS uyumlu PowerShell düzeltme betiği derler.
        """
        audit_id = f"AUD-FW-{secrets.token_hex(4).upper()}"
        timestamp = datetime.now().isoformat()
        findings: List[FirewallAuditFinding] = []
        score = 100.0

        # ====================================================================
        # 1. PROFİL DURUM VE VARSAYILAN EYLEM DENETİMLERİ (CIS BÖLÜM 9)
        # ====================================================================

        for prof_type in [FirewallProfileType.DOMAIN, FirewallProfileType.PRIVATE, FirewallProfileType.PUBLIC]:
            prof_config = spec.profiles.get(prof_type)

            # Profil hiç tanımlanmamışsa veya kapalıysa (CWE-693 / MITRE T1562.004)
            if not prof_config or not prof_config.enabled:
                if prof_type == FirewallProfileType.PUBLIC:
                    # Public profilin kapalı olması en ağır zafiyettir (30 puan)
                    score -= 30.0
                    sev = AuditSeverity.CRITICAL
                else:
                    # Domain veya Private kapalıysa 20 puan kırılır
                    score -= 20.0
                    sev = AuditSeverity.HIGH

                findings.append(FirewallAuditFinding(
                    finding_id=f"FIND-FW-STATE-{secrets.token_hex(3).upper()}",
                    title=f"Windows Güvenlik Duvarı {prof_type.value} Profili Devre Dışı",
                    severity=sev,
                    cwe_id="CWE-693",
                    mitre_technique_id="T1562.004 (Impair Defenses: Disable or Modify System Firewall)",
                    current_value=False,
                    recommended_value=True,
                    description=f"{prof_type.value} profili için güvenlik duvarı kapatılmıştır. Gelen ağ saldırılarına karşı koruma yoktur.",
                    powershell_remediation=f"Set-NetFirewallProfile -Profile {prof_type.value} -Enabled True",
                    netsh_remediation=f"netsh advfirewall set {prof_type.value.lower()}profile state on"
                ))
                continue

            # Varsayılan Gelen Eylem Block mu? (CIS: Block) (CWE-284)
            if prof_config.default_inbound_action != FirewallAction.BLOCK:
                score -= 25.0
                findings.append(FirewallAuditFinding(
                    finding_id=f"FIND-FW-INACT-{secrets.token_hex(3).upper()}",
                    title=f"{prof_type.value} Profili Varsayılan Gelen Eylem 'Allow' Olarak Ayarlı",
                    severity=AuditSeverity.CRITICAL,
                    cwe_id="CWE-284",
                    mitre_technique_id="T1562.004",
                    current_value="Allow",
                    recommended_value="Block",
                    description=f"{prof_type.value} profilinde varsayılan gelen trafik engellenmemektedir (Kural eşleşmeyen tüm trafik geçer).",
                    powershell_remediation=f"Set-NetFirewallProfile -Profile {prof_type.value} -DefaultInboundAction Block",
                    netsh_remediation=f"netsh advfirewall set {prof_type.value.lower()}profile firewallpolicy blockinbound,allowoutbound"
                ))

            # Engellenen Paketlerin Kütüklenmesi (LogBlocked) (CWE-778)
            if not prof_config.log_blocked:
                score -= 10.0
                findings.append(FirewallAuditFinding(
                    finding_id=f"FIND-FW-LOG-{secrets.token_hex(3).upper()}",
                    title=f"{prof_type.value} Profilinde Engellenen Paket Kütüklemesi Kapalı",
                    severity=AuditSeverity.MEDIUM,
                    cwe_id="CWE-778",
                    mitre_technique_id="T1562.004",
                    current_value=False,
                    recommended_value=True,
                    description="Güvenlik duvarının engellediği bağlantılar kütüklenmemektedir; ağ keşif girişimleri tespit edilemez.",
                    powershell_remediation=f"Set-NetFirewallProfile -Profile {prof_type.value} -LogBlocked True -LogFileName '%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log'",
                    netsh_remediation=f"netsh advfirewall set {prof_type.value.lower()}profile logging droppedconnections enable"
                ))

            # Kütük Dosyası Boyutu (>= 16384 KB)
            if prof_config.log_file_size_kb < 16384:
                score -= 5.0
                findings.append(FirewallAuditFinding(
                    finding_id=f"FIND-FW-LOGSIZE-{secrets.token_hex(3).upper()}",
                    title=f"{prof_type.value} Profil Kütük Boyutu Yetersiz (< 16 MB)",
                    severity=AuditSeverity.LOW,
                    cwe_id="CWE-778",
                    mitre_technique_id="T1562.004",
                    current_value=f"{prof_config.log_file_size_kb} KB",
                    recommended_value=">= 16384 KB",
                    description="Kütük dosyası boyutu çok küçük olduğu için güvenlik olayları erken üzerine yazılmaktadır.",
                    powershell_remediation=f"Set-NetFirewallProfile -Profile {prof_type.value} -LogMaxSizeKilobytes 16384",
                    netsh_remediation=f"netsh advfirewall set {prof_type.value.lower()}profile logging maxfilesize 16384"
                ))

        # ====================================================================
        # 2. GELEN KURALLAR VE RİSKLİ PORT DENETİMLERİ (CWE-284)
        # ====================================================================

        for rule in spec.rules:
            # Yalnızca aktif gelen ve izin veren kuralları inceliyoruz
            if not rule.enabled or rule.direction.lower() != "inbound" or rule.action != FirewallAction.ALLOW:
                continue

            # 2.1 Any-Any Gelen İzin Kuralı Denetimi (CWE-284)
            if rule.remote_address.upper() == "ANY" and rule.local_port.upper() == "ANY":
                score -= 25.0
                findings.append(FirewallAuditFinding(
                    finding_id=f"FIND-RULE-ANY-{secrets.token_hex(3).upper()}",
                    title=f"Tehlikeli Any-to-Any Gelen İzin Kuralı: '{rule.rule_name}'",
                    severity=AuditSeverity.CRITICAL,
                    cwe_id="CWE-284",
                    mitre_technique_id="T1562.004",
                    current_value="Any -> Any (Allow)",
                    recommended_value="Kural Devre Dışı Bırakılmalı veya Sınırlandırılmalıdır",
                    description=f"'{rule.rule_name}' kuralı tüm IP adreslerinden tüm portlara gelen trafiğe izin vererek güvenlik duvarını fiilen delmektedir.",
                    powershell_remediation=f"Disable-NetFirewallRule -DisplayName '{rule.rule_name}'",
                    netsh_remediation=f"netsh advfirewall firewall set rule name=\"{rule.rule_name}\" new enable=no"
                ))

            # 2.2 Public Profile Üzerinde Yüksek Riskli Yönetim Portları (CWE-284 / MITRE T1021)
            if FirewallProfileType.PUBLIC in rule.profiles and rule.remote_address.upper() == "ANY":
                for port, (port_name, mitre_tech, cwe_code) in self.HIGH_RISK_PUBLIC_PORTS.items():
                    if port in rule.local_port.split(",") or rule.local_port == port:
                        score -= 20.0
                        findings.append(FirewallAuditFinding(
                            finding_id=f"FIND-RULE-PUB-{secrets.token_hex(3).upper()}",
                            title=f"Public Profilde {port_name} (Port {port}) Açık: '{rule.rule_name}'",
                            severity=AuditSeverity.CRITICAL,
                            cwe_id=cwe_code,
                            mitre_technique_id=mitre_tech,
                            current_value=f"Public Profile, Port {port}",
                            recommended_value="Public Profilde Yönetim Portları Kesinlikle Kapatılmalıdır",
                            description=f"Güvenilmeyen genel ağlarda (Public profile) {port_name} portunun açık olması kaba kuvvet ve sızma riskini maksimuma çıkarır.",
                            powershell_remediation=f"Set-NetFirewallRule -DisplayName '{rule.rule_name}' -Profile Domain,Private",
                            netsh_remediation=f"netsh advfirewall firewall set rule name=\"{rule.rule_name}\" new profile=domain,private"
                        ))

        final_score = round(max(0.0, min(100.0, score)), 2)

        if final_score >= 85.0:
            posture = "SIKILAŞTIRILMIŞ / CIS UYUMLU (PASS)"
        elif final_score >= 50.0:
            posture = "ORTA_RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            posture = "KRİTİK_ZAFİYET (SAVUNMASIZ DURUMDA)"

        # PowerShell ve netsh düzeltme betiğini derliyoruz
        remediation_lines = [
            "# ====================================================================",
            "# WINDOWS DEFENDER FIREWALL CIS BENCHMARK SERTLEŞTİRME BETİĞİ",
            f"# Hedef Sistem: {spec.target_host} | Tarih: {timestamp}",
            "# ====================================================================",
            "",
            "# 1. Tüm Profilleri Aç ve Varsayılan Gelen Trafiği Blokla",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow",
            "",
            "# 2. Güvenlik Duvarı Kütükleme (Logging) Politikalarını Yapılandır",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes 16384",
            "Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName '%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log'",
            "",
            "# 3. Public Profilde Gelen İstisnaları Sınırla",
            "Set-NetFirewallProfile -Profile Public -AllowInboundRules False",
            ""
        ]

        if any("FIND-RULE" in f.finding_id for f in findings):
            remediation_lines.append("# 4. Tehlikeli Açık Kuralları Kapat / Sınırla")
            for f in findings:
                if "FIND-RULE" in f.finding_id:
                    remediation_lines.append(f.powershell_remediation)
            remediation_lines.append("")

        remediation_lines.extend([
            "Write-Host '[+] Windows Güvenlik Duvarı CIS Sertleştirmesi Başarıyla Tamamlandı!' -ForegroundColor Green"
        ])

        full_script = "\n".join(remediation_lines)

        result = FirewallAuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            target_host=spec.target_host,
            security_score=final_score,
            posture_status=posture,
            findings=findings,
            remediation_script=full_script
        )

        self.audit_log.append({
            "audit_id": audit_id,
            "host": spec.target_host,
            "score": final_score,
            "findings_count": len(findings)
        })

        return result

    def export_markdown_report(self, result: FirewallAuditResult) -> str:
        """Denetim sonucunu Markdown rapor formatında dışa aktarır."""
        lines: List[str] = [
            f"# WINDOWS DEFENDER GÜVENLİK DUVARI (FIREWALL) DENETİM RAPORU",
            f"**Hedef Sistem:** `{result.target_host}`  ",
            f"**Denetim Kimliği:** `{result.audit_id}`  ",
            f"**Tarih / Saat:** `{result.timestamp}`  ",
            f"**Denetçi Otoritesi:** `{self.auditor_name}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Güvenlik Skoru",
            "",
            f"- **Güvenlik Duvarı Duruş Skoru:** `{result.security_score} / 100`",
            f"- **Duruş Durumu:** **{result.posture_status}**",
            f"- **Tespit Edilen Güvenlik Açıklığı:** `{len(result.findings)} Adet`",
            "",
            "---",
            "",
            "## 2. Tespit Edilen Güvenlik Duvarı Açıklıkları Tablosu",
            "",
            "| No | Ciddiyet | Zafiyet Başlığı | CWE | MITRE ATT&CK | Mevcut Değer | Önerilen Değer |",
            "|---|---|---|---|---|---|---|"
        ]

        if result.findings:
            for idx, f in enumerate(result.findings, start=1):
                lines.append(
                    f"| {idx} | **{f.severity.value}** | {f.title} | `{f.cwe_id}` | `{f.mitre_technique_id}` | `{f.current_value}` | `{f.recommended_value}` |"
                )
        else:
            lines.append("| - | - | Temiz (Güvenlik Duvarı CIS standartlarına tam uygundur) | - | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. PowerShell ve netsh Otomatik Sıkılaştırma (Hardening) Betiği",
            "",
            "```powershell",
            result.remediation_script,
            "```",
            "",
            "---",
            "",
            "> [!NOTE]",
            "> Bu denetim raporu **CIS Microsoft Windows 11 / Server Benchmark (Section 9)** ve **MITRE ATT&CK T1562.004 / T1021** standartlarına dayalı olarak üretilmiştir."
        ])

        return "\n".join(lines)
