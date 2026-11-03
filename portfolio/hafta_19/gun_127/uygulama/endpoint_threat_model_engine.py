# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 127: UÇ NOKTA TEHDİT MODELİ MOTORU (ENDPOINT THREAT MODEL ENGINE)
---------------------------------------------------------------------
Bu motor; Windows, Linux ve hibrit uç nokta (endpoint) sistemlerinin
saldırı yüzeyini analiz eder, MITRE ATT&CK ve CWE zafiyet haritası
çıkarır, uç nokta tehdit skorunu hesaplar ve CIS Benchmark / Microsoft
Baseline uyumlu sıkılaştırma (hardening) yol haritası üretir.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem parametreleri ve arama yolu için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve serileştirmek için json modülü
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
from datetime import datetime
# Benzersiz rastgele kimlik üretimi için secrets modülü
import secrets
# Veri yapılarını modellemek için dataclass ve field yapıları
from dataclasses import dataclass, field
# Tip ipuçları için typing modülü
from typing import Dict, List, Set, Any, Optional, Tuple
# Numaralandırma sınıfları için Enum modülü
from enum import Enum


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class EndpointThreatModelError(Exception):
    """Uç nokta tehdit modelleme motoru temel istisna sınıfı."""
    pass


class InvalidEndpointSpecError(EndpointThreatModelError):
    """Uç nokta şartnamesi eksik veya geçersiz olduğunda fırlatılır."""
    pass


class HighRiskCriticalExposureError(EndpointThreatModelError):
    """Uç noktada kabul edilemez seviyede kritik zafiyet tespit edildiğinde fırlatılır."""
    pass


class MissingMandatoryControlError(EndpointThreatModelError):
    """Kritik sunucu rolünde zorunlu uç nokta kontrolü eksik olduğunda fırlatılır."""
    pass


# ============================================================================
# ENUM VE VERİ MODELLERİ
# ============================================================================

class OperatingSystemFamily(Enum):
    """Desteklenen işletim sistemi aileleri."""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"


class EndpointRole(Enum):
    """Uç noktanın kurumsal ağdaki kritiklik rolü."""
    WORKSTATION = "Kullanıcı İş İstasyonu"
    APPLICATION_SERVER = "Uygulama Sunucusu"
    DATABASE_SERVER = "Veritabanı Sunucusu"
    DOMAIN_CONTROLLER = "Etki Alanı Denetleyicisi (DC)"
    BASTION_HOST = "Sıçrama Noktası (Bastion/Jumpbox)"


class AttackSurfaceArea(Enum):
    """Uç nokta saldırı yüzeyi kategorileri (MITRE ATT&CK Taktikleri)."""
    AUTHENTICATION_CREDENTIALS = "Kimlik Bilgisi Güvenliği (Credential Access)"
    SERVICE_EXECUTION = "Servis ve Çalıştırma Güvenliği (Execution / PrivEsc)"
    REGISTRY_CONFIG = "Kayıt Defteri ve Kalıcılık (Persistence)"
    SCRIPTING_LOLBINS = "Betik ve LOLBin Güvenliği (Defense Evasion)"
    NETWORK_EXPOSURE = "Ağ ve Port Açıklığı (Initial Access / Lateral Movement)"
    DEFENSE_MECHANISMS = "Uç Nokta Savunma Mekanizmaları (EDR / Telemetri)"


class ThreatSeverity(Enum):
    """Tehdit ciddiyet dereceleri."""
    CRITICAL = "Kritik"
    HIGH = "Yüksek"
    MEDIUM = "Orta"
    LOW = "Düşük"
    INFO = "Bilgilendirme"


@dataclass
class EndpointControlStatus:
    """Uç noktada kurulu ve aktif olan güvenlik kontrolleri modeli."""
    # EDR / Antivirüs ajanının durumu
    edr_active: bool = False
    # EDR kurcalama koruması (Tamper Protection) devrede mi?
    tamper_protection_active: bool = False
    # Sysmon (Windows) veya Auditd (Linux) derin telemetri devrede mi?
    telemetry_active: bool = False
    # LSA Protection (RunAsPPL) veya Credential Guard aktif mi?
    credential_guard_active: bool = False
    # Disk şifreleme (BitLocker veya LUKS) aktif mi?
    disk_encryption_active: bool = False
    # Kullanıcı Hesabı Denetimi (UAC) en yüksek seviyede mi?
    strict_uac_active: bool = False
    # Kod Bütünlüğü / Uygulama İzin Listeleme (WDAC / AppLocker) aktif mi?
    app_whitelisting_active: bool = False
    # PowerShell Kısıtlı Dil Modu (Constrained Language Mode - CLM) aktif mi?
    powershell_clm_active: bool = False
    # Tırnaksız servis yolları (Unquoted Service Path) sayısı
    unquoted_service_paths_count: int = 0
    # Linux SUID/SGID zafiyetli ikili dosya sayısı
    suid_misconfigurations_count: int = 0
    # Açık güvensiz portlar listesi (örn: SMBv1, Telnet, NLA'sız RDP)
    insecure_open_ports: List[str] = field(default_factory=list)
    # Zayıf yetkili Kayıt Defteri (Run/RunOnce) anahtarları sayısı
    weak_registry_autoruns_count: int = 0


@dataclass
class ThreatFinding:
    """Tespit edilen münferit uç nokta tehdit bulgusu."""
    finding_id: str                      # Benzersiz bulgu kimliği
    title: str                           # Tehdit başlığı
    surface_area: AttackSurfaceArea      # Saldırı yüzeyi kategorisi
    severity: ThreatSeverity             # Ciddiyet seviyesi
    cwe_id: str                          # İlgili CWE zafiyet kodu
    mitre_technique_id: str              # MITRE ATT&CK teknik kimliği (örn: T1003.001)
    description: str                     # Tehdit ayrıntısı ve etki analizi
    remediation: str                     # Sıkılaştırma ve çözüm önerisi


@dataclass
class EndpointThreatModelReport:
    """Uç nokta tehdit modelleme nihai değerlendirme raporu."""
    report_id: str                       # Benzersiz rapor kimliği
    timestamp: str                       # Analiz zamanı
    endpoint_name: str                   # Hedef cihaz adı
    os_family: OperatingSystemFamily     # İşletim sistemi
    role: EndpointRole                   # Cihaz rolü
    threat_index_score: float            # 0-100 Tehdit Endeksi (Düşük = Güvenli)
    security_posture_level: str          # 'GÜVENLİ/SIKILAŞTIRILMIŞ', 'ORTA_RİSK', 'YÜKSEK_RİSK', 'KRİTİK_RİSK'
    findings: List[ThreatFinding]        # Tespit edilen tehdit bulguları listesi
    hardening_roadmap: List[str]         # Öncelikli sıkılaştırma adımları


# ============================================================================
# ÇEKİRDEK UÇ NOKTA TEHDİT MODELLEME MOTORU
# ============================================================================

class EndpointThreatModelEngine:
    """
    Uç Nokta Tehdit Modelleme ve Saldırı Yüzeyi Değerlendirme Motoru.
    Windows ve Linux ortamlarında MITRE ATT&CK ve CWE referanslarıyla
    uç nokta zafiyetlerini analiz eder ve risk puanlaması yapar.
    """

    def __init__(self, engine_name: str = "Enterprise Endpoint Threat Modeler"):
        """Motoru başlatır."""
        # Motor adını saklıyoruz
        self.engine_name = engine_name
        # Analiz geçmişini tutan liste
        self.audit_log: List[Dict[str, Any]] = []

    def evaluate_threat_vectors(
        self,
        endpoint_name: str,
        os_family: OperatingSystemFamily,
        role: EndpointRole,
        controls: EndpointControlStatus
    ) -> List[ThreatFinding]:
        """Uç noktadaki tüm saldırı yüzeylerini denetler ve tehdit bulgularını üretir."""
        # Bulgular listesini başlatıyoruz
        findings: List[ThreatFinding] = []

        # 1. KİMLİK BİLGİSİ GÜVENLİĞİ: LSA Protection / Credential Guard (CWE-311 / MITRE T1003.001)
        if os_family == OperatingSystemFamily.WINDOWS and not controls.credential_guard_active:
            # Domain Controller veya Veritabanı için kritik, diğerleri için yüksek
            sev = ThreatSeverity.CRITICAL if role in [EndpointRole.DOMAIN_CONTROLLER, EndpointRole.DATABASE_SERVER] else ThreatSeverity.HIGH
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-CRED-{secrets.token_hex(3).upper()}",
                title="LSA Koruması (RunAsPPL / Credential Guard) Devre Dışı",
                surface_area=AttackSurfaceArea.AUTHENTICATION_CREDENTIALS,
                severity=sev,
                cwe_id="CWE-311",
                mitre_technique_id="T1003.001 (OS Credential Dumping: LSASS Memory)",
                description="LSASS bellek alanı korumasızdır. Yönetici ayrıcalığı kazanan saldırgan Mimikatz gibi araçlarla düz metin parola ve NTLM özetlerini dökebilir.",
                remediation="GPO veya Intune üzerinden 'Turn on Virtualization Based Security' ve 'Credential Guard' etkinleştirilmelidir."
            ))

        # 2. SERVİS VE YETKİ YÜKSELTMESİ: Tırnaksız Servis Yolları (CWE-428 / MITRE T1574.009)
        if controls.unquoted_service_paths_count > 0:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-SVC-{secrets.token_hex(3).upper()}",
                title=f"Tırnaksız Servis Yolu Zafiyeti ({controls.unquoted_service_paths_count} Adet)",
                surface_area=AttackSurfaceArea.SERVICE_EXECUTION,
                severity=ThreatSeverity.HIGH,
                cwe_id="CWE-428",
                mitre_technique_id="T1574.009 (Hijack Execution Flow: Path Interception by Unquoted Path)",
                description="Servis ikili dosya yolu tırnak içine alınmadığı ve boşluk içerdiği için alt yetkili kullanıcılar araya zararlı ikili dosya yerleştirerek SYSTEM yetkisine yükselebilir.",
                remediation="Kayıt defterindeki ImagePath değerleri çift tırnak içerisine alınmalıdır."
            ))

        # 3. LİNUX SUID/SGID YETKİ YÜKSELTMESİ (CWE-250 / MITRE T1548.001)
        if os_family == OperatingSystemFamily.LINUX and controls.suid_misconfigurations_count > 0:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-SUID-{secrets.token_hex(3).upper()}",
                title=f"Güvensiz SUID/SGID İkili Dosya Yapılandırması ({controls.suid_misconfigurations_count} Adet)",
                surface_area=AttackSurfaceArea.SERVICE_EXECUTION,
                severity=ThreatSeverity.CRITICAL,
                cwe_id="CWE-250",
                mitre_technique_id="T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)",
                description="Standart kullanıcıların GTFOBins yöntemleriyle root kabuğu elde etmesine olanak tanıyan SUID bitli ikili dosyalar tespit edildi.",
                remediation="Gereksiz dosyalardan SUID biti ('chmod u-s') kaldırılmalı veya sudoers kuralı sınırlandırılmalıdır."
            ))

        # 4. SAVUNMA MEKANİZMALARI: EDR ve Tamper Protection Eksikliği (CWE-693 / MITRE T1562.001)
        if not controls.edr_active:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-EDR-{secrets.token_hex(3).upper()}",
                title="Aktif Uç Nokta Tespit ve Yanıt (EDR) Ajanı Yok",
                surface_area=AttackSurfaceArea.DEFENSE_MECHANISMS,
                severity=ThreatSeverity.CRITICAL,
                cwe_id="CWE-693",
                mitre_technique_id="T1562.001 (Impair Defenses: Disable or Modify Tools)",
                description="Uç noktada merkezi EDR ajanı yüklü veya aktif değildir. Saldırgan faaliyetleri gerçek zamanlı izlenemez ve engellenemez.",
                remediation="Merkezi kurumsal EDR ajanı yüklenmeli ve güvenlik operasyon merkezine (SOC) bağlanmalıdır."
            ))
        elif not controls.tamper_protection_active:
            # EDR var ama kurcalama koruması kapalı
            findings.append(ThreatFinding(
                finding_id=f"THREAT-TAMPER-{secrets.token_hex(3).upper()}",
                title="EDR Kurcalama Koruması (Tamper Protection) Kapalı",
                surface_area=AttackSurfaceArea.DEFENSE_MECHANISMS,
                severity=ThreatSeverity.HIGH,
                cwe_id="CWE-693",
                mitre_technique_id="T1562.001 (Impair Defenses)",
                description="Yerel yönetici haklarına sahip bir saldırgan veya fidye yazılımı EDR servislerini durdurabilir veya kayıt defterinden silebilir.",
                remediation="Merkezi yönetim panelinden 'Tamper Protection' kilidi açılmalıdır."
            ))

        # 5. DERİN TELEMETRİ: Sysmon / Auditd Eksikliği (CWE-778 / MITRE T1070)
        if not controls.telemetry_active:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-LOG-{secrets.token_hex(3).upper()}",
                title="Gelişmiş Uç Nokta Telemetrisi (Sysmon / Auditd) Eksik",
                surface_area=AttackSurfaceArea.DEFENSE_MECHANISMS,
                severity=ThreatSeverity.MEDIUM,
                cwe_id="CWE-778",
                mitre_technique_id="T1070 (Indicator Removal)",
                description="Süreç oluşturma (Process Creation), ağ bağlantıları ve DLL yüklemeleri gibi düşük seviyeli olaylar izlenememektedir.",
                remediation="Windows için SwiftOnSecurity kurallı Sysmon, Linux için ise auditd yapılandırması dağıtılmalıdır."
            ))

        # 6. BETİK VE LOLBIN GÜVENLİĞİ: PowerShell Kısıtlanmamış Dil Modu (CWE-284 / MITRE T1059.001)
        if os_family == OperatingSystemFamily.WINDOWS and not controls.powershell_clm_active:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-PS-{secrets.token_hex(3).upper()}",
                title="PowerShell Kısıtlı Dil Modu (CLM) Etkin Değil",
                surface_area=AttackSurfaceArea.SCRIPTING_LOLBINS,
                severity=ThreatSeverity.MEDIUM,
                cwe_id="CWE-284",
                mitre_technique_id="T1059.001 (Command and Scripting Interpreter: PowerShell)",
                description="FullLanguage modu açıktır. Saldırganlar bellek içi .NET çağrıları yaparak AMSI atlatma ve kod yürütme gerçekleştirebilir.",
                remediation="__PSLockdownPolicy ortam değişkeni veya AppLocker ile ConstrainedLanguage modu zorlanmalıdır."
            ))

        # 7. AĞ AÇIKLIĞI VE TEHLİKELİ PORTLAR (CWE-319 / MITRE T1021)
        if controls.insecure_open_ports:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-NET-{secrets.token_hex(3).upper()}",
                title=f"Güvensiz Ağ Protokolleri ve Portlar Açık ({', '.join(controls.insecure_open_ports)})",
                surface_area=AttackSurfaceArea.NETWORK_EXPOSURE,
                severity=ThreatSeverity.HIGH,
                cwe_id="CWE-319",
                mitre_technique_id="T1021 (Remote Services)",
                description=f"Açık bulunan portlar ({', '.join(controls.insecure_open_ports)}) man-in-the-middle, kaba kuvvet ve yanal hareket risklerine zemin hazırlar.",
                remediation="SMBv1 tamamen kaldırılmalı, RDP için NLA (Network Level Authentication) şart koşulmalı, gereksiz portlar güvenlik duvarından kapatılmalıdır."
            ))

        # 8. DİSK ŞİFRELEME EKSİKLİĞİ (CWE-311 / MITRE T1005)
        if not controls.disk_encryption_active:
            # Taşınabilir iş istasyonu için kritik/yüksek
            sev = ThreatSeverity.HIGH if role == EndpointRole.WORKSTATION else ThreatSeverity.MEDIUM
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-DISK-{secrets.token_hex(3).upper()}",
                title="Tam Disk Şifreleme (BitLocker / LUKS) Devre Dışı",
                surface_area=AttackSurfaceArea.AUTHENTICATION_CREDENTIALS,
                severity=sev,
                cwe_id="CWE-311",
                mitre_technique_id="T1005 (Data from Local System)",
                description="Cihazın çalınması veya doğrudan fiziksel erişim durumunda işletim sistemi diski çıkarılarak veriler şifresiz okunabilir.",
                remediation="TPM 2.0 destekli BitLocker veya LUKS tam disk şifrelemesi zorunlu kılınmalıdır."
            ))

        # 9. KALICILIK: Zayıf Kayıt Defteri Otomatik Başlatma İzinleri (CWE-732 / MITRE T1547.001)
        if controls.weak_registry_autoruns_count > 0:
            # Bulgu oluşturuyoruz
            findings.append(ThreatFinding(
                finding_id=f"THREAT-REG-{secrets.token_hex(3).upper()}",
                title=f"Zayıf İzinli Otomatik Başlatma Kayıtları ({controls.weak_registry_autoruns_count} Adet)",
                surface_area=AttackSurfaceArea.REGISTRY_CONFIG,
                severity=ThreatSeverity.HIGH,
                cwe_id="CWE-732",
                mitre_technique_id="T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)",
                description="Standart kullanıcıların yazma iznine sahip olduğu Run/RunOnce kayıtları kalıcı zararlı yazılım çalıştırmak için kullanılabilir.",
                remediation="HKLM ve HKCU altındaki Run anahtarlarının ACL izinleri yalnızca Yöneticilere yazma yetkisi verecek şekilde kilitlenmelidir."
            ))

        # Bulgular listesini döndürüyoruz
        return findings

    def calculate_threat_index(
        self,
        role: EndpointRole,
        findings: List[ThreatFinding]
    ) -> Tuple[float, str]:
        """
        Tehdit ciddiyetlerine ve uç noktanın kurumsal rolüne göre
        0-100 Tehdit Endeksi Skorunu ve Güvenlik Seviyesini hesaplar.
        0: Mükemmel Güvenli, 100: Kritik Seviyede Savunmasız.
        """
        # Ciddiyet katsayıları
        severity_weights = {
            ThreatSeverity.CRITICAL: 25.0,
            ThreatSeverity.HIGH: 15.0,
            ThreatSeverity.MEDIUM: 8.0,
            ThreatSeverity.LOW: 3.0,
            ThreatSeverity.INFO: 0.0
        }

        # Rol etki çarpanları (Kritik sunucuların tehdit ağırlığı daha yüksektir)
        role_multipliers = {
            EndpointRole.DOMAIN_CONTROLLER: 1.5,
            EndpointRole.DATABASE_SERVER: 1.3,
            EndpointRole.BASTION_HOST: 1.3,
            EndpointRole.APPLICATION_SERVER: 1.1,
            EndpointRole.WORKSTATION: 1.0
        }

        # Ham skoru hesaplıyoruz
        raw_score = sum(severity_weights.get(f.severity, 0.0) for f in findings)
        # Rol çarpanını uyguluyoruz
        multiplier = role_multipliers.get(role, 1.0)
        # Ağırlıklı skoru hesaplıyoruz
        weighted_score = raw_score * multiplier
        # 0 ile 100 arasında sınırlandırıyoruz
        final_threat_index = round(min(100.0, weighted_score), 2)

        # Tehdit seviyesi belirleme
        if final_threat_index >= 70.0:
            posture = "KRİTİK_RİSK (ACİL MÜDAHALE GEREKLİ)"
        elif final_threat_index >= 45.0:
            posture = "YÜKSEK_RİSK (ÖNEMLİ ZAFİYETLER MEVCUT)"
        elif final_threat_index >= 20.0:
            posture = "ORTA_RİSK (İYİLEŞTİRME ÖNERİLİR)"
        else:
            posture = "GÜVENLİ / SIKILAŞTIRILMIŞ (PASS)"

        # Skor ve seviyeyi döndürüyoruz
        return final_threat_index, posture

    def generate_hardening_roadmap(self, findings: List[ThreatFinding]) -> List[str]:
        """Bulgulara göre önceliklendirilmiş sıkılaştırma (Hardening) eylemleri listeler."""
        # Yol haritası listesi
        roadmap: List[str] = []
        # Öncelik sırasına göre sıralıyoruz (Critical -> High -> Medium -> Low)
        order_map = {
            ThreatSeverity.CRITICAL: 1,
            ThreatSeverity.HIGH: 2,
            ThreatSeverity.MEDIUM: 3,
            ThreatSeverity.LOW: 4,
            ThreatSeverity.INFO: 5
        }
        sorted_findings = sorted(findings, key=lambda f: order_map.get(f.severity, 99))

        # Her bulgu için sıkılaştırma adımı üretiyoruz
        for idx, f in enumerate(sorted_findings, start=1):
            # Adım metnini biçimlendiriyoruz
            step = f"Adım {idx} [{f.severity.value}] {f.title}: {f.remediation}"
            # Listeye ekliyoruz
            roadmap.append(step)

        # Eğer hiç bulgu yoksa tebrik mesajı ekliyoruz
        if not roadmap:
            roadmap.append("Sistem CIS Benchmark ve Microsoft Security Baseline standartlarına tam uygundur; ek acil sıkılaştırma adımı gerekmemektedir.")

        # Listeyi döndürüyoruz
        return roadmap

    def model_endpoint_threats(
        self,
        endpoint_name: str,
        os_family: OperatingSystemFamily,
        role: EndpointRole,
        controls: EndpointControlStatus
    ) -> EndpointThreatModelReport:
        """Uç nokta için uçtan uca tehdit modelleme analizini icra eder ve rapor üretir."""
        # Rapor kimliği üretiyoruz
        report_id = f"REP-EP-{secrets.token_hex(4).upper()}"
        # Zaman damgasını alıyoruz
        timestamp = datetime.now().isoformat()

        # 1. Tehdit bulgularını çıkarıyoruz
        findings = self.evaluate_threat_vectors(endpoint_name, os_family, role, controls)

        # 2. Tehdit endeksi ve güvenlik seviyesini hesaplıyoruz
        threat_index, posture = self.calculate_threat_index(role, findings)

        # 3. Sıkılaştırma yol haritasını üretiyoruz
        roadmap = self.generate_hardening_roadmap(findings)

        # Rapor nesnesini oluşturuyoruz
        report = EndpointThreatModelReport(
            report_id=report_id,
            timestamp=timestamp,
            endpoint_name=endpoint_name,
            os_family=os_family,
            role=role,
            threat_index_score=threat_index,
            security_posture_level=posture,
            findings=findings,
            hardening_roadmap=roadmap
        )

        # Denetim kütüğüne kaydediyoruz
        self.audit_log.append({
            "report_id": report_id,
            "timestamp": timestamp,
            "endpoint": endpoint_name,
            "score": threat_index,
            "posture": posture,
            "findings_count": len(findings)
        })

        # Raporu döndürüyoruz
        return report

    def export_markdown_report(self, report: EndpointThreatModelReport) -> str:
        """Tehdit modelleme raporunu didaktik Markdown formatında dışa aktarır."""
        # Satır listesi
        lines: List[str] = [
            f"# UÇ NOKTA TEHDİT MODELİ RAPORU: {report.endpoint_name}",
            f"**Rapor Kimliği:** `{report.report_id}`  ",
            f"**Tarih / Saat:** `{report.timestamp}`  ",
            f"**İşletim Sistemi:** `{report.os_family.value}`  ",
            f"**Uç Nokta Rolü:** `{report.role.value}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Tehdit Endeksi",
            "",
            f"- **Uç Nokta Tehdit Endeksi:** `{report.threat_index_score} / 100` *(Düşük = Daha Güvenli)*",
            f"- **Güvenlik Duruşu:** **{report.security_posture_level}**",
            f"- **Tespit Edilen Tehdit Sayısı:** `{len(report.findings)}`",
            "",
            "---",
            "",
            "## 2. Tespit Edilen Tehditler ve Saldırı Yüzeyi Analizi",
            "",
            "| No | Ciddiyet | Tehdit Başlığı | Saldırı Yüzeyi | CWE | MITRE ATT&CK |",
            "|---|---|---|---|---|---|"
        ]

        # Bulguları tabloya ekliyoruz
        if report.findings:
            for idx, f in enumerate(report.findings, start=1):
                lines.append(
                    f"| {idx} | **{f.severity.value}** | {f.title} | {f.surface_area.value} | `{f.cwe_id}` | `{f.mitre_technique_id}` |"
                )
        else:
            lines.append("| - | - | Temiz (Herhangi bir tehdit tespit edilmedi) | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Öncelikli Sıkılaştırma (Hardening) Yol Haritası",
            ""
        ])

        # Yol haritasını ekliyoruz
        for step in report.hardening_roadmap:
            lines.append(f"- {step}")

        lines.extend([
            "",
            "---",
            "",
            "> [!NOTE]",
            "> Bu tehdit modeli **Microsoft Security Baselines**, **CIS Benchmarks** ve **MITRE ATT&CK for Enterprise** standartlarına dayalı olarak üretilmiştir."
        ])

        # Metni birleştiriyoruz
        return "\n".join(lines)
