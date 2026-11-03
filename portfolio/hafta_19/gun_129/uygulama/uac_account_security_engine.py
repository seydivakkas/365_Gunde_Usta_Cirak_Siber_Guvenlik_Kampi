# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 129: WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC GÜVENLİK MOTORU
--------------------------------------------------------------
Bu motor; Windows yerel kullanıcı hesapları (Administrator, Guest), hassas yerel gruplar
(Administrators, Remote Desktop Users vb.) ve Kullanıcı Hesabı Denetimi (UAC) kayıt
defteri politikalarını CIS Microsoft Windows Benchmark ve MITRE ATT&CK standartlarına
göre denetler, güvenlik açığı puanını hesaplar ve PowerShell sıkılaştırma betikleri üretir.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem arama yolu ve parametreleri için sys modülü
import sys
# JSON verilerini okumak ve yazmak için json modülü
import json
# Zaman damgaları için datetime modülü
from datetime import datetime
# Kriptografik güvenli benzersiz kimlik üretimi için secrets modülü
import secrets
# Veri sınıfları oluşturmak için dataclass ve field yapıları
from dataclasses import dataclass, field
# Tip ipuçları için typing modülü
from typing import Dict, List, Set, Any, Optional, Tuple
# Numaralandırma sınıfları için Enum modülü
from enum import Enum


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class UACSecurityEngineError(Exception):
    """UAC ve Yerel Hesap Güvenlik Motoru temel istisna sınıfı."""
    pass


class InvalidSecurityConfigError(UACSecurityEngineError):
    """Geçersiz veya bozuk hesap/UAC yapılandırma verisi girildiğinde fırlatılır."""
    pass


class CriticalPrivilegeEscalationRiskError(UACSecurityEngineError):
    """UAC'nin tamamen devre dışı bırakıldığı kritik zaaf durumunda fırlatılır."""
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


@dataclass
class LocalAccountConfig:
    """Windows yerel hesapları yapılandırma modeli."""
    # Yerleşik Guest hesabı etkin mi? (Varsayılan: False olmalıdır; True ise kritik zafiyettir)
    guest_account_enabled: bool = False
    # Yerleşik Administrator hesabı adı (Varsayılan: 'Administrator'; CIS yeniden adlandırılmasını zorunlu kılar)
    builtin_admin_name: str = "Administrator"
    # Yerleşik Administrator hesabı devre dışı bırakılmış mı? (True önerilir; LAPS ile yönetilmeyen ortamda)
    builtin_admin_disabled: bool = True
    # Hatalı parola kilitleme eşiği (Account Lockout Threshold, CIS: <= 5, 0 = Kilitlenmez/Zafiyettir)
    account_lockout_threshold: int = 5
    # Hesap kilitleme süresi dakika cinsinden (Account Lockout Duration, CIS: >= 15 dk)
    account_lockout_duration_mins: int = 15
    # Kilitleme sayacını sıfırlama süresi dakika (Reset Account Lockout Counter, CIS: >= 15 dk)
    reset_lockout_counter_mins: int = 15
    # Windows LAPS (Local Administrator Password Solution) etkin mi?
    laps_enabled: bool = True


@dataclass
class UACConfig:
    """Windows Kullanıcı Hesabı Denetimi (UAC) kayıt defteri parametreleri modeli."""
    # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System altındaki anahtarlar:
    # UAC Temel Motoru devrede mi? (EnableLUA: 1 = Açık, 0 = UAC Tamamen Kapalı/Kritik Zafiyet)
    enable_lua: bool = True
    # Yerleşik Yönetici için Yönetici Onay Modu (FilterAdministratorToken: 1 = Aktif, 0 = Tam Yetki)
    filter_administrator_token: bool = True
    # Yöneticiler için yükseltme istemi davranışı (ConsentPromptBehaviorAdmin: 2 = Güvenli Masaüstünde Onay, 1 = Parola)
    consent_prompt_behavior_admin: int = 2
    # Standart kullanıcılar için yükseltme davranışı (ConsentPromptBehaviorUser: 0 = Otomatik Reddet, 3 = Güvenli Parola)
    consent_prompt_behavior_user: int = 0
    # Güvenli Masaüstü zorunluluğu (PromptOnSecureDesktop: 1 = Açık, 0 = Normal Masaüstü/Clickjacking Riski)
    prompt_on_secure_desktop: bool = True
    # Dosya ve kayıt defteri yazma hatalarını kullanıcı başına sanallaştırma (EnableVirtualization: 1 = Açık)
    enable_virtualization: bool = True
    # Yalnızca imzalı ve doğrulanmış yürütülebilir dosyaları yükselt (ValidateAdminCodeSignatures: 1 = Açık)
    validate_admin_code_signatures: bool = False


@dataclass
class LocalGroupConfig:
    """Hassas yerel grupların üyelik modeli."""
    # Yerel Yöneticiler grubu üyeleri ('Administrators')
    administrators_members: List[str] = field(default_factory=list)
    # Uzak Masaüstü Kullanıcıları grubu üyeleri ('Remote Desktop Users')
    remote_desktop_members: List[str] = field(default_factory=list)
    # Yedekleme Operatörleri grubu üyeleri ('Backup Operators')
    backup_operators_members: List[str] = field(default_factory=list)


@dataclass
class EndpointAccountSpec:
    """Bir uç noktanın tam hesap, grup ve UAC profil spesifikasyonu."""
    target_host: str                                # Hedef makine adı
    accounts: LocalAccountConfig                    # Yerel hesap ayarları
    uac: UACConfig                                  # UAC ayarları
    groups: LocalGroupConfig                        # Yerel grup üyelikleri


@dataclass
class UACAuditFinding:
    """Tespit edilen münferit hesap/UAC güvenlik açığı bulgusu."""
    finding_id: str                      # Benzersiz bulgu kimliği
    title: str                           # Zafiyet başlığı
    severity: AuditSeverity              # Ciddiyet seviyesi
    cwe_id: str                          # İlgili CWE kodu
    mitre_technique_id: str              # MITRE ATT&CK teknik kodu
    current_value: Any                   # Mevcut yapılandırma değeri
    recommended_value: Any               # Önerilen CIS değeri
    description: str                     # Zafiyet ayrıntısı
    powershell_remediation: str          # PowerShell düzeltme komutu


@dataclass
class UACAuditResult:
    """UAC ve Yerel Hesap Denetimi nihai sonuç karnesi."""
    audit_id: str                        # Denetim kimliği
    timestamp: str                       # Denetim zaman damgası
    target_host: str                     # Hedef makine adı
    security_score: float                # 0-100 Güvenlik Skoru (100 = Kusursuz CIS Uyumu)
    posture_status: str                  # 'SIKILAŞTIRILMIŞ (PASS)', 'ORTA_RİSK', 'KRİTİK_ZAFİYET'
    findings: List[UACAuditFinding]      # Bulgular listesi
    remediation_script: str              # Tam PowerShell sıkılaştırma betiği


# ============================================================================
# ÇEKİRDEK UAC VE YEREL HESAP GÜVENLİK MOTORU
# ============================================================================

class UACAccountSecurityEngine:
    """
    Windows Yerel Hesaplar, Gruplar ve Kullanıcı Hesabı Denetimi (UAC) Denetim Motoru.
    CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Bölüm 2.3) standartlarına göre
    yetki yükseltme ve hesap güvenliği politikalarını teftiş eder.
    """

    # Bilinen yetkisiz/tehlikeli grup üyeleri listesi
    UNAUTHORIZED_ADMIN_USERS: Set[str] = {
        "EVERYONE", "USERS", "INTERACTIVE", "GUEST", "ANONYMOUS",
        "DOMAIN USERS", "AUTHENTICATED USERS"
    }

    def __init__(self, auditor_name: str = "Enterprise UAC & Account Auditor"):
        """Motoru başlatır."""
        # Denetçi unvanını atıyoruz
        self.auditor_name = auditor_name
        # Denetim kütüklerini tutan liste
        self.audit_log: List[Dict[str, Any]] = []

    def audit_endpoint(self, spec: EndpointAccountSpec) -> UACAuditResult:
        """
        Hedef uç noktanın hesap, grup ve UAC yapılandırmasını denetler,
        zafiyetleri CWE ve MITRE ATT&CK kodlarıyla etiketler, skor hesaplar.
        """
        # Benzersiz denetim kimliği oluşturuyoruz
        audit_id = f"AUD-UAC-{secrets.token_hex(4).upper()}"
        # Zaman damgasını alıyoruz
        timestamp = datetime.now().isoformat()
        # Bulgular listesini başlatıyoruz
        findings: List[UACAuditFinding] = []
        # Başlangıç güvenlik puanı (100 üzerinden kırılacak)
        score = 100.0

        # ====================================================================
        # 1. KULLANICI HESABI DENETİMİ (UAC) DENETİMLERİ
        # ====================================================================

        # 1.1 UAC Motorunun Tamamen Açık Olması (EnableLUA) (CWE-693 / MITRE T1548.002)
        if not spec.uac.enable_lua:
            # UAC kapatılmışsa en ağır ceza uygulanır (40 puan kırılır)
            score -= 40.0
            # Kritik bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="Kullanıcı Hesabı Denetimi (UAC / EnableLUA) Tamamen Devre Dışı",
                severity=AuditSeverity.CRITICAL,
                cwe_id="CWE-693",
                mitre_technique_id="T1548.002 (Bypass User Account Control)",
                current_value=False,
                recommended_value=True,
                description="EnableLUA=0 olarak ayarlanmıştır. İşletim sistemi tüm süreçleri en üst yönetici yetkisiyle doğrudan çalıştırır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
            ))

        # 1.2 Yerleşik Administrator için Yönetici Onay Modu (FilterAdministratorToken) (CWE-250)
        if not spec.uac.filter_administrator_token:
            # 20 puan kırılır
            score -= 20.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="Yerleşik Yönetici Onay Modu (Admin Approval Mode) Kapalı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-250",
                mitre_technique_id="T1548.002",
                current_value=False,
                recommended_value=True,
                description="FilterAdministratorToken=0. Yerleşik Administrator hesabı UAC onay istemi olmadan doğrudan tam yetki token'ı alır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord"
            ))

        # 1.3 Güvenli Masaüstü Zorunluluğu (PromptOnSecureDesktop) (CWE-284)
        if not spec.uac.prompt_on_secure_desktop:
            # 15 puan kırılır
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="UAC Güvenli Masaüstü İstemi (PromptOnSecureDesktop) Devre Dışı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-284",
                mitre_technique_id="T1548.002",
                current_value=False,
                recommended_value=True,
                description="PromptOnSecureDesktop=0. UAC onay pencereleri normal masaüstünde açılmakta ve SendKeys/Clickjacking saldırılarına maruz kalmaktadır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord"
            ))

        # 1.4 Yöneticiler için Yükseltme Davranışı (ConsentPromptBehaviorAdmin) (CWE-250)
        # Güvenli değerler: 2 (Prompt for consent on secure desktop) veya 1 (Prompt for credentials)
        # 0 (Elevate without prompting) veya 5 (Prompt for consent for non-Windows binaries) güvensiz kabul edilir
        if spec.uac.consent_prompt_behavior_admin in [0, 4, 5]:
            # 15 puan kırılır
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="Yöneticiler için Zayıf UAC Yükseltme İstemi Davranışı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-250",
                mitre_technique_id="T1548.002",
                current_value=spec.uac.consent_prompt_behavior_admin,
                recommended_value=2,
                description=f"ConsentPromptBehaviorAdmin={spec.uac.consent_prompt_behavior_admin}. Yöneticiler için UAC onayı yetersizdir; otomatik yükseltmeye veya sessiz atlamaya açıktır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord"
            ))

        # 1.5 Standart Kullanıcılar için Yükseltme Davranışı (ConsentPromptBehaviorUser) (CWE-284)
        # CIS Tavsiyesi: 0 (Automatically deny elevation requests) veya 3 (Prompt for credentials on secure desktop)
        # 1 (Prompt for credentials normal desktop) güvensiz kabul edilir
        if spec.uac.consent_prompt_behavior_user not in [0, 3]:
            # 10 puan kırılır
            score -= 10.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="Standart Kullanıcılar için Güvensiz Yükseltme İstemi",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-284",
                mitre_technique_id="T1548.002",
                current_value=spec.uac.consent_prompt_behavior_user,
                recommended_value=0,
                description=f"ConsentPromptBehaviorUser={spec.uac.consent_prompt_behavior_user}. Standart kullanıcılar yerel yönetici parolası girerek işlem yükseltmeye teşvik edilmemelidir (0=Otomatik Reddet önerilir).",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord"
            ))

        # 1.6 Sanallaştırma (EnableVirtualization) (CWE-1188)
        if not spec.uac.enable_virtualization:
            # 5 puan kırılır
            score -= 5.0
            findings.append(UACAuditFinding(
                finding_id=f"FIND-UAC-{secrets.token_hex(3).upper()}",
                title="Dosya ve Kayıt Defteri Yazma Sanallaştırması (EnableVirtualization) Kapalı",
                severity=AuditSeverity.LOW,
                cwe_id="CWE-1188",
                mitre_technique_id="T1083",
                current_value=False,
                recommended_value=True,
                description="Eski uygulamaların sistem alanlarına yazma denemelerinin kullanıcı dizinine sanallaştırılması kapatılmıştır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableVirtualization' -Value 1 -Type DWord"
            ))

        # ====================================================================
        # 2. YEREL HESAP GÜVENLİĞİ DENETİMLERİ
        # ====================================================================

        # 2.1 Yerleşik Guest Hesabı Durumu (CWE-284 / MITRE T1078.003)
        if spec.accounts.guest_account_enabled:
            # 20 puan kırılır
            score -= 20.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-ACC-{secrets.token_hex(3).upper()}",
                title="Yerleşik Konuk (Guest) Hesabı Etkin",
                severity=AuditSeverity.CRITICAL,
                cwe_id="CWE-284",
                mitre_technique_id="T1078.003 (Local Accounts)",
                current_value="Aktif (Enabled)",
                recommended_value="Devre Dışı (Disabled)",
                description="Yerel Guest hesabı açık bırakılmıştır. Parolasız oturum açma ve anonim ağ keşfi için kullanılabilir.",
                powershell_remediation="Disable-LocalUser -Name 'Guest'"
            ))

        # 2.2 Yerleşik Administrator Adı ve Durumu (CWE-1188)
        norm_admin_name = spec.accounts.builtin_admin_name.strip().lower()
        if norm_admin_name == "administrator" and not spec.accounts.builtin_admin_disabled:
            # Yeniden adlandırılmamış ve açık bırakılmışsa 15 puan kırılır
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append(UACAuditFinding(
                finding_id=f"FIND-ACC-{secrets.token_hex(3).upper()}",
                title="Yerleşik Administrator Hesabı Varsayılan Adda ve Etkin",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-1188",
                mitre_technique_id="T1078.003",
                current_value="Ad: Administrator (Etkin)",
                recommended_value="Yeniden Adlandırılmalı ve Devre Dışı Bırakılmalı",
                description="SID 500 nolu yerleşik yönetici hesabı 'Administrator' adıyla aktiftir. Kaba kuvvet ve parola püskürtme saldırılarına açıktır.",
                powershell_remediation="Rename-LocalUser -Name 'Administrator' -NewName 'SecAdmin_Local'; Disable-LocalUser -Name 'SecAdmin_Local'"
            ))

        # 2.3 Parola Kilitleme Eşiği (Account Lockout Threshold) (CWE-307)
        if spec.accounts.account_lockout_threshold == 0 or spec.accounts.account_lockout_threshold > 5:
            # 10 puan kırılır
            score -= 10.0
            findings.append(UACAuditFinding(
                finding_id=f"FIND-ACC-{secrets.token_hex(3).upper()}",
                title="Hatalı Oturum Açma Kilitleme Eşiği Yetersiz veya Sıfır",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-307",
                mitre_technique_id="T1110 (Brute Force)",
                current_value=spec.accounts.account_lockout_threshold,
                recommended_value="<= 5 Geçersiz Deneme",
                description="Hesap kilitleme eşiği 0 ise saldırgan sınırsız parola denemesi yapabilir (Brute Force koruması eksik).",
                powershell_remediation="net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15"
            ))

        # 2.4 Windows LAPS Durumu (CWE-1188 / MITRE T1078.003)
        if not spec.accounts.laps_enabled:
            # 10 puan kırılır
            score -= 10.0
            findings.append(UACAuditFinding(
                finding_id=f"FIND-ACC-{secrets.token_hex(3).upper()}",
                title="Windows LAPS (Local Administrator Password Solution) Etkin Değil",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-1188",
                mitre_technique_id="T1078.003",
                current_value=False,
                recommended_value=True,
                description="Yerel yönetici parolaları merkezi olarak döndürülmemekte; yanal ilerlemede (Pass-the-Hash) statik parola riski taşımaktadır.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LAPS' -Name 'BackupDirectory' -Value 1 -Type DWord"
            ))

        # ====================================================================
        # 3. YEREL GRUP ÜYELİKLERİ VE YETKİ FAZLALIĞI (CWE-250)
        # ====================================================================

        for member in spec.groups.administrators_members:
            norm_member = member.strip().upper()
            if norm_member in self.UNAUTHORIZED_ADMIN_USERS:
                # 20 puan kırılır
                score -= 20.0
                findings.append(UACAuditFinding(
                    finding_id=f"FIND-GRP-{secrets.token_hex(3).upper()}",
                    title=f"Yerel Yöneticiler Grubunda Yetkisiz Üye: '{member}'",
                    severity=AuditSeverity.CRITICAL,
                    cwe_id="CWE-250",
                    mitre_technique_id="T1078.003",
                    current_value=member,
                    recommended_value="Gruptan Kaldırılmalıdır",
                    description=f"Genel veya anonim hesap/grup ({member}) doğrudan yerel Yöneticiler grubuna eklenmiştir.",
                    powershell_remediation=f"Remove-LocalGroupMember -Group 'Administrators' -Member '{member}'"
                ))

        for rdp_member in spec.groups.remote_desktop_members:
            norm_rdp = rdp_member.strip().upper()
            if norm_rdp in ["EVERYONE", "USERS", "AUTHENTICATED USERS", "GUEST"]:
                # 15 puan kırılır
                score -= 15.0
                findings.append(UACAuditFinding(
                    finding_id=f"FIND-GRP-{secrets.token_hex(3).upper()}",
                    title=f"Uzak Masaüstü Grubunda Geniş Erişim Üyesi: '{rdp_member}'",
                    severity=AuditSeverity.HIGH,
                    cwe_id="CWE-284",
                    mitre_technique_id="T1021.001 (Remote Desktop Protocol)",
                    current_value=rdp_member,
                    recommended_value="Gruptan Kaldırılmalıdır",
                    description=f"'{rdp_member}' grubuna RDP hakkı verilmesi tüm kullanıcıların makineye uzaktan bağlanabilmesine yol açar.",
                    powershell_remediation=f"Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member '{rdp_member}'"
                ))

        # ====================================================================
        # SKOR VE DURUŞ HESAPLAMA
        # ====================================================================

        final_score = round(max(0.0, min(100.0, score)), 2)

        if final_score >= 85.0:
            posture = "SIKILAŞTIRILMIŞ / CIS UYUMLU (PASS)"
        elif final_score >= 50.0:
            posture = "ORTA_RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            posture = "KRİTİK_ZAFİYET (SAVUNMASIZ DURUMDA)"

        # PowerShell düzeltme betiğini derliyoruz
        remediation_lines = [
            "# ====================================================================",
            "# WINDOWS YEREL HESAPLAR VE UAC CIS BENCHMARK SERTLEŞTİRME BETİĞİ",
            f"# Hedef Sistem: {spec.target_host} | Oluşturulma: {timestamp}",
            "# ====================================================================",
            "",
            "# 1. Kullanıcı Hesabı Denetimi (UAC) Politikalarını Sıkılaştırma",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'FilterAdministratorToken' -Value 1 -Type DWord",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type DWord",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableVirtualization' -Value 1 -Type DWord",
            "",
            "# 2. Yerel Hesap Güvenliği ve Kilitleme Politikaları",
            "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue",
            "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
            ""
        ]

        # Varsa münferit yetkisiz üye kaldırma komutlarını ekliyoruz
        group_findings = [f for f in findings if f.cwe_id in ["CWE-250", "CWE-284"] and "Gruptan" in str(f.recommended_value)]
        if group_findings:
            remediation_lines.append("# 3. Hassas Gruplardaki Yetkisiz Üyeleri Temizleme")
            for gf in group_findings:
                remediation_lines.append(gf.powershell_remediation)
            remediation_lines.append("")

        remediation_lines.extend([
            "Write-Host '[+] Windows Yerel Hesaplar ve UAC CIS Sıkılaştırması Başarıyla Tamamlandı!' -ForegroundColor Green"
        ])

        full_script = "\n".join(remediation_lines)

        # Sonuç nesnesini oluşturuyoruz
        result = UACAuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            target_host=spec.target_host,
            security_score=final_score,
            posture_status=posture,
            findings=findings,
            remediation_script=full_script
        )

        # Kütüğe ekliyoruz
        self.audit_log.append({
            "audit_id": audit_id,
            "host": spec.target_host,
            "score": final_score,
            "findings_count": len(findings)
        })

        return result

    def export_markdown_report(self, result: UACAuditResult) -> str:
        """Denetim sonucunu Markdown rapor formatında dışa aktarır."""
        lines: List[str] = [
            f"# WINDOWS YEREL HESAPLAR, GRUPLAR VE UAC DENETİM RAPORU",
            f"**Hedef Sistem:** `{result.target_host}`  ",
            f"**Denetim Kimliği:** `{result.audit_id}`  ",
            f"**Tarih / Saat:** `{result.timestamp}`  ",
            f"**Denetçi Otoritesi:** `{self.auditor_name}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Güvenlik Skoru",
            "",
            f"- **UAC ve Hesap Güvenlik Skoru:** `{result.security_score} / 100`",
            f"- **Duruş Durumu:** **{result.posture_status}**",
            f"- **Tespit Edilen Güvenlik Açıklığı:** `{len(result.findings)} Adet`",
            "",
            "---",
            "",
            "## 2. Tespit Edilen Zafiyet ve Risk Tablosu",
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
            lines.append("| - | - | Temiz (CIS Windows Benchmark standartlarına tam uygundur) | - | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. PowerShell Otomatik Sıkılaştırma (Hardening) Betiği",
            "",
            "```powershell",
            result.remediation_script,
            "```",
            "",
            "---",
            "",
            "> [!NOTE]",
            "> Bu denetim raporu **CIS Microsoft Windows 11 Benchmark v3.0.0 (Section 2.3)** ve **MITRE ATT&CK T1548.002 / T1078.003** standartlarına dayalı olarak üretilmiştir."
        ])

        return "\n".join(lines)
