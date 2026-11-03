# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Mini Proje 18: Bütünleşik Windows Güvenlik Denetim ve Raporlama Motoru.

Bu modül; Hafta 19 boyunca işlenen beş temel Windows güvenlik alanını
(Defender, UAC & Yerel Hesaplar, NTFS Erişim Listeleri, Windows Firewall ve
Windows Hizmet Güvenliği) tek bir orkestrasyon motoru altında birleştirir.
CIS Microsoft Windows Benchmark ve MITRE ATT&CK standartlarında kurumsal
denetim skorları ve otomatik PowerShell iyileştirme yönergeleri üretir.
"""

# Veri sınıfları oluşturmak için dataclass dekoratörü içe aktarılıyor
from dataclasses import dataclass, field
# Tip güvenliği için gerekli typing modülleri içe aktarılıyor
from typing import Dict, List, Optional, Tuple, Any
# Metin deseni ve regex işlemleri için re modülü içe aktarılıyor
import re
# Dosya ve işletim sistemi yol fonksiyonları için os modülü içe aktarılıyor
import os
# JSON veri yapılarını ayrıştırmak ve dışa aktarmak için json modülü içe aktarılıyor
import json
# Zaman damgası üretimi için datetime kütüphanesi içe aktarılıyor
from datetime import datetime, timezone


@dataclass
class DomainFinding:
    """Tekil bir denetim alanı zafiyet bulgusunu temsil eden veri modeli."""
    # Hangi güvenlik alanına ait olduğu (DEFENDER, UAC, NTFS, FIREWALL, SERVICE)
    domain: str
    # Zafiyetin ait olduğu bileşen veya nesne adı
    target_name: str
    # İlgili CWE (Common Weakness Enumeration) kimliği
    cwe_id: str
    # İlgili MITRE ATT&CK taktik/teknik kimliği
    mitre_id: str
    # Önem derecesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Zafiyet başlığı
    title: str
    # Teknik detay ve etki açıklaması
    description: str
    # Düzeltici PowerShell veya komut satırı aksiyonu
    remediation: str
    # Bu alanın puanından düşülecek ceza puanı
    penalty: float


@dataclass
class DomainScore:
    """Tekil bir denetim alanının puan kartı özeti."""
    # Alan adı
    domain_name: str
    # Alınan ham puan (20.0 üzerinden)
    score: float
    # Maksimum alan puanı
    max_score: float = 20.0
    # Alandaki toplam zafiyet sayısı
    vulnerability_count: int = 0
    # Uyum durumu: COMPLIANT, WARNING, CRITICAL
    status: str = "COMPLIANT"


class WindowsAuditPlatformEngine:
    """
    Bütünleşik Windows Güvenlik Denetim, Puanlama ve Raporlama Platformu Motoru.
    
    5 Temel Güvenlik Alanı (Her biri 20 puan, Toplam 100 puan):
    1. Windows Defender ve Uç Nokta Koruması
    2. Yerel Hesaplar, Gruplar ve UAC
    3. NTFS Erişim Kontrol Listeleri (DACL / İzinler)
    4. Windows Firewall Profilleri ve Port Maruziyeti
    5. Windows Hizmet Güvenliği (SCM, Tırnaksız Yollar, DACL)
    """

    def __init__(self) -> None:
        """Denetim motorunu başlatır ve veri yapılarını hazırlar."""
        # Toplam sistem puanı (100.0 üzerinden)
        self.overall_score: float = 100.0
        # Tüm alanlardan toplanan zafiyet listesi
        self.all_findings: List[DomainFinding] = []
        # Alan bazında skorları saklayan sözlük
        self.domain_scores: Dict[str, DomainScore] = {}
        # Yürütülen denetimin genel sonuç raporu
        self.audit_report: Dict[str, Any] = {}

    def audit_defender_domain(self, defender_spec: Dict[str, Any]) -> Tuple[float, List[DomainFinding]]:
        """
        Alan 1: Windows Defender ve Uç Nokta Koruması Denetimi (20 Puan).
        """
        # Başlangıç alan puanı
        score = 20.0
        findings: List[DomainFinding] = []

        # Gerçek Zamanlı Koruma (Real-Time Protection)
        if not defender_spec.get("real_time_protection_enabled", True):
            score -= 10.0
            findings.append(
                DomainFinding(
                    domain="DEFENDER",
                    target_name="RealTimeProtection",
                    cwe_id="CWE-693",
                    mitre_id="T1562.001",
                    severity="CRITICAL",
                    title="Defender Gerçek Zamanlı Koruma Devre Dışı",
                    description="Windows Defender gerçek zamanlı koruma mekanizması kapalıdır.",
                    remediation="Set-MpPreference -DisableRealtimeMonitoring $false",
                    penalty=10.0,
                )
            )

        # Davranış İzleme (Behavior Monitoring)
        if not defender_spec.get("behavior_monitoring_enabled", True):
            score -= 4.0
            findings.append(
                DomainFinding(
                    domain="DEFENDER",
                    target_name="BehaviorMonitoring",
                    cwe_id="CWE-693",
                    mitre_id="T1562.001",
                    severity="HIGH",
                    title="Davranışsal İzleme Motoru Kapalı",
                    description="Zararlı yazılım süreç davranışlarını analiz eden motor devre dışıdır.",
                    remediation="Set-MpPreference -DisableBehaviorMonitoring $false",
                    penalty=4.0,
                )
            )

        # Kurcalama Koruması (Tamper Protection)
        if not defender_spec.get("tamper_protection_enabled", True):
            score -= 3.0
            findings.append(
                DomainFinding(
                    domain="DEFENDER",
                    target_name="TamperProtection",
                    cwe_id="CWE-693",
                    mitre_id="T1562.001",
                    severity="HIGH",
                    title="Kurcalama Koruması (Tamper Protection) Kapalı",
                    description="Saldırganlar kayıt defterinden güvenlik ayarlarını değiştirebilir.",
                    remediation="Windows Güvenlik Merkezi üzerinden Tamper Protection özelliğini aktifleştirin.",
                    penalty=3.0,
                )
            )

        # İstenmeyen Potansiyel Uygulama Koruması (PUA Protection)
        if defender_spec.get("pua_protection", 0) != 1:
            score -= 3.0
            findings.append(
                DomainFinding(
                    domain="DEFENDER",
                    target_name="PUAProtection",
                    cwe_id="CWE-693",
                    mitre_id="T1562.001",
                    severity="MEDIUM",
                    title="PUA / PUP Koruması Etkin Değil",
                    description="İstenmeyen potansiyel yazılım ve reklam yazılımları engellenmemektedir.",
                    remediation="Set-MpPreference -PUAProtection Enabled",
                    penalty=3.0,
                )
            )

        # Puanın sıfırın altına düşmesi engellenir
        score = max(0.0, round(score, 2))
        return score, findings

    def audit_uac_domain(self, uac_spec: Dict[str, Any]) -> Tuple[float, List[DomainFinding]]:
        """
        Alan 2: Yerel Hesaplar, Gruplar ve UAC Denetimi (20 Puan).
        """
        score = 20.0
        findings: List[DomainFinding] = []

        # UAC Anahtarı (EnableLUA)
        if uac_spec.get("enable_lua", 1) != 1:
            score -= 10.0
            findings.append(
                DomainFinding(
                    domain="UAC",
                    target_name="EnableLUA",
                    cwe_id="CWE-250",
                    mitre_id="T1548.002",
                    severity="CRITICAL",
                    title="Kullanıcı Hesabı Denetimi (UAC) Tamamen Devre Dışı",
                    description="EnableLUA=0 yapılandırması Split-Token korumasını kaldırır.",
                    remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1",
                    penalty=10.0,
                )
            )

        # Yönetici Onay Modu (ConsentPromptBehaviorAdmin)
        consent_admin = uac_spec.get("consent_prompt_behavior_admin", 2)
        if consent_admin == 0:
            score -= 4.0
            findings.append(
                DomainFinding(
                    domain="UAC",
                    target_name="ConsentPromptBehaviorAdmin",
                    cwe_id="CWE-250",
                    mitre_id="T1548.002",
                    severity="HIGH",
                    title="Yöneticiler İçin UAC Onay İstemi Kapalı (Sessiz Yükseltme)",
                    description="ConsentPromptBehaviorAdmin=0 iken süreçler kullanıcıya sormadan tam yetki alır.",
                    remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2",
                    penalty=4.0,
                )
            )

        # Güvenli Masaüstü (PromptOnSecureDesktop)
        if uac_spec.get("prompt_on_secure_desktop", 1) != 1:
            score -= 3.0
            findings.append(
                DomainFinding(
                    domain="UAC",
                    target_name="PromptOnSecureDesktop",
                    cwe_id="CWE-284",
                    mitre_id="T1548.002",
                    severity="MEDIUM",
                    title="UAC İstemi Güvenli Masaüstünde Açılmıyor",
                    description="Kullanıcı masaüstünde açılan pencereler UI spoofing saldırılarına açıktır.",
                    remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'PromptOnSecureDesktop' -Value 1",
                    penalty=3.0,
                )
            )

        # Yerel Konuk (Guest) Hesabı Durumu
        if uac_spec.get("guest_account_enabled", False):
            score -= 3.0
            findings.append(
                DomainFinding(
                    domain="UAC",
                    target_name="GuestAccount",
                    cwe_id="CWE-284",
                    mitre_id="T1078.001",
                    severity="MEDIUM",
                    title="Yerel Guest (Konuk) Hesabı Etkin",
                    description="Konuk hesabı yetkisiz anonim oturumlara imkan tanır.",
                    remediation="Disable-LocalUser -Name 'Guest'",
                    penalty=3.0,
                )
            )

        score = max(0.0, round(score, 2))
        return score, findings

    def audit_ntfs_domain(self, ntfs_spec: Dict[str, Any]) -> Tuple[float, List[DomainFinding]]:
        """
        Alan 3: NTFS Erişim Kontrol Listeleri ve İzin Denetimi (20 Puan).
        """
        score = 20.0
        findings: List[DomainFinding] = []

        # Sistem Dizinlerinde Standart Kullanıcılara Yazma Hakkı (CWE-732)
        writable_sys_dirs = ntfs_spec.get("writable_system_directories_for_users", [])
        if writable_sys_dirs:
            penalty_val = min(12.0, len(writable_sys_dirs) * 6.0)
            score -= penalty_val
            dirs_str = ", ".join(writable_sys_dirs)
            findings.append(
                DomainFinding(
                    domain="NTFS",
                    target_name="SystemDirectoriesACL",
                    cwe_id="CWE-732",
                    mitre_id="T1574.009",
                    severity="CRITICAL",
                    title="Kritik Sistem Dizinlerinde Kullanıcı Yazma İzni",
                    description=f"Standart kullanıcılar şu sistem dizinlerine yazabilmektedir: {dirs_str}",
                    remediation=f"icacls \"{writable_sys_dirs[0]}\" /remove:g \"BUILTIN\\Users\" /grant:r \"BUILTIN\\Users:(RX)\"",
                    penalty=penalty_val,
                )
            )

        # Devre Dışı Bırakılmış Kalıtım (Inheritance Broken)
        if ntfs_spec.get("broken_inheritance_count", 0) > 0:
            count = ntfs_spec.get("broken_inheritance_count", 0)
            score -= 4.0
            findings.append(
                DomainFinding(
                    domain="NTFS",
                    target_name="InheritanceIntegrity",
                    cwe_id="CWE-284",
                    mitre_id="T1222.001",
                    severity="MEDIUM",
                    title="Kalıtım Bütünlüğü Bozulmuş Dizinler Mevcut",
                    description=f"Sistemde kalıtımı kesilmiş {count} adet dizin bulundu; yetki tutarsızlığı riski vardır.",
                    remediation="icacls <Dizin> /inheritance:e",
                    penalty=4.0,
                )
            )

        # Güvenlik Denetim Günlüğü (SACL) Eksikliği
        if not ntfs_spec.get("sacl_auditing_enabled", True):
            score -= 4.0
            findings.append(
                DomainFinding(
                    domain="NTFS",
                    target_name="SACLAuditing",
                    cwe_id="CWE-778",
                    mitre_id="T1083",
                    severity="LOW",
                    title="Kritik Dosyalar İçin Nesne Erişim Denetimi (SACL) Kapalı",
                    description="Hassas dosyalara yetkisiz erişim teşebbüsleri Windows Event Log'a kaydedilmemektedir.",
                    remediation="auditpol /set /subcategory:'File System' /success:enable /failure:enable",
                    penalty=4.0,
                )
            )

        score = max(0.0, round(score, 2))
        return score, findings

    def audit_firewall_domain(self, firewall_spec: Dict[str, Any]) -> Tuple[float, List[DomainFinding]]:
        """
        Alan 4: Windows Firewall Profilleri ve Port Maruziyeti (20 Puan).
        """
        score = 20.0
        findings: List[DomainFinding] = []

        # Profil Durumları (Domain, Private, Public)
        profiles = firewall_spec.get("profiles", {})
        for p_name in ["Domain", "Private", "Public"]:
            p_data = profiles.get(p_name, {})
            if not p_data.get("enabled", True):
                score -= 4.0
                findings.append(
                    DomainFinding(
                        domain="FIREWALL",
                        target_name=f"Profile_{p_name}",
                        cwe_id="CWE-284",
                        mitre_id="T1562.004",
                        severity="HIGH",
                        title=f"Windows Güvenlik Duvarı {p_name} Profili Kapalı",
                        description=f"{p_name} profili devre dışı bırakılmıştır. Ağ trafiği filtrelenmemektedir.",
                        remediation=f"Set-NetFirewallProfile -Profile {p_name} -Enabled True",
                        penalty=4.0,
                    )
                )
            elif p_data.get("default_inbound_action", "Block") != "Block":
                score -= 3.0
                findings.append(
                    DomainFinding(
                        domain="FIREWALL",
                        target_name=f"DefaultInbound_{p_name}",
                        cwe_id="CWE-284",
                        mitre_id="T1562.004",
                        severity="HIGH",
                        title=f"{p_name} Profilinde Varsayılan Gelen Eylem Block Değil",
                        description=f"Gelen bağlantılar varsayılan olarak izin verilmektedir ({p_data.get('default_inbound_action')}).",
                        remediation=f"Set-NetFirewallProfile -Profile {p_name} -DefaultInboundAction Block",
                        penalty=3.0,
                    )
                )

        # Public Profilde Kritik Port Maruziyeti (RDP, SMB, WinRM)
        public_exposed_ports = firewall_spec.get("public_exposed_ports", [])
        risky_ports = {3389: "RDP", 445: "SMB", 5985: "WinRM"}
        exposed_risks = [f"{port} ({risky_ports[port]})" for port in public_exposed_ports if port in risky_ports]
        if exposed_risks:
            score -= 5.0
            risks_str = ", ".join(exposed_risks)
            findings.append(
                DomainFinding(
                    domain="FIREWALL",
                    target_name="PublicPortExposure",
                    cwe_id="CWE-284",
                    mitre_id="T1021.001",
                    severity="CRITICAL",
                    title="Public Profilde Tehlikeli Yönetim Portları Açık",
                    description=f"Kamusal ağda şu kritik servis portları açıktır: {risks_str}",
                    remediation="Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -Profile Public",
                    penalty=5.0,
                )
            )

        score = max(0.0, round(score, 2))
        return score, findings

    def audit_services_domain(self, services_spec: Dict[str, Any]) -> Tuple[float, List[DomainFinding]]:
        """
        Alan 5: Windows Hizmet Güvenliği Denetimi (20 Puan).
        """
        score = 20.0
        findings: List[DomainFinding] = []

        services_list = services_spec.get("services", [])
        for svc in services_list:
            svc_name = svc.get("service_name", "UnknownService")
            image_path = svc.get("image_path", "").strip()

            # Kontrol 5.1: Tırnaksız Servis Yolu (CWE-428)
            if " " in image_path and not (image_path.startswith('"') and '"' in image_path[1:]):
                score -= 5.0
                findings.append(
                    DomainFinding(
                        domain="SERVICE",
                        target_name=svc_name,
                        cwe_id="CWE-428",
                        mitre_id="T1574.009",
                        severity="HIGH",
                        title=f"Tırnaksız Servis Yolu ({svc_name})",
                        description=f"'{svc_name}' hizmetinin yolu tırnaksızdır ve boşluk içerir: {image_path}",
                        remediation=f'sc.exe config "{svc_name}" binPath= "\\"{image_path}\\""',
                        penalty=5.0,
                    )
                )

            # Kontrol 5.2: Zayıf Servis DACL / SDDL İzinleri (CWE-732)
            sddl = svc.get("sddl", "")
            if ";;DC;;;BU" in sddl or ";;DC;;;WD" in sddl or ";;WD;;;BU" in sddl or ";;WD;;;WD" in sddl:
                score -= 6.0
                findings.append(
                    DomainFinding(
                        domain="SERVICE",
                        target_name=svc_name,
                        cwe_id="CWE-732",
                        mitre_id="T1543.003",
                        severity="CRITICAL",
                        title=f"Zayıf Servis DACL İzni ({svc_name})",
                        description=f"'{svc_name}' servisinde düşük yetkili kullanıcılara yapılandırma (DC) veya DACL değiştirme (WD) hakkı verilmiş.",
                        remediation=f'sc.exe sdset "{svc_name}" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"',
                        penalty=6.0,
                    )
                )

            # Kontrol 5.3: Zayıf Binary Dosya İzinleri (CWE-732)
            binary_perms = svc.get("binary_permissions", {})
            users_perms = binary_perms.get("BUILTIN\\Users", []) + binary_perms.get("Everyone", [])
            if any(r in ["Write", "Modify", "FullControl"] for r in users_perms):
                clean_path = image_path.strip().strip('"')
                score -= 5.0
                findings.append(
                    DomainFinding(
                        domain="SERVICE",
                        target_name=svc_name,
                        cwe_id="CWE-732",
                        mitre_id="T1574.010",
                        severity="CRITICAL",
                        title=f"Yazılabilir Servis İkili Dosyası ({svc_name})",
                        description=f"'{svc_name}' ikili dosyası standart kullanıcılar tarafından değiştirilebilir.",
                        remediation=f'icacls "{clean_path}" /grant:r "BUILTIN\\Users:(RX)"',
                        penalty=5.0,
                    )
                )

            # Kontrol 5.4: CIS Kapsamında Kapatılması Gereken Servis (CWE-16)
            if svc_name == "RemoteRegistry" and svc.get("start_type") != "Disabled":
                score -= 4.0
                findings.append(
                    DomainFinding(
                        domain="SERVICE",
                        target_name="RemoteRegistry",
                        cwe_id="CWE-16",
                        mitre_id="T1003.002",
                        severity="HIGH",
                        title="Riskli RemoteRegistry Servisi Aktif",
                        description="Uzaktan kayıt defteri manipülasyonu riski oluşturan servis etkindir.",
                        remediation='Set-Service -Name "RemoteRegistry" -StartupType Disabled; Stop-Service -Name "RemoteRegistry" -Force',
                        penalty=4.0,
                    )
                )

        score = max(0.0, round(score, 2))
        return score, findings

    def run_full_windows_audit(self, full_spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tüm 5 alanı sırayla denetler, ağırlıklı genel puanı hesaplar ve rapor üretir.
        """
        self.all_findings.clear()
        self.domain_scores.clear()

        # 1. Defender Alanı
        def_score, def_findings = self.audit_defender_domain(full_spec.get("defender", {}))
        self.domain_scores["DEFENDER"] = DomainScore(
            domain_name="Windows Defender ve Uç Nokta Koruması",
            score=def_score,
            vulnerability_count=len(def_findings),
            status="COMPLIANT" if def_score >= 17.0 else ("WARNING" if def_score >= 12.0 else "CRITICAL"),
        )
        self.all_findings.extend(def_findings)

        # 2. UAC & Hesaplar Alanı
        uac_score, uac_findings = self.audit_uac_domain(full_spec.get("uac_and_accounts", {}))
        self.domain_scores["UAC"] = DomainScore(
            domain_name="Yerel Hesaplar, Gruplar ve UAC",
            score=uac_score,
            vulnerability_count=len(uac_findings),
            status="COMPLIANT" if uac_score >= 17.0 else ("WARNING" if uac_score >= 12.0 else "CRITICAL"),
        )
        self.all_findings.extend(uac_findings)

        # 3. NTFS Alanı
        ntfs_score, ntfs_findings = self.audit_ntfs_domain(full_spec.get("ntfs_security", {}))
        self.domain_scores["NTFS"] = DomainScore(
            domain_name="NTFS Erişim Kontrol Listeleri",
            score=ntfs_score,
            vulnerability_count=len(ntfs_findings),
            status="COMPLIANT" if ntfs_score >= 17.0 else ("WARNING" if ntfs_score >= 12.0 else "CRITICAL"),
        )
        self.all_findings.extend(ntfs_findings)

        # 4. Firewall Alanı
        fw_score, fw_findings = self.audit_firewall_domain(full_spec.get("firewall", {}))
        self.domain_scores["FIREWALL"] = DomainScore(
            domain_name="Windows Firewall Profilleri",
            score=fw_score,
            vulnerability_count=len(fw_findings),
            status="COMPLIANT" if fw_score >= 17.0 else ("WARNING" if fw_score >= 12.0 else "CRITICAL"),
        )
        self.all_findings.extend(fw_findings)

        # 5. Servisler Alanı
        svc_score, svc_findings = self.audit_services_domain(full_spec.get("services", {}))
        self.domain_scores["SERVICE"] = DomainScore(
            domain_name="Windows Hizmet Güvenliği",
            score=svc_score,
            vulnerability_count=len(svc_findings),
            status="COMPLIANT" if svc_score >= 17.0 else ("WARNING" if svc_score >= 12.0 else "CRITICAL"),
        )
        self.all_findings.extend(svc_findings)

        # Genel Toplam Puan
        self.overall_score = round(def_score + uac_score + ntfs_score + fw_score + svc_score, 2)

        # Genel Durum
        if self.overall_score >= 85.0:
            overall_status = "COMPLIANT"
        elif self.overall_score >= 60.0:
            overall_status = "WARNING"
        else:
            overall_status = "CRITICAL"

        # Şiddet dağılımı
        severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.all_findings:
            if f.severity in severity_summary:
                severity_summary[f.severity] += 1

        # Rapor sözlüğü oluşturulur
        self.audit_report = {
            "audit_metadata": {
                "project_name": "Mini Proje 18: Windows Denetim Raporu Platformu",
                "auditor": "Seydi Eryılmaz (@seydivakkas)",
                "audit_date": datetime.now(timezone.utc).isoformat(),
                "benchmark": "CIS Microsoft Windows Server 2022 / Windows 11 Enterprise",
            },
            "overall_summary": {
                "total_score": self.overall_score,
                "max_score": 100.0,
                "overall_status": overall_status,
                "total_vulnerabilities": len(self.all_findings),
                "severity_breakdown": severity_summary,
            },
            "domain_breakdown": {
                k: {
                    "domain_name": v.domain_name,
                    "score": v.score,
                    "max_score": v.max_score,
                    "vulnerabilities": v.vulnerability_count,
                    "status": v.status,
                }
                for k, v in self.domain_scores.items()
            },
            "findings_detail": [
                {
                    "domain": f.domain,
                    "target": f.target_name,
                    "cwe_id": f.cwe_id,
                    "mitre_id": f.mitre_id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "penalty": f.penalty,
                }
                for f in self.all_findings
            ],
        }

        return self.audit_report

    def generate_master_remediation_powershell(self) -> str:
        """
        Denetim sonucunda tespit edilen tüm zafiyetler için tek parça kurumsal
        PowerShell Master Sıkılaştırma Betiği üretir.
        """
        lines = [
            "# ===========================================================================",
            "# Mini Proje 18: Bütünleşik Windows Güvenlik Sıkılaştırma Master Betiği",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas) - Tüm Hakları Saklıdır",
            "# ===========================================================================",
            "# Bu betik yükseltilmiş ayrıcalıklarla (Run as Administrator) çalıştırılmalıdır.",
            "$ErrorActionPreference = 'Continue'",
            "Write-Host '[*] Kurumsal Windows Güvenlik Sıkılaştırma Başlatılıyor...' -ForegroundColor Cyan",
            "",
        ]

        if not self.all_findings:
            lines.append("Write-Host '[+] Tebrikler! Tüm denetim alanları tam uyumludur. Müdahaleye gerek yoktur.' -ForegroundColor Green")
            return "\n".join(lines)

        # Alanlara göre gruplandırarak iyileştirme adımları yazdırılır
        domain_groups: Dict[str, List[DomainFinding]] = {}
        for f in self.all_findings:
            domain_groups.setdefault(f.domain, []).append(f)

        step_idx = 1
        for domain_key, findings in domain_groups.items():
            lines.append(f"# ---------------------------------------------------------------------------")
            lines.append(f"# BÖLÜM: {domain_key} ALANI İYİLEŞTİRMELERİ ({len(findings)} Adet)")
            lines.append(f"# ---------------------------------------------------------------------------")
            for f in findings:
                lines.append(f"# Adım {step_idx}: [{f.severity}] {f.title} ({f.cwe_id})")
                lines.append(f"Write-Host '[>] Uygulanıyor: {f.title}...' -ForegroundColor Yellow")
                lines.append(f"{f.remediation}")
                lines.append("")
                step_idx += 1

        lines.append("Write-Host '[+] Tüm Windows güvenlik alanları başarıyla sıkılaştırıldı!' -ForegroundColor Green")
        return "\n".join(lines)

    def generate_executive_markdown_report(self) -> str:
        """
        Yönetici düzeyinde teknik bulgular içeren kapsamlı Markdown denetim raporu üretir.
        """
        rep = self.audit_report
        summary = rep.get("overall_summary", {})
        domains = rep.get("domain_breakdown", {})
        findings = rep.get("findings_detail", [])

        md = [
            "# Mini Proje 18: Bütünleşik Windows Güvenlik Denetim Raporu",
            "",
            f"**Denetçi:** Seydi Eryılmaz (@seydivakkas)  ",
            f"**Tarih:** {rep.get('audit_metadata', {}).get('audit_date', '')}  ",
            f"**Standart:** {rep.get('audit_metadata', {}).get('benchmark', '')}  ",
            f"**Genel Durum:** **{summary.get('overall_status', 'UNKNOWN')}** ({summary.get('total_score', 0.0)} / 100.0)  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Alan Puan Dağılımı",
            "",
            "| Denetim Alanı | Alınan Puan | Maksimum | Zafiyet Sayısı | Alan Durumu |",
            "|---|---|---|---|---|",
        ]

        for _, d in domains.items():
            md.append(f"| **{d['domain_name']}** | {d['score']} | {d['max_score']} | {d['vulnerabilities']} | {d['status']} |")

        md.extend([
            f"| **TOPLAM** | **{summary.get('total_score', 0.0)}** | **100.0** | **{summary.get('total_vulnerabilities', 0)}** | **{summary.get('overall_status', '')}** |",
            "",
            "---",
            "",
            "## 2. Tespit Edilen Zafiyetlerin Dağılımı",
            "",
            f"- **Kritik (CRITICAL):** {summary.get('severity_breakdown', {}).get('CRITICAL', 0)}",
            f"- **Yüksek (HIGH):** {summary.get('severity_breakdown', {}).get('HIGH', 0)}",
            f"- **Orta (MEDIUM):** {summary.get('severity_breakdown', {}).get('MEDIUM', 0)}",
            f"- **Düşük (LOW):** {summary.get('severity_breakdown', {}).get('LOW', 0)}",
            "",
            "---",
            "",
            "## 3. Ayrıntılı Zafiyet Kataloğu ve İyileştirme Planı",
            "",
        ])

        if not findings:
            md.append("> [!TIP]\n> Sistemde hiçbir zafiyet tespit edilmemiştir. Uç nokta güvenlik duruşu mükemmeldir.\n")
        else:
            for idx, f in enumerate(findings, 1):
                md.append(f"### {idx}. [{f['severity']}] {f['title']}")
                md.append(f"- **Alan:** `{f['domain']}` | **Hedef:** `{f['target']}`")
                md.append(f"- **Standart:** `{f['cwe_id']}` | MITRE ATT&CK: `{f['mitre_id']}`")
                md.append(f"- **Teknik Açıklama:** {f['description']}")
                md.append(f"- **Düzeltici Aksiyon:**")
                md.append(f"  ```powershell\n  {f['remediation']}\n  ```")
                md.append("")

        return "\n".join(md)
