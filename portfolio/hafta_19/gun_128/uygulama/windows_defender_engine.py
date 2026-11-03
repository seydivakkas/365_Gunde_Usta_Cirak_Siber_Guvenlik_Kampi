# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 128: WINDOWS GÜVENLİK MERKEZİ VE DEFENDER SERTLEŞTİRME MOTORU
-----------------------------------------------------------------
Bu motor; Microsoft Defender Antivirus, Attack Surface Reduction (ASR) kuralları,
Kurcalama Koruması (Tamper Protection), Bulut Koruması ve Hariç Tutma (Exclusion)
politikalarını CIS Microsoft Windows Benchmark standartlarına göre teftiş eder,
zafiyetleri CWE/MITRE kodlarıyla puanlar ve PowerShell düzeltme betikleri üretir.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem parametreleri ve arama yolu için sys modülü
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

class DefenderAuditEngineError(Exception):
    """Defender denetim motoru temel istisna sınıfı."""
    pass


class InvalidPreferenceError(DefenderAuditEngineError):
    """Geçersiz veya bozuk Defender yapılandırma verisi girildiğinde fırlatılır."""
    pass


class CriticalDefenderDisarmError(DefenderAuditEngineError):
    """Defender'ın gerçek zamanlı korumasının tamamen kapatıldığı tespit edildiğinde fırlatılır (CWE-693)."""
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


class ASRAction(Enum):
    """Attack Surface Reduction (ASR) Kuralı Eylem Durumu."""
    DISABLED = 0
    BLOCK = 1
    AUDIT = 2
    WARN = 6


@dataclass
class DefenderPreferences:
    """Microsoft Defender yapılandırma parametreleri veri modeli."""
    # Gerçek zamanlı koruma kapalı mı? (Varsayılan: False olmalıdır; True ise zafiyettir)
    disable_realtime_monitoring: bool = False
    # Davranışsal izleme kapalı mı? (Varsayılan: False)
    disable_behavior_monitoring: bool = False
    # İndirilen dosyaların taranması (IOAV) kapalı mı?
    disable_ioav_protection: bool = False
    # Kurcalama Koruması (Tamper Protection) devrede mi?
    tamper_protection_active: bool = False
    # Bulut koruma seviyesi ('Disabled', 'Basic', 'High', 'HighPlus', 'ZeroTolerance')
    cloud_protection_level: str = "Basic"
    # Örnek gönderim izni ('NeverSend', 'SendAllSamples', 'SendSafeSamples')
    submit_samples_consent: str = "SendSafeSamples"
    # İstenmeyen yazılım koruması (PUAProtection: 'Disabled', 'Enabled', 'AuditMode')
    pua_protection: str = "Disabled"
    # Fidye yazılımı klasör koruması (ControlledFolderAccess: 'Disabled', 'Enabled', 'AuditMode')
    controlled_folder_access: str = "Disabled"
    # Ağ koruması (NetworkProtection: 'Disabled', 'Enabled', 'AuditMode')
    network_protection: str = "Disabled"
    # Hariç tutulan dosya yolları listesi (ExclusionPaths)
    exclusion_paths: List[str] = field(default_factory=list)
    # Hariç tutulan dosya uzantıları listesi (ExclusionExtensions)
    exclusion_extensions: List[str] = field(default_factory=list)
    # Hariç tutulan süreç adları listesi (ExclusionProcesses)
    exclusion_processes: List[str] = field(default_factory=list)
    # ASR kuralları ve durumları haritası (GUID -> ASRAction int değeri)
    asr_rules_map: Dict[str, int] = field(default_factory=dict)


@dataclass
class DefenderAuditFinding:
    """Tespit edilen münferit Defender zafiyet veya yanlış yapılandırma bulgusu."""
    finding_id: str                      # Benzersiz bulgu kimliği
    title: str                           # Zafiyet başlığı
    severity: AuditSeverity              # Ciddiyet seviyesi
    cwe_id: str                          # İlgili CWE zafiyet kodu
    mitre_technique_id: str              # MITRE ATT&CK teknik kodu (örn: T1562.001)
    current_value: Any                   # Mevcut yapılandırma değeri
    recommended_value: Any               # Önerilen güvenli değer
    description: str                     # Zafiyet ayrıntısı
    powershell_remediation: str          # PowerShell düzeltme komutu


@dataclass
class DefenderAuditResult:
    """Defender denetimi nihai sonuç karnesi."""
    audit_id: str                        # Denetim kimliği
    timestamp: str                       # Denetim zaman damgası
    target_host: str                     # Hedef makine adı
    defender_security_score: float       # 0-100 Güvenlik Skoru (100 = Kusursuz CIS Uyumu)
    posture_status: str                  # 'SIKILAŞTIRILMIŞ (PASS)', 'ORTA_RİSK', 'KRİTİK_ZAFİYET'
    findings: List[DefenderAuditFinding] # Bulgular listesi
    remediation_script: str              # Tam PowerShell sıkılaştırma betiği


# ============================================================================
# ÇEKİRDEK DEFENDER DENETİM VE SERTLEŞTİRME MOTORU
# ============================================================================

class WindowsDefenderAuditEngine:
    """
    Microsoft Defender ve Windows Güvenlik Merkezi Denetim Motoru.
    CIS Microsoft Windows 11 / Server Baseline ve MITRE ATT&CK ilkelerine göre
    uç nokta koruma mekanizmalarını teftiş eder.
    """

    # En kritik Attack Surface Reduction (ASR) kuralları ve GUID tanımları
    CRITICAL_ASR_RULES: Dict[str, str] = {
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "Office uygulamalarının alt süreç başlatmasını engelle",
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": "LSASS bellek alanından kimlik bilgisi çalınmasını engelle",
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": "E-posta istemcilerinden yürütülebilir içerik çalışmasını engelle",
        "3B576C88-A8D9-4467-9781-CE450E586364": "PSExec ve WMI komutlarından süreç oluşturulmasını engelle",
        "5BEB8E28-82E8-4337-BCB8-D4CB72E45278": "Gizlenmiş/Karartılmış (Obfuscated) betiklerin çalışmasını engelle",
        "D3E037E1-3EB8-44C8-A917-57927947596D": "JavaScript/VBScript'in indirilen yürütülebilir dosyaları çalıştırmasını engelle",
        "C1DB55AB-C21A-4637-BB3F-A12568109D35": "Fidye yazılımlarına karşı gelişmiş koruma kullan"
    }

    # Güvensiz/Tehlikeli kabul edilen aşırı geniş hariç tutma (exclusion) kalıpları
    DANGEROUS_EXCLUSIONS: Set[str] = {
        "C:\\", "C:\\*", "*", "C:\\WINDOWS", "C:\\WINDOWS\\*",
        "C:\\USERS", "C:\\PROGRAMDATA", "TEMP", "TMP",
        "*.EXE", "*.DLL", "*.BAT", "*.PS1", "*.VBS"
    }

    def __init__(self, auditor_name: str = "Enterprise Defender Hardener"):
        """Motoru başlatır."""
        # Denetçi unvanını atıyoruz
        self.auditor_name = auditor_name
        # Denetim kütüklerini tutan liste
        self.audit_log: List[Dict[str, Any]] = []

    def audit_preferences(
        self,
        target_host: str,
        prefs: DefenderPreferences
    ) -> DefenderAuditResult:
        """
        Defender tercihlerini CIS standartlarına göre teftiş eder,
        bulguları üretir, skor hesaplar ve PowerShell düzeltme betiği derler.
        """
        # Benzersiz denetim kimliği üretiyoruz
        audit_id = f"AUD-DEF-{secrets.token_hex(4).upper()}"
        # Zaman damgasını alıyoruz
        timestamp = datetime.now().isoformat()
        # Bulgular listesini başlatıyoruz
        findings: List[DefenderAuditFinding] = []
        # Başlangıç güvenlik puanı (100 üzerinden kırılacak)
        score = 100.0

        # 1. GERÇEK ZAMANLI KORUMA DENETİMİ (CWE-693 / MITRE T1562.001)
        if prefs.disable_realtime_monitoring:
            # En kritik güvenlik mekanizması kapatılmışsa 40 puan kırıyoruz
            score -= 40.0
            # Kritik bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Defender Gerçek Zamanlı Koruma (Real-Time Protection) Devre Dışı",
                severity=AuditSeverity.CRITICAL,
                cwe_id="CWE-693",
                mitre_technique_id="T1562.001 (Impair Defenses: Disable or Modify Tools)",
                current_value=True,
                recommended_value=False,
                description="DisableRealtimeMonitoring=$true olarak ayarlanmıştır. Antivirüs motoru dosyaları çalıştırma anında taramamaktadır.",
                powershell_remediation="Set-MpPreference -DisableRealtimeMonitoring $false"
            ))

        # 2. DAVRANIŞSAL İZLEME (BEHAVIOR MONITORING) DENETİMİ (CWE-693)
        if prefs.disable_behavior_monitoring:
            # 20 puan kırıyoruz
            score -= 20.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Davranışsal İzleme (Behavior Monitoring) Kapalı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-693",
                mitre_technique_id="T1562.001",
                current_value=True,
                recommended_value=False,
                description="Zararlı yazılımların davranış kalıpları (örneğin dosya şifreleme, enjeksiyon) gerçek zamanlı izlenmemektedir.",
                powershell_remediation="Set-MpPreference -DisableBehaviorMonitoring $false"
            ))

        # 3. İNDİRİLEN DOSYALARIN TARANMASI (IOAV PROTECTION) (CWE-693)
        if prefs.disable_ioav_protection:
            # 15 puan kırıyoruz
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="İnternet ve E-posta İndirmeleri Taraması (IOAV) Kapalı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-693",
                mitre_technique_id="T1566 (Phishing)",
                current_value=True,
                recommended_value=False,
                description="Tarayıcı ve e-posta istemcilerinden indirilen ekler disk üzerine yazılırken ön kontrolden geçirilmemektedir.",
                powershell_remediation="Set-MpPreference -DisableIOAVProtection $false"
            ))

        # 4. KURCALAMA KORUMASI (TAMPER PROTECTION) DENETİMİ (CWE-693)
        if not prefs.tamper_protection_active:
            # 25 puan kırıyoruz
            score -= 25.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Defender Kurcalama Koruması (Tamper Protection) Devre Dışı",
                severity=AuditSeverity.CRITICAL,
                cwe_id="CWE-693",
                mitre_technique_id="T1562.001 (Impair Defenses)",
                current_value=False,
                recommended_value=True,
                description="Yerel yönetici yetkisi elde eden zararlı yazılım PowerShell veya Kayıt Defteri üzerinden Defender ayarlarını kapatabilir.",
                powershell_remediation="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features' -Name 'TamperProtection' -Value 5 -Type DWord"
            ))

        # 5. BULUT KORUMASI VE ÖRNEK GÖNDERİMİ (CWE-1188 / MITRE T1027)
        if prefs.cloud_protection_level in ["Disabled", "Basic"]:
            # 10 puan kırıyoruz
            score -= 10.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Bulut Teslimatlı Koruma Seviyesi Yetersiz",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-1188",
                mitre_technique_id="T1027",
                current_value=prefs.cloud_protection_level,
                recommended_value="HighPlus",
                description="Microsoft MAPS bulut istihbarat seviyesi 'HighPlus' veya 'ZeroTolerance' olarak ayarlanmalıdır (Sıfır Gün Tehdit Koruması).",
                powershell_remediation="Set-MpPreference -CloudBlockLevel HighPlus"
            ))

        # 6. POTANSİYEL İSTENMEYEN UYGULAMALAR (PUA / PUP) KORUMASI (CWE-1188)
        if prefs.pua_protection != "Enabled":
            # 10 puan kırıyoruz
            score -= 10.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="İstenmeyen Yazılım Koruması (PUA Protection) Kapalı",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-1188",
                mitre_technique_id="T1489",
                current_value=prefs.pua_protection,
                recommended_value="Enabled",
                description="Kripto madenciler, reklam yazılımları ve istenmeyen araç çubukları engellenmemektedir.",
                powershell_remediation="Set-MpPreference -PUAProtection Enabled"
            ))

        # 7. AĞ KORUMASI (NETWORK PROTECTION) (CWE-319 / MITRE T1071)
        if prefs.network_protection != "Enabled":
            # 10 puan kırıyoruz
            score -= 10.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Ağ Koruması (Network Protection) Etkin Değil",
                severity=AuditSeverity.MEDIUM,
                cwe_id="CWE-319",
                mitre_technique_id="T1071",
                current_value=prefs.network_protection,
                recommended_value="Enabled",
                description="Uç noktanın C2 (Komuta Kontrol) sunucularına veya bilinen zararlı IP/Domain adreslerine giden trafiği engellenmemektedir.",
                powershell_remediation="Set-MpPreference -EnableNetworkProtection Enabled"
            ))

        # 8. FİDYE YAZILIMI VE KLASÖR KORUMASI (CONTROLLED FOLDER ACCESS) (CWE-693 / MITRE T1486)
        if prefs.controlled_folder_access != "Enabled":
            # 15 puan kırıyoruz
            score -= 15.0
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-DEF-{secrets.token_hex(3).upper()}",
                title="Denetimli Klasör Erişimi (Fidye Yazılımı Koruması) Kapalı",
                severity=AuditSeverity.HIGH,
                cwe_id="CWE-693",
                mitre_technique_id="T1486 (Data Encrypted for Impact)",
                current_value=prefs.controlled_folder_access,
                recommended_value="Enabled",
                description="Yetkisiz uygulamaların Belgelere, Masaüstüne ve Resimler klasörüne doğrudan yazması engellenmemektedir.",
                powershell_remediation="Set-MpPreference -EnableControlledFolderAccess Enabled"
            ))

        # 9. GÜVENSİZ HARİÇ TUTMALAR (EXCLUSION ABUSE) (CWE-732 / MITRE T1562.001)
        for ep in prefs.exclusion_paths:
            # Yolu büyük harfe çevirip boşlukları alıyoruz
            norm_ep = ep.strip().upper()
            # Tehlikeli kalıplardan biriyle eşleşiyor mu?
            if norm_ep in self.DANGEROUS_EXCLUSIONS or norm_ep.startswith("C:\\") and len(norm_ep) <= 4:
                # 20 puan kırıyoruz
                score -= 20.0
                # Bulgu ekliyoruz
                findings.append(DefenderAuditFinding(
                    finding_id=f"FIND-EXCL-{secrets.token_hex(3).upper()}",
                    title=f"Kritik Güvensiz Hariç Tutma Yolu: '{ep}'",
                    severity=AuditSeverity.CRITICAL,
                    cwe_id="CWE-732",
                    mitre_technique_id="T1562.001 (Impair Defenses)",
                    current_value=ep,
                    recommended_value="Hariç Tutma Kaldırılmalıdır",
                    description=f"Aşırı geniş hariç tutma yolu ({ep}), saldırganların bu konuma koydukları hiçbir zararlının taranmamasına yol açar.",
                    powershell_remediation=f"Remove-MpPreference -ExclusionPath '{ep}'"
                ))

        for ext in prefs.exclusion_extensions:
            # Uzantıyı kontrol ediyoruz
            norm_ext = ext.strip().upper()
            if norm_ext in self.DANGEROUS_EXCLUSIONS or norm_ext in [".EXE", ".DLL", ".BAT", ".PS1", ".VBS"]:
                # 20 puan kırıyoruz
                score -= 20.0
                # Bulgu ekliyoruz
                findings.append(DefenderAuditFinding(
                    finding_id=f"FIND-EXCL-EXT-{secrets.token_hex(3).upper()}",
                    title=f"Kritik Güvensiz Hariç Tutma Uzantısı: '{ext}'",
                    severity=AuditSeverity.CRITICAL,
                    cwe_id="CWE-732",
                    mitre_technique_id="T1562.001",
                    current_value=ext,
                    recommended_value="Hariç Tutma Kaldırılmalıdır",
                    description=f"'{ext}' uzantılı dosyaların taranmaması, yürütülebilir zararlıların denetimsiz çalışmasına sebep olur.",
                    powershell_remediation=f"Remove-MpPreference -ExclusionExtension '{ext}'"
                ))

        # 10. ATTACK SURFACE REDUCTION (ASR) KURALLARI DENETİMİ (CWE-358)
        missing_or_disabled_asr: List[str] = []
        for guid, rule_name in self.CRITICAL_ASR_RULES.items():
            # Kural haritada var mı ve 'Block' (1) modunda mı?
            action = prefs.asr_rules_map.get(guid, ASRAction.DISABLED.value)
            if action != ASRAction.BLOCK.value:
                # Eksik listesine ekliyoruz
                missing_or_disabled_asr.append(f"{rule_name} (GUID: {guid})")

        if missing_or_disabled_asr:
            # Eksik oranına göre puan kırıyoruz
            penalty = min(25.0, len(missing_or_disabled_asr) * 4.0)
            score -= penalty
            # Bulgu ekliyoruz
            findings.append(DefenderAuditFinding(
                finding_id=f"FIND-ASR-{secrets.token_hex(3).upper()}",
                title=f"ASR Kuralları Eksik veya Blok Modunda Değil ({len(missing_or_disabled_asr)} Kural)",
                severity=AuditSeverity.HIGH if len(missing_or_disabled_asr) > 2 else AuditSeverity.MEDIUM,
                cwe_id="CWE-358",
                mitre_technique_id="T1566 / T1059 / T1003",
                current_value=f"{len(self.CRITICAL_ASR_RULES) - len(missing_or_disabled_asr)} / {len(self.CRITICAL_ASR_RULES)} Aktif",
                recommended_value="Tüm Kritik ASR Kuralları Block (1) Modunda Olmalıdır",
                description="Attack Surface Reduction (ASR) kuralları devre dışı veya yalnızca denetim (audit) modundadır.",
                powershell_remediation="Set-MpPreference -AttackSurfaceReductionRules_Ids @('" + "','".join(self.CRITICAL_ASR_RULES.keys()) + "') -AttackSurfaceReductionRules_Actions @(" + ",".join(["Enabled"] * len(self.CRITICAL_ASR_RULES)) + ")"
            ))

        # Puanın 0 ile 100 arasında kalmasını sağlıyoruz
        final_score = round(max(0.0, min(100.0, score)), 2)

        # Güvenlik duruş seviyesini belirliyoruz
        if final_score >= 85.0:
            posture = "SIKILAŞTIRILMIŞ / CIS UYUMLU (PASS)"
        elif final_score >= 50.0:
            posture = "ORTA_RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            posture = "KRİTİK_ZAFİYET (SAVUNMASIZ DURUMDA)"

        # PowerShell düzeltme betiğini derliyoruz
        remediation_lines = [
            "# ====================================================================",
            "# MICROSOFT DEFENDER CIS BENCHMARK SERTLEŞTİRME BETİĞİ",
            f"# Hedef Sistem: {target_host} | Oluşturulma: {timestamp}",
            "# ====================================================================",
            "",
            "# 1. Temel Koruma ve Davranışsal İzleme Etkinleştirme",
            "Set-MpPreference -DisableRealtimeMonitoring $false",
            "Set-MpPreference -DisableBehaviorMonitoring $false",
            "Set-MpPreference -DisableIOAVProtection $false",
            "",
            "# 2. Bulut Koruması, PUA ve Ağ Koruması Sıkılaştırma",
            "Set-MpPreference -MAPSReporting Advanced",
            "Set-MpPreference -CloudBlockLevel HighPlus",
            "Set-MpPreference -SubmitSamplesConsent SendSafeSamples",
            "Set-MpPreference -PUAProtection Enabled",
            "Set-MpPreference -EnableNetworkProtection Enabled",
            "Set-MpPreference -EnableControlledFolderAccess Enabled",
            ""
        ]

        # Varsa tehlikeli hariç tutmaları kaldırma komutları ekliyoruz
        if any(f.cwe_id == "CWE-732" for f in findings):
            remediation_lines.append("# 3. Tehlikeli Hariç Tutma Listelerini Temizleme")
            for f in findings:
                if f.cwe_id == "CWE-732":
                    remediation_lines.append(f.powershell_remediation)
            remediation_lines.append("")

        # ASR kurallarını blok moduna alma komutları
        asr_joined_guids = "', '".join(self.CRITICAL_ASR_RULES.keys())
        asr_joined_actions = ",".join(["1"] * len(self.CRITICAL_ASR_RULES))
        remediation_lines.extend([
            "# 4. Kritik Attack Surface Reduction (ASR) Kurallarını Blok Moduna Alma",
            f"$asrGuids = @('{asr_joined_guids}')",
            f"$asrActions = @({asr_joined_actions})",
            "Set-MpPreference -AttackSurfaceReductionRules_Ids $asrGuids -AttackSurfaceReductionRules_Actions $asrActions",
            "",
            "Write-Host '[+] Microsoft Defender CIS Sıkılaştırması Başarıyla Tamamlandı!' -ForegroundColor Green"
        ])

        full_script = "\n".join(remediation_lines)

        # Sonuç nesnesini oluşturuyoruz
        result = DefenderAuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            target_host=target_host,
            defender_security_score=final_score,
            posture_status=posture,
            findings=findings,
            remediation_script=full_script
        )

        # Kütüğe ekliyoruz
        self.audit_log.append({
            "audit_id": audit_id,
            "host": target_host,
            "score": final_score,
            "findings_count": len(findings)
        })

        # Sonucu döndürüyoruz
        return result

    def export_markdown_report(self, result: DefenderAuditResult) -> str:
        """Denetim sonucunu Markdown rapor formatında dışa aktarır."""
        # Satırlar listesi
        lines: List[str] = [
            f"# MICROSOFT DEFENDER VE GÜVENLİK MERKEZİ DENETİM RAPORU",
            f"**Hedef Sistem:** `{result.target_host}`  ",
            f"**Denetim Kimliği:** `{result.audit_id}`  ",
            f"**Tarih / Saat:** `{result.timestamp}`  ",
            f"**Denetçi Otoritesi:** `{self.auditor_name}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Defender Güvenlik Skoru",
            "",
            f"- **Defender Güvenlik Skoru:** `{result.defender_security_score} / 100`",
            f"- **Duruş Durumu:** **{result.posture_status}**",
            f"- **Tespit Edilen Zafiyet/Açıklık:** `{len(result.findings)} Adet`",
            "",
            "---",
            "",
            "## 2. Tespit Edilen Güvenlik Açıklıkları",
            "",
            "| No | Ciddiyet | Zafiyet Başlığı | CWE | MITRE ATT&CK | Mevcut Değer | Önerilen Değer |",
            "|---|---|---|---|---|---|---|"
        ]

        # Bulguları tabloya ekliyoruz
        if result.findings:
            for idx, f in enumerate(result.findings, start=1):
                lines.append(
                    f"| {idx} | **{f.severity.value}** | {f.title} | `{f.cwe_id}` | `{f.mitre_technique_id}` | `{f.current_value}` | `{f.recommended_value}` |"
                )
        else:
            lines.append("| - | - | Temiz (Defender CIS standartlarına tam uygundur) | - | - | - | - |")

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
            "> Bu denetim raporu **CIS Microsoft Windows 11 Benchmark v3.0.0** ve **Microsoft Security Baselines** tavsiyelerine dayalı olarak üretilmiştir."
        ])

        # Metni birleştiriyoruz
        return "\n".join(lines)
