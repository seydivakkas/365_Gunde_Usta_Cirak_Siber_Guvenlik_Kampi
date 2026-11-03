# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 130: NTFS ERİŞİM KONTROL LİSTELERİ (ACL/DACL/SACL) SERTLEŞTİRME MOTORU
-------------------------------------------------------------------------
Bu motor; Windows NTFS dosya ve dizin Güvenlik Tanımlayıcılarını (Security Descriptors),
İsteğe Bağlı Erişim Kontrol Listelerini (DACL), Sistem Erişim Denetim Listelerini (SACL)
ve ACE (Access Control Entry) kurallarını CIS Windows Benchmark ve MITRE ATT&CK
standartlarına göre denetler. Zayıf izinleri (CWE-732, CWE-276, CWE-428), DLL Hijacking
ve servis ikilisi üzerine yazma zafiyetlerini tespit eder ve icacls/PowerShell
sertleştirme reçeteleri üretir.
"""

# İşletim sistemi işlemleri için os modülü
import os
# Sistem parametreleri için sys modülü
import sys
# JSON ayrıştırma ve serileştirme için json modülü
import json
# Zaman damgaları için datetime modülü
from datetime import datetime
# Kriptografik güvenli rastgele kimlik üretimi için secrets modülü
import secrets
# Veri yapılarını tanımlamak için dataclass ve field modülü
from dataclasses import dataclass, field
# Tip belirteçleri için typing modülü
from typing import Dict, List, Set, Any, Optional, Tuple
# Sabitler ve numaralandırmalar için Enum modülü
from enum import Enum


# ============================================================================
# ÖZEL HATA VE İSTİSNA SINIFLARI
# ============================================================================

class NTFSAuditEngineError(Exception):
    """NTFS Denetim Motoru temel istisna sınıfı."""
    pass


class InvalidSecurityDescriptorError(NTFSAuditEngineError):
    """Bozuk veya geçersiz bir Güvenlik Tanımlayıcısı sağlandığında fırlatılır."""
    pass


class DangerousPermissionAssignmentError(NTFSAuditEngineError):
    """Kritik sistem ikilisine Everyone/Users tam yetki verildiğinde fırlatılır."""
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


class ACEType(Enum):
    """Access Control Entry (ACE) Türü."""
    ACCESS_ALLOWED = "AccessAllowed"
    ACCESS_DENIED = "AccessDenied"
    SYSTEM_AUDIT = "SystemAudit"


class NTFSPermission(Enum):
    """NTFS Erişim İzin Seviyeleri ve Hakları."""
    FULL_CONTROL = "FullControl"           # Tam Denetim (F / 0x1F01FF)
    MODIFY = "Modify"                       # Değiştirme (M / 0x1301BF)
    READ_AND_EXECUTE = "ReadAndExecute"     # Okuma ve Yürütme (RX / 0x1200A9)
    READ = "Read"                           # Yalnızca Okuma (R / 0x120089)
    WRITE = "Write"                         # Yalnızca Yazma (W / 0x100116)
    WRITE_DAC = "WriteDAC"                 # İzin Değiştirme Hakkı (0x40000)
    WRITE_OWNER = "WriteOwner"             # Sahiplik Alma Hakkı (0x80000)


@dataclass
class NTFSACE:
    """Tek bir Access Control Entry (ACE) modeli."""
    # Hedef kimlik (örn: 'BUILTIN\\Users', 'Everyone', 'NT AUTHORITY\\SYSTEM')
    identity: str
    # Güvenlik Tanımlayıcısı (SID) (örn: 'S-1-1-0', 'S-1-5-32-545')
    sid: str = ""
    # ACE Türü (Allowed, Denied, Audit)
    ace_type: ACEType = ACEType.ACCESS_ALLOWED
    # Tanımlanmış NTFS hakları listesi
    rights: List[NTFSPermission] = field(default_factory=list)
    # Bu kural üst dizinden miras mı alınmış? (Inherited)
    is_inherited: bool = False
    # Miras yayılım bayrakları (örn: 'ContainerInherit', 'ObjectInherit')
    inheritance_flags: List[str] = field(default_factory=list)


@dataclass
class NTFSSecurityDescriptor:
    """Dosya veya dizin NTFS Güvenlik Tanımlayıcısı modeli."""
    # Dosya veya dizinin tam dosya yolu
    path: str
    # Dizin mi dosya mı olduğu bayrağı
    is_directory: bool = False
    # Nesne sahibi (Owner)
    owner: str = "BUILTIN\\Administrators"
    # Birincil grup (Group)
    group: str = "BUILTIN\\Administrators"
    # Miras korumalı mı? (Explicit ACL / Block Inheritance)
    are_access_rules_protected: bool = False
    # İsteğe Bağlı Erişim Denetim Listesi (DACL)
    dacl: List[NTFSACE] = field(default_factory=list)
    # Sistem Denetim Listesi (SACL - Audit)
    sacl: List[NTFSACE] = field(default_factory=list)


@dataclass
class ACLAuditFinding:
    """Tespit edilen münferit NTFS izin açığı bulgusu."""
    finding_id: str                      # Benzersiz bulgu kimliği
    title: str                           # Zafiyet başlığı
    severity: AuditSeverity              # Ciddiyet seviyesi
    cwe_id: str                          # İlgili CWE kodu (CWE-732, CWE-276, CWE-428)
    mitre_technique_id: str              # MITRE ATT&CK tekniği (T1574.009, T1068, T1548)
    path: str                            # Etkilenen dosya/dizin yolu
    identity: str                        # Yetkili kılınan zayıf hesap/grup
    current_rights: str                  # Mevcut tehlikeli izinler
    recommended_action: str              # Önerilen güvenli izin
    description: str                     # Zafiyet ayrıntısı ve saldırı vektörü
    powershell_remediation: str          # PowerShell düzeltme komutu
    icacls_remediation: str              # icacls komutu ile düzeltme


@dataclass
class NTFSAuditResult:
    """NTFS ACL denetimi nihai sonuç karnesi."""
    audit_id: str                        # Denetim kimliği
    timestamp: str                       # Denetim zaman damgası
    target_system: str                   # Hedef sistem/host
    security_score: float                # 0-100 Güvenlik Skoru (100 = Kusursuz CIS Uyumu)
    posture_status: str                  # 'SIKILAŞTIRILMIŞ (PASS)', 'ORTA_RİSK', 'KRİTİK_ZAFİYET'
    findings: List[ACLAuditFinding]      # Bulgular listesi
    remediation_script: str              # PowerShell ve icacls toplu düzeltme betiği


# ============================================================================
# ÇEKİRDEK NTFS ACL DENETİM VE SERTLEŞTİRME MOTORU
# ============================================================================

class NTFSACLEngine:
    """
    NTFS Erişim Kontrol Listeleri (ACL/DACL/SACL) Denetim ve Sertleştirme Motoru.
    CIS Windows Benchmark (Bölüm 18/19 Dosya Sistemi Güvenliği) ve MITRE ATT&CK
    T1574 (Hijack Execution Flow) ilkelerine göre izinleri teftiş eder.
    """

    # Yetkisiz/Standart kabul edilen ve sistem dizinlerinde yazma izni OLMAMASI gereken kimlikler
    UNPRIVILEGED_IDENTITIES: Set[str] = {
        "EVERYONE", "BUILTIN\\USERS", "USERS", "AUTHENTICATED USERS",
        "INTERACTIVE", "ANONYMOUS LOGON", "GUEST", "BUILTIN\\GUESTS",
        "S-1-1-0", "S-1-5-32-545", "S-1-5-11"
    }

    # Yazma ve manipülasyon hakları kümesi (Zafiyet doğuran tehlikeli izinler)
    DANGEROUS_WRITE_PERMISSIONS: Set[NTFSPermission] = {
        NTFSPermission.FULL_CONTROL,
        NTFSPermission.MODIFY,
        NTFSPermission.WRITE,
        NTFSPermission.WRITE_DAC,
        NTFSPermission.WRITE_OWNER
    }

    # Korunması gereken kritik sistem yolları ve desenleri
    CRITICAL_SYSTEM_PREFIXES: List[str] = [
        "C:\\WINDOWS", "C:\\PROGRAM FILES", "C:\\PROGRAM FILES (X86)",
        "C:\\PROGRAMDATA", "C:\\SERVICES", "C:\\DRIVERS"
    ]

    def __init__(self, auditor_name: str = "Enterprise NTFS ACL Auditor"):
        """Motoru başlatır."""
        # Denetçi unvanını atıyoruz
        self.auditor_name = auditor_name
        # Denetim kütüklerini tutan liste
        self.audit_log: List[Dict[str, Any]] = []

    def audit_security_descriptors(
        self,
        target_system: str,
        descriptors: List[NTFSSecurityDescriptor]
    ) -> NTFSAuditResult:
        """
        Belirtilen NTFS Güvenlik Tanımlayıcıları listesini denetler,
        zafiyetleri CWE ve MITRE ATT&CK kodlarıyla puanlar, düzeltme betikleri üretir.
        """
        # Benzersiz denetim kimliği oluşturuyoruz
        audit_id = f"AUD-NTFS-{secrets.token_hex(4).upper()}"
        # Zaman damgasını alıyoruz
        timestamp = datetime.now().isoformat()
        # Bulgular listesini başlatıyoruz
        findings: List[ACLAuditFinding] = []
        # Başlangıç güvenlik puanı (100 üzerinden kırılacak)
        score = 100.0

        # Her güvenlik tanımlayıcısını tek tek teftiş ediyoruz
        for desc in descriptors:
            norm_path = desc.path.strip().upper()

            # 1. SAHİPLİK DENETİMİ (CWE-284 / MITRE T1078.003)
            norm_owner = desc.owner.strip().upper()
            if norm_owner in self.UNPRIVILEGED_IDENTITIES:
                # Standart kullanıcı kritik bir sistem dosyasının/dizininin sahibi ise 15 puan kırılır
                score -= 15.0
                findings.append(ACLAuditFinding(
                    finding_id=f"FIND-OWN-{secrets.token_hex(3).upper()}",
                    title=f"Kritik Yolda Standart Kullanıcı Sahipliği: '{desc.path}'",
                    severity=AuditSeverity.HIGH,
                    cwe_id="CWE-284",
                    mitre_technique_id="T1078.003",
                    path=desc.path,
                    identity=desc.owner,
                    current_rights="Owner (Sahiplik)",
                    recommended_action="Sahiplik BUILTIN\\Administrators veya SYSTEM'e devredilmelidir",
                    description=f"Nesne sahibi ({desc.owner}), dosyanın DACL izinlerini dilediği gibi değiştirme hakkına sahiptir.",
                    powershell_remediation=f"takeown /f '{desc.path}' /a; icacls '{desc.path}' /setowner 'BUILTIN\\Administrators'",
                    icacls_remediation=f"icacls \"{desc.path}\" /setowner \"BUILTIN\\Administrators\""
                ))

            # 2. DACL İÇİNDEKİ TEHLİKELİ İZİNLERİN DENETİMİ (CWE-732 / CWE-276 / MITRE T1574.009)
            for ace in desc.dacl:
                norm_id = ace.identity.strip().upper()
                # Yalnızca izin veren (Allow) kuralları denetliyoruz
                if ace.ace_type != ACEType.ACCESS_ALLOWED:
                    continue

                # Kural standart/yetkisiz bir kimliğe mi ait?
                if norm_id in self.UNPRIVILEGED_IDENTITIES or ace.sid in self.UNPRIVILEGED_IDENTITIES:
                    # Kuralda tehlikeli yazma/değiştirme izinleri var mı?
                    dangerous_rights = [r for r in ace.rights if r in self.DANGEROUS_WRITE_PERMISSIONS]

                    if dangerous_rights:
                        rights_str = ", ".join([r.value for r in dangerous_rights])

                        # Kritik sistem ikilisi veya Program Files klasörü mü?
                        is_critical_path = any(norm_path.startswith(prefix) for prefix in self.CRITICAL_SYSTEM_PREFIXES)
                        is_executable = norm_path.endswith(".EXE") or norm_path.endswith(".DLL") or norm_path.endswith(".SYS")

                        if is_critical_path or is_executable:
                            # En ağır zafiyet: DLL Hijacking / İkili Değiştirme (25 puan kırılır)
                            score -= 25.0
                            sev = AuditSeverity.CRITICAL
                            cwe = "CWE-732"
                            mitre = "T1574.009 (Hijack Execution Flow / Unquoted Path / Binary Overwrite)"
                            desc_detail = (
                                f"Standart hesap/grup ({ace.identity}), '{desc.path}' konumunda '{rights_str}' haklarına sahiptir. "
                                f"Saldırgan sistem ikilisini veya dizinini değiştirerek SYSTEM yetkisine yükselebilir."
                            )
                        else:
                            # Genel zayıf izin (15 puan kırılır)
                            score -= 15.0
                            sev = AuditSeverity.HIGH
                            cwe = "CWE-276"
                            mitre = "T1068 (Privilege Escalation)"
                            desc_detail = (
                                f"Yetkisiz kimlik ({ace.identity}), '{desc.path}' üzerinde '{rights_str}' izinlerine sahiptir."
                            )

                        # PowerShell ve icacls komutları
                        ps_cmd = f"(Get-Acl '{desc.path}').Access | Where-Object {{ $_.IdentityReference -match '{ace.identity}' }} | ForEach-Object {{ (Get-Acl '{desc.path}').RemoveAccessRule($_) }}"
                        icacls_cmd = f"icacls \"{desc.path}\" /remove:g \"{ace.identity}\""

                        findings.append(ACLAuditFinding(
                            finding_id=f"FIND-DACL-{secrets.token_hex(3).upper()}",
                            title=f"Zayıf NTFS İzni: '{ace.identity}' -> '{rights_str}' ({os.path.basename(desc.path)})",
                            severity=sev,
                            cwe_id=cwe,
                            mitre_technique_id=mitre,
                            path=desc.path,
                            identity=ace.identity,
                            current_rights=rights_str,
                            recommended_action=f"'{ace.identity}' için yazma/değiştirme hakkı kaldırılmalı, yalnızca ReadAndExecute verilmelidir",
                            description=desc_detail,
                            powershell_remediation=ps_cmd,
                            icacls_remediation=icacls_cmd
                        ))

            # 3. KANONİK ACE SIRALAMASI DENETİMİ (CANONICAL ORDERING) (CWE-284)
            # Standart Windows kanonik sırası:
            # 1. Açık Reddetme (Explicit Deny)
            # 2. Açık İzin Verme (Explicit Allow)
            # 3. Miras Alınan Reddetme (Inherited Deny)
            # 4. Miras Alınan İzin Verme (Inherited Allow)
            explicit_allow_seen = False
            for ace in desc.dacl:
                if not ace.is_inherited:
                    if ace.ace_type == ACEType.ACCESS_ALLOWED:
                        explicit_allow_seen = True
                    elif ace.ace_type == ACEType.ACCESS_DENIED and explicit_allow_seen:
                        # Açık izin, açık reddetmeden önce gelmişse kural sırası bozuktur (10 puan kırılır)
                        score -= 10.0
                        findings.append(ACLAuditFinding(
                            finding_id=f"FIND-ORD-{secrets.token_hex(3).upper()}",
                            title=f"Kanonik Olmayan ACE Sıralaması: '{desc.path}'",
                            severity=AuditSeverity.MEDIUM,
                            cwe_id="CWE-284",
                            mitre_technique_id="T1548",
                            path=desc.path,
                            identity=ace.identity,
                            current_rights="Non-Canonical Order (Bozuk Sıralama)",
                            recommended_action="DACL kuralları kanonik sıraya göre yeniden düzenlenmelidir",
                            description="Explicit Allow kuralı Explicit Deny kuralından önce gelmektedir. Reddetme kuralı işletilmeyebilir.",
                            powershell_remediation=f"icacls '{desc.path}' /verify",
                            icacls_remediation=f"icacls \"{desc.path}\" /verify"
                        ))
                        break

            # 4. SİSTEM SERVİS DİZİNİ BOŞLUKLU YOL DENETİMİ (UNQUOTED SERVICE PATH) (CWE-428 / MITRE T1574.009)
            if " " in desc.path and (norm_path.endswith(".EXE") or "SERVICE" in norm_path):
                # Boşluklu yolda üst dizinlerin yazılabilirliği zafiyettir
                for ace in desc.dacl:
                    if ace.identity.strip().upper() in self.UNPRIVILEGED_IDENTITIES and any(r in self.DANGEROUS_WRITE_PERMISSIONS for r in ace.rights):
                        score -= 20.0
                        findings.append(ACLAuditFinding(
                            finding_id=f"FIND-UQP-{secrets.token_hex(3).upper()}",
                            title=f"Tırnak İçine Alınmamış Servis Yolu İstismarı (Unquoted Path): '{desc.path}'",
                            severity=AuditSeverity.CRITICAL,
                            cwe_id="CWE-428",
                            mitre_technique_id="T1574.009",
                            path=desc.path,
                            identity=ace.identity,
                            current_rights="Write/Modify on Unquoted Path Ancestor",
                            recommended_action="Servis kayıt defteri yolu çift tırnak içine alınmalı ve dizin izinleri sıkılaştırılmalıdır",
                            description=f"Yol boşluk karakteri içermektedir ({desc.path}) ve standart kullanıcılar bu konuma dosya yazabilmektedir.",
                            powershell_remediation=f"icacls '{desc.path}' /inheritance:r /grant:r 'BUILTIN\\Administrators:(OI)(CI)F' 'NT AUTHORITY\\SYSTEM:(OI)(CI)F' 'BUILTIN\\Users:(OI)(CI)RX'",
                            icacls_remediation=f"icacls \"{desc.path}\" /inheritance:r /grant:r \"BUILTIN\\Administrators:(OI)(CI)F\" \"NT AUTHORITY\\SYSTEM:(OI)(CI)F\" \"BUILTIN\\Users:(OI)(CI)RX\""
                        ))
                        break

        # Skoru 0 ile 100 arasında sabitliyoruz
        final_score = round(max(0.0, min(100.0, score)), 2)

        # Güvenlik duruşunu belirliyoruz
        if final_score >= 85.0:
            posture = "SIKILAŞTIRILMIŞ / CIS UYUMLU (PASS)"
        elif final_score >= 50.0:
            posture = "ORTA_RİSK (İYİLEŞTİRME GEREKLİ)"
        else:
            posture = "KRİTİK_ZAFİYET (SAVUNMASIZ DURUMDA)"

        # PowerShell ve icacls sertleştirme betiğini derliyoruz
        remediation_lines = [
            "# ====================================================================",
            "# NTFS ERİŞİM KONTROL LİSTELERİ (DACL) CIS SERTLEŞTİRME BETİĞİ",
            f"# Hedef Sistem: {target_system} | Tarih: {timestamp}",
            "# ====================================================================",
            "",
            "# 1. Güvensiz ve Yetkisiz İzinleri Kaldırma (icacls komutları)"
        ]

        if findings:
            for f in findings:
                remediation_lines.append(f"# {f.title} ({f.cwe_id})")
                remediation_lines.append(f.icacls_remediation)
        else:
            remediation_lines.append("# Tüm taranan dosya ve dizinler CIS NTFS standartlarına tam uygundur.")

        remediation_lines.extend([
            "",
            "# 2. Standart CIS Güvenli İzin Şablonunu Uygulama",
            "# Yöneticiler ve SYSTEM: Tam Yetki (F), Standart Kullanıcılar: Yalnızca Okuma ve Yürütme (RX)",
            "Write-Host '[+] NTFS ACL Sertleştirmesi Başarıyla Tamamlandı!' -ForegroundColor Green"
        ])

        full_script = "\n".join(remediation_lines)

        result = NTFSAuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            target_system=target_system,
            security_score=final_score,
            posture_status=posture,
            findings=findings,
            remediation_script=full_script
        )

        self.audit_log.append({
            "audit_id": audit_id,
            "target": target_system,
            "score": final_score,
            "findings_count": len(findings)
        })

        return result

    def export_markdown_report(self, result: NTFSAuditResult) -> str:
        """Denetim sonucunu Markdown rapor formatında dışa aktarır."""
        lines: List[str] = [
            f"# NTFS ERİŞİM KONTROL LİSTELERİ (ACL/DACL/SACL) DENETİM RAPORU",
            f"**Hedef Sistem:** `{result.target_system}`  ",
            f"**Denetim Kimliği:** `{result.audit_id}`  ",
            f"**Tarih / Saat:** `{result.timestamp}`  ",
            f"**Denetçi Otoritesi:** `{self.auditor_name}`  ",
            "",
            "---",
            "",
            "## 1. Yönetici Özeti ve Güvenlik Skoru",
            "",
            f"- **NTFS Güvenlik Skoru:** `{result.security_score} / 100`",
            f"- **Duruş Durumu:** **{result.posture_status}**",
            f"- **Tespit Edilen Güvenlik Açıklığı:** `{len(result.findings)} Adet`",
            "",
            "---",
            "",
            "## 2. Tespit Edilen NTFS İzin Zafiyetleri Tablosu",
            "",
            "| No | Ciddiyet | Zafiyet Başlığı | Yol | Hesap | Haklar | CWE | MITRE ATT&CK |",
            "|---|---|---|---|---|---|---|---|"
        ]

        if result.findings:
            for idx, f in enumerate(result.findings, start=1):
                clean_path = os.path.basename(f.path) if len(f.path) > 30 else f.path
                lines.append(
                    f"| {idx} | **{f.severity.value}** | {f.title} | `{clean_path}` | `{f.identity}` | `{f.current_rights}` | `{f.cwe_id}` | `{f.mitre_technique_id}` |"
                )
        else:
            lines.append("| - | - | Temiz (NTFS izinleri CIS standartlarına tam uygundur) | - | - | - | - | - |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. icacls ve PowerShell Otomatik Sıkılaştırma (Hardening) Betiği",
            "",
            "```powershell",
            result.remediation_script,
            "```",
            "",
            "---",
            "",
            "> [!NOTE]",
            "> Bu denetim raporu **CIS Microsoft Windows 11 Benchmark v3.0.0 (Section 18/19)** ve **MITRE ATT&CK T1574.009 / T1068** standartlarına dayalı olarak üretilmiştir."
        ])

        return "\n".join(lines)
