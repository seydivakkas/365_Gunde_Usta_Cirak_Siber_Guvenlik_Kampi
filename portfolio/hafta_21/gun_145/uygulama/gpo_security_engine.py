# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 145: Group Policy Güvenlik Etkileri ve Sertleştirme Motoru.
Active Directory Group Policy Objects (GPO) güvenlik mimarisini, miras (inheritance)
ve LSDOU öncelik sırasını, SYSVOL cpassword (MS14-025) açıklarını, GPO ACL yetkilendirme
suistimallerini (WriteDacl/WriteGPLink), LAPS yapılandırmasını ve CIS güvenlik kıstaslarını denetler.
"""

# JSON veri formatı ayrıştırma ve kaydetme modülü içe aktarılır.
import json
# Zaman damgaları ve denetim süreleri için datetime modülü içe aktarılır.
import datetime
# Veri yapılarını nesne yönelimli ve tip güvenli tanımlamak için dataclass içe aktarılır.
from dataclasses import dataclass, field
# Tip ipuçları ve statik analiz desteği için typing bileşenleri içe aktarılır.
from typing import Dict, List, Optional, Any, Set, Tuple
# Numaralandırma yapıları için Enum sınıfı içe aktarılır.
from enum import Enum
# Regex desen eşleştirme için re modülü içe aktarılır.
import re


class GpoLinkScope(str, Enum):
    """
    GPO'nun bağlandığı AD konteyner hiyerarşisi kapsamı (LSDOU).
    """
    LOCAL = "LOCAL"       # Yerel Bilgisayar İlkesi
    SITE = "SITE"         # Active Directory Sitesi
    DOMAIN = "DOMAIN"     # Etki Alanı Kökü (Default Domain Policy)
    OU = "OU"             # Organizasyonel Birim (Organizational Unit)


class SeverityLevel(str, Enum):
    """
    Tespit edilen güvenlik bulgusunun ciddiyet derecesi.
    """
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class GpoPolicyItem:
    """
    Tek bir GPO nesnesi ve barındırdığı ayarları temsil eden veri yapısı.
    """
    # GPO'nun benzersiz GUID değeri (Örn: {31B2F340-016D-11D2-945F-00C04FB984F9})
    guid: str
    # GPO'nun anlaşılır adı (Örn: 'Default Domain Policy', 'CIS-Workstations-Baseline')
    display_name: str
    # Bağlantı kapsamı (DOMAIN, OU, SITE)
    scope: GpoLinkScope
    # Bağlı olduğu hedef konteyner yolu (Örn: 'OU=Workstations,DC=kurum,DC=local')
    target_path: str
    # İlkenin 'Enforced' (NoOverride - Miras ezilemez) olup olmadığı bayrağı
    is_enforced: bool = False
    # İlkenin aktif olup olmadığı bayrağı
    is_enabled: bool = True
    # GPO üzerindeki yetkiler (Principal -> İzinler listesi, örn: 'WriteDacl', 'GenericAll')
    acl_permissions: Dict[str, List[str]] = field(default_factory=dict)
    # SYSVOL tercih dosyalarında cpassword içerip içermediği
    has_cpassword_leak: bool = False
    # LAPS ilkesini (Local Administrator Password Solution) etkinleştirip etkinleştirmediği
    enforces_laps: bool = False
    # Kullanıcı Hakları Atamaları (User Rights Assignment)
    user_rights: Dict[str, List[str]] = field(default_factory=dict)
    # Güvenlik Filtrelemesi (Security Filtering) hedef grupları
    security_filtering: List[str] = field(default_factory=lambda: ["Authenticated Users"])
    # Başlangıç ve Oturum Açma betikleri listesi
    scripts: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class GpoSecurityFinding:
    """
    GPO denetimi sırasında tespit edilen somut bir güvenlik açığını temsil eder.
    """
    # Kural veya bulgu kodu (Örn: 'GPO-SYSVOL-01')
    rule_id: str
    # Bulguyu tanımlayan başlık
    title: str
    # Ciddiyet seviyesi (CRITICAL, HIGH, MEDIUM, LOW)
    severity: SeverityLevel
    # Denetim kategorisi (SYSVOL_SECURITY, INHERITANCE_LSDOU, ACL_DELEGATION, LAPS, RIGHTS)
    category: str
    # Durum (PASS / FAIL)
    status: str
    # Detaylı teknik açıklama ve etki analizi
    description: str
    # İhlale neden olan ilgili GPO veya konteyner adı
    affected_target: str
    # Kurumsal düzeltici eylem ve sertleştirme önerisi
    remediation: str


@dataclass
class GpoAuditSummary:
    """
    Group Policy güvenlik denetiminin konsolide sonuç özeti.
    """
    # Denetlenen etki alanı adı
    domain_name: str
    # Denetim tarihi (ISO 8601)
    audit_timestamp: str
    # Genel güvenlik skoru (0 - 100)
    security_score: float
    # Toplam denetlenen kural sayısı
    total_checks: int
    # Başarılı kural sayısı
    passed_checks: int
    # Başarısız kural sayısı
    failed_checks: int
    # Kritik seviyedeki açık sayısı
    critical_findings_count: int
    # Üretilen tüm bulguların listesi
    findings: List[GpoSecurityFinding] = field(default_factory=list)


class GpoSecurityEngine:
    """
    Group Policy Güvenlik Etkileri ve Sertleştirme Analiz Motoru.
    GPO miras kurallarını, LSDOU öncelik sırasını, SYSVOL cpassword zafiyetlerini,
    yetkisiz GPO izinlerini ve LAPS uyumluluğunu uçtan uca denetler.
    """

    def __init__(self, spec_data: Dict[str, Any]):
        """
        Motoru kurumsal GPO konfigürasyon spesifikasyonu ile başlatır.
        """
        # Gelen konfigürasyon sözlüğü kaydedilir.
        self.spec: Dict[str, Any] = spec_data
        # Etki alanı adı alınır veya varsayılan atanır.
        self.domain_name: str = spec_data.get("domain", "kurum.local")
        # GPO nesnelerinin listesini ayrıştırır.
        self.gpos: List[GpoPolicyItem] = self._parse_gpos(spec_data.get("gpo_list", []))
        # Organizasyonel Birim (OU) yapısını ayrıştırır.
        self.ou_structure: Dict[str, Dict[str, Any]] = spec_data.get("organizational_units", {})

    def _parse_gpos(self, raw_gpo_list: List[Dict[str, Any]]) -> List[GpoPolicyItem]:
        """
        Ham JSON sözlüklerinden tip güvenli GpoPolicyItem nesneleri üretir.
        """
        parsed: List[GpoPolicyItem] = []
        for g in raw_gpo_list:
            item = GpoPolicyItem(
                guid=g.get("guid", "{00000000-0000-0000-0000-000000000000}"),
                display_name=g.get("display_name", "Unnamed GPO"),
                scope=GpoLinkScope(g.get("scope", "OU")),
                target_path=g.get("target_path", ""),
                is_enforced=g.get("is_enforced", False),
                is_enabled=g.get("is_enabled", True),
                acl_permissions=g.get("acl_permissions", {}),
                has_cpassword_leak=g.get("has_cpassword_leak", False),
                enforces_laps=g.get("enforces_laps", False),
                user_rights=g.get("user_rights", {}),
                security_filtering=g.get("security_filtering", ["Authenticated Users"]),
                scripts=g.get("scripts", [])
            )
            parsed.append(item)
        return parsed

    def evaluate_lsdou_effective_policies(self, target_ou_dn: str) -> List[Tuple[str, bool]]:
        """
        Hedef bir OU için LSDOU (Local -> Site -> Domain -> OU) kuralına göre
        etkin (effective) GPO sırasını ve Enforced durumlarını hesaplar.
        """
        effective_chain: List[Tuple[str, bool]] = []
        
        # 1. Domain Seviyesindeki GPO'lar eklenir (LSDOU'da Domain, OU'dan önce işlenir)
        for gpo in self.gpos:
            if gpo.scope == GpoLinkScope.DOMAIN and gpo.is_enabled:
                effective_chain.append((gpo.display_name, gpo.is_enforced))

        # 2. OU Miras Engelleme (Block Inheritance) kontrolü
        ou_info = self.ou_structure.get(target_ou_dn, {})
        block_inheritance = ou_info.get("block_inheritance", False)

        if block_inheritance:
            # Miras engellenmişse, yalnızca 'Enforced' (NoOverride) olan üst ilkeler kalır!
            effective_chain = [item for item in effective_chain if item[1]]

        # 3. Hedef OU'ya bağlı doğrudan GPO'lar eklenir (En son OU işlenir ve üsttekileri ezer)
        for gpo in self.gpos:
            if gpo.scope == GpoLinkScope.OU and gpo.target_path.lower() == target_ou_dn.lower() and gpo.is_enabled:
                effective_chain.append((gpo.display_name, gpo.is_enforced))

        return effective_chain

    def audit_sysvol_cpassword_leak(self) -> GpoSecurityFinding:
        """
        SYSVOL Tercih Dosyalarında (GPP) cpassword Açığını Denetler (MS14-025, CWE-312).
        """
        leaking_gpos: List[str] = []
        for gpo in self.gpos:
            if gpo.has_cpassword_leak:
                leaking_gpos.append(f"{gpo.display_name} ({gpo.guid})")

        if leaking_gpos:
            return GpoSecurityFinding(
                rule_id="GPO-SYSVOL-01",
                title="SYSVOL Tercih Dosyalarında Şifreli Parola (cpassword) Sızıntısı",
                severity=SeverityLevel.CRITICAL,
                category="SYSVOL_SECURITY",
                status="FAIL",
                description=(
                    f"Aşağıdaki GPO'ların XML dosyalarında (Groups.xml / ScheduledTasks.xml) cpassword alanı tespit edildi: "
                    f"{', '.join(leaking_gpos)}. Microsoft AES anahtarı genel erişime açık olduğundan tüm etki alanı kullanıcıları "
                    f"bu parolayı anında çözebilir (MS14-025)."
                ),
                affected_target="SYSVOL Tercih Dosyaları",
                remediation=(
                    "İlgili GPP ayarını siliniz, SYSVOL geçmişini temizleyiniz ve sızan hesapların parolalarını derhal sıfırlayınız. "
                    "KB2962486 yamasını doğrulayınız."
                )
            )
        
        return GpoSecurityFinding(
            rule_id="GPO-SYSVOL-01",
            title="SYSVOL Tercih Dosyalarında cpassword Sızıntısı Bulunmadı",
            severity=SeverityLevel.INFO,
            category="SYSVOL_SECURITY",
            status="PASS",
            description="Tüm GPO XML dosyaları temiz. Sabit kodlanmış cpassword anahtarı tespit edilmedi.",
            affected_target="SYSVOL",
            remediation="Mevcut temiz durumu koruyunuz ve GPP ile asla yerel parola dağıtmayınız."
        )

    def audit_gpo_delegation_abuse(self) -> GpoSecurityFinding:
        """
        GPO Konteyner İzinlerini ve Yetkilendirme Suistimali (WriteDacl / GenericAll) Risklerini Denetler.
        """
        dangerous_permissions = {"writedacl", "writeowner", "genericall", "genericwrite", "writeproperty"}
        unauthorized_principals = {"authenticated users", "domain users", "everyone", "domain computers"}
        vulnerabilities: List[str] = []

        for gpo in self.gpos:
            for principal, perms in gpo.acl_permissions.items():
                p_lower = principal.lower()
                perms_lower = {p.lower() for p in perms}
                if p_lower in unauthorized_principals:
                    intersect = perms_lower.intersection(dangerous_permissions)
                    if intersect:
                        vulnerabilities.append(
                            f"{gpo.display_name} -> {principal} ({', '.join(intersect)})"
                        )

        if vulnerabilities:
            return GpoSecurityFinding(
                rule_id="GPO-ACL-01",
                title="GPO Üzerinde Standart Kullanıcılara Tehlikeli Yazma/Sahiplik İzni",
                severity=SeverityLevel.CRITICAL,
                category="ACL_DELEGATION",
                status="FAIL",
                description=(
                    f"Standart kullanıcı gruplarına GPO değiştirme yetkisi verilmiş: {'; '.join(vulnerabilities)}. "
                    f"Saldırgan GPO içine kötü amaçlı startup script veya zamanlanmış görev ekleyerek etki alanındaki tüm "
                    f"bilgisayarlarda SYSTEM haklarıyla kod çalıştırabilir (GPO Hijacking)."
                ),
                affected_target="GPO ACL Delegasyonu",
                remediation=(
                    "Standart gruplardan Write/Modify izinlerini kaldırınız. Yalnızca Domain Admins ve Enterprise Admins "
                    "gruplarına tam denetim (Full Control) hakkı tanıyınız."
                )
            )

        return GpoSecurityFinding(
            rule_id="GPO-ACL-01",
            title="GPO İzinleri ve Delegasyon Modeli Güvenli",
            severity=SeverityLevel.INFO,
            category="ACL_DELEGATION",
            status="PASS",
            description="Standart gruplara tehlikeli GPO değiştirme izni verilmemiş. Yetkiler yönetici gruplarıyla sınırlı.",
            affected_target="GPO ACL Delegasyonu",
            remediation="Mevcut sıkı ACL yapısını periyodik olarak denetlemeye devam ediniz."
        )

    def audit_laps_enforcement(self) -> GpoSecurityFinding:
        """
        Yerel Yönetici Parola Çözümü (LAPS) İlkesinin Etkinliğini Denetler.
        """
        laps_active = any(g.enforces_laps and g.is_enabled for g in self.gpos)

        if not laps_active:
            return GpoSecurityFinding(
                rule_id="GPO-LAPS-01",
                title="Yerel Yönetici Parola Çözümü (LAPS) İlkesi Bulunamadı",
                severity=SeverityLevel.HIGH,
                category="LAPS",
                status="FAIL",
                description=(
                    "Etki alanında iş istasyonları ve sunucular için Microsoft LAPS veya Windows LAPS ilkesi tanımlanmamış. "
                    "Bu durum tüm uç noktalarda aynı yerel yönetici parolasının kullanılmasına ve Pass-the-Hash ile yatay sıçramaya (Lateral Movement) yol açar."
                ),
                affected_target="Local Administrator Accounts",
                remediation=(
                    "Windows LAPS ilkesini GPO üzerinden yapılandırınız. Yerel yönetici parolalarının her makinede karmaşık, "
                    "benzersiz ve 30 günde bir otomatik rotasyona tabi tutulmasını sağlayınız."
                )
            )

        return GpoSecurityFinding(
            rule_id="GPO-LAPS-01",
            title="Windows LAPS İlkesi Aktif ve Zorunlu",
            severity=SeverityLevel.INFO,
            category="LAPS",
            status="PASS",
            description="Etki alanında LAPS ilkesi uygulanıyor. Yerel yönetici parolaları rastgele ve merkezi olarak yönetiliyor.",
            affected_target="LAPS GPO",
            remediation="LAPS parola okuma yetkisini yalnızca Tier 1 / Tier 2 yetkili destek gruplarına veriniz."
        )

    def audit_user_rights_assignment(self) -> GpoSecurityFinding:
        """
        Kullanıcı Hakları Atamalarını (User Rights Assignment) Denetler (SeDebugPrivilege vb.).
        """
        critical_privileges = ["sedebugprivilege", "setakeownershipprivilege", "seloaddriverprivilege"]
        unauthorized_groups = {"everyone", "authenticated users", "domain users", "users"}
        violations: List[str] = []

        for gpo in self.gpos:
            for right_name, principals in gpo.user_rights.items():
                r_lower = right_name.lower()
                if r_lower in critical_privileges:
                    for p in principals:
                        if p.lower() in unauthorized_groups:
                            violations.append(f"{gpo.display_name}: {right_name} -> {p}")

        if violations:
            return GpoSecurityFinding(
                rule_id="GPO-URA-01",
                title="Ayrıcalıklı Sistem Hakları Standart Gruplara Atanmış",
                severity=SeverityLevel.HIGH,
                category="RIGHTS",
                status="FAIL",
                description=(
                    f"Kritik işletim sistemi ayrıcalıkları standart gruplara atanmış: {', '.join(violations)}. "
                    f"Örneğin SeDebugPrivilege yetkisine sahip kullanıcılar LSASS bellek dökümü alarak parola özetlerini çalabilir."
                ),
                affected_target="User Rights Assignment",
                remediation="SeDebugPrivilege ve SeTakeOwnershipPrivilege haklarını yalnızca yerel Administrators grubuna sınırlayınız."
            )

        return GpoSecurityFinding(
            rule_id="GPO-URA-01",
            title="Kullanıcı Hakları Atamaları (URA) Standartlara Uygun",
            severity=SeverityLevel.INFO,
            category="RIGHTS",
            status="PASS",
            description="Tehlikeli işletim sistemi hakları standart kullanıcılardan arındırılmış.",
            affected_target="User Rights Assignment",
            remediation="CIS Windows Server Benchmark standartlarına uygun kısıtlamaları koruyunuz."
        )

    def audit_gpo_scripts_security(self) -> GpoSecurityFinding:
        """
        Başlangıç (Startup) ve Oturum Açma (Logon) Betiklerinin Güvenliğini Denetler.
        """
        insecure_scripts: List[str] = []
        for gpo in self.gpos:
            for sc in gpo.scripts:
                path = sc.get("path", "")
                # HTTP veya doğrulanmamış dış ağ paylaşımı denetimi
                if path.startswith("http://") or path.startswith("ftp://"):
                    insecure_scripts.append(f"{gpo.display_name} -> Güvensiz protokol: {path}")
                elif "\\\\" in path and "sysvol" not in path.lower() and "netlogon" not in path.lower():
                    insecure_scripts.append(f"{gpo.display_name} -> Standart dışı ağ paylaşımı: {path}")

        if insecure_scripts:
            return GpoSecurityFinding(
                rule_id="GPO-SCRIPT-01",
                title="GPO Betiklerinde Güvensiz Yol veya Protokol Kullanımı",
                severity=SeverityLevel.MEDIUM,
                category="SCRIPTS",
                status="FAIL",
                description=(
                    f"Aşağıdaki GPO'lar korumasız yollardan betik çağırmaktadır: {'; '.join(insecure_scripts)}. "
                    f"Ağ içi saldırgan bu paylaşım veya protokolü manipüle ederek zararlı kod enjekte edebilir."
                ),
                affected_target="GPO Scripts",
                remediation="Tüm başlangıç ve oturum betiklerini yalnızca imzalanmış SYSVOL veya NETLOGON klasörlerinde saklayınız."
            )

        return GpoSecurityFinding(
            rule_id="GPO-SCRIPT-01",
            title="GPO Betik Yolları Güvenli ve Bütünlüklü",
            severity=SeverityLevel.INFO,
            category="SCRIPTS",
            status="PASS",
            description="Tüm betikler güvenli SYSVOL/NETLOGON dizinlerinde barındırılıyor veya harici güvensiz yol kullanılmıyor.",
            affected_target="GPO Scripts",
            remediation="Betik dosyalarının dijital imzalarını düzenli olarak doğrulayınız."
        )

    def run_full_gpo_audit(self) -> GpoAuditSummary:
        """
        Tüm GPO güvenlik denetim kurallarını koşturur ve özet raporu üretir.
        """
        findings: List[GpoSecurityFinding] = [
            self.audit_sysvol_cpassword_leak(),
            self.audit_gpo_delegation_abuse(),
            self.audit_laps_enforcement(),
            self.audit_user_rights_assignment(),
            self.audit_gpo_scripts_security()
        ]

        # Skorlama hesabı (Her kritik açık -30, yüksek açık -20, orta açık -10)
        score = 100.0
        passed_count = 0
        failed_count = 0
        critical_count = 0

        for f in findings:
            if f.status == "PASS":
                passed_count += 1
            else:
                failed_count += 1
                if f.severity == SeverityLevel.CRITICAL:
                    score -= 30.0
                    critical_count += 1
                elif f.severity == SeverityLevel.HIGH:
                    score -= 20.0
                elif f.severity == SeverityLevel.MEDIUM:
                    score -= 10.0
                elif f.severity == SeverityLevel.LOW:
                    score -= 5.0

        score = max(0.0, score)

        return GpoAuditSummary(
            domain_name=self.domain_name,
            audit_timestamp=datetime.datetime.now().isoformat(),
            security_score=score,
            total_checks=len(findings),
            passed_checks=passed_count,
            failed_checks=failed_count,
            critical_findings_count=critical_count,
            findings=findings
        )
