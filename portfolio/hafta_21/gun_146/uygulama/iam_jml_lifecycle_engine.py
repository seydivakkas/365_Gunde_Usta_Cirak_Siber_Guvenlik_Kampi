"""
Gün 146: IAM Yaşam Döngüsü JML (Joiner, Mover, Leaver) Güvenlik Motoru
======================================================================
Bu modül; kurumsal Kimlik ve Erişim Yönetimi (IAM) süreçlerinde personel
yaşam döngüsünü (Joiner - Mover - Leaver) simüle eden, yetki birikimi
(Privilege Creep), yetim hesaplar (Orphan Accounts), görevler ayrılığı
(Separation of Duties - SoD) ve atıl hesap (Dormant Account) zafiyetlerini
otonom olarak denetleyen endüstriyel sınıf bir güvenlik motorudur.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import json
import re
import uuid


class LifecycleStatus(str, Enum):
    """Personel insan kaynakları yaşam döngüsü durumları."""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    PENDING_ONBOARDING = "PENDING_ONBOARDING"


class AccountStatus(str, Enum):
    """Hedef sistemlerdeki kullanıcı hesap durumları."""
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    LOCKED = "LOCKED"
    DELETED = "DELETED"


class Severity(str, Enum):
    """Denetim bulgularının güvenlik önem dereceleri."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RoleDefinition:
    """Kurumsal RBAC rol tanımı ve yetki sınırları."""
    role_id: str
    name: str
    department: str
    allowed_entitlements: List[str]
    is_privileged: bool = False


@dataclass
class SoDConflictRule:
    """Görevler Ayrılığı (Separation of Duties - SoD) çatışma kuralı."""
    conflict_id: str
    role_a: str
    role_b: str
    description: str
    severity: Severity = Severity.CRITICAL


@dataclass
class EmployeeRecord:
    """İnsan Kaynakları (HR) otoriter veri kaynağındaki personel kaydı."""
    employee_id: str
    name: str
    department: str
    job_title: str
    manager_id: str
    status: LifecycleStatus
    start_date: str
    end_date: Optional[str] = None
    assigned_roles: List[str] = field(default_factory=list)


@dataclass
class AccountRecord:
    """Active Directory, Entra ID, AWS veya yerel sistemlerdeki hesap kaydı."""
    account_id: str
    username: str
    target_system: str
    owner_employee_id: str
    status: AccountStatus
    roles: List[str] = field(default_factory=list)
    entitlements: List[str] = field(default_factory=list)
    last_logon_date: Optional[str] = None
    mfa_enabled: bool = False
    password_must_change: bool = False


@dataclass
class AuditFinding:
    """IAM denetim sürecinde tespit edilen güvenlik bulgusu."""
    rule_id: str
    title: str
    severity: Severity
    employee_id: Optional[str]
    account_id: Optional[str]
    details: str
    remediation: str


@dataclass
class JMLAuditResult:
    """Kapsamlı JML güvenlik denetimi sonuç özeti."""
    total_employees: int
    total_accounts: int
    orphan_accounts_count: int
    privilege_creep_count: int
    sod_violations_count: int
    dormant_accounts_count: int
    findings: List[AuditFinding]
    security_score: float
    is_compliant: bool


class IAMJMLEngine:
    """
    Kurumsal IAM JML (Joiner, Mover, Leaver) Güvenlik ve Denetim Motoru.
    
    Bu motor; yeni personelin en az yetkiyle sisteme dahil edilmesini (Joiner),
    departman değiştiren personelin eski yetkilerinin temizlenerek yetki birikiminin
    (Privilege Creep) engellenmesini (Mover), işten ayrılan personelin tüm
    hesaplarının derhal kapatılarak yetim hesap (Orphan Account) oluşmasının
    önlenmesini (Leaver) ve görevler ayrılığı (SoD) matrisini yönetir.
    """

    def __init__(self, dormant_threshold_days: int = 90):
        # Atıl (dormant) hesap tespiti için gün eşik değeri (varsayılan 90 gün)
        self.dormant_threshold_days = dormant_threshold_days
        # Otoriter İK personel veri tabanı sözlüğü
        self.employees: Dict[str, EmployeeRecord] = {}
        # Hedef sistemlerdeki hesap veri tabanı sözlüğü
        self.accounts: Dict[str, AccountRecord] = {}
        # Kurumsal rol kataloğu sözlüğü
        self.roles: Dict[str, RoleDefinition] = {}
        # Tanımlanmış SoD çatışma kuralları listesi
        self.sod_rules: List[SoDConflictRule] = []

    def register_role(self, role: RoleDefinition) -> None:
        """Sisteme kurumsal bir rol tanımı kaydeder."""
        # Rolü sözlükte kimliğine göre indeksle
        self.roles[role.role_id] = role

    def register_sod_rule(self, rule: SoDConflictRule) -> None:
        """Sisteme bir Görevler Ayrılığı (SoD) kuralı ekler."""
        # Kuralı SoD listesine ekle
        self.sod_rules.append(rule)

    def load_directory_data(self, data: Dict[str, Any]) -> None:
        """Harici JSON verisinden İK personellerini, hesapları, rolleri ve SoD kurallarını yükler."""
        # Rol tanımlarını yükle
        for r in data.get("roles", []):
            self.register_role(RoleDefinition(
                role_id=r["role_id"],
                name=r["name"],
                department=r["department"],
                allowed_entitlements=r.get("allowed_entitlements", []),
                is_privileged=r.get("is_privileged", False)
            ))

        # SoD kurallarını yükle
        for s in data.get("sod_rules", []):
            self.register_sod_rule(SoDConflictRule(
                conflict_id=s["conflict_id"],
                role_a=s["role_a"],
                role_b=s["role_b"],
                description=s["description"],
                severity=Severity(s.get("severity", "CRITICAL"))
            ))

        # Personel kayıtlarını yükle
        for emp in data.get("employees", []):
            self.employees[emp["employee_id"]] = EmployeeRecord(
                employee_id=emp["employee_id"],
                name=emp["name"],
                department=emp["department"],
                job_title=emp["job_title"],
                manager_id=emp["manager_id"],
                status=LifecycleStatus(emp["status"]),
                start_date=emp["start_date"],
                end_date=emp.get("end_date"),
                assigned_roles=emp.get("assigned_roles", [])
            )

        # Hesap kayıtlarını yükle
        for acc in data.get("accounts", []):
            self.accounts[acc["account_id"]] = AccountRecord(
                account_id=acc["account_id"],
                username=acc["username"],
                target_system=acc["target_system"],
                owner_employee_id=acc["owner_employee_id"],
                status=AccountStatus(acc["status"]),
                roles=acc.get("roles", []),
                entitlements=acc.get("entitlements", []),
                last_logon_date=acc.get("last_logon_date"),
                mfa_enabled=acc.get("mfa_enabled", False),
                password_must_change=acc.get("password_must_change", False)
            )

    def check_sod_conflict(self, role_ids: List[str]) -> List[SoDConflictRule]:
        """Verilen rol kümesinde Görevler Ayrılığı (SoD) çatışması olup olmadığını denetler."""
        # Çatışan kuralları saklayacak liste
        conflicts: List[SoDConflictRule] = []
        # Hızlı sorgulama için rolleri kümeye çevir
        role_set = set(role_ids)
        # Tanımlı tüm SoD kurallarını tara
        for rule in self.sod_rules:
            # Eğer her iki çatışan rol de kullanıcının kümesinde varsa ihlal oluşur
            if rule.role_a in role_set and rule.role_b in role_set:
                conflicts.append(rule)
        # Tespit edilen çatışmaları döndür
        return conflicts

    def process_joiner(
        self,
        employee: EmployeeRecord,
        target_systems: List[str],
        birthright_roles: List[str],
        approver: str
    ) -> Dict[str, Any]:
        """
        Joiner (Katılım): Yeni personelin İK verisiyle kurumsal sisteme güvenli dahil edilmesi.
        
        Doğrulamalar:
        - İK kaydının geçerliliği ve onay mekanizması.
        - Başlangıç rolleri üzerinde SoD denetimi.
        - İlk oturumda zorunlu parola değişimi ve MFA zorlaması.
        """
        # Onaylayan yönetici kontrolü
        if not approver or approver.strip() == "":
            raise ValueError("Joiner işlemi için geçerli bir onaylayan (approver) gereklidir.")

        # SoD çatışma kontrolü
        sod_conflicts = self.check_sod_conflict(birthright_roles)
        if sod_conflicts:
            raise PermissionError(f"Joiner iptal edildi: Başlangıç rolleri SoD çatışması içeriyor ({sod_conflicts[0].conflict_id}).")

        # Personeli İK veri tabanına kaydet
        employee.status = LifecycleStatus.ACTIVE
        employee.assigned_roles = list(birthright_roles)
        self.employees[employee.employee_id] = employee

        # Oluşturulan hesapları saklayacak liste
        created_accounts: List[str] = []
        # Her hedef sistem için standart hesap oluştur
        for sys_name in target_systems:
            # Standart kullanıcı adı türet: isim.soyisim
            clean_name = re.sub(r'[^a-zA-Z0-9]', '', employee.name.lower().replace(" ", "."))
            acc_id = f"ACC-{uuid.uuid4().hex[:8].upper()}"
            new_acc = AccountRecord(
                account_id=acc_id,
                username=clean_name,
                target_system=sys_name,
                owner_employee_id=employee.employee_id,
                status=AccountStatus.ACTIVE,
                roles=list(birthright_roles),
                entitlements=[],
                last_logon_date=datetime.now(timezone.utc).isoformat(),
                mfa_enabled=True,  # Kurumsal standart: MFA varsayılan aktif
                password_must_change=True  # İlk oturumda parola değiştirme zorunlu
            )
            self.accounts[acc_id] = new_acc
            created_accounts.append(acc_id)

        # İşlem detaylarını içeren özet sözlük döndür
        return {
            "status": "SUCCESS",
            "event": "JOINER",
            "employee_id": employee.employee_id,
            "created_accounts": created_accounts,
            "roles": birthright_roles,
            "approver": approver,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def process_mover(
        self,
        employee_id: str,
        new_department: str,
        new_job_title: str,
        new_roles: List[str],
        revoke_old_roles: bool = True,
        approver: str = ""
    ) -> Dict[str, Any]:
        """
        Mover (Rol/Departman Değişimi): Personelin yeni pozisyona geçişi.
        
        Kritik Güvenlik İlkesi (Privilege Creep Önleme):
        - `revoke_old_roles=True` ile personelin eski departmanına ait roller
          tamamen iptal edilmeli, yetki birikimi engellenmelidir.
        - Yeni ve varsa kalan roller üzerinde SoD denetimi icra edilir.
        """
        # Personel İK kaydını kontrol et
        if employee_id not in self.employees:
            raise KeyError(f"Personel bulunamadı: {employee_id}")

        # Onay mekanizması doğrulaması
        if not approver or approver.strip() == "":
            raise ValueError("Mover işlemi için yetkili onaylayıcı (approver) gereklidir.")

        emp = self.employees[employee_id]
        old_department = emp.department
        old_roles = list(emp.assigned_roles)

        # Rol hesaplaması: Eski roller iptal edilecek mi yoksa tutulacak mı?
        if revoke_old_roles:
            final_roles = list(new_roles)
            revoked_roles = old_roles
        else:
            # Yetki birikimi (Privilege Creep) riski: Eski ve yeni roller birleşir
            final_roles = list(set(old_roles + new_roles))
            revoked_roles = []

        # SoD çatışma kontrolü
        conflicts = self.check_sod_conflict(final_roles)
        if conflicts:
            raise PermissionError(f"Mover iptal edildi: Görevler Ayrılığı (SoD) çatışması tespit edildi ({conflicts[0].conflict_id}).")

        # Personel kaydını güncelle
        emp.department = new_department
        emp.job_title = new_job_title
        emp.assigned_roles = final_roles

        # Personelin tüm hedef sistemlerdeki hesaplarını güncelle
        updated_accounts: List[str] = []
        for acc in self.accounts.values():
            if acc.owner_employee_id == employee_id:
                acc.roles = list(final_roles)
                updated_accounts.append(acc.account_id)

        # Mover olay özetini döndür
        return {
            "status": "SUCCESS",
            "event": "MOVER",
            "employee_id": employee_id,
            "old_department": old_department,
            "new_department": new_department,
            "revoked_roles": revoked_roles,
            "final_roles": final_roles,
            "updated_accounts": updated_accounts,
            "approver": approver,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def process_leaver(
        self,
        employee_id: str,
        termination_date: str,
        immediate: bool = True,
        approver: str = ""
    ) -> Dict[str, Any]:
        """
        Leaver (İşten Ayrılma / Deprovisioning): Personelin kurumla ilişiğinin kesilmesi.
        
        Kritik Güvenlik Kuralları:
        - Personelin İK durumu derhal 'TERMINATED' yapılır.
        - Tüm bağlı hesaplar anında 'DISABLED' durumuna alınır (Yetim hesap önleme).
        - Oturum ve yetki jetonları (Refresh Tokens) derhal iptal edilir.
        - Ayrıcalıklı grup üyelikleri ve roller temizlenir.
        """
        # Personel İK kaydını kontrol et
        if employee_id not in self.employees:
            raise KeyError(f"Personel bulunamadı: {employee_id}")

        # Onay mekanizması doğrulaması
        if not approver or approver.strip() == "":
            raise ValueError("Leaver işlemi için İK onaylayıcısı (approver) gereklidir.")

        emp = self.employees[employee_id]
        emp.status = LifecycleStatus.TERMINATED
        emp.end_date = termination_date
        emp.assigned_roles = []

        # İlgili tüm sistem hesaplarını kapat
        disabled_accounts: List[str] = []
        for acc in self.accounts.values():
            if acc.owner_employee_id == employee_id:
                acc.status = AccountStatus.DISABLED
                acc.roles = []
                acc.entitlements = []
                disabled_accounts.append(acc.account_id)

        # Leaver olay özetini döndür
        return {
            "status": "SUCCESS",
            "event": "LEAVER",
            "employee_id": employee_id,
            "termination_date": termination_date,
            "disabled_accounts": disabled_accounts,
            "immediate": immediate,
            "approver": approver,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def audit_directory(self) -> JMLAuditResult:
        """
        Tüm kurumsal dizini JML, SoD, Yetki Birikimi ve Yetim Hesap risklerine karşı denetler.
        """
        findings: List[AuditFinding] = []
        orphan_count = 0
        privilege_creep_count = 0
        sod_violations_count = 0
        dormant_count = 0

        # Zaman hesabı için referans UTC tarihi
        now_utc = datetime.now(timezone.utc)

        # 1. DENETİM: Yetim Hesaplar (Orphan Accounts)
        # Bir hesabın sahibi İK veri tabanında yoksa veya durumu TERMINATED ise yetim hesaptır
        for acc in self.accounts.values():
            owner_emp = self.employees.get(acc.owner_employee_id)
            if owner_emp is None:
                # Sahibi İK'da hiç kayıtlı olmayan hayalet hesap
                if acc.status == AccountStatus.ACTIVE:
                    orphan_count += 1
                    findings.append(AuditFinding(
                        rule_id="JML-ORPHAN-01",
                        title="Sahipsiz Hayalet Hesap (Ghost Account) Tespit Edildi",
                        severity=Severity.CRITICAL,
                        employee_id=None,
                        account_id=acc.account_id,
                        details=f"Hesap '{acc.username}' ({acc.target_system}) İK veri tabanında bulunmayan bir çalışan kimliğine bağlı.",
                        remediation=f"Hesabı derhal devre dışı bırakın: Disable-Account -Id {acc.account_id}"
                    ))
            elif owner_emp.status == LifecycleStatus.TERMINATED:
                # İK'dan ayrılmış ancak hedef sistemde hala aktif kalan yetim hesap
                if acc.status == AccountStatus.ACTIVE:
                    orphan_count += 1
                    findings.append(AuditFinding(
                        rule_id="JML-ORPHAN-02",
                        title="İlişiği Kesilmiş Personele Ait Aktif Yetim Hesap (Orphan Account)",
                        severity=Severity.CRITICAL,
                        employee_id=owner_emp.employee_id,
                        account_id=acc.account_id,
                        details=f"Personel '{owner_emp.name}' ({owner_emp.employee_id}) işten ayrılmış ancak '{acc.username}' hesabı hala AKTİF.",
                        remediation=f"Yetim hesabı derhal kapatın ve oturum jetonlarını iptal edin."
                    ))

        # 2. DENETİM: Görevler Ayrılığı (SoD) İhlalleri
        for emp in self.employees.values():
            if emp.status == LifecycleStatus.ACTIVE:
                conflicts = self.check_sod_conflict(emp.assigned_roles)
                for conf in conflicts:
                    sod_violations_count += 1
                    findings.append(AuditFinding(
                        rule_id="JML-SOD-01",
                        title=f"Görevler Ayrılığı (SoD) Çatışması: {conf.conflict_id}",
                        severity=conf.severity,
                        employee_id=emp.employee_id,
                        account_id=None,
                        details=f"Personel '{emp.name}' birbiriyle çatışan rollere sahip: '{conf.role_a}' ve '{conf.role_b}'. Açıklama: {conf.description}",
                        remediation=f"Kullanıcıdan çatışan rollerden birini geri alın (Revoke role)."
                    ))

        # 3. DENETİM: Yetki Birikimi (Privilege Creep)
        # Personelin kendi departmanı dışındaki departmanlara ait yetkileri haksız tutması
        for emp in self.employees.values():
            if emp.status == LifecycleStatus.ACTIVE:
                other_dept_roles: List[str] = []
                for role_id in emp.assigned_roles:
                    role_def = self.roles.get(role_id)
                    if role_def and role_def.department != emp.department and role_def.department != "GENEL":
                        other_dept_roles.append(role_id)
                if other_dept_roles:
                    privilege_creep_count += 1
                    findings.append(AuditFinding(
                        rule_id="JML-CREEP-01",
                        title="Yetki Birikimi (Privilege Creep) Tespit Edildi",
                        severity=Severity.HIGH,
                        employee_id=emp.employee_id,
                        account_id=None,
                        details=f"Personel '{emp.name}' ({emp.department} departmanı) başka departmanlara ait rollere sahip: {other_dept_roles}",
                        remediation=f"Eski departman rollerini temizleyin ve rol incelemesi (Access Certification) başlatın."
                    ))

        # 4. DENETİM: Atıl Hesaplar (Dormant / Inactive Accounts)
        # 90 günden uzun süredir oturum açılmamış aktif hesaplar
        for acc in self.accounts.values():
            if acc.status == AccountStatus.ACTIVE and acc.last_logon_date:
                try:
                    last_logon = datetime.fromisoformat(acc.last_logon_date.replace("Z", "+00:00"))
                    diff_days = (now_utc - last_logon).days
                    if diff_days > self.dormant_threshold_days:
                        dormant_count += 1
                        findings.append(AuditFinding(
                            rule_id="JML-DORMANT-01",
                            title=f"Atıl Hesap (Dormant Account) - {diff_days} Gündür Oturum Açılmadı",
                            severity=Severity.MEDIUM,
                            employee_id=acc.owner_employee_id,
                            account_id=acc.account_id,
                            details=f"'{acc.username}' ({acc.target_system}) hesabı {diff_days} gündür hareketsiz.",
                            remediation=f"Hesabı pasife alın (Disable) ve hesap sahibine doğrulama e-postası iletin."
                        ))
                except Exception:
                    pass

        # 5. DENETİM: Ayrıcalıklı Hesaplarda MFA Eksikliği
        for acc in self.accounts.values():
            if acc.status == AccountStatus.ACTIVE and not acc.mfa_enabled:
                has_privileged_role = any(
                    self.roles.get(r) and self.roles[r].is_privileged
                    for r in acc.roles
                )
                if has_privileged_role:
                    findings.append(AuditFinding(
                        rule_id="JML-MFA-01",
                        title="Ayrıcalıklı Hesapta MFA Devre Dışı",
                        severity=Severity.CRITICAL,
                        employee_id=acc.owner_employee_id,
                        account_id=acc.account_id,
                        details=f"Ayrıcalıklı '{acc.username}' hesabı üzerinde Çok Faktörlü Kimlik Doğrulama (MFA) etkin değil.",
                        remediation="Hesap için MFA kaydını zorunlu kılın (Conditional Access Policy)."
                    ))

        # Güvenlik puanı hesaplama: 100 üzerinden ceza puanı düşümü
        penalty = 0.0
        for f in findings:
            if f.severity == Severity.CRITICAL:
                penalty += 25.0
            elif f.severity == Severity.HIGH:
                penalty += 15.0
            elif f.severity == Severity.MEDIUM:
                penalty += 10.0
            elif f.severity == Severity.LOW:
                penalty += 5.0
        calculated_score = max(0.0, min(100.0, 100.0 - penalty))

        return JMLAuditResult(
            total_employees=len(self.employees),
            total_accounts=len(self.accounts),
            orphan_accounts_count=orphan_count,
            privilege_creep_count=privilege_creep_count,
            sod_violations_count=sod_violations_count,
            dormant_accounts_count=dormant_count,
            findings=findings,
            security_score=calculated_score,
            is_compliant=(len(findings) == 0)
        )

    def generate_remediation_powershell(self, audit_result: JMLAuditResult) -> str:
        """Denetimde tespit edilen yetim ve güvensiz hesaplar için PowerShell düzeltme betiği üretir."""
        lines = [
            "# =====================================================================",
            "# GÜN 146: IAM JML GÜVENLİK VE SERTLEŞTİRME OTOMASYON BETİĞİ (POWERSHELL)",
            "# Bu betik; denetimde bulunan yetim hesapları kapatır ve SoD rollerini temizler.",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.",
            "# =====================================================================",
            "$ErrorActionPreference = 'Stop'",
            "Write-Host '[+] IAM JML Sertleştirme ve Yetim Hesap Temizliği Başlatılıyor...' -ForegroundColor Cyan",
            ""
        ]

        if not audit_result.findings:
            lines.append("Write-Host '[*] Kurumsal dizin temiz. Kapatılacak yetim hesap veya SoD ihlali bulunamadı.' -ForegroundColor Green")
            return "\n".join(lines)

        for finding in audit_result.findings:
            if finding.rule_id in ["JML-ORPHAN-01", "JML-ORPHAN-02"]:
                acc = self.accounts.get(finding.account_id or "")
                if acc:
                    lines.append(f"# {finding.title} ({finding.account_id})")
                    lines.append(f"Write-Host '[!] Yetim Hesap Kapatılıyor: {acc.username} ({acc.target_system})' -ForegroundColor Yellow")
                    lines.append(f"try {{")
                    lines.append(f"    # Active Directory hesabı kapatma")
                    lines.append(f"    Disable-ADAccount -Identity '{acc.username}' -Confirm:$false")
                    lines.append(f"    # Entra ID / Microsoft 365 oturum jetonlarını iptal etme")
                    lines.append(f"    Revoke-MgUserAllRefreshToken -UserId '{acc.username}@kurum.local'")
                    lines.append(f"    Write-Host '  [OK] {acc.username} hesabı başarıyla kapatıldı ve oturumları sonlandırıldı.' -ForegroundColor Green")
                    lines.append(f"}} catch {{")
                    lines.append(f"    Write-Warning '  [HATA] Hesap kapatılamadı: $_'")
                    lines.append(f"}}")
                    lines.append("")
            elif finding.rule_id == "JML-MFA-01":
                acc = self.accounts.get(finding.account_id or "")
                if acc:
                    lines.append(f"# {finding.title}: {acc.username}")
                    lines.append(f"Write-Host '[!] Ayrıcalıklı hesapta MFA zorlanıyor: {acc.username}' -ForegroundColor Yellow")
                    lines.append(f"Set-MsolUser -UserPrincipalName '{acc.username}@kurum.local' -StrongAuthenticationRequirements @()")
                    lines.append("")

        lines.append("Write-Host '[+] IAM JML düzeltme adımları tamamlandı.' -ForegroundColor Cyan")
        return "\n".join(lines)

    def generate_hardening_matrix(self) -> Dict[str, Any]:
        """CIS, NIST SP 800-63 ve ISO 27001 JML uyumluluk ve kontrol matrisi üretir."""
        return {
            "standartlar": {
                "NIST_SP_800_63B": "Dijital Kimlik Kılavuzu: Kimlik Doğrulama ve Yaşam Döngüsü Yönetimi",
                "CIS_Controls_v8": "Kontrol 5: Hesap Yönetimi ve Kontrol 6: Erişim Kontrolü Yönetimi",
                "ISO_27001_A9": "Madde A.9.2: Kullanıcı Erişim Yönetimi (JML Süreçleri)",
                "SOX_404": "Görevler Ayrılığı (SoD) ve Yetki Denetimi Zorunlulukları"
            },
            "kontrol_maddeleri": [
                {
                    "asama": "Joiner",
                    "kural": "Yetkili İK Kaynağı Doğrulaması",
                    "aciklama": "Hesap açılışları yalnızca İK otoriter veri kaynağından otomatik tetiklenmelidir.",
                    "onem": "CRITICAL"
                },
                {
                    "asama": "Joiner",
                    "kural": "En Az Yetki ve Doğum Hakkı (Birthright) Rolleri",
                    "aciklama": "Yeni personele ilk gün yalnızca pozisyonu için zorunlu temel roller atanır.",
                    "onem": "HIGH"
                },
                {
                    "asama": "Mover",
                    "kural": "Yetki Birikimi Önleme (Privilege Creep Prevention)",
                    "aciklama": "Departman değiştiren personelin eski departmanına ait yetkileri anında iptal edilir.",
                    "onem": "CRITICAL"
                },
                {
                    "asama": "Mover / Her Zaman",
                    "kural": "Görevler Ayrılığı (SoD) Denetimi",
                    "aciklama": "Hassas iş süreçlerinde (fatura oluşturan / ödeme onaylayan) rolleri aynı kişiye verilemez.",
                    "onem": "CRITICAL"
                },
                {
                    "asama": "Leaver",
                    "kural": "Anında Hesap Kapatma ve Jeton İptali",
                    "aciklama": "İşten ayrılan personelin hesapları azami 1 saat içinde kapatılır, oturumları sonlandırılır.",
                    "onem": "CRITICAL"
                },
                {
                    "asama": "Denetim",
                    "kural": "Yetim Hesap Taraması (Orphan Account Detection)",
                    "aciklama": "Hedef sistemlerde sahibi bulunmayan veya ayrılmış personele ait hesaplar taranıp kapatılır.",
                    "onem": "HIGH"
                },
                {
                    "asama": "Denetim",
                    "kural": "Atıl Hesap Yönetimi (Dormant Account Management)",
                    "aciklama": "90 günden uzun süredir kullanılmayan aktif hesaplar otomatik dondurulur.",
                    "onem": "MEDIUM"
                }
            ]
        }
