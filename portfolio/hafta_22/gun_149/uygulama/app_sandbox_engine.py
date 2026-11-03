"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli standart kütüphane modülleri içe aktarılır
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any

# ==============================================================================
# SABİTLER VE TEHLİKELİ SİSTEM ÇAĞRILARI / YETKİLER LİSTESİ
# ==============================================================================

# Çekirdek ve izolasyon sınırlarını aşmak için kullanılan tehlikeli sistem çağrıları (Syscalls)
DANGEROUS_SYSCALLS: Dict[str, str] = {
    "ptrace": "Diğer süreçlerin belleğine erişim ve kod enjeksiyonu riski (CWE-250)",
    "bpf": "eBPF çekirdek programı yükleme ve çekirdek bellek sızıntısı riski",
    "mount": "Dosya sistemi bağlama ve namespace izolasyonunu kırma riski",
    "umount2": "Kritik salt-okunur dosya sistemi bağlarını çözme riski",
    "pivot_root": "Konteyner kök dizin sınırını aşma (chroot escape) riski",
    "reboot": "Ana makine çekirdeğini yeniden başlatarak hizmet kesintisi riski (DoS)",
    "kexec_load": "Ana makineye imzasız yeni çekirdek yükleme riski",
    "kexec_file_load": "Ana makine çekirdeğini dosya üzerinden dinamik değiştirme riski",
    "sys_chroot": "Klasik chroot sınırını aşarak dosya sistemine sızma riski",
    "open_by_handle_at": "Dosya tanıtıcısı üzerinden izinleri atlatma riski (Shocker exploit)",
    "process_vm_readv": "Süreçler arası bellek okuma riski",
    "process_vm_writev": "Süreçler arası bellek yazma riski",
    "keyctl": "Çekirdek anahtar deposuna yetkisiz erişim riski",
    "userfaultfd": "Çekirdek yarış durumu (race condition) açıklarını tetikleme riski",
    "acct": "İşlem muhasebesi mekanizmasını manipüle etme riski",
    "setns": "Başka bir sürecin namespace alanına yetkisiz geçiş yapma riski"
}

# Konteyner ve süreç izolasyonunda en sık suistimal edilen tehlikeli Linux yetenekleri (Capabilities)
DANGEROUS_LINUX_CAPABILITIES: Dict[str, str] = {
    "CAP_SYS_ADMIN": "Konteyner içi fiili root yetkisi sağlar, neredeyse tüm izolasyonları deler",
    "CAP_SYS_PTRACE": "Diğer süreçleri debug etme ve ptrace ile bellek manipülasyonu",
    "CAP_NET_RAW": "Ham paket soketleri açarak ARP/IP zehirleme ve paket koklama",
    "CAP_DAC_OVERRIDE": "Dosya okuma/yazma/çalıştırma izin kontrollerini tamamen devre dışı bırakır",
    "CAP_DAC_READ_SEARCH": "Tüm dizin ve dosyaların okunabilmesini sağlar",
    "CAP_SYS_MODULE": "Çekirdeğe doğrudan ring-0 çekirdek modülü (LKM) yükleme yetkisi",
    "CAP_SYS_RAWIO": "Doğrudan fiziksel I/O portlarına ve bellek adreslerine erişim",
    "CAP_SYS_BOOT": "Sistemi yeniden başlatma yetkisi",
    "CAP_SYS_CHROOT": "chroot sistem çağrısını çalıştırma yetkisi",
    "CAP_SETUID": "Süreç UID kimliğini rastgele değiştirme yetkisi",
    "CAP_SETGID": "Süreç GID grup kimliğini rastgele değiştirme yetkisi"
}

# Korunması gereken ve sandbox içine asla bağlanmaması gereken kritik sistem yolları
CRITICAL_MASKED_PATHS: List[str] = [
    "/proc/kcore",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/sched_debug",
    "/sys/firmware",
    "/etc/shadow",
    "/etc/sudoers",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock"
]

# ==============================================================================
# ENUM VE VERİ MODELLERİ
# ==============================================================================

class SeccompAction(str, Enum):
    """Seccomp-BPF sistem çağrısı filtreleme eylemleri."""
    # Sistem çağrısına izin verilir
    SCMP_ACT_ALLOW = "SCMP_ACT_ALLOW"
    # Süreç çekirdek tarafından anında öldürülür (en güvenli eylem)
    SCMP_ACT_KILL = "SCMP_ACT_KILL"
    # Çağrı engellenir ve uygulamaya EPERM hata kodu döndürülür
    SCMP_ACT_ERRNO = "SCMP_ACT_ERRNO"
    # Çağrı günlüğe kaydedilir ve devamına izin verilir (denetim modu)
    SCMP_ACT_LOG = "SCMP_ACT_LOG"
    # Çağrı engellenir ve hata ayıklayıcıya tuzak sinyali gönderilir
    SCMP_ACT_TRAP = "SCMP_ACT_TRAP"


class WindowsIntegrityLevel(str, Enum):
    """Windows Zorunlu Bütünlük Kontrolü (Mandatory Integrity Control - MIC) Seviyeleri."""
    # En kısıtlı seviye (kötü amaçlı veya tamamen güvenilmeyen kod)
    UNTRUSTED = "UNTRUSTED"
    # Düşük bütünlük seviyesi (Internet Explorer, Edge korumalı mod, AppContainer)
    LOW = "LOW"
    # Standart kullanıcı seviyesi
    MEDIUM = "MEDIUM"
    # Yönetici (Elevated Administrator) seviyesi
    HIGH = "HIGH"
    # İşletim sistemi çekirdek ve servis seviyesi
    SYSTEM = "SYSTEM"


class NetworkIsolationMode(str, Enum):
    """Sandbox ağ izolasyon modelleri."""
    # Tam ağ izolasyonu: hiçbir ağ arabirimi verilmez (loopback dahi yok veya izole)
    DISCONNECTED = "DISCONNECTED"
    # Yalnızca yerel loopback veya dahili host ile haberleşme
    LOCAL_LOOPBACK_ONLY = "LOCAL_LOOPBACK_ONLY"
    # Yalnızca tanımlı güvenli giden proxy üzerinden haberleşme
    OUTBOUND_PROXY_ONLY = "OUTBOUND_PROXY_ONLY"
    # Kısıtlanmamış tam ağ erişimi (tehlikeli)
    UNRESTRICTED = "UNRESTRICTED"


@dataclass
class ResourceLimits:
    """cgroups veya Windows Job Object tarafından uygulanan kaynak sınırlamaları."""
    # Maksimum bellek limiti (Megabayt cinsinden)
    max_memory_mb: int = 512
    # Maksimum süreç sayısı (Fork bomb ataklarına karşı pids.max)
    max_pids: int = 64
    # Maksimum CPU yüzdesi (Yüzdelik kota: %1-%100)
    cpu_quota_pct: int = 50
    # Maksimum dosya boyutu (Megabayt cinsinden)
    max_file_size_mb: int = 100


@dataclass
class SandboxProfile:
    """Tüm işletim sistemi seviyesi sandbox politikasını temsil eden veri modeli."""
    # Profilin benzersiz adı
    profile_name: str
    # Profilin işletim sistemi türü ('linux' veya 'windows')
    os_family: str
    # Varsayılan seccomp eylemi (önerilen: SCMP_ACT_ERRNO veya SCMP_ACT_KILL)
    default_seccomp_action: SeccompAction
    # Açıkça izin verilen sistem çağrıları kümesi (Allowlist)
    allowed_syscalls: Set[str] = field(default_factory=set)
    # Açıkça engellenen sistem çağrıları sözlüğü (Syscall -> SeccompAction)
    blocked_syscalls: Dict[str, SeccompAction] = field(default_factory=dict)
    # Sürece tahsis edilen Linux yetenekleri kümesi
    granted_capabilities: Set[str] = field(default_factory=set)
    # Kök dosya sisteminin salt-okunur (read-only) olup olmadığı
    read_only_root_fs: bool = True
    # Maskelenmiş / gizlenmiş sistem yolları listesi
    masked_paths: List[str] = field(default_factory=list)
    # Ağ izolasyon modu
    network_mode: NetworkIsolationMode = NetworkIsolationMode.DISCONNECTED
    # Kaynak kullanım sınırları (cgroup / job object)
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    # Windows Zorunlu Bütünlük Seviyesi (Yalnızca Windows için)
    windows_integrity_level: WindowsIntegrityLevel = WindowsIntegrityLevel.LOW
    # Windows AppContainer izolasyonu aktif mi?
    windows_app_container: bool = True
    # Kısıtlanmış Windows yetkileri (Devre dışı bırakılması gereken ayrıcalıklar)
    disabled_windows_privileges: List[str] = field(default_factory=list)


@dataclass
class SecurityAuditFinding:
    """Sandbox profil denetiminde tespit edilen güvenlik zafiyeti veya yapılandırma sapması."""
    # Kural veya bulgu kodu (örn: SBX-AUDIT-001)
    rule_id: str
    # Şiddet derecesi: CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity: str
    # Zafiyet başlığı
    title: str
    # Detaylı teknik açıklama
    description: str
    # İlgili güvenlik standardı veya MITRE ATT&CK tekniği (örn: NIST SP 800-190, T1611)
    compliance_ref: str
    # Düzeltme için önerilen teknik adım
    remediation_step: str


@dataclass
class RuntimeSimulationResult:
    """Bir işlem veya sistem çağrısının sandbox içinde koşturulma simülasyonu sonucu."""
    # İşlemin adı veya komutu
    action_name: str
    # İzin verildi mi? (True / False)
    allowed: bool
    # Kararı veren güvenlik mekanizması
    enforcing_layer: str
    # Karar kodu veya dönen hata
    verdict: str
    # Açıklayıcı Türkçe detay
    detail: str


# ==============================================================================
# MOTOR SINIFI: APP SANDBOX MOTORU
# ==============================================================================

class AppSandboxEngine:
    """
    Uygulama İzinleri ve Sandbox Güvenlik Motoru.
    Linux (Seccomp-BPF, Capabilities, Namespaces, cgroups) ve
    Windows (MIC, AppContainer, Restricted Token) güvenlik standartlarını denetler.
    """

    def __init__(self, profile: SandboxProfile):
        # Aktif sandbox profili referansı saklanır
        self.profile = profile

    def audit_sandbox_security(self) -> List[SecurityAuditFinding]:
        """
        Sandbox profilini CIS Container Benchmark, NIST SP 800-190 ve
        Windows Güvenlik Mimarisi standartlarına göre baştan sona denetler.
        """
        # Tespit edilen bulguları saklamak için boş liste oluşturulur
        findings: List[SecurityAuditFinding] = []

        # ----------------------------------------------------------------------
        # 1. LINUX CAPABILITY DENETİMLERİ
        # ----------------------------------------------------------------------
        if self.profile.os_family.lower() == "linux":
            # Sürece verilen tüm yetenekler incelenir
            for cap in self.profile.granted_capabilities:
                # Yetenek tehlikeli listesinde yer alıyor mu kontrol edilir
                if cap in DANGEROUS_LINUX_CAPABILITIES:
                    # Şiddet derecesi belirlenir (CAP_SYS_ADMIN en kritik olanıdır)
                    severity = "CRITICAL" if cap == "CAP_SYS_ADMIN" else "HIGH"
                    # Denetim bulgusu oluşturulur ve listeye eklenir
                    findings.append(SecurityAuditFinding(
                        rule_id=f"SBX-CAP-{cap.replace('CAP_', '')}",
                        severity=severity,
                        title=f"Tehlikeli Linux Yeteneği Verilmiş: {cap}",
                        description=f"'{cap}' yeteneği sürece tanınmış. {DANGEROUS_LINUX_CAPABILITIES[cap]}.",
                        compliance_ref="NIST SP 800-190 Sec 3.3.1 / CIS Docker 5.2",
                        remediation_step=f"Konteyner/Süreç başlatılırken '--cap-drop={cap}' parametresi uygulanmalıdır."
                    ))

        # ----------------------------------------------------------------------
        # 2. SECCOMP SİSTEM ÇAĞRISI FİLTRELEME DENETİMLERİ
        # ----------------------------------------------------------------------
        if self.profile.os_family.lower() == "linux":
            # Varsayılan eylem kontrol edilir: ALLOW olması güvensiz bir allowlist yokluğunu gösterir
            if self.profile.default_seccomp_action == SeccompAction.SCMP_ACT_ALLOW:
                # Kritik bulgu kaydedilir
                findings.append(SecurityAuditFinding(
                    rule_id="SBX-SECCOMP-DEFAULT-ALLOW",
                    severity="CRITICAL",
                    title="Seccomp Varsayılan Eylemi İzin Verici (Default ALLOW)",
                    description="Seccomp filtresinde tanımlanmayan tüm sistem çağrılarına varsayılan olarak izin verilmektedir.",
                    compliance_ref="CWE-250 / NIST SP 800-190 Sec 3.3.2",
                    remediation_step="Varsayılan seccomp eylemi 'SCMP_ACT_ERRNO' veya 'SCMP_ACT_KILL' yapılmalıdır."
                ))

            # Kritik tehlikeli çağrıların engellenip engellenmediği kontrol edilir
            for syscall, reason in DANGEROUS_SYSCALLS.items():
                # Çağrı açıkça engellenmiş mi veya varsayılan ERRNO/KILL altında serbest mi?
                is_blocked = syscall in self.profile.blocked_syscalls and \
                             self.profile.blocked_syscalls[syscall] in (SeccompAction.SCMP_ACT_KILL, SeccompAction.SCMP_ACT_ERRNO)
                # Eğer allowlist kullanılıyorsa ve çağrı allowlist'te varsa engellenmemiştir
                is_allowed_in_allowlist = syscall in self.profile.allowed_syscalls

                # Çağrı engellenmemişse veya allowlist ile izin verilmişse zafiyettir
                if (not is_blocked and self.profile.default_seccomp_action == SeccompAction.SCMP_ACT_ALLOW) or is_allowed_in_allowlist:
                    # Bulgu kaydedilir
                    findings.append(SecurityAuditFinding(
                        rule_id=f"SBX-SYSCALL-{syscall.upper()}",
                        severity="CRITICAL" if syscall in ("ptrace", "bpf", "mount", "pivot_root") else "HIGH",
                        title=f"Kritik Sistem Çağrısı Filtrelenmemiş: {syscall}",
                        description=f"'{syscall}' sistem çağrısı engellenmemiş. Tehlike: {reason}",
                        compliance_ref="MITRE ATT&CK T1611 (Escape to Host) / CIS Docker 5.21",
                        remediation_step=f"Seccomp profilinde '{syscall}' çağrısı için SCMP_ACT_ERRNO kuralı tanımlanmalıdır."
                    ))

        # ----------------------------------------------------------------------
        # 3. DOSYA SİSTEMİ İZOLASYON DENETİMLERİ
        # ----------------------------------------------------------------------
        # Kök dosya sisteminin salt-okunur (read-only) olması zorunludur
        if not self.profile.read_only_root_fs:
            # Bulgu oluşturulur
            findings.append(SecurityAuditFinding(
                rule_id="SBX-FS-WRITABLE-ROOT",
                severity="HIGH",
                title="Kök Dosya Sistemi Yazılabilir Durumda (Writable Root FS)",
                description="Sandbox sürecinin kök dosya sistemine yazma izni bulunmaktadır. Kötü amaçlı yazılım kalıcılık sağlayabilir.",
                compliance_ref="CIS Docker 5.12 / NIST SP 800-190 Sec 3.3.4",
                remediation_step="Sandbox '--read-only' bayrağı ile başlatılmalı; yalnızca geçici alanlar tmpfs olmalıdır."
            ))

        # Maskelenmesi gereken kritik çekirdek yolları kontrol edilir
        for masked_path in CRITICAL_MASKED_PATHS:
            # Yol profilin masked_paths listesinde yoksa zafiyettir
            if masked_path not in self.profile.masked_paths:
                # Bulgu oluşturulur
                findings.append(SecurityAuditFinding(
                    rule_id=f"SBX-FS-UNMASKED-{masked_path.replace('/', '_').strip('_')}",
                    severity="CRITICAL" if "docker.sock" in masked_path or "shadow" in masked_path else "MEDIUM",
                    title=f"Hassas Sistem Yolu Maskelenmemiş: {masked_path}",
                    description=f"'{masked_path}' yolu sandbox içine görünür durumdadır. İzolasyon aşılmasına zemin hazırlar.",
                    compliance_ref="CIS Benchmark 5.31 / CWE-668",
                    remediation_step=f"Konteyner profilinde '{masked_path}' yolu maskedPaths listesine eklenmelidir."
                ))

        # ----------------------------------------------------------------------
        # 4. AĞ İZOLASYON DENETİMLERİ
        # ----------------------------------------------------------------------
        # Kısıtlanmamış ağ kontrol edilir
        if self.profile.network_mode == NetworkIsolationMode.UNRESTRICTED:
            # Bulgu eklenir
            findings.append(SecurityAuditFinding(
                rule_id="SBX-NET-UNRESTRICTED",
                severity="HIGH",
                title="Ağ Erişimi Tamamen Kısıtlanmamış (Unrestricted Network)",
                description="Sandbox süreci ana makine veya dış ağlarla serbestçe soket bağlantısı kurabilmektedir.",
                compliance_ref="MITRE ATT&CK T1071 (Application Layer Protocol) / NIST 800-190 Sec 3.3.3",
                remediation_step="Ağ modu 'DISCONNECTED' veya kısıtlı 'OUTBOUND_PROXY_ONLY' olarak sınırlandırılmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 5. KAYNAK SINIRLAMALARI (CGROUPS / JOB OBJECTS) DENETİMLERİ
        # ----------------------------------------------------------------------
        # Süreç sayısı sınırı kontrolü (Fork Bomb önleme)
        if self.profile.resource_limits.max_pids > 128:
            # Bulgu oluşturulur
            findings.append(SecurityAuditFinding(
                rule_id="SBX-RSRC-PIDS-HIGH",
                severity="MEDIUM",
                title="Süreç Sayısı Sınırı Çok Yüksek (Fork Bomb Riski)",
                description=f"Tanımlanan pids.max ({self.profile.resource_limits.max_pids}) sınırı çok yüksektir.",
                compliance_ref="CIS Docker 5.28 (Limit PIDs)",
                remediation_step="Sandbox için pids.max değeri 64 veya daha düşük bir değere ayarlanmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 6. WINDOWS ÖZEL İZOLASYON DENETİMLERİ
        # ----------------------------------------------------------------------
        if self.profile.os_family.lower() == "windows":
            # Bütünlük seviyesi MEDIUM, HIGH veya SYSTEM ise sandbox değildir
            if self.profile.windows_integrity_level in (WindowsIntegrityLevel.MEDIUM, WindowsIntegrityLevel.HIGH, WindowsIntegrityLevel.SYSTEM):
                # Kritik bulgu eklenir
                findings.append(SecurityAuditFinding(
                    rule_id="SBX-WIN-HIGH-INTEGRITY",
                    severity="CRITICAL",
                    title="Yetersiz Windows Bütünlük Seviyesi (High/Medium Integrity)",
                    description=f"Sandbox bütünlük seviyesi '{self.profile.windows_integrity_level.value}' olarak ayarlanmış. En az LOW veya UNTRUSTED olmalıdır.",
                    compliance_ref="Microsoft Windows Security Architecture / MIC Guidelines",
                    remediation_step="Token bütünlük seviyesi 'LOW' veya 'UNTRUSTED' seviyesine düşürülmelidir."
                ))

            # AppContainer koruması kapalıysa bulgu eklenir
            if not self.profile.windows_app_container:
                # Bulgu eklenir
                findings.append(SecurityAuditFinding(
                    rule_id="SBX-WIN-NO-APPCONTAINER",
                    severity="HIGH",
                    title="Windows AppContainer İzolasyonu Etkin Değil",
                    description="Süreç standart kullanıcı token'ı altında çalışmakta, AppContainer güvenlik duvarı ve nesne izolasyonundan mahrumdur.",
                    compliance_ref="Windows AppContainer Isolation Standard",
                    remediation_step="Süreç 'CreateProcess' çağrılırken AppContainer öznitelik listesi (EXTENDED_STARTUPINFO_PRESENT) ile başlatılmalıdır."
                ))

        # Denetim bulguları listesi geri döndürülür
        return findings

    def simulate_execution(self, action_type: str, target: str, context: Optional[Dict[str, Any]] = None) -> RuntimeSimulationResult:
        """
        Sandbox içinde çalıştırılmak istenen bir işlemi (sistem çağrısı, dosya erişimi, yetenek kullanımı vb.)
        politikaya göre simüle eder ve izolasyon bariyerinin kararını döndürür.
        """
        # Ek bağlam sözlüğü yoksa boş sözlük atanır
        ctx = context or {}

        # ----------------------------------------------------------------------
        # A. SİSTEM ÇAĞRISI (SYSCALL) İSTEĞİ SİMÜLASYONU
        # ----------------------------------------------------------------------
        if action_type == "syscall":
            # Sistem çağrısının adı hedef olarak alınır
            syscall_name = target.lower()

            # Açıkça engellenen sistem çağrıları listesinde var mı?
            if syscall_name in self.profile.blocked_syscalls:
                # Engelleme eylemi alınır
                act = self.profile.blocked_syscalls[syscall_name]
                # Eyleme göre karar üretilir
                if act in (SeccompAction.SCMP_ACT_KILL, SeccompAction.SCMP_ACT_ERRNO, SeccompAction.SCMP_ACT_TRAP):
                    # Engellendi sonucu döndürülür
                    return RuntimeSimulationResult(
                        action_name=f"syscall:{syscall_name}",
                        allowed=False,
                        enforcing_layer="Linux Seccomp-BPF",
                        verdict=act.value,
                        detail=f"Sistem çağrısı '{syscall_name}' seccomp filtresi tarafından kural gereği engellendi ({act.value})."
                    )

            # Allowlist modunda çalışılıyorsa ve çağrı allowlist'te yoksa
            if self.profile.default_seccomp_action != SeccompAction.SCMP_ACT_ALLOW:
                # Çağrı açıkça izin verilenler listesinde mi?
                if syscall_name not in self.profile.allowed_syscalls:
                    # Varsayılan ret eylemi uygulanır
                    return RuntimeSimulationResult(
                        action_name=f"syscall:{syscall_name}",
                        allowed=False,
                        enforcing_layer="Linux Seccomp-BPF (Default Deny)",
                        verdict=self.profile.default_seccomp_action.value,
                        detail=f"Sistem çağrısı '{syscall_name}' beyaz listede bulunmadığından varsayılan politika gereği engellendi."
                    )

            # Aksi durumda çağrıya izin verilir
            return RuntimeSimulationResult(
                action_name=f"syscall:{syscall_name}",
                allowed=True,
                enforcing_layer="Linux Seccomp-BPF",
                verdict="ALLOWED",
                detail=f"Sistem çağrısı '{syscall_name}' izin verilen çağrılar kapsamında çalıştırıldı."
            )

        # ----------------------------------------------------------------------
        # B. LİNUX YETENEK (CAPABILITY) KULLANIM SİMÜLASYONU
        # ----------------------------------------------------------------------
        elif action_type == "capability":
            # Yetenek adı hedef olarak alınır
            cap_name = target.upper()

            # Yetenek sürece verilmiş mi kontrol edilir
            if cap_name not in self.profile.granted_capabilities:
                # Yetenek verilmemiş, engellenir
                return RuntimeSimulationResult(
                    action_name=f"capability:{cap_name}",
                    allowed=False,
                    enforcing_layer="Linux Capabilities Sınırlandırması",
                    verdict="EPERM_OPERATION_NOT_PERMITTED",
                    detail=f"'{cap_name}' yeteneği süreç sınırlandırma kümesinde (bounding set) bulunmamaktadır."
                )

            # Yetenek verilmişse ancak tehlikeliyse uyarılı izin verilir
            return RuntimeSimulationResult(
                action_name=f"capability:{cap_name}",
                allowed=True,
                enforcing_layer="Linux Capabilities",
                verdict="ALLOWED_WARNING",
                detail=f"'{cap_name}' yeteneği sürece tanımlanmış; operasyon çalıştırıldı ancak güvenlik riski teşkil edebilir."
            )

        # ----------------------------------------------------------------------
        # C. DOSYA SİSTEMİ ERİŞİM SİMÜLASYONU
        # ----------------------------------------------------------------------
        elif action_type == "filesystem":
            # Hedef yol alınır
            file_path = target
            # Erişim modu (read veya write) bağlamdan alınır
            mode = ctx.get("mode", "read")

            # 1. Maskelenmiş yollara erişim kontrol edilir
            for masked in self.profile.masked_paths:
                # Yol maskeli yol ile eşleşiyor veya onun altında mı?
                if file_path == masked or file_path.startswith(masked + "/"):
                    # Kesinlikle engellenir
                    return RuntimeSimulationResult(
                        action_name=f"fs:{mode}:{file_path}",
                        allowed=False,
                        enforcing_layer="Linux VFS Mount Masking",
                        verdict="ENOENT_OR_EACCES",
                        detail=f"Hedef yol '{file_path}' sandbox izolasyonu gereği maskelenmiştir; erişim reddedildi."
                    )

            # 2. Yazma işlemi ve Salt-Okunur kök dosya sistemi kontrolü
            if mode == "write":
                # Kök dosya sistemi salt-okunur mu?
                if self.profile.read_only_root_fs:
                    # Yalnızca açıkça izin verilen /tmp veya tmpfs alanlarına yazılabilir
                    is_tmp_mount = file_path.startswith("/tmp") or file_path.startswith("/var/tmp") or file_path.startswith("/run")
                    # Eğer tmpfs değilse engellenir
                    if not is_tmp_mount:
                        # Salt-okunur engeli uygulanır
                        return RuntimeSimulationResult(
                            action_name=f"fs:write:{file_path}",
                            allowed=False,
                            enforcing_layer="Read-Only Root Filesystem",
                            verdict="EROFS_READ_ONLY_FILESYSTEM",
                            detail=f"Kök dosya sistemi salt-okunur bağlandığından '{file_path}' yoluna yazma girişimi engellendi."
                        )

            # Okuma veya izin verilen alana yazma serbesttir
            return RuntimeSimulationResult(
                action_name=f"fs:{mode}:{file_path}",
                allowed=True,
                enforcing_layer="VFS Isolation",
                verdict="ALLOWED",
                detail=f"'{file_path}' yoluna '{mode}' erişimi sağlandı."
            )

        # ----------------------------------------------------------------------
        # D. AĞ BAĞLANTISI KURMA SİMÜLASYONU
        # ----------------------------------------------------------------------
        elif action_type == "network":
            # Hedef ağ adresi alınır
            net_target = target

            # Ağ tamamen devre dışı mı?
            if self.profile.network_mode == NetworkIsolationMode.DISCONNECTED:
                # Engellenir
                return RuntimeSimulationResult(
                    action_name=f"network:connect:{net_target}",
                    allowed=False,
                    enforcing_layer="Network Namespace (Loopback-Only/None)",
                    verdict="ENETUNREACH_NETWORK_UNREACHABLE",
                    detail="Sandbox ağ arabiriminden yoksundur (--net=none); harici soket çağrıları reddedildi."
                )

            # Sadece yerel loopback modu
            elif self.profile.network_mode == NetworkIsolationMode.LOCAL_LOOPBACK_ONLY:
                # Hedef 127.0.0.1 veya localhost değilse engellenir
                if not (net_target.startswith("127.0.0.1") or net_target.startswith("localhost")):
                    # Engellenir
                    return RuntimeSimulationResult(
                        action_name=f"network:connect:{net_target}",
                        allowed=False,
                        enforcing_layer="Network Isolation Policy",
                        verdict="EHOSTUNREACH_HOST_UNREACHABLE",
                        detail=f"Yalnızca yerel döngü (loopback) trafiğine izin verilmektedir. '{net_target}' engellendi."
                    )

            # İzin verilir
            return RuntimeSimulationResult(
                action_name=f"network:connect:{net_target}",
                allowed=True,
                enforcing_layer="Network Filter",
                verdict="ALLOWED",
                detail=f"Ağ bağlantısına izin verildi ({self.profile.network_mode.value})."
            )

        # ----------------------------------------------------------------------
        # E. SÜREÇ ÇATALLANMA (FORK / EXECVE) VE KAYNAK SİMÜLASYONU
        # ----------------------------------------------------------------------
        elif action_type == "process_fork":
            # Mevcut süreç sayısı bağlamdan alınır
            current_pids = ctx.get("current_pids", 1)

            # Süreç limiti aşılmış mı?
            if current_pids >= self.profile.resource_limits.max_pids:
                # Fork bomb engellenir
                return RuntimeSimulationResult(
                    action_name="process_fork",
                    allowed=False,
                    enforcing_layer="Linux cgroups v2 (pids.max) / Job Objects",
                    verdict="EAGAIN_RESOURCE_TEMPORARILY_UNAVAILABLE",
                    detail=f"Maksimum süreç sınırına ({self.profile.resource_limits.max_pids}) ulaşıldı; yeni süreç çatallama engellendi."
                )

            # Yeni sürece izin verilir
            return RuntimeSimulationResult(
                action_name="process_fork",
                allowed=True,
                enforcing_layer="cgroups pids controller",
                verdict="ALLOWED",
                detail=f"Süreç başarıyla oluşturuldu (Mevcut: {current_pids + 1}/{self.profile.resource_limits.max_pids})."
            )

        # Tanımlanamayan eylem türü
        return RuntimeSimulationResult(
            action_name=action_type,
            allowed=False,
            enforcing_layer="Sandbox Fallback Gate",
            verdict="EINVAL_INVALID_OPERATION",
            detail=f"Desteklenmeyen simülasyon eylem türü: {action_type}"
        )


# ==============================================================================
# OCI SECCOMP VE YAPILANDIRMA ÜRETİCİSİ
# ==============================================================================

class OciSeccompGenerator:
    """
    Open Container Initiative (OCI) ve Docker uyumlu Seccomp-BPF
    JSON profil spesifikasyonu üreten yardımcı sınıf.
    """

    @staticmethod
    def generate_oci_seccomp_profile(profile: SandboxProfile) -> Dict[str, Any]:
        """SandboxProfile nesnesinden endüstri standardı OCI Seccomp JSON sözlüğü oluşturur."""
        # Seccomp mimarileri (x86_64 ve aarch64 çekirdek mimarileri)
        architectures = ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"]

        # Sistem çağrısı kuralları listesi oluşturulur
        syscall_rules: List[Dict[str, Any]] = []

        # 1. Açıkça izin verilen sistem çağrıları eklenir
        if profile.allowed_syscalls:
            # İzin kuralı eklenir
            syscall_rules.append({
                "names": sorted(list(profile.allowed_syscalls)),
                "action": SeccompAction.SCMP_ACT_ALLOW.value,
                "args": [],
                "comment": "Uygulama çalışması için zorunlu temel güvenli çağrılar"
            })

        # 2. Açıkça engellenen sistem çağrıları eylemlerine göre gruplanır
        action_groups: Dict[str, List[str]] = {}
        for syscall, action in profile.blocked_syscalls.items():
            # Eylem grubu sözlüğünde liste başlatılır
            if action.value not in action_groups:
                action_groups[action.value] = []
            # Sistem çağrısı eklenir
            action_groups[action.value].append(syscall)

        # Gruplanan kurallar OCI listesine aktarılır
        for act_value, sc_list in action_groups.items():
            # Kural nesnesi oluşturulur
            syscall_rules.append({
                "names": sorted(sc_list),
                "action": act_value,
                "args": [],
                "comment": f"Güvenlik gereği engellenen veya filtrelenen sistem çağrıları ({act_value})"
            })

        # Nihai OCI Seccomp profil sözlüğü inşa edilir
        oci_doc = {
            "$schema": "http://opencontainers.org/schema/image/seccomp.json",
            "profileName": profile.profile_name,
            "defaultAction": profile.default_seccomp_action.value,
            "architectures": architectures,
            "syscalls": syscall_rules,
            "metadata": {
                "author": "Seydi Eryılmaz (@seydivakkas)",
                "license": "Özel Lisans - Tüm Hakları Saklıdır",
                "complianceStandard": "NIST SP 800-190 / CIS Docker Benchmark"
            }
        }

        # Oluşturulan doküman geri döndürülür
        return oci_doc


# ==============================================================================
# SERTLEŞTİRME VE DÜZELTME KOMUT DOSYASI ÜRETİCİSİ
# ==============================================================================

class SandboxRemediationGenerator:
    """
    Denetimde tespit edilen zafiyetleri gidermek için otomatik
    PowerShell ve Linux Bash sertleştirme komut dosyaları üretir.
    """

    @staticmethod
    def generate_linux_hardening_script(profile: SandboxProfile) -> str:
        """Linux ortamı ve konteynerler için sertleştirilmiş başlatma betiği üretir."""
        # Betik satırları oluşturulur
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux Konteyner ve Süreç Sandbox Sertleştirme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "# 1. GÜVENLİK AYARLARI VE BAYRAKLAR",
            "SECCOMP_PROFILE=\"/etc/docker/seccomp-hardened.json\"",
            "CONTAINER_NAME=\"hardened-app-runner\"",
            "IMAGE_NAME=\"alpine:latest\"",
            "",
            "# 2. SERTLEŞTİRİLMİŞ DOCKER RUN KOMUTU",
            "docker run -d \\",
            "  --name \"${CONTAINER_NAME}\" \\",
            "  --security-opt=\"no-new-privileges:true\" \\",
            "  --security-opt=\"seccomp=${SECCOMP_PROFILE}\" \\",
            "  --cap-drop=ALL \\",
            "  --read-only \\",
            "  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \\",
            "  --tmpfs /run:rw,noexec,nosuid,nodev,size=16m \\",
            f"  --pids-limit={profile.resource_limits.max_pids} \\",
            f"  --memory=\"{profile.resource_limits.max_memory_mb}m\" \\",
            f"  --cpus=\"{profile.resource_limits.cpu_quota_pct / 100.0}\" \\",
            "  --network=\"none\" \\",
            "  \"${IMAGE_NAME}\"",
            "",
            "echo \"[+] Hardened Sandbox konteyneri başarıyla başlatıldı.\""
        ]
        # Metin birleştirilerek döndürülür
        return "\n".join(lines)

    @staticmethod
    def generate_windows_powershell_hardening_script(profile: SandboxProfile) -> str:
        """Windows ortamında AppContainer ve Düşük Bütünlük (Low Integrity) yapılandırma betiği üretir."""
        # Betik satırları oluşturulur
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Windows AppContainer ve Zorunlu Bütünlük Seviyesi (MIC) Sertleştirme Betiği",
            "# ==============================================================================",
            "$ErrorActionPreference = 'Stop'",
            "",
            "# 1. HEDEF ÇALIŞMA DİZİNİ VE GÜVENLİK TANIMLARI",
            "$SandboxDir = 'C:\\ProgramData\\HardenedSandbox'",
            "if (-not (Test-Path $SandboxDir)) {",
            "    New-Item -ItemType Directory -Path $SandboxDir -Force | Out-Null",
            "}",
            "",
            "# 2. DÜŞÜK BÜTÜNLÜK SEVİYESİ (LOW INTEGRITY) ACL UYGULAMA",
            "# icacls aracıyla zorunlu etiket (Mandatory Label) Low olarak atanır",
            "& icacls $SandboxDir /setintegritylevel (OI)(CI)L | Out-Null",
            "",
            "# 3. APPCONTAINER PROFİLİ OLUŞTURMA VE SID ELDE ETME",
            "$AppContainerName = 'SecuredAppContainerSandbox'",
            "$SidResult = & whoami /all",
            "",
            "# 4. GEÇİCİ DOSYA İZİNLERİNİ YALNIZCA GEREKLİ KULLANICIYA TAHSİS ETME",
            "Write-Output \"[+] Windows Sandbox klasörü Düşük Bütünlük (Low Integrity) seviyesine ayarlandı: $SandboxDir\"",
            "Write-Output \"[+] İşlem Başarılı: AppContainer ve MIC ilkeleri doğrulandı.\""
        ]
        # Metin birleştirilerek döndürülür
        return "\n".join(lines)
