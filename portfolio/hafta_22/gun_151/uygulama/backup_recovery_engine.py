"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli standart kütüphaneler içe aktarılır
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# ENUM VE SABİT TANIMLARI
# ==============================================================================

class StorageMediaType(str, Enum):
    """Yedekleme depolama ortamı türleri (3-2-1 kuralı için ortam çeşitliliği)."""
    # Yerel hızlı NVMe/SSD disk
    LOCAL_NVME = "LOCAL_NVME"
    # Ağ Paylaşımı (NAS / SMB / NFS)
    NETWORK_NAS_SMB = "NETWORK_NAS_SMB"
    # Kurumsal Blok Depolama (SAN)
    ENTERPRISE_SAN = "ENTERPRISE_SAN"
    # Bulut Nesne Depolama (AWS S3, Azure Blob, Google Cloud Storage)
    CLOUD_S3_OBJECT = "CLOUD_S3_OBJECT"
    # Saha Dışı Manyetik Teyp (LTO Tape)
    OFFSITE_TAPE = "OFFSITE_TAPE"
    # Fiziksel Olarak Yalıtılmış Soğuk Depolama (Air-Gapped Cold Storage)
    AIR_GAPPED_COLD = "AIR_GAPPED_COLD"


class ImmutabilityMode(str, Enum):
    """Değiştirilemezlik (WORM - Write Once Read Many) ve Nesne Kilidi Modları."""
    # Değiştirilebilir / Silinebilir (Fidye yazılımlarına karşı tamamen savunmasız)
    NONE = "NONE"
    # Yönetişim Modu (Governance Mode - Özel yetkili admin rolü silebilir)
    GOVERNANCE = "GOVERNANCE"
    # Uyumluluk Modu (Compliance Mode - Root/Admin dahil saklama süresi dolana kadar HİÇ KİMSE silemez)
    COMPLIANCE = "COMPLIANCE"


class BackupType(str, Enum):
    """Yedek alma yöntemi ve frekans türü."""
    # Tam Yedekleme (Full Backup)
    FULL = "FULL"
    # Fark Yedeklemesi (Differential Backup)
    DIFFERENTIAL = "DIFFERENTIAL"
    # Artımlı Yedekleme (Incremental Backup)
    INCREMENTAL = "INCREMENTAL"
    # Sürekli Veri Koruma (Continuous Data Protection - CDP / Anlık Replikasyon)
    CONTINUOUS_CDP = "CONTINUOUS_CDP"


# ==============================================================================
# VERİ MODELLERİ
# ==============================================================================

@dataclass
class BackupArtifact:
    """Tek bir yedekleme noktasını (Restore Point) temsil eden veri nesnesi."""
    # Yedeğin benzersiz kimliği
    backup_id: str
    # Yedeğin oluşturulduğu zaman damgası (ISO formatında UTC)
    created_at_utc: str
    # Yedek türü
    backup_type: BackupType
    # Depolandığı medya ortamı
    media_type: StorageMediaType
    # Saha dışı (Off-site / Başka coğrafi bölge) mi?
    is_offsite: bool
    # Ağdan tamamen yalıtılmış (Air-gapped) mi?
    is_air_gapped: bool
    # Değiştirilemezlik (Immutability/WORM) seviyesi
    immutability_mode: ImmutabilityMode
    # Değiştirilemezlik sona erme zamanı (ISO formatında UTC)
    retention_expiry_utc: Optional[str]
    # Yedeğin boyutu (Megabayt cinsinden)
    size_mb: int
    # Yedeğin doğrulanmış SHA-256 sağlama toplamı (Checksum)
    sha256_checksum: str
    # Bit bozulması (Bit rot) veya sessiz veri kaybı simülasyon bayrağı
    is_corrupted: bool = False
    # Windows Gölge Kopya (VSS) koruması etkin mi?
    vss_shadow_protected: bool = True
    # Son başarılı geri yükleme doğrulama tarihi
    last_verified_at_utc: Optional[str] = None


@dataclass
class BackupPolicy:
    """Kurumsal Yedekleme ve İş Sürekliliği Politikası (SLA Gereksinimleri)."""
    # Politika adı
    policy_name: str
    # Hedef Kurtarma Noktası (RPO - Recovery Point Objective) Dakika cinsinden
    target_rpo_minutes: int = 60
    # Hedef Kurtarma Süresi (RTO - Recovery Time Objective) Dakika cinsinden
    target_rto_minutes: int = 120
    # 3-2-1 Kuralı: Minimum bağımsız kopya sayısı (Genellikle en az 3)
    required_min_copies: int = 3
    # 3-2-1 Kuralı: Minimum farklı ortam/medya sayısı (Genellikle en az 2)
    required_min_media_types: int = 2
    # En az 1 kopya saha dışında (Off-site / Cloud) olmalı mı?
    require_offsite_copy: bool = True
    # En az 1 kopya değiştirilemez (Immutable WORM) olmalı mı?
    require_immutable_copy: bool = True
    # Periyodik otomatik geri yükleme test frekansı (Gün cinsinden)
    max_verification_interval_days: int = 30
    # VSS gölge kopyalarının fidye yazılımlarına karşı sertleştirilmesi zorunlu mu?
    enforce_vss_hardening: bool = True


@dataclass
class SecurityAuditFinding:
    """Yedekleme ve kurtarma denetiminde tespit edilen güvenlik açığı veya SLA sapması."""
    # Kural kodu
    rule_id: str
    # Şiddet derecesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Bulgu başlığı
    title: str
    # Detaylı teknik açıklama
    description: str
    # İlgili güvenlik standardı (NIST SP 800-209, CIS Control 11, ISO 27001 A.8.13)
    compliance_ref: str
    # Düzeltme adımı
    remediation_step: str


@dataclass
class RecoverySimulationResult:
    """Bir felaket veya fidye yazılımı anında geri yükleme simülasyonu sonucu."""
    # Simülasyon ID
    simulation_id: str
    # Geri yükleme başarılı oldu mu?
    success: bool
    # Durum kodu
    status: str
    # Gerçekleşen RPO (Kaybedilen veri süresi - Dakika)
    actual_rpo_minutes: float
    # Gerçekleşen RTO (Sistemi ayağa kaldırma süresi - Dakika)
    actual_rto_minutes: float
    # RPO hedefi sağlandı mı?
    rpo_compliant: bool
    # RTO hedefi sağlandı mı?
    rto_compliant: bool
    # Sağlama toplamı (Checksum) doğrulandı mı?
    checksum_verified: bool
    # Detaylı açıklama
    detail: str


# ==============================================================================
# MOTOR SINIFI: YEDEK DOĞRULAMA VE KURTARMA DENETÇİSİ
# ==============================================================================

class BackupRecoveryEngine:
    """
    Yedek Doğrulama ve Kurtarma Noktası Güvenlik Motoru.
    3-2-1 Kuralı, Değiştirilemezlik (WORM), RPO/RTO SLA hesaplamaları,
    Sağlama toplamı (Checksum) bütünlüğü ve Fidye Yazılımı simülasyonunu yönetir.
    """

    def __init__(self, policy: BackupPolicy, artifacts: List[BackupArtifact]):
        # Yedekleme politikası saklanır
        self.policy = policy
        # Mevcut yedek arşivleri listesi saklanır
        self.artifacts = artifacts

    def audit_backup_architecture(self) -> List[SecurityAuditFinding]:
        """
        Mevcut yedekleme envanterini NIST SP 800-209, CIS Control 11 ve
        3-2-1-1-0 kurallarına göre baştan sona denetler.
        """
        findings: List[SecurityAuditFinding] = []

        # ----------------------------------------------------------------------
        # 1. 3-2-1 KURALI DENETİMLERİ (KOPYA SAYISI, MEDYA ÇEŞİTLİLİĞİ, OFFSITE)
        # ----------------------------------------------------------------------
        total_copies = len(self.artifacts)
        if total_copies < self.policy.required_min_copies:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-321-TOTAL-COPIES",
                severity="CRITICAL",
                title=f"Yetersiz Yedek Kopyası Sayısı ({total_copies}/{self.policy.required_min_copies})",
                description=f"3-2-1 kuralı gereğince en az {self.policy.required_min_copies} bağımsız kopya bulunmalıdır. Mevcut kopya: {total_copies}.",
                compliance_ref="CIS Control 11.2 / NIST SP 800-209 Sec 4.2",
                remediation_step="Yedekleme yazılımında ikincil ve üçüncül kopyalama işleri (Backup Copy Job) tanımlanmalıdır."
            ))

        # Medya çeşitliliği denetimi
        distinct_media = {a.media_type for a in self.artifacts}
        if len(distinct_media) < self.policy.required_min_media_types:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-321-MEDIA-TYPES",
                severity="HIGH",
                title=f"Yetersiz Depolama Medyası Çeşitliliği ({len(distinct_media)} Tür)",
                description="Tüm yedekler aynı depolama ortamında tutulmaktadır. Depolama donanımının arızalanması tüm kopyaları yok eder.",
                compliance_ref="NIST SP 800-209 Sec 4.2 / 3-2-1 Kuralı",
                remediation_step="Yedekler en az iki farklı fiziksel/mantıksal ortama (örn: Disk + Bulut Nesne Depolama) yazılmalıdır."
            ))

        # Saha dışı (Off-site) kopya denetimi
        has_offsite = any(a.is_offsite for a in self.artifacts)
        if self.policy.require_offsite_copy and not has_offsite:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-321-NO-OFFSITE",
                severity="CRITICAL",
                title="Saha Dışı (Off-site / Cloud) Yedek Kopyası Bulunmuyor",
                description="Tüm yedekler birincil veri merkezinde bulunmaktadır. Yangın, sel veya bina seviyesinde felakette tüm veriler kaybedilir.",
                compliance_ref="ISO 27001 A.8.14 / CIS Control 11.3",
                remediation_step="Yedeklerin bir kopyası coğrafi olarak farklı bir lokasyona veya bulut nesne depolama kasasına aktarılmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 2. DEĞİŞTİRİLEMEZLİK (IMMUTABILITY / WORM) DENETİMİ
        # ----------------------------------------------------------------------
        has_immutable = any(a.immutability_mode == ImmutabilityMode.COMPLIANCE for a in self.artifacts)
        if self.policy.require_immutable_copy and not has_immutable:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-IMMUTABLE-COMPLIANCE",
                severity="CRITICAL",
                title="Değiştirilemez (WORM / Immutable) Yedek Koruması Bulunmuyor",
                description="Hiçbir yedek WORM (Compliance) modunda değildir. Domain Admin yetkisi ele geçiren bir fidye yazılımı tüm yedekleri silebilir.",
                compliance_ref="NIST SP 800-209 Sec 4.4 (Ransomware Defense) / CISA Alert AA21-243A",
                remediation_step="AWS S3 Object Lock Compliance Mode veya Linux Hardened Repository ile değiştirilemez yedekleme zorunlu kılınmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 3. RPO (KURTARMA NOKTASI HEDEFİ) SLA DENETİMİ
        # ----------------------------------------------------------------------
        if self.artifacts:
            # En güncel yedeğin zamanı bulunur
            latest_backup_time = max(datetime.fromisoformat(a.created_at_utc.replace("Z", "+00:00")) for a in self.artifacts)
            now = datetime.now(timezone.utc)
            actual_gap_minutes = (now - latest_backup_time).total_seconds() / 60.0

            if actual_gap_minutes > self.policy.target_rpo_minutes:
                findings.append(SecurityAuditFinding(
                    rule_id="BCK-RPO-BREACH",
                    severity="HIGH",
                    title=f"RPO Hedefi İhlal Edildi ({actual_gap_minutes:.1f} dk > {self.policy.target_rpo_minutes} dk)",
                    description=f"Son başarılı yedekten bu yana geçen süre ({actual_gap_minutes:.1f} dk), kurumun RPO hedefinden ({self.policy.target_rpo_minutes} dk) büyüktür.",
                    compliance_ref="ISO 22301 / NIST SP 800-34 Rev 1",
                    remediation_step="Yedekleme frekansı artırılmalı veya kritik veritabanları için Sürekli Veri Koruma (CDP) devreye alınmalıdır."
                ))

        # ----------------------------------------------------------------------
        # 4. YEDEK DOĞRULAMA VE GERİ YÜKLEME TESTİ DENETİMİ
        # ----------------------------------------------------------------------
        unverified_artifacts = []
        for a in self.artifacts:
            if not a.last_verified_at_utc:
                unverified_artifacts.append(a.backup_id)
            else:
                last_v = datetime.fromisoformat(a.last_verified_at_utc.replace("Z", "+00:00"))
                gap_days = (datetime.now(timezone.utc) - last_v).days
                if gap_days > self.policy.max_verification_interval_days:
                    unverified_artifacts.append(a.backup_id)

        if unverified_artifacts:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-UNVERIFIED-TESTS",
                severity="HIGH",
                title=f"Doğrulanmamış Yedek Noktaları Bulunuyor ({len(unverified_artifacts)} Adet)",
                description=f"Yedeklerin periyodik geri yükleme testleri ({self.policy.max_verification_interval_days} gün) yapılmamıştır. Kurtarma anında yedeğin bozuk olduğu anlaşılabilir.",
                compliance_ref="CIS Control 11.5 (Test Data Recovery) / NIST 800-209",
                remediation_step="Otomatik sanal alan (sandbox) geri yükleme doğrulama işleri (SureBackup / Instant Recovery) planlanmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 5. SESSİZ BOZULMA (BIT ROT) VE CHECK_SUM BÜTÜNLÜK DENETİMİ
        # ----------------------------------------------------------------------
        corrupted_artifacts = [a.backup_id for a in self.artifacts if a.is_corrupted]
        if corrupted_artifacts:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-CHECKSUM-CORRUPTED",
                severity="CRITICAL",
                title=f"Bozuk Sağlama Toplamı / Bit Çürümesi (Bit Rot) Tespit Edildi ({len(corrupted_artifacts)} Adet)",
                description=f"Yedek arşivlerinin sağlama toplamı eşleşmemektedir: {corrupted_artifacts}. Medya bozulmuş veya fidye yazılımı tarafından değiştirilmiştir.",
                compliance_ref="NIST SP 800-209 Sec 4.3 (Data Integrity)",
                remediation_step="Bozuk yedek arşivleri karantinaya alınmalı; temiz ikincil/üçüncül kopyadan otomatik onarım yapılmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 6. WINDOWS GÖLGE KOPYA (VSS) KORUMA DENETİMİ
        # ----------------------------------------------------------------------
        unprotected_vss = [a.backup_id for a in self.artifacts if not a.vss_shadow_protected]
        if self.policy.enforce_vss_hardening and unprotected_vss:
            findings.append(SecurityAuditFinding(
                rule_id="BCK-VSS-UNPROTECTED",
                severity="HIGH",
                title="Gölge Kopyalar (VSS) Yetkisiz Silinmeye Karşı Savunmasız",
                description="Uç noktalardaki Volume Shadow Copy mekanizması sertleştirilmemiştir; 'vssadmin delete shadows' komutuyla anında silinebilir.",
                compliance_ref="MITRE ATT&CK T1490 (Inhibit System Recovery)",
                remediation_step="VSSAdmin ve WMI gölge kopya silme izinleri ACL ile kısıtlanmalı, EDR tamper koruması açılmalıdır."
            ))

        return findings

    def simulate_recovery(self, disaster_time_utc: Optional[str] = None) -> RecoverySimulationResult:
        """
        En güncel geçerli ve bozulmamış yedek noktasından geri yükleme simülasyonu yapar.
        RPO ve RTO başarı durumunu hesaplar.
        """
        # Felaket anı belirtilmemişse şu an kabul edilir
        d_time = datetime.fromisoformat(disaster_time_utc.replace("Z", "+00:00")) if disaster_time_utc else datetime.now(timezone.utc)

        # Bozulmamış ve kurtarılabilir yedekler filtrelenir
        valid_backups = [a for a in self.artifacts if not a.is_corrupted]

        if not valid_backups:
            return RecoverySimulationResult(
                simulation_id="SIM-REC-FAILED",
                success=False,
                status="RANSOMWARE_WIPEOUT",
                actual_rpo_minutes=99999.0,
                actual_rto_minutes=99999.0,
                rpo_compliant=False,
                rto_compliant=False,
                checksum_verified=False,
                detail="Kurtarılabilir hiçbir geçerli yedek noktası bulunamadı! Tüm kopyalar bozulmuş ya da silinmiş."
            )

        # En güncel geçerli yedek seçilir
        best_backup = max(valid_backups, key=lambda a: datetime.fromisoformat(a.created_at_utc.replace("Z", "+00:00")))
        backup_time = datetime.fromisoformat(best_backup.created_at_utc.replace("Z", "+00:00"))

        # RPO hesabı: Felaket anı ile son yedek arasındaki fark
        actual_rpo = max(0.0, (d_time - backup_time).total_seconds() / 60.0)

        # RTO hesabı: Medya türüne ve veri boyutuna göre simüle edilen geri yükleme süresi
        # NVMe: 500 MB/s, SAN: 300 MB/s, Cloud: 100 MB/s, NAS: 80 MB/s, Tape: 40 MB/s
        speed_mb_s = {
            StorageMediaType.LOCAL_NVME: 500.0,
            StorageMediaType.ENTERPRISE_SAN: 300.0,
            StorageMediaType.CLOUD_S3_OBJECT: 100.0,
            StorageMediaType.NETWORK_NAS_SMB: 80.0,
            StorageMediaType.AIR_GAPPED_COLD: 60.0,
            StorageMediaType.OFFSITE_TAPE: 40.0
        }.get(best_backup.media_type, 100.0)

        # Geri yükleme süresi (Dakika cinsinden) + 10 dk işletim sistemi önyükleme süresi
        transfer_minutes = (best_backup.size_mb / speed_mb_s) / 60.0
        actual_rto = transfer_minutes + 10.0

        rpo_ok = actual_rpo <= self.policy.target_rpo_minutes
        rto_ok = actual_rto <= self.policy.target_rto_minutes

        return RecoverySimulationResult(
            simulation_id=f"SIM-REC-{best_backup.backup_id}",
            success=True,
            status="RECOVERY_SUCCESS",
            actual_rpo_minutes=round(actual_rpo, 1),
            actual_rto_minutes=round(actual_rto, 1),
            rpo_compliant=rpo_ok,
            rto_compliant=rto_ok,
            checksum_verified=True,
            detail=f"Yedek noktası '{best_backup.backup_id}' ({best_backup.media_type.value}) üzerinden geri yükleme başarıyla simüle edildi."
        )


# ==============================================================================
# FİDYE YAZILIMI SALDIRI SİMÜLATÖRÜ (RANSOMWARE WIPEOUT SIMULATION)
# ==============================================================================

class RansomwareAttackSimulator:
    """
    Fidye yazılımlarının (LockBit, BlackCat) yedek altyapısına yönelik
    saldırı taktiklerini (VSS silme, yerel/ağ yedeklerini şifreleme, S3 silme) simüle eder.
    """

    @staticmethod
    def simulate_attack(artifacts: List[BackupArtifact]) -> Tuple[List[BackupArtifact], Dict[str, Any]]:
        """
        Saldırı icra eder:
        1. VSS kopyaları silinir (vssadmin delete shadows).
        2. Değiştirilemez (WORM) olmayan tüm yerel ve ağ yedekleri şifrelenir/silinir.
        3. WORM/Compliance modundaki yedekler silinemez (AWS S3 Object Lock korur).
        """
        surviving_artifacts: List[BackupArtifact] = []
        destroyed_count = 0
        preserved_count = 0
        attack_log: List[str] = []

        for art in artifacts:
            # 1. VSS koruması yoksa gölge kopyalar yok edilir
            if not art.vss_shadow_protected:
                attack_log.append(f"[!] {art.backup_id}: VSS kopyaları 'vssadmin delete shadows /all /quiet' ile silindi.")

            # 2. Değiştirilemezlik (WORM) kontrolü
            if art.immutability_mode == ImmutabilityMode.COMPLIANCE:
                # Saldırgan silemez!
                preserved_count += 1
                surviving_artifacts.append(art)
                attack_log.append(f"[+] {art.backup_id}: S3 Object Lock COMPLIANCE modunda; fidye yazılımı silme isteği 403 Access Denied ile engellendi!")
            elif art.is_air_gapped:
                # Ağdan erişilemez!
                preserved_count += 1
                surviving_artifacts.append(art)
                attack_log.append(f"[+] {art.backup_id}: Fiziksel olarak hava boşluklu (Air-gapped); saldırgan ağ üzerinden ulaşamadı.")
            else:
                # Değiştirilebilir yedekler şifrelenir veya silinir
                destroyed_count += 1
                attack_log.append(f"[-] {art.backup_id} ({art.media_type.value}): WORM koruması yok; fidye yazılımı tarafından şifrelendi/silindi.")

        summary = {
            "total_before_attack": len(artifacts),
            "destroyed_backups": destroyed_count,
            "surviving_backups": preserved_count,
            "ransomware_wipeout_resisted": preserved_count > 0,
            "attack_log": attack_log
        }
        return surviving_artifacts, summary


# ==============================================================================
# SERTLEŞTİRME VE DÜZELTME KOMUT DOSYASI ÜRETİCİSİ
# ==============================================================================

class BackupHardeningRemediationGenerator:
    """
    Değiştirilemez depolama (WORM / Object Lock), otomatik SHA-256 doğrulama
    ve VSS koruması için kurumsal PowerShell ve Bash betikleri üretir.
    """

    @staticmethod
    def generate_windows_vss_and_backup_hardening_script() -> str:
        """Windows ortamında VSS gölge kopyalarını koruyan ve otomatik sağlama toplamı alan PowerShell betiği."""
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Windows VSS Gölge Kopya ve Yedek Bütünlüğü Sertleştirme Betiği",
            "# ==============================================================================",
            "$ErrorActionPreference = 'Stop'",
            "",
            "# 1. VSS VE VSSADMIN ARAÇLARININ YETKİSİZ ÇALIŞTIRILMASINI ENGELLEME",
            "# Standart kullanıcıların ve tehlikeli süreçlerin vssadmin çağırmasını engellemek için ACL sıkılaştırılır",
            "$VssAdminPath = \"$env:SystemRoot\\System32\\vssadmin.exe\"",
            "& icacls $VssAdminPath /deny \"Users:(X)\" | Out-Null",
            "",
            "# 2. GÖLGE KOPYA SERVİSİNİ VE AYRILAN ALANI YAPILANDIRMA",
            "# C: sürücüsü için gölge kopya alan sınırını %15 olarak belirleme",
            "& vssadmin resize shadowstorage /for=C: /on=C: /maxsize=15% | Out-Null",
            "",
            "# 3. YEDEK ARŞİVLERİNİN SHA-256 SAĞLAMA TOPLAMINI OTOMATİK HESAPLAMA",
            "$BackupDir = 'C:\\Backups\\Production'",
            "if (Test-Path $BackupDir) {",
            "    Get-ChildItem -Path $BackupDir -Filter *.bak | ForEach-Object {",
            "        $Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash",
            "        Set-Content -Path \"$($_.FullName).sha256\" -Value $Hash",
            "        Write-Output \"[+] Doğrulandı: $($_.Name) -> SHA256: $Hash\"",
            "    }",
            "}",
            "",
            "Write-Output '[+] VSS koruması ve SHA-256 sağlama toplamı ilkeleri başarıyla uygulandı.'"
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_linux_immutable_backup_script(bucket_name: str = "enterprise-immutable-backups") -> str:
        """Linux ortamında AWS S3 Object Lock (Compliance Mode) ile değiştirilemez yedek yükleyen Bash betiği."""
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux Değiştirilemez Yedekleme (S3 WORM / Object Lock Compliance Mode) Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            f"BUCKET=\"{bucket_name}\"",
            "BACKUP_FILE=\"/tmp/db_prod_backup_$(date +%Y%m%d_%H%M%S).tar.gz\"",
            "",
            "# 1. SAĞLAMA TOPLAMI (SHA-256) HESAPLAMA",
            "sha256sum \"${BACKUP_FILE}\" > \"${BACKUP_FILE}.sha256\"",
            "",
            "# 2. DEĞİŞTİRİLEMEZ (WORM) MODDA S3 BUCKET'A YÜKLEME (30 GÜN KİLİT)",
            "RETENTION_DATE=$(date -d \"+30 days\" --iso-8601=seconds --utc)",
            "aws s3 cp \"${BACKUP_FILE}\" \"s3://${BUCKET}/\" \\",
            "  --object-lock-mode COMPLIANCE \\",
            "  --object-lock-retain-until-date \"${RETENTION_DATE}\"",
            "",
            "echo \"[+] Yedek S3 Object Lock COMPLIANCE modunda başarıyla mühürlendi (30 Gün Silinemez).\""
        ]
        return "\n".join(lines)
