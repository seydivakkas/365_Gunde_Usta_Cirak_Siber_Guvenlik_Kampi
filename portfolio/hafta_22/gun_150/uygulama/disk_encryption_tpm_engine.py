"""
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)

Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, tersine mühendislik yapılamaz.
"""

# Gerekli standart kütüphaneler içe aktarılır
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# SABİTLER VE PCR STANDART TANIMLARI (TCG STANDARTLARI)
# ==============================================================================

# Güvenilir Bilgi İşlem Grubu (TCG - Trusted Computing Group) standart PCR açıklamaları
TCG_PCR_DESCRIPTIONS: Dict[int, str] = {
    0: "CRTM, BIOS/UEFI Anakart Üretici Bellenimi Kodu (Firmware Code)",
    1: "Anakart ve Platform Donanım Yapılandırması (Platform Settings)",
    2: "Genişleme Kartları / Ek Donanım ROM Kodları (Option ROMs, GPU Firmware)",
    3: "Genişleme Kartı Yapılandırması ve Cihaz Parametreleri",
    4: "MBR/GPT Önyükleyici Kodu ve Boot Manager (Bootloader Code)",
    5: "Önyükleme Yapılandırma Verisi (BCD - Boot Configuration Data)",
    6: "Durum Sürdürme ve Uyku/Hazırda Bekletme Parametreleri (Resume State)",
    7: "Güvenli Önyükleme Durumu ve Sertifikaları (Secure Boot State: PK, KEK, db, dbx)",
    8: "Linux/GRUB Komut Satırı ve Çekirdek Ölçümleri",
    9: "Linux Initramfs ve EFI İkili Görüntüleri",
    10: "Bütünlük Ölçüm Mimarisi (IMA - Integrity Measurement Architecture)",
    11: "BitLocker Erişim Kontrol Politikası ve İstemci Koruması",
    12: "İstemci / Veri Alanı Ölçümleri"
}

# Varsayılan başlangıç sıfır hash değeri (SHA-256 için 64 karakter '0')
PCR_ZERO_DIGEST = "0" * 64

# ==============================================================================
# ENUM VE VERİ MODELLERİ
# ==============================================================================

class EncryptionAlgorithm(str, Enum):
    """Disk ve birim şifreleme algoritmaları ve modları."""
    # En güçlü endüstri standardı (XTS modu veri manipülasyonuna karşı korur)
    XTS_AES_256 = "XTS-AES-256"
    # Standart XTS şifreleme modu
    XTS_AES_128 = "XTS-AES-128"
    # Eski ve zayıf mod (CBC modu bit çevirme saldırılarına açıktır)
    AES_CBC_256 = "AES-CBC-256"
    # Eski 128-bit CBC modu (Önerilmez)
    AES_CBC_128 = "AES-CBC-128"
    # Şifrelenmemiş düz metin (Kritik güvenlik riski)
    PLAINTEXT = "PLAINTEXT"


class KeyProtectorType(str, Enum):
    """BitLocker ve LUKS anahtar koruyucu türleri."""
    # Yalnızca TPM yongası (Kullanıcı etkileşimsiz, SPI sniffing riskine açık)
    TPM_ONLY = "TPM_ONLY"
    # TPM + Açılış PIN Kodu (En güvenli iki faktörlü açılış koruması)
    TPM_AND_PIN = "TPM_AND_PIN"
    # TPM + Başlangıç USB Anahtarı
    TPM_AND_STARTUP_KEY = "TPM_AND_STARTUP_KEY"
    # Parola / Parola İfadesi (Passphrase)
    PASSWORD = "PASSWORD"
    # 48 Haneli Sayısal Kurtarma Parolası (Recovery Password)
    RECOVERY_PASSWORD = "RECOVERY_PASSWORD"


class KeyDerivationFunction(str, Enum):
    """Anahtar türetme fonksiyonları (KDF - LUKS2 ve BitLocker için)."""
    # Bellek zorluklu modern KDF (GPU/ASIC kırma saldırılarına karşı en dayanıklı)
    ARGON2ID = "Argon2id"
    # Argon2i modu
    ARGON2I = "Argon2i"
    # Eski ve GPU kırma saldırılarına karşı zayıf KDF (LUKS1 varsayılanı)
    PBKDF2 = "PBKDF2"


@dataclass
class PcrRegister:
    """Tek bir TPM Platform Yapılandırma Kaydedicisini (PCR) temsil eder."""
    # Kaydedici indeksi (0-23 arası)
    index: int
    # Mevcut SHA-256 özeti
    digest: str = PCR_ZERO_DIGEST
    # Açıklayıcı donanım bileşeni tanımı
    description: str = ""

    def extend(self, measurement_bytes: bytes) -> str:
        """
        PCR genişletme işlemi: PCR_yeni = SHA256(PCR_eski || SHA256(ölçüm)).
        Bu işlem geriye doğru işletilemez (One-way measurement chain).
        """
        # Gelen ölçüm verisinin SHA-256 özeti alınır
        data_hash = hashlib.sha256(measurement_bytes).digest()
        # Mevcut özet bayt dizisine dönüştürülür
        current_bytes = bytes.fromhex(self.digest)
        # İki özet uç uca eklenerek yeni özet hesaplanır
        new_digest = hashlib.sha256(current_bytes + data_hash).hexdigest()
        # Yeni özet PCR değerine atanır
        self.digest = new_digest
        # Hesaplanan yeni özet döndürülür
        return self.digest


@dataclass
class SealedBlob:
    """TPM tarafından belirli bir PCR durumuna mühürlenmiş (sealed) anahtar nesnesi."""
    # Şifrelenmiş anahtar verisi
    encrypted_payload: str
    # Mühürleme esnasında kilitlenen PCR indeksleri listesi (örn: [0, 2, 4, 7])
    sealed_pcr_indices: List[int]
    # Beklenen bileşik PCR özeti (Composite Hash)
    expected_composite_hash: str
    # Koruyucu PIN kodu hash'i (varsa)
    pin_hash: Optional[str] = None


@dataclass
class SecurityAuditFinding:
    """Disk şifreleme ve TPM denetiminde tespit edilen güvenlik sapması."""
    # Kural kodu
    rule_id: str
    # Şiddet seviyesi: CRITICAL, HIGH, MEDIUM, LOW
    severity: str
    # Bulgu başlığı
    title: str
    # Detaylı teknik açıklama
    description: str
    # İlgili güvenlik standardı (NIST SP 800-111, CIS Benchmark)
    compliance_ref: str
    # Düzeltme adımı
    remediation_step: str


@dataclass
class UnsealResult:
    """TPM mühür çözme (unseal) operasyonu sonucu."""
    # Başarılı mı?
    success: bool
    # Çözülen anahtar (başarısızsa None)
    unsealed_key: Optional[str]
    # Karar veren katman / durum
    status_code: str
    # Açıklayıcı mesaj
    detail: str
    # Tetiklenen PCR uyumsuzlukları
    pcr_mismatches: List[int] = field(default_factory=list)


# ==============================================================================
# BİLEŞEN: DONANIM TPM 2.0 SİMÜLATÖRÜ
# ==============================================================================

class Tpm2Simulator:
    """
    Güvenilir Platform Modülü (TPM 2.0) Kriptografik Yongası Simülatörü.
    PCR ölçümleri, Endorsement Key (EK), Storage Root Key (SRK) ve
    Mühürleme (Sealing / Unsealing) mekanizmalarını yönetir.
    """

    def __init__(self, tpm_id: str = "TPM2_VIRTUAL_CHIP"):
        # Yonganın benzersiz kimliği
        self.tpm_id = tpm_id
        # Donanım Üretici Kimlik Anahtarı (Endorsement Key - EK)
        self.endorsement_key = hashlib.sha256(f"EK_{tpm_id}_{secrets.token_hex(8)}".encode()).hexdigest()
        # Depolama Kök Anahtarı (Storage Root Key - SRK)
        self.storage_root_key = hashlib.sha256(f"SRK_{tpm_id}_{secrets.token_hex(8)}".encode()).hexdigest()
        # 24 adet PCR kaydedicisi başlatılır (0-23)
        self.pcrs: Dict[int, PcrRegister] = {}
        # Kaydediciler sıfırlanır
        self.reset_pcrs()

    def reset_pcrs(self) -> None:
        """Tüm PCR kaydedicilerini sıfır durumuna (PCR_ZERO_DIGEST) döndürür."""
        # 0'dan 23'e kadar tüm kaydediciler oluşturulur
        for i in range(24):
            # Açıklaması TCG tablosundan alınır
            desc = TCG_PCR_DESCRIPTIONS.get(i, f"Kullanıcı/Uygulama Alanı PCR {i}")
            # Kaydedici sıfırlanır
            self.pcrs[i] = PcrRegister(index=i, digest=PCR_ZERO_DIGEST, description=desc)

    def extend_pcr(self, pcr_index: int, measurement: bytes) -> str:
        """Belirtilen PCR kaydedicisine yeni bir donanım/yazılım ölçümü ekler."""
        # İndeks geçerliliği kontrol edilir
        if pcr_index not in self.pcrs:
            # Geçersiz indeks hatası fırlatılır
            raise ValueError(f"Geçersiz PCR indeksi: {pcr_index}. İndeks 0-23 arasında olmalıdır.")
        # İlgili PCR genişletilir
        return self.pcrs[pcr_index].extend(measurement)

    def calculate_composite_hash(self, pcr_indices: List[int]) -> str:
        """Belirtilen PCR kaydedicilerinin mevcut özetlerini birleştirerek bileşik özet üretir."""
        # Sıralı indeks listesi oluşturulur
        sorted_indices = sorted(pcr_indices)
        # Özetler birleştirilir
        concat_digests = "".join(self.pcrs[idx].digest for idx in sorted_indices)
        # Bileşik SHA-256 hesaplanır
        return hashlib.sha256(concat_digests.encode()).hexdigest()

    def seal_key(self, master_key: str, pcr_indices: List[int], user_pin: Optional[str] = None) -> SealedBlob:
        """
        Disk anahtarını (VMK / LUKS Master Key) mevcut PCR durumuna ve opsiyonel PIN koduna mühürler.
        """
        # PCR indeksleri kontrol edilir
        for idx in pcr_indices:
            if idx not in self.pcrs:
                raise ValueError(f"Mühürleme için geçersiz PCR: {idx}")

        # Mevcut bileşik özet hesaplanır
        composite_hash = self.calculate_composite_hash(pcr_indices)

        # PIN varsa hash'lenir
        pin_hash = hashlib.sha256(user_pin.encode()).hexdigest() if user_pin else None

        # Mühürleme anahtarı (KDF: SRK + Composite Hash + PIN)
        kdf_input = f"{self.storage_root_key}:{composite_hash}:{pin_hash or 'NOPIN'}"
        encryption_key = hashlib.sha256(kdf_input.encode()).digest()

        # Simüle edilmiş XOR/HMAC şifreleme (Anahtar baytları şifrelenir)
        key_bytes = master_key.encode("utf-8")
        # Tekrarlanan anahtar ile maskeleme yapılır
        encrypted_bytes = bytes([b ^ encryption_key[i % len(encryption_key)] for i, b in enumerate(key_bytes)])
        # Onaltılık dizgeye çevrilir
        encrypted_payload = encrypted_bytes.hex()

        # Mühürlü nesne oluşturulur ve döndürülür
        return SealedBlob(
            encrypted_payload=encrypted_payload,
            sealed_pcr_indices=sorted(pcr_indices),
            expected_composite_hash=composite_hash,
            pin_hash=pin_hash
        )

    def unseal_key(self, blob: SealedBlob, user_pin: Optional[str] = None) -> UnsealResult:
        """
        Mühürlenmiş disk anahtarını çözer. Mevcut PCR değerleri veya PIN uyuşmazsa anahtarı vermez!
        """
        # Uyuşmayan PCR listesi
        mismatches: List[int] = []

        # 1. PCR Uyuşmazlığı Kontrolü
        current_composite = self.calculate_composite_hash(blob.sealed_pcr_indices)
        if current_composite != blob.expected_composite_hash:
            # Hangi PCR'ların değiştiği tespit edilir
            for idx in blob.sealed_pcr_indices:
                # PCR'ın geçerli durumu ile beklenen durum uyuşmazlığı
                mismatches.append(idx)

            # Başarısız sonuç döndürülür
            return UnsealResult(
                success=False,
                unsealed_key=None,
                status_code="TPM_RC_PCR_CHANGED",
                detail=f"Platform Bütünlük Hatası: PCR değerleri değişti! Değişen PCR'lar: {mismatches}. Saldırı şüphesi veya donanım değişikliği.",
                pcr_mismatches=mismatches
            )

        # 2. PIN Kodu Doğrulaması
        if blob.pin_hash:
            # Kullanıcı PIN girdi mi?
            if not user_pin:
                return UnsealResult(
                    success=False,
                    unsealed_key=None,
                    status_code="TPM_RC_PIN_REQUIRED",
                    detail="Bu birim TPM + PIN ile kilitlenmiştir; PIN kodu girilmedi.",
                    pcr_mismatches=[]
                )
            # Girilen PIN doğru mu?
            entered_pin_hash = hashlib.sha256(user_pin.encode()).hexdigest()
            if entered_pin_hash != blob.pin_hash:
                return UnsealResult(
                    success=False,
                    unsealed_key=None,
                    status_code="TPM_RC_AUTH_FAIL",
                    detail="Girilen TPM başlangıç PIN kodu hatalı! Yetkisiz erişim engellendi.",
                    pcr_mismatches=[]
                )

        # 3. Anahtar Çözme (Decryption)
        kdf_input = f"{self.storage_root_key}:{current_composite}:{blob.pin_hash or 'NOPIN'}"
        encryption_key = hashlib.sha256(kdf_input.encode()).digest()

        # Şifreli veri çözülür
        encrypted_bytes = bytes.fromhex(blob.encrypted_payload)
        decrypted_bytes = bytes([b ^ encryption_key[i % len(encryption_key)] for i, b in enumerate(encrypted_bytes)])
        recovered_key = decrypted_bytes.decode("utf-8")

        # Başarılı sonuç döndürülür
        return UnsealResult(
            success=True,
            unsealed_key=recovered_key,
            status_code="TPM_SUCCESS",
            detail="Bütünlük doğrulandı: Platform konfigürasyonu güvenli, disk anahtarı başarıyla çözüldü.",
            pcr_mismatches=[]
        )


# ==============================================================================
# SİSTEM VE BİRİM YAPILANDIRMA MODELLERİ
# ==============================================================================

@dataclass
class VolumeEncryptionConfig:
    """Tam Disk Şifreleme (FDE - BitLocker veya LUKS2) yapılandırma spesifikasyonu."""
    # Birim adı veya harfi (örn: 'C:' veya '/dev/nvme0n1p3')
    volume_identifier: str
    # İşletim sistemi türü ('windows' veya 'linux')
    os_type: str
    # Şifreleme algoritması
    cipher_algorithm: EncryptionAlgorithm
    # Anahtar koruyucu türleri listesi
    protectors: List[KeyProtectorType]
    # Mühürlenen PCR kaydedicileri listesi
    sealed_pcr_indices: List[int]
    # Güvenli Önyükleme (Secure Boot) etkin mi?
    secure_boot_enabled: bool = True
    # Çekirdek DMA Koruması / IOMMU etkin mi? (Thunderbolt/PCIe saldırılarına karşı)
    kernel_dma_protection: bool = True
    # LUKS için anahtar türetme fonksiyonu
    luks_kdf: KeyDerivationFunction = KeyDerivationFunction.ARGON2ID
    # Kurtarma parolası güvenli merkezi kasaya (Active Directory / Entra ID) yedeklendi mi?
    recovery_key_backed_up: bool = True
    # Kurtarma anahtarı düz metin yerel diskte saklanıyor mu? (Hata/zafiyet)
    plaintext_recovery_key_on_disk: bool = False
    # Başlangıç PIN kodu minimum uzunluğu (BitLocker için)
    pin_length: int = 6


# ==============================================================================
# MOTOR SINIFI: DİSK ŞİFRELEME VE TPM GÜVENLİK DENETÇİSİ
# ==============================================================================

class DiskEncryptionAuditor:
    """
    NIST SP 800-111, CIS Windows ve CIS Linux standartlarına göre
    BitLocker ve LUKS disk şifreleme ve TPM yapılandırmasını denetleyen motor.
    """

    def __init__(self, config: VolumeEncryptionConfig):
        # Denetlenecek yapılandırma saklanır
        self.config = config

    def audit_security(self) -> List[SecurityAuditFinding]:
        """Yapılandırma üzerindeki tüm kriptografik ve donanım izolasyon açıklarını denetler."""
        findings: List[SecurityAuditFinding] = []

        # ----------------------------------------------------------------------
        # 1. ŞİFRELEME ALGORİTMASI VE MOD DENETİMİ
        # ----------------------------------------------------------------------
        if self.config.cipher_algorithm == EncryptionAlgorithm.PLAINTEXT:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-ALGO-PLAINTEXT",
                severity="CRITICAL",
                title="Birim Tamamen Şifresiz (Plaintext Storage)",
                description="Disk birimi şifrelenmemiş durumdadır; cihazın çalınması durumunda tüm veriler sızdırılabilir.",
                compliance_ref="NIST SP 800-111 Sec 2.1 / ISO 27001 A.8.24",
                remediation_step="Birim derhal XTS-AES-256 algoritması ile tam disk şifreleme (BitLocker/LUKS) altına alınmalıdır."
            ))
        elif self.config.cipher_algorithm in (EncryptionAlgorithm.AES_CBC_128, EncryptionAlgorithm.AES_CBC_256):
            findings.append(SecurityAuditFinding(
                rule_id="ENC-ALGO-CBC-MODE",
                severity="HIGH",
                title="Zayıf Şifreleme Modu: CBC Kullanımı",
                description="CBC modu şifreleme bit çevirme (bit-flipping) ve veri manipülasyonu saldırılarına karşı koruma sağlamaz.",
                compliance_ref="NIST SP 800-38E / NIST SP 800-111",
                remediation_step="Şifreleme algoritması kurumsal standart olan 'XTS-AES-256' olarak güncellenmelidir."
            ))

        # ----------------------------------------------------------------------
        # 2. ANAHTAR KORUYUCU VE TPM+PIN DENETİMİ
        # ----------------------------------------------------------------------
        # Yalnızca TPM koruyucu varsa ve PIN yoksa (LPC/SPI Bus Sniffing riski)
        if KeyProtectorType.TPM_ONLY in self.config.protectors and KeyProtectorType.TPM_AND_PIN not in self.config.protectors:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-PROT-TPM-NO-PIN",
                severity="HIGH",
                title="PIN Koruması Olmayan Yalnızca TPM Yapılandırması",
                description="Sistem açılışta PIN sormamaktadır. Saldırgan ana kart üzerindeki SPI/LPC veri yolunu koklayarak (sniffing) şifre çözme anahtarını ele geçirebilir.",
                compliance_ref="MITRE ATT&CK T1552.001 / NSA BitLocker Guidance",
                remediation_step="Grup İlkesi (GPO) üzerinden 'Açılışta ek kimlik doğrulaması gerektir' seçilerek TPM+PIN zorunlu kılınmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 3. PCR MÜHÜRLEME POLİTİKASI (SEALING) DENETİMLERİ
        # ----------------------------------------------------------------------
        # PCR 7 (Secure Boot) kilitlenmemişse
        if 7 not in self.config.sealed_pcr_indices:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-PCR-NO-SECUREBOOT",
                severity="CRITICAL",
                title="PCR 7 (Güvenli Önyükleme Durumu) Mühür Politikasına Dahil Edilmemiş",
                description="Anahtar PCR 7'ye mühürlenmemiştir. Güvenli Önyükleme devre dışı bırakılsa veya sahte sertifika yüklense bile TPM anahtarı serbest bırakacaktır.",
                compliance_ref="Microsoft BitLocker PCR Architecture / TCG Specification",
                remediation_step="Mühürleme profiline PCR 7 eklenmeli ve 'manage-bde -protectors -update C: -tpm' komutu çalıştırılmalıdır."
            ))

        # PCR 0, 2 veya 4 (Firmware ve Bootloader) eksikse
        if not any(idx in self.config.sealed_pcr_indices for idx in [0, 4]):
            findings.append(SecurityAuditFinding(
                rule_id="ENC-PCR-MISSING-BOOT-INTEGRITY",
                severity="HIGH",
                title="Bellenim veya Önyükleyici PCR Kaydedicileri Eksik",
                description="PCR 0 (Firmware) veya PCR 4 (Bootloader) kilitlenmemiştir; kötü amaçlı önyükleyici (Evil Maid / Bootkit) saldırılarına zemin hazırlar.",
                compliance_ref="NIST SP 800-147 / NIST SP 800-155",
                remediation_step="Önyükleme bütünlüğü için PCR 0, 2, 4 ve 7 kaydedicileri birlikte mühürlenmelidir."
            ))

        # ----------------------------------------------------------------------
        # 4. GÜVENLİ ÖNYÜKLEME VE KERNEL DMA KORUMASI
        # ----------------------------------------------------------------------
        if not self.config.secure_boot_enabled:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-HW-SECUREBOOT-DISABLED",
                severity="CRITICAL",
                title="UEFI Güvenli Önyükleme (Secure Boot) Devre Dışı",
                description="Güvenli önyükleme kapalı olduğundan imzasız sürücüler ve ring-0 rootkit'ler önyükleme aşamasında belleğe yüklenebilir.",
                compliance_ref="CIS Benchmark 2.2.1 / NIST SP 800-193",
                remediation_step="UEFI BIOS ayarlarından 'Secure Boot' özelliği derhal aktif edilmelidir."
            ))

        if not self.config.kernel_dma_protection:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-HW-NO-DMA-PROTECTION",
                severity="HIGH",
                title="Çekirdek DMA Koruması (IOMMU) Devre Dışı",
                description="Thunderbolt veya harici PCIe portları üzerinden doğrudan bellek erişimi (DMA) saldırısıyla RAM'deki şifreleme anahtarları çalınabilir.",
                compliance_ref="Microsoft Secured-Core PC Standard / MITRE T1200",
                remediation_step="BIOS'ta Intel VT-d / AMD-Vi IOMMU sanallaştırması ve OS Kernel DMA Protection açılmalıdır."
            ))

        # ----------------------------------------------------------------------
        # 5. LINUX ÖZEL DENETİMLERİ (LUKS KDF)
        # ----------------------------------------------------------------------
        if self.config.os_type.lower() == "linux":
            if self.config.luks_kdf == KeyDerivationFunction.PBKDF2:
                findings.append(SecurityAuditFinding(
                    rule_id="ENC-LUKS-WEAK-KDF",
                    severity="MEDIUM",
                    title="LUKS Başlığında Zayıf KDF: PBKDF2 Kullanımı",
                    description="PBKDF2 fonksiyonu GPU destekli kaba kuvvet (brute-force) parola kırma saldırılarına karşı dayanıksızdır.",
                    compliance_ref="Argon2 IETF RFC 9106 / LUKS2 Specification",
                    remediation_step="'cryptsetup luksConvertKey --pbkdf argon2id' komutu ile anahtar türetme fonksiyonu Argon2id yapılmalıdır."
                ))

        # ----------------------------------------------------------------------
        # 6. KURTARMA ANAHTARI YÖNETİMİ DENETİMLERİ
        # ----------------------------------------------------------------------
        if self.config.plaintext_recovery_key_on_disk:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-KEY-PLAINTEXT-ON-DISK",
                severity="CRITICAL",
                title="Kurtarma Parolası Yerel Diskte Düz Metin Saklanıyor",
                description="48 haneli sayısal kurtarma parolası veya anahtar yedeği yerel diskte düz metin dosyada tespit edilmiştir.",
                compliance_ref="CWE-312 (Cleartext Storage of Sensitive Information)",
                remediation_step="Düz metin anahtar dosyası güvenli şekilde silinmeli; anahtar yalnızca Active Directory veya Entra ID'ye yedeklenmelidir."
            ))

        if not self.config.recovery_key_backed_up:
            findings.append(SecurityAuditFinding(
                rule_id="ENC-KEY-NO-CENTRAL-BACKUP",
                severity="HIGH",
                title="Kurtarma Anahtarı Merkezi Kasaya Yedeklenmemiş",
                description="Donanım arızası veya TPM sıfırlanması durumunda verilere kalıcı olarak erişilememe (erişilebilirlik kaybı) riski bulunmaktadır.",
                compliance_ref="ISO 27001 A.8.14 (Redundancy and Recovery)",
                remediation_step="Kurtarma anahtarı Active Directory Domain Services veya Azure AD / Intune üzerine yedeklenmelidir."
            ))

        return findings


# ==============================================================================
# SALDIRI VE DOĞRULAMA SİMÜLATÖRÜ (EVIL MAID / TAMPERING)
# ==============================================================================

class PhysicalAttackSimulator:
    """
    Fiziksel temas ve önyükleme manipülasyonu (Evil Maid, SPI Bus Sniffing,
    Secure Boot kapatma) ataklarını TPM üzerinde simüle eder.
    """

    @staticmethod
    def simulate_evil_maid_bootloader_tampering(tpm: Tpm2Simulator, sealed_blob: SealedBlob) -> UnsealResult:
        """
        Saldırganın diske sahte bir önyükleyici (malicious bootloader) yazarak
        PCR 4 değerini bozduğu Evil Maid senaryosunu simüle eder.
        """
        # Saldırganın değiştirdiği kötü amaçlı önyükleyici kodu ölçümü eklenir
        tampered_code = b"MALICIOUS_EVIL_MAID_BOOTLOADER_CODE_0xDEADBEEF"
        tpm.extend_pcr(4, tampered_code)

        # TPM'den anahtarı çözmesi istenir
        result = tpm.unseal_key(sealed_blob)
        return result

    @staticmethod
    def simulate_secure_boot_tampering(tpm: Tpm2Simulator, sealed_blob: SealedBlob) -> UnsealResult:
        """
        Saldırganın UEFI ayarlarına girip Secure Boot'u kapattığı veya sahte sertifika
        yüklediği senaryoyu (PCR 7 bozulması) simüle eder.
        """
        # Secure boot durumu değişimi ölçümü eklenir
        tampered_sb = b"SECURE_BOOT_DISABLED_OR_CUSTOM_PK_LOADED"
        tpm.extend_pcr(7, tampered_sb)

        # TPM'den anahtarı çözmesi istenir
        result = tpm.unseal_key(sealed_blob)
        return result


# ==============================================================================
# REMEDIATION VE SERTLEŞTİRME BETİĞİ ÜRETİCİSİ
# ==============================================================================

class DiskEncryptionRemediationGenerator:
    """
    Windows BitLocker ve Linux LUKS2 için kurumsal standartta sertleştirilmiş
    PowerShell ve Bash yapılandırma komut dosyaları üretir.
    """

    @staticmethod
    def generate_windows_bitlocker_hardening_script(drive_letter: str = "C:") -> str:
        """BitLocker için XTS-AES-256, TPM+PIN ve DMA Koruması sağlayan PowerShell betiği üretir."""
        lines = [
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Windows BitLocker TPM 2.0 + PIN ve XTS-AES-256 Sertleştirme Betiği",
            "# ==============================================================================",
            "$ErrorActionPreference = 'Stop'",
            "",
            "# 1. GRUP İLKESİ: XTS-AES-256 ŞİFRELEME ALGORİTMASINI ZORUNLU KILMA",
            "$RegPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE'",
            "if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }",
            "Set-ItemProperty -Path $RegPath -Name 'EncryptionMethodWithXtsOs' -Value 7 -Type DWord",
            "Set-ItemProperty -Path $RegPath -Name 'EncryptionMethodWithXtsFdv' -Value 7 -Type DWord",
            "",
            "# 2. TPM + PIN KORUYUCUSUNU ZORUNLU KILMA",
            "Set-ItemProperty -Path $RegPath -Name 'UseAdvancedStartup' -Value 1 -Type DWord",
            "Set-ItemProperty -Path $RegPath -Name 'EnableBDEWithNoTPM' -Value 0 -Type DWord",
            "Set-ItemProperty -Path $RegPath -Name 'UseTPM' -Value 2 -Type DWord",
            "Set-ItemProperty -Path $RegPath -Name 'UseTPMPIN' -Value 2 -Type DWord",
            "",
            "# 3. KURTARMA PAROLASINI ACTIVE DIRECTORY / ENTRA ID'YE YEDEKLEME",
            "Set-ItemProperty -Path $RegPath -Name 'OSRecovery' -Value 1 -Type DWord",
            "Set-ItemProperty -Path $RegPath -Name 'OSRequireActiveDirectoryBackup' -Value 1 -Type DWord",
            "",
            f"# 4. BİTLOCKER'I {drive_letter} SÜRÜCÜSÜNDE TPM + PIN İLE ETKİNLEŞTİRME",
            f"# Enable-BitLocker -MountPoint '{drive_letter}' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmAndPinProtector",
            "Write-Output '[+] BitLocker sertleştirme ilkeleri başarıyla uygulandı.'",
            "Write-Output '[+] XTS-AES-256 zorunlu kılındı, TPM+PIN kuralı devreye alındı.'"
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_linux_luks_tpm_script(device: str = "/dev/nvme0n1p3") -> str:
        """Linux LUKS2 birimini systemd-cryptenroll ve TPM2 PCR 0+2+4+7 ile bağlayan Bash betiği üretir."""
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Linux LUKS2 + TPM 2.0 (PCR 0+2+4+7) ve Argon2id Sertleştirme Betiği",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            f"TARGET_DEVICE=\"{device}\"",
            "",
            "# 1. LUKS2 BAŞLIĞINI ARGON2ID VE XTS-AES-256 İLE GÜNCELLEME",
            "cryptsetup luksConvertKey --pbkdf argon2id \"${TARGET_DEVICE}\"",
            "",
            "# 2. SYSTEMD-CRYPTENROLL İLE TPM2 YONGASINA MÜHÜRLEME (PCR 0, 2, 4, 7)",
            "systemd-cryptenroll \\",
            "  --tpm2-device=auto \\",
            "  --tpm2-pcrs=0+2+4+7 \\",
            "  --tpm2-with-pin=yes \\",
            "  \"${TARGET_DEVICE}\"",
            "",
            "echo \"[+] LUKS2 birimi TPM2 ve PCR 0+2+4+7 durumuna başarıyla mühürlendi.\""
        ]
        return "\n".join(lines)
