# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G037: Disk Bölümleri ve Dosya Sistemleri Güvenlik Denetçisi (Disk & Filesystem Security Auditor)

Bu modül, modern işletim sistemlerindeki disk bölümleri (Partitioning - MBR/GPT),
dosya sistemleri (NTFS, ext4, FAT32/exFAT), bağlama bayrakları (Mount Options: noexec, nosuid, nodev),
tam disk şifreleme (LUKS/BitLocker) ve disk doluluk oranlarını güvenlik ve adli bilişim
perspektifiyle derinlemesine analiz eder.
"""

# İşletim sistemi ve temel sistem fonksiyonları için os modülünü içeri aktarıyoruz.
import os

# Sistemden argümanları okumak ve çıkış kodlarını yönetmek için sys modülünü dahil ediyoruz.
import sys

# Yapılandırılmış telemetri verilerini okumak ve ayrıştırmak için json kütüphanesini kullanıyoruz.
import json

# Komut satırı parametrelerini güvenli ayrıştırmak için argparse kütüphanesini içeri aktarıyoruz.
import argparse

# ISO standartlarında zaman damgası üretmek için datetime ve timezone modüllerini içeri aktarıyoruz.
from datetime import datetime, timezone

# Tip güvenliği ve statik kod analizi için typing yapılarını dahil ediyoruz.
from typing import Dict, Any, List, Optional, Tuple


# Telemetri veri yapısındaki şema ve mantık bozukluklarını bildiren özel istisna sınıfı tanımlıyoruz.
class DiskTelemetryValidationError(Exception):
    """
    Disk ve dosya sistemi telemetri verisinde tespit edilen şema ve sınır hataları için istisna.
    """
    # Kurucu metod ile gelen hata açıklamasını temel Exception sınıfına aktarıyoruz.
    def __init__(self, message: str) -> None:
        # Üst sınıf olan Exception kurucusunu çağırıyoruz.
        super().__init__(message)


# Disk ve dosya sistemlerini denetleyen ana motor sınıfımızı tanımlıyoruz.
class DiskPartitionFsAuditor:
    """
    Disk bölümleri, dosya sistemleri, şifreleme ve bağlama bayraklarını denetleyen uzman sınıf.
    """

    # Kritik bağlama yollarında zorunlu güvenlik bayrakları sözlüğü tanımlıyoruz.
    HARDENED_MOUNT_RULES: Dict[str, List[str]] = {
        # /tmp dizini dünya tarafından yazılabilir olduğundan kod çalıştırma ve SUID bayrağı yasaklanmalıdır.
        "/tmp": ["noexec", "nosuid", "nodev"],
        # /var/tmp dizini de aynı şekilde geçici dosya alanı olduğundan sertleştirilmelidir.
        "/var/tmp": ["noexec", "nosuid", "nodev"],
        # /dev/shm paylaşılan bellek alanı üzerinde ikili dosyaların çalıştırılması engellenmelidir.
        "/dev/shm": ["noexec", "nosuid", "nodev"]
    }

    # Sınıf kurucu metodunu başlatıyoruz.
    def __init__(self) -> None:
        # Denetim bulgularını depolayacağımız dinamik listeyi başlatıyoruz.
        self.findings: List[Dict[str, Any]] = []

    # Telemetri girdisinin şematik ve mantıksal geçerliliğini denetleyen fonksiyon.
    def validate_telemetry_schema(self, data: Dict[str, Any]) -> bool:
        """
        Telemetri verisinde zorunlu alanları, tipleri ve mantıksal sınırları doğrular.
        """
        # Girdinin sözlük tipi olup olmadığını kontrol ediyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse doğrudan şema hatası fırlatıyoruz.
            raise DiskTelemetryValidationError("Telemetri verisi kök düzeyde bir JSON nesnesi (dict) olmalıdır.")

        # Zorunlu disks alanının varlığını kontrol ediyoruz.
        if "disks" not in data:
            # Eksik disks alanı tespit edildiğinde hata fırlatıyoruz.
            raise DiskTelemetryValidationError("Telemetri verisinde zorunlu 'disks' anahtarı bulunamadı.")

        # Disks alanının liste olup olmadığını kontrol ediyoruz.
        if not isinstance(data["disks"], list):
            # Liste değilse tip uyumsuzluğu hatası veriyoruz.
            raise DiskTelemetryValidationError("'disks' alanı bir liste olmalıdır.")

        # Her bir disk nesnesini tek tek inceliyoruz.
        for disk_index, disk in enumerate(data["disks"]):
            # Diskin sözlük olup olmadığını doğruluyoruz.
            if not isinstance(disk, dict):
                # Disk sözlük değilse hata veriyoruz.
                raise DiskTelemetryValidationError(f"Disk indeksi {disk_index} geçerli bir nesne değil.")

            # Disk boyutu alanını kontrol ediyoruz.
            size_gb = disk.get("size_gb")
            # Boyutun sayısal olup olmadığını doğruluyoruz.
            if not isinstance(size_gb, (int, float)):
                # Sayısal değilse doğrulama hatası fırlatıyoruz.
                raise DiskTelemetryValidationError(f"Disk '{disk.get('device')}' için 'size_gb' sayısal olmalıdır.")

            # Disk boyutunun negatif olup olmadığını denetliyoruz.
            if size_gb <= 0:
                # Negatif veya sıfır disk boyutu fiziksel olarak imkansız olduğundan hata veriyoruz.
                raise DiskTelemetryValidationError(f"Disk '{disk.get('device')}' için 'size_gb' pozitif olmalıdır: {size_gb}")

            # Bölüm tablosu alanının metin olup olmadığını kontrol ediyoruz.
            ptable = disk.get("partition_table")
            # Bölüm tablosunun varlığını ve tipini denetliyoruz.
            if not isinstance(ptable, str):
                # Bölüm tablosu tipi geçersizse hata veriyoruz.
                raise DiskTelemetryValidationError(f"Disk '{disk.get('device')}' için 'partition_table' metin olmalıdır.")

            # Diske ait bölümler listesini alıyoruz.
            partitions = disk.get("partitions", [])
            # Bölümlerin liste olduğunu doğruluyoruz.
            if not isinstance(partitions, list):
                # Liste değilse hata veriyoruz.
                raise DiskTelemetryValidationError(f"Disk '{disk.get('device')}' bölümleri bir liste olmalıdır.")

            # Her bir bölümü tek tek inceliyoruz.
            for part_index, part in enumerate(partitions):
                # Bölümün sözlük olduğunu kontrol ediyoruz.
                if not isinstance(part, dict):
                    # Sözlük değilse hata fırlatıyoruz.
                    raise DiskTelemetryValidationError(f"Disk '{disk.get('device')}' bölüm indeksi {part_index} geçersiz.")

                # Dosya sistemi alanının metin olup olmadığını kontrol ediyoruz.
                fs_type = part.get("filesystem")
                # Dosya sisteminin string tipinde olduğunu denetliyoruz.
                if not isinstance(fs_type, str):
                    # Geçersiz dosya sistemi tipinde hata fırlatıyoruz.
                    raise DiskTelemetryValidationError(f"Bölüm '{part.get('partition_id')}' için 'filesystem' metin olmalıdır.")

                # Bölüm toplam boyutunu alıyoruz.
                total_gb = part.get("total_gb")
                # Bölüm kullanılan boyutunu alıyoruz.
                used_gb = part.get("used_gb")

                # Boyutların sayısal olduğunu kontrol ediyoruz.
                if not isinstance(total_gb, (int, float)) or not isinstance(used_gb, (int, float)):
                    # Sayısal olmayan değerde hata fırlatıyoruz.
                    raise DiskTelemetryValidationError(f"Bölüm '{part.get('partition_id')}' metrikleri sayısal olmalıdır.")

                # Toplam boyutun pozitifliğini kontrol ediyoruz.
                if total_gb < 0 or used_gb < 0:
                    # Negatif kapasite hatası fırlatıyoruz.
                    raise DiskTelemetryValidationError(f"Bölüm '{part.get('partition_id')}' boyutları negatif olamaz.")

                # Kullanılan alanın toplam alanı aşıp aşmadığını denetliyoruz.
                if used_gb > total_gb:
                    # Fiziksel sınır aşımında doğrudan doğrulama hatası fırlatıyoruz.
                    raise DiskTelemetryValidationError(
                        f"Bölüm '{part.get('partition_id')}' kullanılan alan ({used_gb} GB) toplam alanı ({total_gb} GB) aşamaz."
                    )

        # Tüm doğrulamalar başarıyla geçildiyse True döndürüyoruz.
        return True

    # Disk bölümleme tablosunu (MBR vs GPT) mimari ve güvenlik açısından denetleyen fonksiyon.
    def audit_partition_tables(self, disks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        MBR ve GPT bölümleme tablolarını analiz eder; eski MBR kullanımını güvenlik riski olarak raporlar.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her diski inceliyoruz.
        for disk in disks:
            # Disk aygıt adını alıyoruz.
            device = disk.get("device", "Bilinmeyen_Aygıt")
            # Bölümleme tablosu türünü küçük harfe çevirerek alıyoruz.
            ptable = disk.get("partition_table", "").lower()

            # Eğer bölümleme tablosu eski tip MBR (Master Boot Record) ise:
            if ptable == "mbr":
                # MBR'ın güvenlik ve mimari zaaflarını içeren bir bulgu nesnesi hazırlıyoruz.
                finding = {
                    "category": "PARTITION_TABLE_SECURITY",
                    "target": device,
                    "severity": "MEDIUM",
                    "title": "Eski MBR (Master Boot Record) Bölüm Tablosu Tespit Edildi",
                    "description": (
                        f"'{device}' diski eski tip MBR tablosu kullanmaktadır. MBR, yedek tablo başlığı "
                        "barındırmaz, CRC32 veri bütünlüğü doğrulaması sunmaz ve sektör 0 bootkit/rootkit "
                        "manipülasyonlarına karşı savunmasızdır."
                    ),
                    "remediation": "Modern UEFI sistemlerde güvenli önyükleme (Secure Boot) ve GPT (GUID Partition Table) mimarisine geçilmelidir."
                }
                # Bulgu listesine ekliyoruz.
                local_findings.append(finding)

            # Bölüm tablosu GPT ise modern güvenlik standartlarına uygundur.
            elif ptable == "gpt":
                # Güvenli durum için bilgi amaçlı log kaydı üretiyoruz.
                pass

            # Tanınmayan veya boş bölüm tablosu durumu:
            else:
                # Tanımsız bölüm tablosu için uyarı bulgusu oluşturuyoruz.
                finding = {
                    "category": "PARTITION_TABLE_SECURITY",
                    "target": device,
                    "severity": "HIGH",
                    "title": "Bilinmeyen veya Tanımsız Bölüm Tablosu Türü",
                    "description": f"'{device}' diski tanımsız bir bölüm tablosuna ({ptable}) sahiptir.",
                    "remediation": "Diskin bütünlüğünü `gdisk` veya `fdisk -l` ile doğrulayın."
                }
                # Bulgu listesine ekliyoruz.
                local_findings.append(finding)

        # Üretilen bulguları döndürüyoruz.
        return local_findings

    # Dosya sistemleri ve şifreleme durumunu denetleyen fonksiyon.
    def audit_filesystem_and_encryption(self, disks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Dosya sistemi türlerini (ext4, NTFS, FAT32) ve disk şifreleme (LUKS, BitLocker) durumunu analiz eder.
        """
        # Yerel bulgu listesi başlatıyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her diski tarıyoruz.
        for disk in disks:
            # Diskin altındaki bölümleri alıyoruz.
            partitions = disk.get("partitions", [])

            # Her bir bölümü inceliyoruz.
            for part in partitions:
                # Bölüm kimliğini alıyoruz.
                part_id = part.get("partition_id", "Bilinmeyen_Bolum")
                # Dosya sistemini küçük harfle alıyoruz.
                fs = part.get("filesystem", "").lower()
                # Bağlama noktasını alıyoruz.
                mount = part.get("mount_point", "")
                # Şifreleme durumunu boolean olarak alıyoruz.
                is_encrypted = part.get("is_encrypted", False)
                # Şifreleme algoritmasını alıyoruz.
                enc_type = part.get("encryption_type", "none")

                # FAT / FAT32 dosya sistemi denetimi (Güvenlik yetkisi/ACL desteği yoktur):
                if fs in ["fat", "fat32", "vfat"] and mount not in ["/boot/efi", "/boot"]:
                    # FAT32 sistem veya veri diskinde kullanılıyorsa ciddi güvenlik açığıdır.
                    finding = {
                        "category": "FILESYSTEM_PERMISSIONS_SECURITY",
                        "target": part_id,
                        "severity": "HIGH",
                        "title": "İzin Desteği Olmayan Güvensiz Dosya Sistemi (FAT32/VFAT) Tespiti",
                        "description": (
                            f"'{part_id}' ({mount}) üzerinde '{fs}' kullanılmaktadır. FAT32 dosya sistemi; "
                            "POSIX dosya izinlerini (DAC), Windows ACL erişim kontrol listelerini ve dosya "
                            "güvenlik niteliklerini desteklemez. Herkes her dosyayı okuyabilir ve değiştirebilir."
                        ),
                        "remediation": "Veri bütünlüğü ve erişim denetimi için Linux'ta ext4/XFS, Windows'ta NTFS dosya sistemine dönüştürün."
                    }
                    # Bulguyu ekliyoruz.
                    local_findings.append(finding)

                # Şifreleme denetimi (EFI sistem bölümleri hariç tüm sabit disk bölümleri şifrelenmelidir):
                if not is_encrypted and mount != "/boot/efi":
                    # Şifresiz bölüm tespit edildiğinde kritik bulgu oluşturuyoruz.
                    finding = {
                        "category": "ENCRYPTION_AT_REST",
                        "target": part_id,
                        "severity": "CRITICAL" if mount in ["/", "/home", "/var"] else "HIGH",
                        "title": "Şifrelenmemiş Sabit Disk Bölümü (Unencrypted At-Rest Volume)",
                        "description": (
                            f"'{part_id}' ({mount}) sabit disk bölümü şifrelenmemiştir (is_encrypted: false). "
                            "Fiziksel aygıt çalındığında, soğuk önyükleme (cold boot) veya harici canlı USB ile "
                            "erişildiğinde tüm veriler açık metin olarak kopyalanabilir."
                        ),
                        "remediation": "Linux'ta LUKS2 (dm-crypt), Windows'ta BitLocker ile tam disk şifrelemesi (FDE) uygulayın."
                    }
                    # Bulguyu ekliyoruz.
                    local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Bağlama bayraklarını (Mount Options) güvenlik ve sertleştirme standartlarına göre denetleyen fonksiyon.
    def audit_mount_options_hardening(self, disks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Hassas dizinlerin (/tmp, /var/tmp, /dev/shm) noexec, nosuid, nodev bayraklarını denetler.
        """
        # Yerel bulguları tutacak listeyi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her diski tarıyoruz.
        for disk in disks:
            # Bölümleri alıyoruz.
            partitions = disk.get("partitions", [])

            # Her bölümü inceliyoruz.
            for part in partitions:
                # Bölüm kimliği ve bağlama noktasını alıyoruz.
                part_id = part.get("partition_id", "Bilinmeyen_Bolum")
                # Bağlama noktasını alıyoruz.
                mount = part.get("mount_point", "")
                # Bağlama bayrakları listesini alıyoruz.
                options = part.get("mount_options", [])

                # Eğer bu bağlama noktası sertleştirme kurallarımızda tanımlıysa:
                if mount in self.HARDENED_MOUNT_RULES:
                    # Gerekli zorunlu bayrakları alıyoruz.
                    required_flags = self.HARDENED_MOUNT_RULES[mount]

                    # Eksik olan bayrakları tespit ediyoruz.
                    missing_flags = [flag for flag in required_flags if flag not in options]

                    # Eğer eksik bayrak varsa güvenlik açığı olarak raporluyoruz:
                    if missing_flags:
                        # Eksik bayrak uyarısı oluşturuyoruz.
                        severity = "HIGH" if "noexec" in missing_flags or "nosuid" in missing_flags else "MEDIUM"
                        # Detaylı bulgu sözlüğünü oluşturuyoruz.
                        finding = {
                            "category": "MOUNT_SECURITY_HARDENING",
                            "target": f"{part_id} ({mount})",
                            "severity": severity,
                            "title": f"'{mount}' Bağlama Noktasında Eksik Güvenlik Bayrakları",
                            "description": (
                                f"'{mount}' dizininde zorunlu güvenlik bayrakları eksik: {missing_flags}. "
                                "Özellikle 'noexec' eksikliği, saldırganların dünya tarafından yazılabilir geçici "
                                "dizinlere zararlı ELF ikili dosyaları indirip doğrudan çalıştırmasına imkan tanır. "
                                "'nosuid' eksikliği ise yetki yükseltme (privilege escalation) saldırılarına zemin hazırlar."
                            ),
                            "remediation": f"/etc/fstab dosyasına '{', '.join(required_flags)}' seçeneklerini ekleyerek 'mount -o remount' yapın."
                        }
                        # Listeye ekliyoruz.
                        local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Disk doluluk oranlarını ve tükenme (exhaustion/DoS) riskini analiz eden fonksiyon.
    def audit_capacity_and_exhaustion(self, disks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Bölüm doluluk oranlarını inceler; %85 üzeri uyarı, %95 üzeri kritik DoS riski üretir.
        """
        # Yerel bulgu listesi başlatıyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her diski inceliyoruz.
        for disk in disks:
            # Bölümleri alıyoruz.
            for part in disk.get("partitions", []):
                # Bölüm kimliği, bağlama noktası ve boyutları alıyoruz.
                part_id = part.get("partition_id", "Bilinmeyen_Bolum")
                # Bağlama noktasını alıyoruz.
                mount = part.get("mount_point", "")
                # Toplam boyutu alıyoruz.
                total = float(part.get("total_gb", 0))
                # Kullanılan boyutu alıyoruz.
                used = float(part.get("used_gb", 0))

                # Sıfıra bölme hatasını engelliyoruz.
                if total <= 0:
                    # Toplam alan 0 ise atlıyoruz.
                    continue

                # Doluluk yüzdesini hesaplıyoruz.
                usage_pct = (used / total) * 100.0

                # Kritik eşik: %95 veya üzeri:
                if usage_pct >= 95.0:
                    # Kritik tükenme bulgusu oluşturuyoruz.
                    finding = {
                        "category": "DISK_CAPACITY_EXHAUSTION",
                        "target": f"{part_id} ({mount})",
                        "severity": "CRITICAL",
                        "title": "Kritik Disk Doluluğu — Sistem Çökmesi ve Günlük Kaybı Riski",
                        "description": (
                            f"'{part_id}' ({mount}) doluluk oranı %{usage_pct:.1f} seviyesindedir ({used:.1f} / {total:.1f} GB). "
                            "Disk alanının tükenmesi, sistem servislerinin çökmesine, veritabanı kilitlenmelerine ve "
                            "güvenlik olay günlüklerinin (audit logs) yazılamayarak adli izlerin kaybolmasına yol açar."
                        ),
                        "remediation": "Disk temizliği yapın, log döndürme (logrotate) politikalarını denetleyin veya birim boyutunu genişletin."
                    }
                    # Bulguyu listeye ekliyoruz.
                    local_findings.append(finding)

                # Uyarı eşiği: %85 ile %95 arası:
                elif usage_pct >= 85.0:
                    # Uyarı seviyesinde bulgu oluşturuyoruz.
                    finding = {
                        "category": "DISK_CAPACITY_EXHAUSTION",
                        "target": f"{part_id} ({mount})",
                        "severity": "WARNING",
                        "title": "Yüksek Disk Doluluğu Tespiti",
                        "description": (
                            f"'{part_id}' ({mount}) doluluk oranı %{usage_pct:.1f} seviyesindedir ({used:.1f} / {total:.1f} GB)."
                        ),
                        "remediation": "Disk büyüme eğilimini izleyin ve gereksiz geçici dosyaları temizleyin."
                    }
                    # Listeye ekliyoruz.
                    local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Tüm denetim adımlarını birleştiren ana icra fonksiyonu.
    def execute_full_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tüm denetimleri çalıştırır, güvenlik skorunu hesaplar ve yapılandırılmış rapor döner.
        """
        # İlk olarak gelen telemetri verisini şematik olarak doğruluyoruz.
        self.validate_telemetry_schema(data)

        # Sistem bilgilerini alıyoruz.
        sys_info = data.get("system_info", {})
        # Disk listesini alıyoruz.
        disks = data.get("disks", [])

        # Tüm bulguları temizliyoruz.
        self.findings = []

        # 1. Bölümleme tablosu denetimini yapıyoruz.
        self.findings.extend(self.audit_partition_tables(disks))

        # 2. Dosya sistemi ve şifreleme denetimini yapıyoruz.
        self.findings.extend(self.audit_filesystem_and_encryption(disks))

        # 3. Bağlama bayrakları (Mount options) denetimini yapıyoruz.
        self.findings.extend(self.audit_mount_options_hardening(disks))

        # 4. Kapasite ve tükenme denetimini yapıyoruz.
        self.findings.extend(self.audit_capacity_and_exhaustion(disks))

        # Güvenlik puanını 100 üzerinden hesaplıyoruz.
        security_score = 100
        # Kritik bulgu sayısını sayıyoruz.
        critical_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        # Yüksek seviye bulgu sayısını sayıyoruz.
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        # Orta seviye bulgu sayısını sayıyoruz.
        medium_count = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        # Uyarı seviyesi bulgu sayısını sayıyoruz.
        warning_count = sum(1 for f in self.findings if f["severity"] == "WARNING")

        # Puan düşümlerini yapıyoruz: Her kritik için -20, her yüksek için -10, orta için -5, uyarı için -2.
        security_score -= (critical_count * 20)
        security_score -= (high_count * 10)
        security_score -= (medium_count * 5)
        security_score -= (warning_count * 2)

        # Puanın 0'ın altına düşmesini engelliyoruz.
        security_score = max(0, security_score)

        # Durum belirteci belirliyoruz.
        overall_status = "SECURE" if security_score >= 85 else ("WARNING" if security_score >= 60 else "CRITICAL")

        # Rapor sözlüğünü yapılandırıp döndürüyoruz.
        return {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "system_info": sys_info,
            "security_score": security_score,
            "overall_status": overall_status,
            "metrics": {
                "total_disks_analyzed": len(disks),
                "total_partitions_analyzed": sum(len(d.get("partitions", [])) for d in disks),
                "critical_findings": critical_count,
                "high_findings": high_count,
                "medium_findings": medium_count,
                "warning_findings": warning_count,
                "total_findings": len(self.findings)
            },
            "findings": self.findings
        }

    # Denetim sonucunu Markdown formatına dönüştüren raporlama fonksiyonu.
    def export_markdown_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Denetim sonucunu insan tarafından okunabilir Markdown formatında biçimlendirir.
        """
        # Boş bir rapor dizisi başlatıyoruz.
        lines: List[str] = []

        # Lisans başlığını ekliyoruz.
        lines.append("<!--")
        lines.append("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR")
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)")
        lines.append("Bu yazılım ve ilgili tüm dosyalar ('Yazılım') yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.")
        lines.append("-->\n")

        # Rapor başlığını ekliyoruz.
        lines.append("# Disk Bölümleri ve Dosya Sistemleri Güvenlik Denetim Raporu\n")

        # Sistem bilgilerini ekliyoruz.
        sys_info = audit_result.get("system_info", {})
        lines.append(f"**Ana Makine Adı:** `{sys_info.get('hostname', 'N/A')}`  ")
        lines.append(f"**İşletim Sistemi:** `{sys_info.get('operating_system', 'N/A')}`  ")
        lines.append(f"**Denetim Tarihi:** `{audit_result.get('audit_timestamp', 'N/A')}`  ")
        lines.append(f"**Güvenlik Puanı:** `{audit_result.get('security_score', 0)} / 100`  ")
        lines.append(f"**Genel Durum:** `{audit_result.get('overall_status', 'UNKNOWN')}`\n")

        # Metrik tablosunu ekliyoruz.
        metrics = audit_result.get("metrics", {})
        lines.append("## 📊 Denetim Metrikleri Özeti\n")
        lines.append("| Metrik | Değer |")
        lines.append("| :--- | :---: |")
        lines.append(f"| İncelenen Disk Sayısı | {metrics.get('total_disks_analyzed', 0)} |")
        lines.append(f"| İncelenen Bölüm Sayısı | {metrics.get('total_partitions_analyzed', 0)} |")
        lines.append(f"| Kritik (CRITICAL) Bulgular | {metrics.get('critical_findings', 0)} |")
        lines.append(f"| Yüksek (HIGH) Seviye Bulgular | {metrics.get('high_findings', 0)} |")
        lines.append(f"| Orta (MEDIUM) Seviye Bulgular | {metrics.get('medium_findings', 0)} |")
        lines.append(f"| Uyarı (WARNING) Bulgular | {metrics.get('warning_findings', 0)} |")
        lines.append(f"| **Toplam Güvenlik Bulgusu** | **{metrics.get('total_findings', 0)}** |\n")

        # Bulgular detay bölümünü ekliyoruz.
        lines.append("## 🔍 Güvenlik Bulguları ve İyileştirme Reçetesi\n")
        findings = audit_result.get("findings", [])

        # Eğer bulgu yoksa sistemin temiz olduğunu bildiriyoruz.
        if not findings:
            lines.append("✅ *Tüm disk bölümleri ve dosya sistemleri güvenlik standartlarına uygundur. Kritik bulguya rastlanmadı.*\n")
        else:
            # Her bulguyu sırayla numaralandırarak ekliyoruz.
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. [{f['severity']}] {f['title']}")
                lines.append(f"- **Hedef:** `{f['target']}`")
                lines.append(f"- **Kategori:** `{f['category']}`")
                lines.append(f"- **Açıklama:** {f['description']}")
                lines.append(f"- **🛡️ İyileştirme:** {f['remediation']}\n")

        # Satırları birleştirip tek bir string olarak döndürüyoruz.
        return "\n".join(lines)


# Doğrudan komut satırından çalıştırıldığında devreye giren main bloğu.
def main() -> None:
    """
    Komut satırı arayüzü (CLI) giriş noktası.
    """
    # Windows konsolunda Unicode ve emoji karakterlerinin hatasız basılması için stdout yapılandırması yapıyoruz.
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktıyı UTF-8 ve replace hata stratejisi ile ayarlıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Standart hata akışını da aynı şekilde korumaya alıyoruz.
    if hasattr(sys.stderr, "reconfigure"):
        # Standart hatayı UTF-8 ve replace ile yapılandırıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı oluşturuyoruz.
    parser = argparse.ArgumentParser(description="G037: Disk Bölümleri ve Dosya Sistemleri Güvenlik Denetçisi")
    # Telemetri dosyası yolu parametresini ekliyoruz.
    parser.add_argument("--telemetry", type=str, required=True, help="İncelenecek JSON telemetri dosyasının yolu")
    # Çıktı dosyasını belirten opsiyonel parametreyi ekliyoruz.
    parser.add_argument("--output", type=str, default="", help="Markdown raporunun kaydedileceği dosya yolu")

    # Argümanları ayrıştırıyoruz.
    args = parser.parse_args()

    # Dosyanın varlığını denetliyoruz.
    if not os.path.exists(args.telemetry):
        # Dosya yoksa konsola yazıp çıkış yapıyoruz.
        print(f"HATA: Telemetri dosyası bulunamadı: {args.telemetry}", file=sys.stderr)
        # Çıkış kodu 1 ile sonlandırıyoruz.
        sys.exit(1)

    # Telemetri dosyasını okuyoruz.
    with open(args.telemetry, "r", encoding="utf-8") as f:
        # JSON verisini yüklüyoruz.
        telemetry_data = json.load(f)

    # Denetçi nesnesini başlatıyoruz.
    auditor = DiskPartitionFsAuditor()
    # Denetimi çalıştırıyoruz.
    audit_result = auditor.execute_full_audit(telemetry_data)
    # Markdown raporunu üretiyoruz.
    report_md = auditor.export_markdown_report(audit_result)

    # Raporu konsola yazdırıyoruz.
    print(report_md)

    # Eğer çıktı dosyası belirtilmişse dosyaya da yazıyoruz.
    if args.output:
        # Dosyayı yazma modunda açıyoruz.
        with open(args.output, "w", encoding="utf-8") as out_f:
            # Rapor içeriğini yazıyoruz.
            out_f.write(report_md)
        # Bilgilendirme mesajı basıyoruz.
        print(f"\nRapor başarıyla kaydedildi: {args.output}")


# Python betiği doğrudan yürütüldüğünde main'i çağırıyoruz.
if __name__ == "__main__":
    # main fonksiyonunu icra ediyoruz.
    main()
