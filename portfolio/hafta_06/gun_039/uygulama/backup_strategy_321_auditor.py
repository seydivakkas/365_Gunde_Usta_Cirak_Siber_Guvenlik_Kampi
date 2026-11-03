# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.

"""
G039: Yedekleme Stratejisi ve 3-2-1 Kuralı Güvenlik Denetçisi (Backup Strategy & 3-2-1 Auditor)

Bu modül, kurumsal yedekleme politikalarını 3-2-1 kuralı (En az 3 kopya, 2 farklı medya,
1 tesis dışı/izole kopya), fidye yazılımlarına (Ransomware) karşı değiştirilemezlik (Immutability/WORM),
geri yükleme testleri (Restore Verification), RAID vs Snapshot yanılgıları ve RPO/RTO hedefleri
çerçevesinde derinlemesine analiz eder.
"""

# İşletim sistemi ve dosya yolu operasyonları için os modülünü içeri aktarıyoruz.
import os

# Sistem argümanları ve standart giriş/çıkış akışları için sys modülünü dahil ediyoruz.
import sys

# JSON telemetri ve envanter dosyalarını işlemek için json kütüphanesini kullanıyoruz.
import json

# Komut satırı parametrelerini ayrıştırmak için argparse modülünü içeri aktarıyoruz.
import argparse

# Zaman damgaları ve UTC tarih formatı için datetime ve timezone modüllerini alıyoruz.
from datetime import datetime, timezone

# Statik kod analizi ve tip güvenliği için typing bileşenlerini dahil ediyoruz.
from typing import Dict, Any, List, Optional, Tuple


# Yedekleme envanteri telemetrisindeki bozuklukları bildiren özel istisna sınıfı.
class BackupTelemetryValidationError(Exception):
    """
    Yedekleme politikası telemetri verisinde tespit edilen şema ve sınır hataları için istisna.
    """
    # Kurucu metod ile gelen hata açıklamasını temel Exception sınıfına aktarıyoruz.
    def __init__(self, message: str) -> None:
        # Üst sınıf Exception kurucusuna hata iletisini aktarıyoruz.
        super().__init__(message)


# Yedekleme stratejisi ve 3-2-1 kuralını denetleyen uzman sınıfı tanımlıyoruz.
class BackupStrategy321Auditor:
    """
    3-2-1 yedekleme kuralını, fidye yazılımı dayanıklılığını ve geri yükleme testlerini denetleyen motor.
    """

    # Geri yükleme testinin güncelliğini yitirmiş sayılacağı azami gün eşiği (90 gün = 1 çeyrek yıl).
    MAX_ALLOWABLE_DAYS_WITHOUT_RESTORE_TEST: int = 90

    # 3-2-1 kuralı asgari toplam kopya sayısı gereksinimi (1 Birincil + 2 Yedek).
    MIN_REQUIRED_COPIES: int = 3

    # 3-2-1 kuralı asgari farklı medya türü gereksinimi (örn. Disk + Bulut veya Disk + Teyp).
    MIN_REQUIRED_MEDIA_TYPES: int = 2

    # Sınıf kurucu metodunu başlatıyoruz.
    def __init__(self) -> None:
        # Denetim bulgularını depolayacağımız dinamik listeyi başlatıyoruz.
        self.findings: List[Dict[str, Any]] = []

    # Telemetri girdisinin şematik ve mantıksal geçerliliğini denetleyen fonksiyon.
    def validate_telemetry_schema(self, data: Dict[str, Any]) -> bool:
        """
        Telemetri verisinde zorunlu politikaları, alanları ve mantıksal sınırları doğrular.
        """
        # Kök verinin sözlük olup olmadığını sınıyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse doğrulama hatası fırlatıyoruz.
            raise BackupTelemetryValidationError("Yedekleme verisi kök düzeyde bir JSON nesnesi (dict) olmalıdır.")

        # Zorunlu backup_policies anahtarının varlığını kontrol ediyoruz.
        if "backup_policies" not in data:
            # Eksik anahtarda doğrudan hata fırlatıyoruz.
            raise BackupTelemetryValidationError("Telemetri verisinde zorunlu 'backup_policies' anahtarı bulunamadı.")

        # backup_policies alanının liste olduğunu sınıyoruz.
        if not isinstance(data["backup_policies"], list):
            # Liste değilse tip hatası fırlatıyoruz.
            raise BackupTelemetryValidationError("'backup_policies' alanı bir liste olmalıdır.")

        # Her bir yedekleme politikasını tek tek inceliyoruz.
        for pol_idx, policy in enumerate(data["backup_policies"]):
            # Politika girdisinin sözlük olduğunu sınıyoruz.
            if not isinstance(policy, dict):
                # Sözlük değilse hata fırlatıyoruz.
                raise BackupTelemetryValidationError(f"Politika indeksi {pol_idx} geçerli bir JSON nesnesi değil.")

            # Politika kimliğini alıyoruz.
            pid = policy.get("policy_id")
            # Kimliğin string olup olmadığını denetliyoruz.
            if not isinstance(pid, str):
                # String değilse hata veriyoruz.
                raise BackupTelemetryValidationError(f"Politika indeksi {pol_idx} için 'policy_id' metin olmalıdır.")

            # Toplam kopya sayısını alıyoruz.
            total_copies = policy.get("total_copies")
            # Kopya sayısının tamsayı olduğunu sınıyoruz.
            if not isinstance(total_copies, int):
                # Tamsayı değilse hata fırlatıyoruz.
                raise BackupTelemetryValidationError(f"Politika '{pid}' için 'total_copies' tamsayı olmalıdır.")

            # Kopya sayısının negatif olamayacağını denetliyoruz.
            if total_copies < 0:
                # Negatif kopya sayısında hata fırlatıyoruz.
                raise BackupTelemetryValidationError(f"Politika '{pid}' için 'total_copies' negatif olamaz: {total_copies}")

            # Medya türleri listesini alıyoruz.
            media_types = policy.get("media_types")
            # Medya türlerinin liste olduğunu kontrol ediyoruz.
            if not isinstance(media_types, list):
                # Liste değilse hata veriyoruz.
                raise BackupTelemetryValidationError(f"Politika '{pid}' için 'media_types' bir liste olmalıdır.")

            # Tesis dışı kopya sayısını alıyoruz.
            offsite = policy.get("offsite_copies")
            # Tesis dışı kopya sayısının tamsayı olduğunu sınıyoruz.
            if not isinstance(offsite, int) or offsite < 0:
                # Geçersiz tesis dışı kopya sayısında hata veriyoruz.
                raise BackupTelemetryValidationError(f"Politika '{pid}' için 'offsite_copies' sıfır veya pozitif tamsayı olmalıdır.")

            # Son geri yükleme testinden bu yana geçen gün sayısını alıyoruz.
            restore_days = policy.get("days_since_last_restore_test")
            # None (hiç yapılmamış) değilse sayısal ve pozitif olmalıdır.
            if restore_days is not None:
                # Tamsayı veya float olduğunu denetliyoruz.
                if not isinstance(restore_days, (int, float)):
                    # Sayısal değilse hata fırlatıyoruz.
                    raise BackupTelemetryValidationError(f"Politika '{pid}' için 'days_since_last_restore_test' sayısal veya null olmalıdır.")
                # Negatif gün olamayacağını sınıyoruz.
                if restore_days < 0:
                    # Negatif gün hatası veriyoruz.
                    raise BackupTelemetryValidationError(f"Politika '{pid}' için 'days_since_last_restore_test' negatif olamaz.")

        # Tüm kontroller başarıyla tamamlandıysa True dönüyoruz.
        return True

    # 3-2-1 Kuralı uyumluluğunu denetleyen fonksiyon.
    def audit_321_rule_compliance(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        3-2-1 kuralı parametrelerini (3 kopya, 2 medya, 1 offsite, 1 değiştirilemez) analiz eder.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her politikayı inceliyoruz.
        for policy in policies:
            # Politika kimliği ve iş yükü adını alıyoruz.
            pid = policy.get("policy_id", "Bilinmeyen_Politika")
            # İş yükü adını alıyoruz.
            workload = policy.get("workload_name", "Bilinmeyen_Is_Yuku")
            # Toplam kopya sayısını alıyoruz.
            total_copies = int(policy.get("total_copies", 0))
            # Medya türleri listesini alıyoruz.
            media = policy.get("media_types", [])
            # Tesis dışı kopya sayısını alıyoruz.
            offsite = int(policy.get("offsite_copies", 0))
            # Değiştirilemezlik bayrağını alıyoruz.
            is_immutable = bool(policy.get("is_immutable_or_airgapped", False))

            # 1. Kural Adımı: En az 3 kopya var mı?
            if total_copies < self.MIN_REQUIRED_COPIES:
                # Kopya eksikliği bulgusu oluşturuyoruz.
                finding = {
                    "category": "321_RULE_COPIES_INSUFFICIENT",
                    "target": f"{pid} ({workload})",
                    "severity": "HIGH",
                    "title": f"Yetersiz Kopya Sayısı ({total_copies} / {self.MIN_REQUIRED_COPIES}) — 3-2-1 İhlali",
                    "description": (
                        f"'{workload}' iş yükü için yalnızca {total_copies} adet kopya bulunmaktadır. "
                        "3-2-1 kuralı gereği verinin 1 birincil üretim kopyası ve en az 2 adet bağımsız "
                        "yedek kopyası (toplamda en az 3 kopya) bulunmalıdır."
                    ),
                    "remediation": "Yedekleme stratejisine en az bir ikincil yedekleme hedefi ekleyerek toplam kopya sayısını 3'e çıkarın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 2. Kural Adımı: En az 2 farklı medya türü var mı?
            if len(media) < self.MIN_REQUIRED_MEDIA_TYPES:
                # Medya çeşitliliği eksikliği bulgusu oluşturuyoruz.
                finding = {
                    "category": "321_RULE_MEDIA_DIVERSITY_MISSING",
                    "target": f"{pid} ({workload})",
                    "severity": "MEDIUM",
                    "title": "Medya Çeşitliliği Yok — Ortak Arıza Alanı (Common Failure Domain) Riski",
                    "description": (
                        f"'{workload}' için kopyalar yalnızca {media} türünde tutulmaktadır. "
                        "Aynı medya teknolojisine bağımlılık (örn. yalnızca yerel mekanik diskler veya tek bir depolama ünitesi), "
                        "ortak bir kontrolcü veya donanım serisi arızasında tüm kopyaların aynı anda kaybedilmesine yol açar."
                    ),
                    "remediation": "Yedek kopyalardan en az birini manyetik teyp (LTO), bulut nesne depolama (S3) veya farklı SAN mimarisine taşıyın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 3. Kural Adımı: En az 1 tesis dışı (Offsite) kopya var mı?
            if offsite < 1:
                # Tesis dışı kopya eksikliği CRITICAL bulgu üretir.
                finding = {
                    "category": "321_RULE_OFFSITE_MISSING",
                    "target": f"{pid} ({workload})",
                    "severity": "CRITICAL",
                    "title": "Tesis Dışı (Offsite) Kopya Yok — Fiziksel Felaket ve Yangın Riski",
                    "description": (
                        f"'{workload}' iş yüküne ait hiçbir kopya ana veri merkezi/bina dışında tutulmamaktadır (offsite: 0). "
                        "Yangın, su baskını, deprem veya fiziksel hırsızlık durumunda tüm kopyalar tek bir lokasyonda yok olur."
                    ),
                    "remediation": "Kopyalardan en az birini coğrafi olarak farklı bir ikincil veri merkezine veya genel bulut sağlayıcısına aktarın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 4. Kural Adımı: Fidye yazılımlarına karşı Değiştirilemezlik (Immutability / WORM) var mı?
            if not is_immutable:
                # Fidye yazılımı tehdidi altında CRITICAL bulgu oluşturuyoruz.
                finding = {
                    "category": "RANSOMWARE_IMMUTABILITY_GAP",
                    "target": f"{pid} ({workload})",
                    "severity": "CRITICAL",
                    "title": "Fidye Yazılımlarına (Ransomware) Karşı Değiştirilemez/Hava Boşluklu (Air-gapped) Yedek Yok",
                    "description": (
                        f"'{workload}' iş yükü için değiştirilemez (immutable / WORM - Write Once Read Many) veya "
                        "ağdan tamamen izole edilmiş (air-gapped) bir yedek kopyası tanımlanmamıştır. "
                        "Etki alanı yöneticisi (Domain Admin) yetkisini ele geçiren modern fidye yazılımı çeteleri "
                        "(LockBit, BlackCat vb.), şifreleme öncesinde erişebildikleri tüm standart yedekleri silmekte veya şifrelemektedir."
                    ),
                    "remediation": "Yedekleme havuzlarında S3 Object Lock (Compliance Mode) veya çevrimdışı teyp (LTO tape air-gap) zorunlu kılınmalıdır."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Geri yükleme testlerinin (Restore Verification) sıklığını ve başarısını denetleyen fonksiyon.
    def audit_restore_verification_and_testing(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Yedeklerin geri yüklenebilirlik testlerini denetler; test edilmemiş yedekleri 'Schrödinger'in Yedeği' olarak raporlar.
        """
        # Yerel bulgu listesi başlatıyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Politikaları tarıyoruz.
        for policy in policies:
            # Hedef kimliğini alıyoruz.
            pid = policy.get("policy_id", "Bilinmeyen_Politika")
            # İş yükü adını alıyoruz.
            workload = policy.get("workload_name", "Bilinmeyen_Is_Yuku")
            # Son geri yükleme gününü alıyoruz.
            restore_days = policy.get("days_since_last_restore_test")
            # Sağlama algoritmasını alıyoruz.
            checksum_algo = policy.get("integrity_checksum_algorithm", "none").lower()

            # 1. Durum: Geri yükleme testi HİÇ YAPILMAMIŞ (Schrödinger'in Yedeği):
            if restore_days is None:
                # Kritik seviyede test edilmemiş yedek bulgusu oluşturuyoruz.
                finding = {
                    "category": "RESTORE_VERIFICATION_NEVER_TESTED",
                    "target": f"{pid} ({workload})",
                    "severity": "CRITICAL",
                    "title": "Schrödinger'in Yedeği — Geri Yükleme Testi HİÇ Yapılmamış!",
                    "description": (
                        f"'{workload}' için yedekleme alındığı varsayılmakta ancak bugüne kadar HİÇBİR "
                        "geri yükleme testi (restore drill) gerçekleştirilmemiştir. "
                        "Siber güvenlikte 'Geri yükleme testi başarıyla doğrulanmamış hiçbir yedek, gerçekte var sayılmaz.' "
                        "Bozuk disk blokları, eksik veritabanı logları veya şifreleme anahtarı uyumsuzlukları ancak felaket anında anlaşılır."
                    ),
                    "remediation": "İzole bir test ortamında acilen tam geri yükleme (Full Restore Drill) tatbikatı icra edin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 2. Durum: Geri yükleme testi 90 günden daha eski:
            elif restore_days > self.MAX_ALLOWABLE_DAYS_WITHOUT_RESTORE_TEST:
                # Yüksek seviyede güncelliğini yitirmiş test uyarısı veriyoruz.
                finding = {
                    "category": "RESTORE_VERIFICATION_OUTDATED",
                    "target": f"{pid} ({workload})",
                    "severity": "HIGH",
                    "title": f"Geri Yükleme Testi Güncelliğini Yitirmiş ({restore_days:.0f} Gün Önce)",
                    "description": (
                        f"'{workload}' için son geri yükleme testi {restore_days:.0f} gün önce yapılmıştır "
                        f"(Azami kabul edilebilir süre: {self.MAX_ALLOWABLE_DAYS_WITHOUT_RESTORE_TEST} gün). "
                        "Geçen süre zarfında değişen veritabanı şemaları, sistem güncellemeleri veya saklama politikaları "
                        "yedeğin çalışabilirliğini bozmuş olabilir."
                    ),
                    "remediation": "Çeyreklik (Quarterly) periyotlarla düzenli otomatik geri yükleme testleri planlayın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 3. Durum: Kriptografik bütünlük denetimi (Checksum) yok:
            if checksum_algo in ["none", "", "null"]:
                # Bütünlük denetimi eksikliği bulgusu oluşturuyoruz.
                finding = {
                    "category": "BACKUP_INTEGRITY_CHECKSUM_MISSING",
                    "target": f"{pid} ({workload})",
                    "severity": "MEDIUM",
                    "title": "Kriptografik Bütünlük Doğrulaması (Checksum) Eksik",
                    "description": (
                        f"'{workload}' yedekleme arşivlerinde SHA256 veya benzeri bir kriptografik sağlama toplamı "
                        "doğrulaması bulunmamaktadır. Sessiz veri bozulmaları (Bit rot / Silent Data Corruption) fark edilemeyebilir."
                    ),
                    "remediation": "Yedekleme yazılımında arşiv oluşturma ve aktarım sonrası SHA256 karma doğrulamasını etkinleştirin."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # RAID ve Snapshot yanılgılarını (Architecture Misconceptions) denetleyen fonksiyon.
    def audit_raid_and_snapshot_misconceptions(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        'RAID bir yedekleme değildir' ve 'Aynı havuzdaki anlık görüntü (snapshot) yedek sayılmaz' kurallarını denetler.
        """
        # Yerel bulgu listesini oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Her politikayı sınıyoruz.
        for policy in policies:
            # Hedef kimliği alıyoruz.
            pid = policy.get("policy_id", "Bilinmeyen_Politika")
            # İş yükü adını alıyoruz.
            workload = policy.get("workload_name", "Bilinmeyen_Is_Yuku")
            # RAID yanılgısı bayrağını alıyoruz.
            relies_on_raid = bool(policy.get("relies_on_raid_as_backup", False))
            # Snapshot aynı havuzda mı bayrağını alıyoruz.
            same_pool_snap = bool(policy.get("snapshot_on_same_pool_only", False))

            # 1. Yanılgı: RAID'i yedek sanmak:
            if relies_on_raid:
                # Kritik seviyede mimari yanılgı bulgusu oluşturuyoruz.
                finding = {
                    "category": "ARCHITECTURAL_MISCONCEPTION_RAID",
                    "target": f"{pid} ({workload})",
                    "severity": "CRITICAL",
                    "title": "Ölümcül Mimari Hata: RAID Bir Yedekleme Değildir!",
                    "description": (
                        f"'{workload}' iş yükünde yerel RAID dizisi tek koruma mekanizması olarak kullanılmaktadır. "
                        "RAID yalnızca donanımsal disk arızalarına karşı iş sürekliliği (High Availability) sağlar. "
                        "Kazara dosya silinmesi, fidye yazılımı şifrelemesi, bozuk yazılım güncellemesi veya kontrolcü "
                        "arızası anında veriyi TÜM disklere aynı anda eşzamanlı siler veya şifreler. RAID geçmişe dönük koruma sağlamaz."
                    ),
                    "remediation": "RAID'den bağımsız, harici ortamlara (NAS/Cloud/Tape) planlı yedekleme başlatın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

            # 2. Yanılgı: Aynı depolama havuzunda snapshot tutmak:
            if same_pool_snap:
                # Yüksek seviyede snapshot bağımlılığı uyarısı veriyoruz.
                finding = {
                    "category": "ARCHITECTURAL_MISCONCEPTION_SNAPSHOT",
                    "target": f"{pid} ({workload})",
                    "severity": "HIGH",
                    "title": "Aynı Depolama Havuzundaki Anlık Görüntü (Snapshot) Yedek Sayılmaz",
                    "description": (
                        f"'{workload}' için alınan anlık görüntüler (snapshots) birincil verinin bulunduğu aynı fiziksel "
                        "depolama havuzunda (SAN/LUN) tutulmaktadır. Depolama havuzunun meta verisi çöktüğünde veya "
                        "fiziksel depolama ünitesi arızalandığında hem birincil veri hem de snapshot'lar aynı anda yok olur."
                    ),
                    "remediation": "Snapshot'ları depolama seviyesinde replikasyonla farklı bir ikincil fiziksel üniteye kopyalayın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # RPO (Kurtarma Noktası Hedefi) uyumluluğunu denetleyen fonksiyon.
    def audit_rpo_compliance(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Hedef RPO süresi ile fiili yedekleme sıklığını karşılaştırır; veri kaybı riskini raporlar.
        """
        # Yerel bulgu listesi oluşturuyoruz.
        local_findings: List[Dict[str, Any]] = []

        # Politikaları inceliyoruz.
        for policy in policies:
            # Hedef kimliği alıyoruz.
            pid = policy.get("policy_id", "Bilinmeyen_Politika")
            # İş yükü adını alıyoruz.
            workload = policy.get("workload_name", "Bilinmeyen_Is_Yuku")
            # Hedef RPO süresini alıyoruz.
            target_rpo = float(policy.get("target_rpo_hours", 24.0))
            # Gerçekleşen yedekleme sıklığını alıyoruz.
            actual_interval = float(policy.get("actual_backup_interval_hours", 24.0))

            # Eğer fiili yedekleme aralığı hedeflenen RPO'dan büyükse:
            if actual_interval > target_rpo:
                # Yüksek seviyede RPO sapması bulgusu oluşturuyoruz.
                finding = {
                    "category": "RPO_SLA_BREACH_RISK",
                    "target": f"{pid} ({workload})",
                    "severity": "HIGH",
                    "title": f"RPO Hedef Sapması — Kabul Edilemez Veri Kaybı Riski ({actual_interval:.0f}h > {target_rpo:.0f}h)",
                    "description": (
                        f"'{workload}' iş yükü için taahhüt edilen azami veri kaybı süresi (RPO) {target_rpo:.1f} saat iken, "
                        f"fiili yedekleme aralığı {actual_interval:.1f} saattir. Olası bir felaket anında son yedekten bu yana "
                        f"geçen {actual_interval:.1f} saatlik kurumsal veri kalıcı olarak kaybolacaktır."
                    ),
                    "remediation": f"Yedekleme işinin zamanlama sıklığını (schedule) en fazla {target_rpo:.0f} saatte bir çalışacak şekilde artırın."
                }
                # Listeye ekliyoruz.
                local_findings.append(finding)

        # Bulguları döndürüyoruz.
        return local_findings

    # Tüm denetim adımlarını icra eden ve güvenlik puanını hesaplayan ana metod.
    def execute_full_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tüm yedekleme denetimlerini icra eder, puanı hesaplar ve rapor döner.
        """
        # Şemayı doğruluyoruz.
        self.validate_telemetry_schema(data)

        # Politika listesini alıyoruz.
        policies = data.get("backup_policies", [])

        # Önceki bulguları sıfırlıyoruz.
        self.findings = []

        # 1. 3-2-1 kuralı uyumluluk analizi:
        self.findings.extend(self.audit_321_rule_compliance(policies))

        # 2. Geri yükleme testleri ve Schrödinger yedeği analizi:
        self.findings.extend(self.audit_restore_verification_and_testing(policies))

        # 3. RAID vs Snapshot mimari yanılgıları analizi:
        self.findings.extend(self.audit_raid_and_snapshot_misconceptions(policies))

        # 4. RPO hedef sapması analizi:
        self.findings.extend(self.audit_rpo_compliance(policies))

        # Başlangıç güvenlik skoru 100:
        security_score = 100
        # Kritik bulguları sayıyoruz.
        crit_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        # Yüksek seviyeli bulguları sayıyoruz.
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        # Orta seviyeli bulguları sayıyoruz.
        med_count = sum(1 for f in self.findings if f["severity"] == "MEDIUM")
        # Uyarı seviyeli bulguları sayıyoruz.
        warn_count = sum(1 for f in self.findings if f["severity"] == "WARNING")

        # Puan kırma oranları: Kritik -20, Yüksek -10, Orta -5, Uyarı -2.
        security_score -= (crit_count * 20)
        security_score -= (high_count * 10)
        security_score -= (med_count * 5)
        security_score -= (warn_count * 2)

        # Puanın sıfırın altına düşmesini önlüyoruz.
        security_score = max(0, security_score)

        # Genel güvenlik durumunu belirliyoruz.
        overall_status = "SECURE" if security_score >= 85 else ("WARNING" if security_score >= 60 else "CRITICAL")

        # Rapor sözlüğünü oluşturup döndürüyoruz.
        return {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "inventory_metadata": data.get("inventory_metadata", {}),
            "security_score": security_score,
            "overall_status": overall_status,
            "metrics": {
                "total_policies_analyzed": len(policies),
                "critical_findings": crit_count,
                "high_findings": high_count,
                "medium_findings": med_count,
                "warning_findings": warn_count,
                "total_findings": len(self.findings)
            },
            "findings": self.findings
        }

    # Denetim sonucunu Markdown raporuna dönüştüren fonksiyon.
    def export_markdown_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Denetim sonucunu insan tarafından okunabilir Markdown formatında biçimlendirir.
        """
        # Boş liste başlatıyoruz.
        lines: List[str] = []

        # Lisans başlığını ekliyoruz.
        lines.append("<!--")
        lines.append("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR")
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)")
        lines.append("Bu yazılım ve ilgili tüm dosyalar ('Yazılım') yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.")
        lines.append("-->\n")

        # Rapor başlığı:
        lines.append("# Yedekleme Stratejisi ve 3-2-1 Kuralı Güvenlik Denetim Raporu\n")

        # Üst bilgiler:
        lines.append(f"**Denetim Tarihi:** `{audit_result.get('audit_timestamp', 'N/A')}`  ")
        lines.append(f"**Güvenlik Puanı:** `{audit_result.get('security_score', 0)} / 100`  ")
        lines.append(f"**Genel Durum:** `{audit_result.get('overall_status', 'UNKNOWN')}`\n")

        # Metrik tablosu:
        metrics = audit_result.get("metrics", {})
        lines.append("## 📊 Denetim Metrikleri Özeti\n")
        lines.append("| Metrik | Değer |")
        lines.append("| :--- | :---: |")
        lines.append(f"| İncelenen Politika Sayısı | {metrics.get('total_policies_analyzed', 0)} |")
        lines.append(f"| Kritik (CRITICAL) Bulgular | {metrics.get('critical_findings', 0)} |")
        lines.append(f"| Yüksek (HIGH) Seviye Bulgular | {metrics.get('high_findings', 0)} |")
        lines.append(f"| Orta (MEDIUM) Seviye Bulgular | {metrics.get('medium_findings', 0)} |")
        lines.append(f"| Uyarı (WARNING) Bulgular | {metrics.get('warning_findings', 0)} |")
        lines.append(f"| **Toplam Güvenlik Bulgusu** | **{metrics.get('total_findings', 0)}** |\n")

        # Bulgular bölümü:
        lines.append("## 🔍 Güvenlik Bulguları ve İyileştirme Reçetesi\n")
        findings = audit_result.get("findings", [])

        # Bulgu yoksa temiz bildiriyoruz.
        if not findings:
            lines.append("✅ *Tüm yedekleme politikaları 3-2-1 standardına, geri yükleme testlerine ve fidye yazılımı dayanıklılığına tam uygundur.*\n")
        else:
            # Bulguları listeliyoruz.
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. [{f['severity']}] {f['title']}")
                lines.append(f"- **Hedef:** `{f['target']}`")
                lines.append(f"- **Kategori:** `{f['category']}`")
                lines.append(f"- **Açıklama:** {f['description']}")
                lines.append(f"- **🛡️ İyileştirme:** {f['remediation']}\n")

        # Satırları birleştirip döndürüyoruz.
        return "\n".join(lines)


# Komut satırı giriş noktası:
def main() -> None:
    """
    CLI yürütme giriş noktası.
    """
    # Windows konsolunda UTF-8 güvencesi sağlıyoruz.
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktıyı UTF-8 yapıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Standart hatayı da UTF-8 yapıyoruz.
    if hasattr(sys.stderr, "reconfigure"):
        # Standart hata akışını ayarlıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı oluşturuyoruz.
    parser = argparse.ArgumentParser(description="G039: Yedekleme Stratejisi ve 3-2-1 Kuralı Güvenlik Denetçisi")
    # Telemetri yolu argümanı:
    parser.add_argument("--telemetry", type=str, required=True, help="İncelenecek JSON yedekleme envanter dosyasının yolu")
    # Çıktı dosyası argümanı:
    parser.add_argument("--output", type=str, default="", help="Markdown raporunun kaydedileceği dosya yolu")

    # Argümanları ayrıştırıyoruz.
    args = parser.parse_args()

    # Dosya varlık kontrolü:
    if not os.path.exists(args.telemetry):
        # Hata mesajı yazıp çıkıyoruz.
        print(f"HATA: Yedekleme envanter dosyası bulunamadı: {args.telemetry}", file=sys.stderr)
        # Çıkış kodu 1 ile sonlandırıyoruz.
        sys.exit(1)

    # Dosyayı okuyoruz.
    with open(args.telemetry, "r", encoding="utf-8") as f:
        # JSON ayrıştırıyoruz.
        inventory_data = json.load(f)

    # Denetçi nesnesini oluşturuyoruz.
    auditor = BackupStrategy321Auditor()
    # Denetimi icra ediyoruz.
    audit_result = auditor.execute_full_audit(inventory_data)
    # Raporu üretiyoruz.
    report_md = auditor.export_markdown_report(audit_result)

    # Ekrana basıyoruz.
    print(report_md)

    # Çıktı dosyası istendiyse kaydediyoruz:
    if args.output:
        # Dosyaya yazıyoruz.
        with open(args.output, "w", encoding="utf-8") as out_f:
            # İçeriği kaydediyoruz.
            out_f.write(report_md)
        # Bilgi mesajı yazdırıyoruz.
        print(f"\nRapor başarıyla kaydedildi: {args.output}")


# Doğrudan icra durumunda main çağrılır.
if __name__ == "__main__":
    # main'i çağırıyoruz.
    main()
