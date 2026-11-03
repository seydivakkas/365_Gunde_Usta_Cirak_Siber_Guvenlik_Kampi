# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 141 - Yama Yönetimi ve CVE (Patch Management & CVE Engine).
Bu modül; CVE zafiyetlerinin doğrulanması, CVSS v3.1 skorlama ve risk derecelendirmesi,
CISA KEV ve EPSS tehdit istihbaratı analizi, kurumsal yama SLA uyumluluğu,
dağıtım planlaması ve geri alma (rollback) stratejilerini yöneten kurumsal motordur.
"""

# İşletim sistemi dosya yolu ve ortam fonksiyonları
import os
# Sistem akışları ve argüman kontrolü
import sys
# Yapılandırılmış JSON verisi işleme
import json
# Düzenli ifadeler ile CVE formatı ve sürüm kontrolü
import re
# Kriptografik özetleme ve bütünlük hesaplama
import hashlib
# Tarih, saat ve SLA hesaplama işlemleri
from datetime import datetime, date
# Veri yapılarını nesne yönelimli temsil etmek için dataclass modülü
from dataclasses import dataclass, field, asdict
# Tip ipuçları ve statik analiz desteği
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class CveRecord:
    """
    Tekil bir Ortak Güvenlik Açığı ve Maruz Kalma (CVE) kaydı veri modeli.
    """
    cve_id: str                     # CVE kimliği (örn: CVE-2024-6387)
    package_name: str               # Etkilenen paket/yazılım adı (örn: openssh-server)
    installed_version: str          # Sistemde kurulu olan mevcut sürüm
    fixed_version: str              # Zafiyetin giderildiği güvenli sürüm
    cvss_score: float               # CVSS v3.1 taban skoru (0.0 - 10.0)
    cvss_vector: str                # CVSS vektör dizesi (örn: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    is_in_cisa_kev: bool = False    # CISA KEV (Aktif İstismar) kataloğunda mı?
    epss_score: float = 0.0         # EPSS istismar olasılık skoru (0.0 - 1.0)
    published_date: str = ""        # Zafiyetin yayınlanma tarihi (YYYY-MM-DD)
    description: str = ""           # Zafiyetin teknik açıklaması


@dataclass
class PatchTriageResult:
    """
    CVE için yapılan triyaj, önceliklendirme ve SLA değerlendirme sonucu.
    """
    cve_id: str                     # İncelenen CVE kimliği
    severity: str                   # Şiddet derecesi: CRITICAL, HIGH, MEDIUM, LOW
    urgency_level: str              # Müdahale aciliyeti: EMERGENCY, CRITICAL, HIGH, MEDIUM, LOW
    max_sla_days: int               # Politikaya göre tanınan maksimum yama süresi (gün)
    elapsed_days: int               # Zafiyetten bu yana geçen gün sayısı
    sla_breached: bool              # SLA ihlal edilmiş mi?
    remediation_command: str        # Uygulanacak yama komutu
    rollback_command: str           # Geri alma komutu


@dataclass
class SystemPatchStatus:
    """
    Sistemin genel yama sağlığı, açık zafiyetleri ve uyumluluk özeti.
    """
    hostname: str                   # Hedef sunucu adı
    os_distribution: str            # İşletim sistemi dağıtımı (Ubuntu, Debian, RHEL)
    scan_timestamp: str             # Tarama zaman damgası
    total_vulnerabilities: int      # Toplam tespit edilen CVE sayısı
    emergency_count: int            # Acil müdahale (CISA KEV / Critical) sayısı
    sla_breached_count: int         # SLA süresi aşılmış zafiyet sayısı
    auto_update_enabled: bool       # Otomatik güvenlik güncellemesi açık mı?
    reboot_required: bool           # Yama sonrası sistem yeniden başlatma gerektiriyor mu?
    patch_hygiene_score: float      # Yama hijyen puanı (0 - 100)
    compliance_status: str          # COMPLIANT, AT_RISK, NON_COMPLIANT
    triage_results: List[PatchTriageResult] = field(default_factory=list)


class PatchCveEngine:
    """
    Yama Yönetimi ve CVE Analiz Motoru.
    Kurumsal standartlara göre yama yaşam döngüsünü ve SLA uyumunu denetler.
    """

    # Standart CVE desen kontrolü (CVE-YYYY-NNNN+)
    CVE_PATTERN = re.compile(r"^CVE-(1999|20\d{2})-\d{4,}$")

    # Kurumsal SLA Politikası (Gün cinsinden maksimum yama süresi)
    SLA_POLICY_DAYS = {
        "EMERGENCY": 3,      # CISA KEV veya CVSS >= 9.0 + Yüksek EPSS: 72 Saat (3 Gün)
        "CRITICAL": 7,       # CVSS >= 9.0 standart: 7 Gün
        "HIGH": 14,          # CVSS 7.0 - 8.9: 14 Gün
        "MEDIUM": 30,        # CVSS 4.0 - 6.9: 30 Gün
        "LOW": 60            # CVSS < 4.0: 60 Gün
    }

    def __init__(self, inventory_data: Optional[Dict[str, Any]] = None):
        """
        Yama motorunu başlatır ve envanter verisini hazırlar.
        """
        # Hedef sistemin paket ve zafiyet envanteri
        self.inventory = inventory_data or {}
        # Doğrulanmış CVE nesneleri listesi
        self.cve_records: List[CveRecord] = []
        # Analiz ve durum raporu
        self.status_report: Optional[SystemPatchStatus] = None

    def load_inventory_from_file(self, file_path: str) -> None:
        """
        JSON dosyasından sistem paket ve CVE envanterini yükler.
        """
        # Dosya varlığını kontrol et
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Yama envanter dosyası bulunamadı: {file_path}")
        # Dosyayı oku ve JSON verisine ayrıştır
        with open(file_path, "r", encoding="utf-8") as fp:
            self.inventory = json.load(fp)

    def validate_and_parse_cves(self) -> List[CveRecord]:
        """
        Envanterdeki ham CVE listesini doğrular ve CveRecord nesnelerine dönüştürür.
        """
        self.cve_records.clear()
        raw_cves = self.inventory.get("vulnerabilities", [])

        for item in raw_cves:
            cve_id = item.get("cve_id", "").strip().upper()
            # Sözdizimi geçerlilik kontrolü
            if not self.CVE_PATTERN.match(cve_id):
                raise ValueError(f"Geçersiz CVE kimliği biçimi tespit edildi: {cve_id}")

            cvss = float(item.get("cvss_score", 0.0))
            # CVSS skoru 0.0 - 10.0 aralığında olmalıdır
            if not (0.0 <= cvss <= 10.0):
                raise ValueError(f"Geçersiz CVSS skoru ({cvss}) CVE: {cve_id}")

            epss = float(item.get("epss_score", 0.0))
            if not (0.0 <= epss <= 1.0):
                raise ValueError(f"Geçersiz EPSS skoru ({epss}) CVE: {cve_id}")

            rec = CveRecord(
                cve_id=cve_id,
                package_name=item.get("package_name", "unknown"),
                installed_version=item.get("installed_version", "0.0.0"),
                fixed_version=item.get("fixed_version", "0.0.0"),
                cvss_score=cvss,
                cvss_vector=item.get("cvss_vector", ""),
                is_in_cisa_kev=bool(item.get("is_in_cisa_kev", False)),
                epss_score=epss,
                published_date=item.get("published_date", "2026-01-01"),
                description=item.get("description", "")
            )
            self.cve_records.append(rec)

        return self.cve_records

    def calculate_severity(self, cvss_score: float) -> str:
        """
        CVSS v3.1 puanına göre nitel şiddet derecesini belirler.
        """
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        return "NONE"

    def determine_urgency(self, cve: CveRecord) -> Tuple[str, int]:
        """
        CVSS, CISA KEV ve EPSS tehdit istihbaratını birleştirerek müdahale aciliyetini ve SLA süresini belirler.
        """
        # Kural 1: Zafiyet CISA KEV listesindeyse (aktif istismar) doğrudan EMERGENCY (3 Gün)
        if cve.is_in_cisa_kev:
            return "EMERGENCY", self.SLA_POLICY_DAYS["EMERGENCY"]

        # Kural 2: CVSS >= 9.0 ve EPSS >= 0.40 ise yüksek istismar olasılığı nedeniyle EMERGENCY
        if cve.cvss_score >= 9.0 and cve.epss_score >= 0.40:
            return "EMERGENCY", self.SLA_POLICY_DAYS["EMERGENCY"]

        # Kural 3: Standart CVSS şiddet eşlemesi
        severity = self.calculate_severity(cve.cvss_score)
        if severity == "CRITICAL":
            return "CRITICAL", self.SLA_POLICY_DAYS["CRITICAL"]
        elif severity == "HIGH":
            return "HIGH", self.SLA_POLICY_DAYS["HIGH"]
        elif severity == "MEDIUM":
            return "MEDIUM", self.SLA_POLICY_DAYS["MEDIUM"]
        else:
            return "LOW", self.SLA_POLICY_DAYS["LOW"]

    def triage_vulnerabilities(self, current_date_str: Optional[str] = None) -> List[PatchTriageResult]:
        """
        Tüm doğrulanmış CVE'ler için önceliklendirme ve SLA ihlal analizini gerçekleştirir.
        """
        if not self.cve_records:
            self.validate_and_parse_cves()

        # Referans değerlendirme tarihi (varsayılan: bugün veya sağlanan tarih)
        ref_date = date.fromisoformat(current_date_str) if current_date_str else date.today()
        triage_list = []

        # Dağıtım türünü öğren (apt vs dnf)
        os_type = self.inventory.get("system_info", {}).get("os_family", "debian").lower()

        for cve in self.cve_records:
            severity = self.calculate_severity(cve.cvss_score)
            urgency, max_sla = self.determine_urgency(cve)

            # Geçen gün sayısını hesapla
            try:
                pub_date = date.fromisoformat(cve.published_date)
                elapsed_days = (ref_date - pub_date).days
                if elapsed_days < 0:
                    elapsed_days = 0
            except Exception:
                elapsed_days = 0

            # SLA aşımı kontrolü
            sla_breached = elapsed_days > max_sla

            # İşletim sistemine uygun yama komutunu oluştur
            if "debian" in os_type or "ubuntu" in os_type:
                rem_cmd = f"apt-get update && apt-get install --only-upgrade -y {cve.package_name}={cve.fixed_version}"
                roll_cmd = f"apt-get install -y --allow-downgrades {cve.package_name}={cve.installed_version}"
            elif "rhel" in os_type or "centos" in os_type or "rocky" in os_type:
                rem_cmd = f"dnf update-minimal --security -y {cve.package_name}"
                roll_cmd = f"dnf downgrade -y {cve.package_name}-{cve.installed_version}"
            else:
                rem_cmd = f"# Manuel paket güncellemesi: {cve.package_name} -> {cve.fixed_version}"
                roll_cmd = f"# Manuel paket geri alma: {cve.package_name} -> {cve.installed_version}"

            triage_item = PatchTriageResult(
                cve_id=cve.cve_id,
                severity=severity,
                urgency_level=urgency,
                max_sla_days=max_sla,
                elapsed_days=elapsed_days,
                sla_breached=sla_breached,
                remediation_command=rem_cmd,
                rollback_command=roll_cmd
            )
            triage_list.append(triage_item)

        return triage_list

    def evaluate_system_patch_status(self, current_date_str: Optional[str] = None) -> SystemPatchStatus:
        """
        Sistemin genel yama durumunu, hijyen puanını ve uyumluluk düzeyini hesaplar.
        """
        triage_results = self.triage_vulnerabilities(current_date_str)
        sys_info = self.inventory.get("system_info", {})
        config_spec = self.inventory.get("patch_config_spec", {})

        total_vulns = len(triage_results)
        emergency_count = sum(1 for t in triage_results if t.urgency_level == "EMERGENCY")
        critical_count = sum(1 for t in triage_results if t.urgency_level == "CRITICAL")
        sla_breached_count = sum(1 for t in triage_results if t.sla_breached)

        auto_updates = bool(config_spec.get("auto_security_updates", False))
        reboot_req = bool(config_spec.get("reboot_required", False))

        # Yama Hijyen Puanı Hesaplama (100 üzerinden ceza puanı düşülür)
        # Taban puan 100
        score = 100.0

        # Her acil (EMERGENCY) açık için -25 puan
        score -= (emergency_count * 25.0)
        # Her kritik (CRITICAL) açık için -15 puan
        score -= (critical_count * 15.0)
        # Her SLA aşımı için ekstra -10 puan
        score -= (sla_breached_count * 10.0)
        # Otomatik güncellemeler kapalıysa -15 puan
        if not auto_updates:
            score -= 15.0
        # Yeniden başlatma bekleniyorsa -10 puan
        if reboot_req:
            score -= 10.0

        # Puanı 0.0 ile 100.0 arasına sıkıştır
        score = max(0.0, min(100.0, score))
        score = round(score, 2)

        # Uyumluluk durumu sınıflandırması
        if score >= 90.0 and emergency_count == 0 and sla_breached_count == 0:
            compliance = "COMPLIANT"
        elif score >= 60.0:
            compliance = "AT_RISK"
        else:
            compliance = "NON_COMPLIANT"

        self.status_report = SystemPatchStatus(
            hostname=sys_info.get("hostname", "unknown-host"),
            os_distribution=sys_info.get("os_distribution", "Linux"),
            scan_timestamp=datetime.now().isoformat(),
            total_vulnerabilities=total_vulns,
            emergency_count=emergency_count,
            sla_breached_count=sla_breached_count,
            auto_update_enabled=auto_updates,
            reboot_required=reboot_req,
            patch_hygiene_score=score,
            compliance_status=compliance,
            triage_results=triage_results
        )

        return self.status_report

    def generate_patch_execution_plan(self, output_path: Optional[str] = None) -> str:
        """
        Aşamalı yama dağıtım ve acil durum geri alma Bash betiği üretir.
        """
        if not self.status_report:
            self.evaluate_system_patch_status()

        lines = [
            "#!/usr/bin/env bash",
            "# =============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Gün 141: Otomatik Yama Uygulama ve Aşamalı Dağıtım Betiği",
            "# =============================================================================",
            "set -euo pipefail",
            "",
            "echo '[+] Güvenlik Yaması Dağıtım Protokolü Başlatılıyor...'",
            f"echo '[+] Hedef Sunucu: {self.status_report.hostname}'",
            ""
        ]

        # 1. Aşama: Acil (EMERGENCY) ve Kritik Yamaların Uygulanması
        emergency_triages = [t for t in self.status_report.triage_results if t.urgency_level in ["EMERGENCY", "CRITICAL"]]
        if emergency_triages:
            lines.append("# --- AŞAMA 1: ACİL VE KRİTİK GÜVENLİK YAMALARI (CISA KEV / HIGH CVSS) ---")
            for t in emergency_triages:
                lines.append(f"# CVE: {t.cve_id} (Şiddet: {t.severity}, Aciliyet: {t.urgency_level})")
                lines.append(f"echo '[*] Uygulanıyor: {t.cve_id}'")
                lines.append(t.remediation_command)
                lines.append("")

        # 2. Aşama: Standart Seviyedeki Yamaların Uygulanması
        standard_triages = [t for t in self.status_report.triage_results if t.urgency_level not in ["EMERGENCY", "CRITICAL"]]
        if standard_triages:
            lines.append("# --- AŞAMA 2: STANDART VE RUTİN GÜVENLİK YAMALARI ---")
            for t in standard_triages:
                lines.append(f"# CVE: {t.cve_id} (Şiddet: {t.severity})")
                lines.append(t.remediation_command)
                lines.append("")

        # 3. Aşama: Otomatik Güncelleme Konfigürasyonunun Zorlanması
        lines.append("# --- AŞAMA 3: OTOMATİK GÜVENLİK GÜNCELLEMESİ (UNATTENDED UPGRADES) ---")
        lines.append("if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then")
        lines.append("    echo '[*] unattended-upgrades paketi kuruluyor...'")
        lines.append("    apt-get update && apt-get install -y unattended-upgrades")
        lines.append("fi")
        lines.append("echo 'APT::Periodic::Update-Package-Lists \"1\";' > /etc/apt/apt.conf.d/20auto-upgrades")
        lines.append("echo 'APT::Periodic::Unattended-Upgrade \"1\";' >> /etc/apt/apt.conf.d/20auto-upgrades")
        lines.append("")

        # 4. Aşama: Yeniden Başlatma Kontrolü
        lines.append("# --- AŞAMA 4: YENİDEN BAŞLATMA GEREKSİNİMİ DENETİMİ ---")
        lines.append("if [ -f /var/run/reboot-required ]; then")
        lines.append("    echo '[!] UYARI: Çekirdek veya kritik kütüphane güncellendi. Sistem yeniden başlatma bekliyor!'")
        lines.append("    cat /var/run/reboot-required.pkgs 2>/dev/null || true")
        lines.append("fi")
        lines.append("")
        lines.append("echo '[+] Yama uygulama süreci başarıyla tamamlandı.'")

        content = "\n".join(lines)
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fp:
                fp.write(content)

        return content

    def generate_rollback_script(self, output_path: Optional[str] = None) -> str:
        """
        Olası bir gerileme (regression) durumunda paketleri eski sürüme döndüren acil geri alma betiği üretir.
        """
        if not self.status_report:
            self.evaluate_system_patch_status()

        lines = [
            "#!/usr/bin/env bash",
            "# =============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Gün 141: Acil Durum Geri Alma (Rollback) Betiği",
            "# =============================================================================",
            "set -euo pipefail",
            "",
            "echo '[!] DİKKAT: Güvenlik Yaması Geri Alma (Rollback) Protokolü Devrede!'",
            ""
        ]

        for t in self.status_report.triage_results:
            lines.append(f"# Geri Alınıyor: {t.cve_id}")
            lines.append(f"echo '[*] Eski sürüme dönülüyor: {t.cve_id}'")
            lines.append(t.rollback_command)
            lines.append("")

        lines.append("echo '[+] Geri alma süreci tamamlandı. Servisleri kontrol ediniz.'")

        content = "\n".join(lines)
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fp:
                fp.write(content)

        return content

    def export_report_json(self, output_path: str) -> None:
        """
        Analiz sonuçlarını JSON formatında diske yazar.
        """
        if not self.status_report:
            self.evaluate_system_patch_status()

        data = asdict(self.status_report)
        data["_lisans"] = "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)."

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
