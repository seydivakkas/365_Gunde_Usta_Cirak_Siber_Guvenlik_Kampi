# ============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
#
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
#
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
#
# YASAKLAR:
#   1. Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
#   2. Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
#   3. Alt lisanslanamaz, satılamaz veya devredilemez.
#   4. Tersine mühendislik yapılamaz.
#
# İZİN VERİLEN KULLANIM:
#   - GitHub üzerinde görüntüleme ve okuma.
#   - Kişisel öğrenim amacıyla kodu inceleme (kopyalamadan).
#
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ============================================================================
"""
Gün 35: Mini Proje 4: Sistem Durum Kontrolü ve Sağlık Denetleyicisi (MP-04)
Bu modül; Hafta 05 boyunca öğrenilen süreç hiyerarşisi, servis yönetimi,
dosya bütünlüğü (FIM) ve sihirli bayt (magic bytes) analizlerini tek bir
çatı altında birleştirerek salt-okunur (read-only), sıfır yan etkili
ve ayrıcalık gerektirmeyen kapsamlı bir sistem güvenlik duruşu (posture) üretir.
"""

# Standart dosya sistemi işlemleri ve yol operasyonları için os modülü
import os
# Komut satırı ve sistem argümanları için sys modülü
import sys
# JSON tabanlı telemetri verilerini okumak ve raporlamak için json modülü
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
import datetime
# Tip ipuçları ve statik denetimler için typing modülü
from typing import Dict, List, Any, Tuple, Optional
# Nesne modelleri oluşturmak için dataclass yapısı
from dataclasses import dataclass, field, asdict


@dataclass
class PostureFinding:
    """Sistem durum denetiminde saptanan tekil bir güvenlik bulgusu modeli."""
    # Bulguyu tespit eden alt denetim modülü (PROCESS, SERVICE, INTEGRITY, FILE_TYPE)
    domain: str
    # İlgili varlığın kimliği veya adı (PID, Servis Adı, Dosya Yolu)
    target: str
    # Zafiyetin risk derecesi (CRITICAL, HIGH, MEDIUM, LOW)
    severity: str
    # Zafiyet sınıfı (Örn: SUSPICIOUS_PARENT_CHAIN, UNQUOTED_SERVICE_PATH, INTEGRITY_MISMATCH)
    vulnerability_type: str
    # Teknik gözlem açıklaması
    description: str
    # MITRE ATT&CK teknik referansı
    mitre_technique: str
    # Gerekli savunma ve iyileştirme adımı
    remediation: str


class SystemPostureAuditor:
    """
    Mini Proje 4: Sistem Durum Kontrolü Ana Analizcisi.
    G035-SC1 İlkesi: Sistem durum taraması yalnızca gözlemlerden anlamlı özet üretmeli
    ve yönetimsel ayrıcalık gerektirmemelidir (Salt-Okunur Gözlemci Modeli).
    """

    # Kritik işletim sistemi güvenlik servisleri listesi
    CRITICAL_SECURITY_SERVICES = {"windefend", "eventlog", "mpssvc"}

    # Saldırganlar tarafından sıkça taklit edilen meşru sistem ikilileri
    MASQUERADED_NAMES = {"svch0st.exe", "lsasss.exe", "csrsss.exe"}

    def __init__(self) -> None:
        """Denetleyiciyi temiz bir hafıza ve boş bulgu listesiyle başlatır."""
        # Yüklenen sistem telemetri verisi
        self.telemetry_data: Dict[str, Any] = {}
        # Denetim sonucunda ortaya çıkan güvenlik bulguları listesi
        self.findings: List[PostureFinding] = []
        # Reddedilen bozuk telemetri kayıtlarının günlüğü
        self.corrupted_records: List[Dict[str, Any]] = []

    def validate_telemetry_schema(self, data: Any) -> Tuple[bool, str]:
        """
        Gelen telemetri verisinin şema sözleşmesine uygunluğunu denetler.
        Negatif kontrollerin başarısı için zorunlu alanları doğrular.
        """
        # Verinin sözlük tipinde olup olmadığını sınıyoruz
        if not isinstance(data, dict):
            return False, "GECERSIZ_VERI_TIPI: Telemetri verisi bir JSON sozluk nesnesi olmalidir."

        # Zorunlu anahtar alanların varlığını denetliyoruz
        required_keys = ["system_info", "processes", "services", "file_integrity", "file_signatures"]
        for k in required_keys:
            if k not in data:
                return False, f"EKSIK_BOLUM: Zorunlu telemetri bolumu '{k}' eksiktir."

        # Bölümlerin doğru veri tiplerinde olduğunu sınıyoruz
        if not isinstance(data["processes"], list):
            return False, "GECERSIZ_TIP: 'processes' bir liste olmalidir."
        if not isinstance(data["services"], list):
            return False, "GECERSIZ_TIP: 'services' bir liste olmalidir."
        if not isinstance(data["file_integrity"], list):
            return False, "GECERSIZ_TIP: 'file_integrity' bir liste olmalidir."
        if not isinstance(data["file_signatures"], list):
            return False, "GECERSIZ_TIP: 'file_signatures' bir liste olmalidir."

        return True, "GECERLI"

    def load_telemetry(self, file_path: str) -> bool:
        """Disk üzerindeki JSON telemetri anlık görüntüsünü (snapshot) yükler."""
        # Dosya varlığını denetliyoruz
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Telemetri dosyasi bulunamadi: {file_path}")

        # JSON dosyasını okuyoruz
        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        # Şema doğrulaması yapıyoruz
        is_valid, reason = self.validate_telemetry_schema(raw)
        if not is_valid:
            self.corrupted_records.append({"file": file_path, "error": reason})
            return False

        # Başarıyla hafızaya alıyoruz
        self.telemetry_data = raw
        return True

    def audit_process_telemetry(self) -> List[PostureFinding]:
        """Süreç ağacı ve yürütme hiyerarşisi anomalilerini tespit eder."""
        local_findings: List[PostureFinding] = []
        processes = self.telemetry_data.get("processes", [])

        # Hızlı PID araması için harita oluşturuyoruz
        proc_by_pid = {p.get("pid"): p for p in processes if isinstance(p, dict) and "pid" in p}

        for proc in processes:
            if not isinstance(proc, dict):
                continue

            pid = proc.get("pid")
            ppid = proc.get("ppid")
            name = str(proc.get("name", "")).lower()
            cmd = str(proc.get("command_line", "")).lower()
            exe = str(proc.get("executable_path", "")).lower()

            # 1. Ebeveyn-Çocuk İlişkisi Analizi: Office uygulaması (winword/excel) powershell/cmd başlatıyor mu?
            parent_proc = proc_by_pid.get(ppid)
            if parent_proc:
                p_name = str(parent_proc.get("name", "")).lower()
                if p_name in ["winword.exe", "excel.exe", "powerpnt.exe"] and name in ["powershell.exe", "cmd.exe"]:
                    finding = PostureFinding(
                        domain="PROCESS_HIERARCHY",
                        target=f"PID {pid} ({proc.get('name')})",
                        severity="CRITICAL",
                        vulnerability_type="MALICIOUS_OFFICE_SPAWN",
                        description=(
                            f"Kritik saldırı zinciri: '{parent_proc.get('name')}' (PID {ppid}) süreci "
                            f"tarafından '{proc.get('name')}' (PID {pid}) kabuk süreci başlatılmış! "
                            f"Komut Satırı: '{proc.get('command_line')}'"
                        ),
                        mitre_technique="T1059.001 (PowerShell) / T1204.002 (Malicious File)",
                        remediation="İlgili süreci derhal sonlandırın, ağdan izole edin ve belge kaynağını EDR ile inceleyin."
                    )
                    local_findings.append(finding)

            # 2. İsim Sahteciliği ve Typosquatting (svch0st)
            if name in self.MASQUERADED_NAMES or "temp" in exe:
                if name.startswith("svch0st") or "svch0st" in exe:
                    finding = PostureFinding(
                        domain="PROCESS_SECURITY",
                        target=f"PID {pid} ({proc.get('name')})",
                        severity="CRITICAL",
                        vulnerability_type="PROCESS_MASQUERADING",
                        description=(
                            f"Süreç taklidi ve zararlı dizin: '{proc.get('name')}' meşru svchost sürecini taklit ediyor "
                            f"ve şüpheli geçici dizinden ('{proc.get('executable_path')}') yürütülüyor."
                        ),
                        mitre_technique="T1036 (Masquerading)",
                        remediation="Süreci sonlandırın, dosya karmasını (hash) karantinaya alın ve kalıcılık anahtarlarını silin."
                    )
                    local_findings.append(finding)

        return local_findings

    def audit_service_telemetry(self) -> List[PostureFinding]:
        """Sistem servislerini ve başlangıç yapılandırmalarını denetler."""
        local_findings: List[PostureFinding] = []
        services = self.telemetry_data.get("services", [])

        for svc in services:
            if not isinstance(svc, dict):
                continue

            name = str(svc.get("name", "")).strip()
            status = str(svc.get("status", "")).strip()
            start_mode = str(svc.get("start_mode", "")).strip()
            bin_path = str(svc.get("binary_path", "")).strip()

            # 1. Kritik Güvenlik Servisi Devre Dışı/Durdurulmuş mu?
            if name.lower() in self.CRITICAL_SECURITY_SERVICES:
                if status.lower() == "stopped" or start_mode.lower() == "disabled":
                    finding = PostureFinding(
                        domain="SERVICE_SECURITY",
                        target=name,
                        severity="CRITICAL",
                        vulnerability_type="SECURITY_SERVICE_TAMPERED",
                        description=(
                            f"Kritik güvenlik bileşeni '{name}' beklenen çalışma durumunda değildir! "
                            f"Durum: {status}, Başlangıç Türü: {start_mode}."
                        ),
                        mitre_technique="T1562.001 (Impair Defenses: Disable or Modify Tools)",
                        remediation=f"Servisi otomatik moda alıp derhal başlatınız: sc.exe config {name} start= auto && sc.exe start {name}"
                    )
                    local_findings.append(finding)

            # 2. Tırnaksız Servis Yolu (Unquoted Service Path)
            if not bin_path.startswith('"') and " " in bin_path:
                finding = PostureFinding(
                    domain="SERVICE_SECURITY",
                    target=name,
                    severity="HIGH",
                    vulnerability_type="UNQUOTED_SERVICE_PATH",
                    description=(
                        f"Servis ikili yolu ('{bin_path}') boşluk içermesine rağmen çift tırnak içine alınmamış. "
                        f"Windows SCM arama zinciri sebebiyle Yerel Yetki Yükseltme (LPE) riski taşımaktadır."
                    ),
                    mitre_technique="T1574.009 (Path Interception by Unquoted Path)",
                    remediation=f'Servis yolunu tırnak içine alınız: sc.exe config "{name}" binPath= "\\"{bin_path}\\""'
                )
                local_findings.append(finding)

        return local_findings

    def audit_file_integrity_telemetry(self) -> List[PostureFinding]:
        """Dosya bütünlüğü ve taban çizgisi anomalilerini denetler."""
        local_findings: List[PostureFinding] = []
        integrity_items = self.telemetry_data.get("file_integrity", [])

        for item in integrity_items:
            if not isinstance(item, dict):
                continue

            path = str(item.get("file_path", ""))
            status = str(item.get("status", "")).upper()
            exp_h = item.get("expected_sha256", "N/A")
            act_h = item.get("actual_sha256", "N/A")

            # Hash uyuşmazlığı: Dosya tahrif edilmiş
            if status == "MISMATCH":
                finding = PostureFinding(
                    domain="FILE_INTEGRITY",
                    target=path,
                    severity="CRITICAL",
                    vulnerability_type="INTEGRITY_VIOLATION",
                    description=(
                        f"Kritik konfigürasyon dosyası bütünlüğü ihlal edildi! "
                        f"Beklenen SHA-256: {exp_h} | Fiili SHA-256: {act_h}."
                    ),
                    mitre_technique="T1565.001 (Data Manipulation: Stored Data Manipulation)",
                    remediation="Dosyayı temiz yedekten geri yükleyin ve yetkisiz değişiklik yapan oturumu araştırın."
                )
                local_findings.append(finding)
            elif status == "MISSING":
                finding = PostureFinding(
                    domain="FILE_INTEGRITY",
                    target=path,
                    severity="HIGH",
                    vulnerability_type="BASELINE_DISRUPTION",
                    description=f"Taban çizgisinde yer alan zorunlu dosya diskte bulunamadı: '{path}'.",
                    mitre_technique="T1485 (Data Destruction)",
                    remediation="Kayıp dosyayı yetkili yazılım dağıtım paketinden geri yükleyiniz."
                )
                local_findings.append(finding)

        return local_findings

    def audit_file_signature_telemetry(self) -> List[PostureFinding]:
        """Sihirli bayt (magic bytes) ve uzantı uyuşmazlıklarını denetler."""
        local_findings: List[PostureFinding] = []
        signatures = self.telemetry_data.get("file_signatures", [])

        for sig in signatures:
            if not isinstance(sig, dict):
                continue

            fname = str(sig.get("file_name", ""))
            claimed = str(sig.get("claimed_extension", ""))
            detected = str(sig.get("detected_format", ""))
            is_mismatch = bool(sig.get("is_mismatch", False))

            if is_mismatch:
                # Çift uzantı mı kontrolü
                is_double = len(fname.split(".")) >= 3 and fname.endswith(".exe")
                sev = "HIGH" if is_double else "CRITICAL"
                vuln_name = "DOUBLE_EXTENSION_TROJAN" if is_double else "EXTENSION_SPOOFING"

                finding = PostureFinding(
                    domain="FILE_SIGNATURE",
                    target=fname,
                    severity=sev,
                    vulnerability_type=vuln_name,
                    description=(
                        f"Dosya uzantı aldatmacası: Dosya '{claimed}' uzantısıyla sunulmasına karşın, "
                        f"başlık sihirli baytları '{detected}' çalıştırma biçimindedir! Başlık: {sig.get('header_hex')}."
                    ),
                    mitre_technique="T1036.008 (Masquerade File Type)",
                    remediation="Dosyayı karantinaya alın, sandbox ortamında dinamik analize tabi tutun."
                )
                local_findings.append(finding)

        return local_findings

    def compute_system_health_score(self) -> Dict[str, Any]:
        """
        Tüm bulguları ağırlıklandırarak 0-100 arasında Sistem Sağlık Puanı
        ve genel Güvenlik Duruşu (Posture) derecelendirmesi üretir.
        """
        # Başlangıçta tam puan (100)
        base_score = 100

        # Zafiyet ciddiyetine göre puan kırılma tablosu
        deductions = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3
        }

        total_deduction = sum(deductions.get(f.severity, 0) for f in self.findings)
        final_score = max(0, base_score - total_deduction)

        # Duruş sınıflandırması
        if final_score >= 90:
            posture = "HEALTHY_BASELINE"
        elif final_score >= 70:
            posture = "ELEVATED_RISK"
        elif final_score >= 40:
            posture = "CRITICAL_ATTENTION_REQUIRED"
        else:
            posture = "COMPROMISED_ENVIRONMENT"

        return {
            "health_score": final_score,
            "posture": posture,
            "total_findings": len(self.findings),
            "severity_counts": {
                "CRITICAL": sum(1 for f in self.findings if f.severity == "CRITICAL"),
                "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
                "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "LOW": sum(1 for f in self.findings if f.severity == "LOW")
            }
        }

    def run_full_posture_assessment(self) -> Dict[str, Any]:
        """Tüm alt denetimleri sırayla koşturarak konsolide sistem durumu üretir."""
        self.findings = []

        # 1. Süreç Ağacı Denetimi
        self.findings.extend(self.audit_process_telemetry())

        # 2. Servis ve Başlangıç Denetimi
        self.findings.extend(self.audit_service_telemetry())

        # 3. Dosya Bütünlüğü Denetimi
        self.findings.extend(self.audit_file_integrity_telemetry())

        # 4. Sihirli Bayt ve Dosya Türü Denetimi
        self.findings.extend(self.audit_file_signature_telemetry())

        health = self.compute_system_health_score()

        return {
            "system_info": self.telemetry_data.get("system_info", {}),
            "health_metrics": health,
            "findings": [asdict(f) for f in self.findings]
        }

    def generate_executive_dashboard(self) -> str:
        """Yönetici ve analist seviyesinde konsolide ASCII durum panosu üretir."""
        lines: List[str] = []
        lines.append("=" * 85)
        lines.append("MİNİ PROJE 4: SİSTEM DURUM KONTROLÜ VE SAĞLIK DENETİM RAPORU (MP-04)")
        lines.append("=" * 85)

        sys_info = self.telemetry_data.get("system_info", {})
        lines.append(f"Hedef Makine       : {sys_info.get('hostname', 'N/A')}")
        lines.append(f"İşletim Sistemi    : {sys_info.get('os_version', 'N/A')}")
        lines.append(f"Tarama Kipi        : {sys_info.get('scan_mode', 'READ_ONLY_OBSERVER')} (Sıfır Yan Etki)")
        lines.append(f"Tarama Zamanı      : {sys_info.get('scan_timestamp', 'N/A')}")
        lines.append("-" * 85)

        health = self.compute_system_health_score()
        lines.append(f"GENEL SAĞLIK PUANI : {health['health_score']} / 100")
        lines.append(f"GÜVENLİK DURUŞU    : {health['posture']}")
        lines.append(f"Toplam Risk Bulgusu: {health['total_findings']}")
        lines.append(f"Ciddiyet Dağılımı  : CRITICAL={health['severity_counts']['CRITICAL']} | "
                     f"HIGH={health['severity_counts']['HIGH']} | "
                     f"MEDIUM={health['severity_counts']['MEDIUM']}")
        lines.append("=" * 85)

        if not self.findings:
            lines.append("SİSTEM SAĞLIKLI: Herhangi bir güvenlik zafiyeti veya anomali tespit edilmedi.")
        else:
            lines.append("ÖNCELİKLİ GÜVENLİK BULGULARI VE MÜDAHALE KILAVUZU:")
            for idx, f in enumerate(self.findings, 1):
                lines.append(f"\n[{idx:02d}] [{f.severity}] [{f.domain}] {f.target}")
                lines.append(f"     Zafiyet Türü : {f.vulnerability_type}")
                lines.append(f"     MITRE Kodu   : {f.mitre_technique}")
                lines.append(f"     Açıklama     : {f.description}")
                lines.append(f"     Aksiyon      : {f.remediation}")

        if self.corrupted_records:
            lines.append("\n" + "-" * 85)
            lines.append("REDDEDİLEN BOZUK VERİLER (NEGATİF KONTROL):")
            for idx, c in enumerate(self.corrupted_records, 1):
                lines.append(f"  ({idx}) Hata: {c['error']}")

        lines.append("=" * 85)
        return "\n".join(lines)


def main() -> None:
    """Komut satırı yürütücüsü."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    snapshot_path = os.path.join(base_dir, "ornek_veri", "system_telemetry_snapshot.json")

    auditor = SystemPostureAuditor()
    if os.path.exists(snapshot_path):
        auditor.load_telemetry(snapshot_path)
        auditor.run_full_posture_assessment()
        print(auditor.generate_executive_dashboard())
    else:
        print(f"Hata: Telemetri anlık görüntüsü bulunamadı: {snapshot_path}")


if __name__ == "__main__":
    main()
