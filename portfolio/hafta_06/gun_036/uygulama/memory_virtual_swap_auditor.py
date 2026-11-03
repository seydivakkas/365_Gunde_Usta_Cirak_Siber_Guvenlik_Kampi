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
Gün 36: Bellek, Sanal Bellek ve Swap Güvenlik Denetleyicisi
Bu modül; fiziksel RAM, sanal bellek (Virtual Memory), sayfalama (Paging) ve
takas alanını (Swap/Pagefile) inceleyerek; şifresiz swap sebebiyle kalıcı depoda
hassas veri kalıntısı (Data Remanence), bellek dökümü (Memory Scraping / LSASS Dumping)
ve bellek kilitleme (Memory Locking) zafiyetlerini analiz eder.
"""

# Dosya ve işletim sistemi yol operasyonları için os modülü
import os
# Sistem yapılandırmaları ve yürütme parametreleri için sys modülü
import sys
# JSON tabanlı telemetri ve rapor çıktısı için json modülü
import json
# Regex kalıp eşleştirme ve hassas veri tespiti için re modülü
import re
# Tip ipuçları ve statik doğrulama için typing modülü
from typing import Dict, List, Any, Tuple, Optional
# Veri yapılarını modellemek için dataclass yapısı
from dataclasses import dataclass, field, asdict


@dataclass
class MemorySecurityFinding:
    """Bellek ve swap denetiminde tespit edilen bir güvenlik anomalisini modelleyen sınıf."""
    # İlgili denetim alanı (SWAP_SECURITY, PROCESS_MEMORY, DATA_REMANENCE, HARDENING)
    domain: str
    # Zafiyete konu olan hedef (Swap Alanı, Süreç Adı, PID veya Dosya)
    target: str
    # Güvenlik önem derecesi (CRITICAL, HIGH, MEDIUM, LOW)
    severity: str
    # Zafiyet türü (UNENCRYPTED_SWAP, SENSITIVE_KEY_PAGING, MEMORY_SCRAPING, REMANENCE_LEAK)
    vulnerability_type: str
    # Zafiyetin teknik ve operasyonel açıklaması
    description: str
    # MITRE ATT&CK teknik referansı (Örn: T1003.001, T1005)
    mitre_technique: str
    # Güvenlik açığını kapatmak için önerilen eylem adımı
    remediation: str


class MemoryVirtualSwapAuditor:
    """
    Fiziksel bellek, sanal bellek adresleme ve swap alanını güvenlik
    standartlarına göre denetleyen ana analiz sınıfı.
    """

    def __init__(self) -> None:
        """Denetleyiciyi sıfır telemetri ve temiz bulgu listesiyle başlatır."""
        # Bellek telemetri verisi sözlüğü
        self.telemetry: Dict[str, Any] = {}
        # Saptanan güvenlik bulguları listesi
        self.findings: List[MemorySecurityFinding] = []
        # Reddedilen bozuk telemetri kayıtları günlüğü
        self.corrupted_records: List[Dict[str, Any]] = []

    def validate_memory_schema(self, data: Any) -> Tuple[bool, str]:
        """
        Gelen telemetri verisinin veri tiplerini ve pozitif değer sınırlarını doğrular.
        Negatif kontrollerin başarısı için zorunlu şema kapısıdır.
        """
        # Verinin bir sözlük olduğunu sınıyoruz
        if not isinstance(data, dict):
            return False, "KAYIT_SOZLUK_DEGIL: Telemetri verisi JSON nesnesi olmalidir."

        # Zorunlu ana bölümlerin varlığını sınıyoruz
        for section in ["system_memory", "processes"]:
            if section not in data:
                return False, f"EKSIK_BOLUM: '{section}' bolumu zorunludur."

        sys_mem = data["system_memory"]
        if not isinstance(sys_mem, dict):
            return False, "GECERSIZ_BOLUM_TIPI: 'system_memory' bir sozluk olmalidir."

        if not isinstance(data["processes"], list):
            return False, "GECERSIZ_BOLUM_TIPI: 'processes' bir liste olmalidir."

        # Sayısal bellek metriklerinin pozitif değer taşıdığını sınıyoruz
        numeric_fields = ["total_ram_mb", "used_ram_mb", "free_ram_mb", "total_swap_mb", "used_swap_mb", "free_swap_mb"]
        for field in numeric_fields:
            if field in sys_mem:
                val = sys_mem[field]
                # Sayısal tip denetimi
                if not isinstance(val, (int, float)):
                    return False, f"GECERSIZ_SAYISAL_DEGER: '{field}' sayisal bir deger olmalidir."
                # Negatif değer denetimi
                if val < 0:
                    return False, f"NEGATIF_DEGER: '{field}' negatif olamaz ({val})."

        return True, "GECERLI"

    def load_memory_telemetry(self, file_path: str) -> bool:
        """JSON formatındaki bellek telemetri dosyasını doğrular ve yükler."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Bellek telemetri dosyasi bulunamadi: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        is_valid, reason = self.validate_memory_schema(raw)
        if not is_valid:
            self.corrupted_records.append({"file": file_path, "error": reason})
            return False

        self.telemetry = raw
        return True

    def audit_swap_security(self) -> List[MemorySecurityFinding]:
        """
        Takas alanının (Swap/Pagefile) şifrelenme durumunu ve artık veri
        kalıntısı (Data Remanence) risklerini denetler.
        """
        local_findings: List[MemorySecurityFinding] = []
        sys_mem = self.telemetry.get("system_memory", {})

        is_swap_encrypted = bool(sys_mem.get("swap_encrypted", False))
        clear_on_shutdown = bool(sys_mem.get("clear_pagefile_at_shutdown", False))
        total_swap = sys_mem.get("total_swap_mb", 0)
        used_swap = sys_mem.get("used_swap_mb", 0)

        # 1. Şifresiz Swap Alanı Tespiti (Data Remanence Riski)
        if total_swap > 0 and not is_swap_encrypted:
            finding = MemorySecurityFinding(
                domain="SWAP_SECURITY",
                target="Swap Space / Pagefile",
                severity="HIGH",
                vulnerability_type="UNENCRYPTED_SWAP",
                description=(
                    f"Sistem takas alanı ({total_swap} MB) şifrelenmemiştir! RAM üzerindeki sayfalar "
                    f"diske taşındığında şifresiz olarak kalıcı depoya yazılır. Çevrimdışı disk analizi "
                    f"veya adli bellek incelemesiyle hassas veriler (parolalar, anahtarlar) okunabilir."
                ),
                mitre_technique="T1005 (Data from Local System / Data Remanence)",
                remediation="Linux'ta dm-crypt/cryptswap, Windows'ta ise BitLocker ve Pagefile şifrelemeyi devreye alınız."
            )
            local_findings.append(finding)

        # 2. Kapanışta Sayfa Dosyasının Temizlenmemesi (Windows Pagefile)
        if not clear_on_shutdown:
            finding = MemorySecurityFinding(
                domain="SWAP_SECURITY",
                target="ClearPageFileAtShutdown",
                severity="MEDIUM",
                vulnerability_type="PAGEFILE_NOT_SANITIZED",
                description=(
                    "İşletim sistemi kapatılırken sayfa dosyasını sıfırlama (ClearPageFileAtShutdown) "
                    "devre dışıdır. Makine kapalıyken diskten bellek kalıntıları elde edilebilir."
                ),
                mitre_technique="T1005 (Data Remanence)",
                remediation="Kayıt defterinde 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown' değerini 1 yapınız."
            )
            local_findings.append(finding)

        # 3. Aşırı Swap Kullanımı (Memory Thrashing / DoS Riski)
        if total_swap > 0 and (used_swap / total_swap) >= 0.70:
            finding = MemorySecurityFinding(
                domain="SWAP_SECURITY",
                target="Swap Utilization",
                severity="MEDIUM",
                vulnerability_type="HIGH_SWAP_USAGE",
                description=(
                    f"Swap kullanım oranı kritik seviyededir ({used_swap}/{total_swap} MB - %{(used_swap/total_swap)*100:.1f}). "
                    f"Sistem bellek baskısı altında olup disk I/O kilitlenmelerine ve performans çöküşüne (Thrashing) açıktır."
                ),
                mitre_technique="T1499 (Endpoint Denial of Service)",
                remediation="Fiziksel RAM kapasitesini artırın veya bellek sızıntısı (memory leak) yapan süreçleri izole ediniz."
            )
            local_findings.append(finding)

        return local_findings

    def audit_process_memory_anomalies(self) -> List[MemorySecurityFinding]:
        """
        Süreç bellek alanı anomalilerini, bellek kazıma (Memory Scraping)
        ve hassas veri kilitleme (mlock) eksikliklerini inceler.
        """
        local_findings: List[MemorySecurityFinding] = []
        processes = self.telemetry.get("processes", [])

        # Bellek dökümü ve kazıma komut satırı kalıpları
        scraping_patterns = ["--dump-lsass", "procdump", "minidump", "mimikatz", "dumpert"]

        for proc in processes:
            if not isinstance(proc, dict):
                continue

            pid = proc.get("pid")
            name = str(proc.get("name", ""))
            cmd = str(proc.get("command_line", "")).lower()
            mem_locked = bool(proc.get("memory_locked", False))
            page_faults = proc.get("page_faults", 0)

            # 1. Bellek Kazıma / LSASS Bellek Dökümü Girişimi (CRITICAL)
            if any(pattern in cmd for pattern in scraping_patterns):
                finding = MemorySecurityFinding(
                    domain="PROCESS_MEMORY",
                    target=f"PID {pid} ({name})",
                    severity="CRITICAL",
                    vulnerability_type="MEMORY_SCRAPING_ATTEMPT",
                    description=(
                        f"Kritik saldırı tespiti: Süreç komut satırında LSASS bellek dökümü ve kimlik "
                        f"bilgisi çalma kalıpları saptandı! Komut: '{proc.get('command_line')}'."
                    ),
                    mitre_technique="T1003.001 (OS Credential Dumping: LSASS Memory)",
                    remediation="Süreci derhal sonlandırın, LSASS için RunAsPPL ve Credential Guard korumasını devreye alınız."
                )
                local_findings.append(finding)

            # 2. Hassas Süreçlerin Bellek Kilitlememesi (mlock Eksikliği)
            if "crypto" in name.lower() or "wallet" in name.lower():
                if not mem_locked:
                    finding = MemorySecurityFinding(
                        domain="PROCESS_MEMORY",
                        target=f"PID {pid} ({name})",
                        severity="HIGH",
                        vulnerability_type="UNLOCKED_SENSITIVE_MEMORY",
                        description=(
                            f"Kriptografik özel anahtar işleyen '{name}' süreci bellek sayfalarını kilitlememiştir "
                            f"(mlock / VirtualLock = False). Bu anahtarlar swap dosyasına yazılarak kalıcı diske sızabilir."
                        ),
                        mitre_technique="T1005 (Data from Local System)",
                        remediation="Yazılım kodunda mlock() veya VirtualLock() API'sini kullanarak hassas bellek sayfalarını swap dışı bırakınız."
                    )
                    local_findings.append(finding)

            # 3. Aşırı Sayfa Hatası (Page Fault Anomalisi)
            if page_faults > 50000:
                finding = MemorySecurityFinding(
                    domain="PROCESS_MEMORY",
                    target=f"PID {pid} ({name})",
                    severity="LOW",
                    vulnerability_type="HIGH_PAGE_FAULTS",
                    description=(
                        f"Süreç olağan dışı sayıda ({page_faults}) sayfa hatası (Page Fault) üretmektedir. "
                        f"Bu durum bellek tarama faaliyeti ya da bellek sızıntısına işaret edebilir."
                    ),
                    mitre_technique="T1057 (Process Discovery)",
                    remediation="Sürecin bellek erişim modellerini profil çıkarıcı (profiler) araçlarla analiz ediniz."
                )
                local_findings.append(finding)

        return local_findings

    def audit_swap_data_leakage(self) -> List[MemorySecurityFinding]:
        """
        Swap dosyası içerisindeki artık verilerde sızan şifresiz hassas
        belirteçleri (API Key, Bearer Token, Private Key) tespit eder.
        """
        local_findings: List[MemorySecurityFinding] = []
        artifacts = self.telemetry.get("swap_artifacts", {})
        leaked_strings = artifacts.get("leaked_string_patterns", [])

        if leaked_strings:
            finding = MemorySecurityFinding(
                domain="DATA_REMANENCE",
                target=artifacts.get("file_path", "/var/swapfile"),
                severity="CRITICAL",
                vulnerability_type="CREDENTIAL_REMANENCE_LEAK",
                description=(
                    f"Takas dosyasında {len(leaked_strings)} adet şifresiz hassas kimlik bilgisi (API anahtarı, "
                    f"JWT Token, Veritabanı Parolası) kalıntısı saptandı! Örnekler: {', '.join(leaked_strings[:2])}..."
                ),
                mitre_technique="T1552.001 (Unsecured Credentials: Credentials In Files)",
                remediation="Takas dosyasını güvenli şekilde sıfırlayın (shred/sfill), sızan tüm anahtarları ve parolaları derhal geçersiz kılıp döndürünüz (rotate)."
            )
            local_findings.append(finding)

        return local_findings

    def calculate_memory_risk_score(self) -> Dict[str, Any]:
        """Tüm bulguları ağırlıklandırarak 0-100 arasında Sistem Bellek Risk Puanı hesaplar."""
        weights = {
            "CRITICAL": 35,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5
        }

        total_risk = sum(weights.get(f.severity, 0) for f in self.findings)
        final_risk = min(100, total_risk)

        if final_risk >= 80:
            posture = "CRITICAL_MEMORY_EXPOSURE"
        elif final_risk >= 50:
            posture = "ELEVATED_LEAK_RISK"
        elif final_risk >= 20:
            posture = "MODERATE_RISK"
        elif final_risk > 0:
            posture = "LOW_RISK"
        else:
            posture = "SECURE_MEMORY_BASELINE"

        return {
            "risk_score": final_risk,
            "health_score": 100 - final_risk,
            "posture": posture,
            "total_findings": len(self.findings),
            "severity_counts": {
                "CRITICAL": sum(1 for f in self.findings if f.severity == "CRITICAL"),
                "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
                "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "LOW": sum(1 for f in self.findings if f.severity == "LOW")
            }
        }

    def run_comprehensive_memory_audit(self) -> Dict[str, Any]:
        """Tüm bellek ve swap denetimlerini koşturarak konsolide rapor üretir."""
        self.findings = []

        # 1. Swap güvenliği denetimi
        self.findings.extend(self.audit_swap_security())

        # 2. Süreç bellek anomalileri denetimi
        self.findings.extend(self.audit_process_memory_anomalies())

        # 3. Swap içi hassas veri kalıntısı denetimi
        self.findings.extend(self.audit_swap_data_leakage())

        # Risk metrikleri
        metrics = self.calculate_memory_risk_score()

        return {
            "system_memory": self.telemetry.get("system_memory", {}),
            "metrics": metrics,
            "findings": [asdict(f) for f in self.findings]
        }

    def generate_ascii_report(self) -> str:
        """Denetim sonuçlarını temiz ASCII grafik ve tablolarla raporlar."""
        lines: List[str] = []
        lines.append("=" * 85)
        lines.append("GÜN 36: BELLEK, SANAL BELLEK VE SWAP GÜVENLİK DENETİM RAPORU")
        lines.append("=" * 85)

        sys_mem = self.telemetry.get("system_memory", {})
        ram_total = sys_mem.get("total_ram_mb", 0)
        ram_used = sys_mem.get("used_ram_mb", 0)
        swap_total = sys_mem.get("total_swap_mb", 0)
        swap_used = sys_mem.get("used_swap_mb", 0)
        swap_enc = "EVET" if sys_mem.get("swap_encrypted") else "HAYIR (RİSK!)"

        lines.append(f"Hedef Makine       : {sys_mem.get('hostname', 'N/A')}")
        lines.append(f"Fiziksel RAM       : {ram_used} MB / {ram_total} MB (%{(ram_used/ram_total*100) if ram_total else 0:.1f} Dolu)")
        lines.append(f"Takas Alanı (Swap) : {swap_used} MB / {swap_total} MB (%{(swap_used/swap_total*100) if swap_total else 0:.1f} Dolu)")
        lines.append(f"Swap Şifrelenmiş mi: {swap_enc}")
        lines.append(f"ASLR Koruması      : {'AÇIK' if sys_mem.get('aslr_enabled') else 'KAPALI'}")
        lines.append(f"DEP / NX Koruması  : {'AÇIK' if sys_mem.get('dep_nx_enabled') else 'KAPALI'}")
        lines.append("-" * 85)

        metrics = self.calculate_memory_risk_score()
        lines.append(f"BELLEK RİSK PUANI  : {metrics['risk_score']} / 100")
        lines.append(f"GÜVENLİK DURUŞU    : {metrics['posture']}")
        lines.append(f"Toplam Risk Bulgusu: {metrics['total_findings']}")
        lines.append(f"Ciddiyet Dağılımı  : CRITICAL={metrics['severity_counts']['CRITICAL']} | "
                     f"HIGH={metrics['severity_counts']['HIGH']} | "
                     f"MEDIUM={metrics['severity_counts']['MEDIUM']}")
        lines.append("=" * 85)

        if not self.findings:
            lines.append("TEBRİKLER: Bellek ve swap yapılandırmasında herhangi bir güvenlik riski bulunamadı.")
        else:
            lines.append("AYRINTILI GÜVENLİK BULGULARI VE İYİLEŞTİRME KILAVUZU:")
            for idx, f in enumerate(self.findings, 1):
                lines.append(f"\n[{idx:02d}] [{f.severity}] [{f.domain}] {f.target}")
                lines.append(f"     Zafiyet Türü : {f.vulnerability_type}")
                lines.append(f"     MITRE Kodu   : {f.mitre_technique}")
                lines.append(f"     Açıklama     : {f.description}")
                lines.append(f"     Aksiyon      : {f.remediation}")

        if self.corrupted_records:
            lines.append("\n" + "-" * 85)
            lines.append("REDDEDİLEN BOZUK TELEMETRİ GİRDİLERİ (NEGATİF KONTROL):")
            for idx, c in enumerate(self.corrupted_records, 1):
                lines.append(f"  [{idx}] Hata: {c['error']}")

        lines.append("=" * 85)
        return "\n".join(lines)


def main() -> None:
    """Komut satırı yürütme fonksiyonu."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    snapshot_path = os.path.join(base_dir, "ornek_veri", "sample_memory_telemetry.json")

    auditor = MemoryVirtualSwapAuditor()
    if os.path.exists(snapshot_path):
        auditor.load_memory_telemetry(snapshot_path)
        auditor.run_comprehensive_memory_audit()
        print(auditor.generate_ascii_report())
    else:
        print(f"Hata: Bellek telemetri dosyası bulunamadı: {snapshot_path}")


if __name__ == "__main__":
    main()
