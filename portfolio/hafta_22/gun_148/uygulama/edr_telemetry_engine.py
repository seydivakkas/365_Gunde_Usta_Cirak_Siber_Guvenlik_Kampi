"""
Gün 148: EDR, AV ve Uç Nokta Telemetri Güvenlik Motoru
======================================================
Bu modül; geleneksel Antivirüs (AV) imza ve statik dosya taraması ile modern
Uç Nokta Tespit ve Müdahale (EDR) davranışsal telemetri analizini, süreç soy
ağacı (Process Lineage), bellek enjeksiyonu, yetki yükseltme ve MITRE ATT&CK
korelasyonunu simüle eden endüstriyel sınıf bir güvenlik motorudur.

Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Özel Lisans — Tüm Hakları Saklıdır.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib
import json
import re


class EventType(str, Enum):
    """EDR sensörünün topladığı çekirdek ve kullanıcı alanı olay türleri."""
    PROCESS_CREATE = "PROCESS_CREATE"      # Sysmon Event ID 1 / Windows 4688
    FILE_WRITE = "FILE_WRITE"              # Sysmon Event ID 11
    NETWORK_CONNECT = "NETWORK_CONNECT"    # Sysmon Event ID 3
    REGISTRY_SET = "REGISTRY_SET"          # Sysmon Event ID 12/13
    MEMORY_ACCESS = "MEMORY_ACCESS"        # Sysmon Event ID 8 / 10 (Process Tampering / Injection)


class DetectionType(str, Enum):
    """Tespit motoru türü: Geleneksel AV (Statik) veya EDR (Davranışsal)."""
    AV_SIGNATURE = "AV_SIGNATURE"          # Statik imza / Hash / YARA kuralı
    EDR_BEHAVIOR = "EDR_BEHAVIOR"          # Davranışsal anomali / Süreç soy ağacı / Telemetri


class Severity(str, Enum):
    """Güvenlik uyarısı önem dereceleri."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResponseActionType(str, Enum):
    """EDR ajanının otonom veya manuel müdahale yetenekleri."""
    ALERT_ONLY = "ALERT_ONLY"              # Yalnızca alarm üret ve SOC'a ilet
    KILL_PROCESS = "KILL_PROCESS"          # Zararlı süreci anında sonlandır
    QUARANTINE_FILE = "QUARANTINE_FILE"    # Dosyayı karantinaya al
    ISOLATE_HOST = "ISOLATE_HOST"          # Uç noktayı ağdan izole et (Host Isolation)


@dataclass
class TelemetryEvent:
    """EDR sensöründen toplanan yapılandırılmış uç nokta telemetri olayı."""
    event_id: str
    timestamp: str
    event_type: EventType
    pid: int
    process_name: str
    parent_pid: int
    parent_name: str
    command_line: str
    user: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AVSignature:
    """Geleneksel antivirüs statik imza tanımı."""
    sig_id: str
    name: str
    sha256_hash: Optional[str] = None
    pattern_regex: Optional[str] = None
    description: str = ""
    severity: Severity = Severity.HIGH


@dataclass
class EDRBehaviorRule:
    """EDR davranışsal tespit ve MITRE ATT&CK korelasyon kuralı."""
    rule_id: str
    name: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    severity: Severity
    recommended_action: ResponseActionType


@dataclass
class EDRAlert:
    """Motor tarafından üretilen güvenlik uyarısı ve müdahale tavsiyesi."""
    alert_id: str
    timestamp: str
    detection_type: DetectionType
    rule_id: str
    title: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    culprit_pid: int
    process_name: str
    command_line: str
    details: str
    recommended_action: ResponseActionType


@dataclass
class EDRAuditSummary:
    """Kapsamlı EDR ve AV denetim sonuç özeti."""
    total_events_processed: int
    av_detections_count: int
    edr_detections_count: int
    total_alerts_count: int
    quarantined_files: List[str]
    killed_pids: List[int]
    isolated_hosts: bool
    mitre_coverage: List[str]
    security_score: float
    is_threat_contained: bool
    alerts: List[EDRAlert]


class EDRTelemetryEngine:
    """
    Kurumsal Uç Nokta Güvenlik Motoru (EDR, Antivirüs ve Telemetri Analizörü).
    
    Bu motor;
    1. Geleneksel Antivirüs (AV): Dosya hash'leri (SHA-256), bilinen zararlı
       yazılım imzaları ve EICAR test kalıplarını tarar.
    2. Uç Nokta Tespit ve Müdahale (EDR): Süreç soy ağacını (Parent-Child ilişkisi),
       bellek enjeksiyonlarını (Process Injection), yetki yükseltmeyi, LOLBAS
       suistimallerini ve komuta kontrol (C2) bağlantılarını analiz eder.
    3. MITRE ATT&CK Çerçevesiyle eşleşen alarmlar üretir ve otomatik müdahale
       (Process Kill, File Quarantine, Host Isolation) aksiyonlarını belirler.
    """

    def __init__(self):
        # Kayıtlı AV imzaları sözlüğü
        self.av_signatures: Dict[str, AVSignature] = {}
        # Kayıtlı EDR davranış kuralları sözlüğü
        self.behavior_rules: Dict[str, EDRBehaviorRule] = {}
        # Varsayılan temel kuralları yükle
        self._init_default_rules()

    def _init_default_rules(self) -> None:
        """Sektörel standartlardaki AV imzalarını ve EDR davranış kurallarını başlatır."""
        # Standart EICAR Antivirüs Test İmzası
        eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        eicar_hash = hashlib.sha256(eicar_str.encode("utf-8")).hexdigest()
        self.register_av_signature(AVSignature(
            sig_id="AV-SIG-001",
            name="EICAR.Standard.Antivirus.TestFile",
            sha256_hash=eicar_hash,
            pattern_regex=r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            description="Standart Antivirüs Doğrulama ve Test İmzası",
            severity=Severity.MEDIUM
        ))

        # Bilinen Mimikatz ve Cobalt Strike Hash İmzası Örneği
        self.register_av_signature(AVSignature(
            sig_id="AV-SIG-002",
            name="HackTool.Win64.Mimikatz.B",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            pattern_regex=r"(?i)sekurlsa::logonpasswords|lsadump::sam|privilege::debug",
            description="Mimikatz Bellek Parola Çalma Aracı İmzası",
            severity=Severity.CRITICAL
        ))

        # EDR Davranış Kuralı 1: Office Uygulamasının Betik Yorumlayıcı Başlatması (Phishing Macro)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-001",
            name="Office Uygulaması Komut Satırı/PowerShell Başlattı",
            mitre_tactic="Execution",
            mitre_technique="T1059.001 - Command and Scripting Interpreter: PowerShell",
            description="Word/Excel/PowerPoint süreçlerinin doğrudan powershell.exe veya cmd.exe başlatması tipik makro saldırısıdır.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.KILL_PROCESS
        ))

        # EDR Davranış Kuralı 2: Şifrelenmiş / Gizlenmiş PowerShell İndirme Kodu (Download Cradle)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-002",
            name="Şifrelenmiş veya Gizlenmiş PowerShell Download Cradle",
            mitre_tactic="Execution / Defense Evasion",
            mitre_technique="T1059.001 / T1027 - Obfuscated Files or Information",
            description="PowerShell'in Base64 kodlu (-enc/-encodedcommand) veya DownloadString/IEX ile dışarıdan kod çalıştırması.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.KILL_PROCESS
        ))

        # EDR Davranış Kuralı 3: LSASS Bellek Okuma / Döküm Alma (Credential Dumping)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-003",
            name="LSASS Bellek Erişim ve Kimlik Bilgisi Çalma Girişimi",
            mitre_tactic="Credential Access",
            mitre_technique="T1003.001 - OS Credential Dumping: LSASS Memory",
            description="Ayrıcalıksız veya yetkisiz bir sürecin lsass.exe sürecine PROCESS_VM_READ hakkıyla bağlanması.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.ISOLATE_HOST
        ))

        # EDR Davranış Kuralı 4: Süreç Enjeksiyonu (Process Injection / Hollowing)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-004",
            name="Çapraz Süreç Bellek Enjeksiyonu (Process Injection)",
            mitre_tactic="Defense Evasion / Privilege Escalation",
            mitre_technique="T1055 - Process Injection",
            description="Bir sürecin başka bir meşru sürecin belleğine WriteProcessMemory veya CreateRemoteThread ile kod enjekte etmesi.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.KILL_PROCESS
        ))

        # EDR Davranış Kuralı 5: Kayıt Defteri Kalıcılık Anahtarı Ekleme (Persistence)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-005",
            name="Kayıt Defteri Otomatik Başlatma (Run Key) Kalıcılığı",
            mitre_tactic="Persistence",
            mitre_technique="T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys",
            description="Sistemin açılışında otomatik çalışması için HKLM\\...\\CurrentVersion\\Run anahtarına kayıt eklenmesi.",
            severity=Severity.HIGH,
            recommended_action=ResponseActionType.ALERT_ONLY
        ))

        # EDR Davranış Kuralı 6: Şüpheli Komuta Kontrol (C2) Dış Ağ Bağlantısı
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-006",
            name="Şüpheli Dış Ağ Portuna Komuta Kontrol (C2) Bağlantısı",
            mitre_tactic="Command and Control",
            mitre_technique="T1071 - Application Layer Protocol",
            description="Web tarayıcısı olmayan süreçlerin şüpheli harici portlara (4444, 8888, 1337) TCP bağlantısı kurması.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.ISOLATE_HOST
        ))

        # EDR Davranış Kuralı 7: Güvenlik Aracını Durdurma / Savunmayı Bozma (Tampering)
        self.register_behavior_rule(EDRBehaviorRule(
            rule_id="EDR-RULE-007",
            name="Uç Nokta Güvenlik Servisini Durdurma / Bozma Girişimi",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1562.001 - Impair Defenses: Disable or Modify Tools",
            description="Antivirüs veya EDR servislerini (WinDefend, edrservice) kapatma veya sürücüyü kaldırma (fltmc) girişimi.",
            severity=Severity.CRITICAL,
            recommended_action=ResponseActionType.ISOLATE_HOST
        ))

    def register_av_signature(self, sig: AVSignature) -> None:
        """Sisteme statik antivirüs imzası kaydeder."""
        self.av_signatures[sig.sig_id] = sig

    def register_behavior_rule(self, rule: EDRBehaviorRule) -> None:
        """Sisteme EDR davranış kuralı kaydeder."""
        self.behavior_rules[rule.rule_id] = rule

    def scan_file_static(self, file_content: str, file_hash: str) -> Optional[AVSignature]:
        """Geleneksel AV mantığıyla dosya içeriğini ve hash değerini statik imzalara karşı tarar."""
        # 1. Hash karşılaştırması
        for sig in self.av_signatures.values():
            if sig.sha256_hash and sig.sha256_hash.lower() == file_hash.lower():
                return sig

        # 2. İçerik ve regex desen taraması (YARA benzeri)
        for sig in self.av_signatures.values():
            if sig.pattern_regex:
                if re.search(sig.pattern_regex, file_content):
                    return sig

        return None

    def analyze_event(self, event: TelemetryEvent) -> List[EDRAlert]:
        """Tek bir telemetri olayını davranışsal kurallara göre inceler ve gerekirse alarmlar üretir."""
        alerts: List[EDRAlert] = []
        now_ts = event.timestamp or datetime.now(timezone.utc).isoformat()
        cmd = event.command_line.lower()
        proc = event.process_name.lower()
        parent = event.parent_name.lower()

        # 1. KONTROL: Office makro süreci kontrolü (Word/Excel -> powershell / cmd)
        office_parents = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        script_children = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
        if any(op in parent for op in office_parents) and any(sc in proc for sc in script_children):
            rule = self.behavior_rules["EDR-RULE-001"]
            alerts.append(EDRAlert(
                alert_id=f"ALT-{event.event_id}-01",
                timestamp=now_ts,
                detection_type=DetectionType.EDR_BEHAVIOR,
                rule_id=rule.rule_id,
                title=rule.name,
                severity=rule.severity,
                mitre_tactic=rule.mitre_tactic,
                mitre_technique=rule.mitre_technique,
                culprit_pid=event.pid,
                process_name=event.process_name,
                command_line=event.command_line,
                details=f"Office uygulaması '{event.parent_name}' (PID: {event.parent_pid}) yetkisiz betik yorumlayıcısı '{event.process_name}' (PID: {event.pid}) başlattı.",
                recommended_action=rule.recommended_action
            ))

        # 2. KONTROL: Şifrelenmiş veya DownloadString içeren PowerShell
        if "powershell" in proc or "pwsh" in proc:
            suspicious_patterns = [
                r"-enc\b", r"-encodedcommand\b", r"downloadstring", r"downloadfile",
                r"iex\s*\(", r"invoke-expression", r"bitstransfer", r"webclient"
            ]
            if any(re.search(pat, cmd) for pat in suspicious_patterns):
                rule = self.behavior_rules["EDR-RULE-002"]
                alerts.append(EDRAlert(
                    alert_id=f"ALT-{event.event_id}-02",
                    timestamp=now_ts,
                    detection_type=DetectionType.EDR_BEHAVIOR,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    culprit_pid=event.pid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    details=f"PowerShell sürecinde şüpheli indirme ve kod gizleme (Obfuscation) kalıbı yakalandı: {event.command_line}",
                    recommended_action=rule.recommended_action
                ))

        # 3. KONTROL: LSASS Bellek Erişimi (Credential Dumping)
        if event.event_type == EventType.MEMORY_ACCESS:
            target_proc = event.details.get("target_process", "").lower()
            access_mask = event.details.get("access_mask", "")
            if "lsass.exe" in target_proc:
                rule = self.behavior_rules["EDR-RULE-003"]
                alerts.append(EDRAlert(
                    alert_id=f"ALT-{event.event_id}-03",
                    timestamp=now_ts,
                    detection_type=DetectionType.EDR_BEHAVIOR,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    culprit_pid=event.pid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    details=f"Süreç '{event.process_name}' (PID: {event.pid}) kritik 'lsass.exe' sürecinin belleğine erişmeye çalıştı (Erişim Maskesi: {access_mask}).",
                    recommended_action=rule.recommended_action
                ))

        # 4. KONTROL: Çapraz Süreç Bellek Enjeksiyonu
        if event.event_type == EventType.MEMORY_ACCESS:
            call_trace = event.details.get("call_trace", "").lower()
            if "createremotethread" in call_trace or "virtualallocex" in call_trace:
                rule = self.behavior_rules["EDR-RULE-004"]
                alerts.append(EDRAlert(
                    alert_id=f"ALT-{event.event_id}-04",
                    timestamp=now_ts,
                    detection_type=DetectionType.EDR_BEHAVIOR,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    culprit_pid=event.pid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    details=f"Çapraz süreç bellek enjeksiyonu tespit edildi. Çağrı izi: {event.details.get('call_trace')}",
                    recommended_action=rule.recommended_action
                ))

        # 5. KONTROL: Kayıt Defteri Run Key Kalıcılığı
        if event.event_type == EventType.REGISTRY_SET:
            reg_key = event.details.get("target_key", "").lower()
            if "currentversion\\run" in reg_key or "currentversion\\runonce" in reg_key:
                rule = self.behavior_rules["EDR-RULE-005"]
                alerts.append(EDRAlert(
                    alert_id=f"ALT-{event.event_id}-05",
                    timestamp=now_ts,
                    detection_type=DetectionType.EDR_BEHAVIOR,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    culprit_pid=event.pid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    details=f"Kayıt defterine kalıcılık anahtarı yazıldı: {event.details.get('target_key')} = {event.details.get('value_data')}",
                    recommended_action=rule.recommended_action
                ))

        # 6. KONTROL: Şüpheli Komuta Kontrol (C2) Port Bağlantısı
        if event.event_type == EventType.NETWORK_CONNECT:
            dest_port = event.details.get("dest_port", 0)
            dest_ip = event.details.get("dest_ip", "")
            suspicious_ports = [4444, 8888, 1337, 6667, 9001]
            browser_names = ["chrome.exe", "msedge.exe", "firefox.exe"]
            if dest_port in suspicious_ports and not any(b in proc for b in browser_names):
                rule = self.behavior_rules["EDR-RULE-006"]
                alerts.append(EDRAlert(
                    alert_id=f"ALT-{event.event_id}-06",
                    timestamp=now_ts,
                    detection_type=DetectionType.EDR_BEHAVIOR,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    culprit_pid=event.pid,
                    process_name=event.process_name,
                    command_line=event.command_line,
                    details=f"'{event.process_name}' süreci şüpheli C2 portuna ({dest_ip}:{dest_port}) giden TCP bağlantısı kurdu.",
                    recommended_action=rule.recommended_action
                ))

        # 7. KONTROL: Güvenlik Servisini Durdurma / Bozma (Defense Evasion)
        tamper_commands = ["net stop windefend", "sc stop windefend", "fltmc unload", "set-mppreference -disablerealtimemonitoring"]
        if any(tc in cmd for tc in tamper_commands):
            rule = self.behavior_rules["EDR-RULE-007"]
            alerts.append(EDRAlert(
                alert_id=f"ALT-{event.event_id}-07",
                timestamp=now_ts,
                detection_type=DetectionType.EDR_BEHAVIOR,
                rule_id=rule.rule_id,
                title=rule.name,
                severity=rule.severity,
                mitre_tactic=rule.mitre_tactic,
                mitre_technique=rule.mitre_technique,
                culprit_pid=event.pid,
                process_name=event.process_name,
                command_line=event.command_line,
                details=f"Güvenlik savunma mekanizmasını kapatma komutu yürütüldü: {event.command_line}",
                recommended_action=rule.recommended_action
            ))

        return alerts

    def process_telemetry_batch(
        self,
        events: List[TelemetryEvent],
        files_to_scan: Optional[List[Dict[str, str]]] = None
    ) -> EDRAuditSummary:
        """Toplu telemetri akışını ve dosya taramalarını işleyerek genel denetim raporu üretir."""
        all_alerts: List[EDRAlert] = []
        av_count = 0
        edr_count = 0
        quarantined_files: List[str] = []
        killed_pids: List[int] = []
        isolate_host = False
        mitre_techs: Set[str] = set()

        # 1. Statik Dosya / AV Taraması
        if files_to_scan:
            for f_item in files_to_scan:
                path = f_item.get("path", "")
                content = f_item.get("content", "")
                f_hash = f_item.get("hash", hashlib.sha256(content.encode()).hexdigest())
                av_match = self.scan_file_static(content, f_hash)
                if av_match:
                    av_count += 1
                    quarantined_files.append(path)
                    all_alerts.append(EDRAlert(
                        alert_id=f"ALT-AV-{len(all_alerts)+1}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        detection_type=DetectionType.AV_SIGNATURE,
                        rule_id=av_match.sig_id,
                        title=f"Statik AV İmzası Tespit Edildi: {av_match.name}",
                        severity=av_match.severity,
                        mitre_tactic="Malware / Initial Access",
                        mitre_technique="T1204 - User Execution: Malicious File",
                        culprit_pid=0,
                        process_name="N/A (Statik Dosya)",
                        command_line="",
                        details=f"Dosya '{path}' bilinen imza veya hash ile eşleşti ({av_match.name}). Karantinaya alındı.",
                        recommended_action=ResponseActionType.QUARANTINE_FILE
                    ))

        # 2. Dinamik EDR Telemetri Taraması
        for ev in events:
            ev_alerts = self.analyze_event(ev)
            for alert in ev_alerts:
                edr_count += 1
                all_alerts.append(alert)
                mitre_techs.add(alert.mitre_technique)

                # Müdahale aksiyonlarını topla
                if alert.recommended_action == ResponseActionType.KILL_PROCESS:
                    if alert.culprit_pid not in killed_pids and alert.culprit_pid > 0:
                        killed_pids.append(alert.culprit_pid)
                elif alert.recommended_action == ResponseActionType.ISOLATE_HOST:
                    isolate_host = True
                    if alert.culprit_pid not in killed_pids and alert.culprit_pid > 0:
                        killed_pids.append(alert.culprit_pid)

        # Güvenlik puanı hesaplaması: Tehdit yoksa 100 tam puan
        penalty = 0.0
        for al in all_alerts:
            if al.severity == Severity.CRITICAL:
                penalty += 25.0
            elif al.severity == Severity.HIGH:
                penalty += 15.0
            elif al.severity == Severity.MEDIUM:
                penalty += 10.0
            elif al.severity == Severity.LOW:
                penalty += 5.0
        calculated_score = max(0.0, min(100.0, 100.0 - penalty))

        return EDRAuditSummary(
            total_events_processed=len(events),
            av_detections_count=av_count,
            edr_detections_count=edr_count,
            total_alerts_count=len(all_alerts),
            quarantined_files=quarantined_files,
            killed_pids=killed_pids,
            isolated_hosts=isolate_host,
            mitre_coverage=sorted(list(mitre_techs)),
            security_score=calculated_score,
            is_threat_contained=(len(all_alerts) == 0 or (len(killed_pids) > 0 or isolate_host or len(quarantined_files) > 0)),
            alerts=all_alerts
        )

    def generate_response_powershell(self, summary: EDRAuditSummary) -> str:
        """Tespit edilen tehditleri anında durduran kurumsal PowerShell müdahale betiği üretir."""
        lines = [
            "# =====================================================================",
            "# GÜN 148: EDR OTOMATİK MÜDAHALE VE TEHDİT ENGELLEME BETİĞİ (POWERSHELL)",
            "# Bu betik; tespit edilen zararlı süreçleri sonlandırır, dosyaları karantinaya alır",
            "# ve gerekirse uç noktayı ağdan izole eder (Host Isolation).",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Tüm Hakları Saklıdır.",
            "# =====================================================================",
            "$ErrorActionPreference = 'Stop'",
            "Write-Host '[+] EDR Otomatik Müdahale Protokolü Başlatılıyor...' -ForegroundColor Cyan",
            ""
        ]

        if not summary.alerts:
            lines.append("Write-Host '[*] Temiz sistem. Aktif tehdit veya sonlandırılacak süreç bulunamadı.' -ForegroundColor Green")
            return "\n".join(lines)

        # Süreç sonlandırma (Process Kill)
        for pid in summary.killed_pids:
            lines.append(f"# Zararlı Süreç Sonlandırma (PID: {pid})")
            lines.append(f"try {{")
            lines.append(f"    Stop-Process -Id {pid} -Force")
            lines.append(f"    Write-Host '  [OK] PID {pid} süreci zorla sonlandırıldı (Kill).' -ForegroundColor Green")
            lines.append(f"}} catch {{")
            lines.append(f"    Write-Warning '  [BİLGİ] PID {pid} zaten durdurulmuş veya bulunamadı.'")
            lines.append(f"}}")
            lines.append("")

        # Dosya karantinaya alma
        for f_path in summary.quarantined_files:
            lines.append(f"# Dosya Karantinaya Alma: {f_path}")
            lines.append(f"try {{")
            lines.append(f"    $QuarantineDir = 'C:\\ProgramData\\EDR_Quarantine'")
            lines.append(f"    if (!(Test-Path $QuarantineDir)) {{ New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null }}")
            lines.append(f"    Move-Item -Path '{f_path}' -Destination $QuarantineDir -Force")
            lines.append(f"    Write-Host '  [OK] {f_path} karantina dizinine taşındı.' -ForegroundColor Green")
            lines.append(f"}} catch {{")
            lines.append(f"    Write-Warning '  [HATA] Dosya karantinaya alınamadı: $_'")
            lines.append(f"}}")
            lines.append("")

        # Ağ izolasyonu (Host Isolation)
        if summary.isolated_hosts:
            lines.append("# KRİTİK ALARM: Uç Nokta Ağ İzolasyonu (Host Isolation)")
            lines.append("Write-Host '[!] C2 veya Credential Dumping tespiti nedeniyle uç nokta ağdan izole ediliyor...' -ForegroundColor Red")
            lines.append("New-NetFirewallRule -DisplayName 'EDR-Host-Isolation-Outbound' -Direction Outbound -Action Block -Profile Any | Out-Null")
            lines.append("New-NetFirewallRule -DisplayName 'EDR-Host-Isolation-Inbound' -Direction Inbound -Action Block -Profile Any | Out-Null")
            lines.append("Write-Host '  [OK] Uç nokta ağdan başarıyla izole edildi (Yalnızca SOC yönetimi erişebilir).' -ForegroundColor Yellow")
            lines.append("")

        lines.append("Write-Host '[+] EDR müdahale aksiyonları tamamlandı.' -ForegroundColor Cyan")
        return "\n".join(lines)

    def generate_mitre_matrix_json(self) -> Dict[str, Any]:
        """EDR motorunun kapsadığı MITRE ATT&CK taktik ve tekniklerinin haritasını üretir."""
        return {
            "motor": "Enterprise EDR & AV Telemetry Correlation Engine",
            "cerceve": "MITRE ATT&CK v14 for Enterprise",
            "taktik_ve_teknikler": [
                {
                    "taktik": "Execution",
                    "teknik_id": "T1059.001",
                    "teknik_adi": "Command and Scripting Interpreter: PowerShell",
                    "telemetri_kaynagi": "Sysmon Event ID 1 (Process Creation) / Win 4688",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Defense Evasion",
                    "teknik_id": "T1027",
                    "teknik_adi": "Obfuscated Files or Information",
                    "telemetri_kaynagi": "Komut Satırı / Base64 Regex Analizi",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Credential Access",
                    "teknik_id": "T1003.001",
                    "teknik_adi": "OS Credential Dumping: LSASS Memory",
                    "telemetri_kaynagi": "Sysmon Event ID 10 (Process Access) / Kernel Callbacks",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Privilege Escalation",
                    "teknik_id": "T1055",
                    "teknik_adi": "Process Injection",
                    "telemetri_kaynagi": "Sysmon Event ID 8 (CreateRemoteThread) / ETW",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Persistence",
                    "teknik_id": "T1547.001",
                    "teknik_adi": "Boot or Logon Autostart Execution: Registry Run Keys",
                    "telemetri_kaynagi": "Sysmon Event ID 12/13 (Registry Event)",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Command and Control",
                    "teknik_id": "T1071",
                    "teknik_adi": "Application Layer Protocol",
                    "telemetri_kaynagi": "Sysmon Event ID 3 (Network Connection)",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Defense Evasion",
                    "teknik_id": "T1562.001",
                    "teknik_adi": "Impair Defenses: Disable or Modify Tools",
                    "telemetri_kaynagi": "Servis Yönetim Komutları / Sürücü İzleme",
                    "tespit_turu": "Davranışsal EDR"
                },
                {
                    "taktik": "Initial Access",
                    "teknik_id": "T1204",
                    "teknik_adi": "User Execution: Malicious File",
                    "telemetri_kaynagi": "Dosya Giriş / Çıkış ve Statik Hash / YARA Taraması",
                    "tespit_turu": "Geleneksel Antivirüs (AV)"
                }
            ]
        }
