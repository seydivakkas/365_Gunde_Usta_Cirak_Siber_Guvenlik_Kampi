# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G085: PowerShell Nesne Boru Hattı Güvenlik ve Tehdit Avcılığı Motoru.
Bu modül; PowerShell nesne boru hatlarında (object pipeline) veri akışı güvenliğini,
süreç (process) ve ağ (network) nesnelerinin adli analizini, Invoke-Expression (IEX)
enjeksiyonlarını, gizlenmiş Base64 komutlarını ve unquoted service path zafiyetlerini denetler.
"""

from collections import Counter, defaultdict  # Istatistik ve grup sayimlari icin collections ice aktarilir
from dataclasses import dataclass, field  # Veri modelleri olusturmak icin dataclass ice aktarilir
from enum import Enum  # Sabit durumlari tanimlamak icin Enum ice aktarilir
import ipaddress  # IP adreslerinin guvenli dogrulamasi icin ipaddress modulu ice aktarilir
import json  # JSON nesnelerini ayrastirmak icin json modulu ice aktarilir
from pathlib import Path  # Dosya sistemi islemleri icin Path modulu ice aktarilir
import re  # Duzenli ifadelerle desen esleme icin re modulu ice aktarilir
from typing import Any, Dict, List, Optional, Set, Tuple  # Tip guvenligi icin typing modulu ice aktarilir


class PipelineThreatSeverity(Enum):
    """Boru hattinda tespit edilen tehdidin ciddiyet seviyesi."""
    LOW = "LOW"  # Dusuk: kod kalitesi ve hafif anomali
    MEDIUM = "MEDIUM"  # Orta: supheli parametre veya zayif yapilandirma
    HIGH = "HIGH"  # Yuksek: unquoted yol veya zararli tarayici aktivitesi
    CRITICAL = "CRITICAL"  # Kritik: IEX enjeksiyonu, mimikatz veya kaba kuvvet


class PowerShellSecurityException(Exception):
    """PowerShell guvenlik motoru genel temel istisna sinifi."""
    pass  # Temel govde bos birakilir


class DangerousPipelineInvocationException(PowerShellSecurityException):
    """Boru hattinda Invoke-Expression (IEX) gibi tehlikeli calistirmalarda firlatilir (CWE-95)."""
    pass  # IEX istisna govdesi


class ObfuscatedPayloadDetectedException(PowerShellSecurityException):
    """Boru hattinda gizlenmis Base64 veya sifrelenmis komutlar tespit edildiginde firlatilir (CWE-116)."""
    pass  # Base64 tespit istisna govdesi


class UnquotedServicePathException(PowerShellSecurityException):
    """Tirnaksiz ve bosluk iceren calistirilabilir servis yolu tespitinde firlatilir (CWE-428)."""
    pass  # Unquoted path istisna govdesi


class DownloadCradleDetectedException(PowerShellSecurityException):
    """Ag uzerinden kod indirip dogrudan boru hattinda calistirma tespitinde firlatilir (CWE-829)."""
    pass  # Download cradle istisna govdesi


class PipelineObjectLimitExceededException(PowerShellSecurityException):
    """Boru hattindaki nesne sayisi guvenlik limitini astiginda firlatilir (CWE-400 DoS)."""
    pass  # DoS nesne limiti istisnasi


class NullByteForbiddenException(PowerShellSecurityException):
    """Boru hatti metninde veya nesne ozelliklerinde null-byte (0x00) tespitinde firlatilir (CWE-158)."""
    pass  # Null byte istisna govdesi


class AnomalousProcessLineageException(PowerShellSecurityException):
    """Ofis veya tarayici gibi uygunsuz ebeveyn surecler PowerShell baslattiginda firlatilir (CWE-250)."""
    pass  # Supheli ebeveyn-cocuk istisnasi


class MalformedPipelineSyntaxException(PowerShellSecurityException):
    """Bozuk veya gecersiz boru hatti sozdizimi (bos pipe, eksik parantez) tespitinde firlatilir (CWE-20)."""
    pass  # Bozuk sozdizimi istisnasi


class InvalidPipelineSocketException(PowerShellSecurityException):
    """Ag boru hatti nesnesinde gecersiz veya bozuk IP adresi tespitinde firlatilir (CWE-20)."""
    pass  # Gecersiz soket istisnasi


@dataclass
class ProcessSecurityArtifact:
    """PowerShell Get-Process cmdlet ciktisini modelleyen guvenlik nesnesi."""
    pid: int  # Surec kimlik numarasi (Process ID)
    name: str  # Surec calistirilabilir adi
    path: str  # Calistirilabilir dosyanin diskteki tam yolu
    cpu: float  # Toplam CPU tuketimi
    working_set_mb: float  # Bellek tuketimi (MB cinsinden)
    command_line: str  # Sureci baslatan komut satiri parametreleri
    parent_pid: int = 0  # Ebeveyn surec kimlik numarasi
    parent_name: str = ""  # Ebeveyn surec adi
    company: str = ""  # Dosyanin uretici firma bilgisi
    signed: bool = False  # Dijital sertifika imzasi gecerli mi
    is_suspicious: bool = False  # Tehdit avciligi sonucu supheli mi
    flags: List[str] = field(default_factory=list)  # Guvenlik bayraklari listesi


@dataclass
class NetworkSocketArtifact:
    """PowerShell Get-NetTCPConnection ciktisini modelleyen ag soket nesnesi."""
    local_addr: str  # Yerel IP adresi
    local_port: int  # Yerel dinleme / iletisim portu
    remote_addr: str  # Uzak IP adresi
    remote_port: int  # Uzak hedef portu
    state: str  # Soket durumu (Listen, Established vb.)
    owning_pid: int  # Soketi acan surecin kimlik numarasi
    is_suspicious: bool = False  # Supheli port veya yetkisiz dinleme bayragi


@dataclass
class PipelineThreatFinding:
    """Boru hatti denetimi sirasinda tespit edilen tekil guvenlik ihlali."""
    finding_id: str  # Benzersiz bulgu kimligi
    rule_name: str  # Ihlal edilen kuralin tanimi
    severity: PipelineThreatSeverity  # Tehdit ciddiyet derecesi
    cwe_id: str  # Ilgili CWE / MITRE ATT&CK numarasi
    details: str  # Olayin teknik aciklamasi
    code_snippet: str = ""  # Ihlale neden olan kod parcacigi


@dataclass
class PipelineAuditReport:
    """PowerShell nesne boru hatti denetim motorunun urettigi nihai rapor."""
    total_objects_processed: int = 0  # Islenen toplam nesne adedi
    total_threats: int = 0  # Uretilen toplam guvenlik uyarisi
    findings: List[PipelineThreatFinding] = field(default_factory=list)  # Tum guvenlik bulgulari
    suspicious_processes: List[ProcessSecurityArtifact] = field(default_factory=list)  # Supheli surecler
    suspicious_sockets: List[NetworkSocketArtifact] = field(default_factory=list)  # Supheli ag soketleri
    pipeline_safe: bool = True  # Boru hattinin genel guvenlik onayi


class PipelineSyntaxAuditor:
    """
    PowerShell betiklerini ve boru hatti komutlarini statik olarak denetleyen bilesen.
    IEX, Base64 gizleme, Download Cradle ve Unquoted Service Path zafiyetlerini arar.
    """

    IEX_PATTERN = re.compile(r"\|\s*(?:Invoke-Expression|iex)\b", re.IGNORECASE)  # IEX pipe regexi
    BASE64_PATTERN = re.compile(r"(?:-EncodedCommand|-enc|-e)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)  # Encoded
    FROM_BASE64_PATTERN = re.compile(r"\[System\.Convert\]::FromBase64String", re.IGNORECASE)  # FromBase64
    DOWNLOAD_CRADLE_PATTERN = re.compile(r"(?:Net\.WebClient|Invoke-WebRequest|iwr|curl).*(?:DownloadString|DownloadFile)", re.IGNORECASE)
    UNQUOTED_PATH_PATTERN = re.compile(r"^[A-Za-z]:\\[^\"']*\s+[^\"']*\.(?:exe|bat|cmd)", re.IGNORECASE)

    @classmethod
    def audit_script_text(cls, script_text: str, strict: bool = False) -> List[PipelineThreatFinding]:
        """PowerShell betik metnini guvenlik kurallarina gore inceler ve bulgulari dondurur."""
        if "\x00" in script_text:  # Null byte kontrolu yapilir (CWE-158 onlemi)
            raise NullByteForbiddenException("PowerShell betiginde zararli null-byte (0x00) tespit edildi.")

        findings: List[PipelineThreatFinding] = []  # Bulgular listesi baslatilir

        # 1. Bozuk boru hatti sozdizimi denetimi (CWE-20)
        cls._verify_pipeline_syntax(script_text)  # Sozdizim kontrol fonksiyonu cagrilir

        # 2. Download Cradle (Agdan indirip boru hattinda calistirma) denetimi (CWE-829)
        if cls.DOWNLOAD_CRADLE_PATTERN.search(script_text) and ("iex" in script_text.lower() or "invoke-expression" in script_text.lower()):
            finding = PipelineThreatFinding(
                finding_id=f"FIND-CRADLE-{len(findings)+1:03d}",
                rule_name="DOWNLOAD_CRADLE_DETECTED",
                severity=PipelineThreatSeverity.CRITICAL,
                cwe_id="CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
                details="Ag uzerinden WebClient ile harici kod indirip boru hattinda calistiran download cradle tespit edildi.",
                code_snippet=script_text.strip()[:100]
            )  # Bulgu uretilir
            findings.append(finding)  # Listeye eklenir
            if strict:  # Kati modda istisna firlatilir
                raise DownloadCradleDetectedException(finding.details)

        # 3. Invoke-Expression (IEX) boru hatti enjeksiyonu denetimi (CWE-95)
        if cls.IEX_PATTERN.search(script_text):  # Eger boru hattinda IEX varsa
            finding = PipelineThreatFinding(
                finding_id=f"FIND-IEX-{len(findings)+1:03d}",
                rule_name="DANGEROUS_PIPELINE_IEX_INVOCATION",
                severity=PipelineThreatSeverity.CRITICAL,
                cwe_id="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                details="Boru hattina gelen dinamik veri dogrudan Invoke-Expression (IEX) uzerinden calistirilmaktadir.",
                code_snippet=script_text.strip()[:100]  # Kanit kod parcasi
            )  # Bulgu nesnesi olusturulur
            findings.append(finding)  # Listeye eklenir
            if strict:  # Kati modda istisna firlatilir
                raise DangerousPipelineInvocationException(finding.details)

        # 4. Gizlenmis Base64 Payload Denetimi (CWE-116)
        if cls.BASE64_PATTERN.search(script_text) or cls.FROM_BASE64_PATTERN.search(script_text):
            finding = PipelineThreatFinding(
                finding_id=f"FIND-B64-{len(findings)+1:03d}",
                rule_name="OBFUSCATED_BASE64_PAYLOAD",
                severity=PipelineThreatSeverity.HIGH,
                cwe_id="CWE-116: Obfuscated EncodedCommand Execution in Pipeline",
                details="Boru hatti parametresinde gizlenmis Base64 calistirma anahtari (-EncodedCommand) tespit edildi.",
                code_snippet=script_text.strip()[:100]
            )  # Bulgu olusturulur
            findings.append(finding)  # Listeye eklenir
            if strict:  # Kati modda istisna firlatilir
                raise ObfuscatedPayloadDetectedException(finding.details)

        # 5. Unquoted Service Path Denetimi (CWE-428)
        if cls.UNQUOTED_PATH_PATTERN.search(script_text.strip()):
            finding = PipelineThreatFinding(
                finding_id=f"FIND-UNQUOTED-{len(findings)+1:03d}",
                rule_name="UNQUOTED_SERVICE_PATH",
                severity=PipelineThreatSeverity.HIGH,
                cwe_id="CWE-428: Unquoted Search Path or Element",
                details="Bosluk iceren servis calistirma yolu cift tirnak icine alinmamis (ayricalik yukseltme riski).",
                code_snippet=script_text.strip()[:100]
            )  # Bulgu olusturulur
            findings.append(finding)  # Listeye eklenir
            if strict:  # Kati modda istisna firlatilir
                raise UnquotedServicePathException(finding.details)

        return findings  # Tespit edilen tum bulgular dondurulur

    @staticmethod
    def _verify_pipeline_syntax(script_text: str) -> None:
        """Boru hatti sozdiziminin yapisal gecerliligini denetler."""
        temiz = script_text.strip()  # Bosluklar temizlenir
        if "||" in temiz or "| |" in temiz:  # Ardisik bos pipe operatorleri kontrol edilir
            raise MalformedPipelineSyntaxException("Gecersiz boru hatti sozdizimi: Bos boru hatti segmenti tespit edildi.")
        
        satirlar = temiz.splitlines()  # Satirlar ayrilir
        for satir in satirlar:  # Her satir taranir
            satir = satir.strip()  # Bosluklar atilir
            # Eger satir tek basina '|' ile bitiyor ve baska satir yoksa bozuktur
            if satir.endswith("|") and len(satirlar) == 1:  # Tek satirlik betikte boru havada kalmissa
                raise MalformedPipelineSyntaxException("Boru hatti operatoru (|) sonrasinda hedef cmdlet bulunamadi.")


class ProcessPipelineHunter:
    """
    Boru hattindan akan Process (Süreç) nesnelerini tehdit avcılığı kurallarına göre denetler.
    LOLBins, anormal ebeveyn-çocuk ilişkileri ve imzasız zararlıları yakalar.
    """

    KNOWN_MALICIOUS_NAMES: Set[str] = {
        "mimikatz", "rubeus", "bloodhound", "chisel", "nc", "netcat", "procdump", "cobaltstrike"
    }  # Bilinen saldiri araclari isim listesi

    ANOMALOUS_PARENTS: Dict[str, Set[str]] = {
        "powershell.exe": {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"},  # Ofis -> PowerShell
        "pwsh.exe": {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"},  # Ofis -> Pwsh
        "cmd.exe": {"winword.exe", "excel.exe", "powerpnt.exe", "acrobat.exe"},  # Ofis -> CMD
    }  # Supheli ebeveyn cocuk iliskileri eslesmesi

    @classmethod
    def evaluate_process(cls, proc: ProcessSecurityArtifact, strict: bool = False) -> ProcessSecurityArtifact:
        """Surec nesnesini inceler, guvenlik bayraklarini ekler ve supheli olup olmadigini belirler."""
        proc_lower = proc.name.lower().replace(".exe", "")  # Surec adi kucuk harfe cevrilir
        parent_lower = proc.parent_name.lower()  # Ebeveyn adi kucuk harfe cevrilir

        # 1. Bilinen zararli arac tespiti
        if proc_lower in cls.KNOWN_MALICIOUS_NAMES:  # Isim listesinde varsa
            proc.is_suspicious = True  # Supheli olarak isaretlenir
            proc.flags.append(f"KNOWN_ATTACK_TOOL: {proc.name}")  # Bayrak eklenir

        # 2. Anormal Ebeveyn-Cocuk iliskisi tespiti (MITRE T1059 / CWE-250)
        proc_full_exe = proc.name.lower() if proc.name.lower().endswith(".exe") else f"{proc.name.lower()}.exe"
        if proc_full_exe in cls.ANOMALOUS_PARENTS:  # Cocuk supheli aday ise
            if parent_lower in cls.ANOMALOUS_PARENTS[proc_full_exe]:  # Ebeveyn ofis veya tarayici ise
                proc.is_suspicious = True  # Supheli yapilir
                bayrak = f"ANOMALOUS_PARENT_CHILD: {proc.parent_name} -> {proc.name}"  # Bayrak metni
                proc.flags.append(bayrak)  # Listeye eklenir
                if strict:  # Kati modda dogrudan istisna firlatilir
                    raise AnomalousProcessLineageException(f"Tehlikeli ebeveyn-cocuk iliskisi: {bayrak}")

        # 3. Imzasiz ve supheli dizinde calisan surec denetimi
        if not proc.signed and any(p in proc.path.lower() for p in ["\\users\\public", "\\temp\\", "\\appdata\\"]):
            proc.is_suspicious = True  # Supheli yapilir
            proc.flags.append(f"UNSIGNED_BINARY_IN_WRITABLE_PATH: {proc.path}")  # Bayrak eklenir

        return proc  # Degerlendirilen surec nesnesi dondurulur


class NetworkPipelineCorrelator:
    """
    Boru hattindan akan TCP baglanti nesnelerini dogrulayan ve supheli portlari tespit eden bilesen.
    """

    SUSPICIOUS_PORTS: Set[int] = {4444, 1337, 8888, 6667, 9001}  # Bilinen ters baglanti (reverse shell) portlari

    @classmethod
    def evaluate_socket(cls, sock: NetworkSocketArtifact, strict: bool = False) -> NetworkSocketArtifact:
        """Soket nesnesini inceler, IP adresini dogrular ve supheli dinleme portlarini bayraklar."""
        # 1. IP Adresi Dogrulamasi (CWE-20)
        try:  # Standart IP dogrulamasi denenir
            ipaddress.ip_address(sock.local_addr)  # Yerel adres gecerli mi
            if sock.remote_addr and sock.remote_addr != "0.0.0.0":  # Uzak adres varsa
                ipaddress.ip_address(sock.remote_addr)  # Uzak adres kontrol edilir
        except ValueError as ip_err:  # Gecersiz format durumunda
            if strict:  # Kati modda istisna firlatilir
                raise InvalidPipelineSocketException(f"Gecersiz IP adresi tespit edildi: {ip_err}")
            sock.is_suspicious = True  # Supheli yapilir
            return sock  # Dondurulur

        # 2. Supheli dinleme portu tespiti
        if sock.state.lower() in ("listen", "listening") and sock.local_port in cls.SUSPICIOUS_PORTS:
            sock.is_suspicious = True  # Supheli olarak isaretlenir

        # 3. Supheli uzak port baglantisi
        if sock.remote_port in cls.SUSPICIOUS_PORTS:
            sock.is_suspicious = True  # Supheli olarak isaretlenir

        return sock  # Incelenen soket dondurulur


class PowerShellPipelineSecurityEngine:
    """
    PowerShell Nesne Boru Hatti Guvenlik ve Tehdit Avciligi Ana Motoru (Façade Pattern).
    Boru hatti nesne akisini yonetir, bellek sinirini denetler (DoS onlemi) ve adli rapor uretir.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak toplanmasi onlenir

    MAX_PIPELINE_OBJECTS: int = 5000  # DoS / Bellek tukenmesi korumasi icin maksimum nesne tavani

    def __init__(self, max_objects: int = MAX_PIPELINE_OBJECTS):
        self.max_objects = max_objects  # Maksimum nesne siniri kaydedilir
        self.processed_count = 0  # Islenen nesne sayaci sifirlanir

    def audit_pipeline_script(self, script_text: str, strict: bool = False) -> List[PipelineThreatFinding]:
        """PowerShell betik metnini ve boru hatti yapisini statik olarak denetler."""
        return PipelineSyntaxAuditor.audit_script_text(script_text, strict=strict)  # Denetim sonuclari

    def ingest_artifacts_stream(
        self,
        processes_data: List[Dict[str, Any]],
        network_data: List[Dict[str, Any]],
        strict: bool = False
    ) -> PipelineAuditReport:
        """
        Surec ve ag nesnelerini boru hatti akisi seklinde alir, iliskilendirir ve guvenlik raporunu uretir.
        """
        toplam_girdi = len(processes_data) + len(network_data)  # Toplam nesne adedi hesaplanir
        if toplam_girdi > self.max_objects:  # Eger guvenlik tavani asildiysa
            raise PipelineObjectLimitExceededException(
                f"Boru hatti nesne sayisi ({toplam_girdi}) izin verilen guvenlik limitini ({self.max_objects}) asti."
            )  # DoS istisnasi firlatilir

        report = PipelineAuditReport(total_objects_processed=toplam_girdi)  # Rapor nesnesi baslatilir

        # 1. Surec nesnelerini boru hattinda donustur ve tehdit avciligi yap
        for p_dict in processes_data:  # Her surec sozlugu gezilir
            p_obj = ProcessSecurityArtifact(
                pid=int(p_dict.get("Id", 0)),
                name=str(p_dict.get("ProcessName", "")),
                path=str(p_dict.get("Path", "")),
                cpu=float(p_dict.get("CPU", 0.0)),
                working_set_mb=round(float(p_dict.get("WorkingSet64", 0)) / (1024 * 1024), 2),
                command_line=str(p_dict.get("CommandLine", "")),
                parent_pid=int(p_dict.get("ParentProcessId", 0)),
                parent_name=str(p_dict.get("ParentProcessName", "")),
                company=str(p_dict.get("Company", "")),
                signed=bool(p_dict.get("Signed", False))
            )  # Surec nesnesi orneklenir

            incelenmis_p = ProcessPipelineHunter.evaluate_process(p_obj, strict=strict)  # Surec taranir
            if incelenmis_p.is_suspicious:  # Eger supheli bulunduysa
                report.suspicious_processes.append(incelenmis_p)  # Supheli listesine eklenir
                report.total_threats += 1  # Tehdit sayisi artirilir
                report.pipeline_safe = False  # Guvenlik onayi kaldirilir
                for f_tag in incelenmis_p.flags:  # Her bayrak icin bulgu kaydi acilir
                    report.findings.append(PipelineThreatFinding(
                        finding_id=f"FIND-PROC-{len(report.findings)+1:03d}",
                        rule_name="SUSPICIOUS_PROCESS_DETECTED",
                        severity=PipelineThreatSeverity.CRITICAL if "KNOWN_ATTACK" in f_tag else PipelineThreatSeverity.HIGH,
                        cwe_id="CWE-250: Execution with Unnecessary Privileges / LOLBins",
                        details=f"Surec '{incelenmis_p.name}' (PID: {incelenmis_p.pid}) supheli: {f_tag}",
                        code_snippet=incelenmis_p.command_line
                    ))  # Bulgu eklenir

        # 2. Ag soket nesnelerini boru hattinda isle ve korele et
        for s_dict in network_data:  # Her soket girdisi gezilir
            s_obj = NetworkSocketArtifact(
                local_addr=str(s_dict.get("LocalAddress", "")),
                local_port=int(s_dict.get("LocalPort", 0)),
                remote_addr=str(s_dict.get("RemoteAddress", "")),
                remote_port=int(s_dict.get("RemotePort", 0)),
                state=str(s_dict.get("State", "")),
                owning_pid=int(s_dict.get("OwningProcess", 0))
            )  # Soket nesnesi olusturulur

            incelenmis_s = NetworkPipelineCorrelator.evaluate_socket(s_obj, strict=strict)  # Soket taranir
            if incelenmis_s.is_suspicious:  # Eger supheli port bulunduysa
                report.suspicious_sockets.append(incelenmis_s)  # Listeye eklenir
                report.total_threats += 1  # Tehdit sayisi artirilir
                report.pipeline_safe = False  # Guvenlik onayi kaldirilir
                report.findings.append(PipelineThreatFinding(
                    finding_id=f"FIND-NET-{len(report.findings)+1:03d}",
                    rule_name="SUSPICIOUS_NETWORK_SOCKET",
                    severity=PipelineThreatSeverity.HIGH,
                    cwe_id="CWE-200: Information Exposure Through Network Socket",
                    details=f"Supheli ag soketi: {incelenmis_s.local_addr}:{incelenmis_s.local_port} (Durum: {incelenmis_s.state}, PID: {incelenmis_s.owning_pid})",
                    code_snippet=f"{incelenmis_s.local_addr}:{incelenmis_s.local_port} -> {incelenmis_s.remote_addr}:{incelenmis_s.remote_port}"
                ))  # Bulgu eklenir

        return report  # Hazirlanan adli rapor dondurulur
