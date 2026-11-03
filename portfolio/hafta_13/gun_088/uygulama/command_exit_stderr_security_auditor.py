# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G088: Komut Çıkış Kodu ve Standart Hata (stderr) Güvenlik Denetim Motoru.
Bu modül; alt süreç yürütmelerini güvenle denetler, POSIX/Windows çıkış kodlarını (exit codes)
anlamlandırır, stderr akışındaki hassas kimlik bilgisi sızıntılarını (CWE-209 / CWE-532)
ve sessiz hata yutma (silent error suppression - CWE-390) zafiyetlerini tespit eder.
"""

from dataclasses import dataclass, field  # Veri modelleri icin dataclass
from enum import Enum  # Sabitler icin Enum
from pathlib import Path  # Dosya yollari icin Path
import re  # Regex islemleri icin re
import subprocess  # Surec calistirma icin subprocess
import time  # Sure olcumu icin time
from typing import Dict, List, Optional, Tuple  # Tip ipuclari icin typing


class ExitSeverity(Enum):
    """Zafiyet ve bulgularin ciddiyet derecesi."""
    INFO = "INFO"  # Bilgilendirme
    LOW = "LOW"  # Dusuk risk
    MEDIUM = "MEDIUM"  # Orta risk
    HIGH = "HIGH"  # Yuksek risk
    CRITICAL = "CRITICAL"  # Kritik seviye


class ExitStderrAuditorException(Exception):
    """Cikis kodu ve stderr denetim motoru temel istisnasi."""
    pass


class CommandExecutionFailedException(ExitStderrAuditorException):
    """Surec sifir disi basarisiz bir cikis koduyla sonlandiginda firlatilir."""
    pass


class SensitiveDataInStderrException(ExitStderrAuditorException):
    """stderr akisinda acik metin parola, token veya gizli anahtar yakalandiginda firlatilir."""
    pass


class SilentErrorSuppressionException(ExitStderrAuditorException):
    """2> /dev/null veya sahte 'exit 0' ile hatalar yutuldugunda firlatilir."""
    pass


class CommandNotFoundSecurityException(ExitStderrAuditorException):
    """Cagrilan komut sistemde bulunamadiginda (Exit Code 127) firlatilir."""
    pass


class NullByteForbiddenException(ExitStderrAuditorException):
    """Girdi veya ciktida zararli null byte (0x00) tespit edildiginde firlatilir."""
    pass


class ProcessExecutionTimeoutException(ExitStderrAuditorException):
    """Surec izin verilen maksimum zaman asimi suresini astiginda firlatilir."""
    pass


class OversizedStderrPayloadException(ExitStderrAuditorException):
    """stderr ciktisi izin verilen guvenli boyut limitini astiginda firlatilir."""
    pass


@dataclass
class ExecutionResult:
    """Alt surec yurutme sonucunun ayrintili ozeti."""
    command: str  # Calistirilan komut dizesi
    exit_code: int  # Surec cikis kodu
    stdout: str  # Standart cikis metni
    stderr: str  # Standart hata metni
    duration_ms: float  # Calisma suresi (milisaniye)
    is_success: bool  # Basari durumu (exit_code == 0)
    status_meaning: str  # Cikis kodunun teknik anlami


@dataclass
class ExitStderrFinding:
    """Statik veya dinamik denetim bulgusu veri modeli."""
    rule_name: str  # Ihlal edilen kuralin adi
    severity: ExitSeverity  # Ciddiyet derecesi
    cwe_id: str  # Ilgili CWE standardi
    details: str  # Teknik detay aciklamasi
    recommendation: str  # Duzeltme onerisi
    line_number: Optional[int] = None  # Satir no (varsa)


@dataclass
class ExitStderrAuditReport:
    """Denetim raporu cikti nesnesi."""
    total_findings: int = 0  # Toplam bulgu adedi
    findings: List[ExitStderrFinding] = field(default_factory=list)  # Bulgular listesi
    is_secure: bool = True  # Guvenlik durumu


class ProcessExecutionInspector:
    """Alt surecleri (subprocesses) guvenli sinirlar altinda calistiran ve cikis kodlarini inceleyen bilesen."""

    MAX_STDERR_SIZE = 65536  # Maksimum guvenli stderr boyutu (64 KB)
    DEFAULT_TIMEOUT_SEC = 5.0  # Varsayilan maksimum calisma suresi (5 saniye)

    # POSIX cikis kodu anlamlari haritasi
    EXIT_CODE_MAP = {
        0: "Basari (Success)",
        1: "Genel Hata (General Error)",
        2: "Kabuk Dahili Komut Hatasi (Misuse of Shell Builtins)",
        126: "Calistirma Izni Yok (Permission Denied / Cannot Execute)",
        127: "Komut Bulunamadi (Command Not Found)",
        130: "Kullanici Tarafindan Kesildi (SIGINT - Ctrl+C)",
        137: "Zorla Sonlandirildi (SIGKILL - OOM Killer)",
        143: "Sonlandirma Sinyali Alindi (SIGTERM)"
    }

    @classmethod
    def get_exit_meaning(cls, code: int) -> str:
        """Verilen cikis kodunun POSIX standardindaki anlamini dondurur."""
        if code in cls.EXIT_CODE_MAP:
            return cls.EXIT_CODE_MAP[code]
        if code > 128:
            return f"Olumcul Sinyal Hatasi (Signal {code - 128})"
        return f"Ozel Uygulama Hata Kodu ({code})"

    @classmethod
    def execute_command_safely(cls, cmd: List[str], timeout_sec: float = DEFAULT_TIMEOUT_SEC, strict: bool = False) -> ExecutionResult:
        """Komutu alt surecte guvenli sekilde calistirir, cikis kodunu ve akislari toplar."""
        cmd_str = " ".join(cmd)  # Loglama icin komut dizesi
        if any("\x00" in arg for arg in cmd):  # Null byte denetimi
            raise NullByteForbiddenException("Komut argumanlarinda zararli null-byte (0x00) tespit edildi.")

        start_time = time.perf_counter()  # Baslangic zamani alinir

        try:
            # Guvenli alt surec yurutme
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False
            )
            duration_ms = (time.perf_counter() - start_time) * 1000.0  # Sure hesaplanir
            stdout_text = proc.stdout or ""  # Standart cikis
            stderr_text = proc.stderr or ""  # Standart hata
            exit_code = proc.returncode  # Cikis kodu

            # stderr boyut kontrolu
            if len(stderr_text) > cls.MAX_STDERR_SIZE:
                raise OversizedStderrPayloadException(
                    f"stderr boyutu izin verilen {cls.MAX_STDERR_SIZE} bayt limitini asti (Uzunluk: {len(stderr_text)})."
                )

            # Null byte denetimi ciktida da yapilir
            if "\x00" in stdout_text or "\x00" in stderr_text:
                raise NullByteForbiddenException("Surec ciktisinda zararli null-byte (0x00) tespit edildi.")

            status_meaning = cls.get_exit_meaning(exit_code)  # Anlam cozulur
            is_success = (exit_code == 0)  # Basari durumu

            if strict:
                if exit_code == 127:
                    raise CommandNotFoundSecurityException(f"Komut sistemde bulunamadi (127): {cmd_str}")
                elif exit_code != 0:
                    raise CommandExecutionFailedException(
                        f"Komut basarisiz cikis kodu ({exit_code} - {status_meaning}) ile sonlandi: {cmd_str}"
                    )

            return ExecutionResult(
                command=cmd_str,
                exit_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_ms=round(duration_ms, 2),
                is_success=is_success,
                status_meaning=status_meaning
            )

        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            raise ProcessExecutionTimeoutException(
                f"Surec {timeout_sec} saniyelik zaman asimini asti ve asili kaldi: {cmd_str}"
            )
        except FileNotFoundError:
            raise CommandNotFoundSecurityException(f"Komut bulunamadi (PATH hatasi): {cmd[0] if cmd else ''}")


class StderrSecurityScanner:
    """Standart hata (stderr) ciktilarindaki hassas veri sizintilarini tespit eden bilesen."""

    SENSITIVE_PATTERNS = [
        ("PLAINTEXT_PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s]{4,})")),
        ("API_KEY_LEAK", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|bearer)\s*[:=]\s*([a-zA-Z0-9_\-\.]{8,})")),
        ("DATABASE_URI", re.compile(r"(?i)\b(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s]+@")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----")),
    ]

    @classmethod
    def scan_stderr_for_secrets(cls, stderr_text: str, strict: bool = False) -> List[ExitStderrFinding]:
        """stderr metnini hassas kimlik bilgisi sizintilarina karsi tarar."""
        findings: List[ExitStderrFinding] = []  # Bulgular koleksiyonu
        if not stderr_text:
            return findings

        if "\x00" in stderr_text:
            raise NullByteForbiddenException("stderr akisinda zararli null-byte (0x00) tespit edildi.")

        if len(stderr_text) > ProcessExecutionInspector.MAX_STDERR_SIZE:
            raise OversizedStderrPayloadException("stderr metni maksimum boyut sınırını asti.")

        for rule_id, pattern in cls.SENSITIVE_PATTERNS:
            match = pattern.search(stderr_text)
            if match:
                finding = ExitStderrFinding(
                    rule_name=f"STDERR_{rule_id}_LEAKAGE",
                    severity=ExitSeverity.CRITICAL,
                    cwe_id="CWE-209: Error Message Containing Sensitive Information",
                    details=f"stderr akisinda hassas veri kalibi tespit edildi: '{match.group(0)[:40]}...'",
                    recommendation="Hata mesajlarindan parolalari, tokenlari ve veritabani baglanti dizilerini maskeleyin."
                )
                findings.append(finding)
                if strict:
                    raise SensitiveDataInStderrException(finding.details)

        return findings


class ScriptErrorHandlingAuditor:
    """Bash ve betik dosyalarindaki hata yutma ve cikis kodu ihmallerini statik analiz eden bilesen."""

    # 2> /dev/null veya 2>$null ile sessizce yutulan hatalar (CWE-390)
    SILENT_SUPPRESSION_REGEX = re.compile(r"(2\s*>\s*\/dev\/null|2\s*>\s*\$null|&>\s*\/dev\/null)")

    # Betigin sonunda sahte exit 0 donulmesi
    FAKE_EXIT_ZERO_REGEX = re.compile(r"^\s*exit\s+0\s*$", re.MULTILINE)

    @classmethod
    def audit_script_content(cls, script_text: str, strict: bool = False) -> List[ExitStderrFinding]:
        """Betik metninde sessiz hata gizleme ve hatali cikis kaliplarini denetler."""
        findings: List[ExitStderrFinding] = []
        lines = script_text.splitlines()

        has_strict_e = bool(re.search(r"\bset\s+-[a-zA-Z]*e\b", script_text))  # set -e kontrolu

        for line_no, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if line.startswith("#") or not line:
                continue

            # 1. 2> /dev/null ile Sessiz Hata Yutma Tespiti (CWE-390)
            if cls.SILENT_SUPPRESSION_REGEX.search(line):
                finding = ExitStderrFinding(
                    rule_name="SILENT_ERROR_SUPPRESSION",
                    severity=ExitSeverity.HIGH,
                    cwe_id="CWE-390: Detection of Error Condition Without Action",
                    details=f"Satir {line_no}: Hata akisi '2> /dev/null' ile sessizce yutulmus.",
                    recommendation="Hata akisini tamamen yok etmek yerine guvenli log dosyasina yonlendirin veya cikis kodunu denetleyin.",
                    line_number=line_no
                )
                findings.append(finding)
                if strict:
                    raise SilentErrorSuppressionException(finding.details)

            # 2. stderr Akisina Parola Yazdirma Tespiti
            if ">&2" in line and any(term in line.lower() for term in ["pass", "token", "secret", "key"]):
                finding = ExitStderrFinding(
                    rule_name="STDERR_CREDENTIAL_PRINT",
                    severity=ExitSeverity.CRITICAL,
                    cwe_id="CWE-532: Insertion of Sensitive Information into Log / Error Stream",
                    details=f"Satir {line_no}: stderr akisina (&>2) hassas degisken degeri yazdiriliyor.",
                    recommendation="Hata akisina asla parola veya gizli anahtar yazdirmayin; genel hata kodlari kullanin.",
                    line_number=line_no
                )
                findings.append(finding)
                if strict:
                    raise SensitiveDataInStderrException(finding.details)

        # 3. set -e Olmadan En Son Satirda 'exit 0' Donulmesi (Sahte Basari)
        if not has_strict_e and len(lines) >= 2:
            last_executable_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
            if last_executable_lines and last_executable_lines[-1] == "exit 0":
                finding = ExitStderrFinding(
                    rule_name="FRAUDULENT_SUCCESS_EXIT_ZERO",
                    severity=ExitSeverity.MEDIUM,
                    cwe_id="CWE-390: Fraudulent Success Status Code",
                    details="Betikte 'set -e' tanimli degilken en sonda 'exit 0' donulmus; onceki basarisiz komutlar gizleniyor.",
                    recommendation="Betiğe 'set -e' ekleyin veya son satira ulasmadan once adimlarin cikis kodlarini ($?) dogrulayin."
                )
                findings.append(finding)
                if strict:
                    raise SilentErrorSuppressionException(finding.details)

        return findings


class CommandExitStderrSecurityAuditor:
    """
    Komut Cikis Kodu ve stderr Guvenlik Denetim Motoru (Façade Pattern).
    Surec denetimini, stderr taramasini ve betik analizi bilesenlerini birlestirir.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak toplanmasi onlenir

    def __init__(self):
        self.audit_count = 0  # Gerceklestirilen denetim sayaci

    def audit_script_file(self, file_path: Path, strict: bool = False) -> ExitStderrAuditReport:
        """Dosyayi okur ve cikis kodu / stderr yonetimi acisindan denetler."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return self.audit_script_text(content, strict=strict)

    def audit_script_text(self, script_text: str, strict: bool = False) -> ExitStderrAuditReport:
        """Betik metnini ve icindeki hata yonetim kaliplarini denetler."""
        self.audit_count += 1
        if "\x00" in script_text:
            raise NullByteForbiddenException("Betik metninde zararli null-byte (0x00) tespit edildi.")

        if len(script_text) > ProcessExecutionInspector.MAX_STDERR_SIZE:
            raise OversizedStderrPayloadException("Betik metni maksimum boyut limitini asti.")

        findings = ScriptErrorHandlingAuditor.audit_script_content(script_text, strict=strict)
        is_secure = not any(f.severity in (ExitSeverity.HIGH, ExitSeverity.CRITICAL) for f in findings)

        return ExitStderrAuditReport(
            total_findings=len(findings),
            findings=findings,
            is_secure=is_secure
        )

    def inspect_process_execution(self, cmd: List[str], strict: bool = False) -> Tuple[ExecutionResult, List[ExitStderrFinding]]:
        """Komutu calistirir ve uretilen stderr ciktisini guvenlik taramasina tabi tutar."""
        exec_res = ProcessExecutionInspector.execute_command_safely(cmd, strict=strict)
        stderr_findings = StderrSecurityScanner.scan_stderr_for_secrets(exec_res.stderr, strict=strict)
        return exec_res, stderr_findings
