# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G087: Bash Betik İskeleti ve Quoting Güvenlik Denetim Motoru.
Bu modül; Bash betiklerini statik analizle inceler, katı kip (strict mode) direktiflerini,
hata yakalama tuzaklarını (trap handlers), tırnaksız değişken genişletmelerini (unquoted expansions),
eval zafiyetlerini (CWE-78) ve kelime bölünmesi / globbing tehditlerini (CWE-88) denetler.
"""

from dataclasses import dataclass, field  # Veri yapilari icin dataclass kullanilir
from enum import Enum  # Sabitler icin Enum modulu ice aktarilir
from pathlib import Path  # Dosya yollari icin Path sinifi ice aktarilir
import re  # Duzenli ifadeler icin re modulu ice aktarilir
from typing import List, Optional, Set, Tuple  # Tip ipuclari icin typing modulu


class BashSeverity(Enum):
    """Zafiyet ve bulgularin ciddiyet seviyesi enum sinifi."""
    INFO = "INFO"  # Bilgilendirme amacli bildirim
    LOW = "LOW"  # Dusuk oncelikli iyilestirme onerisi
    MEDIUM = "MEDIUM"  # Orta riskli kural ihlali
    HIGH = "HIGH"  # Yuksek guvenlik riski tasiyan kalip
    CRITICAL = "CRITICAL"  # Kritik komut enjeksiyonu veya veri kaybi riski


class BashAuditorException(Exception):
    """Bash denetim motoru icin temel istisna sinifi."""
    pass  # Temel istisna govdeli sinif


class MissingShebangException(BashAuditorException):
    """Shebang satirinin eksik veya hatali olmasi durumunda firlatilir."""
    pass  # Shebang eksikligi istisnasi


class MissingStrictModeException(BashAuditorException):
    """set -euo pipefail kati modunun bulunmamasi durumunda firlatilir."""
    pass  # Kati kip eksikligi istisnasi


class UnquotedVariableException(BashAuditorException):
    """Tehlikeli komutlarda tirnaksiz degisken genislemesi tespit edildiginde firlatilir."""
    pass  # Tirnaksiz degisken istisnasi


class DangerousEvalException(BashAuditorException):
    """eval komutunun guvensiz parametrelerle kullanilmasi durumunda firlatilir."""
    pass  # Tehlikeli eval istisnasi


class WordSplittingDetectedException(BashAuditorException):
    """Bosluk iceren girdilerin tirnaksiz genislemesinde kelime bolunmesi olustugunda firlatilir."""
    pass  # Kelime bolunmesi istisnasi


class GlobbingInjectionException(BashAuditorException):
    """Tirnaksiz degiskende joker karakter veya bayrak enjeksiyonu tespit edildiginde firlatilir."""
    pass  # Globbing enjeksiyonu istisnasi


class UnquotedArrayExpansionException(BashAuditorException):
    """$* veya tirnaksiz $@ kullanimi tespit edildiginde firlatilir."""
    pass  # Tirnaksiz dizi genislemesi istisnasi


class NullByteForbiddenException(BashAuditorException):
    """Betik iceriginde zararli null-byte (0x00) tespit edildiginde firlatilir."""
    pass  # Null byte istisnasi


class BashScriptSizeLimitException(BashAuditorException):
    """Betik dosyasinin izin verilen maksimum boyutu asmasi durumunda firlatilir."""
    pass  # Boyut limiti asimi istisnasi


@dataclass
class BashFinding:
    """Tek bir statik guvenlik bulgusunu temsil eden veri modeli."""
    rule_id: str  # Ihlal edilen guvenlik kurali kimligi
    severity: BashSeverity  # Tehdit ciddiyet derecesi
    line_number: int  # Hatanin tespit edildigi satir numarasi
    code_snippet: str  # Ilgili kod satiri
    cwe_id: str  # Iliskili CWE zafiyet standardi
    description: str  # Detayli zafiyet aciklamasi
    remediation: str  # Onerilen guvenli duzeltme kodu


@dataclass
class BashAuditReport:
    """Bash betik guvenlik denetim raporu ozeti."""
    total_lines: int = 0  # Toplam incelenen satir sayisi
    has_shebang: bool = False  # Gecerli shebang mevcut mu
    shebang: Optional[str] = None  # Yakalanan shebang metni
    has_strict_mode: bool = False  # set -euo pipefail mevcut mu
    has_ifs: bool = False  # Guvenli IFS tanimi var mi
    has_trap: bool = False  # trap hata yakalayicisi var mi
    findings: List[BashFinding] = field(default_factory=list)  # Tespit edilen bulgular
    is_secure: bool = True  # Betik guvenli kabul edildi mi


class BashSkeletonParser:
    """Bash betiginin iskelet elemanlarini (shebang, strict mode, trap, IFS) denetleyen bilesen."""

    MAX_SCRIPT_SIZE = 65536  # Maksimum guvenli betik boyutu (64 KB)
    VALID_SHEBANGS = [
        re.compile(r"^#!\s*/usr/bin/env\s+bash\b"),  # Portable bash shebang
        re.compile(r"^#!\s*/bin/bash\b"),  # Dogrudan sistem bash shebang
    ]

    @classmethod
    def validate_script_text(cls, script_text: str) -> None:
        """Betigin temel boyut ve null-byte guvenlik sinirlarini dogrular."""
        if "\x00" in script_text:  # Null byte denetimi
            raise NullByteForbiddenException("Bash betiginde zararli null-byte (0x00) tespit edildi.")
        if len(script_text) > cls.MAX_SCRIPT_SIZE:  # Boyut kontrolu
            raise BashScriptSizeLimitException(
                f"Betik boyutu izin verilen {cls.MAX_SCRIPT_SIZE} bayt limitini asti (Uzunluk: {len(script_text)})."
            )

    @classmethod
    def check_shebang(cls, lines: List[str]) -> Tuple[bool, Optional[str]]:
        """Ilk satirdaki shebang bildirimini kontrol eder."""
        if not lines:  # Satir yoksa
            return False, None
        first_line = lines[0].strip()  # Ilk satir alinir
        for pattern in cls.VALID_SHEBANGS:  # Gecerli kalip kontrolu
            if pattern.match(first_line):  # Eslesirse
                return True, first_line  # Gecerli
        return False, first_line if first_line.startswith("#!") else None

    @classmethod
    def check_strict_mode(cls, script_text: str) -> bool:
        """set -euo pipefail veya parcali kati kip direktiflerini dogrular (yorum satirlari haric)."""
        clean_lines = [l.strip() for l in script_text.splitlines() if not l.strip().startswith("#")]
        clean_text = "\n".join(clean_lines)
        if re.search(r"\bset\s+-[a-zA-Z]*e[a-zA-Z]*u[a-zA-Z]*\b.*pipefail", clean_text):
            return True
        if re.search(r"\bset\s+-euo\s+pipefail\b", clean_text):
            return True
        has_e = bool(re.search(r"\bset\s+-[a-zA-Z]*e\b", clean_text))
        has_u = bool(re.search(r"\bset\s+-[a-zA-Z]*u\b", clean_text))
        has_pipefail = bool(re.search(r"\bset\s+-o\s+pipefail\b", clean_text))
        return has_e and has_u and has_pipefail

    @classmethod
    def check_ifs(cls, script_text: str) -> bool:
        """Dahili alan ayiricinin (IFS) guvenli tanimlanip tanimlanmadigini kontrol eder."""
        clean_lines = [l.strip() for l in script_text.splitlines() if not l.strip().startswith("#")]
        clean_text = "\n".join(clean_lines)
        return bool(re.search(r"IFS=['\"]?\\n\\t['\"]?", clean_text) or re.search(r"IFS=\$'\\n\\t'", clean_text))

    @classmethod
    def check_trap(cls, script_text: str) -> bool:
        """Hata yakalama tuzaginin (trap) tanimli olup olmadigini denetler."""
        clean_lines = [l.strip() for l in script_text.splitlines() if not l.strip().startswith("#")]
        clean_text = "\n".join(clean_lines)
        return bool(re.search(r"\btrap\s+['\"].*?['\"]\s+(?:EXIT|ERR|SIGINT)", clean_text))


class QuotingSecurityScanner:
    """Bash komut ve degisken genislemelerindeki quoting zafiyetlerini tespit eden bilesen."""

    # eval komutunun tespiti (CWE-78)
    EVAL_REGEX = re.compile(r"^\s*eval\b", re.MULTILINE)

    # Tehlikeli komut havuzlarinda (sinks) tirnaksiz degisken genislemesi
    # ornek: rm -rf $DIR/*, cat $FILE, chmod 777 $PATH
    DANGEROUS_SINKS_REGEX = re.compile(r"\b(rm|cat|chmod|chown|source|\.)\s+.*?(?<![\"\'])\$([a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\})(?![\"\'])")

    # Genel tirnaksiz degisken kalibi: cift tirnak veya tek tirnak icinde olmayan $VAR
    UNQUOTED_VAR_IN_COMMAND = re.compile(r"(?<![\"\'\\])\$([a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\})")

    # Tirnaksiz $@ veya $* kullanimi
    UNQUOTED_ALL_ARGS = re.compile(r"(?<![\"'])\$(\*|@)(?![\"'])")

    # ls ciktisi uzerinde tirnaksiz dongu: for f in $(ls ...)
    UNQUOTED_LS_LOOP = re.compile(r"\bfor\s+[a-zA-Z0-9_]+\s+in\s+\$\(\s*ls\b")

    @classmethod
    def scan_line_for_quoting_issues(cls, line_no: int, raw_line: str) -> List[BashFinding]:
        """Tek bir kod satirini quoting ve enjeksiyon zafiyetleri acisindan inceler."""
        findings: List[BashFinding] = []  # Bulgular listesi
        line = raw_line.strip()  # Satir temizlenir

        # Yorum satirlari atlanir
        if line.startswith("#") or not line:
            return findings

        # 1. eval Komut Enjeksiyonu Tespiti (CWE-78)
        if cls.EVAL_REGEX.search(line):
            findings.append(BashFinding(
                rule_id="DANGEROUS_EVAL_USAGE",
                severity=BashSeverity.CRITICAL,
                line_number=line_no,
                code_snippet=line,
                cwe_id="CWE-78: OS Command Injection via eval",
                description="eval komutu calisma zamaninda dinamik kod calistirarak keyfi komut enjeksiyonuna olanak tanir.",
                remediation="eval kullanimini kaldirin; dinamik komutlar yerine yerel fonksiyonlar veya diziler kullanin."
            ))

        # 2. Tehlikeli Komut Havuzunda Tirnaksiz Degisken (CWE-732 / CWE-78)
        if cls.DANGEROUS_SINKS_REGEX.search(line):
            findings.append(BashFinding(
                rule_id="CATASTROPHIC_UNQUOTED_VARIABLE",
                severity=BashSeverity.CRITICAL,
                line_number=line_no,
                code_snippet=line,
                cwe_id="CWE-732: Incorrect Permission Assignment / Path Hijack",
                description="rm, chmod veya dosya silme komutlarinda degisken tirnaksiz kullanilmis. Degisken bossa '/' silinebilir!",
                remediation='Degiskeni mutlaka cift tirnak icine alin: "${TARGET_DIR}" ve degisken boslugunu kontrol edin.'
            ))

        # 3. Tirnaksiz Dizi Genislemesi ($* veya tirnaksiz $@) (CWE-20)
        if cls.UNQUOTED_ALL_ARGS.search(line):
            findings.append(BashFinding(
                rule_id="UNQUOTED_ARRAY_EXPANSION",
                severity=BashSeverity.HIGH,
                line_number=line_no,
                code_snippet=line,
                cwe_id="CWE-20: Unquoted Parameter List Expansion",
                description="Tirnaksiz $* veya $@ kullanimi kelime bolunmesine (word splitting) yol acar.",
                remediation='Her zaman cift tirnak icinde "${@}" formatini kullanin.'
            ))

        # 4. ls Ciktisi Uzerinde Dongu (CWE-88)
        if cls.UNQUOTED_LS_LOOP.search(line):
            findings.append(BashFinding(
                rule_id="UNQUOTED_LS_COMMAND_SUBSTITUTION",
                severity=BashSeverity.HIGH,
                line_number=line_no,
                code_snippet=line,
                cwe_id="CWE-88: Word Splitting on Command Output",
                description="'for f in $(ls)' kalibi bosluk iceren dosya adlarinda bozulur ve globbing zafiyetine aciktir.",
                remediation="ls yerine kabuk globbingi kullanin: 'for f in *; do' veya find -print0 ile while read dongusu kurun."
            ))

        return findings


class RuntimeWordSplittingSimulator:
    """
    Bash kelime bolunmesi (Word Splitting) ve pathname expansion (Globbing)
    mekanizmalarinin davranisini modelleyen ve test eden calisma zamani simulatörü.
    """

    @classmethod
    def simulate_expansion(cls, input_str: str, quoted: bool, ifs: str = " \t\n") -> List[str]:
        """
        Girdinin tırnaklı ve tırnaksız genişleme senaryolarındaki argüman ayrımını simüle eder.
        quoted=True ise girdi tek parça kalır.
        quoted=False ise IFS karakterlerine göre kelimelere bölünür (Word Splitting).
        """
        if quoted:  # Cift tirnak altinda tek bir sozcuk olarak korunur
            return [input_str]

        # Tirnaksiz genisleme: IFS karakterlerine gore kelimelere bolunur
        regex_ifs = "[" + re.escape(ifs) + "]+"  # IFS regex kalibi
        tokens = [t for t in re.split(regex_ifs, input_str) if t]  # Kelimeler bolunur
        return tokens

    @classmethod
    def test_flag_injection_risk(cls, tokens: List[str]) -> bool:
        """Arguman listesinde komut bayragi gibi algilanabilecek (-rf, --option) girdi olup olmadigini test eder."""
        return any(t.startswith("-") and len(t) > 1 for t in tokens)


class BashSkeletonQuotingAuditor:
    """
    Bash Betik Iskeleti ve Quoting Guvenlik Denetim Motoru (Façade Pattern).
    Iskelet dogrulamasini, quoting taramasini ve simülasyon testlerini koordine eder.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak toplanmasi onlenir

    def __init__(self):
        self.total_audits = 0  # Gerceklestirilen denetim sayisi

    def audit_script_file(self, file_path: Path, strict: bool = False) -> BashAuditReport:
        """Verilen Bash betik dosyasini okur ve guvenlik denetimini yurutur."""
        with open(file_path, "r", encoding="utf-8") as f:  # Dosya okunur
            content = f.read()
        return self.audit_script_text(content, strict=strict)  # Metin denetimine iletilir

    def audit_script_text(self, script_text: str, strict: bool = False) -> BashAuditReport:
        """Bash betik metnini tum guvenlik kurallarina gore denetler ve rapor uretir."""
        self.total_audits += 1  # Denetim sayaci artirilir
        BashSkeletonParser.validate_script_text(script_text)  # Null byte ve boyut kontrolu

        lines = script_text.splitlines()  # Satirlara bolunur
        has_shebang, shebang_str = BashSkeletonParser.check_shebang(lines)  # Shebang kontrolu
        has_strict_mode = BashSkeletonParser.check_strict_mode(script_text)  # Kati kip kontrolu
        has_ifs = BashSkeletonParser.check_ifs(script_text)  # IFS kontrolu
        has_trap = BashSkeletonParser.check_trap(script_text)  # Trap kontrolu

        findings: List[BashFinding] = []  # Bulgular koleksiyonu

        # 1. Shebang Denetimi
        if not has_shebang:
            finding = BashFinding(
                rule_id="MISSING_OR_INVALID_SHEBANG",
                severity=BashSeverity.MEDIUM,
                line_number=1,
                code_snippet=lines[0] if lines else "",
                cwe_id="CWE-20: Missing Script Interpreter Declaration",
                description="Betiğin ilk satirinda standart bash shebang bildirimi (#!/usr/bin/env bash) bulunmuyor.",
                remediation="Betiğin ilk satirina '#!/usr/bin/env bash' ifadesini ekleyin."
            )
            findings.append(finding)
            if strict:
                raise MissingShebangException(finding.description)

        # 2. Katı Kip (Strict Mode) Denetimi
        if not has_strict_mode:
            finding = BashFinding(
                rule_id="MISSING_STRICT_MODE",
                severity=BashSeverity.HIGH,
                line_number=2,
                code_snippet="set -euo pipefail",
                cwe_id="CWE-754: Improper Check for Exceptional Conditions",
                description="Betiğin basinda 'set -euo pipefail' katı modu tanimlanmamis. Hatalar yakalanmadan yurutme devam edebilir.",
                remediation="Betiğin basina 'set -euo pipefail' ekleyerek tanimsiz degisken ve boru hatti hatalarini engelleyin."
            )
            findings.append(finding)
            if strict:
                raise MissingStrictModeException(finding.description)

        # 3. IFS Denetimi
        if not has_ifs:
            findings.append(BashFinding(
                rule_id="MISSING_SAFE_IFS",
                severity=BashSeverity.LOW,
                line_number=3,
                code_snippet="IFS=$'\\n\\t'",
                cwe_id="CWE-20: Default Internal Field Separator",
                description="Betiğin basinda IFS=$'\\n\\t' guvenli alan ayiricisi ayarlanmamis.",
                remediation="Kelime bolunmesini (word splitting) sinirlandirmak icin 'IFS=$'\\n\\t'' tanimlayin."
            ))

        # 4. Trap Denetimi
        if not has_trap:
            findings.append(BashFinding(
                rule_id="MISSING_CLEANUP_TRAP",
                severity=BashSeverity.LOW,
                line_number=4,
                code_snippet="trap 'cleanup' EXIT",
                cwe_id="CWE-754: Missing Error Cleanup Handler",
                description="Beklenmeyen cikis veya hata aninda kaynak temizligi yapacak bir trap yakalayicisi bulunmuyor.",
                remediation="trap 'cleanup' EXIT ERR ekleyerek gecici dosyalari ve kilitleri guvenle temizleyin."
            ))

        # 5. Satir Bazli Quoting ve Enjeksiyon Taramasi
        for idx, line in enumerate(lines, 1):
            line_findings = QuotingSecurityScanner.scan_line_for_quoting_issues(idx, line)
            for lf in line_findings:
                findings.append(lf)
                if strict:
                    if lf.rule_id == "DANGEROUS_EVAL_USAGE":
                        raise DangerousEvalException(lf.description)
                    elif lf.rule_id == "CATASTROPHIC_UNQUOTED_VARIABLE":
                        raise UnquotedVariableException(lf.description)
                    elif lf.rule_id == "UNQUOTED_ARRAY_EXPANSION":
                        raise UnquotedArrayExpansionException(lf.description)

        # Rapor nesnesi insa edilir
        is_secure = not any(f.severity in (BashSeverity.HIGH, BashSeverity.CRITICAL) for f in findings)
        return BashAuditReport(
            total_lines=len(lines),
            has_shebang=has_shebang,
            shebang=shebang_str,
            has_strict_mode=has_strict_mode,
            has_ifs=has_ifs,
            has_trap=has_trap,
            findings=findings,
            is_secure=is_secure
        )
