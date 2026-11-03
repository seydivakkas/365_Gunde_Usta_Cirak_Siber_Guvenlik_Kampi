# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G086: PowerShell Betik Parametreleri ve Güvenlik Denetim Motoru.

Bu modül; PowerShell betiklerindeki param(...) bloklarını, tip bildirimlerini,
doğrulama özniteliklerini (ValidateScript, ValidatePattern, ValidateRange, ValidateSet),
açık metin parola bildirimlerini (CWE-312), alt komut argüman enjeksiyonlarını (CWE-88)
ve çalışma zamanı parametre bağlama (parameter binding) sınırlarını denetleyen bağımsız bir motordur.
"""

from dataclasses import dataclass, field  # Veri modelleri tanimlamak icin dataclass modulu ice aktarilir
from enum import Enum  # Sabit seviyeleri tanimlamak icin Enum modulu ice aktarilir
from pathlib import Path  # Dosya sistemi islemleri icin Path modulu ice aktarilir
import re  # Duzenli ifadelerle desen esleme ve AST analizi icin re modulu ice aktarilir
from typing import Any, Dict, List, Optional, Set, Tuple  # Tip guvenligi icin typing modulu ice aktarilir


class ParameterSeverity(Enum):
    """Parametre guvenlik ihlalinin ciddiyet derecesi."""
    LOW = "LOW"  # Dusuk: kod stili ve eksik aciklama
    MEDIUM = "MEDIUM"  # Orta: eksik tip bildirimi veya kismi dogrulama
    HIGH = "HIGH"  # Yuksek: dogrulanmamis yol veya unquoted komut calistirma
    CRITICAL = "CRITICAL"  # Kritik: acik metin parola veya arguman enjeksiyonu


class PowerShellParameterException(Exception):
    """PowerShell parametre guvenlik motoru temel istisna sinifi."""
    pass  # Temel govde bos birakilir


class ArgumentInjectionDetectedException(PowerShellParameterException):
    """Parametre degerinde alt komut calistirma veya arguman bayragi tespitinde firlatilir (CWE-88)."""
    pass  # Arguman enjeksiyonu istisnasi


class PlaintextCredentialParameterException(PowerShellParameterException):
    """Parola veya gizli anahtarin [SecureString] yerine duz [string] olarak bildirilmesinde firlatilir (CWE-312)."""
    pass  # Acik metin parola istisnasi


class ParameterPathTraversalException(PowerShellParameterException):
    """Dosya parametresinde guvenli dizin disina cikma denemesinde firlatilir (CWE-22)."""
    pass  # Dizin atlama istisnasi


class InvalidParameterSetException(PowerShellParameterException):
    """Parametre degerinin tanimli ValidateSet kumesi disinda olmasi durumunda firlatilir (CWE-20)."""
    pass  # Gecersiz set degeri istisnasi


class ParameterOutOfRangeException(PowerShellParameterException):
    """Sayisal parametrenin ValidateRange sinirlari disinda kalmasinda firlatilir (CWE-20)."""
    pass  # Sinir disi aralik istisnasi


class NullByteForbiddenException(PowerShellParameterException):
    """Parametre degerinde veya betik metninde null-byte (0x00) tespitinde firlatilir (CWE-158)."""
    pass  # Null byte istisnasi


class ParameterPatternMismatchException(PowerShellParameterException):
    """Parametre degerinin ValidatePattern duzenli ifadesine uymamasi durumunda firlatilir (CWE-20)."""
    pass  # Desen uyumsuzluk istisnasi


class ParameterSizeLimitExceededException(PowerShellParameterException):
    """Parametre uzunlugu maksimum guvenlik sinirini astiginda firlatilir (CWE-400 DoS)."""
    pass  # Boyut asim istisnasi


class MalformedParameterBlockException(PowerShellParameterException):
    """Bozuk, kapanmamis veya gecersiz param() blogu sozdiziminde firlatilir (CWE-20)."""
    pass  # Bozuk param blogu istisnasi


@dataclass
class ParsedParameter:
    """Ayrastirilan tekil bir PowerShell parametresinin ozellikleri."""
    name: str  # Parametre degisken adi (orn: $LogPath)
    type_hint: str  # Bildirilen veri tipi (orn: [string], [SecureString])
    is_mandatory: bool = False  # Zorunlu parametre mi (Mandatory = $true)
    validations: List[str] = field(default_factory=list)  # ValidateSet, ValidateRange vb. listesi
    default_value: Optional[str] = None  # Varsa varsayilan degeri
    is_sensitive: bool = False  # Parola, token veya anahtar adayi mi


@dataclass
class ParameterSecurityFinding:
    """Parametre denetimi sirasinda tespit edilen guvenlik bulgusu."""
    finding_id: str  # Benzersiz bulgu kimligi
    parameter_name: str  # Bulgulanan parametre adi
    severity: ParameterSeverity  # Tehdit seviyesi
    cwe_id: str  # Ilgili CWE / MITRE numarasi
    rule_name: str  # Ihlal edilen kuralin tanimi
    details: str  # Teknik detay aciklamasi
    recommendation: str  # Cozum ve guvenli kod onerisi


@dataclass
class ScriptParameterAuditReport:
    """Betik parametre blogu denetim raporu nesnesi."""
    total_params_found: int = 0  # Bulunan toplam parametre adedi
    total_findings: int = 0  # Uretilen toplam guvenlik bulgusu
    findings: List[ParameterSecurityFinding] = field(default_factory=list)  # Bulgular listesi
    has_cmdlet_binding: bool = False  # [CmdletBinding()] mevcut mu
    is_secure: bool = True  # Betik parametreleri guvenli mi


class ScriptParamBlockParser:
    """
    PowerShell betiklerindeki param(...) bloklarini statik olarak ayrastiran ve denetleyen bilesen.
    """

    PARAM_START_REGEX = re.compile(r"\bparam\s*\(", re.IGNORECASE)  # param( blogu baslangici
    SENSITIVE_NAMES_REGEX = re.compile(r"(?i)(password|passwd|pwd|secret|apikey|token|credential)")  # Hassas adlar substring aramasi

    @classmethod
    def _extract_param_block(cls, script_text: str) -> Optional[str]:
        """Dengeli parantez sayma algoritmasi ile param(...) blogunun icerigini cikarir."""
        match = cls.PARAM_START_REGEX.search(script_text)  # param( baslangici aranir
        if not match:  # Eslenmediyse
            return None  # Yoktur
        start_idx = match.end()  # '(' sonrasi indeks
        depth = 1  # Baslangic derinligi
        in_quote = None  # Tirnak durumu
        escape = False  # Kacis durumu
        for i in range(start_idx, len(script_text)):  # Karakterler taranir
            c = script_text[i]  # Mevcut karakter
            if escape:  # Kacis aktifse
                escape = False  # Sifirla
                continue  # Devam et
            if c == "`":  # PowerShell kacis karakteri
                escape = True  # Aktif yap
                continue  # Devam et
            if in_quote:  # Tirnak icindeysek
                if c == in_quote:  # Kapanis tirnagi mi
                    in_quote = None  # Tirnak kapandi
                continue  # Tirnak ici karakteri atla
            if c in ("'", '"'):  # Yeni tirnak baslangici
                in_quote = c  # Aktif tirnagi kaydet
                continue  # Atla
            if c in "([{":  # Acilan parantez turleri
                depth += 1  # Derinligi artir
            elif c in ")]}":  # Kapanan parantez turleri
                depth -= 1  # Derinligi azalt
                if depth == 0:  # Ana param( parantezi kapandi mi
                    return script_text[start_idx:i]  # Blok metnini dondur
        raise MalformedParameterBlockException("Bozuk param() blogu: Parantez acilip kapatilmamis.")  # Kapanmadiysa hata

    @classmethod
    def parse_script_parameters(cls, script_text: str, strict: bool = False) -> Tuple[bool, List[ParsedParameter]]:
        """Betikten param() blogunu ayristirir ve parametre nesnelerini dondurur."""
        if "\x00" in script_text:  # Null byte denetimi
            raise NullByteForbiddenException("Betik metninde zararli null-byte (0x00) tespit edildi.")

        has_cmdlet_binding = "[cmdletbinding" in script_text.lower()  # CmdletBinding kontrol edilir

        # Sozdizimi dogrulama: param( baslayip kapanmayan blok var mi?
        if "param" in script_text.lower() and "(" in script_text:  # param ve parantez varsa
            if script_text.count("(") != script_text.count(")"):  # Parantez sayilari esit degilse
                raise MalformedParameterBlockException("Bozuk param() blogu: Parantez acilip kapatilmamis.")

        block_content = cls._extract_param_block(script_text)  # param(...) blogu dengeli cikartilir
        if block_content is None:  # Parametre blogu bulunamazsa
            return has_cmdlet_binding, []  # Bos liste dondurulur

        raw_params = cls._split_parameters(block_content)  # Virgullerle ayrilmis parametreler bolunur
        parsed_list: List[ParsedParameter] = []  # Ayrastirilanlar listesi

        for p_str in raw_params:  # Her parametre ifadesi incelenir
            p_str = p_str.strip()  # Bosluklar temizlenir
            if not p_str:  # Bos ise gecilir
                continue  # Sonraki parametre

            matches = list(re.finditer(r"(?:\[([a-zA-Z0-9_\.]+)\]\s*)?\$([a-zA-Z0-9_]+)(?:\s*=|\s*$)", p_str))  # Eslesmeler
            valid_matches = [m for m in matches if m.group(2).lower() not in ("true", "false", "null", "_")]  # Gecerli adlar
            if not valid_matches:  # Degisken adi yoksa atlanir
                continue
            last_m = valid_matches[-1]  # Son gercek parametre bildirimi
            param_name = last_m.group(2)  # Degisken adi alinir
            type_hint = last_m.group(1) if last_m.group(1) else "Object"  # Belirtilmemisse Object varsayilir

            is_mandatory = bool(re.search(r"Mandatory\s*=\s*\$true", p_str, re.IGNORECASE))  # Mandatory kontrolu
            validations = re.findall(r"\[(Validate[a-zA-Z0-9]+)\b", p_str, re.IGNORECASE)  # Dogrulama ozellikleri

            is_sensitive = bool(cls.SENSITIVE_NAMES_REGEX.search(param_name))  # Isimden hassaslik kontrolu

            parsed_obj = ParsedParameter(
                name=param_name,
                type_hint=type_hint,
                is_mandatory=is_mandatory,
                validations=validations,
                is_sensitive=is_sensitive
            )  # Nesne olusturulur
            parsed_list.append(parsed_obj)  # Listeye eklenir

        return has_cmdlet_binding, parsed_list  # Sonuclar dondurulur

    @staticmethod
    def _split_parameters(block_content: str) -> List[str]:
        """Parantez ve virgul hiyerarsisini bozmadan parametreleri boler."""
        parcalar = []  # Sonuc parcalari
        mevcut = []  # Aktif toplanan karakterler
        derinlik = 0  # Parantez derinlik sayaci
        in_quote = None  # Tirnak durumu
        escape = False  # Kacis durumu

        for char in block_content:  # Karakter karakter taranir
            if escape:  # Kacis aktifse
                escape = False  # Sifirla
                mevcut.append(char)  # Karakteri ekle
                continue  # Devam et
            if char == "`":  # Kacis karakteri
                escape = True  # Aktif et
                mevcut.append(char)  # Ekle
                continue  # Devam et
            if in_quote:  # Tirnak icindeysek
                if char == in_quote:  # Tirnak kapandiysa
                    in_quote = None  # Sifirla
                mevcut.append(char)  # Karakteri ekle
                continue  # Devam et
            if char in ("'", '"'):  # Tirnak baslangiciysa
                in_quote = char  # Kaydet
                mevcut.append(char)  # Ekle
                continue  # Devam et

            if char in "([{":  # Acilan parantez
                derinlik += 1  # Derinlik artirilir
                mevcut.append(char)  # Karakter eklenir
            elif char in ")]}":  # Kapanan parantez
                derinlik = max(0, derinlik - 1)  # Derinlik azaltilir
                mevcut.append(char)  # Karakter eklenir
            elif char == "," and derinlik == 0:  # Ana seviyedeki virgul
                s = "".join(mevcut).strip()  # Parca birlestirilir
                if s:  # Bos degilse
                    parcalar.append(s)  # Parca listeye atilir
                mevcut = []  # Sifirlanir
            else:  # Diger karakterler
                mevcut.append(char)  # Eklenir

        if mevcut:  # Kalan son parca
            s = "".join(mevcut).strip()  # Birlestir
            if s:  # Bos degilse
                parcalar.append(s)  # Eklenir

        return parcalar  # Bolunmus liste dondurulur


class ArgumentInjectionDetector:
    """
    Parametre degerlerinde alt sureclere (cmd.exe, Start-Process, curl vb.) yonelik
    arguman enjeksiyonu (CWE-88) ve komut zincirleme karakterlerini tespit eder.
    """

    DANGEROUS_DELIMITERS = [
        re.compile(r"[;&|`$]"),  # Komut ayirici karakterler (;, &&, ||, |, `, $)
        re.compile(r"\b(?:whoami|net\s+user|calc|cmd|powershell)\b", re.IGNORECASE),  # Supheli komutlar
        re.compile(r"^\s*[-/][a-zA-Z0-9]+\b"),  # Alt komuta bayrak gibi gecirilmeye calisilan girdiler
    ]

    @classmethod
    def scan_argument_value(cls, value: str, strict: bool = False) -> bool:
        """Parametre degerinde komut/arguman enjeksiyonu olup olmadigini denetler."""
        if not isinstance(value, str):  # Metin degilse enjeksiyon sayilmaz
            return False  # Guvenli

        for pattern in cls.DANGEROUS_DELIMITERS:  # Tum zararli kaliplar taranir
            if pattern.search(value):  # Kalip eslesirse
                if strict:  # Kati modda dogrudan istisna firlatilir
                    raise ArgumentInjectionDetectedException(
                        f"Arguman Enjeksiyonu Tespiti: '{value}' icerisinde tehlikeli karakterler bulundu."
                    )  # Istisna
                return True  # Supheli bulundu

        return False  # Temiz


class RuntimeParameterValidator:
    """
    PowerShell calisma zamani parametre baglama (parameter binding) kurallarini uygulayan dogrulayici.
    ValidateScript, ValidatePattern, ValidateRange ve ValidateSet kontrollerini gerceklestirir.
    """

    MAX_PARAM_LENGTH: int = 4096  # DoS onleme maks karakter siniri

    @classmethod
    def validate_string_param(cls, name: str, value: str, strict: bool = True) -> str:
        """Genel metin parametresini boyut ve null-byte kontrolunden gecirir."""
        if "\x00" in value:  # Null byte kontrolu
            raise NullByteForbiddenException(f"Parametre '{name}' icerisinde null byte (0x00) tespit edildi.")

        if len(value) > cls.MAX_PARAM_LENGTH:  # Boyut asim kontrolu
            raise ParameterSizeLimitExceededException(
                f"Parametre '{name}' maksimum {cls.MAX_PARAM_LENGTH} karakter limitini asti (Uzunluk: {len(value)})."
            )

        return value  # Gecerli metin dondurulur

    @classmethod
    def validate_path_param(cls, name: str, path_val: str) -> Path:
        """Dosya yolu parametresini path traversal (CWE-22) acisindan denetler."""
        cls.validate_string_param(name, path_val)  # Temel kontroller yapilir
        if ".." in path_val.replace("\\", "/").split("/"):  # Dizin atlama kontrolu
            raise ParameterPathTraversalException(
                f"Parametre '{name}' gecersiz dizin atlama (..) iceriyor: '{path_val}'"
            )
        return Path(path_val)  # Path nesnesi dondurulur

    @classmethod
    def validate_set_param(cls, name: str, value: str, allowed_set: Set[str]) -> str:
        """Parametre degerinin izin verilen kume (ValidateSet) icinde oldugunu dogrular."""
        cls.validate_string_param(name, value)  # Temel kontrol
        if value not in allowed_set:  # Kume disindaysa
            raise InvalidParameterSetException(
                f"Parametre '{name}' degeri ('{value}') izin verilen kume disindadir: {allowed_set}"
            )
        return value  # Onayli deger

    @classmethod
    def validate_range_param(cls, name: str, value: int, min_val: int, max_val: int) -> int:
        """Sayisal parametrenin izin verilen aralikta (ValidateRange) oldugunu denetler."""
        if not (min_val <= value <= max_val):  # Aralik disindaysa
            raise ParameterOutOfRangeException(
                f"Parametre '{name}' degeri ({value}) [{min_val}, {max_val}] araligi disindadir."
            )
        return value  # Onayli sayisal deger

    @classmethod
    def validate_pattern_param(cls, name: str, value: str, regex_pattern: str) -> str:
        """Parametrenin ValidatePattern duzenli ifadesine uydugunu denetler."""
        cls.validate_string_param(name, value)  # Temel kontroller
        if not re.match(regex_pattern, value):  # Regex eslesmezse
            raise ParameterPatternMismatchException(
                f"Parametre '{name}' degeri ('{value}') '{regex_pattern}' kalibina uymuyor."
            )
        return value  # Onayli deger


class PowerShellParameterSecurityAuditor:
    """
    PowerShell Betik Parametreleri Guvenlik Denetim Motoru (Façade Pattern).
    Betik AST analizini ve calisma zamani parametre kontrollerini birlestirir.
    """
    __test__ = False  # pytest tarafindan test sinifi olarak toplanmasi onlenir

    def __init__(self):
        self.finding_counter = 0  # Bulgu sayaci sifirlanir

    def audit_script_file(self, file_path: Path, strict: bool = False) -> ScriptParameterAuditReport:
        """Verilen PowerShell betik dosyasini okur ve parametre guvenligini denetler."""
        with open(file_path, "r", encoding="utf-8") as f:  # Dosya acilir
            script_text = f.read()  # Metin okunur
        return self.audit_script_text(script_text, strict=strict)  # Metin denetim fonksiyonuna yonlendirilir

    def audit_script_text(self, script_text: str, strict: bool = False) -> ScriptParameterAuditReport:
        """Betik metnini inceler, acik metin parolalari, eksik dogrulamalari ve zafiyetleri raporlar."""
        has_binding, parsed_params = ScriptParamBlockParser.parse_script_parameters(script_text, strict=strict)  # Ayrastir
        findings: List[ParameterSecurityFinding] = []  # Bulgular listesi

        # 1. [CmdletBinding()] Eksikligi Denetimi
        if not has_binding and parsed_params:  # Parametre var ama CmdletBinding yoksa
            findings.append(self._create_finding(
                param_name="GLOBAL",
                severity=ParameterSeverity.LOW,
                cwe_id="CWE-20: Improper Input Validation",
                rule_name="MISSING_CMDLET_BINDING",
                details="Betikte parametre tanimlanmis ancak [CmdletBinding()] bildirimi yapilmamis.",
                recommendation="Gelismis fonksiyon ozellikleri ve hata kontrolu icin betigin basina [CmdletBinding()] ekleyin."
            ))

        # 2. Her Parametre Uzerinde Guvenlik Kurallari
        for p in parsed_params:  # Tum parametreler gezilir
            # A. Acik Metin Parola Parametresi Bildirimi (CWE-312)
            if p.is_sensitive and p.type_hint.lower() not in ("securestring", "pscredential", "system.security.securestring"):
                finding = self._create_finding(
                    param_name=p.name,
                    severity=ParameterSeverity.CRITICAL,
                    cwe_id="CWE-312: Cleartext Storage of Sensitive Information in Parameter",
                    rule_name="PLAINTEXT_CREDENTIAL_PARAMETER",
                    details=f"Hassas parametre '${p.name}' acik metin [{p.type_hint}] olarak bildirilmis.",
                    recommendation=f"Parametreyi [System.Security.SecureString] veya [PSCredential] turune donusturun."
                )  # Bulgu olusturulur
                findings.append(finding)  # Listeye eklenir
                if strict:  # Kati modda istisna firlatilir
                    raise PlaintextCredentialParameterException(finding.details)

            # B. Tiplendirilmemis (Untyped) Parametre Kontrolu (CWE-20)
            if p.type_hint == "Object":  # Tip belirtilmemisse
                findings.append(self._create_finding(
                    param_name=p.name,
                    severity=ParameterSeverity.MEDIUM,
                    cwe_id="CWE-20: Weak Typing in Parameter Declaration",
                    rule_name="UNTYPED_PARAMETER_DECLARATION",
                    details=f"Parametre '${p.name}' icin tip belirtilmemis (varsayilan [Object]).",
                    recommendation=f"Parametre basina [string], [int], [FileInfo] gibi kati tip tanimi ekleyin."
                ))

            # C. Dogrulanmamis Dosya Yolu Parametresi (CWE-22)
            if any(term in p.name.lower() for term in ["path", "file", "dir", "folder"]):  # Yol adayi ise
                if not any("validatescript" in v.lower() for v in p.validations):  # ValidateScript yoksa
                    findings.append(self._create_finding(
                        param_name=p.name,
                        severity=ParameterSeverity.HIGH,
                        cwe_id="CWE-22: Unvalidated Path Parameter",
                        rule_name="UNVALIDATED_PATH_PARAMETER",
                        details=f"Yol parametresi '${p.name}' [ValidateScript] ile sinirlandirilmamis.",
                        recommendation="[ValidateScript({ Test-Path $_ -PathType Leaf })] ekleyerek dizin atlamayi onleyin."
                    ))

        # 3. Kod Icerisinde Arguman Enjeksiyonu Kaliplari Taramasi (CWE-88)
        if re.search(r"(?:cmd\.exe|Start-Process|Invoke-Item)\s+.*\$[a-zA-Z0-9_]+", script_text):
            findings.append(self._create_finding(
                param_name="SUBPROCESS_INVOCATION",
                severity=ParameterSeverity.CRITICAL,
                cwe_id="CWE-88: Argument Injection via Subprocess",
                rule_name="SUBPROCESS_ARGUMENT_INJECTION_RISK",
                details="Dis komut cagrilarinda dogrulanmamis parametreler tirnak veya dizi kullanilmadan birlestirilmis.",
                recommendation="Start-Process cmdlet'ini -ArgumentList dizisiyle kullanin veya param splatting uygulayin."
            ))

        report = ScriptParameterAuditReport(
            total_params_found=len(parsed_params),
            total_findings=len(findings),
            findings=findings,
            has_cmdlet_binding=has_binding,
            is_secure=not any(f.severity in (ParameterSeverity.CRITICAL, ParameterSeverity.HIGH) for f in findings)
        )  # Rapor doldurulur
        return report  # Rapor dondurulur

    def _create_finding(
        self,
        param_name: str,
        severity: ParameterSeverity,
        cwe_id: str,
        rule_name: str,
        details: str,
        recommendation: str
    ) -> ParameterSecurityFinding:
        """Yeni bir guvenlik bulgusu nesnesi olusturur ve sayaci artirir."""
        self.finding_counter += 1  # Sayac artirilir
        fid = f"PARAM-SEC-{self.finding_counter:03d}"  # Benzersiz kimlik
        return ParameterSecurityFinding(
            finding_id=fid,
            parameter_name=param_name,
            severity=severity,
            cwe_id=cwe_id,
            rule_name=rule_name,
            details=details,
            recommendation=recommendation
        )  # Nesne dondurulur
