# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G083: Git Commit ve Değişiklik İnceleme Motoru (Git Commit & Diff Auditor).

Bu modül, yazılım geliştirme yaşam döngüsünde (CI/CD) ve güvenlik operasyonlarında (SecOps)
Git commit nesnelerini ve Unified Diff akışlarını statik olarak analiz eden,
güvenlik zafiyetlerini (CWE-798, CWE-312, CWE-95, CVE-2021-42574 Trojan Source),
yüksek entropili gizli anahtarları ve zararlı desenleri tespit eden bağımsız bir denetim motorudur.
"""

from collections import Counter  # Karakter frekanslarini saymak icin Counter sinifi ice aktarilir
from dataclasses import dataclass, field  # Veri yapilarini yapilandirmak icin dataclass modulu ice aktarilir
from enum import Enum  # Sabit durumlari temsil etmek icin Enum sinifi ice aktarilir
import math  # Entropi logaritma hesaplamalari icin math modulu ice aktarilir
import re  # Duzenli ifadelerle desen eslestirmesi icin re modulu ice aktarilir
from typing import Any, Dict, List, Optional, Set, Tuple  # Tip ipuclari icin typing modulu ice aktarilir


class FindingSeverity(Enum):
    """Bulgunun guvenlik etki derecesi."""
    CRITICAL = "CRITICAL"  # Kritik seviye: acil commit reddi gerektirir
    HIGH = "HIGH"  # Yuksek seviye: dogrudan guvenlik acigi veya anahtar sizintisi
    MEDIUM = "MEDIUM"  # Orta seviye: potansiyel guvensiz desen veya zayif yapilandirma
    LOW = "LOW"  # Dusuk seviye: kod kalitesi veya stil uyarisi
    INFO = "INFO"  # Bilgilendirme seviyesi: genel metrik ve commit bilgisi


class AuditVerdict(Enum):
    """Denetim nihai karari."""
    APPROVE = "APPROVE"  # Onaylandi: commit guvenli ve kurallara uygun
    WARN = "WARN"  # Uyarili Onay: bazi supheli durumlar var, gozden gecirilmeli
    REJECT = "REJECT"  # Reddedildi: kritik zafiyet veya sizinti tespit edildi


class GitAuditException(Exception):
    """Git denetim motoru genel temel istisna sinifi."""
    pass  # Temel istisna govdesi bos birakilir


class MalformedDiffException(GitAuditException):
    """Bozuk, gecersiz veya zararli formatlanmis diff akisinda firlatilir."""
    pass  # Bozuk diff istisna govdesi


class DiffSizeLimitExceededException(GitAuditException):
    """Diff boyutu veya satir sayisi guvenlik limitlerini astiginda firlatilir (DoS onlemi)."""
    pass  # Boyut asim istisna govdesi


class SecretDetectedException(GitAuditException):
    """Commit icinde acik metin parola veya API anahtari tespit edildiginde firlatilir."""
    pass  # Gizli anahtar istisna govdesi


class HighEntropySecretException(GitAuditException):
    """Yuksek Shannon entropisine sahip rastgele uretilmis gizli deger tespit edildiginde firlatilir."""
    pass  # Yuksek entropi istisna govdesi


class TrojanSourceAttackException(GitAuditException):
    """Unicode cift yonlu (Bidi) kontrol karakterleri tespit edildiginde firlatilir (CVE-2021-42574)."""
    pass  # Trojan source istisna govdesi


class InsecureCodePatternException(GitAuditException):
    """Tehlikeli kod desenleri (eval, exec, shell injection riski) eklendiginde firlatilir."""
    pass  # Guvensiz kod deseni istisna govdesi


@dataclass
class SecurityFinding:
    """Tespit edilen tekil bir guvenlik bulgusu nesnesi."""
    finding_id: str  # Bulguyu benzersiz kilan kimlik
    severity: FindingSeverity  # Bulgulanan zafiyetin onem seviyesi
    cwe_id: str  # Iliskili Ortak Zafiyet Numaralandirmasi (CWE / CVE)
    dosya_yolu: str  # Bulgulanan dosyanin goreceli yolu
    satir_no: int  # Diff icerisindeki degisiklik satir numarasi
    kural_adi: str  # Ihlal edilen guvenlik kuralinin tanimi
    kanit: str  # Zafiyete sebep olan kod satiri veya gizlenmis parca


@dataclass
class DiffHunk:
    """Unified Diff icerisindeki tekil bir degisiklik blogu (hunk)."""
    eski_baslangic: int  # Orijinal dosyadaki baslangic satiri
    eski_satir_sayisi: int  # Orijinal dosyadaki satir adedi
    yeni_baslangic: int  # Yeni dosyadaki baslangic satiri
    yeni_satir_sayisi: int  # Yeni dosyadaki satir adedi
    eklenen_satirlar: List[Tuple[int, str]] = field(default_factory=list)  # (satir_no, icerik) listesi
    silinen_satirlar: List[Tuple[int, str]] = field(default_factory=list)  # (satir_no, icerik) listesi
    baglam_satirlari: List[str] = field(default_factory=list)  # Degismeyen baglam satirlari


@dataclass
class FileDelta:
    """Tekil bir dosya uzerindeki tum degisiklikleri temsil eder."""
    eski_yol: str  # Degisiklik oncesi dosya yolu (--- a/...)
    yeni_yol: str  # Degisiklik sonrasi dosya yolu (+++ b/...)
    hunklar: List[DiffHunk] = field(default_factory=list)  # Dosyaya ait degisiklik bloklari
    eklenen_toplam: int = 0  # Dosyada eklenen toplam satir adedi
    silinen_toplam: int = 0  # Dosyada silinen toplam satir adedi


@dataclass
class CommitMetadata:
    """Git commit ustbilgilerini tasiyan nesne."""
    commit_hash: Optional[str] = None  # 40 veya 64 karakterlik commit hash ozeti
    yazar_adi: Optional[str] = None  # Commiti olusturan yazarin adi
    yazar_eposta: Optional[str] = None  # Commiti olusturan yazarin e-posta adresi
    tarih: Optional[str] = None  # Commit olusturulma zaman damgasi
    mesaj: str = ""  # Commit aciklama mesaji


@dataclass
class AuditReport:
    """Denetim sonucunda uretilen kapsamli teknik rapor nesnesi."""
    verdict: AuditVerdict  # Nihai karar (APPROVE, WARN, REJECT)
    guvenlik_puani: int  # 100 uzerinden hesaplanan guvenlik skoru
    toplam_dosya: int  # Incelenen dosya sayisi
    toplam_eklenen: int  # Toplam eklenen satir sayisi
    toplam_silinen: int  # Toplam silinen satir sayisi
    bulgular: List[SecurityFinding] = field(default_factory=list)  # Tespit edilen bulgular
    metadata: CommitMetadata = field(default_factory=CommitMetadata)  # Commit ustbilgileri


class ShannonEntropyCalculator:
    """
    Karakter dizilerinin Shannon bilgi entropisini hesaplayan statik analiz araci.
    Formul: H = - SUM(p_i * log2(p_i))
    Rastgele olusturulan yuksek entropili gizli anahtarlari duz metinlerden ayirir.
    """

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Verilen metnin Shannon entropisini (bit/karakter cinsinden) hesaplar."""
        if not text:  # Eger metin bossa veya None ise
            return 0.0  # Entropi degeri sifir dondurulur
        
        metin_uzunlugu = len(text)  # Metnin toplam karakter sayisi alinir
        frekanslar = Counter(text)  # Her karakterin gecis frekansi sayilir
        entropi = 0.0  # Entropi toplami baslangicta sifirlanir

        for sayim in frekanslar.values():  # Her karakter frekansi uzerinde donulur
            olasilik = sayim / metin_uzunlugu  # Karakterin metin icindeki olasiligi hesaplanir
            entropi -= olasilik * math.log2(olasilik)  # Shannon formulune gore entropi katlanarak eklenir

        return round(entropi, 4)  # 4 basamak hassasiyetle dondurulur


class TrojanSourceDetector:
    """
    CVE-2021-42574 ve CVE-2021-42694 kapsamindaki Trojan Source saldirilarini tespit eder.
    Gorunur kodu insan gozu icin zararsiz kilip derleyici/yorumlayici tarafindan
    farkli calistirilmasini saglayan cift yonlu (Bidi) Unicode kontrol karakterlerini denetler.
    """

    # Tehlikeli Unicode Bidi kontrol karakterlerinin kumesi
    BIDI_CONTROL_CHARS: Set[str] = {
        "\u202A",  # Left-to-Right Embedding (LRE)
        "\u202B",  # Right-to-Left Embedding (RLE)
        "\u202C",  # Pop Directional Formatting (PDF)
        "\u202D",  # Left-to-Right Override (LRO)
        "\u202E",  # Right-to-Left Override (RLO)
        "\u2066",  # Left-to-Right Isolate (LRI)
        "\u2067",  # Right-to-Left Isolate (RLI)
        "\u2068",  # First Strong Isolate (FSI)
        "\u2069",  # Pop Directional Isolate (PDI)
        "\u200E",  # Left-to-Right Mark (LRM)
        "\u200F",  # Right-to-Left Mark (RLM)
        "\u061C",  # Arabic Letter Mark (ALM)
    }

    @classmethod
    def scan_text(cls, text: str) -> List[str]:
        """Metin icerisindeki Trojan Source Bidi karakterlerini bulur ve listeler."""
        bulunan_karakterler = []  # Tespit edilen karakterlerin adlari listesi
        for ch in text:  # Metindeki her bir karakter tek tek incelenir
            if ch in cls.BIDI_CONTROL_CHARS:  # Karakter yasakli Bidi kumesinde mevcutsa
                bulunan_karakterler.append(f"U+{ord(ch):04X}")  # Unicode hexadecimal kodu listeye eklenir
        return bulunan_karakterler  # Bulunanlar listesi dondurulur


class SecretPatternMatcher:
    """
    Kaynak kod degisiklikleri icerisindeki hassas verileri, API anahtarlarini,
    ozel sertifikalari ve yetki belirteclerini duzenli ifadelerle tespit eder.
    """

    PATTERNS = {
        "AWS_ACCESS_KEY": (
            re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            FindingSeverity.CRITICAL,
            "CWE-798: Use of Hard-coded Credentials"
        ),
        "RSA_PRIVATE_KEY": (
            re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
            FindingSeverity.CRITICAL,
            "CWE-312: Cleartext Storage of Sensitive Information"
        ),
        "GITHUB_PAT": (
            re.compile(r"\b(ghp_[a-zA-Z0-9]{30,60}|github_pat_[a-zA-Z0-9_]{50,100})\b"),
            FindingSeverity.CRITICAL,
            "CWE-798: Hardcoded GitHub Personal Access Token"
        ),
        "GENERIC_JWT_TOKEN": (
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            FindingSeverity.HIGH,
            "CWE-312: Cleartext JWT Token in Source Code"
        ),
        "SLACK_TOKEN": (
            re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
            FindingSeverity.HIGH,
            "CWE-798: Hardcoded Slack Integration Token"
        ),
    }

    @classmethod
    def scan_line(cls, line: str) -> List[Tuple[str, FindingSeverity, str, str]]:
        """
        Satir icerisindeki gizli kaliplari tarar.
        Dondurur: List[(kural_adi, severity, cwe_id, eslesen_parca)]
        """
        eslesmeler = []  # Eslesen kurallarin listesi
        for kural_adi, (desen, severity, cwe) in cls.PATTERNS.items():  # Tum kayitli kaliplar donulur
            match = desen.search(line)  # Satir uzerinde arama yapilir
            if match:  # Eger kalip bulunduysa
                bulunan_metin = match.group(0)  # Eslenen metin yakalanir
                # Hassas verinin logda tamamen gorunmemesi icin maskeleme yapilir
                if len(bulunan_metin) > 8:  # 8 karakterden uzun ise maskelenir
                    maskeli = bulunan_metin[:4] + "***" + bulunan_metin[-4:]  # Bas ve son korunarak maskelenir
                else:  # Kisa ise tamamen yildizlanir
                    maskeli = "***"  # Tamamen maskelenir
                eslesmeler.append((kural_adi, severity, cwe, maskeli))  # Bulgular listesine eklenir
        return eslesmeler  # Eslesmeler dondurulur


class DangerousPatternDetector:
    """
    Guvenlik zaafiyetine yol acabilecek tehlikeli fonksiyon cagrilarini tespit eder.
    (Orn: eval, exec, os.system, shell=True vb.)
    """

    DANGEROUS_CALLS = {
        "DANGEROUS_EVAL": (
            re.compile(r"\beval\s*\("),
            FindingSeverity.HIGH,
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
        ),
        "DANGEROUS_EXEC": (
            re.compile(r"\bexec\s*\("),
            FindingSeverity.HIGH,
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
        ),
        "INSECURE_OS_SYSTEM": (
            re.compile(r"\bos\.system\s*\("),
            FindingSeverity.HIGH,
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
        ),
        "SUBPROCESS_SHELL_TRUE": (
            re.compile(r"subprocess\.(?:Popen|run|call)\s*\(.*shell\s*=\s*True"),
            FindingSeverity.HIGH,
            "CWE-78: Command Injection via shell=True"
        ),
    }

    @classmethod
    def scan_line(cls, line: str) -> List[Tuple[str, FindingSeverity, str]]:
        """Satirda tehlikeli kod kaliplarini tarar."""
        bulunanlar = []  # Tespit edilen tehlikeli cagri listesi
        for kural_adi, (desen, severity, cwe) in cls.DANGEROUS_CALLS.items():  # Tehlikeli kaliplar gezilir
            if desen.search(line):  # Satirda kalip eslesirse
                bulunanlar.append((kural_adi, severity, cwe))  # Bulgulara eklenir
        return bulunanlar  # Liste dondurulur


class UnifiedDiffParser:
    """
    Git Unified Diff formatindaki metinleri ve commit ustbilgilerini ayrastirir.
    DoS saldirilarina, format bozukluklarina ve null-byte enjeksiyonlarina karsi guclendirilmistir.
    """

    MAX_DIFF_BYTES: int = 1_048_576  # 1 MB maksimum diff boyutu (DoS / Diff Bomb korumasi)
    MAX_LINES: int = 10_000  # Maksimum incelenebilecek satir sayisi

    def __init__(self, max_bytes: int = MAX_DIFF_BYTES, max_lines: int = MAX_LINES):
        self.max_bytes = max_bytes  # Maksimum bayt limiti saklanir
        self.max_lines = max_lines  # Maksimum satir limiti saklanir

    def parse(self, diff_text: str) -> Tuple[CommitMetadata, List[FileDelta]]:
        """
        Unified diff metnini guvenli sekilde ayrastirir.
        Dondurur: (CommitMetadata, List[FileDelta])
        """
        if not diff_text or not isinstance(diff_text, str):  # Girdi yoksa veya metin degilse
            raise MalformedDiffException("Diff metni bos olamaz veya metin turunde olmalidir.")  # Hata firlatilir

        if "\x00" in diff_text:  # Null byte kontrolu yapilir (CWE-158 onlemi)
            raise MalformedDiffException("Diff akisi icerisinde zararli null-byte (0x00) tespit edildi.")  # Hata firlatilir

        bayt_uzunlugu = len(diff_text.encode("utf-8"))  # UTF-8 bayt uzunlugu hesaplanir
        if bayt_uzunlugu > self.max_bytes:  # Bayt boyutu siniri asarsa
            raise DiffSizeLimitExceededException(
                f"Diff boyutu ({bayt_uzunlugu} bayt) guvenlik sinirini ({self.max_bytes} bayt) asti."
            )  # DoS onleme istisnasi firlatilir

        satirlar = diff_text.splitlines()  # Satirlara bolunur
        if len(satirlar) > self.max_lines:  # Satir sayisi siniri asarsa
            raise DiffSizeLimitExceededException(
                f"Diff satir sayisi ({len(satirlar)}) izin verilen siniri ({self.max_lines}) asti."
            )  # DoS onleme istisnasi firlatilir

        metadata = self._extract_metadata(satirlar)  # Commit baslik bilgileri cikarilir
        dosyalar = self._extract_files(satirlar)  # Dosya degisiklikleri cikarilir

        if not dosyalar and not metadata.commit_hash:  # Ne gecerli bir dosya ne de commit hash bulunamadiysa
            # Eger metin sadece anlamsiz metin ise format hatasi verilir
            raise MalformedDiffException("Gecerli bir Unified Diff basligi veya Git commit basligi bulunamadi.")  # Hata

        return metadata, dosyalar  # Ayristirilan sonuclar dondurulur

    def _extract_metadata(self, satirlar: List[str]) -> CommitMetadata:
        """Commit hash, yazar, tarih ve commit mesajini satirlardan cikarir."""
        meta = CommitMetadata()  # Bos metadata nesnesi olusturulur
        mesaj_satirlari = []  # Mesaj satirlarini toplayacak liste
        mesaj_kaydediliyor = False  # Mesaj bloguna girilip girilmedigini izleyen bayrak

        for satir in satirlar:  # Tum satirlar sirayla taranir
            if satir.startswith("diff --git "):  # Diff baslangicina gelindiyse metadata bitmistir
                break  # Donguden cikilir
            
            if satir.startswith("commit "):  # Commit hash satiri kontrolu
                meta.commit_hash = satir.split()[1] if len(satir.split()) > 1 else None  # Hash degeri atanir
            elif satir.startswith("Author: "):  # Yazar satiri kontrolu
                yazar_kismi = satir[8:].strip()  # Yazar metni alinir
                if "<" in yazar_kismi and ">" in yazar_kismi:  # E-posta iceriyorsa ayrilir
                    meta.yazar_adi = yazar_kismi[:yazar_kismi.find("<")].strip()  # Isim atanir
                    meta.yazar_eposta = yazar_kismi[yazar_kismi.find("<")+1:yazar_kismi.find(">")].strip()  # Eposta
                else:  # Sadece isim varsa
                    meta.yazar_adi = yazar_kismi  # Isim olarak atanir
            elif satir.startswith("Date: "):  # Tarih satiri kontrolu
                meta.tarih = satir[6:].strip()  # Tarih atanir
            elif satir.startswith("    "):  # 4 bosluk ile girintilenmis commit mesaji satiri
                mesaj_satirlari.append(satir.strip())  # Mesaj satiri listeye eklenir
                mesaj_kaydediliyor = True  # Bayrak aktif edilir
            elif mesaj_kaydediliyor and not satir.strip():  # Mesaj ici bosluk satiri
                mesaj_satirlari.append("")  # Bosluk korunur

        meta.mesaj = "\n".join(mesaj_satirlari).strip()  # Mesaj satirlari birlestirilir
        return meta  # Doldurulan metadata nesnesi dondurulur

    def _extract_files(self, satirlar: List[str]) -> List[FileDelta]:
        """Diff satirlarindan dosya deltalarini ve hunk bloklarini cikarir."""
        dosyalar: List[FileDelta] = []  # Dosya nesneleri listesi
        mevcut_dosya: Optional[FileDelta] = None  # Uzerinde calisilan aktif dosya
        mevcut_hunk: Optional[DiffHunk] = None  # Uzerinde calisilan aktif hunk
        yeni_satir_sayaci = 0  # Yeni dosyadaki satir sayaci

        hunk_deseni = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")  # Hunk baslik duzenli ifadesi

        for satir in satirlar:  # Tum satirlar adim adim taranir
            if satir.startswith("diff --git "):  # Yeni bir dosya baslangici
                if mevcut_dosya:  # Onceki dosya varsa
                    if mevcut_hunk:  # Onceki hunk aciksa
                        mevcut_dosya.hunklar.append(mevcut_hunk)  # Hunk dosyaya eklenir
                        mevcut_hunk = None  # Hunk sifirlanir
                    dosyalar.append(mevcut_dosya)  # Dosya listeye eklenir
                
                parcalar = satir.split()  # Satir bosluklardan parcalanir
                eski_yol = parcalar[2][2:] if len(parcalar) > 2 else "unknown"  # a/... kismi temizlenir
                yeni_yol = parcalar[3][2:] if len(parcalar) > 3 else "unknown"  # b/... kismi temizlenir
                mevcut_dosya = FileDelta(eski_yol=eski_yol, yeni_yol=yeni_yol)  # Yeni FileDelta baslatilir
            
            elif satir.startswith("--- ") and mevcut_dosya:  # Eski dosya adi belirtimi
                yol = satir[4:].strip()  # Yol metni alinir
                if yol.startswith("a/"):  # Git prefixi kaldirilir
                    yol = yol[2:]  # Prefix temizlenir
                mevcut_dosya.eski_yol = yol  # Eski yol guncellenir

            elif satir.startswith("+++ ") and mevcut_dosya:  # Yeni dosya adi belirtimi
                yol = satir[4:].strip()  # Yol metni alinir
                if yol.startswith("b/"):  # Git prefixi kaldirilir
                    yol = yol[2:]  # Prefix temizlenir
                mevcut_dosya.yeni_yol = yol  # Yeni yol guncellenir

            elif satir.startswith("@@ ") and mevcut_dosya:  # Hunk basligi
                if mevcut_hunk:  # Onceki hunk varsa
                    mevcut_dosya.hunklar.append(mevcut_hunk)  # Dosyaya eklenir
                
                match = hunk_deseni.match(satir)  # Hunk basligi regex ile eslestirilir
                if not match:  # Eslestirilemezse format bozuktur
                    raise MalformedDiffException(f"Gecersiz hunk baslik formati: '{satir}'")  # Format hatasi
                
                eski_bas = int(match.group(1))  # Eski baslangic satiri
                eski_adet = int(match.group(2)) if match.group(2) else 1  # Eski satir adedi
                yeni_bas = int(match.group(3))  # Yeni baslangic satiri
                yeni_adet = int(match.group(4)) if match.group(4) else 1  # Yeni satir adedi

                mevcut_hunk = DiffHunk(
                    eski_baslangic=eski_bas,
                    eski_satir_sayisi=eski_adet,
                    yeni_baslangic=yeni_bas,
                    yeni_satir_sayisi=yeni_adet
                )  # Yeni hunk baslatilir
                yeni_satir_sayaci = yeni_bas  # Yeni satir sayaci baslangica kurulur

            elif mevcut_hunk and mevcut_dosya:  # Hunk govdesi satirlari
                if satir.startswith("+") and not satir.startswith("+++"):  # Eklenen satir
                    icerik = satir[1:]  # Arti isareti atilir
                    mevcut_hunk.eklenen_satirlar.append((yeni_satir_sayaci, icerik))  # Eklenen listeye eklenir
                    mevcut_dosya.eklenen_toplam += 1  # Toplam eklenen artirilir
                    yeni_satir_sayaci += 1  # Sayac ilerletilir
                elif satir.startswith("-") and not satir.startswith("---"):  # Silinen satir
                    icerik = satir[1:]  # Eksi isareti atilir
                    mevcut_hunk.silinen_satirlar.append((yeni_satir_sayaci, icerik))  # Silinen listeye eklenir
                    mevcut_dosya.silinen_toplam += 1  # Toplam silinen artirilir
                elif satir.startswith(" "):  # Baglam satiri (degismeyen)
                    icerik = satir[1:]  # Bosluk atilir
                    mevcut_hunk.baglam_satirlari.append(icerik)  # Baglam listesine eklenir
                    yeni_satir_sayaci += 1  # Sayac ilerletilir

        if mevcut_dosya:  # Son dosya kalmissa
            if mevcut_hunk:  # Son hunk aciksa
                mevcut_dosya.hunklar.append(mevcut_hunk)  # Hunk eklenir
            dosyalar.append(mevcut_dosya)  # Dosya listeye eklenir

        return dosyalar  # Dosya listesi dondurulur


class GitCommitDiffAuditor:
    """
    Git commit ve diff denetim motoru (Façade Pattern).
    Ayrastirici, desen tarayici, Trojan Source kontrolcusu ve entropi analizorunu koordine eder.
    Nihai guvenlik raporunu ve onay/ret kararini olusturur.
    """

    DEFAULT_ENTROPY_THRESHOLD: float = 4.3  # Parola/token tespiti icin entropi esik degeri
    MIN_TOKEN_LENGTH_FOR_ENTROPY: int = 16  # Entropi analizi yapilacak asgari karakter boyutu

    def __init__(self, entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD):
        self.parser = UnifiedDiffParser()  # Diff ayrastirici baslatilir
        self.entropy_threshold = entropy_threshold  # Entropi esik degeri saklanir
        self.finding_counter = 0  # Bulgu sayaci sifirlanir

    def audit(self, diff_text: str, fail_fast: bool = False) -> AuditReport:
        """
        Diff metnini bastan sona guvenlik denetiminden gecirir.
        fail_fast=True ise ilk kritik bulguda istisna firlatir.
        """
        metadata, dosyalar = self.parser.parse(diff_text)  # Metin ayristirilir
        bulgular: List[SecurityFinding] = []  # Tespit edilen bulgular listesi

        # 1. Commit mesaji ve yazar uzerinde Trojan Source denetimi
        if metadata.mesaj:  # Eger commit mesaji mevcutsa
            bidi_karakterler = TrojanSourceDetector.scan_text(metadata.mesaj)  # Bidi taramasi yapilir
            if bidi_karakterler:  # Bidi karakter tespit edilirse
                bulgu = self._create_finding(
                    severity=FindingSeverity.HIGH,
                    cwe_id="CVE-2021-42574",
                    dosya_yolu="COMMIT_MESSAGE",
                    satir_no=0,
                    kural_adi="TROJAN_SOURCE_IN_COMMIT_MESSAGE",
                    kanit=f"Commit mesajinda Bidi kontrol karakterleri: {', '.join(bidi_karakterler)}"
                )  # Bulgu nesnesi olusturulur
                bulgular.append(bulgu)  # Listeye eklenir
                if fail_fast:  # Hizli basarisizlik modundaysa
                    raise TrojanSourceAttackException(bulgu.kanit)  # Istisna firlatilir

        toplam_eklenen = 0  # Toplam eklenen satir sayaci
        toplam_silinen = 0  # Toplam silinen satir sayaci

        # 2. Dosyalar ve eklenen kod satirlari uzerinde guvenlik denetimleri
        for dosya in dosyalar:  # Tum dosyalar donulur
            toplam_eklenen += dosya.eklenen_toplam  # Dosya ekleme sayisi eklenir
            toplam_silinen += dosya.silinen_toplam  # Dosya silme sayisi eklenir

            for hunk in dosya.hunklar:  # Dosyadaki her hunk donulur
                for satir_no, satir_icerik in hunk.eklenen_satirlar:  # Sadece eklenen satirlar taranir
                    # A. Trojan Source / Bidi karakter denetimi
                    bidi_chars = TrojanSourceDetector.scan_text(satir_icerik)  # Bidi kontrolu
                    if bidi_chars:  # Eger Bidi karakteri varsa
                        bulgu = self._create_finding(
                            severity=FindingSeverity.CRITICAL,
                            cwe_id="CVE-2021-42574: Trojan Source",
                            dosya_yolu=dosya.yeni_yol,
                            satir_no=satir_no,
                            kural_adi="TROJAN_SOURCE_BIDI_INJECTION",
                            kanit=f"Satirda Bidi karakterleri ({', '.join(bidi_chars)}): {repr(satir_icerik)}"
                        )  # Bulgu uretilir
                        bulgular.append(bulgu)  # Listeye eklenir
                        if fail_fast:  # Hizli basarisizlik isteniyorsa
                            raise TrojanSourceAttackException(bulgu.kanit)  # Istisna firlatilir

                    # B. Acik metin gizli anahtar / token denetimi
                    secret_matches = SecretPatternMatcher.scan_line(satir_icerik)  # Secret taramasi
                    for kural, sev, cwe, maskeli_kanit in secret_matches:  # Eslesen kurallar
                        bulgu = self._create_finding(
                            severity=sev,
                            cwe_id=cwe,
                            dosya_yolu=dosya.yeni_yol,
                            satir_no=satir_no,
                            kural_adi=kural,
                            kanit=maskeli_kanit
                        )  # Bulgu uretilir
                        bulgular.append(bulgu)  # Listeye eklenir
                        if fail_fast:  # Hizli hata modundaysa
                            raise SecretDetectedException(f"{kural} tespit edildi: {maskeli_kanit}")  # Istisna

                    # C. Tehlikeli kod kaliplari denetimi (eval, exec vb.)
                    dangerous_calls = DangerousPatternDetector.scan_line(satir_icerik)  # Tehlikeli cagri taramasi
                    for kural, sev, cwe in dangerous_calls:  # Tespit edilenler
                        bulgu = self._create_finding(
                            severity=sev,
                            cwe_id=cwe,
                            dosya_yolu=dosya.yeni_yol,
                            satir_no=satir_no,
                            kural_adi=kural,
                            kanit=satir_icerik.strip()[:100]  # Satir basi kanit olarak kaydedilir
                        )  # Bulgu uretilir
                        bulgular.append(bulgu)  # Listeye eklenir
                        if fail_fast:  # Hizli hata modundaysa
                            raise InsecureCodePatternException(f"{kural} tespit edildi: {satir_icerik.strip()}")

                    # D. Shannon Entropi analizi (Rastgele olusturulan gizli tokenlar)
                    literal_strings = re.findall(r"['\"]([A-Za-z0-9!@#$%^&*()_+=\-{}[\]:;<>?,./~`]{16,})['\"]", satir_icerik)
                    for token in literal_strings:  # Tanimlanan uzun string literalleri
                        entropi = ShannonEntropyCalculator.calculate_entropy(token)  # Entropi hesaplanir
                        if entropi >= self.entropy_threshold:  # Eger entropi esik degerden yuksekse
                            maskeli = token[:4] + "***" + token[-4:]  # Maskeleme yapilir
                            bulgu = self._create_finding(
                                severity=FindingSeverity.HIGH,
                                cwe_id="CWE-798: High Entropy Secret",
                                dosya_yolu=dosya.yeni_yol,
                                satir_no=satir_no,
                                kural_adi="HIGH_ENTROPY_SECRET_DETECTED",
                                kanit=f"Entropi: {entropi:.2f} bit/char - Token: {maskeli}"
                            )  # Bulgu olusturulur
                            bulgular.append(bulgu)  # Listeye eklenir
                            if fail_fast:  # Hizli basarisizlik isteniyorsa
                                raise HighEntropySecretException(f"Yuksek entropili gizli deger ({entropi}): {maskeli}")

        # Guvenlik skoru ve karar hesaplama
        guvenlik_puani, verdict = self._compute_verdict_and_score(bulgular)  # Karar ve puan hesaplanir

        rapor = AuditReport(
            verdict=verdict,
            guvenlik_puani=guvenlik_puani,
            toplam_dosya=len(dosyalar),
            toplam_eklenen=toplam_eklenen,
            toplam_silinen=toplam_silinen,
            bulgular=bulgular,
            metadata=metadata
        )  # Rapor nesnesi doldurulur
        return rapor  # Hazirlanan rapor dondurulur

    def _create_finding(
        self,
        severity: FindingSeverity,
        cwe_id: str,
        dosya_yolu: str,
        satir_no: int,
        kural_adi: str,
        kanit: str
    ) -> SecurityFinding:
        """Yeni bir SecurityFinding nesnesi olusturur ve sayaci artirir."""
        self.finding_counter += 1  # Sayac 1 artirilir
        fid = f"SEC-FIND-{self.finding_counter:04d}"  # Benzersiz kimlik olusturulur
        return SecurityFinding(
            finding_id=fid,
            severity=severity,
            cwe_id=cwe_id,
            dosya_yolu=dosya_yolu,
            satir_no=satir_no,
            kural_adi=kural_adi,
            kanit=kanit
        )  # Nesne dondurulur

    def _compute_verdict_and_score(self, bulgular: List[SecurityFinding]) -> Tuple[int, AuditVerdict]:
        """Bulgulara gore 100 uzerinden guvenlik puanini ve nihai onay kararini belirler."""
        puan = 100  # Baslangic puani tam puan olarak alinir
        has_critical = False  # Kritik bulgu var mi bayragi
        has_high = False  # Yuksek bulgu var mi bayragi

        for b in bulgular:  # Her bulgu incelenir
            if b.severity == FindingSeverity.CRITICAL:  # Eger kritik ise
                puan -= 40  # 40 puan kirilir
                has_critical = True  # Kritik bayragi aktif edilir
            elif b.severity == FindingSeverity.HIGH:  # Eger yuksek ise
                puan -= 25  # 25 puan kirilir
                has_high = True  # Yuksek bayragi aktif edilir
            elif b.severity == FindingSeverity.MEDIUM:  # Eger orta ise
                puan -= 10  # 10 puan kirilir
            elif b.severity == FindingSeverity.LOW:  # Eger dusuk ise
                puan -= 5  # 5 puan kirilir

        puan = max(0, puan)  # Puanin sifirin altina dusmesi engellenir

        if has_critical or has_high or puan < 60:  # Kritik/yuksek bulgu veya dusuk puanda
            verdict = AuditVerdict.REJECT  # Commit reddedilir
        elif puan < 90:  # Uyarili puan araligi
            verdict = AuditVerdict.WARN  # Commit uyarili kabul edilir
        else:  # Temiz commit
            verdict = AuditVerdict.APPROVE  # Commit onaylanir

        return puan, verdict  # Puan ve karar dondurulur
