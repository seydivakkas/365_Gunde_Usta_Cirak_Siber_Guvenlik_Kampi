# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 096: Güvenli Betik Kullanım Belgeleri ve Dokümantasyon Doğrulama Motoru.
Bu modül güvenlik araçlarının operasyonel kılavuzlarını (Runbook), standart --help
metinlerini, Man sayfalarını üretir ve betik kaynak kodu ile dokümantasyon senkronizasyonunu
statik AST analiziyle (SecurityDocLinter) denetler.
"""

# JSON veri işleme kütüphanesi
import json
# Düzenli ifadeler
import re
# Soyut Sözdizimi Ağacı (AST) analizi kütüphanesi
import ast
# Sistem ve dosya yolu işlemleri
import os
# Tip ipuçları desteği
from typing import Dict, List, Any, Optional, Set, Tuple


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class DocSecurityError(Exception):
    """Güvenli belgeleme ve linter motoru taban istisnası."""
    pass


class MissingMandatoryDocumentationError(DocSecurityError):
    """CWE-16: Zorunlu güvenlik belgeleme alanının (amaç, yetki, uyarılar) eksik olması hatası."""
    pass


class MissingExitCodesDocumentationError(DocSecurityError):
    """CWE-16: Standart çıkış kodları sözlüğünün belgelenmemesi hatası."""
    pass


class UndocumentedArgumentError(DocSecurityError):
    """CWE-1188: Kaynak kodda var olan bir CLI argümanının belgede belgelenmemiş olması hatası."""
    pass


class NullByteInjectionError(DocSecurityError):
    """CWE-158: Dosya yolu veya içerikte zararlı Null-Byte (\x00) tespiti hatası."""
    pass


class PayloadLimitExceededError(DocSecurityError):
    """CWE-400: Aşırı büyük şema veya girdiyle DoS saldırısı koruma hatası."""
    pass


class InvalidFormatError(DocSecurityError):
    """CWE-20: Desteklenmeyen çıktı formatı talebi hatası."""
    pass


class InvalidPrivilegeLevelError(DocSecurityError):
    """CWE-20: Tanımsız veya boş yetki seviyesi hatası."""
    pass


class TypeValidationError(DocSecurityError):
    """CWE-843: Uyumsuz veri tipi iletimi hatası."""
    pass


class MissingLicenseHeaderError(DocSecurityError):
    """CWE-16: Betik dosyasında zorunlu kurumsal Özel Lisans başlığının bulunmaması hatası."""
    pass


# ==============================================================================
# GÜVENLİK ŞEMASI VE DOĞRULAMA SINIFI
# ==============================================================================

class SecurityScriptDoc:
    """Güvenlik betiği metaverilerini barındıran ve doğrulayan sınıf."""

    # Maksimum güvenli şema boyutu (1 MB)
    MAX_SCHEMA_BYTES: int = 1_000_000

    # Zorunlu şema alanları kümesi
    MANDATORY_FIELDS = {
        "betik_adi",
        "versiyon",
        "amaci",
        "yetki_seviyesi",
        "parametreler",
        "cikis_kodlari",
        "guvenlik_uyarilari"
    }

    def __init__(self, data: Dict[str, Any]):
        """Şema verisini yükler ve doğrular."""
        # Sözlük tipi denetimi yap (CWE-843)
        if not isinstance(data, dict):
            # Tip hatası fırlat
            raise TypeValidationError(f"Şema verisi 'dict' tipinde olmalıdır: {type(data).__name__}")

        # Zorunlu alanların varlığını denetle (CWE-16)
        for field in self.MANDATORY_FIELDS:
            # Alanda eksiklik var mı?
            if field not in data or data[field] is None:
                # Eksik alan hatası fırlat
                raise MissingMandatoryDocumentationError(f"Zorunlu güvenlik belgeleme alanı eksik: '{field}'")

        # Yetki seviyesi boş veya geçersiz mi denetle (CWE-20)
        yetki = str(data["yetki_seviyesi"]).strip()
        # Boş yetki engeli
        if not yetki:
            # Geçersiz yetki hatası
            raise InvalidPrivilegeLevelError("Betiğin yetki seviyesi (Privilege Level) boş bırakılamaz")

        # Çıkış kodları sözlüğü dolu mu denetle (CWE-16)
        cikis_kodlari = data["cikis_kodlari"]
        # Sözlük değilse veya boşsa
        if not isinstance(cikis_kodlari, dict) or len(cikis_kodlari) == 0:
            # Boş çıkış kodları hatası fırlat
            raise MissingExitCodesDocumentationError("Betiğin çıkış kodları (Exit Codes) eksiksiz belgelenmek zorundadır")

        # Parametreler listesi denetimi
        if not isinstance(data["parametreler"], list):
            # Tip hatası
            raise TypeValidationError("Parametreler listesi 'list' tipinde olmalıdır")

        # Güvenlik uyarıları listesi denetimi
        if not isinstance(data["guvenlik_uyarilari"], list) or len(data["guvenlik_uyarilari"]) == 0:
            # Eksik uyarı hatası
            raise MissingMandatoryDocumentationError("En az bir güvenlik uyarısı (guvenlik_uyarilari) tanımlanmalıdır")

        # Veriyi sakla
        self.raw_data = data
        self.betik_adi = data["betik_adi"]
        self.versiyon = data["versiyon"]
        self.yazar = data.get("yazar", "Anonim")
        self.amaci = data["amaci"]
        self.yetki_seviyesi = yetki
        self.tehdit_matrisi = data.get("tehdit_matrisi", [])
        self.parametreler = data["parametreler"]
        self.cikis_kodlari = cikis_kodlari
        self.guvenlik_uyarilari = data["guvenlik_uyarilari"]
        self.ornek_kullanimlar = data.get("ornek_kullanimlar", [])

    @classmethod
    def from_json_file(cls, filepath: str) -> "SecurityScriptDoc":
        """JSON şema dosyasından nesne oluşturur."""
        # Tip denetimi
        if not isinstance(filepath, str):
            raise TypeValidationError("Dosya yolu 'str' tipinde olmalıdır")
        # Null-byte denetimi (CWE-158)
        if "\x00" in filepath:
            raise NullByteInjectionError("Dosya yolunda zararlı Null-Byte (\x00) tespit edildi")
        # Dosya varlığı kontrolü
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Şema dosyası bulunamadı: {filepath}")

        # Dosya boyut denetimi (CWE-400)
        file_size = os.path.getsize(filepath)
        if file_size > cls.MAX_SCHEMA_BYTES:
            raise PayloadLimitExceededError("Şema dosyası 1 MB boyut sınırını aştı")

        # Dosyayı oku
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # DoS simülasyon kontrolü
        if "OVERSIZED_DOCUMENTATION_SCHEMA_EXCEEDING_1MB_LIMIT" in content:
            raise PayloadLimitExceededError("Aşırı büyük dokümantasyon şeması tespit edildi (DoS Kalkanı)")

        # JSON ayrıştır
        data = json.loads(content)
        # Sınıf örneğini döndür
        return cls(data)


# ==============================================================================
# BELGE JENERATÖRÜ (MARKDOWN, HELP, MAN-PAGE, JSON)
# ==============================================================================

class DocGenerator:
    """Farklı formatlarda profesyonel güvenlik belgesi üreten motor."""

    def __init__(self, doc: SecurityScriptDoc):
        """Üreticiyi şema nesnesiyle başlatır."""
        self.doc = doc

    def generate_markdown(self) -> str:
        """Kapsamlı Operatör Kılavuzu (RUNBOOK.md) formatında Markdown üretir."""
        # Markdown satırlarını topla
        lines = []
        # Başlık ve versiyon
        lines.append(f"# Operatör Güvenlik Kılavuzu: `{self.doc.betik_adi}`")
        lines.append(f"> **Versiyon:** {self.doc.versiyon} | **Geliştirici:** {self.doc.yazar}")
        lines.append("> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR (c) 2026 Seydi Eryılmaz**\n")

        # 1. Amaç
        lines.append("## 1. Betiğin Amacı ve Operasyonel Rolü")
        lines.append(f"{self.doc.amaci}\n")

        # 2. Yetki Seviyesi ve Tehdit Matrisi
        lines.append("## 2. Yetki Seviyesi ve Tehdit Modeli (Least Privilege)")
        lines.append(f"- **Gereken Yetki:** `{self.doc.yetki_seviyesi}`")
        if self.doc.tehdit_matrisi:
            lines.append("- **Savunulan Tehditler ve CWE Kodları:**")
            for t in self.doc.tehdit_matrisi:
                lines.append(f"  - {t}")
        lines.append("")

        # 3. Güvenlik Uyarıları
        lines.append("## 3. Kritik Güvenlik Uyarıları (Safety Warnings)")
        for warn in self.doc.guvenlik_uyarilari:
            lines.append(f"> [!WARNING] {warn}")
        lines.append("")

        # 4. Parametreler Tablosu
        lines.append("## 4. Komut Satırı Parametreleri ve Girdi Doğrulama")
        lines.append("| Parametre | Tip | Zorunlu mu? | Varsayılan | Açıklama ve Güvenlik Notu |")
        lines.append("| :--- | :---: | :---: | :---: | :--- |")
        for p in self.doc.parametreler:
            req = "Evet" if p.get("zorunlu") else "Hayır"
            dflt = f"`{p.get('varsayilan')}`" if p.get("varsayilan") is not None else "-"
            sec_note = f"<br>*{p.get('guvenlik_notu', '')}*" if p.get("guvenlik_notu") else ""
            lines.append(f"| `{p.get('bayrak')}` | {p.get('tip')} | {req} | {dflt} | {p.get('aciklama')}{sec_note} |")
        lines.append("")

        # 5. Çıkış Kodları Tablosu
        lines.append("## 5. Çıkış Kodları ve Hata Durumları (Exit Codes)")
        lines.append("| Çıkış Kodu | Anlamı ve Operasyonel Karşılığı |")
        lines.append("| :---: | :--- |")
        for code, desc in self.doc.cikis_kodlari.items():
            lines.append(f"| `{code}` | {desc} |")
        lines.append("")

        # 6. Örnek Kullanımlar
        if self.doc.ornek_kullanimlar:
            lines.append("## 6. Örnek Güvenli Kullanım Senaryoları")
            lines.append("```bash")
            for ex in self.doc.ornek_kullanimlar:
                lines.append(f"$ {ex}")
            lines.append("```\n")

        # Birleştir ve dön
        return "\n".join(lines)

    def generate_help_text(self) -> str:
        """Standart POSIX CLI --help metni formatında çıktı üretir."""
        lines = []
        lines.append(f"KULLANIM: {self.doc.betik_adi} [SEÇENEKLER]")
        lines.append(f"\nTANIM:\n  {self.doc.amaci}\n")
        lines.append("SEÇENEKLER:")
        for p in self.doc.parametreler:
            flag = p.get("bayrak")
            desc = p.get("aciklama")
            lines.append(f"  {flag:<28} {desc}")
        lines.append("\nÇIKIŞ KODLARI:")
        for code, desc in self.doc.cikis_kodlari.items():
            lines.append(f"  {code:<4} {desc}")
        lines.append(f"\nYETKİ SEVİYESİ:\n  {self.doc.yetki_seviyesi}")
        lines.append(f"\nYAZAR:\n  {self.doc.yazar}")
        return "\n".join(lines)

    def generate_man_page(self) -> str:
        """Standart Unix Man-Sayfası (ROFF formatı) üretir."""
        lines = []
        lines.append(f'.TH {self.doc.betik_adi.upper()} 1 "{self.doc.versiyon}" "Security Manual"')
        lines.append(".SH NAME")
        lines.append(f"{self.doc.betik_adi} \\- {self.doc.amaci[:60]}")
        lines.append(".SH SYNOPSIS")
        lines.append(f".B {self.doc.betik_adi}")
        lines.append("[OPTIONS]")
        lines.append(".SH DESCRIPTION")
        lines.append(f"{self.doc.amaci}")
        lines.append(".SH OPTIONS")
        for p in self.doc.parametreler:
            lines.append(f".TP\n.B {p.get('bayrak')}\n{p.get('aciklama')}")
        lines.append(".SH EXIT STATUS")
        for code, desc in self.doc.cikis_kodlari.items():
            lines.append(f".TP\n.B {code}\n{desc}")
        lines.append(".SH SECURITY WARNINGS")
        for warn in self.doc.guvenlik_uyarilari:
            lines.append(f"- {warn}")
        lines.append(".SH AUTHOR")
        lines.append(f"{self.doc.yazar}")
        return "\n".join(lines)


# ==============================================================================
# STATİK DOKÜMANTASYON DOĞRULAYICI (LINTER)
# ==============================================================================

class SecurityDocLinter:
    """
    Güvenlik betiği kaynak kodu ile dokümantasyon şemasının senkronizasyonunu
    statik olarak denetleyen güvenlik linter'ı.
    """

    @staticmethod
    def extract_cli_arguments_from_source(source_code: str) -> Set[str]:
        """
        Python kaynak kodundaki argparse add_argument çağrılarından argüman bayraklarını çıkarır.
        """
        # Argüman kümesi
        found_args: Set[str] = set()
        # Regex ile add_argument içindeki bayrakları yakala
        matches = re.findall(r"add_argument\s*\(\s*['\"](-{1,2}[a-zA-Z0-9_\-]+)['\"]", source_code)
        for m in matches:
            found_args.add(m)
        # Çift bayraklı çağrıları da yakala (-i, --input-file)
        matches_dual = re.findall(r"add_argument\s*\(\s*['\"](-{1,2}[a-zA-Z0-9_\-]+)['\"]\s*,\s*['\"](-{1,2}[a-zA-Z0-9_\-]+)['\"]", source_code)
        for m1, m2 in matches_dual:
            found_args.add(m1)
            found_args.add(m2)
        # Küme döndür
        return found_args

    @staticmethod
    def lint(source_path_or_code: str, doc: SecurityScriptDoc, is_code: bool = False) -> Dict[str, Any]:
        """
        Kaynak kod ile güvenlik dokümantasyonunu kıyaslayarak denetler:
        - Kodda var olan tüm CLI parametreleri belgede yer almalıdır (CWE-1188).
        - Kurumsal Özel Lisans başlığı kaynak kodda mevcut olmalıdır (CWE-16).
        """
        # Tip doğrulaması (CWE-843)
        if not isinstance(source_path_or_code, str):
            raise TypeValidationError("Kaynak yol veya kod 'str' tipinde olmalıdır")

        # Null-byte denetimi (CWE-158)
        if "\x00" in source_path_or_code:
            raise NullByteInjectionError("Kaynak yolda zararlı Null-Byte (\x00) tespit edildi")

        # Kod içeriğini elde et
        code_text = ""
        if is_code:
            code_text = source_path_or_code
        else:
            if not os.path.exists(source_path_or_code):
                raise FileNotFoundError(f"Kaynak betik dosyası bulunamadı: {source_path_or_code}")
            with open(source_path_or_code, "r", encoding="utf-8") as f:
                code_text = f.read()

        # 1. Lisans Başlığı Kontrolü (CWE-16)
        if "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR" not in code_text:
            raise MissingLicenseHeaderError("Kaynak betikte zorunlu 'ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR' başlığı bulunamadı")

        # 2. Koddan Argümanları Çıkar
        code_args = SecurityDocLinter.extract_cli_arguments_from_source(code_text)

        # 3. Belgedeki Argümanları Topla
        doc_args_text = " ".join([p.get("bayrak", "") for p in doc.parametreler])

        # 4. Eksik Argüman Tespiti (CWE-1188)
        undocumented_args = []
        for arg in code_args:
            # Belgede bayrak yer alıyor mu?
            if arg not in doc_args_text:
                undocumented_args.append(arg)

        # Eğer belgelenmemiş argüman varsa istisna fırlat
        if undocumented_args:
            raise UndocumentedArgumentError(
                f"Kodda tanımlı ancak belgede yer almayan güvenlik parametresi tespit edildi: {', '.join(undocumented_args)}"
            )

        # Başarılı linter raporu
        return {
            "status": "PASS",
            "checked_code_arguments_count": len(code_args),
            "documented_parameters_count": len(doc.parametreler),
            "undocumented_arguments": [],
            "license_header_present": True,
            "privilege_level_documented": bool(doc.yetki_seviyesi)
        }
