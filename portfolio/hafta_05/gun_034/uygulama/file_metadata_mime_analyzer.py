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
Gün 34: Dosya Türleri, Metadata ve MIME Analizcisi
Bu modül; dosya uzantılarının yüzeysel aldatmacasını bertaraf ederek
dosya başlıklarındaki sihirli baytları (Magic Bytes / File Signatures)
inceler, gerçek MIME türünü doğrular, çift uzantı ve uzantı-imza uyuşmazlığı
(Extension vs Signature Mismatch) saldırılarını tespit eder.
"""

# Dosya sistemi operasyonları ve dosya varlığı denetimi için os modülü
import os
# Sistem yapılandırmaları ve komut satırı yönetimi için sys modülü
import sys
# JSON tabanlı envanter ve rapor formatları için json modülü
import json
# Zaman damgaları ve metadata analizi için datetime modülü
import datetime
# Tip güvenliği ve statik analiz desteği için typing modülü
from typing import Dict, List, Any, Tuple, Optional
# Veri yapılarını modellemek için dataclass bileşeni
from dataclasses import dataclass, field, asdict


@dataclass
class FileSignature:
    """Bilinen bir dosya biçiminin imza şablonunu temsil eden model."""
    # Dosya türünün genel adı (Örn: Windows PE Executable, PDF Document)
    format_name: str
    # Dosyanın ilk baytlarında yer alan sihirli bayt dizisi
    magic_bytes: bytes
    # İmzanın dosya başındaki konumu (offset)
    offset: int = 0
    # Bu biçime karşılık gelen standart birincil dosya uzantısı
    primary_extension: str = ""
    # Standart IANA MIME türü (Örn: application/pdf, image/png)
    mime_type: str = "application/octet-stream"
    # Dosya biçiminin güvenlik açıklaması
    description: str = ""


@dataclass
class FileInspectionResult:
    """Tek bir dosyanın metadata ve imza inceleme çıktısı."""
    # İncelenen dosyanın adı
    file_name: str
    # Dosyanın göreli veya tam yolu
    file_path: str
    # Dosya adı uzantısından türetilen iddia edilen uzantı
    claimed_extension: str
    # Başlıktaki sihirli baytlardan tespit edilen gerçek dosya biçimi
    detected_format: str
    # Tespit edilen fiili MIME türü
    detected_mime: str
    # İstemci veya üstveride beyan edilen raporlanan MIME türü
    reported_mime: str
    # İlk 16 baytın onaltılık (hex) gösterimi
    header_hex: str
    # Dosya boyutu (bayt)
    size_bytes: int
    # Uzantı ile gerçek imza arasında çelişki var mı?
    is_mismatch: bool = False
    # Dosya adında çift uzantı hilesi var mı? (Örn: .pdf.exe)
    is_double_extension: bool = False
    # Güvenlik risk derecesi (CRITICAL, HIGH, MEDIUM, LOW, CLEAN)
    risk_level: str = "CLEAN"
    # Güvenlik anomalisi açıklaması
    finding_description: str = ""
    # Önerilen müdahale adımı
    remediation: str = ""


class FileMetadataMimeAnalyzer:
    """
    Sihirli bayt (Magic Bytes) tabanlı dosya türü tespit motoru ve
    metadata güvenilirlik denetleyicisi.
    """

    # Endüstri standardı temel dosya imzaları veritabanı
    SIGNATURE_DATABASE: List[FileSignature] = [
        # Windows Taşınabilir Yürütülebilir (PE / EXE / DLL / SYS) dosyası (MZ)
        FileSignature(
            format_name="Windows PE Executable",
            magic_bytes=b"MZ",
            offset=0,
            primary_extension=".exe",
            mime_type="application/x-dosexec",
            description="Windows çalýþtýrýlabilir ikili programý (DOS/PE baþlýðý)"
        ),
        # Linux / Unix Yürütülebilir ve Bağlanabilir Biçim (ELF) dosyası (\x7fELF)
        FileSignature(
            format_name="Linux ELF Executable",
            magic_bytes=b"\x7fELF",
            offset=0,
            primary_extension=".elf",
            mime_type="application/x-executable",
            description="Linux/Unix çalýþtýrýlabilir ikili programý"
        ),
        # Adobe Portable Document Format (PDF) belgesi (%PDF-)
        FileSignature(
            format_name="PDF Document",
            magic_bytes=b"%PDF-",
            offset=0,
            primary_extension=".pdf",
            mime_type="application/pdf",
            description="Standart PDF taþýnabilir belge biçimi"
        ),
        # Portable Network Graphics (PNG) resim dosyası (\x89PNG\r\n\x1a\n)
        FileSignature(
            format_name="PNG Image",
            magic_bytes=b"\x89PNG\r\n\x1a\n",
            offset=0,
            primary_extension=".png",
            mime_type="image/png",
            description="Kayıpsız sıkıştırılmış PNG grafik dosyası"
        ),
        # JPEG / JFIF dijital fotoğraf dosyası (\xff\xd8\xff)
        FileSignature(
            format_name="JPEG Image",
            magic_bytes=b"\xff\xd8\xff",
            offset=0,
            primary_extension=".jpg",
            mime_type="image/jpeg",
            description="Standart JPEG raster görüntü dosyası"
        ),
        # PKZIP arşiv dosyası (ZIP, DOCX, XLSX, JAR, APK) (PK\x03\x04)
        FileSignature(
            format_name="ZIP Archive",
            magic_bytes=b"PK\x03\x04",
            offset=0,
            primary_extension=".zip",
            mime_type="application/zip",
            description="Sıkıştırılmış PKZIP arşiv kapsayıcısı"
        ),
        # Unix Shell / Betik dosyası (#! Shebang)
        FileSignature(
            format_name="Shell Script",
            magic_bytes=b"#!",
            offset=0,
            primary_extension=".sh",
            mime_type="text/x-shellscript",
            description="Unix kabuk komut betiği"
        )
    ]

    # Çalıştırılabilir tehlikeli uzantılar kümesi
    EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".cpl", ".dll", ".elf"}

    def __init__(self) -> None:
        """Analizciyi temiz sonuç ve hata kayıtlarıyla başlatır."""
        # Gerçekleştirilen tüm dosya inceleme sonuçları
        self.results: List[FileInspectionResult] = []
        # Reddedilen bozuk veya geçersiz girdi kayıtları
        self.corrupted_records: List[Dict[str, Any]] = []

    def detect_magic_signature(self, header_bytes: bytes) -> Tuple[str, str, str]:
        """
        Dosyanın ilk baytlarını imza veritabanıyla eşleştirerek
        biçim adı, birincil uzantı ve MIME türünü tespit eder.
        """
        # Boş dosya kontrolü
        if not header_bytes:
            return "Empty File", "", "application/x-empty"

        # İmza listesindeki bilinen kalıplarla karşılaştırıyoruz
        for sig in self.SIGNATURE_DATABASE:
            start_pos = sig.offset
            end_pos = start_pos + len(sig.magic_bytes)
            # Yeterli uzunlukta veri varsa ve eşleşiyorsa
            if len(header_bytes) >= end_pos and header_bytes[start_pos:end_pos] == sig.magic_bytes:
                return sig.format_name, sig.primary_extension, sig.mime_type

        # Eğer ikili imza bulunamadıysa metin (ASCII/UTF-8) kontrolü yapıyoruz
        try:
            # İlk 256 baytı UTF-8 olarak çözmeye çalışıyoruz
            header_bytes.decode("utf-8")
            # Çözüldüyse düz metin kabul ediyoruz
            return "Plain Text", ".txt", "text/plain"
        except UnicodeDecodeError:
            pass

        # Bilinmeyen genel ikili veri
        return "Unknown Binary", "", "application/octet-stream"

    def check_double_extension(self, file_name: str) -> Tuple[bool, str]:
        """
        Dosya adında birden fazla uzantı olup olmadığını ve gizli çalıştırma
        amacı taşıyıp taşımadığını denetler (Örn: fatura.pdf.exe).
        """
        # Dosya adını noktalara göre parçalıyoruz
        parts = file_name.split(".")
        # İkiden fazla parça varsa (Örn: ['fatura', 'pdf', 'exe'])
        if len(parts) >= 3:
            last_ext = "." + parts[-1].lower()
            prev_ext = "." + parts[-2].lower()
            # Son uzantı çalıştırılabilir iken önceki masum bir doküman uzantısı ise
            if last_ext in self.EXECUTABLE_EXTENSIONS and prev_ext in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".xlsx"}:
                return True, f"CIFT_UZANTI_TESPITI: Dosya '{prev_ext}{last_ext}' seklinde gizlenmis calistirilabilir zararlidir."

        return False, "NORMAL_UZANTI"

    def inspect_file(
        self,
        file_path: str,
        reported_mime: Optional[str] = None,
        claimed_extension: Optional[str] = None
    ) -> FileInspectionResult:
        """
        Tek bir dosyayı fiziksel olarak açar; başlık baytlarını, boyutunu ve
        uzantısını inceleyerek kapsamlı güvenlik sonucunu oluşturur.
        """
        # Dosyanın varlığını sınıyoruz
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Incelenecek dosya diskte bulunamadi: {file_path}")

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # İddia edilen uzantıyı türetiyoruz
        derived_ext = os.path.splitext(file_name)[1].lower()
        effective_claimed_ext = claimed_extension.lower() if claimed_extension else derived_ext

        # Dosya başlığından ilk 32 baytı okuyoruz
        with open(file_path, "rb") as f:
            header = f.read(32)

        # Onaltılık gösterim oluşturuyoruz
        hex_dump = " ".join(f"{b:02X}" for b in header[:16])

        # Sihirli baytlardan gerçek türü tespit ediyoruz
        fmt_name, primary_ext, detected_mime = self.detect_magic_signature(header)

        # Çift uzantı kontrolü
        is_double, double_desc = self.check_double_extension(file_name)

        # Uzantı - İmza uyuşmazlığı kontrolü (Mismatch)
        is_mismatch = False
        risk_level = "CLEAN"
        finding_desc = "Dosya uzantisi ve baslik sihirli baytlari tam uyumludur."
        remediation = "Herhangi bir guvenlik mudahalesi gerekmemektedir."

        # Eğer çift uzantı varsa doğrudan HIGH seviyesine çekiyoruz
        if is_double:
            is_mismatch = True
            risk_level = "HIGH"
            finding_desc = double_desc
            remediation = "Dosyayi sakin calistirmayin! EDR veya Sandbox ortaminda karantinaya aliniz."

        # Uzantı masum görünüyor (.pdf, .jpg, .txt) ama başlık PE veya ELF ise: CRITICAL
        is_executable_header = "Executable" in fmt_name
        is_benign_extension = effective_claimed_ext in {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".csv", ".doc"}

        if is_executable_header and is_benign_extension:
            is_mismatch = True
            risk_level = "CRITICAL"
            finding_desc = (
                f"KRITIK TEHDIT: Dosya '{effective_claimed_ext}' uzantisina sahip gorunmesine karsin, "
                f"baslik baytlari '{fmt_name}' ({hex_dump}) calistirilabilir ikili programdir! "
                f"Bu yontem (Extension Spoofing) saldirganlar tarafindan kullanicilari aldatmak icin kullanilir."
            )
            remediation = (
                f"Dosyayi derhal karantinaya alin. Dosya sisteminde ve web yukleme alanlarinda "
                f"yalnizca dosya uzantisina guvenen filtreleri kaldirip 'Magic Bytes' dogrulamasini zorunlu kilin."
            )
        elif primary_ext and effective_claimed_ext != primary_ext and not is_double:
            # Genel zararsız uyuşmazlıklar (Örn: .jpg yerine .png yazılmış)
            if fmt_name != "Plain Text" and fmt_name != "Empty File":
                is_mismatch = True
                risk_level = "MEDIUM"
                finding_desc = (
                    f"UZANTI UYUSMAZLIGI: Dosya uzantisi '{effective_claimed_ext}', "
                    f"ancak baslik imzasi '{fmt_name}' ({primary_ext}) bicimindedir."
                )
                remediation = "Dosya uzantisini gercek bicimine uygun olarak yeniden adlandiriniz."

        # Sonuç nesnesini inşa ediyoruz
        result = FileInspectionResult(
            file_name=file_name,
            file_path=file_path,
            claimed_extension=effective_claimed_ext,
            detected_format=fmt_name,
            detected_mime=detected_mime,
            reported_mime=reported_mime or detected_mime,
            header_hex=hex_dump,
            size_bytes=file_size,
            is_mismatch=is_mismatch,
            is_double_extension=is_double,
            risk_level=risk_level,
            finding_description=finding_desc,
            remediation=remediation
        )

        return result

    def validate_manifest_entry(self, entry: Any) -> Tuple[bool, str]:
        """Envanter girdisinin şema bütünlüğünü kontrol eder."""
        if not isinstance(entry, dict):
            return False, "KAYIT_SOZLUK_DEGIL: Girdi bir JSON objesi olmalidir."

        for req in ["file_name", "relative_path"]:
            if req not in entry:
                return False, f"EKSIK_ALAN: '{req}' alani zorunludur."

        name_str = str(entry.get("file_name", "")).strip()
        if not name_str:
            return False, "GECERSIZ_ISIM: Dosya adi bos olamaz."

        path_str = str(entry.get("relative_path", "")).strip()
        if not path_str:
            return False, "GECERSIZ_YOL: Dosya yolu bos olamaz."

        return True, "GECERLI"

    def load_inventory_and_analyze(self, inventory_path: str, root_dir: str) -> Dict[str, Any]:
        """Envanter dosyasını okuyup içindeki tüm dosyaları fiziksel olarak inceler."""
        if not os.path.exists(inventory_path):
            raise FileNotFoundError(f"Envanter dosyasi bulunamadi: {inventory_path}")

        with open(inventory_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError("Envanter veri yapisi liste olmalidir.")

        self.results = []
        self.corrupted_records = []

        for item in raw_data:
            is_valid, reason = self.validate_manifest_entry(item)
            if not is_valid:
                self.corrupted_records.append({"item": item, "reason": reason})
                continue

            rel_p = str(item.get("relative_path", "")).strip().replace("/", os.sep)
            full_disk_p = os.path.join(root_dir, rel_p)

            # Dosya fiziksel olarak yoksa hata kaydına al
            if not os.path.exists(full_disk_p):
                self.corrupted_records.append({"item": item, "reason": f"DOSYA_YOK: '{full_disk_p}'"})
                continue

            reported_m = item.get("reported_mime")
            claimed_e = item.get("claimed_extension")

            res = self.inspect_file(full_disk_p, reported_mime=reported_m, claimed_extension=claimed_e)
            self.results.append(res)

        return {
            "total_analyzed": len(self.results),
            "corrupted_records": len(self.corrupted_records),
            "mismatch_count": sum(1 for r in self.results if r.is_mismatch),
            "critical_threats": sum(1 for r in self.results if r.risk_level == "CRITICAL"),
            "high_threats": sum(1 for r in self.results if r.risk_level == "HIGH"),
            "results": [asdict(r) for r in self.results]
        }

    def generate_ascii_report(self) -> str:
        """Denetim bulgularını tablo biçiminde ASCII metin olarak üretir."""
        lines: List[str] = []
        lines.append("=" * 85)
        lines.append("DOSYA TÜRLERİ, METADATA VE MIME GÜVENLİK ANALİZ RAPORU")
        lines.append("=" * 85)
        lines.append(f"İncelenen Toplam Dosya  : {len(self.results)}")
        lines.append(f"Reddedilen Bozuk Kayıt : {len(self.corrupted_records)}")
        lines.append(f"Uzantı/İmza Uyuşmazlığı: {sum(1 for r in self.results if r.is_mismatch)}")
        lines.append(f"Kritik Güvenlik Tehdidi: {sum(1 for r in self.results if r.risk_level == 'CRITICAL')}")
        lines.append("-" * 85)

        for idx, res in enumerate(self.results, 1):
            flag = " [!] UYUSMAZLIK" if res.is_mismatch else " [OK] TEMIZ"
            lines.append(f"\n({idx}) {res.file_name:<25} | Risk: {res.risk_level:<8} |{flag}")
            lines.append(f"    İddia Edilen Uzantı : {res.claimed_extension}")
            lines.append(f"    Gerçek Biçim (Magic): {res.detected_format} ({res.detected_mime})")
            lines.append(f"    İlk 16 Bayt (Hex)   : {res.header_hex}")
            lines.append(f"    Dosya Boyutu        : {res.size_bytes} bayt")
            if res.is_mismatch:
                lines.append(f"    Güvenlik Analizi    : {res.finding_description}")
                lines.append(f"    Önerilen Aksiyon    : {res.remediation}")

        if self.corrupted_records:
            lines.append("\n" + "-" * 85)
            lines.append("REDDEDİLEN BOZUK VERİLER (NEGATİF KONTROL):")
            for idx, c in enumerate(self.corrupted_records, 1):
                lines.append(f"  [{idx}] Neden: {c['reason']}")

        lines.append("=" * 85)
        return "\n".join(lines)


def main() -> None:
    """Komut satırından çalıştırma fonksiyonu."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inv_path = os.path.join(base_dir, "ornek_veri", "sample_file_type_inventory.json")
    root_p = os.path.join(base_dir, "ornek_veri")

    analyzer = FileMetadataMimeAnalyzer()
    if os.path.exists(inv_path):
        analyzer.load_inventory_and_analyze(inv_path, root_p)
        print(analyzer.generate_ascii_report())
    else:
        print(f"Hata: Envanter dosyası bulunamadı: {inv_path}")


if __name__ == "__main__":
    main()
