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
Gün 33: Dosya Hash ve Kriptografik Bütünlük Denetleyicisi
Bu modül; SHA-256 ve MD5 kriptografik özetleme algoritmaları ile dosya
bütünlüğünü (File Integrity Monitoring - FIM) denetler, yetkisiz dosya
modifikasyonlarını, yeni yetkisiz dosyaları ve silinen dosyaları tespit eder.
Ayrıca Çığ Etkisini (Avalanche Effect) ve özetlerin güvenilirlik sınırlarını analiz eder.
"""

# Dosya sistemi işlemleri ve yol yönetimi için standart os kütüphanesi
import os
# Komut satırı ve sistem yapılandırmaları için sys kütüphanesi
import sys
# JSON tabanlı taban çizgisi (baseline) serileştirmeleri için json modülü
import json
# Kriptografik özet fonksiyonları (SHA-256, MD5 vb.) için hashlib modülü
import hashlib
# Düzenli ifadeler ve girdi doğrulama için re modülü
import re
# Tip ipuçları ve statik tip denetimi için typing modülü
from typing import Dict, List, Any, Tuple, Optional
# Veri sınıfları oluşturmak için dataclass yapısı
from dataclasses import dataclass, field, asdict


@dataclass
class FileMetadata:
    """Tek bir dosyanın dosya sistemi ve kriptografik üstverilerini temsil eden model."""
    # Dosyanın adı (Örn: config.json)
    file_name: str
    # Denetim kök dizinine göre bağıl yolu (Örn: sample_files/config.json)
    relative_path: str
    # Dosyanın SHA-256 kriptografik özeti (64 onaltılık karakter)
    sha256: str
    # Dosyanın MD5 özeti (32 onaltılık karakter - geriye dönük uyumluluk)
    md5: str = ""
    # Dosyanın bayt cinsinden boyutu
    size_bytes: int = 0
    # Dosyanın taban çizgisindeki durumu (AUTHORIZED_BASELINE, UNTRACKED)
    status: str = "AUTHORIZED_BASELINE"


@dataclass
class IntegrityFinding:
    """Bütünlük denetimi sırasında saptanan anomali veya ihlali modelleyen sınıf."""
    # İhlale konu olan dosya yolu
    file_path: str
    # İhlal türü (INTEGRITY_COMPROMISED, FILE_MISSING, NEW_UNAUTHORIZED_FILE, TAMPERED_METADATA)
    finding_type: str
    # Güvenlik önem derecesi (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    severity: str
    # İhlalin teknik ve operasyonel açıklaması
    description: str
    # Taban çizgisinde beklenen kriptografik özet
    expected_hash: str = "N/A"
    # Disk üzerinde hesaplanan fiili kriptografik özet
    actual_hash: str = "N/A"
    # Güvenlik ihlaline karşı önerilen iyileştirme adımı
    remediation: str = ""


class FileIntegrityHashChecker:
    """
    Dosya hash hesaplama, taban çizgisi doğrulama, çığ etkisi ölçümü ve
    bütünlük izleme (FIM) işlevlerini yürüten temel denetleyici sınıfı.
    """

    # Desteklenen algoritmaların beklenen onaltılık (hex) karakter uzunlukları
    HASH_LENGTHS = {
        "sha256": 64,
        "sha1": 40,
        "md5": 32
    }

    def __init__(self) -> None:
        """Denetleyiciyi temiz bir taban çizgisi ve bulgu hafızasıyla başlatır."""
        # Taban çizgisi olarak kabul edilen yetkili dosyalar haritası {relative_path: FileMetadata}
        self.baseline_entries: Dict[str, FileMetadata] = {}
        # Bütünlük denetimi sonucunda tespit edilen bulguların listesi
        self.findings: List[IntegrityFinding] = []
        # Doğrulama sırasında reddedilen bozuk kayıtların günlüğü
        self.corrupted_records: List[Dict[str, Any]] = []

    def validate_hash_format(self, hash_str: Any, algorithm: str = "sha256") -> Tuple[bool, str]:
        """
        Kriptografik özet dizgisinin hex formatını ve uzunluğunu doğrular.
        Negatif kontroller ve bozuk veri koruması için kritik güvenlik katmanıdır.
        """
        # Girdinin metinsel bir ifade olup olmadığını denetliyoruz
        if not isinstance(hash_str, str):
            # Metin değilse derhal reddediyoruz
            return False, "GECERSIZ_TIP: Hash degeri bir karakter dizisi (string) olmalidir."

        # Boşlukları temizliyoruz
        clean_hash = hash_str.strip().lower()

        # Boş veya salt boşluk kontrolü
        if not clean_hash:
            # Boş hash hatası
            return False, "BOS_HASH: Hash degeri bos veya yalnizca bosluk olamaz."

        # Algoritmanın desteklenip desteklenmediğini sınıyoruz
        algo_key = algorithm.lower()
        if algo_key not in self.HASH_LENGTHS:
            # Desteklenmeyen algoritma hatası
            return False, f"DESTEKLENMEYEN_ALGORITMA: '{algorithm}' algoritmasi tanimli degildir."

        # Beklenen uzunluğu alıyoruz
        expected_len = self.HASH_LENGTHS[algo_key]
        if len(clean_hash) != expected_len:
            # Uzunluk uyuşmazlığı hatası
            return False, f"HATALI_UZUNLUK: {algorithm.upper()} hash degeri tam {expected_len} karakter olmalidir."

        # Karakterlerin geçerli onaltılık (0-9, a-f) olduğunu regex ile sınıyoruz
        if not re.fullmatch(r"^[0-9a-f]+$", clean_hash):
            # Geçersiz hex karakteri hatası
            return False, "GECERSIZ_HEX: Hash degeri yalnizca onaltilik (0-9, a-f) karakterler icerebilir."

        # Bütün kontroller başarıyla geçildi
        return True, "GECERLI"

    def compute_file_hash(self, file_path: str, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
        """
        Büyük dosyaları dahi bellek tüketmeden (streaming chunks) güvenle özetler.
        Varsayılan olarak SHA-256 kullanır.
        """
        # Dosyanın diskte mevcut olup olmadığını sınıyoruz
        if not os.path.exists(file_path):
            # Bulunamadı hatası fırlatıyoruz
            raise FileNotFoundError(f"Ozetlenecek dosya bulunamadi: {file_path}")

        # Seçilen algoritma nesnesini dinamik başlatıyoruz
        algo_name = algorithm.lower()
        if algo_name == "sha256":
            hasher = hashlib.sha256()
        elif algo_name == "md5":
            hasher = hashlib.md5()
        elif algo_name == "sha1":
            hasher = hashlib.sha1()
        else:
            raise ValueError(f"Bilinmeyen hash algoritmasi: {algorithm}")

        # Dosyayı ikili (binary) okuma kipinde açıyoruz
        with open(file_path, "rb") as f:
            # Dosyayı 64 KB'lık parçalar halinde okuyoruz
            while True:
                # Blok veriyi okuyoruz
                chunk = f.read(chunk_size)
                # Okunacak veri kalmadıysa döngüden çıkıyoruz
                if not chunk:
                    break
                # Okunan bloğu hash nesnesine ekliyoruz
                hasher.update(chunk)

        # Onaltılık karakter dizisi (hexdigest) olarak sonucu döndürüyoruz
        return hasher.hexdigest().lower()

    def calculate_avalanche_effect(self, data_a: bytes, data_b: bytes) -> Dict[str, Any]:
        """
        İki veri kümesi arasındaki Çığ Etkisini (Avalanche Effect) bit düzeyinde ölçer.
        Kriptografik özet fonksiyonlarında tek 1 bitlik değişimin bile çıktı bitlerinin
        yaklaşık %50'sini rastgele değiştirmesi gerektiğini matematiksel olarak ispatlar.
        """
        # İlk verinin SHA-256 özetini çıkarıyoruz
        hash_a = hashlib.sha256(data_a).hexdigest()
        # İkinci verinin SHA-256 özetini çıkarıyoruz
        hash_b = hashlib.sha256(data_b).hexdigest()

        # 16'lık tabandaki özeti 256 bitlik ikili (binary) dizgiye dönüştürüyoruz
        bin_a = bin(int(hash_a, 16))[2:].zfill(256)
        bin_b = bin(int(hash_b, 16))[2:].zfill(256)

        # Farklı olan bit sayısını (Hamming Distance) hesaplıyoruz
        diff_bits = sum(bit_a != bit_b for bit_a, bit_b in zip(bin_a, bin_b))
        # Yüzdesel farkı hesaplıyoruz
        percentage = (diff_bits / 256.0) * 100.0

        # Metrikleri sözlük olarak geri dönüyoruz
        return {
            "hash_a": hash_a,
            "hash_b": hash_b,
            "total_bits": 256,
            "different_bits": diff_bits,
            "change_percentage": round(percentage, 2),
            "avalanche_proven": 40.0 <= percentage <= 60.0
        }

    def validate_baseline_entry(self, entry: Any) -> Tuple[bool, str]:
        """Taban çizgisi manifestosundaki tek bir kaydın bütünlüğünü doğrular."""
        # Girdinin sözlük olduğunu sınıyoruz
        if not isinstance(entry, dict):
            return False, "KAYIT_SOZLUK_DEGIL: Taban cizgisi kaydi sozluk olmalidir."

        # Zorunlu alanların kontrolü
        for req in ["relative_path", "sha256"]:
            if req not in entry:
                return False, f"EKSIK_ALAN: '{req}' alani zorunludur."

        # Yolun geçerliliğini denetliyoruz
        path_str = str(entry.get("relative_path", "")).strip()
        if not path_str:
            return False, "GECERSIZ_YOL: Dosya yolu bos olamaz."

        # Hash formatını denetliyoruz
        sha_val = entry.get("sha256")
        is_valid_hash, hash_msg = self.validate_hash_format(sha_val, "sha256")
        if not is_valid_hash:
            return False, f"GECERSIZ_HASH_FORMATI: {hash_msg}"

        return True, "GECERLI"

    def load_baseline(self, manifest_path: str) -> int:
        """Yetkili taban çizgisi dosyasını (baseline manifest JSON) yükler."""
        # Dosya varlığını denetliyoruz
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Taban cizgisi dosyasi bulunamadi: {manifest_path}")

        # JSON dosyasını okuyoruz
        with open(manifest_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Liste biçiminde olduğunu sınıyoruz
        if not isinstance(raw_data, list):
            raise ValueError("Taban cizgisi manifestosu bir liste formatinda olmalidir.")

        # Yüklenen geçerli girdi sayısı
        loaded = 0
        for item in raw_data:
            # Girdiyi doğruluyoruz
            is_valid, reason = self.validate_baseline_entry(item)
            if not is_valid:
                # Bozuk kayıt listesine ekliyoruz
                self.corrupted_records.append({"entry": item, "reason": reason})
                continue

            # Model nesnesini oluşturuyoruz
            rel_p = str(item.get("relative_path", "")).strip().replace("\\", "/")
            f_meta = FileMetadata(
                file_name=str(item.get("file_name", os.path.basename(rel_p))).strip(),
                relative_path=rel_p,
                sha256=str(item.get("sha256", "")).strip().lower(),
                md5=str(item.get("md5", "")).strip().lower(),
                size_bytes=int(item.get("size_bytes", 0)),
                status=str(item.get("status", "AUTHORIZED_BASELINE")).strip()
            )
            # Haritaya ekliyoruz
            self.baseline_entries[rel_p] = f_meta
            loaded += 1

        return loaded

    def verify_file_integrity(self, root_scan_dir: str) -> Dict[str, Any]:
        """
        Diskteki dosyaları taban çizgisiyle karşılaştırarak bütünlük ihlallerini,
        eksik dosyaları ve yetkisiz yeni dosyaları saptar.
        """
        # Bulgular listesini sıfırlıyoruz
        self.findings = []
        # Diskte bulunan ve taranan dosyaların kümesi
        scanned_files: List[str] = []

        # Taban çizgisi boşsa denetim yapılamaz
        if not self.baseline_entries:
            raise RuntimeError("Denetim yapabilmek icin once gecerli bir taban cizgisi yuklenmelidir.")

        # Kök dizin varlığını denetliyoruz
        if not os.path.exists(root_scan_dir):
            raise FileNotFoundError(f"Tarama kok dizini mevcut degil: {root_scan_dir}")

        # 1. Aşama: Taban çizgisindeki dosyaların diskteki durumunu denetle
        for rel_path, expected_meta in self.baseline_entries.items():
            # Diskteki tam yolu oluşturuyoruz
            full_disk_path = os.path.join(root_scan_dir, rel_path.replace("/", os.sep))

            # Dosya diskte mevcut değilse: FILE_MISSING
            if not os.path.exists(full_disk_path):
                finding = IntegrityFinding(
                    file_path=rel_path,
                    finding_type="FILE_MISSING",
                    severity="HIGH",
                    description=f"Taban cizgisinde yer alan yetkili dosya diskte bulunamadi: '{rel_path}'",
                    expected_hash=expected_meta.sha256,
                    actual_hash="FILE_NOT_FOUND",
                    remediation="Dosyayi yetkili yedekten geri yukleyin veya bilerek silindiyse taban cizgisini guncelleyin."
                )
                self.findings.append(finding)
                continue

            # Dosya diskte mevcut, fiili hash'ini hesaplıyoruz
            actual_sha = self.compute_file_hash(full_disk_path, "sha256")
            scanned_files.append(rel_path)

            # Hash eşleşmiyor ise: INTEGRITY_COMPROMISED
            if actual_sha != expected_meta.sha256:
                finding = IntegrityFinding(
                    file_path=rel_path,
                    finding_type="INTEGRITY_COMPROMISED",
                    severity="CRITICAL",
                    description=(
                        f"Dosya butunlugu ihlal edildi! Taban cizgisindeki SHA-256 ozeti ile "
                        f"diskteki fiili ozet uyusmuyor. Dosya yetkisizce degistirilmis olabilir."
                    ),
                    expected_hash=expected_meta.sha256,
                    actual_hash=actual_sha,
                    remediation="Sistemi agdan izole edin, dosya degisiklik kayitlarini inceleyin ve temiz yedekten donun."
                )
                self.findings.append(finding)

        # 2. Aşama: Diskte olup taban çizgisinde olmayan yetkisiz yeni dosyaları bul
        for root, dirs, files in os.walk(root_scan_dir):
            for f in files:
                full_p = os.path.join(root, f)
                rel_p = os.path.relpath(full_p, root_scan_dir).replace("\\", "/")

                # Dosya taban çizgisinde yer almıyorsa ve tarananlarda yoksa: NEW_UNAUTHORIZED_FILE
                if rel_p not in self.baseline_entries:
                    new_file_hash = self.compute_file_hash(full_p, "sha256")
                    finding = IntegrityFinding(
                        file_path=rel_p,
                        finding_type="NEW_UNAUTHORIZED_FILE",
                        severity="MEDIUM",
                        description=f"Taban cizgisinde tanimli olmayan yeni ve yetkisiz dosya saptandi: '{rel_p}'",
                        expected_hash="NONE (UNTRACKED)",
                        actual_hash=new_file_hash,
                        remediation="Yeni dosyayi analiz edin; yetkili ise taban cizgisine ekleyin, supheli ise karantinaya alin."
                    )
                    self.findings.append(finding)

        # Bütünlük denetim sonucunu özetleyen sözlüğü dönüyoruz
        return {
            "total_baseline_files": len(self.baseline_entries),
            "total_findings": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
            "integrity_status": "COMPROMISED" if self.findings else "VERIFIED_CLEAN"
        }

    def assess_trust_limitations(self, file_path: str, hash_str: str) -> Dict[str, Any]:
        """
        G033-SC1 Didaktik Gereksinimi:
        'Hash tek başına bir dosyanın güvenilir olduğunu söylemez.' ilkesini analiz eder.
        Kriptografik özet yalnızca kimlik ve bütünlük doğrular; kodun güvenilirliği
        için dijital imza, sertifika geçerliliği ve tehdit istihbaratı şarttır.
        """
        return {
            "file_path": file_path,
            "hash": hash_str,
            "integrity_verified": True,
            "is_trusted": False,
            "trust_rationale": (
                "Kriptografik hash (SHA-256), dosyanin degismedigini (butunluk) kanitlar; "
                "ancak dosyanin iceriginin kotu niyetli (malware) olup olmadigini tek basina "
                "belirleyemez. Zararli bir yazilim da mukemmel bir SHA-256 ozetine sahiptir. "
                "Guvenilirlik icin dijital imza, sertifika zinciri ve VirusTotal/EDR itibari gereklidir."
            )
        }

    def generate_integrity_report(self) -> str:
        """Denetim bulgularını okunabilir ASCII formatında raporlar."""
        lines: List[str] = []
        lines.append("=" * 80)
        lines.append("DOSYA HASH VE KRİPTOGRAFİK BÜTÜNLÜK DENETİM RAPORU (FIM)")
        lines.append("=" * 80)
        lines.append(f"Taban Çizgisindeki Yetkili Dosya Sayısı: {len(self.baseline_entries)}")
        lines.append(f"Reddedilen Bozuk Taban Çizgisi Kaydı   : {len(self.corrupted_records)}")
        lines.append(f"Toplam Tespit Edilen Bütünlük İhlali    : {len(self.findings)}")
        lines.append("-" * 80)

        if not self.findings:
            lines.append("TEBRİKLER: Tüm dosyalar yetkili taban çizgisiyle %100 uyuşmaktadır. Bütünlük tamdır.")
        else:
            lines.append("BULGULAR VE İHLAL DETAYLARI:")
            for idx, finding in enumerate(self.findings, 1):
                lines.append(f"\n[{idx}] [{finding.severity}] {finding.finding_type}")
                lines.append(f"    Dosya Yolu      : {finding.file_path}")
                lines.append(f"    Beklenen Hash   : {finding.expected_hash}")
                lines.append(f"    Hesaplanan Hash : {finding.actual_hash}")
                lines.append(f"    Açıklama        : {finding.description}")
                lines.append(f"    Önerilen Adım   : {finding.remediation}")

        if self.corrupted_records:
            lines.append("\n" + "-" * 80)
            lines.append("REDDEDİLEN BOZUK MANİFEST KAYITLARI (NEGATİF KONTROL):")
            for idx, rec in enumerate(self.corrupted_records, 1):
                lines.append(f"  ({idx}) Neden: {rec['reason']}")

        lines.append("=" * 80)
        return "\n".join(lines)


def main() -> None:
    """Komut satırı yürütme ve test fonksiyonu."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    manifest_p = os.path.join(base_dir, "ornek_veri", "sample_baseline_manifest.json")
    scan_dir = os.path.join(base_dir, "ornek_veri")

    checker = FileIntegrityHashChecker()
    if os.path.exists(manifest_p):
        checker.load_baseline(manifest_p)
        checker.verify_file_integrity(scan_dir)
        print(checker.generate_integrity_report())
    else:
        print(f"Hata: Taban cizgisi bulunamadi: {manifest_p}")


if __name__ == "__main__":
    main()
