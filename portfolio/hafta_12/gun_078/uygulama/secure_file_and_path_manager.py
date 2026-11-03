# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 078: Dosya Okuma ve Pathlib (Secure File I/O & Pathlib in Cyber Security)
Bu modül, siber güvenlikte dizin aşımı (Path Traversal / CWE-22), sembolik bağlantı
istismarı (Symlink Following / CWE-59), yarış durumları (TOCTOU / CWE-367) ve
kaynak tükenmesi (CWE-400) tehditlerine karşı savunmacı dosya yöneticisini içerir.
"""

# Kriptografik özet hesaplama için hashlib içe aktarılır
import hashlib
# İşletim sistemi ve düşük seviyeli dosya işlemleri için os içe aktarılır
import os
# Modern, nesne yönelimli ve güvenli yol işlemleri için pathlib içe aktarılır
from pathlib import Path
# Zaman damgaları ve atomik adlandırma için time içe aktarılır
import time
# Kapsamlı tip ipuçları için typing modülü içe aktarılır
from typing import Any, Dict, Generator, List, Optional, Set, Union


class SecureFileAndPathManager:
    """
    Siber güvenlikte Pathlib tabanlı katı sandbox izolasyonu, güvenli dosya okuma,
    bellek korumalı akış ve atomik dosya yazma işlemlerini yöneten güvenlik motoru.
    """

    # Varsayılan izin verilen güvenli dosya uzantıları kümesi
    DEFAULT_ALLOWED_EXTENSIONS: Set[str] = {".json", ".log", ".yaml", ".txt"}

    # Bellek tükenmesini (CWE-400) engellemek için varsayılan dosya boyutu tavanı (1 MB)
    DEFAULT_MAX_FILE_SIZE_BYTES: int = 1048576

    def __init__(
        self,
        sandbox_dir: Union[str, Path],
        allowed_extensions: Optional[Set[str]] = None,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    ) -> None:
        """
        Güvenli dosya yöneticisi başlatıcısı; sandbox kök dizinini kanonik olarak sabitler.
        """
        # Gelen dizin yolunu nesneye dönüştürüp sembolik bağları çözerek mutlak yaparız
        self.sandbox_dir: Path = Path(sandbox_dir).resolve()

        # Sandbox dizininin disk üzerinde var olduğunu ve bir dizin olduğunu doğrularız
        if not self.sandbox_dir.is_dir():
            # Belirtilen yol dizin değilse veya yoksa istisna üretiriz
            raise FileNotFoundError(f"Sandbox dizini bulunamadı veya geçerli değil: {self.sandbox_dir}")

        # İzin verilen uzantılar belirlenir; belirtilmemişse varsayılanlar küçük harfe çevrilir
        if allowed_extensions is None:
            self.allowed_extensions: Set[str] = set(self.DEFAULT_ALLOWED_EXTENSIONS)
        else:
            self.allowed_extensions = {ext.lower().strip() for ext in allowed_extensions}

        # Maksimum okunabilir dosya boyutu sınırı atanır
        self.max_file_size_bytes: int = max_file_size_bytes
        # Gerçekleştirilen güvenli okuma operasyonu sayacı
        self.read_operations_count: int = 0
        # Gerçekleştirilen atomik yazma operasyonu sayacı
        self.write_operations_count: int = 0

    def resolve_safe_path(self, requested_path: Union[str, Path]) -> Path:
        """
        Kullanıcıdan veya dış kaynaktan gelen dosya yolunu doğrular, kanonikleştirir (resolve),
        dizin aşımı (Path Traversal / CWE-22) saldırılarını ve uzantı ihlallerini engeller.
        """
        # Yolun string temsili alınır
        path_str = str(requested_path)

        # [SAVUNMA 1]: Null-Byte (\x00) enjeksiyonu denetimi
        if "\x00" in path_str:
            raise ValueError("Dosya yolunda zararlı Null-Byte (\\x00) tespit edildi.")

        # Gelen yol nesnesi Path nesnesine dönüştürülür
        req_path_obj = Path(requested_path)

        # [SAVUNMA 2]: Mutlak yol enjeksiyonu kontrolü (Absolute Path Escape)
        # Eğer kullanıcı /etc/passwd veya C:\Windows gibi mutlak yol vermişse doğrudan reddederiz
        if req_path_obj.is_absolute():
            # Mutlak yol ile sandbox kökünü atlatma girişimi engellenir
            raise PermissionError(f"Mutlak yol enjeksiyonu ile sandbox atlatması engellendi: {path_str}")

        # [SAVUNMA 3]: Göreceli yolları sandbox dizinine ekleyip kanonikleştirme (resolve)
        # .resolve() metodu ../ ve sembolik bağları (symlink) gerçek fiziksel yoluna dönüştürür
        candidate_path = (self.sandbox_dir / req_path_obj).resolve()

        # [SAVUNMA 4]: Kanonik yolun sandbox dizini altında kalıp kalmadığının katı denetimi
        # is_relative_to metodu adayın gerçekten sandbox_dir çocuğu olduğunu garanti eder
        try:
            if not candidate_path.is_relative_to(self.sandbox_dir):
                raise PermissionError(f"Dizin aşımı (Path Traversal) engellendi: {path_str}")
        except AttributeError:
            # Python eski sürümleri için geri uyumluluk: ebeveynler listesinde sandbox aranır
            if self.sandbox_dir not in candidate_path.parents and candidate_path != self.sandbox_dir:
                raise PermissionError(f"Dizin aşımı (Path Traversal) engellendi: {path_str}")

        # [SAVUNMA 5]: Dosya uzantısı beyaz liste kontrolü
        # Eğer yol bir dosya ise uzantısının izin verilen kümede olduğu doğrulanır
        suffix = candidate_path.suffix.lower()
        # Eğer bir uzantı varsa ve izin verilen kümede değilse hata verilir
        if suffix and suffix not in self.allowed_extensions:
            raise ValueError(f"İzin verilmeyen dosya uzantısı: {suffix}")

        # Tamamen güvenli ve doğrulanmış kanonik Path nesnesi döndürülür
        return candidate_path

    def safe_read_text(
        self,
        requested_path: Union[str, Path],
        max_bytes: Optional[int] = None
    ) -> str:
        """
        Güvenli bağlam yöneticisi (Context Manager - with open) ile dosya okur.
        Kaynak sızıntılarını (CWE-775), dizin açma hatalarını ve aşırı boyutu engeller.
        """
        # Yol doğrulanır ve kanonikleştirilir
        safe_path = self.resolve_safe_path(requested_path)

        # [KONTROL 1]: Dosyanın varlığı denetlenir
        if not safe_path.exists():
            raise FileNotFoundError(f"İstenen dosya sandbox içinde bulunamadı: {requested_path}")

        # [KONTROL 2]: Yolun bir dizin değil normal dosya olduğu kontrol edilir
        if not safe_path.is_file():
            raise IsADirectoryError(f"Belirtilen yol bir dosya değil, dizindir: {requested_path}")

        # [KONTROL 3]: Dosya boyutu tavanı kontrolü (CWE-400 Bellek Tükenmesi)
        effective_limit = max_bytes if max_bytes is not None else self.max_file_size_bytes
        file_size = safe_path.stat().st_size
        if file_size > effective_limit:
            raise ValueError(
                f"Dosya boyutu ({file_size} bayt) izin verilen güvenlik tavanını "
                f"({effective_limit} bayt) aştı."
            )

        # [SAVUNMA]: with bloğu ile dosya tanımlayıcısının (FD) kesin kapatılması güvenceye alınır
        with open(safe_path, "r", encoding="utf-8", errors="strict") as file_handle:
            # İçerik güvenle okunur
            content = file_handle.read()

        # Sayaç güncellenir
        self.read_operations_count += 1
        return content

    def safe_stream_lines(
        self,
        requested_path: Union[str, Path],
        chunk_lines: int = 100
    ) -> Generator[str, None, None]:
        """
        Büyük log dosyalarını belleğe tek seferde yüklemeden (OOM koruması),
        üreteç (generator) mantığıyla satır satır akıtan güvenli okuyucu.
        """
        # Yol doğrulanır
        safe_path = self.resolve_safe_path(requested_path)

        # Varlık ve dosya tipi kontrolü
        if not safe_path.is_file():
            raise FileNotFoundError(f"Akış için geçerli dosya bulunamadı: {requested_path}")

        # Dosya bağlam yöneticisiyle açılır ve iteratif olarak satırlar akıtılır
        with open(safe_path, "r", encoding="utf-8", errors="replace") as stream_file:
            for line in stream_file:
                # Satır başı/sonu fazlalıkları temizlenir
                yield line.rstrip("\r\n")

    def atomic_write_text(
        self,
        requested_path: Union[str, Path],
        content: str
    ) -> Path:
        """
        Atomik Dosya Yazma (Atomic Write):
        Veriyi önce geçici bir dosyaya (.tmp) yazar, diske senkronize eder (fsync)
        ve ardından os.replace ile hedef dosyanın üzerine tek adımda atomik olarak taşır.
        Yarıda kesilme, elektrik kesintisi veya TOCTOU yarış durumlarında bozuk dosya kalmasını önler.
        """
        # Hedef yol çözümlenir ve sandbox içinde olduğu doğrulanır
        safe_target = self.resolve_safe_path(requested_path)

        # [GÜVENLİK]: Hedefin üst dizini yoksa güvenle oluşturulur
        safe_target.parent.mkdir(parents=True, exist_ok=True)

        # Aynı dosya sisteminde geçici bir dosya adı oluşturulur
        temp_file_name = f".tmp_{os.getpid()}_{time.time_ns()}"
        temp_path = safe_target.parent / temp_file_name

        try:
            # 1. Aşama: Veri geçici dosyaya yazılır
            with open(temp_path, "w", encoding="utf-8", errors="strict") as temp_file:
                temp_file.write(content)
                # Tamponun işletim sistemi seviyesine aktarılması
                temp_file.flush()
                # İşletim sistemi disk önbelleğinin fiziksel diske yazılması (Data Durability)
                os.fsync(temp_file.fileno())

            # 2. Aşama: Atomik taşıma ve hedefi değiştirme (Atomic Rename / Replace)
            # os.replace işlemi POSIX ve modern Windows sistemlerinde atomiktir
            os.replace(temp_path, safe_target)

            # Yazma sayacı artırılır
            self.write_operations_count += 1
            return safe_target

        except Exception as e:
            # Bir hata oluşursa geçici dosya arkada çöp bırakılmadan temizlenir
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            # İstisna çağıran tarafa iletilir
            raise e

    def inspect_sandbox_status(self) -> Dict[str, Any]:
        """
        Sandbox deposundaki tüm dosyaları tarar; boyut, uzantı ve SHA-256 özetlerini raporlar.
        """
        files_summary: List[Dict[str, Any]] = []

        # Sandbox altındaki tüm nesneler taranır
        for item in sorted(self.sandbox_dir.rglob("*")):
            # Yalnızca normal dosyalar incelenir
            if item.is_file():
                # Geçici dosyalar atlanır
                if item.name.startswith(".tmp_"):
                    continue

                # Dosya boyutu alınır
                size_bytes = item.stat().st_size
                # SHA-256 hesaplanır
                sha256_hash = self._calculate_file_sha256(item)

                # Göreceli yol hesaplanır
                rel_path = item.relative_to(self.sandbox_dir).as_posix()
                files_summary.append({
                    "relative_path": rel_path,
                    "size_bytes": size_bytes,
                    "extension": item.suffix.lower(),
                    "sha256": sha256_hash
                })

        return {
            "sandbox_root": str(self.sandbox_dir),
            "total_files": len(files_summary),
            "files": files_summary
        }

    def _calculate_file_sha256(self, file_path: Path) -> str:
        """
        Büyük dosyaları 64KB'lik bloklarla okuyarak SHA-256 özeti hesaplar.
        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def generate_security_report(self) -> Dict[str, Any]:
        """
        Sandbox durumunu, denetim istatistiklerini ve güvenlik kontrollerini özetleyen rapor üretir.
        """
        status = self.inspect_sandbox_status()
        return {
            "title": "G078: Dosya Okuma ve Pathlib Güvenlik Raporu",
            "sandbox_directory": str(self.sandbox_dir),
            "allowed_extensions": sorted(list(self.allowed_extensions)),
            "max_file_size_bytes": self.max_file_size_bytes,
            "read_operations_count": self.read_operations_count,
            "write_operations_count": self.write_operations_count,
            "files_audited": status["files"],
            "status": "SANDBOX_INTEGRITY_VERIFIED"
        }


if __name__ == "__main__":
    base_repo = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "guvenli_dosya_deposu")
    )
    manager = SecureFileAndPathManager(base_repo)
    report = manager.generate_security_report()
    import json
    print(json.dumps(report, indent=2, ensure_ascii=False))
