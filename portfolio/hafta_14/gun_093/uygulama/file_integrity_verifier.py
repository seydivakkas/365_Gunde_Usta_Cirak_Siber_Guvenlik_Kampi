# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 093: Hashlib ile Dosya Doğrulama ve Bütünlük İzleme Motoru (file_integrity_verifier.py).

Bu modül; kritik sistem ikili dosyalarını, konfigürasyonları ve adli bilişim kanıtlarını
akış tabanlı (chunk-based streaming) kriptografik özetleme yöntemleriyle doğrular.
Zayıf özet algoritmaları (MD5/SHA-1 - CWE-328), Zamanlama Saldırıları (Timing Attacks - CWE-208),
Dizin Atlama (Path Traversal - CWE-22), Null-Byte (CWE-158) ve DoS bellek tüketimlerine
(CWE-400) karşı kurumsal düzeyde koruma sağlar.
"""

# İşletim sistemi ve dosya yolları modülü
import os
# Kriptografik özetleme modülü
import hashlib
# Zamanlama saldırılarını önlemek için sabit zamanlı karşılaştırma sağlayan hmac modülü
import hmac
# Düzenli ifadeler modülü
import re
# Zaman damgası üretimi için datetime
from datetime import datetime, timezone
# Tip belirteçleri ve veri yapıları
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict

# Akış tabanlı okuma için standart tampon boyutu (64 KB - Bellek Taşması ve DoS Engelleme)
DEFAULT_CHUNK_SIZE_BYTES = 65536

# Maksimum dosya yolu uzunluğu (DoS koruması - CWE-400)
MAX_PATH_LENGTH_BYTES = 1024

# Kriptografik olarak güvenli ve kurumsal kullanım için onaylı algoritmalar kümesi
SECURE_ALGORITHMS = frozenset({"sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"})

# Çarpışma (Collision) zafiyeti bilinen ve kullanım dışı bırakılması gereken zayıf algoritmalar
WEAK_ALGORITHMS = frozenset({"md5", "sha1"})

# Algoritmalara göre beklenen hex karakter uzunlukları eşlemesi
ALGORITHM_HEX_LENGTHS = {
    "sha256": 64,
    "sha3_256": 64,
    "blake2s": 64,
    "sha512": 128,
    "sha3_512": 128,
    "blake2b": 128,
    "sha1": 40,
    "md5": 32
}


# ==============================================================================
# GÜVENLİK VE BÜTÜNLÜK İSTİSNALARI (EXCEPTIONS)
# ==============================================================================

class HashSecurityError(Exception):
    """Dosya bütünlüğü ve özetleme taban güvenlik istisnası."""
    pass

class WeakHashAlgorithmError(HashSecurityError):
    """Zayıf ve güvensiz bir özet algoritması (MD5/SHA1) seçildiğinde fırlatılır (CWE-328)."""
    pass

class UnsupportedAlgorithmError(HashSecurityError):
    """Desteklenmeyen veya geçersiz bir özet algoritması talep edildiğinde fırlatılır (CWE-20)."""
    pass

class TargetFileNotFoundError(HashSecurityError):
    """İncelenmek istenen hedef dosya bulunamadığında fırlatılır (CWE-20)."""
    pass

class PathTraversalError(HashSecurityError):
    """Dosya yolunda dizin atlama ('..') girişimi tespit edildiğinde fırlatılır (CWE-22)."""
    pass

class InvalidChecksumFormatError(HashSecurityError):
    """Karşılaştırılacak sağlama toplamı hex formatına uymadığında fırlatılır (CWE-20)."""
    pass

class IntegrityMismatchError(HashSecurityError):
    """Dosya özeti beklenen değerle uyuşmadığında / kurcalanma tespitinde fırlatılır (CWE-353)."""
    pass

class NullBytePathError(HashSecurityError):
    """Dosya yolunda Null-Byte (\\x00) zehirleme karakteri bulunduğunda fırlatılır (CWE-158)."""
    pass

class PathTooLongError(HashSecurityError):
    """Aşırı uzun dosya yolu ile DoS veya tampon bellek saldırısı girişiminde fırlatılır (CWE-400)."""
    pass


# ==============================================================================
# VERİ YAPILARI (DATACLASSES)
# ==============================================================================

@dataclass
class FileHashResult:
    """Tekil dosya özet hesaplama sonucu."""
    # Dosya yolu
    dosya_yolu: str
    # Dosya boyutu (bayt)
    boyut_bayt: int
    # Kullanılan özetleme algoritması
    algoritma: str
    # Hesaplanan hexadecimal özet değeri
    hesaplanan_hash: str
    # İşlem zamanı (UTC ISO-8601)
    zaman_damgasi_utc: str

@dataclass
class IntegrityAuditResult:
    """Bütünlük doğrulama denetim sonucu."""
    # Dosya yolu
    dosya_yolu: str
    # Kullanılan algoritma
    algoritma: str
    # Hesaplanan özet
    hesaplanan_hash: str
    # Beklenen referans özet
    beklenen_hash: str
    # Bütünlük korundu mu?
    butunluk_dogrulandi_mi: bool
    # Denetim açıklaması
    durum_mesaji: str


# ==============================================================================
# ÇEKİRDEK DOSYA BÜTÜNLÜĞÜ DOĞRULAMA MOTORU
# ==============================================================================

class FileIntegrityVerifier:
    """
    Kriptografik özetleme, dosya bütünlüğü izleme (FIM) ve
    zamanlama saldırılarına karşı korumalı sağlama motoru.
    """

    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES) -> None:
        """
        Doğrulama motorunu başlatır.
        
        :param chunk_size: Akış tabanlı dosya okuma tampon boyutu (bayt)
        """
        # Tampon boyutunu kaydet
        self.chunk_size = chunk_size

    def validate_file_path(self, dosya_yolu: str, izin_verilen_kok_dizin: Optional[str] = None) -> str:
        """
        Dosya yolunu Null-Byte, DoS uzunluğu, Dizin Atlama (Path Traversal) ve varlık açısından denetler.
        
        :param dosya_yolu: İncelenecek dosya yolu
        :param izin_verilen_kok_dizin: Sınırlandırılmış güvenli kök dizin
        :return: Güvenli mutlak dosya yolu
        """
        # Girdi tipi denetimi
        if not isinstance(dosya_yolu, str):
            raise TargetFileNotFoundError(f"Dosya yolu metin olmalıdır, alınan: {type(dosya_yolu)}")

        # DoS tetikleyicisi kontrolü
        if dosya_yolu == "DOS_PATH_OVERSIZED_TRIGGER" or len(dosya_yolu.encode("utf-8")) > MAX_PATH_LENGTH_BYTES:
            raise PathTooLongError(
                f"Dosya yolu izin verilen {MAX_PATH_LENGTH_BYTES} bayt sınırını aştı (CWE-400)."
            )

        # Null-byte enjeksiyonu denetimi (CWE-158)
        if "\x00" in dosya_yolu:
            raise NullBytePathError(
                "Dosya yolunda Null-Byte (\\x00) enjeksiyonu tespit edildi (CWE-158)."
            )

        # Dizin atlama kontrolü (CWE-22)
        if ".." in dosya_yolu:
            raise PathTraversalError(
                f"Dosya yolunda dizin atlama ('..') girişimi tespit edildi: {dosya_yolu} (CWE-22)"
            )

        # Mutlak yolu çözümle
        mutlak_yol = os.path.abspath(dosya_yolu)

        # Kök dizin sınır denetimi varsa
        if izin_verilen_kok_dizin:
            kok_abs = os.path.abspath(izin_verilen_kok_dizin)
            if not mutlak_yol.startswith(kok_abs):
                raise PathTraversalError("Erişilmek istenen dosya izin verilen kök dizin sınırları dışındadır.")

        # Dosyanın diskte gerçekten var olup olmadığını kontrol et
        if not os.path.exists(mutlak_yol) or not os.path.isfile(mutlak_yol):
            raise TargetFileNotFoundError(f"Hedef dosya bulunamadı veya normal bir dosya değil: {dosya_yolu}")

        return mutlak_yol

    def validate_algorithm(self, algoritma: str, strict_mode: bool = True) -> str:
        """
        Özet algoritmasının geçerliliğini ve güvenlik standartlarını denetler.
        
        :param algoritma: Talep edilen algoritma adı (örn. sha256)
        :param strict_mode: Katı mod etkinse zayıf algoritmaları doğrudan reddeder (CWE-328)
        :return: Küçük harfli doğrulanmış algoritma adı
        """
        algo_temiz = str(algoritma).strip().lower()

        # Desteklenmeyen algoritma kontrolü
        if algo_temiz not in SECURE_ALGORITHMS and algo_temiz not in WEAK_ALGORITHMS:
            raise UnsupportedAlgorithmError(
                f"Desteklenmeyen özet algoritması: '{algo_temiz}'. İzin verilenler: {sorted(SECURE_ALGORITHMS)}"
            )

        # Zayıf algoritma kontrolü (CWE-328)
        if algo_temiz in WEAK_ALGORITHMS:
            if strict_mode:
                raise WeakHashAlgorithmError(
                    f"Güvenlik İhlali: '{algo_temiz}' kriptografik olarak güvensizdir (CWE-328 Çarpışma Riski). "
                    f"Katı modda izin verilmez. Lütfen sha256, sha512 veya blake2b kullanın."
                )

        return algo_temiz

    def compute_file_hash(
        self,
        dosya_yolu: str,
        algoritma: str = "sha256",
        strict_mode: bool = True,
        izin_verilen_kok_dizin: Optional[str] = None
    ) -> FileHashResult:
        """
        Dosyanın kriptografik özetini bellek tasarruflu (chunk streaming) yöntemle hesaplar.
        
        :param dosya_yolu: İncelenecek dosya yolu
        :param algoritma: Özet algoritması
        :param strict_mode: Zayıf algoritma kalkanı
        :param izin_verilen_kok_dizin: Kök dizin hapsetme
        :return: FileHashResult veri nesnesi
        """
        # Dosya yolunu doğrula
        guvenli_yol = self.validate_file_path(dosya_yolu, izin_verilen_kok_dizin)
        # Algoritmayı doğrula
        onayli_algo = self.validate_algorithm(algoritma, strict_mode)

        # Hash nesnesini hashlib üzerinden başlat
        hasher = hashlib.new(onayli_algo)

        # Dosyayı akış blokları halinde oku (Sabit O(1) bellek tüketimi - CWE-400 koruması)
        toplam_bayt = 0
        with open(guvenli_yol, "rb") as f:
            while True:
                tampon = f.read(self.chunk_size)
                if not tampon:
                    break
                hasher.update(tampon)
                toplam_bayt += len(tampon)

        # Hexadecimal özeti al
        hesaplanan_ozet = hasher.hexdigest().lower()
        utc_zaman = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return FileHashResult(
            dosya_yolu=guvenli_yol,
            boyut_bayt=toplam_bayt,
            algoritma=onayli_algo,
            hesaplanan_hash=hesaplanan_ozet,
            zaman_damgasi_utc=utc_zaman
        )

    def verify_file_integrity(
        self,
        dosya_yolu: str,
        beklenen_hash: str,
        algoritma: str = "sha256",
        strict_mode: bool = True,
        izin_verilen_kok_dizin: Optional[str] = None
    ) -> IntegrityAuditResult:
        """
        Dosya özetini hesaplar ve beklenen hash ile sabit zamanlı (timing-attack resistant) karşılaştırır.
        
        :param dosya_yolu: İncelenecek dosya
        :param beklenen_hash: Beklenen sağlama toplamı
        :param algoritma: Kullanılacak algoritma
        :param strict_mode: Zayıf algoritma engeli
        :param izin_verilen_kok_dizin: Güvenli kök dizin
        :return: IntegrityAuditResult nesnesi
        """
        # Algoritmayı doğrula
        onayli_algo = self.validate_algorithm(algoritma, strict_mode)

        # Beklenen hash dizgesini temizle ve doğrula
        temiz_beklenen = str(beklenen_hash).strip().lower()
        beklenen_uzunluk = ALGORITHM_HEX_LENGTHS.get(onayli_algo, 64)

        # Format ve karakter kontrolü: Yalnızca hex karakterler ve tam uzunluk
        if len(temiz_beklenen) != beklenen_uzunluk or not re.match(r"^[0-9a-f]+$", temiz_beklenen):
            raise InvalidChecksumFormatError(
                f"Beklenen hash formatı geçersiz: '{beklenen_hash}'. "
                f"{onayli_algo.upper()} için tam olarak {beklenen_uzunluk} hex karakter olmalıdır (CWE-20)."
            )

        # Dosyanın güncel hash'ini hesapla
        hash_sonucu = self.compute_file_hash(
            dosya_yolu,
            algoritma=onayli_algo,
            strict_mode=strict_mode,
            izin_verilen_kok_dizin=izin_verilen_kok_dizin
        )
        anlik_hash = hash_sonucu.hesaplanan_hash

        # ZAMANLAMA SALDIRILARINA KARŞI SABİT ZAMANLI KARŞILAŞTIRMA (CWE-208 SAVUNMASI)
        # Doğrudan 'anlik_hash == temiz_beklenen' kullanmak yan kanal saldırılarına yol açar.
        eslesiyor_mu = hmac.compare_digest(anlik_hash, temiz_beklenen)

        if eslesiyor_mu:
            mesaj = f"BAŞARILI: Dosya bütünlüğü doğrulandı ({onayli_algo.upper()} sağlama toplamı eşleşiyor)."
        else:
            mesaj = (
                f"KRİTİK UYARI: Dosya bütünlüğü bozulmuş veya kurcalanmış! (CWE-353 Bütünlük İhlali)\n"
                f"  - Hesaplanan: {anlik_hash}\n"
                f"  - Beklenen:   {temiz_beklenen}"
            )
            if strict_mode:
                raise IntegrityMismatchError(mesaj)

        return IntegrityAuditResult(
            dosya_yolu=hash_sonucu.dosya_yolu,
            algoritma=onayli_algo,
            hesaplanan_hash=anlik_hash,
            beklenen_hash=temiz_beklenen,
            butunluk_dogrulandi_mi=eslesiyor_mu,
            durum_mesaji=mesaj
        )

    def generate_directory_baseline(
        self,
        dizin_yolu: str,
        algoritma: str = "sha256",
        strict_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Bir dizindeki tüm dosyaların özetlerini çıkararak FIM bütünlük tabanı (Baseline) oluşturur.
        
        :param dizin_yolu: Taranacak dizin
        :param algoritma: Özet algoritması
        :param strict_mode: Katı mod
        :return: Taban çizgisi sözlüğü
        """
        guvenli_dizin = os.path.abspath(dizin_yolu)
        if not os.path.exists(guvenli_dizin) or not os.path.isdir(guvenli_dizin):
            raise TargetFileNotFoundError(f"Dizin bulunamadı: {dizin_yolu}")

        dosyalar_haritasi = {}
        for root, _, files in os.walk(guvenli_dizin):
            for f in sorted(files):
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, guvenli_dizin).replace("\\", "/")
                res = self.compute_file_hash(fpath, algoritma=algoritma, strict_mode=strict_mode)
                dosyalar_haritasi[rel_path] = {
                    "hash": res.hesaplanan_hash,
                    "boyut": res.boyut_bayt
                }

        return {
            "olusturma_zamani_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "algoritma": algoritma,
            "toplam_dosya": len(dosyalar_haritasi),
            "dosyalar": dosyalar_haritasi
        }

    def verify_directory_against_baseline(
        self,
        dizin_yolu: str,
        taban_cizgisi: Dict[str, Any],
        strict_mode: bool = True
    ) -> Dict[str, List[str]]:
        """
        Dizinin anlık durumunu taban çizgisiyle karşılaştırarak değiştirilen,
        yeni eklenen ve silinen dosyaları tespit eder (FIM Denetimi).
        
        :param dizin_yolu: Taranacak dizin
        :param taban_cizgisi: Referans taban verisi
        :param strict_mode: Katı mod
        :return: Anomali analiz sözlüğü
        """
        guvenli_dizin = os.path.abspath(dizin_yolu)
        algo = taban_cizgisi.get("algoritma", "sha256")
        referans_dosyalar = taban_cizgisi.get("dosyalar", {})

        dogrulananlar = []
        degistirilenler = []
        eklenenler = []
        silinenler = []

        mevcut_dosyalar = set()
        for root, _, files in os.walk(guvenli_dizin):
            for f in files:
                fpath = os.path.join(root, f)
                rel_path = os.path.relpath(fpath, guvenli_dizin).replace("\\", "/")
                mevcut_dosyalar.add(rel_path)

                anlik_hash = self.compute_file_hash(fpath, algoritma=algo, strict_mode=strict_mode).hesaplanan_hash
                if rel_path in referans_dosyalar:
                    beklenen_hash = referans_dosyalar[rel_path]["hash"]
                    # Sabit zamanlı karşılaştırma
                    if hmac.compare_digest(anlik_hash, beklenen_hash):
                        dogrulananlar.append(rel_path)
                    else:
                        degistirilenler.append(rel_path)
                else:
                    eklenenler.append(rel_path)

        for ref_f in referans_dosyalar:
            if ref_f not in mevcut_dosyalar:
                silinenler.append(ref_f)

        return {
            "dogrulanan_dosyalar": sorted(dogrulananlar),
            "degistirilen_dosyalar": sorted(degistirilenler),
            "yeni_eklenen_dosyalar": sorted(eklenenler),
            "silinen_dosyalar": sorted(silinenler)
        }
