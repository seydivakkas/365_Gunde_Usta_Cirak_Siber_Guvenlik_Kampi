# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 090: Tarih-Saat, UTC ve Saat Dilimi Adli Bilişim Normalizasyon Motoru.

Bu modül; adli bilişim (DFIR), olay müdahalesi (IR) ve güvenlik log analizi süreçlerinde
farklı sunuculardan, işletim sistemlerinden ve coğrafi saat dilimlerinden toplanan zaman
damgalarını (ISO-8601, RFC-3339, Unix Epoch, Windows FileTime) sıfır bilgi kaybı ve mutlak
güvenilirlikle UTC standardına normalize eder. Saat sapması (Clock Skew) ve Replay Attack
risklerini tespit eder, naive (saat dilimsiz) zaman damgalarını engeller.
"""

# İşletim sistemi ve temel kütüphanelerin içe aktarılması
import os
# Düzenli ifadeler ile sözdizimi doğrulama modülü
import re
# Adli zaman hesaplamaları ve saat dilimi yönetimi için datetime sınıfları
from datetime import datetime, timezone, timedelta
# Tip belirteçleri ve veri yapıları
from typing import Dict, Any, List, Optional, Union
# Veri taşıma nesneleri için dataclass kütüphanesi
from dataclasses import dataclass, asdict

# Windows FileTime epoch başlangıcı ile Unix epoch (1970-01-01) arasındaki 100-nanosaniyelik aralık sabiti
WINDOWS_TICK = 10000000
# 1601-01-01 ile 1970-01-01 arasındaki farkın nanosaniye birimi (11644473600 saniye * 10^7)
SEC_TO_UNIX_EPOCH = 116444736000000000
# Kabul edilebilir en erken mantıklı adli bilişim yılı (Unix Epoch başlangıcı)
MIN_REASONABLE_YEAR = 1970
# Kabul edilebilir en uzak mantıklı adli bilişim yılı
MAX_REASONABLE_YEAR = 2050
# Maksimum girdi uzunluğu (DoS ve bellek tüketimi saldırılarını önlemek için)
MAX_TIMESTAMP_STRING_LEN = 128


# ==============================================================================
# GÜVENLİK VE AYRIŞTIRMA İSTİSNALARI (EXCEPTIONS)
# ==============================================================================

class TimestampSecurityError(Exception):
    """Zaman damgası güvenlik ve doğrulama taban istisnası."""
    pass

class NaiveTimestampError(TimestampSecurityError):
    """Saat dilimi veya UTC offset bilgisi içermeyen belirsiz zaman damgası istisnası (CWE-613)."""
    pass

class InvalidTimeRangeError(TimestampSecurityError):
    """Saat, dakika veya saniye sınır değerlerinin aşılması durumunda fırlatılır (CWE-20)."""
    pass

class InvalidCalendarDateError(TimestampSecurityError):
    """Takvimsel olarak var olmayan bir tarih girildiğinde fırlatılır (CWE-20)."""
    pass

class InvalidEpochValueError(TimestampSecurityError):
    """Negatif veya geçersiz Unix Epoch zaman damgası fırlatılır (CWE-20)."""
    pass

class UnreasonableDateRangeError(TimestampSecurityError):
    """Siber güvenlik analiz penceresi dışındaki aşırı uç tarihlerde fırlatılır (CWE-20)."""
    pass

class ClockSkewExceededError(TimestampSecurityError):
    """İstemci ve sunucu arasındaki saat sapması izin verilen eşiği aştığında fırlatılır (CWE-1385)."""
    pass

class MalformedTimestampError(TimestampSecurityError):
    """Format kurallarına uymayan bozuk zaman dizgilerinde fırlatılır (CWE-20)."""
    pass

class PayloadTooLargeError(TimestampSecurityError):
    """Aşırı uzun girdi ile tampon bellek veya DoS saldırısı girişimlerinde fırlatılır (CWE-400)."""
    pass

class InvalidFileTimeError(TimestampSecurityError):
    """Negatif veya taşmalı Windows FileTime değerlerinde fırlatılır (CWE-20)."""
    pass


# ==============================================================================
# VERİ YAPILARI (DATACLASSES)
# ==============================================================================

@dataclass
class NormalizedLogEvent:
    """Normalize edilmiş adli bilişim olay kaydı."""
    # Olayı üreten sunucu veya cihaz kimliği
    kaynak_id: str
    # Orijinal ham zaman damgası girdisi
    zaman_damgasi_orijinal: Any
    # UTC standardında ISO-8601 formatlanmış zaman dizgisi (örn: 2026-11-01T14:30:00Z)
    utc_zaman_damgasi: str
    # Unix epoch saniyesi (adli bilişim sıralaması için)
    unix_epoch_saniye: float
    # Orijinal saat diliminin UTC'den dakika cinsinden farkı
    saat_dilimi_offset_dakika: int
    # Zaman damgasının saat dilimi farkındalığına sahip olup olmadığı
    is_aware: bool
    # Güvenlik olayının tipi (AUTH, LOGOUT, QUERY vb.)
    olay_tipi: str
    # Olay açıklaması
    mesaj: str
    # Güvenlik risk derecesi (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    risk_seviyesi: str

@dataclass
class ClockSkewAuditResult:
    """İstemci-sunucu saat sapması ve Replay Attack denetim sonucu."""
    # İstemci tarafından beyan edilen zaman damgası
    istemci_zamani_utc: str
    # Referans alınan sunucu UTC zaman damgası
    referans_zamani_utc: str
    # Mutlak sapma farkı (saniye cinsinden)
    sapma_saniyesi: float
    # İzin verilen maksimum güvenlik eşiği (saniye cinsinden)
    maks_izin_verilen_sapma: int
    # Sapmanın güvenlik sınırları içerisinde kalıp kalmadığı
    sapma_guvenli_mi: bool
    # Denetim güvenlik değerlendirme hükmü
    hukum: str


# ==============================================================================
# ÇEKİRDEK ADLİ BİLİŞİM VE ZAMAN NORMALİZASYON MOTORU
# ==============================================================================

class UtcTimezoneForensicNormalizer:
    """
    Siber güvenlik logları ve olay müdahalesi süreçleri için
    saat dilimi normalizasyonu ve saat sapması güvenlik denetim motoru.
    """

    def __init__(self, varsayilan_maks_sapma: int = 300) -> None:
        """
        Normalizasyon motorunu başlatır.
        
        :param varsayilan_maks_sapma: Kerberos ve OAuth standartlarına uygun maksimum saat sapması toleransı (saniye)
        """
        # Maksimum kabul edilebilir saat sapması toleransını kaydet (Varsayılan 300 sn / 5 dakika)
        self.varsayilan_maks_sapma = varsayilan_maks_sapma

    def parse_iso_with_strict_tz(self, zaman_dizgisi: str) -> datetime:
        """
        ISO-8601 veya RFC-3339 biçimindeki zaman dizgisini sıkı saat dilimi kontrolüyle ayrıştırır.
        Naive (saat dilimsiz) zaman damgalarını güvenlik gereği reddeder.
        
        :param zaman_dizgisi: İncelenecek zaman metni
        :return: UTC'ye dönüştürülmüş timezone-aware datetime nesnesi
        """
        # Girdi tipinin string olup olmadığını kontrol et
        if not isinstance(zaman_dizgisi, str):
            # String olmayan tipleri derhal reddet
            raise MalformedTimestampError(f"Zaman damgası metin (str) olmalıdır, alınan: {type(zaman_dizgisi)}")

        # Girdi uzunluğunu kontrol ederek DoS saldırılarını engelle
        if len(zaman_dizgisi) > MAX_TIMESTAMP_STRING_LEN:
            # Belirlenen sınır aşıldığında DoS korumasını devreye sok
            raise PayloadTooLargeError(
                f"Zaman damgası uzunluğu izin verilen {MAX_TIMESTAMP_STRING_LEN} karakter sınırını aştı."
            )

        # Baş ve sondaki gereksiz boşlukları temizle
        temiz_dizgi = zaman_dizgisi.strip()

        # Temel ISO tarih başlangıç kontrolü (YYYY-MM-DD): Eğer temel tarih yapısı yoksa bozuk biçimdir
        if not re.match(r"^\d{4}-\d{2}-\d{2}", temiz_dizgi):
            # Sözdizimsel olarak tamamen bozuk girdi için MalformedTimestampError fırlat
            raise MalformedTimestampError(f"Geçersiz zaman damgası biçimi: '{temiz_dizgi}'")

        # Naive zaman damgası deseni: Temel tarih yapısı var ama 'Z' veya offset ('+' ya da '-') yoksa
        # Örnek: '2026-11-01 14:30:00' veya '2026-11-01T14:30:00'
        if not re.search(r"(Z|[+-]\d{2}:?\d{2})$", temiz_dizgi):
            # Saat dilimi içermeyen naive girdiler için CWE-613 istisnasını tetikle
            raise NaiveTimestampError(
                f"Naive zaman damgası tespit edildi: '{temiz_dizgi}'. Saat dilimi bilgisi (Z veya +HH:MM) zorunludur."
            )

        # Geçersiz saat/dakika/saniye sınırlarını regex ile ön denetimden geçir
        # Saat > 23, Dakika > 59, Saniye > 59 kontrolü
        saat_dakika_eslesme = re.search(r"T(\d{2}):(\d{2}):(\d{2})", temiz_dizgi)
        # Eğer saat-dakika-saniye bileşenleri bulunduysa
        if saat_dakika_eslesme:
            # Saat tamsayısını al
            saat = int(saat_dakika_eslesme.group(1))
            # Dakika tamsayısını al
            dakika = int(saat_dakika_eslesme.group(2))
            # Saniye tamsayısını al
            saniye = int(saat_dakika_eslesme.group(3))
            # Saat, dakika veya saniye mantık sınırlarını aşıyor mu denetle
            if saat > 23 or dakika > 59 or saniye > 59:
                # Geçersiz zaman aralığı istisnasını fırlat
                raise InvalidTimeRangeError(
                    f"Geçersiz saat/dakika/saniye değeri: {saat:02d}:{dakika:02d}:{saniye:02d}"
                )

        # ISO formatını datetime nesnesine dönüştürmeyi dene
        try:
            # Standart 'Z' karakterini Python 3.11+ uyumlu '+00:00' UTC offsetine çevir
            islenmis_dizgi = temiz_dizgi.replace("Z", "+00:00")
            # ISO 8601 ayrıştırmasını gerçekleştir
            ayristirilmis_dt = datetime.fromisoformat(islenmis_dizgi)
        except ValueError as val_err:
            # Hata metninde gün/ay uyumsuzluğu var mı incele (örn. Şubat 30)
            hata_mesaji = str(val_err).lower()
            # Eğer gün veya ay sınır hatası ise
            if "day is out of range for month" in hata_mesaji or "month" in hata_mesaji:
                # Takvimsel hata istisnasını fırlat
                raise InvalidCalendarDateError(f"Takvimsel olarak geçersiz tarih: {temiz_dizgi}")
            # Diğer tüm sözdizimsel bozukluklar için genel biçim hatası fırlat
            raise MalformedTimestampError(f"Ayrıştırılamayan zaman damgası formatı: {val_err}")

        # Tarihin adli bilişim mantık sınırları içerisinde olup olmadığını denetle
        if not (MIN_REASONABLE_YEAR <= ayristirilmis_dt.year <= MAX_REASONABLE_YEAR):
            # Aşırı uç tarih tespit edildiğinde istisna fırlat
            raise UnreasonableDateRangeError(
                f"Yıl değeri {ayristirilmis_dt.year} kabul edilebilir güvenlik penceresi [{MIN_REASONABLE_YEAR}-{MAX_REASONABLE_YEAR}] dışındadır."
            )

        # Kesin olarak UTC saat dilimine dönüştür ve döndür
        return ayristirilmis_dt.astimezone(timezone.utc)

    def convert_epoch_to_utc(self, epoch_degeri: Union[int, float]) -> datetime:
        """
        Unix Epoch zaman damgasını (saniye veya milisaniye cinsinden) güvenli bir şekilde UTC datetime'a dönüştürür.
        
        :param epoch_degeri: Saniye veya milisaniye cinsinden sayısal epoch
        :return: UTC datetime nesnesi
        """
        # Sayısal olmayan tipleri reddet
        if not isinstance(epoch_degeri, (int, float)):
            # Tip hatası istisnası fırlat
            raise InvalidEpochValueError(f"Epoch değeri sayısal olmalıdır, alınan: {type(epoch_degeri)}")

        # Negatif veya sıfır epoch değerlerini reddet (Adli bilişimde 1970 öncesi şüphelidir)
        if epoch_degeri <= 0:
            # Negatif değer istisnası fırlat
            raise InvalidEpochValueError(f"Epoch değeri pozitif olmalıdır, girilen: {epoch_degeri}")

        # Milisaniye biçiminde olup olmadığını kontrol et (13 haneli sayılar milisaniyedir)
        # Eğer değer 10^11 değerinden büyükse milisaniye olarak kabul et
        if epoch_degeri > 100000000000:
            # Milisaniyeyi saniyeye çevir
            saniye_degeri = epoch_degeri / 1000.0
        else:
            # Zaten saniye cinsinden
            saniye_degeri = float(epoch_degeri)

        # Epoch saniyesini datetime nesnesine dönüştür
        try:
            # UTC saat dilimiyle zaman damgasını oluştur
            dt_utc = datetime.fromtimestamp(saniye_degeri, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as err:
            # Taşma veya sistem hatası durumunda istisna fırlat
            raise InvalidEpochValueError(f"Epoch değeri dönüştürülemedi (taşma): {err}")

        # Yıl aralığını denetle
        if not (MIN_REASONABLE_YEAR <= dt_utc.year <= MAX_REASONABLE_YEAR):
            # Mantık dışı yıl istisnası
            raise UnreasonableDateRangeError(f"Epoch sonucu yıl {dt_utc.year} izin verilen aralık dışındadır.")

        # Başarıyla dönüştürülen UTC zamanını döndür
        return dt_utc

    def convert_filetime_to_utc(self, filetime_degeri: int) -> datetime:
        """
        Windows FileTime (1 Ocak 1601'den beri geçen 100-nanosaniyelik adımlar) değerini UTC'ye dönüştürür.
        
        :param filetime_degeri: 64-bit işaretsiz tamsayı
        :return: UTC datetime nesnesi
        """
        # Tamsayı tip kontrolü
        if not isinstance(filetime_degeri, int):
            # Tamsayı olmayan girdileri reddet
            raise InvalidFileTimeError(f"Windows FileTime tamsayı olmalıdır, alınan: {type(filetime_degeri)}")

        # Negatif FileTime değerlerini reddet
        if filetime_degeri <= 0:
            # Negatif değer istisnası fırlat
            raise InvalidFileTimeError(f"Windows FileTime pozitif bir tamsayı olmalıdır: {filetime_degeri}")

        # Unix epoch öncesi kontrolü: 1601 ile 1970 arasındaki farktan küçükse reddet
        if filetime_degeri < SEC_TO_UNIX_EPOCH:
            # 1970 öncesi Windows zaman damgası istisnası fırlat
            raise InvalidFileTimeError(f"FileTime Unix Epoch (1970) öncesini gösteremez: {filetime_degeri}")

        # FileTime'dan Unix saniyesine matematiksel dönüşüm
        try:
            # 100-nanosaniyelik adımları saniyeye indirge ve Unix farkını çıkar
            unix_saniye = (filetime_degeri - SEC_TO_UNIX_EPOCH) / WINDOWS_TICK
            # UTC datetime oluştur
            dt_utc = datetime.fromtimestamp(unix_saniye, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as err:
            # Taşma durumunda istisna fırlat
            raise InvalidFileTimeError(f"FileTime dönüştürme hatası: {err}")

        # Yıl aralığını denetle
        if not (MIN_REASONABLE_YEAR <= dt_utc.year <= MAX_REASONABLE_YEAR):
            # Mantıksız yıl uyarısı
            raise UnreasonableDateRangeError(f"FileTime sonucu yıl {dt_utc.year} adli pencere dışındadır.")

        # Sonucu döndür
        return dt_utc

    def audit_clock_skew(
        self,
        istemci_zamani: Union[datetime, str],
        referans_zamani: Optional[Union[datetime, str]] = None,
        maks_sapma_saniye: Optional[int] = None
    ) -> ClockSkewAuditResult:
        """
        İstemci zaman damgası ile yetkili sunucu referans zamanı arasındaki saat sapmasını (Clock Skew) denetler.
        Replay Attack ve Kerberos bilet sahteciliği riskini değerlendirir.
        
        :param istemci_zamani: İstemci tarafından gönderilen zaman damgası
        :param referans_zamani: Sunucu referans zamanı (None verilirse anlık sistem UTC zamanı alınır)
        :param maks_sapma_saniye: İzin verilen maksimum sapma toleransı (saniye)
        :return: Denetim sonucu nesnesi
        """
        # Maksimum sapma parametresini belirle
        limit_sapma = maks_sapma_saniye if maks_sapma_saniye is not None else self.varsayilan_maks_sapma

        # İstemci zamanı metin olarak verildiyse UTC datetime'a çevir
        if isinstance(istemci_zamani, str):
            # ISO ayrıştırma metodunu çağır
            istemci_dt = self.parse_iso_with_strict_tz(istemci_zamani)
        else:
            # Zaten datetime nesnesi ise saat dilimi kontrolü yap
            if istemci_zamani.tzinfo is None:
                # Naive datetime kabul edilemez
                raise NaiveTimestampError("İstemci zamanı saat dilimi bilgisi içermiyor (naive).")
            # UTC'ye dönüştür
            istemci_dt = istemci_zamani.astimezone(timezone.utc)

        # Referans zaman belirlenmemişse anlık sistem UTC zamanını al
        if referans_zamani is None:
            # Python 3.12+ standartlarına uygun timezone-aware utcnow alternatifi
            ref_dt = datetime.now(timezone.utc)
        elif isinstance(referans_zamani, str):
            # String olarak verildiyse ayrıştır
            ref_dt = self.parse_iso_with_strict_tz(referans_zamani)
        else:
            # Datetime nesnesi ise saat dilimi kontrolü yap
            if referans_zamani.tzinfo is None:
                # Naive referans kabul edilemez
                raise NaiveTimestampError("Referans zaman saat dilimi bilgisi içermiyor (naive).")
            # UTC'ye dönüştür
            ref_dt = referans_zamani.astimezone(timezone.utc)

        # İki zaman arasındaki mutlak zaman farkını (delta) saniye cinsinden hesapla
        zaman_farki = abs((istemci_dt - ref_dt).total_seconds())

        # Fark izin verilen limitin üzerinde mi kontrol et
        sapma_guvenli = zaman_farki <= limit_sapma

        # Güvenlik hükmünü oluştur
        if sapma_guvenli:
            # Güvenli tolerans aralığında
            hukum = f"GÜVENLİ: Saat sapması ({zaman_farki:.2f} sn) izin verilen {limit_sapma} sn sınırının altındadır."
        else:
            # Güvenlik eşiği aşıldı, potansiyel Replay Attack riski
            hukum = (
                f"KRİTİK GÜVENLİK İHLALİ: Saat sapması ({zaman_farki:.2f} sn) izin verilen "
                f"{limit_sapma} sn sınırını aştı! (CWE-1385 Replay Attack Riski)"
            )

        # Sonuç nesnesini paketle ve döndür
        return ClockSkewAuditResult(
            istemci_zamani_utc=istemci_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            referans_zamani_utc=ref_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            sapma_saniyesi=round(zaman_farki, 3),
            maks_izin_verilen_sapma=limit_sapma,
            sapma_guvenli_mi=sapma_guvenli,
            hukum=hukum
        )

    def normalize_log_entry(self, ham_kayit: Dict[str, Any]) -> NormalizedLogEvent:
        """
        Herhangi bir kaynaktan gelen ham log girdisini ayrıştırıp normalize edilmiş olay nesnesine dönüştürür.
        
        :param ham_kayit: Ham log sözlüğü
        :return: NormalizedLogEvent veri nesnesi
        """
        # Kaynak kimliğini al (yoksa UNKNOWN_SOURCE ata)
        kaynak_id = str(ham_kayit.get("kaynak_id", "UNKNOWN_SOURCE"))
        # Orijinal zaman damgası girdisini al
        ham_zaman = ham_kayit.get("zaman_damgasi_orijinal")
        # Zaman formatı bilgisini al
        format_tipi = ham_kayit.get("format", "AUTO")
        # Olay tipini al
        olay_tipi = str(ham_kayit.get("olay_tipi", "GENERIC_EVENT"))
        # Mesaj içeriğini al
        mesaj = str(ham_kayit.get("mesaj", ""))

        # Zaman damgasını biçimine göre ayrıştır ve UTC datetime nesnesi elde et
        if format_tipi in ("ISO8601_UTC", "ISO8601_OFFSET") or isinstance(ham_zaman, str):
            # ISO-8601 ayrıştırıcıyı çağır
            dt_utc = self.parse_iso_with_strict_tz(str(ham_zaman))
            # Orijinal offset dakikasını hesapla
            ham_str = str(ham_zaman)
            # Offset deseni ara (+03:00 veya -04:00)
            offset_ara = re.search(r"([+-])(\d{2}):?(\d{2})$", ham_str)
            if offset_ara:
                isaret = 1 if offset_ara.group(1) == "+" else -1
                of_saat = int(offset_ara.group(2))
                of_dak = int(offset_ara.group(3))
                offset_dakika = isaret * (of_saat * 60 + of_dak)
            else:
                # Z ise offset 0'dır
                offset_dakika = 0
        elif format_tipi == "UNIX_EPOCH_SEC" or (isinstance(ham_zaman, (int, float)) and ham_zaman < 10000000000000):
            # Unix epoch saniye/milisaniye ayrıştırıcıyı çağır
            dt_utc = self.convert_epoch_to_utc(ham_zaman)
            # Epoch UTC bazlı olduğu için offset 0 kabul edilir
            offset_dakika = 0
        elif format_tipi == "WINDOWS_FILETIME" or (isinstance(ham_zaman, int) and ham_zaman >= 10000000000000):
            # Windows FileTime ayrıştırıcıyı çağır
            dt_utc = self.convert_filetime_to_utc(ham_zaman)
            # FileTime doğrudan UTC'dir
            offset_dakika = 0
        else:
            # Bilinmeyen format
            raise MalformedTimestampError(f"Desteklenmeyen veya tanımlanamayan zaman formatı: {format_tipi}")

        # Olay tipine göre risk seviyesini derecelendir
        risk = "INFO"
        olay_upper = olay_tipi.upper()
        if "DROP" in olay_upper or "BLOCK" in olay_upper or "DENIED" in olay_upper:
            risk = "HIGH"
        elif "ALERT" in olay_upper or "FAILURE" in olay_upper:
            risk = "MEDIUM"
        elif "KERBEROS" in olay_upper or "AUTH" in olay_upper or "TOKEN" in olay_upper:
            risk = "LOW"

        # Normalize edilmiş olay nesnesini oluştur ve döndür
        return NormalizedLogEvent(
            kaynak_id=kaynak_id,
            zaman_damgasi_orijinal=ham_zaman,
            utc_zaman_damgasi=dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            unix_epoch_saniye=round(dt_utc.timestamp(), 3),
            saat_dilimi_offset_dakika=offset_dakika,
            is_aware=True,
            olay_tipi=olay_tipi,
            mesaj=mesaj,
            risk_seviyesi=risk
        )

    def build_forensic_timeline(self, ham_kayitlar: List[Dict[str, Any]]) -> List[NormalizedLogEvent]:
        """
        Farklı kaynaklardan gelen log kayıtlarını tek tek normalize eder ve
        mutlak UTC zaman sırasına (kronolojik zaman çizgisine) dizer.
        
        :param ham_kayitlar: Ham log listesi
        :return: Kronolojik olarak sıralanmış normalize edilmiş olay listesi
        """
        # Boş liste tanımla
        normalize_olaylar: List[NormalizedLogEvent] = []

        # Her bir ham kaydı döngüyle işle
        for kayit in ham_kayitlar:
            # Kaydı normalize et
            olay = self.normalize_log_entry(kayit)
            # Listeye ekle
            normalize_olaylar.append(olay)

        # Olayları unix_epoch_saniyesine göre küçükten büyüğe sırala
        sirali_olaylar = sorted(normalize_olaylar, key=lambda ev: ev.unix_epoch_saniye)

        # Sıralı listeyi döndür
        return sirali_olaylar

    def generate_forensic_report(self, zaman_cizgisi: List[NormalizedLogEvent]) -> str:
        """
        Adli bilişim zaman çizgisi için ayrıntılı Türkçe analiz ve denetim raporu üretir.
        
        :param zaman_cizgisi: Kronolojik normalize edilmiş olaylar
        :return: Rapor metni
        """
        # Rapor başlığını oluştur
        satirlar = [
            "=" * 85,
            "ADLİ BİLİŞİM VE OLAY MÜDAHALESİ — UTC ZAMAN DAMGASI NORMALİZASYON RAPORU",
            "=" * 85,
            f"Toplam İncelenen Olay Sayısı: {len(zaman_cizgisi)}",
            f"Rapor Oluşturma Zamanı (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "-" * 85,
            f"{'SIRA':<5} | {'UTC ZAMAN DAMGASI':<20} | {'KAYNAK ID':<18} | {'RİSK':<8} | {'OLAY TİPİ'}",
            "-" * 85
        ]

        # Her olayı tablo satırı olarak ekle
        for sira, olay in enumerate(zaman_cizgisi, start=1):
            satir = (
                f"{sira:<5} | {olay.utc_zaman_damgasi:<20} | {olay.kaynak_id:<18} | "
                f"{olay.risk_seviyesi:<8} | {olay.olay_tipi} ({olay.mesaj})"
            )
            satirlar.append(satir)

        satirlar.append("=" * 85)
        # Raporu birleştir ve döndür
        return "\n".join(satirlar)
