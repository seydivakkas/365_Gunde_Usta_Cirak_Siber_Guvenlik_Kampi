# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 090: UTC ve Saat Dilimi Adli Bilişim Motoru Birim Test Seti.

Bu test paketi; ISO-8601, Unix Epoch, Windows FileTime dönüşümlerini,
saat sapması (Clock Skew) ve Replay Attack denetimlerini, naive zaman engellerini
ve kronolojik zaman çizgisi sıralamasını 14 kapsamlı test senaryosuyla doğrular.
"""

# Test çerçevesi ve yardımcı modüllerin içe aktarılması
import unittest
# Sistem yolu ve dosya işlemleri modülleri
import sys
import os
# Tarih ve saat sınıfları
from datetime import datetime, timezone, timedelta

# Test edilecek uygulama modülünün yolunu sisteme ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))

# Adli bilişim sınıflarını ve istisnaları içe aktar
from utc_timezone_forensic_normalizer import (
    UtcTimezoneForensicNormalizer,
    TimestampSecurityError,
    NaiveTimestampError,
    InvalidTimeRangeError,
    InvalidCalendarDateError,
    InvalidEpochValueError,
    UnreasonableDateRangeError,
    ClockSkewExceededError,
    MalformedTimestampError,
    PayloadTooLargeError,
    InvalidFileTimeError,
    NormalizedLogEvent
)

class TestUtcTimezoneForensicNormalizer(unittest.TestCase):
    """UTC zaman damgası normalizasyon motoru test sınıfı."""

    def setUp(self) -> None:
        """Her testten önce çalışarak temiz bir motor örneği oluşturur."""
        # 300 saniye varsayılan sapma toleransıyla motoru başlat
        self.normalizer = UtcTimezoneForensicNormalizer(varsayilan_maks_sapma=300)

    def test_01_parse_iso_utc_z(self) -> None:
        """1. Test: Z soneki içeren ISO-8601 UTC dizgisinin doğru ayrıştırılması."""
        zaman_girdisi = "2026-11-01T14:30:00Z"
        # Ayrıştırmayı çalıştır
        sonuc_dt = self.normalizer.parse_iso_with_strict_tz(zaman_girdisi)
        # Nesnenin saat dilimi farkındalığına sahip olduğunu doğrula
        self.assertIsNotNone(sonuc_dt.tzinfo)
        # Saat diliminin UTC olduğunu doğrula
        self.assertEqual(sonuc_dt.tzinfo, timezone.utc)
        # Tarih ve saat bileşenlerini doğrula
        self.assertEqual(sonuc_dt.year, 2026)
        self.assertEqual(sonuc_dt.hour, 14)
        self.assertEqual(sonuc_dt.minute, 30)

    def test_02_parse_iso_positive_offset(self) -> None:
        """2. Test: Pozitif saat dilimi ofseti (+03:00) içeren dizginin UTC'ye doğru indirgenmesi."""
        # İstanbul zamanı 17:30:15 (+03:00) -> UTC karşılığı 14:30:15 olmalıdır
        zaman_girdisi = "2026-11-01T17:30:15+03:00"
        # Ayrıştır
        sonuc_dt = self.normalizer.parse_iso_with_strict_tz(zaman_girdisi)
        # UTC saatini doğrula
        self.assertEqual(sonuc_dt.hour, 14)
        self.assertEqual(sonuc_dt.minute, 30)
        self.assertEqual(sonuc_dt.second, 15)
        # UTC olduğunu teyit et
        self.assertEqual(sonuc_dt.tzinfo, timezone.utc)

    def test_03_parse_iso_negative_offset(self) -> None:
        """3. Test: Negatif saat dilimi ofseti (-04:00) içeren dizginin UTC'ye doğru dönüştürülmesi."""
        # New York zamanı 10:30:00 (-04:00) -> UTC karşılığı 14:30:00 olmalıdır
        zaman_girdisi = "2026-11-01T10:30:00-04:00"
        # Ayrıştır
        sonuc_dt = self.normalizer.parse_iso_with_strict_tz(zaman_girdisi)
        # UTC saatini doğrula
        self.assertEqual(sonuc_dt.hour, 14)
        self.assertEqual(sonuc_dt.minute, 30)

    def test_04_naive_timestamp_rejection(self) -> None:
        """4. Test: Saat dilimi içermeyen naive zaman damgasının reddedilmesi (CWE-613)."""
        # Saat dilimi belirtilmemiş girdi
        naive_girdi = "2026-11-01 14:30:00"
        # NaiveTimestampError fırlatılmalı
        with self.assertRaises(NaiveTimestampError):
            self.normalizer.parse_iso_with_strict_tz(naive_girdi)

    def test_05_invalid_time_range_rejection(self) -> None:
        """5. Test: Geçersiz saat/dakika/saniye sınır değerlerinin reddedilmesi (CWE-20)."""
        # Saat 25, dakika 70 olamaz
        gecersiz_zaman = "2026-11-01T25:70:00Z"
        with self.assertRaises(InvalidTimeRangeError):
            self.normalizer.parse_iso_with_strict_tz(gecersiz_zaman)

    def test_06_invalid_calendar_date_rejection(self) -> None:
        """6. Test: Takvimsel olarak imkansız tarihlerin (Şubat 30) reddedilmesi."""
        imkansiz_tarih = "2026-02-30T10:00:00Z"
        with self.assertRaises(InvalidCalendarDateError):
            self.normalizer.parse_iso_with_strict_tz(imkansiz_tarih)

    def test_07_unix_epoch_seconds_conversion(self) -> None:
        """7. Test: Geçerli Unix Epoch saniyesinin UTC datetime nesnesine dönüştürülmesi."""
        epoch_sec = 1793543415
        dt_utc = self.normalizer.convert_epoch_to_utc(epoch_sec)
        # Yılın 2026 olduğunu doğrula
        self.assertEqual(dt_utc.year, 2026)
        # UTC olduğunu teyit et
        self.assertEqual(dt_utc.tzinfo, timezone.utc)

    def test_08_unix_epoch_milliseconds_conversion(self) -> None:
        """8. Test: 13 haneli Unix Epoch milisaniye değerinin UTC'ye dönüştürülmesi."""
        epoch_ms = 1793543415000
        dt_utc = self.normalizer.convert_epoch_to_utc(epoch_ms)
        # Saniyenin doğru hesaplandığını doğrula
        self.assertEqual(int(dt_utc.timestamp()), 1793543415)

    def test_09_negative_epoch_rejection(self) -> None:
        """9. Test: Negatif veya sıfır epoch değerinin reddedilmesi."""
        with self.assertRaises(InvalidEpochValueError):
            self.normalizer.convert_epoch_to_utc(-100)

    def test_10_windows_filetime_conversion(self) -> None:
        """10. Test: 64-bit Windows FileTime tamsayısının UTC datetime nesnesine dönüştürülmesi."""
        # 2026 yılına denk gelen geçerli bir Active Directory Windows FileTime
        filetime_val = 134374314050000000
        dt_utc = self.normalizer.convert_filetime_to_utc(filetime_val)
        # Yılın 2026 olduğunu doğrula
        self.assertEqual(dt_utc.year, 2026)
        self.assertEqual(dt_utc.tzinfo, timezone.utc)

    def test_11_invalid_filetime_rejection(self) -> None:
        """11. Test: Negatif veya Unix öncesi Windows FileTime değerinin reddedilmesi."""
        with self.assertRaises(InvalidFileTimeError):
            self.normalizer.convert_filetime_to_utc(-500)

    def test_12_clock_skew_acceptable(self) -> None:
        """12. Test: Kabul edilebilir saat sapması (Clock Skew <= 300 sn) testi."""
        istemci_t = "2026-11-01T14:32:00Z"
        referans_t = "2026-11-01T14:30:00Z" # 120 sn fark
        denetim = self.normalizer.audit_clock_skew(istemci_t, referans_t, maks_sapma_saniye=300)
        # Güvenli olduğunu doğrula
        self.assertTrue(denetim.sapma_guvenli_mi)
        self.assertEqual(denetim.sapma_saniyesi, 120.0)
        self.assertIn("GÜVENLİ", denetim.hukum)

    def test_13_clock_skew_violation(self) -> None:
        """13. Test: İzin verilen saat sapmasının aşılması ve Replay riski hükmü (CWE-1385)."""
        istemci_t = "2026-11-01T14:45:00Z"
        referans_t = "2026-11-01T14:30:00Z" # 900 sn fark (> 300)
        denetim = self.normalizer.audit_clock_skew(istemci_t, referans_t, maks_sapma_saniye=300)
        # Güvenlik eşiğinin aşıldığını doğrula
        self.assertFalse(denetim.sapma_guvenli_mi)
        self.assertEqual(denetim.sapma_saniyesi, 900.0)
        self.assertIn("KRİTİK GÜVENLİK İHLALİ", denetim.hukum)

    def test_14_build_forensic_timeline_chronological_order(self) -> None:
        """14. Test: Çok kaynaklı logların eksiksiz normalize edilip kronolojik UTC sırasına dizilmesi."""
        ornek_kayitlar = [
            # Tokyo 23:30 (+09:00) -> UTC 14:30:20
            {"kaynak_id": "TKY", "zaman_damgasi_orijinal": "2026-11-01T23:30:20+09:00", "olay_tipi": "PACKET_DROP", "mesaj": "T3"},
            # New York 10:29:45 (-04:00) -> UTC 14:29:45 (En erken)
            {"kaynak_id": "NYC", "zaman_damgasi_orijinal": "2026-11-01T10:29:45-04:00", "olay_tipi": "AUTH", "mesaj": "T1"},
            # Londra 14:30:00 (Z) -> UTC 14:30:00 (Ortada)
            {"kaynak_id": "LON", "zaman_damgasi_orijinal": "2026-11-01T14:30:00Z", "olay_tipi": "QUERY", "mesaj": "T2"}
        ]
        # Zaman çizgisini inşa et
        zaman_cizgisi = self.normalizer.build_forensic_timeline(ornek_kayitlar)
        # 3 olay olduğunu teyit et
        self.assertEqual(len(zaman_cizgisi), 3)
        # Sıralamanın NYC (14:29:45), LON (14:30:00), TKY (14:30:20) olduğunu doğrula
        self.assertEqual(zaman_cizgisi[0].kaynak_id, "NYC")
        self.assertEqual(zaman_cizgisi[1].kaynak_id, "LON")
        self.assertEqual(zaman_cizgisi[2].kaynak_id, "TKY")
        # İlk olayın epoch saniyesinin son olayınkinden küçük olduğunu doğrula
        self.assertLess(zaman_cizgisi[0].unix_epoch_saniye, zaman_cizgisi[2].unix_epoch_saniye)

if __name__ == "__main__":
    unittest.main()
