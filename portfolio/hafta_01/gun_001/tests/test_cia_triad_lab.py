"""
CIA Üçlüsü Laboratuvarı Birim ve Entegrasyon Testleri
===================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu test paketi, Gün 001 için pozitif kontrolleri (doğru yetki, sağlam veri, aktif servis)
ve negatif kontrolleri (yetkisiz erişim, tahrif edilmiş veri, çökmüş/kilitli servis)
ayrıntılı biçimde doğrular.
"""

import os
import sys
import tempfile
import unittest

# Uygulama modülünü içe aktar
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uygulama")))
from cia_triad_lab import (
    SchoolSystemSecurityManager,
    ConfidentialityViolationError,
    IntegrityViolationError,
    AvailabilityViolationError,
    run_comprehensive_audit
)


class TestSchoolSystemSecurityManager(unittest.TestCase):
    def setUp(self):
        """Her test için izole geçici veri dosyası hazırlar."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
        self.initial_content = (
            "OGRENCI_NO|AD_SOYAD|DERS|VIZE|FINAL|DURUM\n"
            "101|Ali Yılmaz|Siber Güvenliğe Giriş|45|55|Kaldı\n"
            "102|Ayşe Kaya|Ağ Temelleri|85|90|Geçti\n"
            "103|Mehmet Demir|İşletim Sistemleri|70|75|Geçti\n"
        )
        self.temp_file.write(self.initial_content)
        self.temp_file.close()

        self.mgr = SchoolSystemSecurityManager(self.temp_file.name)
        self.baseline_hash = self.mgr.calculate_file_hash()

    def tearDown(self):
        """Geçici dosyayı temizler."""
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    # -------------------------------------------------------------
    # GİZLİLİK (CONFIDENTIALITY) TESTLERİ
    # -------------------------------------------------------------
    def test_confidentiality_teacher_can_read_all(self):
        """Öğretmen rolünün tüm not kütüğünü eksiksiz okuduğunu doğrular."""
        grades = self.mgr.read_grades("OGRETMEN")
        self.assertEqual(len(grades), 3)
        self.assertEqual(grades[0]["OGRENCI_NO"], "101")
        self.assertEqual(grades[1]["OGRENCI_NO"], "102")

    def test_confidentiality_student_only_reads_own_grade(self):
        """Öğrencinin yalnızca kendi notunu görebildiğini, başkalarını göremediğini doğrular."""
        grades = self.mgr.read_grades("OGRENCI", user_student_id="101")
        self.assertEqual(len(grades), 1)
        self.assertEqual(grades[0]["OGRENCI_NO"], "101")
        self.assertEqual(grades[0]["AD_SOYAD"], "Ali Yılmaz")

    def test_confidentiality_student_without_id_blocked(self):
        """Kimlik numarası belirtmeyen öğrencinin kütüğü okuyamayacağını (Negatif Kontrol) doğrular."""
        with self.assertRaises(ConfidentialityViolationError):
            self.mgr.read_grades("OGRENCI", user_student_id=None)

    def test_confidentiality_guest_access_blocked(self):
        """Misafir kullanıcının erişiminin kesin olarak engellendiğini (Negatif Kontrol) doğrular."""
        with self.assertRaises(ConfidentialityViolationError):
            self.mgr.read_grades("MISAFIR")

    def test_confidentiality_invalid_role_blocked(self):
        """Sistemde tanımlı olmayan rolün engellendiğini (Negatif Kontrol) doğrular."""
        with self.assertRaises(ConfidentialityViolationError):
            self.mgr.read_grades("SALDIRGAN_ROL")

    # -------------------------------------------------------------
    # BÜTÜNLÜK (INTEGRITY) TESTLERİ
    # -------------------------------------------------------------
    def test_integrity_valid_file_passes(self):
        """Değiştirilmemiş dosyanın SHA-256 doğrulamasını geçtiğini (Pozitif Kontrol) doğrular."""
        is_valid, current_h = self.mgr.verify_integrity(self.baseline_hash)
        self.assertTrue(is_valid)
        self.assertEqual(current_h, self.baseline_hash)

    def test_integrity_tampering_detected(self):
        """Dosyadaki tek bir not değiştiğinde Bütünlük İhlalinin yakalandığını (Negatif Kontrol) doğrular."""
        # Ali'nin vizesini 45'ten 95'e çıkar
        self.mgr.tamper_student_grade("101", 95, 95)
        new_hash = self.mgr.calculate_file_hash()

        # Hash kesinlikle değişmiş olmalı (Çığ Etkisi)
        self.assertNotEqual(new_hash, self.baseline_hash)

        # verify_integrity çağrısı IntegrityViolationError fırlatmalı
        with self.assertRaises(IntegrityViolationError):
            self.mgr.verify_integrity(self.baseline_hash)

    # -------------------------------------------------------------
    # ERİŞİLEBİLİRLİK (AVAILABILITY) TESTLERİ
    # -------------------------------------------------------------
    def test_availability_unlocked_system_responds(self):
        """Sistem normal çalışırken isteklerin başarıyla yanıtlandığını doğrular."""
        self.assertTrue(self.mgr.verify_availability())

    def test_availability_locked_system_raises_error(self):
        """Sistem kilitliyken veya çökmüşken isteğin erişim hatası ürettiğini (Negatif Kontrol) doğrular."""
        self.mgr.set_system_lock(True)
        with self.assertRaises(AvailabilityViolationError):
            self.mgr.read_grades("OGRETMEN")

    # -------------------------------------------------------------
    # KAPSAMLI DENETİM TESTİ
    # -------------------------------------------------------------
    def test_full_comprehensive_audit(self):
        """Tüm CIA akışını icra eden audit fonksiyonunun başarılı döndüğünü doğrular."""
        result = run_comprehensive_audit(self.temp_file.name)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
