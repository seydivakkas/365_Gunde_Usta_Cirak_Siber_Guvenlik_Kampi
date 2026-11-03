# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G070: Aşama 3 Kalite Özeti ve Ağ Analizi Kabul Test Paketi.

Bu modül, Asama3KaliteOzetiAnalizor sınıfının doğrulama ve kabul yeteneklerini
14 kapsamlı birim test ve 9 negatif sınır vakası üzerinden doğrular.
"""

# Birim test çerçevesi için unittest modülünü dahil ediyoruz.
import unittest
# JSON veri yükleme ve işleme için json kütüphanesini içeri aktarıyoruz.
import json
# Dosya yolları ve işletim sistemi kontrolleri için os modülünü kullanıyoruz.
import os
# SHA-256 doğrulama testleri için hashlib kütüphanesini çağırıyoruz.
import hashlib

# Test edilecek analizör ve özel istisna sınıfını uygulama paketinden dahil ediyoruz.
from portfolio.hafta_10.gun_070.uygulama.asama_3_kalite_ozeti_analizor import (
    Asama3KaliteOzetiAnalizor,
    Asama3KaliteAuditError,
)


class TestAsama3KaliteOzetiAnalizor(unittest.TestCase):
    """Aşama 3 Kalite Özeti Analizörü için 14 senaryolu birim test sınıfı."""

    @classmethod
    def setUpClass(cls) -> None:
        """Tüm testler öncesinde geçerli ve geçersiz veri kümelerini yükler."""
        # Geçerli aşama metrikleri JSON dosya yolunu belirliyoruz.
        cls.valid_data_path = os.path.join(
            "portfolio", "hafta_10", "gun_070", "ornek_veri", "asama_3_gunluk_metrikleri.json"
        )
        # Negatif sınır testleri JSON dosya yolunu belirliyoruz.
        cls.invalid_data_path = os.path.join(
            "portfolio", "hafta_10", "gun_070", "ornek_veri", "invalid_asama_3_inputs.json"
        )

        # Geçerli veri dosyasını UTF-8 formatında açıyoruz.
        with open(cls.valid_data_path, "r", encoding="utf-8") as f:
            # Geçerli veriyi sözlük olarak bellğe yüklüyoruz.
            cls.valid_data = json.load(f)

        # Geçersiz veri dosyasını UTF-8 formatında açıyoruz.
        with open(cls.invalid_data_path, "r", encoding="utf-8") as f:
            # Geçersiz test senaryolarını belleğe yüklüyoruz.
            cls.invalid_data = json.load(f)

    def setUp(self) -> None:
        """Her testten önce taze bir analizör nesnesi ilklendirir."""
        # Analizör örneğini oluşturuyoruz.
        self.auditor = Asama3KaliteOzetiAnalizor()

    def test_01_full_stage3_audit_success(self) -> None:
        """Geçerli 20 günlük veriyle tam aşama denetiminin PASS ve 100 puan vermesini sınar."""
        # Tam denetim fonksiyonunu icra ediyoruz.
        result = self.auditor.run_full_audit(self.valid_data)
        # Denetim durumunun PASS olduğunu doğruluyoruz.
        self.assertEqual(result["audit_status"], "PASS")
        # Final skorunun 100.0 olduğunu teyit ediyoruz.
        self.assertEqual(result["final_score"], 100.0)
        # Kalite kararının kabul olduğunu sınıyoruz.
        self.assertIn("KABUL", result["quality_decision"])
        # 6 sütunun da değerlendirildiğini kontrol ediyoruz.
        self.assertEqual(len(result["pillars_evaluated"]), 6)
        # Denetlenen gün sayısının 20 olduğunu teyit ediyoruz.
        self.assertEqual(result["days_summary"]["total_days_audited"], 20)

    def test_02_acceptance_certificate_verification(self) -> None:
        """Kriptografik Aşama 3 kabul sertifikasının geçerliliğini ve imzasını sınar."""
        # Tam denetimi çalıştırıyoruz.
        result = self.auditor.run_full_audit(self.valid_data)
        # Sertifika sözlüğünü çekiyoruz.
        cert = result["acceptance_certificate"]
        # Sertifika seri numarasının ön ekini sınıyoruz.
        self.assertTrue(cert["certificate_id"].startswith("CERT-STAGE03-2026-"))
        # Sertifikanın Seydi Eryılmaz adına düzenlendiğini teyit ediyoruz.
        self.assertEqual(cert["issued_to"], "Seydi Eryılmaz (@seydivakkas)")
        # 280 birim testin sertifikaya işlendiğini kontrol ediyoruz.
        self.assertEqual(cert["total_tests_passed"], 280)
        # 180 negatif kontrolün başarıyla işlendiğini teyit ediyoruz.
        self.assertEqual(cert["total_negative_controls_passed"], 180)
        # SHA-256 karmasının 64 karakter olduğunu sınıyoruz.
        self.assertEqual(len(cert["cryptographic_verification_hash"]), 64)

    def test_03_text_report_formatting(self) -> None:
        """İnsan tarafından okunabilir metin raporunun biçimsel gereksinimlerini sınar."""
        # Denetimi icra ediyoruz.
        result = self.auditor.run_full_audit(self.valid_data)
        # Metin raporunu üretiyoruz.
        report = self.auditor.generate_text_report(result)
        # Rapor başlığının varlığını sınıyoruz.
        self.assertIn("AŞAMA 03 KALİTE ÖZETİ VE KABUL RAPORU", report)
        # 6 sütunun raporda listelendiğini teyit ediyoruz.
        self.assertIn("Paket Yakalama ve Ekran Filtreleri", report)
        self.assertIn("Ağ Anomalileri, Tünelleme ve QoS Performansı", report)
        # Lisans bilgisinin raporda geçtiğini kontrol ediyoruz.
        self.assertIn("Telif Hakkı (c) 2026 Seydi Eryılmaz", report)
        # Sertifika imzasının raporda yer aldığını sınıyoruz.
        self.assertIn("SHA-256 Adli İmza", report)

    def test_04_json_report_serialization(self) -> None:
        """JSON raporlama formatının hatasız parse edilebildiğini ve alanlarını sınar."""
        # Denetimi tamamlıyoruz.
        result = self.auditor.run_full_audit(self.valid_data)
        # JSON dizgisini oluşturuyoruz.
        json_str = self.auditor.generate_json_report(result)
        # JSON dizgisini yeniden nesneye ayrıştırıyoruz.
        parsed = json.loads(json_str)
        # Aşama kimliğinin '03' olduğunu teyit ediyoruz.
        self.assertEqual(parsed["stage_id"], "03")
        # Skorun 100 olduğunu kontrol ediyoruz.
        self.assertEqual(parsed["final_score"], 100.0)

    def test_05_stage_metrics_calculation(self) -> None:
        """Aşama 3 toplam test, negatif kontrol ve eser sayılarının hesaplamasını sınar."""
        # Metrik hesaplama fonksiyonunu çalıştırıyoruz.
        metrics = self.auditor.calculate_stage_metrics(self.valid_data)
        # Toplam birim test sayısının 280 olduğunu teyit ediyoruz (20 gün * 14 test).
        self.assertEqual(metrics["total_unit_tests"], 280)
        # Toplam negatif kontrol sayısının 180 olduğunu sınıyoruz (20 gün * 9 kontrol).
        self.assertEqual(metrics["total_negative_controls"], 180)
        # Toplam önerme sayısının 460 olduğunu teyit ediyoruz.
        self.assertEqual(metrics["total_assertions_verified"], 460)
        # Toplam eser sayısının 320 olduğunu sınıyoruz (20 gün * 16 dosya).
        self.assertEqual(metrics["total_artifacts"], 320)
        # Tamamlanma indeksinin %100 olduğunu kontrol ediyoruz.
        self.assertEqual(metrics["stage_completion_index_pct"], 100.0)

    def test_06_neg_01_not_a_dict(self) -> None:
        """NEG_01: Girdi JSON sözlüğü olmadığında istisna fırlatıldığını sınar."""
        # Negatif veri paketini çekiyoruz.
        case = self.invalid_data["NEG_01_NOT_A_DICT"]
        # Asama3KaliteAuditError istisnasının tetiklendiğini doğruluyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Hatalı yük ile denetimi tetikliyoruz.
            self.auditor.run_full_audit(case["payload"])
        # Hata mesajında beklenen ifadenin geçtiğini teyit ediyoruz.
        self.assertIn("JSON sözlüğü", str(ctx.exception))

    def test_07_neg_02_stage_id_mismatch(self) -> None:
        """NEG_02: Aşama kimliği '03' olmadığında istisna fırlatıldığını sınar."""
        # Negatif vaka yükünü alıyoruz.
        case = self.invalid_data["NEG_02_STAGE_ID_MISMATCH"]
        # Asama3KaliteAuditError istisnasını sınıyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Hatalı aşama kimliği ile çalıştırıyoruz.
            self.auditor.run_full_audit(case["payload"])
        # Aşama ID uyarısının verildiğini teyit ediyoruz.
        self.assertIn("Aşama ID '03' olmalıdır", str(ctx.exception))

    def test_08_neg_03_missing_mandatory_pillar(self) -> None:
        """NEG_03: Zorunlu 6 sütundan biri eksik olduğunda hata fırlatıldığını sınar."""
        # Negatif test verisini alıyoruz.
        case = self.invalid_data["NEG_03_MISSING_MANDATORY_PILLAR"]
        # Asama3KaliteAuditError istisnasını bekliyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Eksik sütun verisi ile denetim başlatıyoruz.
            self.auditor.run_full_audit(case["payload"])
        # Eksik sütun uyarısını kontrol ediyoruz.
        self.assertIn("threat_detection", str(ctx.exception))

    def test_09_neg_04_incomplete_days_count(self) -> None:
        """NEG_04: 20 günden eksik gün listesi sağlandığında hata fırlatıldığını sınar."""
        # Negatif senaryoyu yüklüyoruz.
        case = self.invalid_data["NEG_04_INCOMPLETE_DAYS_COUNT"]
        # Asama3KaliteAuditError istisnasını sınıyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Eksik gün listesi ile denetim çağırıyoruz.
            self.auditor.run_full_audit(case["payload"])
        # 20 gün eksiklik uyarısını teyit ediyoruz.
        self.assertIn("tam 20 gün", str(ctx.exception))

    def test_10_neg_05_subpar_score(self) -> None:
        """NEG_05: Herhangi bir günün skoru 100'den düşük olduğunda hata verildiğini sınar."""
        # Negatif test verisini alıyoruz.
        case = self.invalid_data["NEG_05_SUBPAR_SCORE"]
        # Asama3KaliteAuditError istisnasını sınıyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # 75 puanlık gün girdisiyle audit_days çağırıyoruz.
            self.auditor.audit_days(case["payload"]["days"])
        # Skor yetersizliği mesajını teyit ediyoruz.
        self.assertIn("skoru 100 olmalıdır", str(ctx.exception))

    def test_11_neg_06_open_source_license_violation(self) -> None:
        """NEG_06: Açık kaynak lisans (MIT vb.) tespit edildiğinde hata fırlatıldığını sınar."""
        # Negatif test verisini çekiyoruz.
        case = self.invalid_data["NEG_06_OPEN_SOURCE_LICENSE_VIOLATION"]
        # Asama3KaliteAuditError istisnasını bekliyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # MIT lisansı içeren gün girdisi ile çağırıyoruz.
            self.auditor.audit_days(case["payload"]["days"])
        # Lisans kural ihlali uyarısını doğruluyoruz.
        self.assertIn("Lisans kuralı ihlali", str(ctx.exception))

    def test_12_neg_07_insufficient_test_count(self) -> None:
        """NEG_07: Test sayısı 14'ün altında olduğunda hata verildiğini sınar."""
        # Negatif vaka verisini alıyoruz.
        case = self.invalid_data["NEG_07_INSUFFICIENT_TEST_COUNT"]
        # Asama3KaliteAuditError istisnasını kontrol ediyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # 10 testlik gün girdisiyle denetim çağırıyoruz.
            self.auditor.audit_days(case["payload"]["days"])
        # Yetersiz test sayısı uyarısını sınıyoruz.
        self.assertIn("en az 14 test içermelidir", str(ctx.exception))

    def test_13_neg_08_unverified_backup(self) -> None:
        """NEG_08: Yedek doğrulanmadığında (backup_verified=False) hata fırlatıldığını sınar."""
        # Negatif vaka nesnesini yüklüyoruz.
        case = self.invalid_data["NEG_08_UNVERIFIED_BACKUP"]
        # Asama3KaliteAuditError istisnasını sınıyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Doğrulanmamış yedek kaydı ile denetim tetikliyoruz.
            self.auditor.audit_days(case["payload"]["days"])
        # Yedek doğrulama başarısızlığı uyarısını teyit ediyoruz.
        self.assertIn("Yedek doğrulama başarısız", str(ctx.exception))

    def test_14_neg_09_corrupt_day_number(self) -> None:
        """NEG_09: Gün numarası 51-70 aralığı dışında olduğunda hata verildiğini sınar."""
        # Negatif vaka verisini çekiyoruz.
        case = self.invalid_data["NEG_09_CORRUPT_DAY_NUMBER"]
        # Asama3KaliteAuditError istisnasını bekliyoruz.
        with self.assertRaises(Asama3KaliteAuditError) as ctx:
            # Gün 99 içeren kayıt ile denetim çağırıyoruz.
            self.auditor.audit_days(case["payload"]["days"])
        # Gün aralığı dışı uyarısını sınıyoruz.
        self.assertIn("gün aralığı dışı", str(ctx.exception))


# Test betiğinin doğrudan çalıştırılmasını yönetiyoruz.
if __name__ == "__main__":
    # Testleri ayrıntılı (verbose) modda tetikliyoruz.
    unittest.main()
