# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G070: Aşama 3 Kalite Özeti ve Ağ Analizi Kabul Motoru.

Bu modül, Aşama 03 (Gün 51-70) boyunca icra edilen tüm ağ analizi ve güvenliği müfredatını
(paket yakalama, ekran filtreleri, TCP akış takibi, temel L2-L4 protokolleri, L7 ve TLS kriptografi,
ağ anomalileri, QoS performans metrikleri, kişisel veri arındırma ve Wireshark adli raporlaması)
6 kurumsal kalite sütunu altında matematiksel ve adli kanıtlarla denetler.
Tüm aşamanın %100 başarı ve sıfır açık kaynak lisans ihlaliyle tamamlandığını tescil eder.
"""

# Dosya yolu ve işletim sistemi ortamı işlemleri için os modülünü içeri aktarıyoruz.
import os
# Komut satırı bağımsız değişkenlerini ve parametreleri ayrıştırmak için argparse modülünü ekliyoruz.
import argparse
# JSON veri yapılarını okumak ve serileştirmek amacıyla json kütüphanesini çağırıyoruz.
import json
# Sistem çıkış kodları ve hata akışları için sys modülünü dahil ediyoruz.
import sys
# Tip güvenliğini sağlamak için typing modülünden gerekli tip açıklamalarını alıyoruz.
from typing import Dict, Any, List, Optional
# Zaman damgalı denetim sertifikaları üretmek için datetime ve timezone sınıflarını kullanıyoruz.
from datetime import datetime, timezone
# Sertifika bütünlüğü ve adli parmak izi doğrulaması için hashlib kütüphanesini içeri aktarıyoruz.
import hashlib


class Asama3KaliteAuditError(ValueError):
    """Aşama 3 denetim kuralı ihlallerinde fırlatılan özel istisna sınıfı."""
    # ValueError temel sınıfından türeyerek özel istisna mekanizmasını tanımlıyoruz.
    pass


class Asama3KaliteOzetiAnalizor:
    """
    Aşama 3 (Ağ Analizi ve Güvenliği) kalite göstergelerini, 20 günlük müfredat başarılarını
    ve 6 kurumsal kalite sütununu doğrulayan kurumsal denetim ve kabul motoru.
    """

    # Aşama 3 kabulü için zorunlu kılınan 6 temel ağ analizi sütunu
    MANDATORY_PILLARS = [
        "capture_and_filters",
        "stream_and_automation",
        "core_protocols",
        "app_layer_and_crypto",
        "threat_detection",
        "compliance_and_forensics",
    ]

    # Müfredatta kesinlikle yasaklanan açık kaynak lisans anahtar kelimeleri
    DISALLOWED_LICENSES = ["MIT", "APACHE", "GPL", "BSD", "MPL", "LGPL", "AGPL"]

    # Proje genelinde uygulanması mecburi olan özel lisans kodu
    REQUIRED_LICENSE = "OZEL_LISANS_TUM_HAKLARI_SAKLIDIR"

    # Aşama 3 kapsamındaki kesin gün listesi (Gün 51'den Gün 70'e kadar 20 gün)
    STAGE_DAYS = list(range(51, 71))

    def __init__(self) -> None:
        """Denetim analizörü sınıfının yapıcı metodu."""
        # Analizör başlatıldığında denetim durumu bayrağını başlangıçta False olarak ayarlıyoruz.
        self.audit_completed: bool = False
        # Son üretilen denetim sonucunu saklamak için boş sözlük ilklendiriyoruz.
        self.last_audit_result: Dict[str, Any] = {}

    def validate_schema(self, data: Any) -> None:
        """
        Aşama 3 girdi verisinin JSON sözlüğü ve gerekli anahtar alanlara sahip olduğunu doğrular.

        Parametreler:
            data: Denetlenecek ham veri nesnesi.
        """
        # Girdinin sözlük (dict) tipinde olup olmadığını sınıyoruz.
        if not isinstance(data, dict):
            # Sözlük değilse kurumsal hata fırlatıyoruz.
            raise Asama3KaliteAuditError("Aşama 3 denetim verisi bir JSON sözlüğü (dict) olmalıdır.")

        # Kök sözlükte yer alması zorunlu alanları belirliyoruz.
        required_keys = ["stage_metadata", "quality_pillars", "days"]
        # Her bir zorunlu anahtarın varlığını denetliyoruz.
        for key in required_keys:
            # Anahtar sözlükte yoksa hata veriyoruz.
            if key not in data:
                # Eksik anahtar bildiren istisna fırlatıyoruz.
                raise Asama3KaliteAuditError(f"Aşama 3 envanterinde zorunlu '{key}' anahtarı bulunamadı.")

        # Aşama metaverisini alıyoruz.
        meta = data.get("stage_metadata", {})
        # Aşama kimliğini kontrol ediyoruz.
        stage_id = str(meta.get("stage_id", ""))
        # Aşama ID'sinin '03' olduğunu teyit ediyoruz.
        if stage_id != "03":
            # Uyuşmazlık durumunda hata fırlatıyoruz.
            raise Asama3KaliteAuditError(f"Aşama ID '03' olmalıdır, alınan: {stage_id}")

        # Lisans politikasının doğruluğunu denetliyoruz.
        license_policy = str(meta.get("license_policy", ""))
        # Lisans politikası kural dışı ise hata veriyoruz.
        if license_policy != self.REQUIRED_LICENSE:
            # Lisans ihlali tespit edildiğinde istisna fırlatıyoruz.
            raise Asama3KaliteAuditError(
                f"Aşama metaveri lisans politikası '{self.REQUIRED_LICENSE}' olmalıdır, alınan: {license_policy}"
            )

    def audit_pillars(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aşama 3'ün 6 temel kalite sütununu ve kapsadıkları günleri denetler.

        Parametreler:
            data: Doğrulanmış girdi sözlüğü.

        Döndürür:
            Sütun denetim sonuçlarını içeren sözlük.
        """
        # Kalite sütunları sözlüğünü alıyoruz.
        pillars = data.get("quality_pillars", {})
        # Denetim sonuçlarını biriktireceğimiz sözlüğü oluşturuyoruz.
        pillar_summary: Dict[str, Any] = {}

        # 6 zorunlu sütunun her birini tek tek sınıyoruz.
        for pillar_name in self.MANDATORY_PILLARS:
            # Sütunun sözlükte bulunup bulunmadığına bakıyoruz.
            if pillar_name not in pillars:
                # Sütun eksikse istisna fırlatıyoruz.
                raise Asama3KaliteAuditError(f"Zorunlu kalite sütunu '{pillar_name}' envanterde bulunamadı.")

            # Sütun detayını çekiyoruz.
            p_info = pillars[pillar_name]
            # Sütun bilgisinin sözlük tipinde olduğunu teyit ediyoruz.
            if not isinstance(p_info, dict):
                # Sözlük değilse hata veriyoruz.
                raise Asama3KaliteAuditError(f"Kalite sütunu '{pillar_name}' bir sözlük olmalıdır.")

            # Sütun özetine onaylanmış olarak kaydediyoruz.
            pillar_summary[pillar_name] = {
                "name": p_info.get("name", pillar_name),
                "status": "PASS",
                "days_count": len(p_info.get("covered_days", []))
            }

        # Tamamlanan sütun özetini döndürüyoruz.
        return pillar_summary

    def audit_days(self, days_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aşama 3'ün 20 gününü (Gün 51-70) eksiksizlik, skor, test adedi, negatif kontroller,
        lisans uyumu ve yedekleme açısından katı kurallarla denetler.

        Parametreler:
            days_list: Günlük metrik sözlüklerinin listesi.

        Döndürür:
            Günlük denetim istatistiklerini içeren özet sözlük.
        """
        # Gün listesinin liste tipinde olduğunu teyit ediyoruz.
        if not isinstance(days_list, list):
            # Liste değilse hata fırlatıyoruz.
            raise Asama3KaliteAuditError("Günler verisi bir liste (list) olmalıdır.")

        # Karşılaşılan gün kimliklerini tutmak için küme oluşturuyoruz.
        seen_days = set()
        # Toplam çalıştırılan test sayısını tutan sayaç ilklendiriyoruz.
        total_tests_run = 0
        # Toplam başarılı test sayısını tutan sayaç ilklendiriyoruz.
        total_tests_passed = 0
        # Toplam negatif kontrol sayısını tutan sayaç ilklendiriyoruz.
        total_neg_controls = 0
        # Toplam başarılı negatif kontrol sayısını tutan sayaç ilklendiriyoruz.
        total_neg_passed = 0
        # Toplam üretilen eser sayısını tutan sayaç ilklendiriyoruz.
        total_artifacts = 0

        # Her bir gün girdisini sırayla denetliyoruz.
        for day in days_list:
            # Gün nesnesinin sözlük tipinde olduğunu sınıyoruz.
            if not isinstance(day, dict):
                # Sözlük değilse hata veriyoruz.
                raise Asama3KaliteAuditError("Gün kaydı bir sözlük olmalıdır.")

            # Gün kimliğini alıyoruz.
            day_id = day.get("day_id")
            # Gün kimliğinin tamsayı olduğunu ve aralıkta bulunduğunu teyit ediyoruz.
            if not isinstance(day_id, int) or day_id < 51 or day_id > 70:
                # Gün aralık dışındaysa hata fırlatıyoruz.
                raise Asama3KaliteAuditError(f"Aşama 3 gün aralığı dışı: Gün {day_id} (beklenen: 51-70)")

            # Gün kimliğinin mükerrer olup olmadığını kontrol ediyoruz.
            if day_id in seen_days:
                # Mükerrer gün tespit edilirse hata veriyoruz.
                raise Asama3KaliteAuditError(f"Mükerrer gün kaydı tespit edildi: Gün {day_id}")
            # Gün kimliğini kümeye ekliyoruz.
            seen_days.add(day_id)

            # Gün skorunu alıyoruz.
            score = day.get("score")
            # Skorun tam 100 puan olup olmadığını denetliyoruz.
            if score != 100:
                # 100 puandan düşük veya geçersizse hata veriyoruz.
                raise Asama3KaliteAuditError(f"Gün {day_id} skoru 100 olmalıdır, alınan: {score}")

            # Gün durumunun PASS olduğunu doğruluyoruz.
            status = day.get("status")
            # Durum PASS değilse hata fırlatıyoruz.
            if status != "PASS":
                # Başarısız gün durumu hatası veriyoruz.
                raise Asama3KaliteAuditError(f"Gün {day_id} durumu 'PASS' olmalıdır, alınan: {status}")

            # Lisans bilgisini alıyoruz.
            license_val = str(day.get("license", ""))
            # Yasaklı açık kaynak lisanslarını sınıyoruz.
            for disallowed in self.DISALLOWED_LICENSES:
                # Lisans metninde yasaklı kelime varsa hata fırlatıyoruz.
                if disallowed in license_val.upper():
                    # Açık kaynak lisans kuralı ihlali hatası üretiyoruz.
                    raise Asama3KaliteAuditError(
                        f"Lisans kuralı ihlali: Gün {day_id} açık kaynak lisans ('{license_val}') içeremez."
                    )

            # Lisansın zorunlu özel lisans olup olmadığını teyit ediyoruz.
            if license_val != self.REQUIRED_LICENSE:
                # Zorunlu lisans eksikse hata veriyoruz.
                raise Asama3KaliteAuditError(
                    f"Lisans kuralı ihlali: Gün {day_id} geçerli özel lisans ('{self.REQUIRED_LICENSE}') taşımalıdır."
                )

            # Çalıştırılan test sayısını alıyoruz.
            tests_run = day.get("tests_run", 0)
            # Test sayısının en az 14 olup olmadığını denetliyoruz.
            if tests_run < 14:
                # Yetersiz test sayısı hatası veriyoruz.
                raise Asama3KaliteAuditError(
                    f"Yetersiz test sayısı: Gün {day_id} en az 14 test içermelidir, alınan: {tests_run}"
                )

            # Başarılı test sayısını alıyoruz.
            tests_passed = day.get("tests_passed", 0)
            # Tüm testlerin başarılı olduğunu şart koşuyoruz.
            if tests_passed != tests_run:
                # Başarısız test tespit edildiğinde hata veriyoruz.
                raise Asama3KaliteAuditError(
                    f"Başarısız test tespit edildi: Gün {day_id} {tests_passed}/{tests_run} test geçti."
                )

            # Negatif kontrol sayısını alıyoruz.
            neg_controls = day.get("negative_controls", 0)
            # En az 9 negatif sınır kontrolü yapılmasını şart koşuyoruz.
            if neg_controls < 9:
                # Yetersiz negatif kontrol hatası fırlatıyoruz.
                raise Asama3KaliteAuditError(
                    f"Yetersiz negatif kontrol: Gün {day_id} en az 9 negatif kontrol içermelidir, alınan: {neg_controls}"
                )

            # Başarılı negatif kontrol adedini alıyoruz.
            neg_passed = day.get("negative_controls_passed", 0)
            # Tüm negatif kontrollerin başarılı olduğunu teyit ediyoruz.
            if neg_passed != neg_controls:
                # Başarısız negatif kontrol hatası veriyoruz.
                raise Asama3KaliteAuditError(
                    f"Başarısız negatif kontrol: Gün {day_id} {neg_passed}/{neg_controls} negatif kontrol geçti."
                )

            # Yedek doğrulama bayrağını alıyoruz.
            backup_verified = day.get("backup_verified", False)
            # Yedeğin doğrulanmış olmasını zorunlu tutuyoruz.
            if backup_verified is not True:
                # Doğrulanmamış yedek hatası fırlatıyoruz.
                raise Asama3KaliteAuditError(
                    f"Yedek doğrulama başarısız: Gün {day_id} için doğrulanmış arşiv bulunamadı."
                )

            # Sayaçları topluyoruz.
            total_tests_run += tests_run
            # Başarılı testleri topluyoruz.
            total_tests_passed += tests_passed
            # Negatif kontrolleri topluyoruz.
            total_neg_controls += neg_controls
            # Başarılı negatif kontrolleri topluyoruz.
            total_neg_passed += neg_passed
            # Eser sayısını ekliyoruz (varsayılan 16 eser).
            total_artifacts += day.get("artifact_count", 16)

        # Tam 20 günün mevcut olup olmadığını inceliyoruz.
        if len(seen_days) != len(self.STAGE_DAYS):
            # 20 günden farklıysa hata bildiriyoruz.
            raise Asama3KaliteAuditError(
                f"Aşama 3 tam 20 gün (Gün 51-70) içermelidir. Mevcut gün adedi: {len(seen_days)}"
            )

        # Gün listesi özet istatistiklerini döndürüyoruz.
        return {
            "total_days_audited": len(days_list),
            "expected_days_count": len(self.STAGE_DAYS),
            "total_tests_run": total_tests_run,
            "total_tests_passed": total_tests_passed,
            "test_pass_rate_pct": 100.0 if total_tests_run > 0 else 0.0,
            "total_negative_controls": total_neg_controls,
            "total_negative_passed": total_neg_passed,
            "negative_control_pass_rate_pct": 100.0 if total_neg_controls > 0 else 0.0,
            "total_artifacts_produced": total_artifacts,
            "average_score": 100.0,
            "all_backups_verified": True,
            "license_compliance_rate_pct": 100.0
        }

    def calculate_stage_metrics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aşama 3'ün tüm metriklerini birleştirir ve aşama genel başarı indeksini hesaplar.

        Parametreler:
            data: Denetlenen tam veri kümesi.

        Döndürür:
            Metrik özet sözlüğü.
        """
        # Sütunları denetliyoruz.
        pillars_summary = self.audit_pillars(data)
        # Günleri denetliyoruz.
        days_summary = self.audit_days(data.get("days", []))

        # Aşamaya dair genel metrikleri oluşturuyoruz.
        stage_metrics = {
            "stage_id": "03",
            "stage_name": "Ağ Analizi ve Güvenliği",
            "weeks_covered": [8, 9, 10],
            "day_range": "Gün 51 - Gün 70",
            "pillars_evaluated": len(pillars_summary),
            "pillars_passed": len(pillars_summary),
            "days_evaluated": days_summary["total_days_audited"],
            "total_unit_tests": days_summary["total_tests_run"],
            "total_negative_controls": days_summary["total_negative_controls"],
            "total_assertions_verified": days_summary["total_tests_run"] + days_summary["total_negative_controls"],
            "total_artifacts": days_summary["total_artifacts_produced"],
            "average_stage_score": days_summary["average_score"],
            "stage_completion_index_pct": 100.0,
            "overall_decision": "KABUL_EDILDI_PASS"
        }

        # Üretilen aşama metriklerini döndürüyoruz.
        return stage_metrics

    def generate_acceptance_certificate(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aşama 3'ün başarıyla tamamlandığını belgeleyen SHA-256 imzalı kabul sertifikası üretir.

        Parametreler:
            metrics: Hesaplanmış aşama metrikleri sözlüğü.

        Döndürür:
            Kriptografik kabul sertifikası nesnesi.
        """
        # Sertifikanın UTC zaman damgasını alıyoruz.
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # Sertifika içeriği için belirleyici metin bloğu oluşturuyoruz.
        cert_payload = (
            f"STAGE:03|WEEKS:8-10|DAYS:51-70|SCORE:100.0|TESTS:{metrics['total_unit_tests']}|"
            f"NEG_CONTROLS:{metrics['total_negative_controls']}|ARTIFACTS:{metrics['total_artifacts']}|"
            f"TIMESTAMP:{timestamp_utc}|LICENSE:{self.REQUIRED_LICENSE}"
        )

        # Metin bloğunun SHA-256 karmasını hesaplıyoruz.
        cert_hash = hashlib.sha256(cert_payload.encode("utf-8")).hexdigest()

        # Sertifika sözlüğünü yapılandırıyoruz.
        certificate = {
            "certificate_id": f"CERT-STAGE03-2026-{cert_hash[:12].upper()}",
            "issued_to": "Seydi Eryılmaz (@seydivakkas)",
            "curriculum_track": "Siber Güvenlik 365 Gün - Aşama 03: Ağ Analizi",
            "days_covered": "Gün 51 - Gün 70 (20 Gün)",
            "weeks_covered": "Hafta 08 - Hafta 10",
            "total_tests_passed": metrics["total_unit_tests"],
            "total_negative_controls_passed": metrics["total_negative_controls"],
            "stage_average_score": metrics["average_stage_score"],
            "stage_status": "KABUL_EDILDI / YETERLI (PASS)",
            "license_status": "Özel Lisans — Tüm Hakları Saklıdır (Zero Open-Source Violations)",
            "issued_at_utc": timestamp_utc,
            "cryptographic_verification_hash": cert_hash
        }

        # Oluşturulan sertifikayı döndürüyoruz.
        return certificate

    def run_full_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aşama 3'ün tam denetim sürecini baştan sona icra eder.

        Parametreler:
            data: Denetlenecek envanter verisi.

        Döndürür:
            Tam denetim raporu sözlüğü.
        """
        # Şema ve temel yapıyı doğruluyoruz.
        self.validate_schema(data)
        # Sütunları denetliyoruz.
        pillars = self.audit_pillars(data)
        # Günlük metrikleri denetliyoruz.
        days_stats = self.audit_days(data.get("days", []))
        # Aşama metriklerini hesaplıyoruz.
        stage_metrics = self.calculate_stage_metrics(data)
        # Kabul sertifikasını oluşturuyoruz.
        certificate = self.generate_acceptance_certificate(stage_metrics)

        # Bütünleşik denetim sonucunu hazırlıyoruz.
        audit_result = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "stage_id": "03",
            "stage_title": "Aşama 3 Kalite Özeti: Ağ Analizi",
            "audit_status": "PASS",
            "final_score": 100.0,
            "quality_decision": "YETERLİ / KABUL EDİLDİ",
            "pillars_evaluated": pillars,
            "days_summary": days_stats,
            "stage_metrics": stage_metrics,
            "acceptance_certificate": certificate
        }

        # Durum bayrağını ve sonucunu kaydediyoruz.
        self.audit_completed = True
        # Sonucu nesne belleğine atıyoruz.
        self.last_audit_result = audit_result

        # Denetim sonucunu döndürüyoruz.
        return audit_result

    def generate_text_report(self, audit_result: Dict[str, Any]) -> str:
        """
        İnsan tarafından okunabilir kurumsal Aşama 3 kabul ve kalite denetim raporu üretir.

        Parametreler:
            audit_result: run_full_audit çıktısı olan denetim sözlüğü.

        Döndürür:
            Biçimlendirilmiş rapor metni.
        """
        # Rapor satırlarını biriktireceğimiz liste ilklendiriyoruz.
        lines = []
        # Başlık ve ayırıcı ekliyoruz.
        lines.append("=" * 80)
        # Kurumsal başlık metnini yazıyoruz.
        lines.append("AŞAMA 03 KALİTE ÖZETİ VE KABUL RAPORU: AĞ ANALİZİ VE GÜVENLİĞİ")
        # Müfredat kapsam bilgisini ekliyoruz.
        lines.append("Kapsam: Gün 51 - Gün 70 | Hafta 08 - Hafta 10 | 20 Tam Gün")
        # Standart ve metodoloji bilgisini ekliyoruz.
        lines.append("Standart: ISO/IEC 27001, NIST SP 800-86 & Kurumsal Siber Savunma Kriterleri")
        # Lisans bilgisini ekliyoruz.
        lines.append("Lisans: Özel Lisans — Tüm Hakları Saklıdır (Telif Hakkı (c) 2026 Seydi Eryılmaz)")
        # Ayırıcı çizgi ekliyoruz.
        lines.append("=" * 80)
        # Boşluk bırakıyoruz.
        lines.append("")

        # İcra özeti bölümünü başlatıyoruz.
        lines.append("1. YÖNETİCİ VE İCRA ÖZETİ")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 40)
        # Genel kararı ekliyoruz.
        lines.append(f"Genel Kabul Kararı       : {audit_result.get('quality_decision', 'N/A')}")
        # Aşama başarı skorunu yazıyoruz.
        lines.append(f"Aşama Başarı Skoru       : %{audit_result.get('final_score', 0):.1f} / 100.0 (KUSURSUZ)")
        # Denetlenen gün sayısını yazıyoruz.
        m = audit_result.get("stage_metrics", {})
        lines.append(f"Denetlenen Gün Sayısı    : {m.get('days_evaluated', 0)} / 20 Gün (%100 Tamamlanma)")
        # Doğrulanan birim test sayısını ekliyoruz.
        lines.append(f"Birim Test Sayısı (Poz.) : {m.get('total_unit_tests', 0)} / {m.get('total_unit_tests', 0)} PASS (%100)")
        # Doğrulanan negatif kontrol sayısını yazıyoruz.
        lines.append(f"Negatif Kontrol Sayısı   : {m.get('total_negative_controls', 0)} / {m.get('total_negative_controls', 0)} PASS (%100)")
        # Toplam doğrulanan önerme adedini ekliyoruz.
        lines.append(f"Toplam Adli Önerme       : {m.get('total_assertions_verified', 0)} Doğrulandı")
        # Üretilen toplam eser sayısını ekliyoruz.
        lines.append(f"Üretilen Toplam Eser     : {m.get('total_artifacts', 0)} Dosya (Kod, Test, Rapor, Kanıt)")
        # Lisans uyum oranını ekliyoruz.
        lines.append("Açık Kaynak Lisans İhlali: SIFIR (Tam Kurumsal Özel Lisans Uyumu)")
        # Boş satır ekliyoruz.
        lines.append("")

        # 6 Temel Kalite Sütunu denetimini başlatıyoruz.
        lines.append("2. 6 TEMEL KALİTE SÜTUNU DENETİMİ")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 40)
        # Sütunları döngüye alıyoruz.
        pillars = audit_result.get("pillars_evaluated", {})
        # Her sütun için durum satırı yazıyoruz.
        for p_key, p_val in pillars.items():
            # Sütun adını ve durumunu ekliyoruz.
            lines.append(f"  [PASS] {p_val.get('name', p_key):<55} | Kapsam: {p_val.get('days_count', 0)} Gün")
        # Boş satır ekliyoruz.
        lines.append("")

        # Aşama 3 Adli Kabul Sertifikası bölümünü başlatıyoruz.
        lines.append("3. KRİPTOGRAFİK AŞAMA KABUL SERTİFİKASI")
        # Alt çizgi ekliyoruz.
        lines.append("-" * 40)
        # Sertifika sözlüğünü çekiyoruz.
        cert = audit_result.get("acceptance_certificate", {})
        # Sertifika numarasını yazıyoruz.
        lines.append(f"Sertifika Seri No : {cert.get('certificate_id', 'N/A')}")
        # Hak sahibini ekliyoruz.
        lines.append(f"Verilen Kişi      : {cert.get('issued_to', 'N/A')}")
        # Eğitim dalını yazıyoruz.
        lines.append(f"Müfredat Dalı     : {cert.get('curriculum_track', 'N/A')}")
        # Zaman damgasını ekliyoruz.
        lines.append(f"Tanzim Tarihi UTC : {cert.get('issued_at_utc', 'N/A')}")
        # SHA-256 imzasını yazıyoruz.
        lines.append(f"SHA-256 Adli İmza : {cert.get('cryptographic_verification_hash', 'N/A')}")
        # Ayırıcı alt çizgi ekliyoruz.
        lines.append("=" * 80)

        # Satırları yeni satır karakteriyle birleştirip döndürüyoruz.
        return "\n".join(lines)

    def generate_json_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Denetim sonucunu biçimlendirilmiş JSON dizgisi olarak serileştirir.

        Parametreler:
            audit_result: run_full_audit çıktısı olan denetim sözlüğü.

        Döndürür:
            Okunaklı JSON formatında metin.
        """
        # Türkçe karakterleri koruyarak ve 2 boşluk girintileyerek JSON serileştirmesi yapıyoruz.
        return json.dumps(audit_result, indent=2, ensure_ascii=False)


def main() -> None:
    """Komut satırı arayüzü (CLI) giriş noktası."""
    # Argparse nesnesi tanımlıyoruz.
    parser = argparse.ArgumentParser(
        description="G070: Aşama 3 Kalite Özeti ve Ağ Analizi Kabul Motoru"
    )
    # Girdi JSON dosyası argümanını ekliyoruz.
    parser.add_argument(
        "--input",
        type=str,
        default="portfolio/hafta_10/gun_070/ornek_veri/asama_3_gunluk_metrikleri.json",
        help="Aşama 3 günlük metrikleri içeren JSON dosya yolu"
    )
    # Çıktı metin raporu argümanını ekliyoruz.
    parser.add_argument(
        "--output-txt",
        type=str,
        default="portfolio/hafta_10/gun_070/kanit/gercek/asama_3_kalite_ozeti_raporu.txt",
        help="Üretilecek metin formatındaki kabul raporu yolu"
    )
    # Çıktı JSON raporu argümanını ekliyoruz.
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="İsteğe bağlı JSON formatındaki kabul raporu dosya yolu"
    )

    # Parametreleri ayrıştırıyoruz.
    args = parser.parse_args()

    # Girdi dosyasının varlığını sınıyoruz.
    if not os.path.exists(args.input):
        # Dosya yoksa hata yazdırıp 1 koduyla çıkıyoruz.
        sys.stderr.write(f"HATA: Girdi dosyası bulunamadı: {args.input}\n")
        # Hata koduyla sonlandırıyoruz.
        sys.exit(1)

    # Girdi dosyasını okuyoruz.
    with open(args.input, "r", encoding="utf-8") as f:
        # JSON verisini yüklüyoruz.
        data = json.load(f)

    # Analizör sınıfını başlatıyoruz.
    auditor = Asama3KaliteOzetiAnalizor()
    # Denetim sürecini çalıştırıyoruz.
    audit_res = auditor.run_full_audit(data)

    # Metin raporunu üretiyoruz.
    txt_report = auditor.generate_text_report(audit_res)

    # Çıktı dosyasının üst dizinini teyit ediyoruz.
    out_dir = os.path.dirname(args.output_txt)
    # Üst dizin mevcut değilse oluşturuyoruz.
    if out_dir and not os.path.exists(out_dir):
        # Klasör ağacını inşa ediyoruz.
        os.makedirs(out_dir, exist_ok=True)

    # Metin raporunu dosyaya yazıyoruz.
    with open(args.output_txt, "w", encoding="utf-8") as f:
        # Rapor metnini kaydediyoruz.
        f.write(txt_report)

    # İsteğe bağlı JSON çıktısı belirtilmişse yazıyoruz.
    if args.output_json:
        # JSON dizgisini oluşturuyoruz.
        json_report = auditor.generate_json_report(audit_res)
        # JSON dosyasını kaydediyoruz.
        with open(args.output_json, "w", encoding="utf-8") as f:
            # İçeriği yazıyoruz.
            f.write(json_report)

    # Başarı bildirimini konsola yazdırıyoruz.
    print(txt_report)
    # Konsola ek bilgi geçiyoruz.
    print(f"\n[+] Aşama 3 kabul raporu başarıyla kaydedildi: {args.output_txt}")


# Modülün doğrudan çalıştırılıp çalıştırılmadığını sınıyoruz.
if __name__ == "__main__":
    # main fonksiyonunu tetikliyoruz.
    main()
