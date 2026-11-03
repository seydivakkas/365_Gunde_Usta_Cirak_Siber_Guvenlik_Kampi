# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 030: Linux journalctl ve Günlük Dizinleri Denetim Motoru.
Bu modül; systemd-journald günlüklerini ayrıştırır, kalıcılık (persistent vs volatile)
durumunu denetler (G030-SC1), saat dilimi korelasyonunu sağlar (UTC vs Yerel Saat),
gelişmiş filtreleme uygular ve adli kanıt üretir (G030-SC2).
"""

# Komut satırı argümanlarını ayrıştırmak için standart kütüphane modülü içe aktarılır.
import argparse
# Olayların zaman damgalarını uluslararası ISO 8601 ve UTC formatında işlemek için içe aktarılır.
import datetime
# Günlük kayıtlarının kriptografik bütünlük özetini (SHA256) hesaplamak için içe aktarılır.
import hashlib
# Yapılandırılmış JSON veri dosyalarını okumak ve yazmak için içe aktarılır.
import json
# Dosya sistemi ve dizin varlık kontrollerini yürütmek için içe aktarılır.
import os
# Mesaj ve servis adlarında güvenlik desenlerini regex ile aramak için içe aktarılır.
import re
# Standart girdi/çıktı akışlarını ve sistem parametrelerini yönetmek için içe aktarılır.
import sys
# Tip ipuçları ile nesne yönelimli mimarinin güvenliğini pekiştirmek için içe aktarılır.
from typing import Any, Dict, List, Optional, Tuple


# Windows konsollarında Türkçe karakterlerin bozulmasını önlemek için stdout kodlaması yapılandırılır.
if hasattr(sys.stdout, "reconfigure"):
    # Standart çıktı akışı UTF-8 kodlamasına zorlanır ve karakter hataları güvenle ikame edilir.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class JournalValidationError(Exception):
    """
    Journal günlüğü girdisinde eksik alan veya geçersiz değer olduğunda fırlatılan istisna.
    Negatif kontrol ve adli veri bütünlüğü testi için kullanılır.
    """
    # Özel hata mesajını ve hata kodunu saklayan yapıcı fonksiyon.
    def __init__(self, message: str, error_code: str, entry_data: Optional[Dict[str, Any]] = None):
        # Üst sınıf Exception başlatıcısı çağrılır.
        super().__init__(message)
        # Hata kodu nitelik olarak atanır.
        self.error_code = error_code
        # Hatalı veri sözlüğü saklanır.
        self.entry_data = entry_data or {}


class LinuxJournalValidator:
    """
    systemd journal kayıtlarının teknik alan bütünlüğünü denetleyen doğrulayıcı sınıf.
    Öncelik sınırlarını (0-7), zaman damgası geçerliliğini ve kalıcılık risklerini sınar.
    """

    # Syslog öncelik seviyesi sözlüğü (0: En Kritik - 7: En Düşük).
    PRIORITY_LEVELS = {
        0: "emerg",
        1: "alert",
        2: "crit",
        3: "err",
        4: "warning",
        5: "notice",
        6: "info",
        7: "debug"
    }

    @classmethod
    # Tek bir journal kaydını doğrulayan ana statik metod.
    def validate_entry(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Journal kaydını doğrular.
        Dönüş: (is_valid: bool, error_code: Optional[str], detail: Optional[str])
        """
        # 1. Kontrol: Mesaj içeriği (MESSAGE) dolu ve geçerli dize olmalıdır.
        msg = data.get("message")
        if not msg or not str(msg).strip():
            # Mesajı boş olan kayıt adli delil niteliği taşımaz.
            return False, "MISSING_MESSAGE", "Günlük mesajı (MESSAGE) boş veya tanımsız!"

        # 2. Kontrol: Öncelik düzeyi (PRIORITY) 0 ile 7 arasında tamsayı olmalıdır.
        raw_priority = data.get("priority")
        if raw_priority is None:
            # Öncelik düzeyi eksikse hata verilir.
            return False, "MISSING_PRIORITY", "Syslog öncelik seviyesi (PRIORITY) eksik!"
        try:
            # Önceliğin tamsayıya çevrilmesi denenir.
            pri_int = int(raw_priority)
            if pri_int not in cls.PRIORITY_LEVELS:
                # 0-7 dışındaki değerler reddedilir.
                return False, "INVALID_PRIORITY_LEVEL", f"Öncelik düzeyi 0-7 aralığında olmalıdır, gelen değer: {pri_int}."
        except (ValueError, TypeError):
            # Sayısal olmayan öncelik reddedilir.
            return False, "INVALID_PRIORITY_LEVEL", f"Öncelik düzeyi sayısal olmalıdır: '{raw_priority}'."

        # 3. Kontrol: UTC Zaman Damgasının ISO format uygunluğu.
        time_utc = data.get("time_utc")
        if not time_utc or not isinstance(time_utc, str):
            # Zaman damgası yoksa hata döndürülür.
            return False, "MISSING_TIME_CREATED", "Zaman damgası (time_utc) eksik!"
        try:
            # UTC 'Z' harfi standartlaştırılıp doğrulanır.
            iso_clean = time_utc.replace("Z", "+00:00")
            datetime.datetime.fromisoformat(iso_clean)
        except ValueError:
            # Bozuk zaman formatı reddedilir.
            return False, "MALFORMED_TIMESTAMP", f"Zaman damgası geçerli ISO 8601 formatında değil: '{time_utc}'."

        # 4. Kontrol: Kalıcılık (Storage Persistence) Denetimi (G030-SC1 & G030-SC3).
        # Eğer depolama konumu geçici bellek (/run/log/journal) ise veya is_persistent False ise risk bildirilir.
        storage_loc = data.get("storage_location", "")
        is_persistent = data.get("is_persistent", True)
        if "/run/" in str(storage_loc) or is_persistent is False:
            # Geçici bellek kullanımı sistem yeniden başlatıldığında log kaybına yol açar (CWE-778).
            return False, "VOLATILE_STORAGE_RISK", "Günlükler geçici bellekte (/run/log/journal) tutuluyor! Yeniden başlatmada silinme riski (CWE-778)."

        # Tüm adli bütünlük kurallarını başarıyla geçen kayıt onaylanır.
        return True, None, None


class LinuxJournalctlAuditor:
    """
    Linux systemd-journald günlüklerini ve yapılandırmasını denetleyen ana motor.
    Zaman dilimi korelasyonu (UTC vs Local), birim filtreleme ve adli kanıt üretimi yapar.
    """

    # Başlatıcı metod; veri listelerini hazırlar.
    def __init__(self):
        # Yüklenen ve doğrulanan günlük kayıtları listesi.
        self.verified_entries: List[Dict[str, Any]] = []
        # Reddedilen veya riskli bulunan kayıtlar listesi.
        self.rejected_entries: List[Dict[str, Any]] = []
        # journald.conf yapılandırma parametreleri sözlüğü.
        self.journald_conf: Dict[str, str] = {}

    # JSON dosyasından günlük kayıtlarını yükleyen metod.
    def load_journal_from_json(self, json_path: str) -> List[Dict[str, Any]]:
        """JSON dosyasındaki günlükleri okur, doğrular ve SHA-256 ile mühürler."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_entries = data.get("journal_entries", [])
        self.verified_entries = []
        self.rejected_entries = []

        for entry in raw_entries:
            is_valid, err_code, detail = LinuxJournalValidator.validate_entry(entry)
            if is_valid:
                # Kriptografik bütünlük özeti (SHA256) hesaplanır.
                hash_payload = f"{entry.get('cursor')}:{entry.get('systemd_unit')}:{entry.get('time_utc')}:{entry.get('message')}".encode("utf-8")
                entry["integrity_sha256"] = hashlib.sha256(hash_payload).hexdigest()
                self.verified_entries.append(entry)
            else:
                self.rejected_entries.append({
                    "entry": entry,
                    "error_code": err_code,
                    "detail": detail
                })

        return self.verified_entries

    # journald.conf yapılandırma dosyasını ayrıştıran metod (G030-SC1 & G030-SC3).
    def load_journald_conf(self, conf_path: str) -> Dict[str, str]:
        """/etc/systemd/journald.conf dosyasını okur ve temel güvenlik parametrelerini çıkarır."""
        self.journald_conf = {}
        if not os.path.exists(conf_path):
            return self.journald_conf

        with open(conf_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Yorum ve boş satırları atla.
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    self.journald_conf[key.strip()] = val.strip()

        return self.journald_conf

    # Çok ölçütlü filtreleme metodu (G030-SC2).
    def filter_entries(
        self,
        unit: Optional[str] = None,
        max_priority: Optional[int] = None,
        search_pattern: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Birim (unit), maksimum öncelik (priority) ve metin desenine göre filtreler.
        journalctl -u <unit> -p <priority> mantığını simüle eder.
        """
        results: List[Dict[str, Any]] = []

        for e in self.verified_entries:
            # 1. Birim filtresi (Örn: sshd.service)
            if unit:
                entry_unit = e.get("systemd_unit", "")
                if unit.lower() not in entry_unit.lower():
                    continue

            # 2. Öncelik filtresi (Örn: 4 ve altı -> err, crit, emerg)
            if max_priority is not None:
                if int(e.get("priority", 7)) > max_priority:
                    continue

            # 3. Metin deseni filtresi
            if search_pattern:
                msg = e.get("message", "")
                if not re.search(search_pattern, msg, re.IGNORECASE):
                    continue

            results.append(e)

        return results

    # Bozuk günlük veri kümesini test eden negatif kontrol metodu (G030-SC2).
    def test_corrupted_dataset(self, corrupted_json_path: str) -> Dict[str, Any]:
        """Bozuk ve geçici bellek kullanan kayıtların reddedildiğini doğrular."""
        with open(corrupted_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        corrupt_list = data.get("corrupted_entries", [])
        results: List[Dict[str, Any]] = []
        rejected_count = 0

        for item in corrupt_list:
            case_id = item.get("test_case_id", "TEST-X")
            entry_data = item.get("data", {})
            expected_err = item.get("expected_error", "")

            is_valid, actual_code, detail = LinuxJournalValidator.validate_entry(entry_data)
            if not is_valid:
                rejected_count += 1
                matched = (actual_code == expected_err) or (expected_err in str(actual_code))
                results.append({
                    "case_id": case_id,
                    "status": "REJECTED_AS_EXPECTED",
                    "actual_error_code": actual_code,
                    "expected_error_code": expected_err,
                    "rule_matched": matched,
                    "detail": detail
                })
            else:
                results.append({
                    "case_id": case_id,
                    "status": "UNEXPECTEDLY_ACCEPTED",
                    "detail": "Bozuk veya geçici bellek günlüğü filtreden kaçtı!"
                })

        total = len(corrupt_list)
        return {
            "total_tested": total,
            "rejected_count": rejected_count,
            "passed": (rejected_count == total),
            "results": results
        }

    # Saat dilimi korelasyonu ve adli filtreleme raporu üreten metod (G030-SC1 & G030-SC2).
    def generate_audit_report(self, filtered_list: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Zaman dilimi (UTC ve Yerel Saat) karşılaştırmalı adli denetim raporu üretir.
        """
        target_list = filtered_list if filtered_list is not None else self.verified_entries
        lines: List[str] = []
        lines.append("======================================================================")
        lines.append("LINUX JOURNALCTL VE GÜNLÜK DİZİNLERİ ADLİ DENETİM RAPORU")
        lines.append("======================================================================")
        lines.append(f"Rapor Zamanı (UTC)     : {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        lines.append(f"Toplam Doğrulanan Kayıt: {len(self.verified_entries)}")
        lines.append(f"Filtrelenmiş Olay Sayısı: {len(target_list)}")
        lines.append(f"Reddedilen Hatalı Kayıt: {len(self.rejected_entries)}")

        # journald.conf durumu varsa raporlanır:
        if self.journald_conf:
            storage_mode = self.journald_conf.get("Storage", "auto")
            lines.append("----------------------------------------------------------------------")
            lines.append("YAPILANDIRMA DENETİMİ (/etc/systemd/journald.conf):")
            lines.append(f"   Kalıcılık Modu (Storage) : {storage_mode} {'[GÜVENLİ - DISKTE KALICI]' if storage_mode == 'persistent' else '[UYARI - GECICI]'}")
            lines.append(f"   FSS Mühürleme (Seal)     : {self.journald_conf.get('Seal', 'no')}")
            lines.append(f"   Maksimum Kota (SystemMax): {self.journald_conf.get('SystemMaxUse', 'Belirtilmedi')}")

        lines.append("----------------------------------------------------------------------")
        lines.append("G030-SC1 SAAT DİLİMİ VE KORELASYON İNCELEMESİ (UTC vs YEREL SAAT):")
        lines.append("----------------------------------------------------------------------")

        for idx, e in enumerate(target_list, start=1):
            pri_label = LinuxJournalValidator.PRIORITY_LEVELS.get(int(e.get("priority", 6)), "unknown")
            lines.append(f"\n[GÜNLÜK #{idx}] Birim: {e.get('systemd_unit')} (PID: {e.get('pid')}) | Öncelik: {e.get('priority')} ({pri_label.upper()})")
            lines.append(f"   Zaman (UTC)         : {e.get('time_utc')}")
            lines.append(f"   Zaman (Yerel Saat)  : {e.get('time_local')} (Ofset: {e.get('timezone_offset', '+00:00')})")
            lines.append(f"   Depolama Yolu       : {e.get('storage_location')} (Kalıcı: {e.get('is_persistent')})")
            lines.append(f"   Kriptografik İzi    : {e.get('integrity_sha256', '-')[:24]}...")
            lines.append(f"   Mesaj               : {e.get('message')}")

        lines.append("\n======================================================================")
        lines.append("GÜVENLİK VE ADLİ ANALİZ DERSİ (G030-SC1 & G030-SC2):")
        lines.append("- Saat dilimi farkı (+03:00 vs UTC), çoklu sunucu olay korelasyonunda")
        lines.append("  olayların sırasının yanlış yorumlanmasına yol açabilir.")
        lines.append("- Adli araştırmalarda daima `journalctl --utc` parametresi kullanılmalıdır.")
        lines.append("======================================================================")

        return "\n".join(lines)


def main():
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Gün 030: Linux journalctl ve Günlük Dizinleri Denetim Motoru."
    )
    parser.add_argument(
        "--logs",
        type=str,
        default="portfolio/hafta_05/gun_030/ornek_veri/sample_journal_logs.json",
        help="İncelenecek journal kayıtları JSON dosya yolu."
    )
    parser.add_argument(
        "--conf",
        type=str,
        default="portfolio/hafta_05/gun_030/ornek_veri/sample_journald_conf_baseline.ini",
        help="İncelenecek journald.conf dosya yolu."
    )
    parser.add_argument(
        "--unit",
        type=str,
        help="systemd birimine göre filtrele (örn: sshd.service)."
    )
    parser.add_argument(
        "--priority",
        type=int,
        help="Maksimum syslog öncelik seviyesi (0-7)."
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Detaylı adli denetim ve saat dilimi korelasyon raporu üretir."
    )
    parser.add_argument(
        "--test-corrupted",
        type=str,
        help="Bozuk journal kayıtları ile negatif kontrol testi çalıştırır."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı JSON olarak basar."
    )

    args = parser.parse_args()
    engine = LinuxJournalctlAuditor()

    # Negatif kontrol testi istenmişse:
    if args.test_corrupted:
        res = engine.test_corrupted_dataset(args.test_corrupted)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("======================================================================")
            print("NEGATİF KONTROL VE BOZUK VERİ DOĞRULAMA TESTİ (G030-SC2)")
            print("======================================================================")
            print(f"Toplam Test Edilen Hatalı Kayıt: {res['total_tested']}")
            print(f"Başarıyla Reddedilen Kayıt     : {res['rejected_count']}")
            print(f"Sonuç                          : {'TAM BAŞARILI (PASS)' if res['passed'] else 'BAŞARISIZ'}")
            print("----------------------------------------------------------------------")
            for item in res["results"]:
                print(f"[{item['status']}] {item['case_id']} -> {item['detail']}")
            print("======================================================================")
        sys.exit(0 if res["passed"] else 1)

    # Yapılandırma ve günlükleri yükleme:
    if os.path.exists(args.conf):
        engine.load_journald_conf(args.conf)

    if os.path.exists(args.logs):
        engine.load_journal_from_json(args.logs)

    # Filtreleme uygulama:
    filtered = engine.filter_entries(unit=args.unit, max_priority=args.priority)

    if args.json:
        print(json.dumps(filtered, indent=2, ensure_ascii=False))
    else:
        report = engine.generate_audit_report(filtered_list=filtered)
        print(report)


if __name__ == "__main__":
    main()
