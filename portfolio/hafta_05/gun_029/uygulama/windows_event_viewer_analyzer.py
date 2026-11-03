# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz veya yeniden yayınlanamaz.
# Ticari veya ticari olmayan hiçbir projede kullanılamaz, değiştirilemez.
# Alt lisanslanamaz, satılamaz veya devredilemez. Tersine mühendislik yapılamaz.
# İzin talepleri için: GitHub @seydivakkas
"""
Hafta 05, Gün 029: Windows Event Viewer'a Giriş ve Adli Olay Analiz Motoru.
Bu modül, Windows Olay Günlüklerini (EVTX / JSON) standartlara uygun biçimde ayrıştırır,
zorunlu alan bütünlüğünü doğrular (G029-SC2), tekil olay kimliklerini bağlamsal
korelasyon kurarak değerlendirir (G029-SC1) ve adli raporlar üretir.
"""

# Komut satırı argümanlarını ayrıştırmak için standart kütüphane modülü içe aktarılır.
import argparse
# Olayların zaman damgalarını uluslararası ISO 8601 standardında işlemek için içe aktarılır.
import datetime
# Olay kayıtlarının kriptografik bütünlük özetini (SHA256) hesaplamak için içe aktarılır.
import hashlib
# Yapılandırılmış JSON veri dosyalarını okumak ve yazmak için içe aktarılır.
import json
# Dosya sistemi ve dizin varlık kontrollerini yürütmek için içe aktarılır.
import os
# Metin ve mesaj alanlarında güvenlik kalıplarını regex ile denetlemek için içe aktarılır.
import re
# Windows üzerinde canlı olay sorgularını güvenle alt süreçte koşturmak için içe aktarılır.
import subprocess
# Standart girdi/çıktı akışlarını ve sistem parametrelerini yönetmek için içe aktarılır.
import sys
# Tip ipuçları ile nesne yönelimli mimarinin güvenliğini pekiştirmek için içe aktarılır.
from typing import Any, Dict, List, Optional, Tuple


# Windows konsollarında Türkçe karakterlerin bozulmasını önlemek için stdout kodlaması yapılandırılır.
if hasattr(sys.stdout, "reconfigure"):
    # Standart çıktı akışı UTF-8 kodlamasına zorlanır ve karakter hataları güvenle ikame edilir.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


class EventValidationError(Exception):
    """
    Olay kaydında zorunlu alan eksikliği veya biçim bozukluğu olduğunda fırlatılan istisna.
    Negatif kontrol ve adli veri doğrulaması için kullanılır (G029-SC2).
    """
    # Özel hata mesajını ve hata kodunu saklayan yapıcı fonksiyon.
    def __init__(self, message: str, error_code: str, event_data: Optional[Dict[str, Any]] = None):
        # Üst sınıf olan Exception başlatıcısı çağrılır.
        super().__init__(message)
        # Hata kodu nitelik olarak atanır.
        self.error_code = error_code
        # Hatalı olay verisi kaydedilir.
        self.event_data = event_data or {}


class WindowsEventValidator:
    """
    Windows olay kaydının teknik alan bütünlüğünü denetleyen doğrulayıcı sınıf.
    ProviderName, EventID, TimeCreated ve Kanal alanlarının doğruluğunu şart koşar.
    """

    # Olay kaydında bulunması zorunlu anahtar alanlar listesi.
    MANDATORY_FIELDS = ["provider_name", "event_id", "time_created"]

    @classmethod
    # Tek bir olay sözlüğünün yapısal geçerliliğini denetleyen metod.
    def validate_event_dict(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Olay verisini doğrular.
        Dönüş: (is_valid: bool, error_code: Optional[str], message: Optional[str])
        """
        # Sağlayıcı adının (ProviderName) varlığı ve dolu olduğu kontrol edilir.
        provider = data.get("provider_name")
        if not provider or not str(provider).strip():
            # Sağlayıcı adı eksikse adli geçersizlik bildirilir.
            return False, "MISSING_PROVIDER_NAME", "Olay Sağlayıcı Adı (ProviderName) boş veya eksik!"

        # Olay Kimliğinin (EventID) varlığı ve sayısal niteliği kontrol edilir.
        raw_event_id = data.get("event_id")
        if raw_event_id is None:
            # Olay kimliği yoksa hata döndürülür.
            return False, "MISSING_EVENT_ID", "Olay Kimliği (EventID) tanımlanmamış!"

        # Olay kimliğinin tamsayıya dönüştürülebilirliği test edilir.
        try:
            # Sayısal değere çevirme denenir.
            int(raw_event_id)
        except (ValueError, TypeError):
            # Sayısal olmayan olay kimliği reddedilir.
            return False, "INVALID_EVENT_ID", f"Olay Kimliği (EventID) tamsayı olmalıdır, gelen değer: '{raw_event_id}'."

        # Zaman damgasının (TimeCreated) geçerli bir ISO biçiminde olup olmadığı denetlenir.
        time_str = data.get("time_created")
        if not time_str or not isinstance(time_str, str):
            # Zaman damgası eksikse hata kodu üretilir.
            return False, "MISSING_TIME_CREATED", "Zaman Damgası (TimeCreated) eksik veya geçersiz türde!"

        # ISO 8601 tarih biçiminin doğrulanması regex ve datetime ayrıştırması ile sınanır.
        try:
            # 'Z' harfi UTC için '+00:00' formatına uyarlanarak test edilir.
            iso_clean = time_str.replace("Z", "+00:00")
            datetime.datetime.fromisoformat(iso_clean)
        except ValueError:
            # Tarih formatı bozuksa negatif kontrol hatası verilir.
            return False, "MALFORMED_TIMESTAMP", f"Zaman Damgası (TimeCreated) geçerli ISO 8601 formatında değil: '{time_str}'."

        # Kanal (channel) ve Bilgisayar (computer) üstveri alanlarının kontrolü (varsa boş olmamalıdır).
        channel = data.get("channel")
        computer = data.get("computer")
        if (channel is not None and not str(channel).strip()) or (computer is not None and not str(computer).strip()):
            # Eksik veya boş kanal/bilgisayar üstverisi reddedilir.
            return False, "MISSING_MANDATORY_METADATA", "Kanal (channel) veya Bilgisayar (computer) üstverisi boş olamaz!"

        # Olay kaydı tüm biçimsel kuralları başarıyla karşılamıştır.
        return True, None, None


class ContextualCorrelationEngine:
    """
    Olayları tekil kimliklerine göre değil, bağlamsal ilişkilerine göre değerlendiren motor.
    G029-SC1 İlkesi: 'Tek bir olay kimliği bağlam olmadan saldırı kanıtı değildir.'
    """

    # Şüpheli dizin desenleri (Örn: Geçici veya kullanıcı dizininden servis/süreç başlatılması).
    SUSPICIOUS_PATHS = [
        r"\\AppData\\Local\\Temp",
        r"\\Windows\\Temp",
        r"C:\\Users\\[^\\]+\\Downloads",
        r"C:\\Users\\[^\\]+\\AppData\\Roaming"
    ]

    @classmethod
    # Bir olayı bağlamsal olarak analiz edip güvenlik değerlendirmesi üreten metod.
    def evaluate_event_context(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Olayı derinlemesine bağlamsal analize tabi tutar.
        Tekil kimlik yerine; kullanıcı, süreç yolu, frekans ve MITRE tekniğini korele eder.
        """
        event_id = int(event.get("event_id", 0))
        provider = event.get("provider_name", "")
        raw_msg = event.get("raw_message", "")
        event_data = event.get("event_data", {})

        # Varsayılan bağlam analizi değişkenleri tanımlanır.
        verdict = "NORMAL_BASELINE"
        risk_level = "LOW"
        rationale = "Olay olağan sistem işleyişi kapsamında gözlemlenmiştir."
        mitre_mapping = "N/A"

        # Durum 1: Event 7045 - Yeni Servis Kurulumu (Persistence / Privilege Escalation)
        if event_id == 7045:
            mitre_mapping = "T1543.003 - Create or Modify System Process: Windows Service"
            image_path = event_data.get("ImagePath", "") or raw_msg
            service_name = event_data.get("ServiceName", "Unknown")

            # İkili dosya yolu şüpheli geçici dizinlerde mi aranır?
            is_suspicious_path = any(re.search(pat, image_path, re.IGNORECASE) for pat in cls.SUSPICIOUS_PATHS)

            if is_suspicious_path:
                verdict = "SUSPICIOUS_SERVICE_INSTALLATION"
                risk_level = "HIGH"
                rationale = f"Yeni servis ('{service_name}') şüpheli/geçici dizinden çalıştırılmak üzere kuruldu: '{image_path}'."
            else:
                verdict = "AUTHORIZED_SERVICE_INSTALLATION"
                risk_level = "INFORMATIONAL"
                rationale = f"Sistem genelinde yeni servis ('{service_name}') kuruldu. İkili yol meşru görünüyor: '{image_path}'."

        # Durum 2: Event 1074 - Sistem Kapatma veya Yeniden Başlatma
        elif event_id == 1074:
            mitre_mapping = "T1529 - System Shutdown/Reboot"
            user = event_data.get("InitiatingUser") or event.get("user_name", "")
            reason = event_data.get("Reason", "") or "Belirtilmemiş"

            verdict = "SYSTEM_SHUTDOWN_PLANNED"
            risk_level = "LOW"
            rationale = f"Sistem yeniden başlatması '{user}' kullanıcısı tarafından başlatıldı. Gerekçe: '{reason}'."

        # Durum 3: Event 6005 - Olay Günlüğü Servisi Başlatıldı (System Boot)
        elif event_id == 6005:
            mitre_mapping = "N/A - System Baseline"
            verdict = "SYSTEM_BOOT_AUDIT_START"
            risk_level = "INFO"
            rationale = "İşletim sistemi başlatıldı ve EventLog servisi günlük kaydına başladı."

        # Durum 4: Event 4625 - Başarısız Oturum Açma (Logon Failure)
        elif event_id == 4625:
            mitre_mapping = "T1110 - Brute Force"
            # Tek bir 4625 saldırı ispatı değildir!
            verdict = "SINGLE_LOGON_FAILURE"
            risk_level = "LOW_TO_MEDIUM"
            rationale = "Tekil başarısız oturum açma olayı. Kullanıcı parola yazım hatası olabilir; ancak yüksek frekansla tekrarlanırsa kaba kuvvet (Brute Force) alarmı üretilmelidir (G029-SC1)."

        # Durum 5: Event 1102 - Güvenlik Günlüğü Silindi (Clear Event Logs)
        elif event_id == 1102:
            mitre_mapping = "T1070.001 - Clear Windows Event Logs"
            verdict = "AUDIT_LOG_TAMPERING"
            risk_level = "CRITICAL"
            rationale = "Güvenlik günlüğü yetkili bir kullanıcı tarafından temizlendi! Savunmadan kaçınma (Defense Evasion) göstergesidir."

        # Bağlamsal değerlendirme sonucu döndürülür.
        return {
            "verdict": verdict,
            "risk_level": risk_level,
            "rationale": rationale,
            "mitre_mapping": mitre_mapping,
            "context_rule_applied": "G029-SC1 Bağlamsal Güvenlik Analizi"
        }


class WindowsEventViewerAnalyzer:
    """
    Windows Event Viewer denetim motoru.
    Girdi dosyalarını okur, doğrular, bağlamsal analizi yürütür ve adli kanıt üretir.
    """

    # Başlatıcı metod; veri yapılarını hazırlar.
    def __init__(self):
        # İşlenen doğrulanmış olaylar listesi.
        self.analyzed_events: List[Dict[str, Any]] = []
        # Doğrulamadan geçemeyen bozuk olaylar listesi.
        self.rejected_events: List[Dict[str, Any]] = []

    # JSON dosyasından olay kayıtlarını yükleyip ayrıştıran metod.
    def load_events_from_json(self, json_path: str) -> List[Dict[str, Any]]:
        """JSON dosyasındaki olayları okur ve doğrular."""
        # Dosya UTF-8 kodlamasında açılır.
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_events = data.get("events", [])
        self.analyzed_events = []
        self.rejected_events = []

        for item in raw_events:
            # Alan doğrulaması yapılır.
            is_valid, err_code, err_msg = WindowsEventValidator.validate_event_dict(item)
            if is_valid:
                # Bağlamsal analiz çalıştırılır.
                context_eval = ContextualCorrelationEngine.evaluate_event_context(item)
                item["context_eval"] = context_eval

                # Kriptografik bütünlük özeti (SHA256) hesaplanır.
                hash_payload = f"{item.get('record_id')}:{item.get('event_id')}:{item.get('time_created')}:{item.get('raw_message')}".encode("utf-8")
                item["integrity_sha256"] = hashlib.sha256(hash_payload).hexdigest()

                self.analyzed_events.append(item)
            else:
                self.rejected_events.append({
                    "data": item,
                    "error_code": err_code,
                    "error_message": err_msg
                })

        return self.analyzed_events

    # Bozuk olaylar test kümesini doğrulayan negatif kontrol metodu (G029-SC2).
    def test_corrupted_dataset(self, corrupted_json_path: str) -> Dict[str, Any]:
        """
        Bozuk olayların sistem tarafından tespit edilip reddedildiğini doğrular.
        Negatif kontrol mekanizması.
        """
        with open(corrupted_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        corrupted_list = data.get("corrupted_events", [])
        results: List[Dict[str, Any]] = []
        rejected_count = 0

        for entry in corrupted_list:
            case_id = entry.get("test_case_id", "TEST-X")
            event_payload = entry.get("data", {})
            expected_err = entry.get("expected_error", "")

            is_valid, actual_code, msg = WindowsEventValidator.validate_event_dict(event_payload)
            if not is_valid:
                rejected_count += 1
                matched = (actual_code == expected_err) or (expected_err in str(actual_code))
                results.append({
                    "case_id": case_id,
                    "status": "REJECTED_AS_EXPECTED",
                    "actual_error_code": actual_code,
                    "expected_error_code": expected_err,
                    "rule_matched": matched,
                    "detail": msg
                })
            else:
                results.append({
                    "case_id": case_id,
                    "status": "UNEXPECTEDLY_ACCEPTED",
                    "detail": "Bozuk olay güvenlik filtresinden kaçtı!"
                })

        total = len(corrupted_list)
        return {
            "total_tested": total,
            "rejected_count": rejected_count,
            "passed": (rejected_count == total),
            "results": results
        }

    # Yerel Windows sisteminde PowerShell ile canlı olay sorgulayan metod.
    def query_live_windows_events(self, log_name: str = "System", max_events: int = 3) -> List[Dict[str, Any]]:
        """
        Windows ortamında Get-WinEvent çalıştırarak canlı olayları çeker.
        Windows dışı ortamda veya yetki yetersizliğinde kontrollü fallback uygular.
        """
        live_records: List[Dict[str, Any]] = []
        # İşletim sistemi Windows değilse canlı sorgu atlanır.
        if sys.platform != "win32":
            return []

        # PowerShell komut dizesi hazırlanır; hassas veriler çekilmez, salt-okunur meta alanlar alınır.
        ps_cmd = (
            f"Get-WinEvent -LogName {log_name} -MaxEvents {max_events} | "
            "Select-Object RecordId, Id, ProviderName, TimeCreated, LevelDisplayName, Message | "
            "ConvertTo-Json -Compress"
        )

        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
                encoding="utf-8",
                errors="replace"
            )
            if proc.returncode == 0 and proc.stdout.strip():
                parsed = json.loads(proc.stdout)
                # Tek bir nesne veya liste dönme durumunu normalize et.
                items = parsed if isinstance(parsed, list) else [parsed]
                for raw in items:
                    time_iso = str(raw.get("TimeCreated", ""))
                    # Zaman dizesini ISO standardına yakınlaştır.
                    clean_entry = {
                        "record_id": raw.get("RecordId", 0),
                        "provider_name": str(raw.get("ProviderName", "")),
                        "event_id": int(raw.get("Id", 0)),
                        "level": str(raw.get("LevelDisplayName", "Information")),
                        "channel": log_name,
                        "time_created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "computer": os.environ.get("COMPUTERNAME", "LOCALHOST"),
                        "raw_message": str(raw.get("Message", "")).strip()[:300]
                    }
                    live_records.append(clean_entry)
        except Exception:
            # Canlı sorgu başarısız olursa boş liste döndürülür.
            pass

        return live_records

    # Adli olay analizi kartlarını metin formatında raporlayan metod.
    def generate_forensic_report(self) -> str:
        """
        G029-SC2 gereğince 3 sistem olayının alanlarıyla ayrıntılı adli dökümünü üretir.
        """
        lines: List[str] = []
        lines.append("======================================================================")
        lines.append("WINDOWS EVENT VIEWER ADLİ VE GÜVENLİK OLAY ANALİZ RAPORU")
        lines.append("======================================================================")
        lines.append(f"Analiz Zamanı (UTC)  : {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        lines.append(f"İncelenen Olay Sayısı : {len(self.analyzed_events)}")
        lines.append(f"Reddedilen Hatalı Olay: {len(self.rejected_events)}")
        lines.append("Metodoloji           : G029-SC1 Bağlamsal Korelasyon & G029-SC2 3 Sistem Olayı")
        lines.append("----------------------------------------------------------------------")

        for idx, ev in enumerate(self.analyzed_events, start=1):
            ctx = ev.get("context_eval", {})
            lines.append(f"\n[OLAY #{idx}] Event ID: {ev.get('event_id')} | Provider: {ev.get('provider_name')}")
            lines.append(f"   Record ID       : {ev.get('record_id')}")
            lines.append(f"   Kanal (Channel) : {ev.get('channel')}")
            lines.append(f"   Düzey (Level)   : {ev.get('level')}")
            lines.append(f"   Zaman (UTC)     : {ev.get('time_created')}")
            lines.append(f"   Bilgisayar      : {ev.get('computer')}")
            lines.append(f"   Kullanıcı       : {ev.get('user_name', 'Bilinmiyor')} (SID: {ev.get('user_sid', '-')})")
            lines.append(f"   Kriptografik İzi: {ev.get('integrity_sha256', '-')[:24]}...")
            lines.append(f"   Ham Mesaj       : {ev.get('raw_message')[:140]}...")
            lines.append(f"   --> Bağlam Kararı : [{ctx.get('risk_level')}] {ctx.get('verdict')}")
            lines.append(f"   --> MITRE ATT&CK  : {ctx.get('mitre_mapping')}")
            lines.append(f"   --> Adli Gerekçe  : {ctx.get('rationale')}")

        lines.append("\n======================================================================")
        lines.append("GÜVENLİK KURALI HATIRLATMASI (G029-SC1):")
        lines.append("'Tek bir olay kimliği bağlam olmadan saldırı kanıtı değildir.'")
        lines.append("Her olay; zaman çizelgesi, kullanıcı ayrıcalığı ve süreç ağacıyla")
        lines.append("birlikte korele edilmelidir.")
        lines.append("======================================================================")

        return "\n".join(lines)


def main():
    """CLI giriş noktası."""
    parser = argparse.ArgumentParser(
        description="Gün 029: Windows Event Viewer Analiz ve Adli Korelasyon Motoru."
    )
    parser.add_argument(
        "--events",
        type=str,
        default="portfolio/hafta_05/gun_029/ornek_veri/sample_system_events.json",
        help="İncelenecek sistem olayları JSON dosya yolu."
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Olayları ayrıştırıp adli döküm raporunu ekrana basar."
    )
    parser.add_argument(
        "--test-corrupted",
        type=str,
        help="Bozuk/eksik olay kayıtları ile negatif kontrol testi çalıştırır."
    )
    parser.add_argument(
        "--query-live",
        action="store_true",
        help="Windows üzerinde Get-WinEvent ile canlı System log sorgular."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları JSON formatında basar."
    )

    args = parser.parse_args()
    engine = WindowsEventViewerAnalyzer()

    # Negatif kontrol testi istenmişse:
    if args.test_corrupted:
        res = engine.test_corrupted_dataset(args.test_corrupted)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("======================================================================")
            print("NEGATİF KONTROL VE BOZUK VERİ DOĞRULAMA TESTİ (G029-SC2)")
            print("======================================================================")
            print(f"Toplam Test Edilen Hatalı Olay : {res['total_tested']}")
            print(f"Başarıyla Reddedilen Olay     : {res['rejected_count']}")
            print(f"Sonuç                          : {'TAM BAŞARILI (PASS)' if res['passed'] else 'BAŞARISIZ'}")
            print("----------------------------------------------------------------------")
            for item in res["results"]:
                print(f"[{item['status']}] {item['case_id']} -> {item['detail']}")
            print("======================================================================")
        sys.exit(0 if res["passed"] else 1)

    # Canlı sorgu modu istenmişse:
    if args.query_live:
        live_events = engine.query_live_windows_events()
        print(f"[BİLGİ] Canlı sistemden çekilen olay sayısı: {len(live_events)}")
        if live_events:
            for ev in live_events:
                print(f"  RecordId: {ev['record_id']} | ID: {ev['event_id']} | Provider: {ev['provider_name']}")

    # Olay analizi ve raporlama:
    if args.analyze or not (args.test_corrupted or args.query_live):
        if os.path.exists(args.events):
            engine.load_events_from_json(args.events)
            report_text = engine.generate_forensic_report()
            if args.json:
                print(json.dumps(engine.analyzed_events, indent=2, ensure_ascii=False))
            else:
                print(report_text)


if __name__ == "__main__":
    main()
