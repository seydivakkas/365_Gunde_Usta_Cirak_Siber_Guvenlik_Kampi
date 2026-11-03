# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 077: Mini Proje 10 — Bağımsız Savunmacı Log Ayrıştırıcı (Standalone Security Log Parser)
Bu modül, Hafta 11'de işlenen tüm Python savunmacı kodlama prensiplerini (temiz kod,
ReDoS korumalı regex, küme cebri, brute-force kayan pencere, Unicode NFKC sanitizasyonu)
tek ve bağımsız bir adli bilişim ve log analiz motorunda birleştirir.
"""

# Hata sayaçları ve zaman takibi için collections içe aktarılır
import collections
# IP adresi sözdizimsel ve mantıksal doğrulaması için ipaddress içe aktarılır
import ipaddress
# Yapılandırılmış veri okuma ve yazma için json modülü içe aktarılır
import json
# Dosya sistemi ve yol kontrolleri için os modülü içe aktarılır
import os
# Savunmacı düzenli ifadeler için re modülü içe aktarılır
import re
# Zaman damgaları ve pencere hesaplamaları için time içe aktarılır
import time
# Unicode normalizasyonu ve karakter sınıfı analizi için unicodedata içe aktarılır
import unicodedata
# URL ayrıştırma ve kod çözme için urllib.parse içe aktarılır
import urllib.parse
# Tip güvenliği için typing modülü içe aktarılır
from typing import Any, Dict, Iterable, List, Optional, Pattern, Set, Tuple


class StandaloneSecurityLogParser:
    """
    Web, SSH ve Güvenlik Duvarı loglarını çok katmanlı savunmacı kontrollerle
    ayrıştıran, tehdit istihbaratı korelasyonu ve brute force tespiti yapan ana motor.
    """

    # ReDoS ve tampon taşması saldırılarını sınırlandırmak için satır tavanı
    MAX_LINE_LENGTH: int = 4096

    # Unicode Bidi Trojan Source (CVE-2021-42574) tehlikeli yön karakterleri
    BIDI_CONTROL_CHARS: Set[str] = {
        "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
        "\u2066", "\u2067", "\u2068", "\u2069"
    }

    # 1. Web Erişim Logu (Apache/Nginx Combined) Savunmacı Regex Deseni
    WEB_PATTERN: Pattern[str] = re.compile(
        r'^(?P<ip>[0-9a-fA-F.:]+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]{3,10})\s+(?P<uri>\S+)\s+(?P<protocol>HTTP/[0-9.]+)"\s+'
        r'(?P<status>[1-5]\d{2})\s+(?P<size>\d+|-)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$'
    )

    # 2. Linux SSH Kimlik Doğrulama Logu Savunmacı Regex Deseni
    SSHD_PATTERN: Pattern[str] = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+'
        r'(?P<auth_action>Failed|Accepted)\s+(?:password|publickey)\s+for\s+'
        r'(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+'
        r'(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)\s+ssh2$'
    )

    # 3. Güvenlik Duvarı Çekirdek Logu Savunmacı Regex Deseni
    FIREWALL_PATTERN: Pattern[str] = re.compile(
        r'^(?P<timestamp>[A-Z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+kernel:\s+\[(?P<rule_tag>\w+)\]\s+'
        r'SRC=(?P<src_ip>[0-9a-fA-F.:]+)\s+DST=(?P<dst_ip>[0-9a-fA-F.:]+)\s+'
        r'PROTO=(?P<proto>\w+)\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)\s+'
        r'ACTION=(?P<action>ALLOW|DROP|REJECT)$'
    )

    def __init__(self) -> None:
        """
        Log ayrıştırıcı motor başlatıcısı; dahili durum tablolarını kurar.
        """
        # Bilinen zararlı IP'ler kümesi (O(1) hızlı arama için set)
        self.ioc_set: Set[str] = set()
        # Kurumsal beyaz liste IP'ler kümesi (Yanlış alarmları bastırmak için)
        self.whitelist_set: Set[str] = set()
        # Saldırı imza desenleri listesi (SQLi, Path Traversal vb.)
        self.attack_signatures: List[Dict[str, Any]] = []
        # Kaynak IP bazlı başarısız kimlik doğrulama zaman damgaları (Brute force takibi)
        self.failed_auth_attempts: Dict[str, List[float]] = collections.defaultdict(list)
        # Kilitlenen IP adresleri kümesi
        self.locked_out_ips: Set[str] = set()
        # Brute force eşik ayarları
        self.brute_force_max_failures: int = 5
        self.brute_force_window_seconds: int = 60
        # Üretilen güvenlik alarmları listesi
        self.alerts: List[Dict[str, Any]] = []
        # Ayrıştırılan toplam geçerli olay sayısı
        self.parsed_event_count: int = 0
        # Ayrıştırılamayan malforme satır sayısı
        self.unrecognized_line_count: int = 0

    def load_rules_and_ioc(self, rules_path: str) -> None:
        """
        Tehdit istihbaratı kurallarını, beyaz listeyi ve imza sözlüklerini diskten yükler.
        """
        # Dosya mevcudiyeti kontrol edilir
        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"Kural dosyası bulunamadı: {rules_path}")

        # JSON kural dosyası okunur
        with open(rules_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        # IoC IP'leri kümeye dönüştürülür
        self.ioc_set = set(config.get("bilinen_zararli_ioc_ipleri", []))
        # Beyaz liste IP'leri kümeye dönüştürülür
        self.whitelist_set = set(config.get("kurumsal_beyaz_liste", []))

        # Saldırı imzaları derlenerek listeye eklenir
        self.attack_signatures = []
        for sig in config.get("saldiri_imzalari", []):
            self.attack_signatures.append({
                "name": sig["ad"],
                "compiled_re": re.compile(sig["desen"]),
                "risk": sig.get("risk", "HIGH")
            })

        # Brute force eşikleri atanır
        bf_config = config.get("brute_force_esigi", {})
        self.brute_force_max_failures = bf_config.get("maksimum_hatali_giris", 5)
        self.brute_force_window_seconds = bf_config.get("pencere_saniyesi", 60)

    def parse_single_line(self, raw_line: str) -> Dict[str, Any]:
        """
        Tek bir log satırını çok katmanlı savunmacı kontrollerden geçirerek ayrıştırır.
        """
        # Tip doğrulaması
        if not isinstance(raw_line, str):
            raise TypeError("Log satırı bir dize (str) olmalıdır.")

        # [SAVUNMA 1]: Girdi uzunluğu tavanı (ReDoS koruması)
        if len(raw_line) > self.MAX_LINE_LENGTH:
            raise ValueError(f"Log satırı izin verilen uzunluk tavanını ({self.MAX_LINE_LENGTH}) aştı.")

        # [SAVUNMA 2]: Null-Byte (\x00) enjeksiyon denetimi
        if "\x00" in raw_line:
            raise ValueError("Log satırında tehlikeli Null-Byte (\\x00) tespit edildi.")

        # [SAVUNMA 3]: Trojan Source (Bidi) yönlendirme karakterleri denetimi
        for bidi_ch in self.BIDI_CONTROL_CHARS:
            if bidi_ch in raw_line:
                raise ValueError("Log satırında Unicode Bidi (Trojan Source) karakteri tespit edildi.")

        # [SAVUNMA 4]: Unicode NFKC kanonik normalizasyonu
        normalized_line = unicodedata.normalize("NFKC", raw_line.strip())

        # [SAVUNMA 5]: ANSI terminal kaçış kodları ve tehlikeli kontrol karakterlerinin temizliği
        clean_line = self._strip_ansi_and_control_chars(normalized_line)

        # Biçim belirleme ve Regex ayrıştırma
        record: Dict[str, Any] = {}

        # 1. Web log formatı denemesi
        web_match = self.WEB_PATTERN.match(clean_line)
        if web_match:
            record = web_match.groupdict()
            record["log_type"] = "WEB_ACCESS"
            self._validate_and_enrich_ip(record["ip"])
            record["status"] = int(record["status"])
            record["size"] = int(record["size"]) if record["size"] != "-" else 0
            self._check_web_attack_signatures(record)
            self._check_ioc_reputation(record["ip"], "WEB_ACCESS_IOC")

        else:
            # 2. SSHD log formatı denemesi
            sshd_match = self.SSHD_PATTERN.match(clean_line)
            if sshd_match:
                record = sshd_match.groupdict()
                record["log_type"] = "SSH_AUTH"
                self._validate_and_enrich_ip(record["ip"])
                record["pid"] = int(record["pid"])
                record["port"] = int(record["port"])
                self._process_ssh_auth_event(record)
                self._check_ioc_reputation(record["ip"], "SSH_AUTH_IOC")

            else:
                # 3. Güvenlik Duvarı log formatı denemesi
                fw_match = self.FIREWALL_PATTERN.match(clean_line)
                if fw_match:
                    record = fw_match.groupdict()
                    record["log_type"] = "FIREWALL_TRAFFIC"
                    self._validate_and_enrich_ip(record["src_ip"])
                    self._validate_and_enrich_ip(record["dst_ip"])
                    record["spt"] = int(record["spt"])
                    record["dpt"] = int(record["dpt"])
                    self._check_ioc_reputation(record["src_ip"], "FIREWALL_SRC_IOC")

                else:
                    # Tanınmayan veya malforme format
                    self.unrecognized_line_count += 1
                    return {
                        "log_type": "UNRECOGNIZED",
                        "raw_line": clean_line,
                        "status": "PARSE_SKIPPED"
                    }

        # Başarıyla ayrıştırılan olay sayısı güncellenir
        self.parsed_event_count += 1
        return record

    def _strip_ansi_and_control_chars(self, text: str) -> str:
        """
        ANSI terminal kaçış kodlarını ve yazdırılamayan kontrol baytlarını temizler.
        """
        # ANSI kaçış dizilerini temizleme
        no_ansi = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)
        # Yazdırılabilir karakterleri ve boşlukları koruma
        cleaned = [
            c for c in no_ansi
            if c in ("\t", "\n") or (unicodedata.category(c) != "Cc" and ord(c) >= 32)
        ]
        return "".join(cleaned)

    def _validate_and_enrich_ip(self, ip_str: str) -> None:
        """
        IP adresinin geçerliliğini katı şekilde doğrular.
        """
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Geçersiz IP adresi tespit edildi: {ip_str}")

    def _check_web_attack_signatures(self, record: Dict[str, Any]) -> None:
        """
        Web URI ve istek parametrelerinde bilinen saldırı imzalarını (SQLi, LFI) tarar.
        """
        # Ham URI değeri alınır
        uri = record.get("uri", "")
        # URL kodlamasını (URL decoding / unquote) çözerek %20 gibi atlatmaları kanonikleştiririz
        decoded_uri = urllib.parse.unquote_plus(uri)
        # Tüm derlenmiş saldırı imzaları taranır
        for sig in self.attack_signatures:
            # Hem ham hem de çözülmüş URI üzerinde arama yapılır
            if sig["compiled_re"].search(uri) or sig["compiled_re"].search(decoded_uri):
                # Eşleşme durumunda güvenlik alarmı oluşturulur
                self.alerts.append({
                    "alert_type": f"WEB_ATTACK_{sig['name']}",
                    "source_ip": record["ip"],
                    "risk_level": sig["risk"],
                    "evidence": uri
                })

    def _process_ssh_auth_event(self, record: Dict[str, Any]) -> None:
        """
        SSH kimlik doğrulama olaylarını kayan pencere (sliding window) ile takip eder;
        başarısız girişler eşiği aştığında brute force kilidi uygular.
        """
        src_ip = record["ip"]
        action = record["auth_action"]

        if action == "Failed":
            now = time.time()
            # Başarısız girişim zaman damgası listeye eklenir
            self.failed_auth_attempts[src_ip].append(now)

            # Kayan pencere süresi dışındaki eski kayıtlar temizlenir
            valid_window_start = now - self.brute_force_window_seconds
            self.failed_auth_attempts[src_ip] = [
                t for t in self.failed_auth_attempts[src_ip] if t >= valid_window_start
            ]

            # Eşik kontrolü yapılır
            current_failures = len(self.failed_auth_attempts[src_ip])
            if current_failures >= self.brute_force_max_failures:
                if src_ip not in self.locked_out_ips:
                    self.locked_out_ips.add(src_ip)
                    self.alerts.append({
                        "alert_type": "BRUTE_FORCE_LOCKOUT",
                        "source_ip": src_ip,
                        "risk_level": "CRITICAL",
                        "failure_count": current_failures,
                        "evidence": f"{self.brute_force_window_seconds} saniyede {current_failures} hatalı deneme."
                    })

    def _check_ioc_reputation(self, ip_str: str, alert_tag: str) -> None:
        """
        IP'nin bilinen zararlı IoC kümesinde olup olmadığını O(1) hızla kontrol eder;
        beyaz listedeki IP'ler için yanlış alarm üretilmesini (False Positive) engeller.
        """
        # [KÜME FARKI SAVUNMASI]: Beyaz listede ise alarm üretilmez
        if ip_str in self.whitelist_set:
            return

        # [KÜME KESİŞİMİ KONTROLÜ]: IoC kümesinde var mı?
        if ip_str in self.ioc_set:
            self.alerts.append({
                "alert_type": alert_tag,
                "source_ip": ip_str,
                "risk_level": "HIGH",
                "evidence": f"Tehdit İstihbaratı Karaliste Eşleşmesi: {ip_str}"
            })

    def process_log_stream(self, lines: Iterable[str]) -> Dict[str, Any]:
        """
        Gelen log akışını satır satır işler ve konsolide güvenlik raporu üretir.
        """
        parsed_records: List[Dict[str, Any]] = []

        for line in lines:
            # Boş satırlar atlanır
            if not line or not line.strip():
                continue
            rec = self.parse_single_line(line)
            parsed_records.append(rec)

        # Özet metrikler hesaplanır
        summary = {
            "total_lines_read": len(parsed_records),
            "parsed_events_count": self.parsed_event_count,
            "unrecognized_lines_count": self.unrecognized_line_count,
            "total_alerts_generated": len(self.alerts),
            "locked_out_ips": sorted(list(self.locked_out_ips)),
            "alerts": self.alerts,
            "parsed_records": parsed_records
        }
        return summary

    def parse_log_file(self, file_path: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Belirtilen log dosyasını diskten güvenle okur, kuralları uygular ve rapor döndürür.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log dosyası bulunamadı: {file_path}")

        if rules_path is not None:
            self.load_rules_and_ioc(rules_path)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        return self.process_log_stream(lines)

    def generate_forensic_summary(self, result: Dict[str, Any]) -> str:
        """
        Ayrıştırma sonuçlarını insan-okunabilir adli bilişim özet raporu olarak biçimlendirir.
        """
        lines = [
            "================================================================================",
            "          MİNİ PROJE 10: BAĞIMSIZ GÜVENLİK LOG AYRIŞTIRMA VE ADLİ RAPOR        ",
            "================================================================================",
            f"Toplam İşlenen Satır   : {result.get('total_lines_read', 0)}",
            f"Ayrıştırılan Olaylar   : {result.get('parsed_events_count', 0)}",
            f"Tanınmayan Satırlar    : {result.get('unrecognized_lines_count', 0)}",
            f"Üretilen Tehdit Alarmı : {result.get('total_alerts_generated', 0)}",
            f"Kilitlenen Saldırgan IP: {len(result.get('locked_out_ips', []))} adet",
            "--------------------------------------------------------------------------------",
            "KİLİTLENEN SALDIRGANLAR (BRUTE FORCE LOCKOUT):",
        ]
        for ip in result.get("locked_out_ips", []):
            lines.append(f"  [BLOCKED] -> {ip}")

        lines.append("--------------------------------------------------------------------------------")
        lines.append("GÜVENLİK ALARMLARI VE TEHDİT KORELASYONLARI:")
        for al in result.get("alerts", []):
            lines.append(f"  [{al.get('risk_level', 'INFO')}] {al.get('alert_type')}: Kaynak IP={al.get('source_ip')}")
            lines.append(f"      Kanıt: {al.get('evidence')}")

        lines.append("================================================================================")
        return "\n".join(lines)


if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)
    log_file = os.path.join(base_dir, "..", "ornek_veri", "mixed_security_event_stream.log")
    rule_file = os.path.join(base_dir, "..", "ornek_veri", "threat_intel_and_whitelist_rules.json")

    parser = StandaloneSecurityLogParser()
    res = parser.parse_log_file(log_file, rule_file)
    print(parser.generate_forensic_summary(res))
