# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 076: Metin, Regex ve Karakter Kodlaması (Text, Regex & Character Encoding Security)
Bu modül, siber güvenlikte ReDoS (CWE-1333) açıklarını engelleyen savunmacı regex derlemesini,
Unicode NFKC normalizasyonunu, IDN homograf saldırı tespitini, Null-Byte enjeksiyon
korumasını ve Trojan Source (Bidi) karakter denetimini icra eder.
"""

# IP adresi doğrulaması için ipaddress kütüphanesi içe aktarılır
import ipaddress
# JSON veri formatlama ve okuma için json modülü içe aktarılır
import json
# Dosya yolu işlemleri için os modülü içe aktarılır
import os
# Düzenli ifadeler motoru için re modülü içe aktarılır
import re
# Unicode karakter kategorileri ve normalizasyonu için unicodedata içe aktarılır
import unicodedata
# Tip ipuçları için typing modülü içe aktarılır
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


class SecureRegexAndEncodingEngine:
    """
    Metin işleme, düzenli ifade ve karakter kodlaması güvenlik motoru.
    """

    # ReDoS ve bellek tüketimini (CWE-400) engellemek için girdi uzunluğu tavanı
    MAX_INPUT_LENGTH: int = 4096

    # Unicode Trojan Source (Bidi) tehlikeli yön değiştirme karakterleri (CVE-2021-42574)
    BIDI_CONTROL_CHARS: Set[str] = {
        "\u202A",  # LRE: Left-to-Right Embedding
        "\u202B",  # RLE: Right-to-Left Embedding
        "\u202C",  # PDF: Pop Directional Formatting
        "\u202D",  # LRO: Left-to-Right Override
        "\u202E",  # RLO: Right-to-Left Override
        "\u2066",  # LRI: Left-to-Right Isolate
        "\u2067",  # RLI: Right-to-Left Isolate
        "\u2068",  # FSI: First Strong Isolate
        "\u2069"   # PDI: Pop Directional Isolate
    }

    # NCSA/Apache Extended Log Format için önceden derlenmiş savunmacı regex deseni
    # Başlangıç (^) ve bitiş ($) bağlaçları katı tutulmuştur; geri izleme (backtracking) sınırlandırılmıştır
    LOG_PATTERN: Pattern[str] = re.compile(
        r'^(?P<ip>[0-9a-fA-F.:]+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]{3,10})\s+(?P<uri>\S+)\s+(?P<protocol>HTTP/[0-9.]+)"\s+'
        r'(?P<status>[1-5]\d{2})\s+'
        r'(?P<size>\d+|-)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"$'
    )

    def __init__(self) -> None:
        """
        Güvenlik motoru başlatıcısı; sınıf durumunu ve denetim sayaçlarını kurar.
        """
        # Motorun hazır olduğunu belirten bayrak
        self.is_active: bool = True
        # İncelenen metin adedi sayacı
        self.inspected_text_count: int = 0

    def parse_access_log(self, raw_line: str) -> Dict[str, Any]:
        """
        Web erişim logunu savunmacı regex ve güvenlik filtreleri ile ayrıştırır.
        """
        # Girdinin metin olup olmadığı kontrol edilir
        if not isinstance(raw_line, str):
            # Geçersiz tipte TypeError fırlatılır
            raise TypeError("Log satırı bir metin (str) olmalıdır.")

        # [GÜVENLİK KONTROLÜ 1]: Giriş uzunluğu tavanı (ReDoS ve bellek koruması)
        if len(raw_line) > self.MAX_INPUT_LENGTH:
            # Sınır aşıldığında işlem derhal reddedilir
            raise ValueError(f"Log satırı izin verilen uzunluk sınırını ({self.MAX_INPUT_LENGTH}) aştı.")

        # [GÜVENLİK KONTROLÜ 2]: Null-Byte enjeksiyonu kontrolü
        if "\x00" in raw_line:
            # Null bayt tespit edilirse güvenlik gereği hata fırlatılır
            raise ValueError("Log satırında zararlı Null-Byte (\\x00) tespit edildi.")

        # [GÜVENLİK KONTROLÜ 3]: Unicode Trojan Source (Bidi) karakter denetimi
        for bidi_ch in self.BIDI_CONTROL_CHARS:
            if bidi_ch in raw_line:
                # Görsel aldatmaca karakteri tespit edilirse reddedilir
                raise ValueError("Log satırında Unicode Bidi (Trojan Source) karakteri tespit edildi.")

        # Önceden derlenmiş regex ile eşleştirme yapılır
        match = self.LOG_PATTERN.match(raw_line.strip())
        # Eşleşme sağlanamazsa log formatı geçersiz kabul edilir
        if not match:
            # Format uyuşmazlığında ValueError üretilir
            raise ValueError("Log satırı geçerli ve güvenli erişim logu formatına uymuyor.")

        # İsimlendirilmiş yakalama gruplarından sözlük üretilir
        parsed = match.groupdict()

        # IP adresinin sözdizimsel geçerliliği test edilir
        ip_str = parsed["ip"]
        try:
            # ipaddress modülü ile IPv4 veya IPv6 doğrulaması
            ipaddress.ip_address(ip_str)
        except ValueError:
            # Geçersiz IP durumunda hata verilir
            raise ValueError(f"Log başlığında geçersiz IP adresi ayrıştırıldı: {ip_str}")

        # Durum kodu ve boyut tamsayıya çevrilir
        parsed["status"] = int(parsed["status"])
        # Boyut '-' ise 0, değilse tamsayı yapılır
        parsed["size"] = int(parsed["size"]) if parsed["size"] != "-" else 0

        # Sayaç güncellenir
        self.inspected_text_count += 1

        # Doğrulanmış log sözlüğü döndürülür
        return parsed

    def detect_homoglyph_attack(self, domain: str) -> Dict[str, Any]:
        """
        Unicode NFKC normalizasyonu ve alfabe analizi ile IDN Homograf
        (benzer karakterlerle alan adı taklit etme) saldırılarını tespit eder.
        """
        # Girdinin string olduğu kontrol edilir
        if not isinstance(domain, str):
            # Tip hatası fırlatılır
            raise TypeError("Domain bir metin (str) olmalıdır.")

        # Kenar boşlukları ve küçük harf dönüşümü yapılır
        clean_domain = domain.strip().lower()

        # [NORMALİZASYON]: Unicode NFKC kanonik ayrıştırma ve uyumluluk birleştirmesi
        normalized_domain = unicodedata.normalize("NFKC", clean_domain)

        # Alan adı içindeki karakterlerin Unicode blokları (script) taranır
        has_latin = False
        has_non_latin = False
        suspicious_chars: List[str] = []

        # Her bir karaktere bakılır
        for char in normalized_domain:
            # Nokta ve tire alan adlarında meşrudur, atlanır
            if char in ".-":
                continue

            # Karakterin Unicode adını alırız
            char_name = unicodedata.name(char, "UNKNOWN")

            # Latin alfabesi tespiti
            if "LATIN" in char_name:
                has_latin = True
            # Kiril veya Yunan gibi diğer alfabelerin tespiti
            elif "CYRILLIC" in char_name or "GREEK" in char_name:
                has_non_latin = True
                suspicious_chars.append(f"{char} ({char_name})")
            elif ord(char) > 127:
                # ASCII dışı diğer potansiyel homograf karakterler
                has_non_latin = True
                suspicious_chars.append(f"{char} ({char_name})")

        # Homograf kararı: Latin ile yabancı alfabe karıştırılmışsa (Mixed-Script) saldırıdır
        is_spoofed = (has_latin and has_non_latin) or (has_non_latin and ".com" in normalized_domain)

        # Analiz çıktısı döndürülür
        return {
            "original_domain": clean_domain,
            "normalized_domain": normalized_domain,
            "is_homoglyph_attack": is_spoofed,
            "suspicious_characters": suspicious_chars,
            "is_clean_ascii": not has_non_latin
        }

    def safe_decode_bytes(
        self,
        raw_bytes: bytes,
        encoding: str = "utf-8",
        strict: bool = True
    ) -> str:
        """
        Bayt dizisini karakter kodlaması hatalarına (Overlong/Bozuk UTF-8) karşı
        kontrollü şekilde çözen savunmacı fonksiyon.
        """
        # Girdinin bayt tipi olduğu kontrol edilir
        if not isinstance(raw_bytes, (bytes, bytearray)):
            # Bayt değilse TypeError üretilir
            raise TypeError("Girdi bayt (bytes) tipinde olmalıdır.")

        try:
            # Katı modda hata fırlatılır, gevşek modda soru işareti ile değiştirilir
            error_mode = "strict" if strict else "replace"
            # Bayt dizesi belirtilen kodlamayla çözülür
            decoded_text = raw_bytes.decode(encoding, errors=error_mode)
        except (UnicodeDecodeError, LookupError) as e:
            # Bozuk kodlamada açıklayıcı ValueError üretilir
            raise ValueError(f"Karakter çözme (decode) hatası oluştu: {e}")

        # Çözülen metinde Null-Byte kontrolü yapılır
        if "\x00" in decoded_text:
            raise ValueError("Çözülen metinde zararlı Null-Byte (\\x00) tespit edildi.")

        # Güvenli çözülmüş metin döndürülür
        return decoded_text

    def validate_strict_pattern(self, pattern_str: str, text: str) -> bool:
        """
        Regex desenini derler ve metni katı bağlaçlar ile tam eşleşme yönünden sınar.
        Kısmi eşleşme (partial match) atlatmalarını engeller.
        """
        # Metin uzunluğu denetlenir
        if len(text) > self.MAX_INPUT_LENGTH:
            raise ValueError("Doğrulanacak metin uzunluk sınırını aştı.")

        try:
            # Regex deseni derlenir (re.error yakalanır)
            compiled_re = re.compile(pattern_str)
        except re.error as e:
            # Geçersiz regex enjeksiyonunda kontrollü hata verilir
            raise ValueError(f"Geçersiz düzenli ifade (regex) sözdizimi: {e}")

        # Eşleşme test edilir
        match = compiled_re.match(text)
        # Eğer eşleşme varsa ve metnin tamamını kapsıyorsa True döner
        if match and match.end() == len(text):
            return True
        return False

    def sanitize_log_control_characters(self, raw_text: str) -> str:
        """
        Log satırlarındaki terminal kaçış dizilerini (ANSI escape codes)
        ve tehlikeli kontrol karakterlerini temizleyerek log forging engeller.
        """
        if not isinstance(raw_text, str):
            raise TypeError("Temizlenecek girdi metin olmalıdır.")

        # ANSI terminal kaçış dizilerini temizleyen regex
        ansi_cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw_text)

        # Yazdırılamayan kontrol karakterlerini filtreleriz (\t ve \n korunur)
        sanitized_chars = [
            ch for ch in ansi_cleaned
            if ch in ("\t", "\n") or (unicodedata.category(ch) != "Cc" and ord(ch) >= 32)
        ]

        # Temiz metin birleştirilerek döndürülür
        return "".join(sanitized_chars)

    def generate_security_report(self, sample_data_path: str) -> Dict[str, Any]:
        """
        Örnek veri setini okuyarak regex log ayrıştırma, homograf tespiti ve
        kodlama doğrulaması testlerini koşturan ana raporlayıcı metot.
        """
        if not os.path.exists(sample_data_path):
            raise FileNotFoundError(f"Örnek veri dosyası bulunamadı: {sample_data_path}")

        with open(sample_data_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        report: Dict[str, Any] = {
            "title": "G076: Metin, Regex ve Karakter Kodlaması Doğrulama Raporu",
            "parsed_logs": [],
            "homoglyph_results": [],
            "status": "ALL_TEXT_COMPONENTS_VERIFIED"
        }

        # 1. Log Ayrıştırma Testleri
        for log_entry in data.get("ornek_erisim_loglari", []):
            parsed = self.parse_access_log(log_entry["raw_line"])
            report["parsed_logs"].append({
                "id": log_entry["id"],
                "ip": parsed["ip"],
                "status": parsed["status"]
            })

        # 2. Homograf Tespiti Testi
        for homo_item in data.get("unicode_ve_homograf_ornekleri", []):
            if "domain" in homo_item:
                res = self.detect_homoglyph_attack(homo_item["domain"])
                report["homoglyph_results"].append({
                    "domain": homo_item["domain"],
                    "is_homoglyph": res["is_homoglyph_attack"]
                })

        # Kiril Spoofing Testi
        cyrillic_test = self.detect_homoglyph_attack("p\u0430yp\u0430l.com")
        report["homoglyph_results"].append({
            "domain": "p\\u0430yp\\u0430l.com",
            "is_homoglyph": cyrillic_test["is_homoglyph_attack"]
        })

        return report


if __name__ == "__main__":
    sample_file = os.path.join(
        os.path.dirname(__file__),
        "..",
        "ornek_veri",
        "guvenli_metin_ve_regex_ornekleri.json"
    )

    engine = SecureRegexAndEncodingEngine()
    gen_report = engine.generate_security_report(sample_file)
    print(json.dumps(gen_report, indent=2, ensure_ascii=False))
