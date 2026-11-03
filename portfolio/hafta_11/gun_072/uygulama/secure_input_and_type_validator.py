# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G072: Değişkenler, Veri Tipleri ve Güvenli Giriş Doğrulama Motoru.

Bu modül, siber güvenlik araçları, CLI programları ve otomasyon scriptlerine gelen
güvenilmez (untrusted) kullanıcı girdilerini; tip karmaşası (type confusion),
komut enjeksiyonu (command injection), dizin atlatma (path traversal),
tam sayı sınır aşımı (integer overflow) ve null byte zehirlemelerine karşı
katı beyaz liste (whitelisting) ve kanonikleştirme ilkeleriyle denetler.
"""

# Dosya ve dizin yolu denetimleri için os modülünü içeri aktarıyoruz.
import os
# Komut satırı argümanlarını ayrıştırmak için argparse modülünü kullanıyoruz.
import argparse
# JSON veri formatı ayrıştırma ve serileştirme için json kütüphanesini çağırıyoruz.
import json
# Çıkış kodları ve akış yönlendirmesi için sys modülünü ekliyoruz.
import sys
# Tip güvenliği için typing modülünden gerekli tipleri alıyoruz.
from typing import Dict, Any, List, Optional, Union
# Unicode karakter kanonikleştirme (NFKC) için unicodedata modülünü dahil ediyoruz.
import unicodedata
# IPv4 adreslerinin doğrulanması ve oktet sınır kontrolleri için ipaddress modülünü alıyoruz.
import ipaddress
# Düzenli ifadeler (Regex) ile sözdizimi doğrulaması için re modülünü kullanıyoruz.
import re
# Raporlama zaman damgaları için datetime ve timezone sınıflarını çağırıyoruz.
from datetime import datetime, timezone


class SecureInputValidationError(ValueError):
    """Güvensiz girdi, tip uyuşmazlığı veya sınır ihlali durumlarında fırlatılan özel istisna."""
    # ValueError temel sınıfından türeyerek hata yakalama hiyerarşisini kuruyoruz.
    pass


class SecureInputAndTypeValidator:
    """
    Güvenli değişken tipi dönüşümü, sınır kontrolü ve girdi sanitizasyonu motoru.
    """

    # Kabuk (Shell) komut enjeksiyonlarında kullanılan tehlikeli metakarakterler listesi
    SHELL_INJECTION_CHARS = [";", "|", "&", "$", "`", "<", ">", "\n", "\r", "\\", "!", "(", ")"]

    # RFC 1123 uyarınca azami ana makine adı (hostname) uzunluk sınırı
    MAX_HOSTNAME_LEN = 253

    # RFC 1123 uyumlu alan adı ve ana makine regex deseni
    HOSTNAME_REGEX = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    def __init__(self) -> None:
        """Denetleyici sınıfının kurucu metodu."""
        # Doğrulanan girdi sayacını sıfır olarak ilklendiriyoruz.
        self.validated_inputs_count: int = 0

    def canonicalize_string(self, raw_val: Any) -> str:
        """
        Girdiyi dizgiye dönüştürür, Unicode NFKC normalizasyonu uygular ve null byte denetimi yapar.

        Parametreler:
            raw_val: Ham girdi nesnesi.

        Döndürür:
            Kanonikleştirilmiş ve temizlenmiş metin.
        """
        # Girdinin string tipinde olduğunu sınıyoruz.
        if not isinstance(raw_val, str):
            # Dize değilse dönüştürüyoruz.
            raw_val = str(raw_val)

        # Null byte (\x00) içerip içermediğini kontrol ediyoruz.
        if "\x00" in raw_val:
            # Null byte tespitinde istisna fırlatıyoruz.
            raise SecureInputValidationError("Null byte enjeksiyonu (\\x00) tespit edildi.")

        # Unicode NFKC (Compatibility Decomposition + Canonical Composition) uyguluyoruz.
        normalized = unicodedata.normalize("NFKC", raw_val)
        # Baş ve sondaki boşlukları siliyoruz.
        clean_text = normalized.strip()

        # Kanonikleştirilmiş metni döndürüyoruz.
        return clean_text

    def validate_integer(
        self, val: Any, min_val: Optional[int] = None, max_val: Optional[int] = None, param_name: str = "tamsayı"
    ) -> int:
        """
        Girdinin katı bir tamsayı olduğunu ve belirtilen aralıkta bulunduğunu doğrular.
        Tip karmaşasını (Type Confusion) engellemek için bool tipini kesinlikle reddeder.

        Parametreler:
            val: Denetlenecek değer.
            min_val: İsteğe bağlı taban sınır.
            max_val: İsteğe bağlı tavan sınır.
            param_name: Hata mesajlarında kullanılacak parametre adı.

        Döndürür:
            Doğrulanmış int değeri.
        """
        # Python'da bool sınıfı int'ten türediği için isinstance(True, int) True döner; bunu engelliyoruz.
        if isinstance(val, bool):
            # Tip karmaşası hatası fırlatıyoruz.
            raise SecureInputValidationError(
                f"Tip karmaşası (Type Confusion): Boolean tipi {param_name}/tamsayı olarak kabul edilemez."
            )

        # Eğer değer string ise rakamlardan oluştuğunu teyit ediyoruz.
        if isinstance(val, str):
            # Kanonikleştiriyoruz.
            clean_str = self.canonicalize_string(val)
            # Sayısal karakterleri kontrol ediyoruz (işaret dahil).
            if not re.match(r"^[-+]?\d+$", clean_str):
                # Rakam dışı karakter hatası veriyoruz.
                raise SecureInputValidationError(
                    f"Geçersiz tamsayı biçimi: '{val}' rakam olmayan karakterler içeriyor."
                )
            try:
                # String'i int tipine dönüştürüyoruz.
                parsed_int = int(clean_str)
            except ValueError:
                # Dönüşüm hatası fırlatıyoruz.
                raise SecureInputValidationError(f"Dönüştürülemeyen tamsayı: '{val}'")
        elif isinstance(val, int):
            # Değer zaten tam sayı ise doğrudan alıyoruz.
            parsed_int = val
        else:
            # Diğer geçersiz tipleri reddediyoruz.
            raise SecureInputValidationError(
                f"Geçersiz veri tipi: {type(val).__name__} ({param_name} için tamsayı bekleniyor)."
            )

        # Taban sınır denetimi yapıyoruz.
        if min_val is not None and parsed_int < min_val:
            # Sınır aşımı hatası fırlatıyoruz.
            raise SecureInputValidationError(
                f"{param_name.capitalize()} sınır aşımı: {parsed_int} (Asgari sınır: {min_val})"
            )

        # Tavan sınır denetimi yapıyoruz.
        if max_val is not None and parsed_int > max_val:
            # Sınır aşımı hatası veriyoruz.
            raise SecureInputValidationError(
                f"{param_name.capitalize()} sınır aşımı: {parsed_int} (Azami sınır: {max_val})"
            )

        # Doğrulanmış tam sayıyı döndürüyoruz.
        return parsed_int

    def validate_port(self, val: Any) -> int:
        """
        Ağ port numarasının 1 ile 65535 arasında geçerli bir tam sayı olduğunu doğrular.

        Parametreler:
            val: Denetlenecek port değeri.

        Döndürür:
            1-65535 aralığında geçerli port numarası.
        """
        # Boolean tip karmaşasını önceden sınıyoruz.
        if isinstance(val, bool):
            # Port tipi hatası veriyoruz.
            raise SecureInputValidationError(
                "Tip karmaşası (Type Confusion): Boolean tipi port/tamsayı olarak kabul edilemez."
            )

        try:
            # validate_integer fonksiyonunu 1-65535 aralığıyla çağırıyoruz.
            port = self.validate_integer(val, min_val=1, max_val=65535, param_name="port")
        except SecureInputValidationError as err:
            # Eğer sınır aşımı söz konusuysa açık standart port mesajını iletiyoruz.
            if "sınır aşımı" in str(err).lower():
                # Port sınır aşımı mesajını fırlatıyoruz.
                raise SecureInputValidationError(
                    f"Port sınır aşımı: {val} (Geçerli aralık: 1-65535)"
                )
            # Diğer hataları olduğu gibi iletiyoruz.
            raise

        # Geçerli port numarasını döndürüyoruz.
        return port

    def validate_ipv4(self, val: Any) -> str:
        """
        Girdinin geçerli bir IPv4 adresi (0.0.0.0 - 255.255.255.255) olduğunu doğrular.

        Parametreler:
            val: Denetlenecek IP adresi.

        Döndürür:
            Kanonik IPv4 adres dizgisi.
        """
        # Metni kanonikleştiriyoruz.
        clean_ip = self.canonicalize_string(val)

        try:
            # ipaddress modülünün katı ayrıştırmasını çalıştırıyoruz.
            ip_obj = ipaddress.IPv4Address(clean_ip)
            # Kanonik dizgiyi alıyoruz.
            return str(ip_obj)
        except (ipaddress.AddressValueError, ValueError):
            # Geçersiz IPv4 adresi istisnası fırlatıyoruz.
            raise SecureInputValidationError(
                f"Geçersiz IPv4 adresi: '{val}' (Oktet 0-255 aralığında olmalıdır)."
            )

    def validate_hostname(self, val: Any) -> str:
        """
        Ana makine adının RFC 1123 uyumlu olduğunu ve komut enjeksiyon karakterleri içermediğini doğrular.

        Parametreler:
            val: Denetlenecek hostname.

        Döndürür:
            Güvenli ana makine adı dizgisi.
        """
        # Girdiyi kanonikleştiriyoruz.
        clean_host = self.canonicalize_string(val)

        # Uzunluk sınırını denetliyoruz.
        if len(clean_host) > self.MAX_HOSTNAME_LEN:
            # DoS ve arabellek aşımı engelleme hatası veriyoruz.
            raise SecureInputValidationError(
                f"Dize uzunluk sınırı aşıldı: {len(clean_host)} karakter (Azami: {self.MAX_HOSTNAME_LEN})"
            )

        # Kabuk metakarakterlerinin varlığını sınıyoruz.
        for ch in self.SHELL_INJECTION_CHARS:
            # Eğer yasaklı karakter varsa komut enjeksiyonu hatası veriyoruz.
            if ch in clean_host:
                # Komut enjeksiyonu istisnası fırlatıyoruz.
                raise SecureInputValidationError(
                    f"Komut enjeksiyonu riski: Ana makine adında yasaklı karakter '{ch}' tespit edildi."
                )

        # Regex ile RFC 1123 desenini sınıyoruz.
        if not self.HOSTNAME_REGEX.match(clean_host):
            # Geçersiz sözdizimi hatası veriyoruz.
            raise SecureInputValidationError(
                f"RFC 1123 uyumsuz ana makine adı: '{clean_host}'"
            )

        # Güvenli hostname değerini döndürüyoruz.
        return clean_host

    def validate_safe_path(self, base_dir: str, untrusted_filename: str) -> str:
        """
        Dizin atlatma (Path Traversal) saldırılarını engellemek için dosya yolunu kanonikleştiren fonksiyon.

        Parametreler:
            base_dir: İzin verilen güvenli kök dizin.
            untrusted_filename: Kullanıcıdan gelen güvenilmez dosya adı veya göreli yol.

        Döndürür:
            Güvenli mutlak dosya yolu.
        """
        # Güvenilmez dosya adını kanonikleştiriyoruz.
        clean_name = self.canonicalize_string(untrusted_filename)

        # Güvenli temel dizinin mutlak yolunu alıyoruz.
        abs_base = os.path.abspath(base_dir)
        # Hedef mutlak yolu oluşturuyoruz.
        abs_target = os.path.abspath(os.path.join(abs_base, clean_name))

        # Hedef yolun temel dizin altında kalıp kalmadığını commonpath ile sınıyoruz.
        try:
            # Ortak kök yolu hesaplıyoruz.
            common = os.path.commonpath([abs_base, abs_target])
            # Eğer ortak yol temel dizine eşit değilse dizin atlatma yapılmıştır.
            if common != abs_base:
                # Dizin atlatma hatası veriyoruz.
                raise SecureInputValidationError(
                    "Dizin atlatma (Path Traversal) tespiti: Yol temel dizin dışına çıkamaz."
                )
        except ValueError:
            # Farklı sürücüler arası atlatma girişimlerinde hata veriyoruz.
            raise SecureInputValidationError(
                "Dizin atlatma (Path Traversal) tespiti: Yol temel dizin dışına çıkamaz."
            )

        # Güvenli mutlak yolu döndürüyoruz.
        return abs_target

    def validate_boolean(self, val: Any) -> bool:
        """
        Girdiyi katı biçimde mantıksal (Boolean) değere dönüştürür. Belirsiz değerleri reddeder.

        Parametreler:
            val: Denetlenecek değer.

        Döndürür:
            True veya False.
        """
        # Değer zaten boolean ise doğrudan döndürüyoruz.
        if isinstance(val, bool):
            # Değeri döndürüyoruz.
            return val

        # Değer integer ise sadece 1 ve 0'ı kabul ediyoruz.
        if isinstance(val, int):
            # 1 ise True veriyoruz.
            if val == 1:
                return True
            # 0 ise False veriyoruz.
            if val == 0:
                return False
            # Diğer sayılarda belirsizlik hatası fırlatıyoruz.
            raise SecureInputValidationError(
                f"Belirsiz mantıksal değer (Boolean): '{val}' geçerli bir bool (true/false/1/0) değildir."
            )

        # Değer metin ise katı beyaz liste denetimi yapıyoruz.
        if isinstance(val, str):
            # Metni küçük harfe çevirip temizliyoruz.
            s = self.canonicalize_string(val).lower()
            # Doğru değerler listesi
            if s in ["true", "1", "yes", "on"]:
                return True
            # Yanlış değerler listesi
            if s in ["false", "0", "no", "off"]:
                return False
            # Belirsiz dize hatası fırlatıyoruz.
            raise SecureInputValidationError(
                f"Belirsiz mantıksal değer (Boolean): '{val}' geçerli bir bool (true/false/1/0) değildir."
            )

        # Diğer tipleri belirsiz kabul edip reddediyoruz.
        raise SecureInputValidationError(
            f"Belirsiz mantıksal değer (Boolean): {type(val).__name__} tipi bool olarak yorumlanamaz."
        )

    def validate_payload(
        self, payload: Dict[str, Any], schema_spec: Dict[str, str], base_dir: str = "logs"
    ) -> Dict[str, Any]:
        """
        Karmaşık bir girdi sözlüğünü belirtilen şemaya göre baştan sona doğrular.

        Parametreler:
            payload: Kullanıcıdan gelen parametre sözlüğü.
            schema_spec: Her alan için beklenen tip tanımı ('ipv4', 'port', 'hostname', 'safe_path', 'boolean', 'integer').
            base_dir: safe_path doğrulaması için temel klasör.

        Döndürür:
            Tüm alanları doğrulanmış ve kanonikleştirilmiş temiz veri sözlüğü.
        """
        # Yükün sözlük tipinde olduğunu teyit ediyoruz.
        if not isinstance(payload, dict):
            # Sözlük değilse hata fırlatıyoruz.
            raise SecureInputValidationError("Girdi yükü bir JSON sözlüğü (dict) olmalıdır.")

        # Temiz verileri toplayacağımız sözlük
        sanitized_output: Dict[str, Any] = {}

        # Şemadaki her bir alanı sırayla sınıyoruz.
        for field_name, field_type in schema_spec.items():
            # Eğer alan payload'da yoksa atlayabilir veya varsayılan belirleyebiliriz.
            if field_name not in payload:
                # Bir sonraki alana geçiyoruz.
                continue

            # Ham değeri alıyoruz.
            raw_val = payload[field_name]

            # Tip kurallarına göre yönlendirme yapıyoruz.
            if field_type == "ipv4":
                # IPv4 doğrulaması.
                sanitized_output[field_name] = self.validate_ipv4(raw_val)
            elif field_type == "port":
                # Port doğrulaması.
                sanitized_output[field_name] = self.validate_port(raw_val)
            elif field_type == "hostname":
                # Hostname doğrulaması.
                sanitized_output[field_name] = self.validate_hostname(raw_val)
            elif field_type == "safe_path":
                # Dizin atlatma korumalı dosya yolu doğrulaması.
                sanitized_output[field_name] = self.validate_safe_path(base_dir, str(raw_val))
            elif field_type == "boolean":
                # Katı mantıksal değer doğrulaması.
                sanitized_output[field_name] = self.validate_boolean(raw_val)
            elif field_type == "integer":
                # Genel tamsayı doğrulaması.
                sanitized_output[field_name] = self.validate_integer(raw_val, param_name=field_name)
            else:
                # Bilinmeyen tipler için genel dize kanonikleştirme yapıyoruz.
                sanitized_output[field_name] = self.canonicalize_string(raw_val)

        # Doğrulanan girdi sayacını güncelliyoruz.
        self.validated_inputs_count += len(sanitized_output)

        # Temiz ve güvenli sözlüğü döndürüyoruz.
        return sanitized_output

    def generate_text_report(self, validated_data: Dict[str, Any]) -> str:
        """Doğrulama sonuçlarını içeren kurumsal rapor metni üretir."""
        # Satırlar listesini ilklendiriyoruz.
        lines = []
        # Üst çizgi
        lines.append("=" * 80)
        # Başlık
        lines.append("G072: DEĞİŞKENLER, VERİ TİPLERİ VE GÜVENLİ GİRİŞ DOĞRULAMA RAPORU")
        # Telif ve lisans
        lines.append("Telif Hakkı (c) 2026 Seydi Eryılmaz | Özel Lisans — Tüm Hakları Saklıdır")
        # Ayırıcı çizgi
        lines.append("=" * 80)
        # Boş satır
        lines.append("")

        # Yönetici Özeti
        lines.append("1. GİRDİ GÜVENLİK DENETİMİ ÖZETİ")
        # Alt çizgi
        lines.append("-" * 40)
        # Durum
        lines.append("Denetim Durumu            : TAM BAŞARILI (PASS)")
        # Zaman damgası
        lines.append(f"Zaman Damgası UTC         : {datetime.now(timezone.utc).isoformat()}")
        # Doğrulanan alan sayısı
        lines.append(f"Doğrulanan Alan Sayısı    : {len(validated_data)}")
        # Kanonikleştirme durumu
        lines.append("Unicode Kanonikleştirme   : NFKC Aktif")
        # Null byte koruması
        lines.append("Null Byte Filtreleme      : Aktif (Sıfır Tolerans)")
        # Tip karmaşası koruması
        lines.append("Tip Karmaşası Koruması    : Aktif (Boolean vs Int Trap Engellendi)")
        # Boş satır
        lines.append("")

        # Doğrulanan Alanlar Tablosu
        lines.append("2. DOĞRULANMIŞ VE KANONİKLEŞTİRİLMİŞ PARAMETRELER")
        # Alt çizgi
        lines.append("-" * 80)
        # Tablo başlığı
        lines.append(f"{'Parametre Adı':<25} {'Doğrulanan Tip':<18} {'Güvenli Değer'}")
        # Tablo ayırıcı
        lines.append("-" * 80)
        # Sözlüğü döngüye alıyoruz.
        for k, v in validated_data.items():
            # Satırı biçimlendirip ekliyoruz.
            lines.append(f"{k:<25} {type(v).__name__:<18} {str(v)}")
        # Ayırıcı çizgi
        lines.append("=" * 80)

        # Metni birleştirip döndürüyoruz.
        return "\n".join(lines)

    def generate_json_report(self, validated_data: Dict[str, Any]) -> str:
        """Denetim sonucunu JSON formatında serileştirir."""
        # JSON sözlüğünü oluşturuyoruz.
        res = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "PASS",
            "security_score": 100.0,
            "fields_validated_count": len(validated_data),
            "sanitized_payload": validated_data
        }
        # JSON metnini döndürüyoruz.
        return json.dumps(res, indent=2, ensure_ascii=False)


def main() -> None:
    """Komut satırı arayüzü (CLI) giriş fonksiyonu."""
    # Argparse nesnesi oluşturuyoruz.
    parser = argparse.ArgumentParser(
        description="G072: Güvenli Giriş ve Değişken Tipi Doğrulayıcı"
    )
    # Girdi JSON dosyası yolu
    parser.add_argument(
        "--input",
        type=str,
        default="portfolio/hafta_11/gun_072/ornek_veri/guvenli_girdi_ornekleri.json",
        help="Doğrulanacak JSON girdi dosya yolu"
    )
    # Metin rapor yolu
    parser.add_argument(
        "--output-txt",
        type=str,
        default="portfolio/hafta_11/gun_072/kanit/gercek/guvenli_girdi_dogrulama_raporu.txt",
        help="Üretilecek metin rapor yolu"
    )

    # Parametreleri ayrıştırıyoruz.
    args = parser.parse_args()

    # Girdi dosyasının varlığını kontrol ediyoruz.
    if not os.path.exists(args.input):
        # Dosya yoksa hata yazıp çıkıyoruz.
        sys.stderr.write(f"HATA: Girdi dosyası bulunamadı: {args.input}\n")
        # Hata koduyla çıkış.
        sys.exit(1)

    # Girdi dosyasını okuyoruz.
    with open(args.input, "r", encoding="utf-8") as f:
        # JSON verisini yüklüyoruz.
        raw_data = json.load(f)

    # Örnek tarama görevini çekiyoruz.
    scanner_task = raw_data.get("scanner_task", {})

    # Şema kurallarını tanımlıyoruz.
    schema = {
        "target_ip": "ipv4",
        "target_port": "port",
        "hostname": "hostname",
        "timeout_sec": "integer",
        "verbose": "boolean",
        "packet_count": "integer",
        "log_filename": "safe_path"
    }

    # Doğrulayıcıyı ilklendiriyoruz.
    validator = SecureInputAndTypeValidator()

    try:
        # Yükü doğruluyoruz.
        sanitized = validator.validate_payload(scanner_task, schema, base_dir="logs")
    except SecureInputValidationError as err:
        # Güvenlik doğrulama hatasını ekrana yazıyoruz.
        sys.stderr.write(f"GÜVENLİK GİRİŞ HATASI: {err}\n")
        # Çıkış koduyla sonlandırıyoruz.
        sys.exit(1)

    # Metin raporunu üretiyoruz.
    report_txt = validator.generate_text_report(sanitized)

    # Çıktı dizinini kontrol ediyoruz.
    out_dir = os.path.dirname(args.output_txt)
    # Dizin yoksa oluşturuyoruz.
    if out_dir and not os.path.exists(out_dir):
        # Dizin yapısını kuruyoruz.
        os.makedirs(out_dir, exist_ok=True)

    # Raporu dosyaya kaydediyoruz.
    with open(args.output_txt, "w", encoding="utf-8") as f:
        # İçeriği yazıyoruz.
        f.write(report_txt)

    # Konsola raporu yazdırıyoruz.
    print(report_txt)
    # Başarı bildirimini iletiyoruz.
    print(f"\n[+] Güvenli girdi doğrulama raporu kaydedildi: {args.output_txt}")


# Doğrudan çalıştırmayı yönetiyoruz.
if __name__ == "__main__":
    # main fonksiyonunu tetikliyoruz.
    main()
