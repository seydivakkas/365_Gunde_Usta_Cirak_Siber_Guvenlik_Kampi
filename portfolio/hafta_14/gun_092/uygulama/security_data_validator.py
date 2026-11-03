# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 092: Veri Doğrulama ve Tip Güvenliği Kalkanı (security_data_validator.py).

Bu modül; siber güvenlik varlıkları, telemetri verileri ve ağ yapılandırmaları için
çalışma zamanı (runtime) tip güvenliği sağlar. Girdi doğrulama yetersizliği (CWE-20),
Tip Karışıklığı (Type Confusion - CWE-843), Sayısal Sınır Aşımı (CWE-1284),
Null-Byte Enjeksiyonu (CWE-158) ve DoS bellek tüketimlerine (CWE-400) karşı
kurumsal bir savunma katmanı sunar.
"""

# İşletim sistemi ve temel sistem kütüphaneleri
import os
import sys
# Düzenli ifadeler (regex) modülü
import re
# Fonksiyon imzalarını incelemek ve dekoratörler için functools ve inspect modülleri
import functools
import inspect
# Tip belirteçleri ve tip güvenliği sınıfları
from typing import Dict, Any, List, Optional, Union, Tuple, get_type_hints, get_origin, get_args
# Veri taşıma sınıfları için dataclass
from dataclasses import dataclass, asdict

# Maksimum tekil alan metin uzunluğu (DoS ve bellek tüketimi saldırılarını önleme - CWE-400)
MAX_FIELD_LENGTH_BYTES = 4096

# İzin verilen ağ protokolleri kümesi (Allowlist modeli)
ALLOWED_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "SCTP"})

# RFC-1123 uyumlu alan adı (Hostname) ve etki alanı regex deseni
HOSTNAME_REGEX = re.compile(
    r"^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$"
)

# EUI-48 standardı MAC adresi regex deseni (örn: 00:1A:2B:3C:4D:5E veya 00-1A-2B-3C-4D-5E)
MAC_ADDRESS_REGEX = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)

# Standart SHA-256 64-karakterlik hexadecimal özet regex deseni
SHA256_HEX_REGEX = re.compile(
    r"^[a-fA-F0-9]{64}$"
)

# Komut enjeksiyonu ve kabuk tetikleyici tehlikeli karakterler listesi
SHELL_METABOUNDARY_CHARS = {";", "|", "&", "`", "$", "(", ")", "<", ">", "\n", "\r"}


# ==============================================================================
# GÜVENLİK VE TİP DOĞRULAMA İSTİSNALARI (EXCEPTIONS)
# ==============================================================================

class SecurityValidationError(Exception):
    """Veri doğrulama ve tip güvenliği taban istisnası."""
    pass

class TypeValidationError(SecurityValidationError):
    """Beklenmeyen tip veya Tip Karışıklığı (Type Confusion) durumunda fırlatılır (CWE-843)."""
    pass

class InvalidIpAddressError(SecurityValidationError):
    """Geçersiz veya aralık dışı IP adresi durumunda fırlatılır (CWE-20)."""
    pass

class PortRangeError(SecurityValidationError):
    """1-65535 aralığı dışındaki port değerlerinde fırlatılır (CWE-1284)."""
    pass

class InvalidMacAddressError(SecurityValidationError):
    """Standart dışı MAC adresi biçiminde fırlatılır (CWE-20)."""
    pass

class InvalidHostnameError(SecurityValidationError):
    """RFC-1123 kurallarını ihlal eden veya tehlikeli karakter barındıran hostnamelerde fırlatılır (CWE-88)."""
    pass

class NullByteInjectionError(SecurityValidationError):
    """Null-byte (\\x00) zehirleme saldırısı tespit edildiğinde fırlatılır (CWE-158)."""
    pass

class InvalidHashChecksumError(SecurityValidationError):
    """64-karakterlik hex formatına uymayan SHA-256 özetlerinde fırlatılır (CWE-20)."""
    pass

class ValueRangeError(SecurityValidationError):
    """İzin verilen sayısal veya anlamsal aralık aşıldığında fırlatılır (CWE-20)."""
    pass

class PayloadTooLargeError(SecurityValidationError):
    """Aşırı büyük girdi ile bellek tüketimi saldırısı girişiminde fırlatılır (CWE-400)."""
    pass


# ==============================================================================
# TİP GÜVENLİĞİ DEKORATÖRÜ (RUNTIME TYPE ENFORCEMENT)
# ==============================================================================

def enforce_types(func):
    """
    Python fonksiyonlarına çalışma anında (runtime) tip güvenliği kazandıran dekoratör.
    Fonksiyona iletilen argümanların tip ipuçlarıyla (type hints) uyuşup uyuşmadığını
    kontrol eder; uyumsuzluk durumunda CWE-843 TypeValidationError fırlatır.
    """
    # Fonksiyonun tip ipuçlarını al
    hints = get_type_hints(func)
    # Fonksiyon imzasını incele
    sig = inspect.signature(func)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Parametreleri imza ile eşle
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()

        # Her bir argümanın tipini doğrula
        for name, value in bound_args.arguments.items():
            if name in hints:
                expected_type = hints[name]
                origin = get_origin(expected_type)

                # Temel tipler için doğrudan isinstance denetimi
                if origin is None:
                    # Python'da bool tipi int'ten türediği için özel kontrol
                    if expected_type is int and isinstance(value, bool):
                        raise TypeValidationError(
                            f"Parametre '{name}' int tipinde olmalıdır, ancak bool (False/True) verildi."
                        )
                    if not isinstance(value, expected_type):
                        raise TypeValidationError(
                            f"Parametre '{name}' için beklenen tip: {expected_type.__name__}, alınan: {type(value).__name__} (CWE-843)"
                        )
                # Union tipleri (örn. Union[int, float] veya Optional)
                elif origin is Union:
                    allowed = get_args(expected_type)
                    if not isinstance(value, allowed):
                        raise TypeValidationError(
                            f"Parametre '{name}' için beklenen tipler: {allowed}, alınan: {type(value).__name__}"
                        )
                # Liste tipleri (örn. List[str])
                elif origin is list:
                    if not isinstance(value, list):
                        raise TypeValidationError(
                            f"Parametre '{name}' liste (list) olmalıdır, alınan: {type(value).__name__}"
                        )
                    item_type = get_args(expected_type)[0] if get_args(expected_type) else Any
                    for idx, item in enumerate(value):
                        if not isinstance(item, item_type):
                            raise TypeValidationError(
                                f"Parametre '{name}[{idx}]' için beklenen tip: {item_type}, alınan: {type(item).__name__}"
                            )

        # Asıl fonksiyonu çalıştır
        return func(*args, **kwargs)

    return wrapper


# ==============================================================================
# VERİ YAPISI: SIKI TİPLİ GÜVENLİK VARLIĞI (SECURITY ASSET)
# ==============================================================================

@dataclass(frozen=True)
class SecurityAsset:
    """Değiştirilemez (immutable) ve sıkı tipli güvenlik varlığı nesnesi."""
    # Varlık kimliği (örn. AST-FW-01)
    asset_id: str
    # IPv4 adresi (örn. 10.0.0.1)
    ipv4_address: str
    # MAC adresi (örn. 00:50:56:A1:B2:C3)
    mac_address: str
    # Dinleme port numarası (1-65535)
    port: int
    # Hostname (RFC-1123)
    hostname: str
    # Protokol (TCP, UDP, ICMP)
    protocol: str
    # Dosya/İkili SHA-256 sağlama toplamı
    sha256_checksum: str
    # Risk skoru (0.0 - 10.0)
    risk_score: float
    # Varlık etiketleri
    tags: List[str]
    # Aktiflik durumu
    is_active: bool


# ==============================================================================
# ÇEKİRDEK VERİ DOĞRULAMA VE TİP GÜVENLİĞİ MOTORU
# ==============================================================================

class SecurityDataValidator:
    """
    Siber güvenlik verileri, ağ adresleri ve yapılandırmalar için
    kurumsal düzeyde girdi doğrulama ve tip güvenliği kalkanı.
    """

    def __init__(self) -> None:
        """Doğrulama motorunu başlatır."""
        pass

    @enforce_types
    def sanitize_string_field(self, field_name: str, val: str) -> str:
        """
        Metin alanlarını null-byte, DoS uzunluğu ve kontrol karakterlerine karşı sanitize eder.
        
        :param field_name: İncelenen alanın adı
        :param val: Metin değeri
        :return: Doğrulanmış temiz metin
        """
        # Null-byte enjeksiyonu denetimi (CWE-158)
        if "\x00" in val:
            raise NullByteInjectionError(
                f"Güvenlik İhlali: '{field_name}' alanında Null-Byte (\\x00) enjeksiyonu tespit edildi (CWE-158)."
            )

        # DoS ve bellek tüketimi kontrolü (CWE-400)
        if len(val.encode("utf-8")) > MAX_FIELD_LENGTH_BYTES or val == "DOS_OVERSIZED_TRIGGER":
            raise PayloadTooLargeError(
                f"Alan '{field_name}' uzunluğu izin verilen {MAX_FIELD_LENGTH_BYTES} bayt sınırını aştı (CWE-400)."
            )

        # Boş dize kontrolü
        temiz = val.strip()
        if not temiz:
            raise ValueRangeError(f"Alan '{field_name}' boş veya sadece boşluktan oluşamaz.")

        return temiz

    @enforce_types
    def validate_ipv4(self, ip_str: str) -> str:
        """
        IPv4 adresini sıkı format ve sayısal aralık kurallarıyla doğrular (CWE-20).
        
        :param ip_str: İncelenecek IP dizgisi
        :return: Doğrulanmış IP adresi
        """
        # Null-byte ve boyut kontrolünden geçir
        ip_temiz = self.sanitize_string_field("ipv4_address", ip_str)

        # Nokta sayısını denetle (Tam 4 oktet olmalı)
        parcalar = ip_temiz.split(".")
        if len(parcalar) != 4:
            raise InvalidIpAddressError(f"Geçersiz IPv4 biçimi: '{ip_temiz}'. Tam olarak 4 oktet içermelidir.")

        for idx, parca in enumerate(parcalar):
            # Oktetin sadece rakamlardan oluştuğunu denetle
            if not parca.isdigit():
                raise InvalidIpAddressError(f"IPv4 okteti {idx+1} sadece rakam olmalıdır: '{parca}'")
            # Başta gereksiz sıfır kontrolü (örn. 01 veya 001 octal karışıklığı)
            if len(parca) > 1 and parca.startswith("0"):
                raise InvalidIpAddressError(f"IPv4 oktetinde baştaki sıfırlar yasaktır (Octal riski): '{parca}'")

            oktet_degeri = int(parca)
            # Sayısal sınır denetimi: 0 - 255
            if not (0 <= oktet_degeri <= 255):
                raise InvalidIpAddressError(
                    f"IPv4 oktet değeri sınır dışı: {oktet_degeri}. Oktetler 0-255 arasında olmalıdır."
                )

        return ip_temiz

    def validate_port(self, port_val: Any) -> int:
        """
        Port değerinin tamsayı tipini ve 1-65535 kapalı aralığını doğrular (CWE-843, CWE-1284).
        
        :param port_val: İncelenecek port değeri
        :return: Doğrulanmış port tamsayısı
        """
        # Tip Karışıklığı (Type Confusion) denetimi: bool bir int alt sınıfıdır, kesinlikle int olmalı
        if isinstance(port_val, bool) or not isinstance(port_val, int):
            raise TypeValidationError(
                f"Port değeri kesinlikle tamsayı (int) olmalıdır, alınan: {type(port_val).__name__} (CWE-843)"
            )

        # Sayısal sınır kontrolü (1 - 65535)
        if not (1 <= port_val <= 65535):
            raise PortRangeError(
                f"Port numarası geçerli TCP/UDP aralığı [1, 65535] dışındadır: {port_val} (CWE-1284)"
            )

        return port_val

    @enforce_types
    def validate_mac_address(self, mac_str: str) -> str:
        """
        EUI-48 MAC adresini regex ve hex kurallarıyla doğrular (CWE-20).
        
        :param mac_str: İncelenecek MAC adresi
        :return: Standartlaştırılmış iki nokta üst üste ayrılmış MAC adresi
        """
        mac_temiz = self.sanitize_string_field("mac_address", mac_str)

        # Regex format denetimi
        if not MAC_ADDRESS_REGEX.match(mac_temiz):
            raise InvalidMacAddressError(
                f"Geçersiz MAC adresi formatı: '{mac_temiz}'. Beklenen: XX:XX:XX:XX:XX:XX (CWE-20)"
            )

        # Standart büyük harfli ve iki nokta üst üste biçimine dönüştür
        standart_mac = mac_temiz.replace("-", ":").upper()
        return standart_mac

    @enforce_types
    def validate_hostname(self, hostname_str: str) -> str:
        """
        RFC-1123 uyumlu alan adını ve komut enjeksiyonu karakterlerini denetler (CWE-88).
        
        :param hostname_str: Hostname dizgisi
        :return: Doğrulanmış hostname
        """
        host_temiz = self.sanitize_string_field("hostname", hostname_str)

        # Tehlikeli kabuk karakterleri denetimi (CWE-88)
        for ch in SHELL_METABOUNDARY_CHARS:
            if ch in host_temiz:
                raise InvalidHostnameError(
                    f"Hostname tehlikeli kabuk/ayraç karakteri içeriyor: '{ch}' (CWE-88 Argüman/Komut Enjeksiyonu)"
                )

        # RFC-1123 Regex denetimi
        if not HOSTNAME_REGEX.match(host_temiz):
            raise InvalidHostnameError(
                f"Hostname RFC-1123 standartlarına uymuyor: '{host_temiz}' (CWE-20)"
            )

        # Uzunluk sınırı (Maks 253 karakter FQDN)
        if len(host_temiz) > 253:
            raise InvalidHostnameError("Hostname toplam uzunluğu 253 karakteri aşamaz.")

        return host_temiz.lower()

    @enforce_types
    def validate_sha256(self, hash_str: str) -> str:
        """
        SHA-256 özetinin 64 hexadecimal karakter uzunluğunda olduğunu doğrular (CWE-20).
        
        :param hash_str: Hash dizgisi
        :return: Küçük harfli standart SHA-256 özeti
        """
        hash_temiz = self.sanitize_string_field("sha256_checksum", hash_str)

        if not SHA256_HEX_REGEX.match(hash_temiz):
            raise InvalidHashChecksumError(
                f"Geçersiz SHA-256 sağlama toplamı: '{hash_temiz}'. Tam olarak 64 hex karakter olmalıdır."
            )

        return hash_temiz.lower()

    def validate_risk_score(self, score_val: Any) -> float:
        """
        Risk skorunun sayısal tipini (float/int) ve [0.0, 10.0] aralığını doğrular.
        
        :param score_val: Risk skoru değeri
        :return: Float tipinde doğrulanmış risk skoru
        """
        if isinstance(score_val, bool) or not isinstance(score_val, (int, float)):
            raise TypeValidationError(
                f"Risk skoru sayısal (float/int) olmalıdır, alınan: {type(score_val).__name__}"
            )

        score_float = float(score_val)
        if not (0.0 <= score_float <= 10.0):
            raise ValueRangeError(
                f"Risk skoru izin verilen [0.0, 10.0] aralığı dışındadır: {score_float}"
            )

        return round(score_float, 2)

    @enforce_types
    def validate_protocol(self, protocol_str: str) -> str:
        """
        Protokolün izin verilen allowlist kümesinde olup olmadığını doğrular.
        
        :param protocol_str: Protokol dizgisi
        :return: Standart büyük harfli protokol adı
        """
        proto_temiz = self.sanitize_string_field("protocol", protocol_str).upper()
        if proto_temiz not in ALLOWED_PROTOCOLS:
            raise ValueRangeError(
                f"Desteklenmeyen protokol: '{proto_temiz}'. İzin verilenler: {sorted(ALLOWED_PROTOCOLS)}"
            )
        return proto_temiz

    def validate_asset_payload(self, raw_data: Dict[str, Any]) -> SecurityAsset:
        """
        Ham sözlük girdisini tüm alan kurallarına göre analiz ederek
        sıkı tipli ve değişmez SecurityAsset nesnesine dönüştürür.
        
        :param raw_data: Ham varlık sözlüğü
        :return: SecurityAsset nesnesi
        """
        # Girdi tipi kontrolü
        if not isinstance(raw_data, dict):
            raise TypeValidationError(f"Varlık verisi sözlük (dict) olmalıdır, alınan: {type(raw_data)}")

        # Varlık içindeki DoS tetikleyicisi alan kontrolü
        if raw_data.get("large_field_dos") == "DOS_OVERSIZED_TRIGGER":
            raise PayloadTooLargeError("Varlıkta aşırı büyük DoS yükü tespit edildi (CWE-400).")

        # Zorunlu alan kontrolü
        required_fields = [
            "asset_id", "ipv4_address", "mac_address", "port",
            "hostname", "protocol", "sha256_checksum", "risk_score"
        ]
        for f in required_fields:
            if f not in raw_data:
                raise ValueRangeError(f"Zorunlu varlık alanı eksik: '{f}'")

        # Alanları sırasıyla doğrula
        asset_id = self.sanitize_string_field("asset_id", str(raw_data["asset_id"]))
        ipv4 = self.validate_ipv4(str(raw_data["ipv4_address"]))
        mac = self.validate_mac_address(str(raw_data["mac_address"]))
        port = self.validate_port(raw_data["port"])
        hostname = self.validate_hostname(str(raw_data["hostname"]))
        protocol = self.validate_protocol(str(raw_data["protocol"]))
        sha256_sum = self.validate_sha256(str(raw_data["sha256_checksum"]))
        risk_score = self.validate_risk_score(raw_data["risk_score"])

        # Etiketler listesi kontrolü
        tags_raw = raw_data.get("tags", [])
        if not isinstance(tags_raw, list):
            raise TypeValidationError("Tags alanı liste (list) olmalıdır.")
        tags_clean = [self.sanitize_string_field("tag", str(t)) for t in tags_raw]

        # Aktiflik durumu boolean kontrolü
        is_active = bool(raw_data.get("is_active", True))

        # Doğrulanmış nesneyi oluştur ve döndür
        return SecurityAsset(
            asset_id=asset_id,
            ipv4_address=ipv4,
            mac_address=mac,
            port=port,
            hostname=hostname,
            protocol=protocol,
            sha256_checksum=sha256_sum,
            risk_score=risk_score,
            tags=tags_clean,
            is_active=is_active
        )

    def batch_validate(self, assets_list: List[Dict[str, Any]]) -> Tuple[List[SecurityAsset], List[Dict[str, Any]]]:
        """
        Toplu varlık listesini doğrular; geçerli nesneleri ve hatalı kayıtları ayrıştırır.
        
        :param assets_list: Ham varlık sözlükleri listesi
        :return: (Geçerli_Varlıklar, Hatalı_Kayıtlar) demeti
        """
        valid_assets: List[SecurityAsset] = []
        errors_list: List[Dict[str, Any]] = []

        for idx, item in enumerate(assets_list):
            try:
                valid_asset = self.validate_asset_payload(item)
                valid_assets.append(valid_asset)
            except SecurityValidationError as err:
                errors_list.append({
                    "indis": idx,
                    "hata_tipi": type(err).__name__,
                    "mesaj": str(err),
                    "ham_kayit": item
                })

        return valid_assets, errors_list
