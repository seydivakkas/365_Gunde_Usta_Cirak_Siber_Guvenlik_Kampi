# -*- coding: utf-8 -*-
"""
Gün 165: CORS ile Güvenlik Sınırı Savunma Motoru (cors_engine.py)

Bu modül; Siteler Arası Kaynak Paylaşımı (Cross-Origin Resource Sharing - CORS)
mimarisini, Aynı Köken İlkesi'nin (Same-Origin Policy - SOP) sınırlarını,
tehlikeli CORS yanlış yapılandırmalarını (Körlemesine Origin Yansıtma, Null Origin,
Gevşek Regex Eşleşmesi, Önbellek Zehirlenmesi) ve kurumsal düzeyde katı
beyaz liste (Allowlist) tabanlı Preflight ve Yanıt doğrulama motorunu simüle eder.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri içe aktarılır
import re  # Düzenli ifadeler ile köken ve başlık denetimi için
import json  # JSON biçimlendirme ve yapılandırılmış çıktı için
import urllib.parse  # URL ayrıştırma ve köken (scheme, host, port) çözümleme için
from enum import Enum  # Sabit durum sınıfları oluşturmak için
from typing import Dict, Any, List, Optional, Tuple, Set  # Tip ipuçları için
from dataclasses import dataclass, field  # Veri sınıfları tanımlamak için


class CORSRiskType(str, Enum):
    """CORS yanlış yapılandırmaları ve saldırı vektörleri numaralandırması."""
    ARBITRARY_ORIGIN_REFLECTION = "ARBITRARY_ORIGIN_REFLECTION"  # Herhangi bir Origin'i körlemesine geri yansıtma
    NULL_ORIGIN_ALLOWED = "NULL_ORIGIN_ALLOWED"  # Sandbox veya yerel 'null' Origin'e izin verilmesi
    LOOSE_REGEX_SUBDOMAIN = "LOOSE_REGEX_SUBDOMAIN"  # Gevşek regex nedeniyle ön/son ek alan adı atlatması
    UNESCAPED_DOT_REGEX = "UNESCAPED_DOT_REGEX"  # Kaçılmamış nokta nedeniyle yabancı alan adlarının eşleşmesi
    WILDCARD_WITH_CREDENTIALS = "WILDCARD_WITH_CREDENTIALS"  # Joker karakter (*) ile kimlik bilgisi (credentials) çelişkisi
    CACHE_POISONING_MISSING_VARY = "CACHE_POISONING_MISSING_VARY"  # Dinamik yanıtta Vary: Origin başlığının unutulması
    UNAUTHORIZED_FOREIGN_ORIGIN = "UNAUTHORIZED_FOREIGN_ORIGIN"  # İzin verilmeyen yabancı üçüncü taraf köken


@dataclass
class CORSRequest:
    """Gelen HTTP isteğini ve CORS başlıklarını modelleyen veri yapısı."""
    method: str  # HTTP yöntemi (GET, POST, OPTIONS, PUT, DELETE vb.)
    path: str  # İstek yolu (/api/kullanici/profil vb.)
    origin: Optional[str] = None  # Gelen HTTP 'Origin' başlığı
    headers: Dict[str, str] = field(default_factory=dict)  # İstek başlıkları
    access_control_request_method: Optional[str] = None  # Preflight istenen metot (ACRM)
    access_control_request_headers: Optional[str] = None  # Preflight istenen başlıklar (ACRH)


@dataclass
class CORSResponse:
    """Sunucu tarafından üretilen HTTP yanıtını ve CORS başlıklarını modelleyen veri yapısı."""
    status_code: int  # HTTP durum kodu (200, 204, 403 vb.)
    headers: Dict[str, str] = field(default_factory=dict)  # Dönen HTTP başlıkları
    body: Optional[str] = None  # Yanıt gövdesi
    is_cross_origin_allowed: bool = False  # Tarayıcının yanıtı okumasına izin verildi mi?
    detected_risks: List[CORSRiskType] = field(default_factory=list)  # Saptanan CORS zafiyetleri


@dataclass
class EnterpriseCORSPolicy:
    """Kurumsal düzeyde katı CORS güvenlik politikasını tanımlayan veri yapısı."""
    allowed_origins: Set[str] = field(default_factory=set)  # Tam köken beyaz listesi (scheme://host:port)
    allowed_methods: Set[str] = field(default_factory=lambda: {"GET", "POST", "OPTIONS"})  # İzinli metotlar
    allowed_headers: Set[str] = field(default_factory=lambda: {"content-type", "authorization", "x-requested-with", "x-csrf-token"})  # İzinli başlıklar
    allow_credentials: bool = True  # Oturum çerezleri / yetkilendirme iletim izni
    max_age_seconds: int = 86400  # Preflight önbellek süresi (24 saat)
    enforce_vary_origin: bool = True  # Vary: Origin başlığı zorunluluğu


class CORSDefenseEngine:
    """
    Merkezi CORS Savunma ve Denetim Motoru:
    Zafiyetli ve güvenli sunucu yapılandırmalarını karşılaştırmalı olarak çalıştırır,
    preflight (OPTIONS) mekanizmasını doğrular ve zafiyetli desenleri yakalar.
    """

    def __init__(self, policy: Optional[EnterpriseCORSPolicy] = None):
        # Varsayılan kurumsal politika yüklenir
        if policy is None:
            self.policy = EnterpriseCORSPolicy(
                allowed_origins={
                    "https://portal.kurum.internal",
                    "https://mobil.kurum.internal",
                    "https://yonetim.kurum.internal:8443"
                },
                allowed_methods={"GET", "POST", "PUT", "DELETE", "OPTIONS"},
                allowed_headers={"content-type", "authorization", "x-csrf-token", "x-requested-with"},
                allow_credentials=True,
                max_age_seconds=3600,
                enforce_vary_origin=True
            )
        else:
            self.policy = policy

    def normalize_origin(self, origin: Optional[str]) -> Optional[str]:
        """Köken dizesini ayrıştırarak standart scheme://host[:port] biçimine getirir."""
        # Eğer köken boşsa None döner
        if not origin or not isinstance(origin, str):
            return None
        # Küçük harfe çevrilir ve sağdaki eğik çizgi temizlenir
        cleaned = origin.strip().lower().rstrip("/")
        # Eğer özel durum 'null' ise aynen döndürülür
        if cleaned == "null":
            return "null"
        # URL ayrıştırılır
        parsed = urllib.parse.urlparse(cleaned)
        # Şema ve netloc eksikse geçersizdir
        if not parsed.scheme or not parsed.netloc:
            return None
        # Normalize edilmiş köken döner
        return f"{parsed.scheme}://{parsed.netloc}"

    def vulnerable_cors_handler(self, request: CORSRequest) -> CORSResponse:
        """
        ZAFİYETLİ CORS UYGULAMASI:
        1. Gelen her 'Origin' başlığını körlemesine geri yansıtır (Arbitrary Reflection).
        2. 'null' Origin'e güvenerek izin verir.
        3. 'Access-Control-Allow-Credentials: true' bayrağını sorgusuz ekler.
        4. 'Vary: Origin' başlığını unutarak önbellek zehirlenmesine kapı aralar.
        """
        response_headers: Dict[str, str] = {}
        detected_risks: List[CORSRiskType] = []

        # Gelen köken taranır
        if request.origin:
            req_origin_norm = self.normalize_origin(request.origin)
            
            # ZAFİYET 1: 'null' kökene izin verme
            if req_origin_norm == "null":
                response_headers["Access-Control-Allow-Origin"] = "null"
                response_headers["Access-Control-Allow-Credentials"] = "true"
                detected_risks.append(CORSRiskType.NULL_ORIGIN_ALLOWED)
            # ZAFİYET 2: Gelen yabancı kökeni körlemesine geri yansıtma (Arbitrary Reflection)
            else:
                response_headers["Access-Control-Allow-Origin"] = request.origin
                response_headers["Access-Control-Allow-Credentials"] = "true"
                detected_risks.append(CORSRiskType.ARBITRARY_ORIGIN_REFLECTION)

            # ZAFİYET 3: Vary: Origin başlığı eksikliği
            detected_risks.append(CORSRiskType.CACHE_POISONING_MISSING_VARY)

        # Preflight OPTIONS kontrolü (Zafiyetli: Tüm yöntem ve başlıklara izin veriyor)
        if request.method.upper() == "OPTIONS":
            response_headers["Access-Control-Allow-Methods"] = "*"
            response_headers["Access-Control-Allow-Headers"] = "*"
            return CORSResponse(
                status_code=200,
                headers=response_headers,
                body="",
                is_cross_origin_allowed=True,
                detected_risks=detected_risks
            )

        # Gerçek veri isteği
        return CORSResponse(
            status_code=200,
            headers=response_headers,
            body=json.dumps({"kullanici_id": 101, "ad": "Ahmet Kaya", "bakiye": 45000.0, "gizli_not": "Gizli Kurumsal Finansal Veri"}),
            is_cross_origin_allowed=True,
            detected_risks=detected_risks
        )

    def secure_cors_handler(self, request: CORSRequest) -> CORSResponse:
        """
        GÜVENLİ KURUMSAL CORS UYGULAMASI:
        1. Yalnızca katı beyaz listede (Allowlist) birebir eşleşen kökenlere ACAO başlığı döner.
        2. 'null' Origin KESİNLİKLE reddedilir (CORS başlığı dönülmez).
        3. Joker (*) ile Credentials asla bir arada kullanılmaz.
        4. Dinamik yanıtlarda önbellek zehirlenmesini önlemek için DAİMA 'Vary: Origin' eklenir.
        5. Preflight (OPTIONS) isteklerinde yalnızca izinli yöntem ve başlıklar onaylanır.
        """
        response_headers: Dict[str, str] = {}
        detected_risks: List[CORSRiskType] = []

        # Eğer istekte Origin başlığı yoksa (Aynı siteden meşru doğrudan istek)
        if not request.origin:
            return CORSResponse(
                status_code=200,
                headers={},
                body=json.dumps({"mesaj": "Aynı köken (Same-Origin) isteği başarıyla yürütüldü."}),
                is_cross_origin_allowed=False,
                detected_risks=[]
            )

        req_origin_norm = self.normalize_origin(request.origin)

        # 1. KONTROL: 'null' Origin derhal reddedilir
        if req_origin_norm == "null":
            detected_risks.append(CORSRiskType.NULL_ORIGIN_ALLOWED)
            return CORSResponse(
                status_code=403,
                headers={},
                body=json.dumps({"hata": "Güvensiz 'null' Origin reddedildi. CORS izni verilmedi."}),
                is_cross_origin_allowed=False,
                detected_risks=detected_risks
            )

        # 2. KONTROL: Katı Beyaz Liste (Allowlist) Karşılaştırması
        # Şema, ana makine ve port tam olarak eşleşmelidir
        is_origin_allowed = False
        if req_origin_norm in self.policy.allowed_origins:
            is_origin_allowed = True

        if not is_origin_allowed:
            # İzin verilmeyen yabancı kökene ACAO başlığı VERİLMEZ!
            detected_risks.append(CORSRiskType.UNAUTHORIZED_FOREIGN_ORIGIN)
            return CORSResponse(
                status_code=403,
                headers={},
                body=json.dumps({"hata": f"Yetkisiz yabancı köken (Cross-Origin): '{request.origin}'. Erişim engellendi."}),
                is_cross_origin_allowed=False,
                detected_risks=detected_risks
            )

        # Köken izinli ise güvenli başlıklar inşa edilir
        response_headers["Access-Control-Allow-Origin"] = req_origin_norm  # Yalnızca eşleşen köken yazılır
        if self.policy.allow_credentials:
            response_headers["Access-Control-Allow-Credentials"] = "true"  # Kimlik bilgisi izni

        # Önbellek zehirlenmesine karşı 'Vary: Origin' başlığı zorunludur
        if self.policy.enforce_vary_origin:
            response_headers["Vary"] = "Origin"

        # 3. KONTROL: Preflight (OPTIONS) Doğrulaması
        if request.method.upper() == "OPTIONS":
            # İstenen metot denetlenir
            req_method = (request.access_control_request_method or "").upper()
            if req_method and req_method not in self.policy.allowed_methods:
                return CORSResponse(
                    status_code=405,
                    headers=response_headers,
                    body=json.dumps({"hata": f"İzin verilmeyen metot: '{req_method}'"}),
                    is_cross_origin_allowed=False,
                    detected_risks=[]
                )

            # İstenen başlıklar denetlenir
            if request.access_control_request_headers:
                requested_headers = [h.strip().lower() for h in request.access_control_request_headers.split(",")]
                for h in requested_headers:
                    if h and h not in self.policy.allowed_headers:
                        return CORSResponse(
                            status_code=403,
                            headers=response_headers,
                            body=json.dumps({"hata": f"İzin verilmeyen özel başlık: '{h}'"}),
                            is_cross_origin_allowed=False,
                            detected_risks=[]
                        )

            # Preflight onay başlıkları eklenir
            response_headers["Access-Control-Allow-Methods"] = ", ".join(sorted(self.policy.allowed_methods))
            response_headers["Access-Control-Allow-Headers"] = ", ".join(sorted(self.policy.allowed_headers))
            response_headers["Access-Control-Max-Age"] = str(self.policy.max_age_seconds)

            return CORSResponse(
                status_code=204,  # No Content
                headers=response_headers,
                body=None,
                is_cross_origin_allowed=True,
                detected_risks=[]
            )

        # 4. KONTROL: Gerçek İstek ve Veri İletimi
        return CORSResponse(
            status_code=200,
            headers=response_headers,
            body=json.dumps({"durum": "BASARILI", "veri": "Gizli Veri Yalnızca İzinli Kökene Teslim Edildi"}),
            is_cross_origin_allowed=True,
            detected_risks=[]
        )

    def test_regex_misconfiguration(self, candidate_origin: str, pattern: str) -> bool:
        """Belirli bir regex ifadesinin zayıflığını (bypass edilebilirliğini) test eder."""
        try:
            return bool(re.search(pattern, candidate_origin))
        except re.error:
            return False
