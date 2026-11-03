# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# Yazarın açık yazılı izni olmaksızın hiçbir kullanım hakkı tanınmaz.

"""
G058 - HTTP Yöntemleri ve Idempotency Yönetim, Önbellekleme ve Güvenlik Motoru.

Bu modül, RFC 7231 (HTTP Semantiği) ve RFC 5789 (PATCH) standartlarına tam uyumlu
HTTP metot doğrulaması, Güvenli (Safe) ve Eşgüçlü (Idempotent) davranış analizi,
Stripe / IETF standardında 'Idempotency-Key' ile mükerrer işlem engelleme,
çift para çekme (double charge) koruması ve HTTP Verb Tampering denetimini gerçekleştirir.
"""

# SHA-256 ile gövde özetleri ve idempotency anahtarı doğrulaması için hashlib
import hashlib
# Zaman damgaları ve TTL (yaşam süresi) hesaplamaları için time modülü
import time
# Tip güvenliği ve zengin nesne yapıları için dataclass, typing araçları
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable


class MethodValidationError(Exception):
    """HTTP metot adı veya kurallarına aykırılıklarda fırlatılan özel istisna sınıfı."""
    pass


class IdempotencyConflictError(Exception):
    """Aynı Idempotency-Key ile farklı gövde gönderildiğinde fırlatılan istisna sınıfı."""
    pass


class VerbTamperingAlert(Exception):
    """HTTP Metot Atlatma (Verb Tampering) veya yetkisiz metot kullanımında fırlatılan istisna."""
    pass


# RFC 7231 ve RFC 5789 Standart HTTP Metotları
HTTP_METHODS_STANDARD: Set[str] = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"
}

# RFC 7231 §4.2.1 Güvenli (Safe) Metotlar (Sunucu durumunda yan etki oluşturmayanlar)
HTTP_METHODS_SAFE: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"}

# RFC 7231 §4.2.2 Eşgüçlü (Idempotent) Metotlar (Tekrarlanan isteklerin sunucu durumunu aynı bırakması)
HTTP_METHODS_IDEMPOTENT: Set[str] = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}


class HTTPMethodSemantics:
    """HTTP metotlarının anlamsal doğruluğunu, güvenliğini ve eşgüçlülüğünü denetleyen sınıf."""

    @staticmethod
    def validate_method_syntax(method: str) -> None:
        """Metot adının geçerliliğini ve RFC 7231 büyük harf kuralını denetler."""
        if not method or not isinstance(method, str):
            raise MethodValidationError("HTTP metodu bos veya gecersiz tipte olamaz.")
        # RFC 7231 gereğince metot adları kesinlikle büyük harfle yazılmalıdır
        if method != method.upper():
            raise MethodValidationError(f"RFC 7231 geregi HTTP metotlari buyuk harfle yazilmalidir: '{method}'.")
        # Standart HTTP metotları kümesinde olmalıdır
        if method not in HTTP_METHODS_STANDARD:
            raise MethodValidationError(
                f"Gecersiz veya standart disi HTTP metodu: '{method}'. Yalnizca RFC 7231 metotlari desteklenir."
            )

    @classmethod
    def is_safe(cls, method: str) -> bool:
        """Metodun sunucu durumunu değiştirmeyen 'safe' metot olup olmadığını döner."""
        cls.validate_method_syntax(method)
        return method in HTTP_METHODS_SAFE

    @classmethod
    def is_idempotent(cls, method: str) -> bool:
        """Metodun eşgüçlü (idempotent: f(f(x)) = f(x)) olup olmadığını döner."""
        cls.validate_method_syntax(method)
        return method in HTTP_METHODS_IDEMPOTENT

    @classmethod
    def audit_method_usage(cls, method: str, path: str, body: str) -> List[str]:
        """
        Metot kullanımındaki potansiyel güvenlik ve standart ihlallerini denetler.
        """
        cls.validate_method_syntax(method)
        uyarilar = []

        # 1. Kural: GET isteklerinde durum değiştirici eylemler aranır (RFC 7231 İhlali)
        if method == "GET":
            supheli_kelimeler = ["delete", "remove", "transfer", "pay", "update", "drop"]
            path_lower = path.lower()
            if any(k in path_lower for k in supheli_kelimeler):
                raise MethodValidationError(
                    f"RFC 7231 Ihlali: GET metodu sunucu durumunu degistiren islemler "
                    f"(para transferi, silme) icin kullanilamaz: '{path}'."
                )

        # 2. Kural: PUT metodu kaynağın tam temsilini gerektirir (gövde boş olamaz)
        if method == "PUT" and (not body or not body.strip()):
            raise MethodValidationError("PUT metodu kaynagin tam temsilini gerektirir; istek govdesi bos olamaz.")

        # 3. Kural: TRACE metodu güvenlik açığı oluşturur (XST - Cross-Site Tracing)
        if method == "TRACE":
            uyarilar.append("TRACE metodu XST saldirilarina yol acabilir; uretim ortaminda kapatilmalidir.")

        return uyarilar


@dataclass
class IdempotencyRecord:
    """Tek bir Idempotency-Key için saklanan işlem ve önbellek kaydı."""
    key: str                                  # İstemci tarafından sağlanan benzersiz anahtar
    method: str                               # İstek metodu (genellikle POST)
    path: str                                 # İstek URI yolu
    payload_hash: str                         # İstek gövdesinin SHA-256 özeti
    status_code: int                          # Üretilen HTTP durum kodu
    response_headers: Dict[str, str]          # Üretilen yanıt başlıkları
    response_body: str                        # Üretilen yanıt gövdesi
    created_at: float = field(default_factory=time.time)  # Kayıt oluşturulma zaman damgası
    ttl_seconds: int = 86400                  # Kaydın geçerlilik süresi (varsayılan 24 saat)
    state: str = "COMPLETED"                  # Durum: IN_PROGRESS veya COMPLETED

    @property
    def is_expired(self) -> bool:
        """Kaydın geçerlilik süresinin dolup dolmadığını hesaplar."""
        return time.time() > (self.created_at + self.ttl_seconds)


class IdempotencyManager:
    """
    IETF / Stripe standardında Idempotency-Key yaşam döngüsü yöneticisi.
    Ağ kesintilerinde mükerrer işlem (çift çekim, çift kayıt) oluşmasını önler.
    """
    def __init__(self, default_ttl_seconds: int = 86400) -> None:
        self.default_ttl = default_ttl_seconds
        # Anahtar veritabanı: key -> IdempotencyRecord
        self.records: Dict[str, IdempotencyRecord] = {}

    @staticmethod
    def _compute_hash(data: str) -> str:
        """İstek gövdesinin SHA-256 özetini üretir."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def clean_expired_records(self) -> int:
        """Süresi dolmuş idempotency kayıtlarını bellekten temizler."""
        expired = [k for k, r in self.records.items() if r.is_expired]
        for k in expired:
            del self.records[k]
        return len(expired)

    def execute_transaction(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str,
        handler: Callable[[str, str, str], Tuple[int, Dict[str, str], str]]
    ) -> Tuple[int, Dict[str, str], str, bool]:
        """
        İsteği idempotency denetiminden geçirerek çalıştırır.
        Dönüş Değeri: (status_code, headers, body, is_cached_replay)
        """
        # Başlıklar arasında Idempotency-Key aranır (küçük-büyük harf duyarsız)
        has_idempotency_header = False
        idempotency_key: Optional[str] = None
        for k, v in headers.items():
            if k.lower() == "idempotency-key":
                has_idempotency_header = True
                idempotency_key = v.strip()
                break

        # Eğer başlık verilmişse doğrulanır (boş olamaz, 128 karakteri aşamaz)
        if has_idempotency_header:
            if not idempotency_key:
                raise MethodValidationError("Idempotency-Key basligi bos veya yalnizca bosluk karakterlerinden olusamaz.")
            if len(idempotency_key) > 128:
                raise MethodValidationError(
                    "Gecersiz Idempotency-Key formati: Uzunluk 128 karakteri asamaz veya gecersiz karakterler iceremez."
                )

        # Eğer başlık yoksa veya metot zaten eşgüçlüyse (GET, HEAD vb.) doğrudan çalıştırılır
        if not has_idempotency_header or HTTPMethodSemantics.is_idempotent(method):
            status, resp_h, resp_b = handler(method, path, body)
            return status, resp_h, resp_b, False

        payload_hash = self._compute_hash(body)

        # Anahtar daha önce kullanılmış mı kontrol edilir
        if idempotency_key in self.records:
            rec = self.records[idempotency_key]
            # Eğer kayıt süresi dolmuşsa temizlenir
            if rec.is_expired:
                del self.records[idempotency_key]
            else:
                # Gövde özeti uyuşmazlığı kontrolü (Payload Mismatch)
                if rec.payload_hash != payload_hash or rec.path != path:
                    raise IdempotencyConflictError(
                        f"Idempotency-Key Cakismasi: Ayni anahtar ('{idempotency_key}') "
                        f"farkli bir istek govdesiyle yeniden kullanilamaz (422 Unprocessable Entity / 409 Conflict)."
                    )
                # İstek daha önce başarıyla tamamlanmışsa doğrudan önbellekteki yanıt dönülür
                cached_headers = dict(rec.response_headers)
                cached_headers["Idempotent-Replayed"] = "true"
                return rec.status_code, cached_headers, rec.response_body, True

        # İlk defa gelen istek: İşlem çalıştırılır
        status, resp_h, resp_b = handler(method, path, body)

        # Sonuç idempotency tablosuna kaydedilir
        record = IdempotencyRecord(
            key=idempotency_key,
            method=method,
            path=path,
            payload_hash=payload_hash,
            status_code=status,
            response_headers=resp_h,
            response_body=resp_b,
            ttl_seconds=self.default_ttl
        )
        self.records[idempotency_key] = record

        return status, resp_h, resp_b, False


class VerbTamperingAuditor:
    """
    HTTP Metot Atlatma (HTTP Verb Tampering) zafiyet denetçisi.
    Erişim denetimi kurallarının yalnızca belirli metotlara uygulanmasından doğan açıkları yakalar.
    """
    def __init__(self, protected_rules: Dict[str, Set[str]]) -> None:
        # Yol -> İzin verilen yetkili metotlar kümesi
        # Örnek: {"/admin/delete": {"POST"}, "/api/v1/users": {"GET", "POST"}}
        self.protected_rules = protected_rules

    def inspect_request(self, method: str, path: str, is_authenticated: bool) -> bool:
        """
        İsteğin erişim denetim kurallarını atlatmaya çalışıp çalışmadığını denetler.
        """
        HTTPMethodSemantics.validate_method_syntax(method)

        # Yol için tanımlı kural var mı?
        for rule_path, allowed_methods in self.protected_rules.items():
            if path.startswith(rule_path):
                # Eğer kullanıcı kimlik doğrulamamışsa ve korumalı bir yola erişiyorsa
                if not is_authenticated:
                    # Saldırgan HEAD veya PUT ile POST korumasını aşmaya çalışıyorsa
                    if method not in allowed_methods:
                        raise VerbTamperingAlert(
                            f"HTTP Verb Tampering Tehdidi: '{rule_path}' kaynagi yalnizca "
                            f"{allowed_methods} ile kullanilabilir; '{method}' metodu ile "
                            f"guvenlik filtresi atlatilamaz (403 Forbidden)."
                        )
                    # İzinli olsa dahi oturumsuz erişemez
                    raise VerbTamperingAlert(f"Erisim Engellendi: '{path}' icin yetkilendirme gereklidir (401 Unauthorized).")
        return True
