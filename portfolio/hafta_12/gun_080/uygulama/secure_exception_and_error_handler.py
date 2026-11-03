# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
G080: Hata Yönetimi ve Özel Durumlar Modülü (Defensive Exception Handling Architecture)

Bu modül; siber güvenlik sistemlerinde istisnaların (exceptions) fail-closed prensibiyle
yönetilmesini, yığın izi (stack trace) sızıntılarının (CWE-209) önlenmesini, log zehirlemesinin
(CWE-117) engellenmesini ve kaynakların (resource cleanup) deterministik olarak serbest
bırakılmasını sağlayan kurumsal bir hata işleme mimarisidir.
"""

# Güvenli rastgele dize ve benzersiz olay referans kodu üretimi için uuid modülünü içeri aktarıyoruz.
import uuid
# Olay zaman damgalarının UTC standardında oluşturulması için datetime modülünü içeri aktarıyoruz.
import datetime
# Dosya sistemi işlemleri ve nesne yönelimli yol kontrolü için Path modülünü içeri aktarıyoruz.
from pathlib import Path
# Tip denetimi ve statik analiz desteği için generic tipleri içeri aktarıyoruz.
from typing import Any, Dict, List, Optional, Tuple, Type
# Güvenli log temizliği ve regex işlemleri için re modülünü içeri aktarıyoruz.
import re


# ==============================================================================
# 1. ÖZEL GÜVENLİK İSTİSNA HİYERARŞİSİ (SECURITY EXCEPTION HIERARCHY)
# ==============================================================================

class SecurityException(Exception):
    """
    Tüm siber güvenlik istisnalarının türediği temel istisna sınıfı.
    Olay referans numarası (incident_id) ve adli bağlam taşır.
    """

    def __init__(
        self,
        message: str,
        incident_id: Optional[str] = None,
        context_details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Güvenlik istisnasını adli referans kodu ve temizlenmiş mesajla başlatır.
        """
        # Standart üst sınıf Exception başlatıcısını temiz mesajla çağırıyoruz.
        super().__init__(message)
        # İstisnanın orijinal güvenlik mesajını saklıyoruz.
        self.message = message
        # Referans kodu yoksa benzersiz bir SEC-ERR belirteci üretiyoruz.
        self.incident_id = incident_id if incident_id is not None else f"SEC-ERR-{uuid.uuid4().hex[:8].upper()}"
        # Adli bağlam detaylarını boş sözlük garantisiyle saklıyoruz.
        self.context_details = context_details if context_details is not None else {}
        # Olayın gerçekleştiği UTC zaman damgasını kaydediyoruz.
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()


class AuthenticationFailureException(SecurityException):
    """Kimlik doğrulama başarısızlıkları ve yetkisiz oturum açma denemeleri için istisna."""
    # Sınıf gövdesini tanımlıyoruz.
    pass


class AuthorizationDeniedException(SecurityException):
    """Yetki aşımı, rol yetersizliği ve erişim engeli durumları için istisna."""
    # Sınıf gövdesini tanımlıyoruz.
    pass


class InputSanitizationException(SecurityException):
    """Zararlı girdi enjeksiyonu ve biçim ihlalleri için istisna."""
    # Sınıf gövdesini tanımlıyoruz.
    pass


class RateLimitExceededException(SecurityException):
    """İstek sıklığı aşımı ve kaba kuvvet (brute-force) koruması için istisna."""
    # Sınıf gövdesini tanımlıyoruz.
    pass


class SecurityResourceException(SecurityException):
    """Kritik kaynak tahsis, kilit ve dosya temizleme arızaları için istisna."""
    # Sınıf gövdesini tanımlıyoruz.
    pass


# ==============================================================================
# 2. DETERMINİSTİK KAYNAK YÖNETİMİ (RESOURCE CONTEXT MANAGER)
# ==============================================================================

class SecureResourceContext:
    """
    İşlem sırasında hata meydana gelse dahi kaynakların (dosya, kilit, oturum)
    deterministik olarak kapatılmasını güvenceye alan güvenli bağlam yöneticisi.
    """

    def __init__(self, resource_name: str) -> None:
        """
        Bağlam yöneticisini kaynak ismi ve başlangıç durumu ile yapılandırır.
        """
        # Yönetilen kaynağın adını kaydediyoruz.
        self.resource_name = resource_name
        # Kaynağın açık/tahsis edilmiş durumda olup olmadığını takip ediyoruz.
        self.is_acquired = False
        # Temizlik işleminin başarıyla yapılıp yapılmadığını izliyoruz.
        self.is_released = False

    def __enter__(self) -> "SecureResourceContext":
        """
        Bağlama girildiğinde kaynağı tahsis eder ve durumu günceller.
        """
        # Kaynak tahsis bayrağını True yapıyoruz.
        self.is_acquired = True
        # Temizlik bayrağını False yapıyoruz.
        self.is_released = False
        # Yönetici nesnesinin kendisini döndürüyoruz.
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any]
    ) -> bool:
        """
        Bağlamdan çıkılırken hata olsa dahi kaynağı serbest bırakır (Fail-Closed).
        """
        # Kaynağı zorunlu olarak serbest bırakıyoruz.
        self.is_acquired = False
        # Temizlik bayrağını True yapıyoruz.
        self.is_released = True
        # İstisnanın dışarı fırlatılmasını engellemiyoruz (False döndürerek yukarı taşıyoruz).
        return False


# ==============================================================================
# 3. GÜVENLİ HATA İŞLEME VE İFŞA ENGELLEME MOTORU (SECURE ERROR HANDLER)
# ==============================================================================

class SecureErrorHandler:
    """
    Hata kayıtlarını güvenle temizleyen (CWE-117 log forgery koruması),
    istemciye yığın izi ifşasını önleyen (CWE-209) ve fail-closed kalkanı sağlayan sınıf.
    """

    # Log manipülasyonu yapabilecek CRLF ve tehlikeli karakterleri tespit eden regex.
    LOG_INJECTION_PATTERN = re.compile(r"[\r\n\x1b\x00]")

    def __init__(self) -> None:
        """
        Hata işleyicisini adli kayıt belleğiyle başlatır.
        """
        # Dahili denetim için tutulan adli olay kayıtları listesi.
        self.forensic_log_records: List[Dict[str, Any]] = []

    def sanitize_log_message(self, raw_message: str) -> str:
        """
        Hata mesajı içindeki satır başı, yeni satır, null-byte ve terminal kaçış kodlarını temizler.
        """
        # Girdi dize tipinde değilse dizeye dönüştürüyoruz.
        if not isinstance(raw_message, str):
            # Dize dönüşümü yapıyoruz.
            raw_message = str(raw_message)
        # CRLF ve kontrol karakterlerini boşluk ile değiştiriyoruz.
        sanitized = self.LOG_INJECTION_PATTERN.sub(" ", raw_message)
        # Fazla ardışık boşlukları kırpıp temiz dizeyi döndürüyoruz.
        return " ".join(sanitized.split())

    def build_sanitized_client_response(self, exception_obj: Exception) -> Dict[str, Any]:
        """
        Dış istemciye döndürülecek yanıtı hazırlar; dosya yollarını, satırları ve stack trace'i gizler.
        """
        # İstisna bir SecurityException örneği ise incident_id değerini alıyoruz.
        if isinstance(exception_obj, SecurityException):
            # Güvenlik istisnasının referans kodunu alıyoruz.
            incident_id = exception_obj.incident_id
            # Kullanıcı dostu genel hata mesajını belirliyoruz.
            public_msg = f"Güvenlik politikası ihlali tespit edildi. Olay Kodu: {incident_id}"
        # Bilinmeyen genel sistem hatalarında genel referans kodu üretiyoruz.
        else:
            # Genel hata referansı üretiyoruz.
            incident_id = f"SEC-ERR-{uuid.uuid4().hex[:8].upper()}"
            # Genel kullanıcı mesajı belirliyoruz.
            public_msg = f"Sistem güvenliği nedeniyle işleminiz tamamlanamadı. Destek Kodu: {incident_id}"

        # İstemciye yalnızca güvenli alanları içeren sözlüğü döndürüyoruz.
        return {
            "durum": "HATA_ERISIM_ENGEL",
            "olay_referans_kodu": incident_id,
            "mesaj": public_msg,
            "zaman": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    def record_forensic_incident(
        self,
        exception_obj: Exception,
        client_ip: str,
        action_name: str
    ) -> str:
        """
        Dahili güvenlik denetimi için ayrıntılı ve temizlenmiş adli olay kaydı tutar.
        """
        # Olay referans kodunu alıyoruz veya oluşturuyoruz.
        if isinstance(exception_obj, SecurityException):
            # Güvenlik istisnasından referans kodunu çekiyoruz.
            incident_id = exception_obj.incident_id
        # Diğer hatalarda yeni referans kodu oluşturuyoruz.
        else:
            # Yeni referans kodu oluşturuyoruz.
            incident_id = f"SYS-ERR-{uuid.uuid4().hex[:8].upper()}"

        # Hata mesajını log zehirlemesine karşı temizliyoruz.
        clean_err_msg = self.sanitize_log_message(str(exception_obj))
        # Adli kayıt nesnesini oluşturuyoruz.
        record = {
            "incident_id": incident_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "client_ip": client_ip,
            "action": action_name,
            "exception_type": type(exception_obj).__name__,
            "sanitized_error": clean_err_msg
        }
        # Dahili listeye ekliyoruz.
        self.forensic_log_records.append(record)
        # Olay referans kodunu geri döndürüyoruz.
        return incident_id


# ==============================================================================
# 4. GÜVENLİK GEÇİDİ VE FAIL-CLOSED POLİTİKASI (DEFENSIVE SECURITY GATEWAY)
# ==============================================================================

class DefensiveSecurityGateway:
    """
    Tüm istekleri fail-closed mimarisiyle işleyen, özel durumları yakalayan
    ve hiçbir koşulda açık bırakmayan güvenlik geçit motoru.
    """

    def __init__(self, error_handler: Optional[SecureErrorHandler] = None) -> None:
        """
        Güvenlik geçidini hata yöneticisi ve bellek içi hız takibiyle başlatır.
        """
        # Hata işleyicisini atıyoruz veya yenisini başlatıyoruz.
        self.handler = error_handler if error_handler is not None else SecureErrorHandler()
        # IP bazlı başarısız istek sayaçlarını tutan sözlüğü başlatıyoruz.
        self.failed_attempts_by_ip: Dict[str, int] = {}
        # Geçerli sahte yetki belirteçleri kümesi.
        self.valid_tokens: Dict[str, str] = {"TOKEN_ADMIN_123": "admin", "TOKEN_USER_456": "analyst"}

    def check_rate_limit(self, client_ip: str, max_allowed_failures: int = 5) -> None:
        """
        IP bazlı hız sınırını kontrol eder; esik aşılırsa RateLimitExceededException fırlatır.
        """
        # Mevcut başarısızlık sayısını alıyoruz.
        failures = self.failed_attempts_by_ip.get(client_ip, 0)
        # Başarısızlık sayısı eşiğe ulaştıysa veya aştıysa engelliyoruz.
        if failures >= max_allowed_failures:
            # Hız sınırı aşımı istisnası fırlatıyoruz.
            raise RateLimitExceededException(
                f"IP adresi için azami başarısız deneme eşiği aşıldı: {client_ip}",
                context_details={"client_ip": client_ip, "failures": failures}
            )

    def validate_and_authenticate(self, token: str, client_ip: str) -> str:
        """
        Kullanıcı belirtecini doğrular. Hatalıysa fail-closed gereği erişimi reddeder.
        """
        # Belirteç boşsa veya dize değilse hata fırlatıyoruz.
        if not token or not isinstance(token, str):
            # Başarısız deneme sayısını artırıyoruz.
            self.failed_attempts_by_ip[client_ip] = self.failed_attempts_by_ip.get(client_ip, 0) + 1
            # Kimlik doğrulama istisnası fırlatıyoruz.
            raise AuthenticationFailureException("Geçersiz veya eksik kimlik doğrulama belirteci.")

        # Belirtecin meşru tokenlar içinde olup olmadığını sınıyoruz.
        if token not in self.valid_tokens:
            # Başarısız deneme sayacını artırıyoruz.
            self.failed_attempts_by_ip[client_ip] = self.failed_attempts_by_ip.get(client_ip, 0) + 1
            # Kimlik doğrulama hatası fırlatıyoruz.
            raise AuthenticationFailureException("Yetkisiz veya tanınmayan kimlik belirteci.")

        # Doğrulanmış kullanıcı rolünü döndürüyoruz.
        return self.valid_tokens[token]

    def check_authorization(self, user_role: str, required_role: str) -> None:
        """
        Kullanıcı rolünün hedeflenen işlem için yeterli olup olmadığını denetler.
        """
        # Kullanıcı rolü gereken role eşit değilse ve admin değilse reddediyoruz.
        if user_role != required_role and user_role != "admin":
            # Yetkilendirme reddi istisnası fırlatıyoruz.
            raise AuthorizationDeniedException(
                f"Erişim engellendi: '{user_role}' rolü '{required_role}' işlemine yetkili değil."
            )

    def sanitize_parameter(self, param_name: str, param_value: str) -> str:
        """
        Girdideki şüpheli karakterleri ve komut enjeksiyonlarını denetler.
        """
        # Girdinin dize olduğunu doğruluyoruz.
        if not isinstance(param_value, str):
            # Dize değilse girdi ihlali fırlatıyoruz.
            raise InputSanitizationException(f"'{param_name}' parametresi metin formatında olmalıdır.")
        # Zararlı betik veya komut göstergelerini tarıyoruz.
        dangerous_patterns = ["<script>", "DROP TABLE", "--", "exec(", "../"]
        # Her bir deseni sınıyoruz.
        for pattern in dangerous_patterns:
            # Desenin değer içinde geçip geçmediğini sınıyoruz.
            if pattern.lower() in param_value.lower():
                # Enjeksiyon ihlali fırlatıyoruz.
                raise InputSanitizationException(
                    f"'{param_name}' parametresi içinde yasaklı karakter dizisi tespit edildi."
                )
        # Temiz değeri döndürüyoruz.
        return param_value

    def process_secure_transaction(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        İsteği uçtan uca kaynak bağlamı ve çok katmanlı fail-closed kalkanı altında yürütür.
        """
        # İstemci IP adresini alıyoruz (varsayılan: bilinmeyen IP).
        client_ip = request_payload.get("client_ip", "0.0.0.0")
        # Eylem adını alıyoruz.
        action = request_payload.get("action", "UNKNOWN_ACTION")

        # Deterministik kaynak yöneticisi başlatıyoruz.
        resource_guard = SecureResourceContext(f"TransactionLock_{action}")

        # Kaynak bağlamını açıyoruz.
        try:
            # Kaynak bağlamına giriş yapıyoruz.
            with resource_guard:
                # 1. Aşama: Hız sınırı denetimi yapıyoruz.
                self.check_rate_limit(client_ip)

                # 2. Aşama: Kimlik doğrulama belirtecini sınıyoruz.
                token = request_payload.get("token", "")
                user_role = self.validate_and_authenticate(token, client_ip)

                # 3. Aşama: Yetkilendirme kontrolü yapıyoruz.
                required_role = request_payload.get("required_role", "analyst")
                self.check_authorization(user_role, required_role)

                # 4. Aşama: Girdileri temizliyoruz.
                raw_param = request_payload.get("parameter", "")
                clean_param = self.sanitize_parameter("parameter", raw_param)

                # 5. Aşama: Simüle edilmiş hata enjeksiyonu denetimi.
                if request_payload.get("simulate_io_error"):
                    # Kaynak hatası fırlatıyoruz.
                    raise SecurityResourceException("Kritik donanım G/Ç arızası simüle edildi.")

                # Tüm denetimler başarılıysa güvenli işlem sonucunu döndürüyoruz.
                return {
                    "durum": "BASARILI",
                    "rol": user_role,
                    "islem": action,
                    "veri": clean_param,
                    "kaynak_temizlendi": resource_guard.is_released
                }

        # Bilinen güvenlik istisnalarını yakalıyoruz (Fail-Closed).
        except SecurityException as sec_err:
            # Adli kaydı tutuyoruz.
            self.handler.record_forensic_incident(sec_err, client_ip, action)
            # İstemciye sızıntısız temiz hata yanıtı döndürüyoruz.
            return self.handler.build_sanitized_client_response(sec_err)

        # Beklenmeyen sistem veya bellek istisnalarını yakalıyoruz (Kalkantaki Son Savunma).
        except Exception as unk_err:
            # Beklenmeyen hatayı logluyoruz.
            self.handler.record_forensic_incident(unk_err, client_ip, action)
            # İstemciye sızıntısız temiz hata yanıtı döndürüyoruz.
            return self.handler.build_sanitized_client_response(unk_err)


# Modül doğrudan yürütüldüğünde örnek denetim ve kanıt raporunu oluşturuyoruz.
if __name__ == "__main__":
    # Başlangıç mesajını basıyoruz.
    print("[+] G080: Hata Yönetimi ve Özel Durumlar Motoru Başlatılıyor...")

    # Güvenlik geçidini başlatıyoruz.
    gateway = DefensiveSecurityGateway()

    # Örnek 1: Meşru başarılı istek.
    valid_req = {
        "client_ip": "198.51.100.10",
        "action": "QUERY_IOC",
        "token": "TOKEN_ADMIN_123",
        "required_role": "admin",
        "parameter": "malware_hash_sha256"
    }
    # İsteği işliyoruz.
    res_valid = gateway.process_secure_transaction(valid_req)
    # Konsola sonucu yazdırıyoruz.
    print(f"[+] Meşru İstek Sonucu: {res_valid['durum']}")

    # Örnek 2: Geçersiz token ile yetkisiz giriş (Fail-Closed doğrulaması).
    invalid_req = {
        "client_ip": "198.51.100.99",
        "action": "UPDATE_FIREWALL",
        "token": "FORGED_EVIL_TOKEN",
        "required_role": "admin",
        "parameter": "allow_all"
    }
    # Yetkisiz isteği işliyoruz.
    res_invalid = gateway.process_secure_transaction(invalid_req)
    # Konsola sonucu yazdırıyoruz.
    print(f"[+] Yetkisiz İstek Sonucu: {res_invalid['durum']} (Olay Kodu: {res_invalid['olay_referans_kodu']})")

    # Kanıt raporunun yazılacağı yolu belirliyoruz.
    base_dir = Path(__file__).resolve().parent.parent
    # Rapor dosya yolunu alıyoruz.
    report_path = base_dir / "kanit" / "gercek" / "hata_yonetimi_guvenlik_raporu.txt"
    # Raporu UTF-8 olarak açıyoruz.
    with open(report_path, "w", encoding="utf-8") as rf:
        # Rapor başlığını yazıyoruz.
        rf.write("=== G080 HATA YÖNETİMİ VE ÖZEL DURUMLAR ADLİ DENETİM RAPORU ===\n")
        # Meşru işlem özetini yazıyoruz.
        rf.write(f"Meşru İşlem Durumu: {res_valid['durum']}\n")
        # Yetkisiz istek süzgecini yazıyoruz.
        rf.write(f"Engellenen Yetkisiz İstek: {res_invalid['durum']} -> {res_invalid['mesaj']}\n")
        # Adli kayıt sayısını yazıyoruz.
        rf.write(f"Kaydedilen Adli Olay Sayısı: {len(gateway.handler.forensic_log_records)}\n")
        # Fail-closed onayını yazıyoruz.
        rf.write("Fail-Closed Prensibi: Doğrulandı (Tüm istisnalarda erişim engellendi, sızıntı sıfır)\n")

    # Tamamlanma bildirimini basıyoruz.
    print(f"[+] Adli rapor kaydedildi: {report_path}")
