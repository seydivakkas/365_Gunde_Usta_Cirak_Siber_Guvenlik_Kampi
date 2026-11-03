# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 144: Kerberos Temel Bilet Akışı ve Güvenlik Doğrulama Motoru.
RFC 4120 Kerberos v5 bilet yaşam döngüsü (AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP),
PAC HMAC bütünlüğü, yeniden oynatma (replay) önleme, saat sapması (clock skew)
ve bilet sahteciliği (Golden/Silver Ticket, Roasting, Downgrade) tespit motoru.
"""

# Zaman hesaplamaları ve zaman damgası karşılaştırmaları için datetime modülü içe aktarılır.
import datetime
# Güvenlik durumları ve şifreleme türleri için numaralandırma (Enum) modülü içe aktarılır.
from enum import Enum
# Veri yapılarını nesne yönelimli ve tip güvenli tanımlamak için dataclass içe aktarılır.
from dataclasses import dataclass, field
# Tip ipuçları ve statik analiz desteği için typing bileşenleri içe aktarılır.
from typing import Dict, List, Optional, Tuple, Set, Any
# JSON formatında serileştirme ve dosya okuma/yazma işlemleri için json modülü içe aktarılır.
import json
# Hash algoritmaları için hashlib modülü içe aktarılır.
import hashlib
# Mesaj doğrulama kodları (HMAC) üretmek ve doğrulamak için hmac modülü içe aktarılır.
import hmac
# Kriptografik rastgele oturum anahtarları ve rastgele sayılar üretmek için secrets modülü içe aktarılır.
import secrets


class TicketType(str, Enum):
    """
    Kerberos bilet türlerini tanımlayan numaralandırma sınıfı.
    """
    # Kimlik Doğrulama Servisinden (AS) alınan Bilet Verme Bileti (Ticket Granting Ticket)
    TGT = "TGT"
    # Bilet Verme Servisinden (TGS) alınan Servis Bileti (Service Ticket)
    SERVICE = "SERVICE"


class EncryptionType(str, Enum):
    """
    Kerberos v5 desteklenen şifreleme süitleri (RFC 3962, RFC 4757, RFC 6649).
    """
    # Modern ve güvenli AES-256 CTS HMAC SHA1 şifreleme türü (RFC 3962)
    AES256_CTS_HMAC_SHA1_96 = "AES256-CTS-HMAC-SHA1-96"
    # Modern AES-128 CTS HMAC SHA1 şifreleme türü (RFC 3962)
    AES128_CTS_HMAC_SHA1_96 = "AES128-CTS-HMAC-SHA1-96"
    # Eski ve güvensiz RC4-HMAC şifreleme türü (RFC 4757 - Downgrade riski taşır)
    RC4_HMAC = "RC4-HMAC"
    # Kullanımdan kaldırılmış ve tamamen kırılmış DES şifreleme türü (RFC 6649 - Kritik risk)
    DES_CBC_MD5 = "DES-CBC-MD5"


class FlowStep(str, Enum):
    """
    Kerberos bilet takas döngüsündeki adımları tanımlayan sınıf.
    """
    # 1. Adım: İstemcinin Kimlik Doğrulama Servisine TGT başvurusu
    AS_REQ = "AS-REQ"
    # 2. Adım: KDC'nin istemciye TGT ve oturum anahtarı yanıtı
    AS_REP = "AS-REP"
    # 3. Adım: İstemcinin Bilet Verme Servisine hedef servis için bilet başvurusu
    TGS_REQ = "TGS-REQ"
    # 4. Adım: KDC'nin istemciye hedef servis bileti ve servis oturum anahtarı yanıtı
    TGS_REP = "TGS-REP"
    # 5. Adım: İstemcinin hedef uygulama sunucusuna servis bileti ve kanıtlayıcı ile erişim isteği
    AP_REQ = "AP-REQ"
    # 6. Adım: Hedef sunucunun istemciye karşılıklı kimlik doğrulama (mutual auth) yanıtı
    AP_REP = "AP-REP"


@dataclass
class PACInfo:
    """
    Privilege Attribute Certificate (Ayrıcalık Nitelik Sertifikası - PAC) veri yapısı.
    Microsoft Kerberos genişletmesi olarak bilet içinde taşınan kullanıcı SID ve grup hakları.
    """
    # Kullanıcının benzersiz Güvenlik Tanımlayıcısı (SID)
    user_sid: str
    # Kullanıcının üyesi olduğu grup SID'lerinin listesi (Örn: Domain Admins, Enterprise Admins)
    group_sids: List[str]
    # Servis anahtarı ile üretilen sunucu imzası (Server Signature)
    server_signature: str
    # KRBTGT anahtarı ile üretilen KDC imzası (KDC Signature)
    kdc_signature: str

    def verify_server_signature(self, service_key: bytes) -> bool:
        """
        Servis anahtarı kullanılarak PAC sunucu imzasını doğrular.
        """
        # İmzalanacak veri tabanı kullanıcı SID'si ve grup listesinden oluşturulur.
        data_to_sign = f"{self.user_sid}:" + ",".join(sorted(self.group_sids))
        # HMAC-SHA256 algoritmasıyla beklenen imza özeti hesaplanır.
        expected_sig = hmac.new(service_key, data_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        # Zamanlama saldırılarını engellemek için sabit zamanlı (constant-time) karşılaştırma yapılır.
        return hmac.compare_digest(self.server_signature, expected_sig)

    def verify_kdc_signature(self, krbtgt_key: bytes) -> bool:
        """
        KRBTGT anahtarı kullanılarak PAC KDC imzasını doğrular.
        """
        # KDC imzası sunucu imzasının kendisini imzalar (imzaların hiyerarşik doğrulaması).
        expected_sig = hmac.new(krbtgt_key, self.server_signature.encode("utf-8"), hashlib.sha256).hexdigest()
        # Sabit zamanlı karşılaştırma ile KDC imzasının doğruluğu test edilir.
        return hmac.compare_digest(self.kdc_signature, expected_sig)


@dataclass
class Authenticator:
    """
    Kerberos Kanıtlayıcı (Authenticator) veri yapısı.
    Bilet ile birlikte istemcinin oturum anahtarına gerçekten sahip olduğunu kanıtlar.
    """
    # İstemci asıl adı (Client Principal Name, örn: ahmet@LAB.LOCAL)
    client_name: str
    # İstemcinin ait olduğu etki alanı (Realm)
    client_realm: str
    # İsteğin oluşturulduğu istemci zaman damgası (ISO-8601 UTC)
    timestamp: str
    # Mikrosaniye bileşeni (Yeniden oynatma saldırılarını kesin olarak ayrıştırmak için)
    cusec: int
    # İsteğin rastgele doğrulanma numarası (Subkey veya Nonce)
    sub_key: Optional[str] = None


@dataclass
class KerberosTicket:
    """
    Kerberos Bilet (Ticket) veri yapısı.
    TGT veya Servis Bileti olarak KDC tarafından üretilir ve ilgili servisin anahtarıyla şifrelenir.
    """
    # Biletin türü (TGT veya SERVICE)
    ticket_type: TicketType
    # Biletin düzenlendiği etki alanı (Realm)
    realm: str
    # Hedef servis asıl adı (Örn: krbtgt/LAB.LOCAL veya cifs/fs01.lab.local)
    service_principal: str
    # Biletin ait olduğu istemci asıl adı (Örn: mehmet@LAB.LOCAL)
    client_principal: str
    # İstemci ile hedef servis arasında kullanılacak paylaşılan simetrik oturum anahtarı
    session_key: str
    # Biletin oluşturulduğu an (AuthTime)
    auth_time: str
    # Biletin geçerliliğinin başladığı an (StartTime)
    start_time: str
    # Biletin sona ereceği an (EndTime)
    end_time: str
    # Biletin en son yenilenebileceği an (RenewTill)
    renew_till: Optional[str]
    # Kullanılan şifreleme algoritması
    encryption_type: EncryptionType
    # Şifreli bilet yükü (KDC veya Servis anahtarıyla şifrelenmiş temsilî bayt dizisi)
    encrypted_part_hash: str
    # Biletin taşıdığı yetki sertifikası (PAC)
    pac: Optional[PACInfo] = None
    # Biletin yenilenebilir olup olmadığı bayrağı
    is_renewable: bool = True


@dataclass
class ValidationResult:
    """
    Bir Kerberos doğrulama adımının sonucunu temsil eden veri yapısı.
    """
    # Doğrulamanın başarılı olup olmadığı (True / False)
    is_valid: bool
    # İncelenen adım veya kuralın adı
    rule_name: str
    # Detaylı açıklama ve tespit mesajı
    message: str
    # Tespit edilen güvenlik ciddiyet seviyesi (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    severity: str = "INFO"
    # Düzeltici aksiyon önerisi
    remediation: Optional[str] = None


@dataclass
class KerberosValidationReport:
    """
    Kerberos bilet akışı uçtan uca denetim raporu.
    """
    # Genel doğrulama durumu (Tüm adımlar başarılıysa True)
    success: bool
    # İstemci asıl adı
    client: str
    # Hedef servis asıl adı
    service: str
    # Gerçekleştirilen tüm kontrol sonuçlarının listesi
    checks: List[ValidationResult] = field(default_factory=list)
    # Tespit edilen güvenlik açıkları ve anomaliler
    anomalies: List[str] = field(default_factory=list)
    # Güvenlik skoru (0 - 100 arası)
    security_score: int = 100


class KerberosTicketFlowEngine:
    """
    Kerberos v5 Bilet Yaşam Döngüsü Simülasyon ve Güvenlik Denetim Motoru.
    RFC 4120 standartlarına uygun olarak bilet oluşturma, takas, şifreleme düşürme,
    saat sapması denetimi, yeniden oynatma engelleme ve sahte bilet tespiti yapar.
    """

    def __init__(self, realm: str, max_clock_skew_seconds: int = 300):
        """
        Motoru yapılandırır.
        
        Args:
            realm: Etki alanı adı (Örn: 'KURUM.LOCAL')
            max_clock_skew_seconds: İzin verilen maksimum saat sapması süresi (varsayılan 300 saniye / 5 dakika)
        """
        # Etki alanı adını büyük harflerle standartlaştırarak kaydeder.
        self.realm: str = realm.upper()
        # İzin verilen maksimum saat sapması eşiğini kaydeder.
        self.max_clock_skew: int = max_clock_skew_seconds
        # KDC'nin bildiği KRBTGT anahtarı (TGT biletlerini imzalamak ve şifrelemek için)
        self.krbtgt_key: bytes = b"KDC_SECRET_MASTER_KRBTGT_KEY_2026_AES256"
        # Kayıtlı servis anahtarlarını saklayan sözlük (SPN -> secret_key)
        self.service_keys: Dict[str, bytes] = {}
        # Kayıtlı kullanıcı anahtarları ve ön kimlik doğrulama gereksinimleri (Kullanıcı -> {key, req_preauth})
        self.user_database: Dict[str, Dict[str, Any]] = {}
        # Yeniden oynatma saldırılarını önlemek için kullanılan Replay Cache (İstemci, Zaman damgası, Cusec)
        self.replay_cache: Set[Tuple[str, str, int]] = set()

    def register_user(self, username: str, secret_key: bytes, require_preauth: bool = True) -> None:
        """
        Sisteme bir kullanıcı kaydeder veya yapılandırır.
        """
        # Kullanıcı adını etki alanı biçiminde oluşturur.
        principal = f"{username}@{self.realm}" if "@" not in username else username
        # Kullanıcı bilgilerini veritabanına ekler.
        self.user_database[principal] = {
            "key": secret_key,
            "require_preauth": require_preauth
        }

    def register_service(self, spn: str, service_key: bytes) -> None:
        """
        Sisteme bir hedef servis (SPN) kaydeder.
        """
        # Servis asıl adını ve gizli anahtarını sözlüğe kaydeder.
        self.service_keys[spn.lower()] = service_key

    def create_pac(self, user_sid: str, group_sids: List[str], service_key: bytes) -> PACInfo:
        """
        Kullanıcı SID ve grup bilgilerini içeren, Server ve KDC imzalarıyla mühürlenmiş PAC üretir.
        """
        # İmzalanacak temel veri dizesini hazırlar.
        data_to_sign = f"{user_sid}:" + ",".join(sorted(group_sids))
        # Servis anahtarıyla sunucu imzasını üretir.
        server_sig = hmac.new(service_key, data_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        # KRBTGT anahtarıyla KDC imzasını üretir (sunucu imzasını mühürler).
        kdc_sig = hmac.new(self.krbtgt_key, server_sig.encode("utf-8"), hashlib.sha256).hexdigest()
        # Oluşturulan PAC nesnesini döndürür.
        return PACInfo(
            user_sid=user_sid,
            group_sids=group_sids,
            server_signature=server_sig,
            kdc_signature=kdc_sig
        )

    def process_as_req(
        self,
        client_principal: str,
        preauth_timestamp: Optional[str] = None,
        requested_encryption: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
        current_time: Optional[datetime.datetime] = None
    ) -> Tuple[Optional[KerberosTicket], Optional[str], List[ValidationResult]]:
        """
        1. Aşama: AS-REQ İsteğini İşler ve TGT Üretir (Authentication Service Exchange).
        """
        # Kontrol sonuçlarını tutacak liste başlatılır.
        results: List[ValidationResult] = []
        # Geçerli zaman verilmediyse UTC olarak anlık zaman alınır.
        now = current_time or datetime.datetime.now(datetime.timezone.utc)

        # 1. Kullanıcı kaydı denetimi yapılır.
        user_info = self.user_database.get(client_principal)
        if not user_info:
            # Kullanıcı bulunamadıysa hata kaydı oluşturulur ve işlem reddedilir.
            results.append(ValidationResult(
                is_valid=False,
                rule_name="USER_EXISTENCE",
                message=f"Kullanıcı asıl adı KDC veritabanında bulunamadı: {client_principal}",
                severity="HIGH"
            ))
            return None, None, results

        # 2. Ön Kimlik Doğrulama (Pre-Authentication) Denetimi.
        if user_info["require_preauth"]:
            if not preauth_timestamp:
                # Ön kimlik doğrulama zorunlu olduğu halde zaman damgası gönderilmediyse reddedilir.
                results.append(ValidationResult(
                    is_valid=False,
                    rule_name="PRE_AUTHENTICATION",
                    message="Kullanıcı için ön kimlik doğrulama zorunlu ancak PA-ENC-TIMESTAMP eksik.",
                    severity="CRITICAL",
                    remediation="İstemci parolasından türetilen anahtarla şifreli ön kimlik doğrulama paketi göndermelidir."
                ))
                return None, None, results
            
            # Zaman damgası ayrıştırılır ve saat sapması kontrol edilir.
            try:
                pa_time = datetime.datetime.fromisoformat(preauth_timestamp)
                # Saat dilimi bilgisi yoksa UTC olarak varsayılır.
                if pa_time.tzinfo is None:
                    pa_time = pa_time.replace(tzinfo=datetime.timezone.utc)
                # KDC zamanı ile istek zamanı arasındaki mutlak fark hesaplanır.
                skew = abs((now - pa_time).total_seconds())
                if skew > self.max_clock_skew:
                    # Saat sapması eşiği aşıldıysa KRB_AP_ERR_SKEW hatası üretilir.
                    results.append(ValidationResult(
                        is_valid=False,
                        rule_name="CLOCK_SKEW",
                        message=f"Saat sapması izin verilen limiti aştı: {skew:.1f}s > {self.max_clock_skew}s",
                        severity="HIGH",
                        remediation="İstemci ve Domain Controller saatlerini NTP protokolü ile senkronize ediniz."
                    ))
                    return None, None, results
            except Exception as e:
                # Zaman formatı bozuksa hata verilir.
                results.append(ValidationResult(
                    is_valid=False,
                    rule_name="TIMESTAMP_PARSING",
                    message=f"Geçersiz zaman damgası formatı: {e}",
                    severity="HIGH"
                ))
                return None, None, results
        else:
            # Ön kimlik doğrulama kapalıysa AS-REP Roasting riski raporlanır!
            results.append(ValidationResult(
                is_valid=True,
                rule_name="PREAUTH_VULNERABILITY",
                message=f"DİKKAT: {client_principal} üzerinde DONT_REQ_PREAUTH bayrağı aktif. AS-REP Roasting riski!",
                severity="HIGH",
                remediation="Active Directory Users and Computers üzerinden 'Do not require Kerberos preauthentication' kutucuğunun işaretini kaldırınız."
            ))

        # 3. Şifreleme Süiti Güvenlik Denetimi.
        if requested_encryption in (EncryptionType.RC4_HMAC, EncryptionType.DES_CBC_MD5):
            results.append(ValidationResult(
                is_valid=False,
                rule_name="CIPHER_SUITE_DOWNGRADE",
                message=f"Güvensiz şifreleme türü talep edildi: {requested_encryption.value}. Downgrade atağı şüphesi!",
                severity="CRITICAL",
                remediation="DES ve RC4 algoritmalarını devre dışı bırakıp yalnızca AES-128/256 kullanımını zorunlu tutunuz."
            ))
            return None, None, results

        # 4. TGT Biletinin Üretimi (Geçerlilik süresi: 10 saat, Yenileme süresi: 7 gün).
        auth_time_str = now.isoformat()
        end_time_str = (now + datetime.timedelta(hours=10)).isoformat()
        renew_till_str = (now + datetime.timedelta(days=7)).isoformat()
        session_key = secrets.token_hex(32)

        # TGT yükünün KRBTGT anahtarıyla şifrelenmesi simülasyonu.
        tgt_payload = f"{client_principal}:{session_key}:{end_time_str}"
        tgt_hash = hmac.new(self.krbtgt_key, tgt_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        # Standart kullanıcı PAC'i KRBTGT anahtarıyla üretilir.
        user_sid = f"S-1-5-21-123456789-987654321-1001"
        group_sids = ["S-1-5-21-123456789-987654321-513"] # Domain Users
        pac = self.create_pac(user_sid, group_sids, self.krbtgt_key)

        tgt = KerberosTicket(
            ticket_type=TicketType.TGT,
            realm=self.realm,
            service_principal=f"krbtgt/{self.realm}",
            client_principal=client_principal,
            session_key=session_key,
            auth_time=auth_time_str,
            start_time=auth_time_str,
            end_time=end_time_str,
            renew_till=renew_till_str,
            encryption_type=requested_encryption,
            encrypted_part_hash=tgt_hash,
            pac=pac,
            is_renewable=True
        )

        results.append(ValidationResult(
            is_valid=True,
            rule_name="AS_EXCHANGE_SUCCESS",
            message=f"TGT başarıyla üretildi: İstemci={client_principal}, Bilet Ömrü=10 saat, Şifreleme={requested_encryption.value}"
        ))

        return tgt, session_key, results

    def process_tgs_req(
        self,
        tgt: KerberosTicket,
        authenticator: Authenticator,
        target_spn: str,
        current_time: Optional[datetime.datetime] = None
    ) -> Tuple[Optional[KerberosTicket], Optional[str], List[ValidationResult]]:
        """
        2. Aşama: TGS-REQ İsteğini İşler ve Servis Bileti Üretir (Ticket Granting Service Exchange).
        """
        # Doğrulama sonuçları listesi başlatılır.
        results: List[ValidationResult] = []
        # Geçerli zaman belirlenir.
        now = current_time or datetime.datetime.now(datetime.timezone.utc)

        # 1. Hedef Servisin Varlığı Denetlenir.
        spn_clean = target_spn.lower()
        if spn_clean not in self.service_keys:
            results.append(ValidationResult(
                is_valid=False,
                rule_name="SPN_EXISTENCE",
                message=f"Hedef Servis Asıl Adı (SPN) KDC veritabanında bulunamadı: {target_spn}",
                severity="HIGH",
                remediation="Servis hesabına uygun 'setspn -s' komutu ile geçerli SPN ataması yapınız."
            ))
            return None, None, results

        service_key = self.service_keys[spn_clean]

        # 2. TGT Bütünlüğü ve KRBTGT İmzası Denetlenir (Golden Ticket Tespiti!).
        expected_tgt_payload = f"{tgt.client_principal}:{tgt.session_key}:{tgt.end_time}"
        expected_tgt_hash = hmac.new(self.krbtgt_key, expected_tgt_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tgt.encrypted_part_hash, expected_tgt_hash):
            results.append(ValidationResult(
                is_valid=False,
                rule_name="GOLDEN_TICKET_DETECTED",
                message="TGT imzası KDC KRBTGT anahtarıyla uyuşmuyor! Sahte bilet (Golden Ticket) atağı tespit edildi!",
                severity="CRITICAL",
                remediation="KRBTGT parolasını 12-24 saat arayla iki kez sıfırlayınız ve etki alanı denetleyicilerini izole ediniz."
            ))
            return None, None, results

        # 3. TGT Süre Sınırı (Expiration) Denetlenir.
        tgt_end = datetime.datetime.fromisoformat(tgt.end_time)
        if tgt_end.tzinfo is None:
            tgt_end = tgt_end.replace(tzinfo=datetime.timezone.utc)
        if now > tgt_end:
            results.append(ValidationResult(
                is_valid=False,
                rule_name="TGT_EXPIRED",
                message=f"Sunulan TGT biletinin süresi dolmuş. Sona erme zamanı: {tgt.end_time}",
                severity="MEDIUM",
                remediation="İstemci yeni bir AS-REQ isteği yaparak güncel TGT temin etmelidir."
            ))
            return None, None, results

        # 4. Kanıtlayıcı (Authenticator) ve İstemci Kimliği Eşleşmesi Denetlenir.
        if authenticator.client_name != tgt.client_principal:
            results.append(ValidationResult(
                is_valid=False,
                rule_name="CLIENT_PRINCIPAL_MISMATCH",
                message=f"Kanıtlayıcıdaki istemci ({authenticator.client_name}) ile TGT istemcisi ({tgt.client_principal}) uyuşmuyor!",
                severity="HIGH"
            ))
            return None, None, results

        # 5. Saat Sapması ve Yeniden Oynatma (Replay Attack) Denetimi.
        try:
            auth_time = datetime.datetime.fromisoformat(authenticator.timestamp)
            if auth_time.tzinfo is None:
                auth_time = auth_time.replace(tzinfo=datetime.timezone.utc)
            skew = abs((now - auth_time).total_seconds())
            if skew > self.max_clock_skew:
                results.append(ValidationResult(
                    is_valid=False,
                    rule_name="AUTHENTICATOR_CLOCK_SKEW",
                    message=f"Kanıtlayıcı saat sapması limiti aştı: {skew:.1f}s > {self.max_clock_skew}s",
                    severity="HIGH"
                ))
                return None, None, results
        except Exception as e:
            results.append(ValidationResult(
                is_valid=False,
                rule_name="TIMESTAMP_PARSING",
                message=f"Kanıtlayıcı zaman damgası bozuk: {e}",
                severity="HIGH"
            ))
            return None, None, results

        # Yeniden oynatma kontrolü (Replay Cache)
        replay_key = (authenticator.client_name, authenticator.timestamp, authenticator.cusec)
        if replay_key in self.replay_cache:
            results.append(ValidationResult(
                is_valid=False,
                rule_name="REPLAY_ATTACK_DETECTED",
                message="Aynı kanıtlayıcı (Authenticator) daha önce kullanılmış! Yeniden oynatma saldırısı tespit edildi!",
                severity="CRITICAL",
                remediation="Şüpheli istemci bağlantısını sonlandırınız ve ağda yetkisiz paket yakalama/enjeksiyonu araştırınız."
            ))
            return None, None, results
        
        # Kanıtlayıcı yeniden oynatma önbelleğine kaydedilir.
        self.replay_cache.add(replay_key)

        # 6. Servis Bileti (TGS) Üretimi (Geçerlilik süresi: TGT sonu veya maksimum 10 saat).
        tgs_session_key = secrets.token_hex(32)
        tgs_end_time = min(tgt_end, now + datetime.timedelta(hours=10)).isoformat()
        
        # Servis bileti yükünün hedef servis anahtarıyla şifrelenmesi.
        service_payload = f"{tgt.client_principal}:{tgs_session_key}:{tgs_end_time}"
        service_hash = hmac.new(service_key, service_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        # PAC bilgisi TGT'den aktarılır ve hedef servis anahtarı ile sunucu imzası güncellenir.
        if tgt.pac:
            pac = self.create_pac(tgt.pac.user_sid, tgt.pac.group_sids, service_key)
        else:
            pac = None

        service_ticket = KerberosTicket(
            ticket_type=TicketType.SERVICE,
            realm=self.realm,
            service_principal=target_spn,
            client_principal=tgt.client_principal,
            session_key=tgs_session_key,
            auth_time=now.isoformat(),
            start_time=now.isoformat(),
            end_time=tgs_end_time,
            renew_till=tgt.renew_till,
            encryption_type=tgt.encryption_type,
            encrypted_part_hash=service_hash,
            pac=pac,
            is_renewable=False
        )

        results.append(ValidationResult(
            is_valid=True,
            rule_name="TGS_EXCHANGE_SUCCESS",
            message=f"Servis bileti başarıyla üretildi: Servis={target_spn}, İstemci={tgt.client_principal}"
        ))

        return service_ticket, tgs_session_key, results

    def process_ap_req(
        self,
        service_ticket: KerberosTicket,
        authenticator: Authenticator,
        current_time: Optional[datetime.datetime] = None
    ) -> KerberosValidationReport:
        """
        3. Aşama: AP-REQ İsteğini Doğrular (Application / Client-Server Exchange).
        Hedef servis sunucusu bileti ve kanıtlayıcıyı inceler, PAC imzasını test eder.
        """
        # Kontrol adımları listesi başlatılır.
        checks: List[ValidationResult] = []
        # Tespit edilen güvenlik anomalileri listesi
        anomalies: List[str] = []
        # Başlangıç güvenlik skoru
        security_score: int = 100
        # Geçerli zaman
        now = current_time or datetime.datetime.now(datetime.timezone.utc)

        # 1. Servis Anahtarının Mevcudiyeti Denetlenir.
        spn_clean = service_ticket.service_principal.lower()
        if spn_clean not in self.service_keys:
            checks.append(ValidationResult(
                is_valid=False,
                rule_name="SERVICE_KEY_UNKNOWN",
                message=f"Sunucu bu SPN için özel anahtara sahip değil: {service_ticket.service_principal}",
                severity="CRITICAL"
            ))
            return KerberosValidationReport(
                success=False,
                client=authenticator.client_name,
                service=service_ticket.service_principal,
                checks=checks,
                anomalies=["Bilinmeyen servis anahtarı"],
                security_score=0
            )

        service_key = self.service_keys[spn_clean]

        # 2. Servis Bileti Şifre Çözümü ve Bütünlük Kontrolü (Silver Ticket Tespiti!).
        expected_service_payload = f"{service_ticket.client_principal}:{service_ticket.session_key}:{service_ticket.end_time}"
        expected_service_hash = hmac.new(service_key, expected_service_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(service_ticket.encrypted_part_hash, expected_service_hash):
            checks.append(ValidationResult(
                is_valid=False,
                rule_name="SILVER_TICKET_DETECTED",
                message="Servis bileti sunucu anahtarıyla doğrulanamadı! Sahte servis bileti (Silver Ticket) atağı tespit edildi!",
                severity="CRITICAL",
                remediation="Servis hesabının parolasını derhal sıfırlayınız ve sunucu belleğindeki oturumları sonlandırınız."
            ))
            anomalies.append("Silver Ticket Sahteciliği")
            security_score -= 50

        # 3. Süre Sınırı Kontrolü.
        ticket_end = datetime.datetime.fromisoformat(service_ticket.end_time)
        if ticket_end.tzinfo is None:
            ticket_end = ticket_end.replace(tzinfo=datetime.timezone.utc)
        if now > ticket_end:
            checks.append(ValidationResult(
                is_valid=False,
                rule_name="SERVICE_TICKET_EXPIRED",
                message=f"Sunulan servis biletinin süresi dolmuş. Sona erme zamanı: {service_ticket.end_time}",
                severity="MEDIUM"
            ))
            anomalies.append("Süresi dolmuş bilet")
            security_score -= 20
        else:
            checks.append(ValidationResult(
                is_valid=True,
                rule_name="SERVICE_TICKET_VALIDITY",
                message="Servis bileti geçerlilik süresi içinde."
            ))

        # 4. Kanıtlayıcı Zaman Sapması ve Yeniden Oynatma Denetimi.
        try:
            auth_time = datetime.datetime.fromisoformat(authenticator.timestamp)
            if auth_time.tzinfo is None:
                auth_time = auth_time.replace(tzinfo=datetime.timezone.utc)
            skew = abs((now - auth_time).total_seconds())
            if skew > self.max_clock_skew:
                checks.append(ValidationResult(
                    is_valid=False,
                    rule_name="AP_CLOCK_SKEW",
                    message=f"AP-REQ Kanıtlayıcı saat sapması limiti aştı: {skew:.1f}s > {self.max_clock_skew}s",
                    severity="HIGH"
                ))
                anomalies.append("Aşırı Saat Sapması")
                security_score -= 30
            else:
                checks.append(ValidationResult(
                    is_valid=True,
                    rule_name="AP_CLOCK_SKEW_OK",
                    message=f"Saat sapması güvenli aralıkta ({skew:.1f}s)."
                ))
        except Exception as e:
            checks.append(ValidationResult(
                is_valid=False,
                rule_name="AP_TIMESTAMP_ERROR",
                message=f"Zaman damgası okunamadı: {e}",
                severity="HIGH"
            ))
            anomalies.append("Bozuk Zaman Damgası")
            security_score -= 30

        # Replay Cache Kontrolü
        replay_key = (f"AP_{authenticator.client_name}", authenticator.timestamp, authenticator.cusec)
        if replay_key in self.replay_cache:
            checks.append(ValidationResult(
                is_valid=False,
                rule_name="AP_REPLAY_ATTACK",
                message="AP-REQ seviyesinde yeniden oynatma saldırısı tespit edildi! Aynı kanıtlayıcı tekrar sunuldu.",
                severity="CRITICAL"
            ))
            anomalies.append("AP Yeniden Oynatma Saldırısı")
            security_score -= 50
        else:
            self.replay_cache.add(replay_key)
            checks.append(ValidationResult(
                is_valid=True,
                rule_name="AP_REPLAY_CACHE_OK",
                message="Kanıtlayıcı özgün ve daha önce görülmemiş."
            ))

        # 5. PAC HMAC Bütünlük Denetimi (Server ve KDC İmzaları).
        if service_ticket.pac:
            # Sunucu imzası doğrulaması
            if not service_ticket.pac.verify_server_signature(service_key):
                checks.append(ValidationResult(
                    is_valid=False,
                    rule_name="PAC_SERVER_SIG_TAMPERED",
                    message="PAC Sunucu İmzası geçersiz! Yetki ayrıcalıkları manipüle edilmiş olabilir.",
                    severity="CRITICAL",
                    remediation="PAC doğrulama hatası durumunda oturum açma isteğini derhal reddediniz."
                ))
                anomalies.append("PAC Sunucu İmzası Sahteciliği")
                security_score -= 40
            else:
                checks.append(ValidationResult(
                    is_valid=True,
                    rule_name="PAC_SERVER_SIG_OK",
                    message="PAC Sunucu İmzası başarıyla doğrulandı."
                ))

            # KDC imzası doğrulaması
            if not service_ticket.pac.verify_kdc_signature(self.krbtgt_key):
                checks.append(ValidationResult(
                    is_valid=False,
                    rule_name="PAC_KDC_SIG_TAMPERED",
                    message="PAC KDC İmzası geçersiz! KDC dışında üretilmiş sahte bilet şüphesi.",
                    severity="CRITICAL"
                ))
                anomalies.append("PAC KDC İmzası Sahteciliği")
                security_score -= 40
            else:
                checks.append(ValidationResult(
                    is_valid=True,
                    rule_name="PAC_KDC_SIG_OK",
                    message="PAC KDC İmzası başarıyla doğrulandı."
                ))
        else:
            checks.append(ValidationResult(
                is_valid=True,
                rule_name="PAC_ABSENT",
                message="Bilette PAC sertifikası yer almıyor (Yetkisiz temel kimlik doğrulama)."
            ))

        # 6. Şifreleme Algoritması Zafiyet Taraması.
        if service_ticket.encryption_type in (EncryptionType.RC4_HMAC, EncryptionType.DES_CBC_MD5):
            anomalies.append(f"Zayıf Şifreleme Algoritması ({service_ticket.encryption_type.value})")
            security_score -= 25

        # Skor 0'ın altına düşemez.
        security_score = max(0, security_score)
        overall_success = len(anomalies) == 0

        return KerberosValidationReport(
            success=overall_success,
            client=authenticator.client_name,
            service=service_ticket.service_principal,
            checks=checks,
            anomalies=anomalies,
            security_score=security_score
        )
