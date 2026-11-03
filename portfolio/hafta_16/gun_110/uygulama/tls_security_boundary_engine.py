# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
TLS Güvenlik Sınırları ve Protokol Analiz Motoru (tls_security_boundary_engine.py).

Bu modül; TLS el sıkışma (Handshake) ve kayıt (Record) protokollerinin güvenlik sınırlarını,
şifre paketi pazarlığını, Downgrade saldırılarına karşı Fallback-SCSV ve Sentinel baytlarını,
el sıkışma transkript bütünlüğünü (Finished VerifyData), Ephemeral anahtar değişimiyle
sağlanan İleriye Dönük Gizliliği (Perfect Forward Secrecy - PFS), sıra numarası (Sequence Number)
ve AEAD kimlik doğrulamalı şifreleme sınırlarını harici bağımlılık olmadan (Pure Python) simüle eder.
"""

import os
import sys
import json
import time
import hmac
import secrets
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Set

# ==============================================================================
# 1. ÖZEL İSTİSNA SINIFLARI (CWE GÜVENLİK KONTROLLERİ)
# ==============================================================================

class TLSError(Exception):
    """Tüm TLS güvenlik sınırı hatalarının temel sınıfı."""
    pass

class TLSDowngradeDetectedError(TLSError):
    """CWE-757: Protokol sürümünü daha zayıf bir sürüme düşürme (Downgrade Dance) tespiti."""
    pass

class InsecureCipherSuiteError(TLSError):
    """CWE-327: Kırılmış, güvenliği zayıf veya yasaklanmış şifre paketi kullanımı (RC4/DES/NULL)."""
    pass

class HandshakeTranscriptIntegrityError(TLSError):
    """CWE-353: El sıkışma transkriptinde tahrifat tespiti (Finished mesajı doğrulama hatası)."""
    pass

class ForwardSecrecyRequiredError(TLSError):
    """CWE-327: Statik RSA kullanımı nedeniyle İleriye Dönük Gizlilik (PFS) sağlanamaması."""
    pass

class BadRecordMACError(TLSError):
    """CWE-353: Record katmanında AEAD kimlik doğrulama etiketi veya MAC uyuşmazlığı."""
    pass

class ZeroRTTReplayDetectedError(TLSError):
    """CWE-294: TLS 1.3 0-RTT Erken Veri (Early Data) tekrar oynatma (Replay) saldırısı."""
    pass

class InvalidSequenceNumberError(TLSError):
    """CWE-353: Record katmanında sıra numarası (Sequence Number) kayması veya paket çalınması."""
    pass

class RecordOverflowError(TLSError):
    """CWE-20: RFC 8446 standardındaki 16384 baytlık azami record fragment sınırının aşılması."""
    pass

class DowngradeSentinelMismatchError(TLSError):
    """CWE-757: ServerRandom içindeki RFC 8446 Downgrade Sentinel baytlarının tespit edilmesi."""
    pass


# ==============================================================================
# 2. KRİPTOGRAFİK YARDIMCI İŞLEMLER (HKDF - RFC 5869 VE AEAD SİMÜLATÖRÜ)
# ==============================================================================

def hkdf_extract(salt: bytes, ikm: bytes, hash_mod=hashlib.sha256) -> bytes:
    """RFC 5869 HKDF-Extract: Girdi anahtar materyalinden sözde rastgele anahtar (PRK) üretir."""
    if not salt:
        # Eğer tuz verilmemişse hash çıktı uzunluğunda sıfır baytları kullanılır
        salt = b"\x00" * hash_mod().digest_size
    return hmac.new(salt, ikm, hash_mod).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, hash_mod=hashlib.sha256) -> bytes:
    """RFC 5869 HKDF-Expand: PRK'yı istenen uzunlukta çıktı anahtarına (OKM) genişletir."""
    hash_len = hash_mod().digest_size
    n = (length + hash_len - 1) // hash_len
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_mod).digest()
        okm.extend(t)
    return bytes(okm[:length])

class SimulatedAEADCipher:
    """TLS 1.3 AEAD (Örn: AES-GCM / ChaCha20-Poly1305) simülatörü."""
    def __init__(self, key: bytes):
        # 256-bit simetrik anahtar
        self.key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """Açık metni şifreler ve ilişkili veriyi (AAD) doğrulayan 16 baytlık etiket (Tag) üretir."""
        # Akış şifreleme simülasyonu: Keystream = HMAC(key, nonce)
        keystream = hkdf_expand(self.key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        # AEAD kimlik doğrulama etiketi: Tag = HMAC(key, AAD || Ciphertext || len(AAD))
        tag_payload = associated_data + ciphertext + len(associated_data).to_bytes(8, "big")
        tag = hmac.new(self.key, tag_payload, hashlib.sha256).digest()[:16]
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes, tag: bytes) -> bytes:
        """Etiketi doğrular ve şifreli metni çözer. Tahrifat varsa BadRecordMACError fırlatır."""
        # Beklenen etiketi hesapla
        tag_payload = associated_data + ciphertext + len(associated_data).to_bytes(8, "big")
        expected_tag = hmac.new(self.key, tag_payload, hashlib.sha256).digest()[:16]
        # Zamanlama saldırılarına dirençli karşılaştırma (CWE-208 / CWE-353)
        if not hmac.compare_digest(tag, expected_tag):
            raise BadRecordMACError("CWE-353: Record katmanı AEAD kimlik doğrulama etiketi (MAC) uyuşmuyor!")
        # Açık metni çöz
        keystream = hkdf_expand(self.key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))


# ==============================================================================
# 3. TLS RECORD PROTOKOLÜ VE SINIR DENETİMLERİ (RFC 8446 SECTION 5)
# ==============================================================================

class TLSRecordLayer:
    """TLS Record Katmanı çerçeveleme, sıra numarası ve boyut kontrol mekanizması."""
    MAX_FRAGMENT_LENGTH = 16384 # 2^14 bayt = 16 KB (RFC 8446)
    
    CONTENT_TYPE_ALERT = 21
    CONTENT_TYPE_HANDSHAKE = 22
    CONTENT_TYPE_APPLICATION_DATA = 23

    def __init__(self, aead_cipher: Optional[SimulatedAEADCipher] = None):
        self.cipher = aead_cipher
        # Gönderici ve alıcı sıra numaraları (64-bit monontonik sayaç)
        self.send_seq_num = 0
        self.recv_seq_num = 0

    def create_record(self, content_type: int, payload_bytes: bytes) -> Dict[str, Any]:
        """Veriyi TLS record formatında paketler ve şifreleme varsa AEAD uygular."""
        # CWE-20: Aşırı büyük record fragment denetimi
        if len(payload_bytes) > self.MAX_FRAGMENT_LENGTH:
            raise RecordOverflowError(
                f"CWE-20: Record boyutu ({len(payload_bytes)} bayt) izin verilen azami sınırı ({self.MAX_FRAGMENT_LENGTH}) aşıyor!"
            )

        seq = self.send_seq_num
        self.send_seq_num += 1

        if self.cipher:
            # 64-bit sequence number'dan 12-bayt nonce türet
            nonce = seq.to_bytes(12, "big")
            # AAD: Type (1B) + Version (2B) + Length (2B)
            aad = bytes([content_type, 0x03, 0x03]) + len(payload_bytes).to_bytes(2, "big")
            ciphertext, tag = self.cipher.encrypt(nonce, payload_bytes, aad)
            return {
                "content_type": content_type,
                "sequence_number": seq,
                "ciphertext_hex": ciphertext.hex(),
                "tag_hex": tag.hex(),
                "is_encrypted": True
            }
        else:
            return {
                "content_type": content_type,
                "sequence_number": seq,
                "payload_hex": payload_bytes.hex(),
                "is_encrypted": False
            }

    def process_record(self, record: Dict[str, Any]) -> bytes:
        """Gelen TLS record'unu ayrıştırır, sıra numarasını denetler ve şifresini çözer."""
        incoming_seq = record.get("sequence_number", 0)
        # CWE-353: Sıra numarası bütünlük ve atlama kontrolü
        if incoming_seq != self.recv_seq_num:
            raise InvalidSequenceNumberError(
                f"CWE-353: Beklenen sıra numarası {self.recv_seq_num}, gelen sıra numarası {incoming_seq} ile uyuşmuyor!"
            )
        self.recv_seq_num += 1

        if record.get("is_encrypted", False):
            if not self.cipher:
                raise TLSError("Şifreli record alındı fakat istemcide anahtar tanımlı değil!")
            nonce = incoming_seq.to_bytes(12, "big")
            ciphertext = bytes.fromhex(record["ciphertext_hex"])
            tag = bytes.fromhex(record["tag_hex"])
            content_type = record["content_type"]
            aad = bytes([content_type, 0x03, 0x03]) + len(ciphertext).to_bytes(2, "big")
            return self.cipher.decrypt(nonce, ciphertext, aad, tag)
        else:
            return bytes.fromhex(record.get("payload_hex", ""))


# ==============================================================================
# 4. TLS EL SIKIŞMASI (HANDSHAKE) VE GÜVENLİK SINIRLARI
# ==============================================================================

# Standart Şifre Paketleri Kataloğu
CIPHER_SUITES_CATALOG = {
    # TLS 1.3 Modern AEAD Paketleri (Güvenli)
    "TLS_AES_256_GCM_SHA384": {"pfs": True, "aead": True, "status": "SECURE", "version": "TLSv1.3"},
    "TLS_CHACHA20_POLY1305_SHA256": {"pfs": True, "aead": True, "status": "SECURE", "version": "TLSv1.3"},
    "TLS_AES_128_GCM_SHA256": {"pfs": True, "aead": True, "status": "SECURE", "version": "TLSv1.3"},
    # TLS 1.2 Güvenli ECDHE Paketleri
    "ECDHE-RSA-AES256-GCM-SHA384": {"pfs": True, "aead": True, "status": "SECURE", "version": "TLSv1.2"},
    "ECDHE-RSA-AES128-GCM-SHA256": {"pfs": True, "aead": True, "status": "SECURE", "version": "TLSv1.2"},
    # Zayıf / Yasaklanmış Paketler (CWE-327)
    "TLS_RSA_WITH_AES_128_CBC_SHA": {"pfs": False, "aead": False, "status": "WEAK", "version": "TLSv1.2"},
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": {"pfs": False, "aead": False, "status": "INSECURE", "version": "TLSv1.2"},
    "TLS_RSA_WITH_RC4_128_MD5": {"pfs": False, "aead": False, "status": "BROKEN", "version": "TLSv1.0"},
    "TLS_RSA_WITH_NULL_SHA": {"pfs": False, "aead": False, "status": "BROKEN", "version": "SSLv3"}
}

# RFC 8446 Section 4.1.3 Downgrade Sentinel Baytları
# Sunucu TLS 1.3 desteklediği halde TLS 1.2'ye düşerse ServerRandom son 8 baytı:
TLS12_DOWNGRADE_SENTINEL = bytes.fromhex("444F574E47524401") # "DOWNGRD\x01"
TLS11_DOWNGRADE_SENTINEL = bytes.fromhex("444F574E47524400") # "DOWNGRD\x00"

class TLSHandshakeEngine:
    """TLS El Sıkışma Protokolü, Sürüm ve Şifre Paketi Pazarlık Denetleyicisi."""
    def __init__(self, supported_versions: List[str], allowed_ciphers: List[str],
                 require_pfs: bool = True, fallback_scsv_enabled: bool = True):
        self.supported_versions = supported_versions
        self.allowed_ciphers = allowed_ciphers
        self.require_pfs = require_pfs
        self.fallback_scsv_enabled = fallback_scsv_enabled
        # El sıkışma transkript günlüğü (Transcript-Hash için)
        self.transcript_messages: List[bytes] = []

    def record_handshake_message(self, msg_type: str, data: Dict[str, Any]) -> None:
        """Kanonik el sıkışma mesajını transkript özetine ekler."""
        msg_bytes = f"{msg_type}:{json.dumps(data, sort_keys=True)}".encode("utf-8")
        self.transcript_messages.append(msg_bytes)

    def compute_transcript_hash(self) -> bytes:
        """Tüm el sıkışma transkriptinin SHA-256 özetini alır."""
        hasher = hashlib.sha256()
        for msg in self.transcript_messages:
            hasher.update(msg)
        return hasher.digest()

    def create_client_hello(self, client_versions: List[str], requested_ciphers: List[str],
                            is_fallback: bool = False) -> Dict[str, Any]:
        """İstemci tarafında ClientHello mesajı oluşturur."""
        client_random = secrets.token_bytes(32)
        ciphers = list(requested_ciphers)
        # Eğer bağlantı yeniden deneniyorsa (Fallback), SCSV sinyali ekle (RFC 7507)
        if is_fallback and self.fallback_scsv_enabled:
            ciphers.append("TLS_FALLBACK_SCSV")

        hello = {
            "client_version": client_versions[0],
            "client_random_hex": client_random.hex(),
            "cipher_suites": ciphers,
            "supported_versions": client_versions,
            "extensions": {
                "server_name": "guvenli.kurum.local",
                "supported_groups": ["x25519", "secp256r1"],
                "key_share": "ephemeral_client_public_key"
            }
        }
        self.record_handshake_message("ClientHello", hello)
        return hello

    def process_client_hello_and_reply(self, client_hello: Dict[str, Any]) -> Dict[str, Any]:
        """Sunucu tarafında ClientHello'yu inceler, şifre ve sürüm pazarlığını yürütür."""
        # Gelen ClientHello mesajını sunucu transkriptine kaydet (Transcript-Hash için)
        self.record_handshake_message("ClientHello", client_hello)

        client_versions = client_hello.get("supported_versions", [client_hello.get("client_version")])
        client_ciphers = client_hello.get("cipher_suites", [])

        # 1. Adım: RFC 7507 Fallback-SCSV Downgrade Kontrolü (CWE-757)
        has_fallback_scsv = "TLS_FALLBACK_SCSV" in client_ciphers
        highest_server_version = self.supported_versions[0] # Örn: TLSv1.3
        highest_client_version = client_versions[0]

        if has_fallback_scsv and highest_server_version != highest_client_version:
            # Sunucu daha yüksek bir sürüm destekliyor ama istemci fallback ile geldi -> Saldırı!
            raise TLSDowngradeDetectedError(
                f"CWE-757: TLS_FALLBACK_SCSV uyarınca downgrade saldırısı tespit edildi! "
                f"Sunucu {highest_server_version} desteklerken istemci {highest_client_version} teklif etti."
            )

        # 2. Adım: Ortak Sürüm Pazarlığı
        negotiated_version = None
        for sv in self.supported_versions:
            if sv in client_versions:
                negotiated_version = sv
                break
        
        if not negotiated_version:
            raise TLSError("Uygun ortak TLS protokol sürümü bulunamadı (Handshake Failure)!")

        # 3. Adım: Şifre Paketi Pazarlığı ve Güvenlik Sınırları
        negotiated_cipher = None
        pfs_violation = False
        for c in client_ciphers:
            if c == "TLS_FALLBACK_SCSV":
                continue
            meta = CIPHER_SUITES_CATALOG.get(c)
            if not meta:
                continue
            # CWE-327 Kontrolü: Zayıf veya kırılmış şifreler elenir
            if meta["status"] in ("INSECURE", "BROKEN"):
                continue
            # İleriye Dönük Gizlilik (PFS) Kontrolü
            if self.require_pfs and not meta["pfs"]:
                pfs_violation = True
                continue
            if c in self.allowed_ciphers:
                negotiated_cipher = c
                break

        if not negotiated_cipher:
            if pfs_violation:
                raise ForwardSecrecyRequiredError(
                    "CWE-327: Sunucu İleriye Dönük Gizlilik (PFS) gerektirmektedir; statik RSA anahtar değişimi reddedildi!"
                )
            # İstemcinin tüm sunduğu paketler zayıf veya yasaklıysa
            raise InsecureCipherSuiteError(
                "CWE-327 / CWE-757: İstemcinin sunduğu paketlerin hiçbiri güvenlik politikasını sağlamıyor (RC4/DES/Statik RSA reddedildi)!"
            )

        # 4. Adım: ServerRandom Üretimi ve Downgrade Sentinel Baytları (RFC 8446 Section 4.1.3)
        server_random_bytes = bytearray(secrets.token_bytes(32))
        if highest_server_version == "TLSv1.3" and negotiated_version == "TLSv1.2":
            # Sunucu 1.3 desteklediği halde 1.2 seçildiyse sentinel baytlarını göm
            server_random_bytes[-8:] = TLS12_DOWNGRADE_SENTINEL

        server_hello = {
            "server_version": negotiated_version,
            "server_random_hex": bytes(server_random_bytes).hex(),
            "cipher_suite": negotiated_cipher,
            "extensions": {
                "key_share": "ephemeral_server_public_key"
            }
        }
        self.record_handshake_message("ServerHello", server_hello)
        return server_hello

    def verify_server_hello_and_downgrade_sentinel(self, server_hello: Dict[str, Any],
                                                   client_highest_version: str) -> None:
        """İstemci tarafında ServerHello'yu ve RFC 8446 Downgrade Sentinel baytlarını doğrular."""
        server_random = bytes.fromhex(server_hello["server_random_hex"])
        server_version = server_hello["server_version"]

        # CWE-757: Eğer istemci 1.3 destekliyorsa ve sunucu 1.2 döndüyse sentinel kontrolü yap
        if client_highest_version == "TLSv1.3" and server_version == "TLSv1.2":
            if server_random[-8:] == TLS12_DOWNGRADE_SENTINEL:
                raise DowngradeSentinelMismatchError(
                    "CWE-757: ServerRandom içinde TLS 1.2 Downgrade Sentinel baytları tespit edildi! Araya girme (MitM) engellendi."
                )

    def generate_finished_message(self, base_key: bytes) -> str:
        """Transcript-Hash üzerinden HMAC doğrulamalı Finished mesajı üretir."""
        transcript_hash = self.compute_transcript_hash()
        verify_data = hmac.new(base_key, transcript_hash, hashlib.sha256).hexdigest()
        return verify_data

    def verify_finished_message(self, base_key: bytes, presented_verify_data: str) -> bool:
        """Finished mesajının transkript ile tutarlılığını doğrular (CWE-353 Koruması)."""
        expected_data = self.generate_finished_message(base_key)
        if not hmac.compare_digest(expected_data, presented_verify_data):
            raise HandshakeTranscriptIntegrityError(
                "CWE-353: Finished mesajı doğrulanamadı! El sıkışma transkripti aradaki saldırgan tarafından değiştirilmiştir."
            )
        return True


# ==============================================================================
# 5. TLS 1.3 0-RTT ERKEN VERİ (EARLY DATA) VE REPLAY SALDIRI ENGELLEYİCİ
# ==============================================================================

class TLS13ZeroRTTAntiReplayCache:
    """TLS 1.3 0-RTT Erken Veri (Early Data) Replay Önleme Önbelleği (RFC 8446 Section 8)."""
    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        # İşlenen bilet kimlikleri ve zaman damgaları: {ticket_id: timestamp}
        self.seen_tickets: Dict[str, float] = {}

    def process_early_data(self, ticket_id: str, request_payload: str) -> Dict[str, Any]:
        """0-RTT verisini inceler. Aynı bilet tekrar sunulursa CWE-294 hatası fırlatır."""
        now = time.time()
        # Süresi dolmuş eski kayıtları temizle
        self.seen_tickets = {t: ts for t, ts in self.seen_tickets.items() if now - ts < self.window_seconds}

        # CWE-294 Replay Tespiti
        if ticket_id in self.seen_tickets:
            raise ZeroRTTReplayDetectedError(
                f"CWE-294: 0-RTT Erken Veri Replay saldırısı engellendi! Bilet ID ({ticket_id}) zaten kullanıldı."
            )

        # Yeni bileti önbelleğe al
        self.seen_tickets[ticket_id] = now
        return {
            "status": "ACCEPTED",
            "ticket_id": ticket_id,
            "payload": request_payload,
            "processed_at": now
        }
