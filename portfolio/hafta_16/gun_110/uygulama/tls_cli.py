# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
"""
TLS Güvenlik Sınırları ve Protokol Analiz CLI Aracı (tls_cli.py).

Kullanıcıların komut satırı üzerinden TLS 1.2 vs 1.3 el sıkışmasını,
şifre paketi pazarlığını, Downgrade saldırılarına karşı Fallback-SCSV ve Sentinel
savunmalarını, Record katmanı AEAD ve Sıra Numarası kontrollerini,
0-RTT Replay engelleme mekanizmalarını test etmesini ve raporlamasını sağlar.
"""

import sys
import json
import argparse
from typing import Dict, Any

# TLS güvenlik motoru bileşenlerini içeri aktar
from tls_security_boundary_engine import (
    TLSHandshakeEngine,
    TLSRecordLayer,
    SimulatedAEADCipher,
    TLS13ZeroRTTAntiReplayCache,
    TLSError,
    TLSDowngradeDetectedError,
    InsecureCipherSuiteError,
    HandshakeTranscriptIntegrityError,
    BadRecordMACError,
    ZeroRTTReplayDetectedError,
    InvalidSequenceNumberError,
    RecordOverflowError,
    DowngradeSentinelMismatchError
)

def print_banner() -> None:
    """CLI aracının karşılama afişini konsola basar."""
    print("=" * 72)
    print("  TLS GÜVENLİK SINIRLARI VE PROTOKOL ANALİZ ARACI")
    print("  RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3) / RFC 7507 (Fallback-SCSV)")
    print("=" * 72)

def run_handshake_demo(json_output: bool = False) -> Dict[str, Any]:
    """Başarılı ve sertleştirilmiş bir TLS 1.3 el sıkışmasını simüle eder."""
    if not json_output:
        print("\n[*] 1. ADIM: İstemci ve Sunucu TLS Motorları Başlatılıyor...")

    server_engine = TLSHandshakeEngine(
        supported_versions=["TLSv1.3", "TLSv1.2"],
        allowed_ciphers=["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        require_pfs=True
    )

    client_engine = TLSHandshakeEngine(
        supported_versions=["TLSv1.3", "TLSv1.2"],
        allowed_ciphers=["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
        require_pfs=True
    )

    # 1. ClientHello
    client_hello = client_engine.create_client_hello(
        client_versions=["TLSv1.3", "TLSv1.2"],
        requested_ciphers=["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]
    )
    if not json_output:
        print(f"[+] ClientHello Gönderildi:")
        print(f"    - Sürümler: {client_hello['supported_versions']}")
        print(f"    - Şifre Paketleri: {client_hello['cipher_suites']}")

    # 2. ServerHello
    server_hello = server_engine.process_client_hello_and_reply(client_hello)
    if not json_output:
        print(f"[+] ServerHello Alındı:")
        print(f"    - Pazarlık Edilen Sürüm: {server_hello['server_version']}")
        print(f"    - Seçilen Şifre Paketi: {server_hello['cipher_suite']}")

    # Sunucu mesajını istemci transkriptine de kaydet
    client_engine.record_handshake_message("ServerHello", server_hello)

    # 3. Transcript Hash ve Finished Mesajları
    handshake_key = b"gizli_el_sikisma_anahtari_256bit!"
    verify_data = client_engine.generate_finished_message(handshake_key)
    # Sunucu doğrular
    is_valid_finished = server_engine.verify_finished_message(handshake_key, verify_data)

    if not json_output:
        print(f"[+] Finished Mesajı (Transcript-Hash): {verify_data[:16]}... (Doğrulandı: {is_valid_finished})")

    # 4. Record Katmanı Güvenli Veri Aktarımı
    aead_cipher = SimulatedAEADCipher(key=b"uygulama_trafigi_simetrik_anaht")
    record_layer = TLSRecordLayer(aead_cipher=aead_cipher)

    http_request = b"GET /api/v1/guvenli-veri HTTP/1.1\r\nHost: guvenli.kurum.local\r\n\r\n"
    encrypted_record = record_layer.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, http_request)
    decrypted_request = record_layer.process_record(encrypted_record)

    if not json_output:
        print(f"[+] Record Katmanı AEAD Şifreleme:")
        print(f"    - Şifreli Veri: {encrypted_record['ciphertext_hex'][:32]}...")
        print(f"    - Auth Tag: {encrypted_record['tag_hex']}")
        print(f"    - Çözülen Veri: {decrypted_request.decode('utf-8').strip()}")

    return {
        "protokol": server_hello["server_version"],
        "secilen_sifre": server_hello["cipher_suite"],
        "finished_verify_data": verify_data,
        "record_tag": encrypted_record["tag_hex"],
        "veri_iletildi": decrypted_request == http_request
    }

def run_flaw_demos(json_output: bool = False) -> Dict[str, Any]:
    """TLS güvenlik sınırları zafiyetlerini (CWE senaryoları) simüle eder."""
    flaw_results = {}
    if not json_output:
        print("\n" + "=" * 72)
        print("  TLS GÜVENLİK SINIRI VE ZAFİYET SALDIRI SENARYOLARI (CWE ANALİZİ)")
        print("=" * 72)

    # 1. Zafiyet: TLS_FALLBACK_SCSV ile Downgrade Saldırısının Engellenmesi (CWE-757)
    if not json_output:
        print("\n[!] 1. Test: TLS_FALLBACK_SCSV Downgrade Saldırısı (CWE-757)...")
    server = TLSHandshakeEngine(supported_versions=["TLSv1.3", "TLSv1.2"], allowed_ciphers=["TLS_AES_256_GCM_SHA384"])
    fake_client_hello = {
        "supported_versions": ["TLSv1.2"],
        "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_FALLBACK_SCSV"]
    }
    try:
        server.process_client_hello_and_reply(fake_client_hello)
        flaw_results["CWE-757_fallback_scsv"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except TLSDowngradeDetectedError as e:
        flaw_results["CWE-757_fallback_scsv"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 2. Zafiyet: Yasaklı Şifre Paketi Talebi (RC4 / DES) (CWE-327)
    if not json_output:
        print("\n[!] 2. Test: Kırılmış Şifre Paketi Talebi (RC4/DES) (CWE-327)...")
    weak_client_hello = {
        "supported_versions": ["TLSv1.2"],
        "cipher_suites": ["TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
    }
    try:
        server.process_client_hello_and_reply(weak_client_hello)
        flaw_results["CWE-327_insecure_ciphers"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except InsecureCipherSuiteError as e:
        flaw_results["CWE-327_insecure_ciphers"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 3. Zafiyet: Transkript Tahrifatı ve Finished Doğrulaması (CWE-353)
    if not json_output:
        print("\n[!] 3. Test: El Sıkışma Transkript Tahrifatı (CWE-353)...")
    trans_engine = TLSHandshakeEngine(["TLSv1.3"], ["TLS_AES_256_GCM_SHA384"])
    trans_engine.record_handshake_message("ClientHello", {"ciphers": ["TLS_AES_256_GCM_SHA384"]})
    try:
        # Saldırgan sahte finished sunuyor
        trans_engine.verify_finished_message(b"anahtar", "sahte_verify_data_00000000000000000000000000000000")
        flaw_results["CWE-353_transcript_tampering"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except HandshakeTranscriptIntegrityError as e:
        flaw_results["CWE-353_transcript_tampering"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 4. Zafiyet: Record AEAD Auth Tag Tahrifatı (BadRecordMAC) (CWE-353)
    if not json_output:
        print("\n[!] 4. Test: Record AEAD Auth Tag Tahrifatı (CWE-353)...")
    cipher = SimulatedAEADCipher(key=b"test_anahtar_32bayt_uzunlugunda!")
    rl = TLSRecordLayer(aead_cipher=cipher)
    rec = rl.create_record(TLSRecordLayer.CONTENT_TYPE_APPLICATION_DATA, b"Gizli Bankacilik Verisi")
    # Tag'i tahrif et
    rec["tag_hex"] = "ff" * 16
    try:
        rl.process_record(rec)
        flaw_results["CWE-353_bad_record_mac"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except BadRecordMACError as e:
        flaw_results["CWE-353_bad_record_mac"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    # 5. Zafiyet: 0-RTT Erken Veri Replay Saldırısı (CWE-294)
    if not json_output:
        print("\n[!] 5. Test: TLS 1.3 0-RTT Erken Veri Replay Saldırısı (CWE-294)...")
    cache = TLS13ZeroRTTAntiReplayCache()
    ticket = "ticket_finans_998877"
    cache.process_early_data(ticket, "TRANSFER 5000 TL")
    try:
        # Aynı isteği ikinci kez gönder (Replay)
        cache.process_early_data(ticket, "TRANSFER 5000 TL")
        flaw_results["CWE-294_0rtt_replay"] = "BAŞARISIZ (Zafiyet Yakalanamadı)"
    except ZeroRTTReplayDetectedError as e:
        flaw_results["CWE-294_0rtt_replay"] = "BAŞARILI (Engellendi: " + type(e).__name__ + ")"
        if not json_output:
            print(f"    -> Savunma Başarılı: {e}")

    return flaw_results

def main() -> None:
    """Komut satırı argümanlarını ayrıştırır ve ilgili fonksiyonları çağırır."""
    parser = argparse.ArgumentParser(
        description="TLS Güvenlik Sınırları ve Protokol Analiz Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--demo-handshake", action="store_true", help="Uçtan uca TLS 1.3 el sıkışmasını yürütür")
    parser.add_argument("--demo-flaws", action="store_true", help="TLS zafiyet ve downgrade saldırılarını çalıştırır")
    parser.add_argument("--json", action="store_true", help="Çıktıyı JSON formatında sunar")

    args = parser.parse_args()

    if not args.demo_handshake and not args.demo_flaws:
        args.demo_handshake = True
        args.demo_flaws = True

    if not args.json:
        print_banner()

    summary: Dict[str, Any] = {}

    if args.demo_handshake:
        summary["el_sikismasi"] = run_handshake_demo(json_output=args.json)

    if args.demo_flaws:
        summary["zafiyet_savunmalari"] = run_flaw_demos(json_output=args.json)

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("\n" + "=" * 72)
        print("  TÜM TLS GÜVENLİK SINIRI İŞLEMLERİ VE TESTLERİ BAŞARIYLA TAMAMLANDI")
        print("=" * 72)

if __name__ == "__main__":
    main()
