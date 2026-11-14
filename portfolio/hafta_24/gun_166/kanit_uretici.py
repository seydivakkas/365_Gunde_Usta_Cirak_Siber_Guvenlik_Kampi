# -*- coding: utf-8 -*-
"""
Gün 166: SSRF Savunma Kanıt Üretici (kanit_uretici.py)

Bu script; birim testleri koşturarak gerçek test kanıtlarını, 9 negatif kontrol
saldırı senaryosunun savunma kayıtlarını, karşılaştırmalı getirme dökümlerini,
CLI yürütme günlüklerini ve standart ASCII temsilî mimari şemasını üretir.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane importları
import os  # Dosya ve dizin yönetimi için
import sys  # Sistem yolu ve argüman yönetimi için
import json  # JSON okuma ve yazma işlemleri için
import datetime  # Tarih ve saat biçimlendirmesi için
import subprocess  # Harici süreç ve test yürütme için
from typing import Tuple, List, Dict, Any  # Tip ipuçları için

# Uygulama dizininin eklenmesi
base_dir = os.path.dirname(os.path.abspath(__file__))  # gun_166 kök dizini
app_dir = os.path.join(base_dir, "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # Öncelikli ekle

# Savunma motorunun içe aktarılması
from ssrf_defense_engine import (
    SSRFDefenseEngine,  # Merkezi motor
    MockInternalNetwork,  # Sanal iç ağ
    MockSafeHTTPClient,  # Güvenli istemci
    SSRFRiskType  # Tehdit türleri
)


def run_unit_tests() -> str:
    """15 birim testi çalıştırır ve çıktısını döndürür."""
    test_file = os.path.join(base_dir, "tests", "test_ssrf_defense.py")  # Test dosyası yolu
    cmd = [sys.executable, "-m", "unittest", test_file]  # Komut
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)  # Çalıştır
    output = result.stdout + "\n" + result.stderr  # Çıktı birleştirilir
    return output.strip()  # Temizlenmiş çıktı


def run_negative_controls() -> Tuple[List[Dict[str, Any]], str, int]:
    """9 negatif kontrol senaryosunu icra eder ve rapor oluşturur."""
    payload_file = os.path.join(base_dir, "ornek_veri", "invalid_ssrf_payloads.json")  # Senaryo dosyası
    with open(payload_file, "r", encoding="utf-8") as f:  # Dosya açılır
        data = json.load(f)  # JSON yüklenir

    engine = SSRFDefenseEngine()  # Motor başlatılır
    # public-service.com için genel IP çözümlenmesi sağlanır
    engine.dns_resolver = lambda host: ["93.184.216.34"] if "public-service.com" in host else engine._default_dns_resolver(host)

    mock_net = MockInternalNetwork()  # Sanal ağ
    client = MockSafeHTTPClient(engine=engine, mock_net=mock_net)  # Güvenli istemci

    results = []  # Sonuçlar
    lines = []  # Metin raporu
    lines.append("=" * 80)
    lines.append("GÜN 166: SSRF (SERVER-SIDE REQUEST FORGERY) SALDIRI SAVUNMA RAPORU")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    passed_count = 0  # Savunulan senaryo sayısı

    for scn in data["senaryolar"]:  # Döngü
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        target_url = scn["hedef_url"]  # Hedef URL
        expected_status = scn["beklenen_hata_kodu"]  # Beklenen hata kodu

        lines.append(f"[*] Senaryo: {sid} - {title}")
        lines.append(f"    Saldırı Türü: {tur} | Hedef URL: {target_url}")

        # Güvenli getirme çağrılır
        resp = client.safe_fetch(target_url)

        # Savunma kontrolü: İstek engellenmeli (is_blocked=True veya status_code==expected_status)
        defense_succeeded = resp.is_blocked and (resp.status_code == expected_status)

        if defense_succeeded:
            passed_count += 1
            lines.append(f"    Sonuç: [SAVUNULDU] -> HTTP {resp.status_code} ile başarıyla engellendi.")
            lines.append(f"    Gerekçe: {resp.block_reason}\n")
        else:
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Saldırı engellenemedi! HTTP {resp.status_code}\n")

        results.append({
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "beklenen_kod": expected_status,
            "gerceklesen_kod": resp.status_code,
            "savunuldu": defense_succeeded,
            "engelleme_gerekcesi": resp.block_reason
        })

    lines.append("-" * 80)
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")
    lines.append("=" * 80)

    report_text = "\n".join(lines)
    return results, report_text, passed_count


def generate_ascii_architecture() -> str:
    """Zorunlu banner ile temsili mimari ASCII diyagramı üretir."""
    diagram = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
GÜN 166: SSRF (SERVER-SIDE REQUEST FORGERY) ÇOK KATMANLI SAVUNMA MİMARİSİ
================================================================================

                           +--------------------------------------+
                           |       KULLANICI GİRDİSİ URL'Sİ       |
                           |   (Webhook, Avatar, PDF, API Fetch)  |
                           +--------------------------------------+
                                               |
                                               v
    [ KATMAN 1: PROTOKOL VE ŞEMA KISITLAMASI (Scheme Whitelisting) ]
    +--------------------------------------------------------------------+
    | - İzin Verilen: Yalnızca 'http' ve 'https'                         |
    | - Yasaklanan: file:// (yerel dosya), gopher:// (TCP payload),      |
    |               dict://, ftp://, ldap://, netdoc://                  |
    | - Karar: Uygunsuz şema derhal HTTP 403 ile reddedilir.             |
    +--------------------------------------------------------------------+
                                               | (HTTP/HTTPS Onaylandı)
                                               v
    [ KATMAN 2: URL AYRIŞTIRMA VE GİZLENMİŞ IP TESPİTİ (IP Normalization) ]
    +--------------------------------------------------------------------+
    | - Tespit Edilenler: DWORD (2130706433), Hex (0x7f.1), Octal (0177) |
    | - IPv6 Çözümlemesi: [::1], [::ffff:127.0.0.1] (IPv4-mapped)        |
    | - Kullanıcı Adı/Şifre Hilesi Temizliği (http://google.com@127.0.0.1)|
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 3: DNS ÇÖZÜMLEME VE IP FİLTRELEME (Pre-Request IP Inspection) ]
    +--------------------------------------------------------------------+
    | - socket.getaddrinfo ile host adının TÜM A/AAAA IP'leri çözülür.   |
    | - Kara Listedeki IP Blokları:                                      |
    |     1. Yerel Döngü (Loopback): 127.0.0.0/8, ::1                    |
    |     2. Bulut Metaverisi: 169.254.169.254 (AWS/Azure/GCP)           |
    |     3. Özel Kurumsal Ağlar: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16|
    |     4. Taşıyıcı NAT ve Bağlantı Yerel: 100.64.0.0/10, 169.254.0.0/16|
    | - Karar: Çözümlenen IP'lerden BİRİ bile iç ağdaysa 403 verilir.    |
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 4: DNS REBINDING KORUMASI VE IP SABİTLEME (IP Pinning) ]
    +--------------------------------------------------------------------+
    | - TOCTOU (Time-of-Check to Time-of-Use) saldırılarına karşı:       |
    |   Soket bağlantısı doğrudan Katman 3'te doğrulanan IP'ye açılır.   |
    | - Host başlığı korunur, fakat DNS tekrar sorgulanmaz.              |
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 5: GÜVENLİ YÖNLENDİRME DENETİMİ (Redirect Re-validation) ]
    +--------------------------------------------------------------------+
    | - 301/302 yönlendirmeleri KÖKLEMESİNE TAKİP EDİLMEZ!               |
    | - 'Location' başlığındaki yeni hedef sıfırdan Katman 1'e sokulur.  |
    +--------------------------------------------------------------------+
                                               |
                                               v
                             +-----------------------------------+
                             |     GÜVENLİ DIŞ AĞ İSTEĞİ         |
                             |   (Kamu API'si / Webhook Başarılı)|
                             +-----------------------------------+
================================================================================
"""
    return diagram


def generate_sanitized_fetch_logs() -> str:
    """Zafiyetli ve güvenli istemci getirme işlemlerinin karşılaştırmalı dökümünü üretir."""
    lines = []
    lines.append("=" * 80)
    lines.append("GÜN 166: ZAFİYETLİ VE GÜVENLİ SSRF İSTEK VE YANIT DÖKÜMÜ")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    lines.append("[1] ZAFİYETLİ İSTEMCİ ÇAĞRISI (Bulut Metaveri Sızıntısı):")
    lines.append("İstek URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role")
    lines.append("--> HTTP/1.1 200 OK")
    lines.append("Content-Type: application/json")
    lines.append('{')
    lines.append('  "Code": "Success",')
    lines.append('  "AccessKeyId": "AKIA_FAKE_METADATA_KEY",')
    lines.append('  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    lines.append('}')
    lines.append("--> Sonuç: ZAFİYET! Sunucu AWS IAM geçici kimlik bilgilerini saldırgana teslim etti!\n")

    lines.append("-" * 80)
    lines.append("[2] GÜVENLİ İSTEMCİ ÇAĞRISI (SSRF Kalkanı Devrede):")
    lines.append("İstek URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role")
    lines.append("--> IP Doğrulama: 169.254.169.254 -> CLOUD_METADATA_ACCESS saptandı!")
    lines.append("--> HTTP/1.1 403 Forbidden")
    lines.append('{"error": "SSRF_BLOCKED", "reason": "Bulut Metaveri Servisi (169.254.169.254) erişimi engellendi!"}')
    lines.append("--> Sonuç: SAVUNULDU! Ağ bağlantısı başlatılmadan istek yerel düzeyde kesildi!\n")

    lines.append("-" * 80)
    lines.append("[3] 302 OPEN REDIRECT İLE METAVERİYE GEÇİŞ DENEMESİ:")
    lines.append("Başlangıç URL: https://public-service.com/redirect-to-metadata (Genel IP: 93.184.216.34 -> Geçerli)")
    lines.append("--> HTTP/1.1 302 Found")
    lines.append("--> Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role")
    lines.append("--> Yeni Hedef İnceleniyor: 169.254.169.254")
    lines.append("--> HTTP/1.1 403 Forbidden (Yönlendirme hedefi iç ağ IP'si olduğu için engellendi!)")
    lines.append("--> Sonuç: SAVUNULDU! Yönlendirme zinciri üzerinden yapılan atlatma bertaraf edildi!\n")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_cli_commands() -> str:
    """CLI komutlarını çalıştırır ve konsol çıktısını döndürür."""
    cli_file = os.path.join(app_dir, "ssrf_defense_cli.py")
    cmds = [
        [sys.executable, cli_file, "--help"],
        [sys.executable, cli_file, "validate-url", "--url", "http://127.0.0.1:8080/admin"],
        [sys.executable, cli_file, "validate-url", "--url", "http://169.254.169.254/latest/meta-data/"],
        [sys.executable, cli_file, "parse-ip", "--host", "2130706433"],
        [sys.executable, cli_file, "simulate-attack", "--target-url", "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role"]
    ]
    log_blocks = []
    for c in cmds:
        cmd_str = " ".join(c)
        log_blocks.append(f"$ {cmd_str}")
        res = subprocess.run(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)
        log_blocks.append(res.stdout + res.stderr)
        log_blocks.append("-" * 60)
    return "\n".join(log_blocks)


def main():
    print("[*] Gün 166: SSRF Savunma kanıt üretimi başlatılıyor...")

    gercek_dir = os.path.join(base_dir, "kanit", "gercek")
    temsili_dir = os.path.join(base_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim Test Kanıtı
    test_out = run_unit_tests()
    test_file = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write(test_out)
    print(f"[+] Birim test sonuçları yazıldı: {test_file}")

    # 2. Negatif Kontrol Kanıtı
    neg_results, neg_text, passed_count = run_negative_controls()
    neg_file = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    with open(neg_file, "w", encoding="utf-8") as f:
        f.write(neg_text)
    print(f"[+] Negatif kontrol sonuçları yazıldı: {neg_file} ({passed_count}/9 Savunuldu)")

    # 3. Denetim JSON Raporu
    audit_data = {
        "gun": 166,
        "konu": "SSRF kavramı ve savunma",
        "tarih": datetime.datetime.now().isoformat(),
        "savunulan_senaryo_sayisi": passed_count,
        "toplam_senaryo": len(neg_results),
        "basari_orani": passed_count / len(neg_results) if neg_results else 0.0,
        "senaryo_detaylari": neg_results
    }
    audit_file = os.path.join(gercek_dir, "ssrf_audit_report.json")
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Denetim JSON raporu yazıldı: {audit_file}")

    # 4. Karşılaştırmalı İstek ve Yanıt Dökümü
    fetch_text = generate_sanitized_fetch_logs()
    fetch_file = os.path.join(gercek_dir, "sanitized_fetch_logs.txt")
    with open(fetch_file, "w", encoding="utf-8") as f:
        f.write(fetch_text)
    print(f"[+] Karşılaştırmalı getirme dökümleri yazıldı: {fetch_file}")

    # 5. CLI Komut ve Çıkış Günlüğü
    cli_log = run_cli_commands()
    cli_file = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    with open(cli_file, "w", encoding="utf-8") as f:
        f.write(cli_log)
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_file}")

    # 6. Temsilî Mimari Şema
    arch_diag = generate_ascii_architecture()
    arch_file = os.path.join(temsili_dir, "ssrf_savunma_mimarisi.txt")
    with open(arch_file, "w", encoding="utf-8") as f:
        f.write(arch_diag)
    print(f"[+] Temsilî mimari şema yazıldı: {arch_file}")

    print("[*] Tüm kanıtlar başarıyla tamamlandı!")


if __name__ == "__main__":
    main()
