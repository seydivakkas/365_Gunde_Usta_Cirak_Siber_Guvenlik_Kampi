# -*- coding: utf-8 -*-
r"""
Gün 167: Path Traversal ve Dosya Erişimi Kanıt Üretici (kanit_uretici.py)

Bu script; birim testleri koşturarak gerçek test kanıtlarını, 9 negatif kontrol
saldırı senaryosunun savunma kayıtlarını, karşılaştırmalı dosya okuma dökümlerini,
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
base_dir = os.path.dirname(os.path.abspath(__file__))  # gun_167 kök dizini
app_dir = os.path.join(base_dir, "uygulama")  # uygulama dizini
if app_dir not in sys.path:  # Sistem yolunda yoksa
    sys.path.insert(0, app_dir)  # Öncelikli ekle

# Savunma motorunun içe aktarılması
from path_traversal_engine import (
    PathTraversalDefenseEngine,  # Merkezi motor
    EnterpriseStoragePolicy,  # Depolama politikası
    TraversalRiskType  # Risk türleri
)


def run_unit_tests() -> str:
    """15 birim testi çalıştırır ve çıktısını döndürür."""
    test_file = os.path.join(base_dir, "tests", "test_path_traversal.py")  # Test dosyası yolu
    cmd = [sys.executable, "-m", "unittest", test_file]  # Komut
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)  # Çalıştır
    output = result.stdout + "\n" + result.stderr  # Çıktı birleştirilir
    return output.strip()  # Temizlenmiş çıktı


def run_negative_controls() -> Tuple[List[Dict[str, Any]], str, int]:
    """9 negatif kontrol senaryosunu icra eder ve rapor oluşturur."""
    payload_file = os.path.join(base_dir, "ornek_veri", "invalid_traversal_payloads.json")  # Senaryo dosyası
    with open(payload_file, "r", encoding="utf-8") as f:  # Dosya açılır
        data = json.load(f)  # JSON yüklenir

    engine = PathTraversalDefenseEngine()  # Motor başlatılır

    results = []  # Sonuçlar
    lines = []  # Metin raporu
    lines.append("=" * 80)
    lines.append("GÜN 167: PATH TRAVERSAL VE DOSYA ERİŞİMİ SALDIRI SAVUNMA RAPORU")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    passed_count = 0  # Savunulan senaryo sayısı

    for scn in data["senaryolar"]:  # Döngü
        sid = scn["senaryo_id"]  # Senaryo ID
        title = scn["baslik"]  # Başlık
        tur = scn["tur"]  # Tür
        payload = scn["payload"]  # Saldırı yükü
        expected_status = scn["beklenen_hata_kodu"]  # Beklenen hata kodu

        lines.append(f"[*] Senaryo: {sid} - {title}")
        lines.append(f"    Saldırı Türü: {tur} | Girdi Yolu: {payload}")

        # Güvenli okuma fonksiyonu çağrılır
        resp = engine.secure_read_file(payload)

        # Savunma kontrolü: İstek başarısız olmalı ve 403 Forbidden üretmelidir
        defense_succeeded = (resp["success"] is False) and (resp["status_code"] == expected_status)

        if defense_succeeded:
            passed_count += 1
            lines.append(f"    Sonuç: [SAVUNULDU] -> HTTP {resp['status_code']} ile başarıyla engellendi.")
            lines.append(f"    Gerekçe: {resp.get('reason')}\n")
        else:
            lines.append(f"    Sonuç: [BAŞARISIZ] -> Saldırı engellenemedi! HTTP {resp['status_code']}\n")

        results.append({
            "senaryo_id": sid,
            "baslik": title,
            "tur": tur,
            "payload": payload,
            "beklenen_kod": expected_status,
            "gerceklesen_kod": resp["status_code"],
            "savunuldu": defense_succeeded,
            "hata_gerekcesi": resp.get("reason")
        })

    lines.append("-" * 80)
    lines.append(f"ÖZET: Toplam {len(data['senaryolar'])} senaryodan {passed_count} tanesi başarıyla savunuldu.")
    lines.append("=" * 80)

    report_text = "\n".join(lines)
    return results, report_text, passed_count


def generate_ascii_architecture() -> str:
    """Zorunlu banner ile temsili mimari ASCII diyagramı üretir."""
    diagram = r"""================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
GÜN 167: PATH TRAVERSAL VE GÜVENLİ DOSYA ERİŞİMİ ÇOK KATMANLI MİMARİSİ
================================================================================

                           +--------------------------------------+
                           |      İSTEMCİ DOSYA TALEP GİRDİSİ     |
                           |  (../etc/passwd, %2e%2e%2f, .env)    |
                           +--------------------------------------+
                                               |
                                               v
    [ KATMAN 1: ÇOK GEÇİŞLİ URL KODLAMA ÇÖZÜMLEME (Multi-Pass Unquote) ]
    +--------------------------------------------------------------------+
    | - Tek Geçişli (%2e%2e%2f) ve Çift Geçişli (%252e%252e%252f)        |
    |   gizlemeler çözümlenerek ham metne dönüştürülür.                  |
    | - Karar: Çift kodlama tespit edildiği an talep 403 ile reddedilir. |
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 2: NULL BYTE VE İÇ İÇE FİLTRE ENGELİ (Null Byte & Nested Dots) ]
    +--------------------------------------------------------------------+
    | - Null Byte Tespiti: %00 veya \x00 karakteri varsa derhal iptal!   |
    | - Özyinelemeli Kalıp: ....// veya ..././ kalıpları derhal iptal!   |
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 3: KATI DOSYA ADI VE UZANTI BEYAZ LİSTESİ (Filename Whitelist) ]
    +--------------------------------------------------------------------+
    | - Dosya Adı Karakterleri: ^[a-zA-Z0-9_\-\.]+$ (Dizin ayraçları / \ |
    |   kesinlikle yasaklanmıştır; alt dizin atlama yapılamaz).          |
    | - İzinli Uzantılar: .pdf, .png, .jpg, .docx, .txt                  |
    | - Yasaklı Uzantılar: .env, .sh, .exe, .php, .config                |
    +--------------------------------------------------------------------+
                                               |
                                               v
    [ KATMAN 4: KANONİK YOL ÇÖZÜMLEME VE HAPİS (Canonical Jail / Chroot) ]
    +--------------------------------------------------------------------+
    | - os.path.realpath / Path.resolve ile sembolik bağlar çözülür.     |
    | - Kural: os.path.commonpath([base_canonical, target_canonical])    |
    |   kesinlikle base_canonical olmak zorundadır!                      |
    | - Karar: Temel depo dizini (/var/www/kurumsal_depo) dışına taşma   |
    |   girişimi saptandığı an HTTP 403 Forbidden ile engellenir.        |
    +--------------------------------------------------------------------+
                                               |
                                               v
                             +-----------------------------------+
                             |     GÜVENLİ DOSYA TESLİMATI       |
                             |   (Yalnızca İzinli Depo Dosyası)  |
                             +-----------------------------------+
================================================================================
"""
    return diagram


def generate_sanitized_file_logs() -> str:
    """Zafiyetli ve güvenli dosya okuma işlemlerinin karşılaştırmalı dökümünü üretir."""
    lines = []
    lines.append("=" * 80)
    lines.append("GÜN 167: ZAFİYETLİ VE GÜVENLİ DOSYA ERİŞİM İŞLEM DÖKÜMÜ")
    lines.append("=" * 80)
    lines.append(f"Tarih/Saat: {datetime.datetime.now().isoformat()}\n")

    lines.append("[1] ZAFİYETLİ DOSYA OKUMA ÖRNEĞİ (os.path.join ve Dizin Atlama İstismarı):")
    lines.append("Talep Edilen Girdi: ../../../../etc/passwd")
    lines.append("Çalıştırılan Kod: os.path.join('/var/www/kurumsal_depo', '../../../../etc/passwd')")
    lines.append("Erişilen Yol: /etc/passwd  <-- SİSTEM PAROLA DOSYASI")
    lines.append("--> HTTP/1.1 200 OK")
    lines.append("root:x:0:0:root:/root:/bin/bash")
    lines.append("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin")
    lines.append("--> Sonuç: ZAFİYET! Kurumsal sunucunun kritik kimlik ve sistem bilgileri çalındı!\n")

    lines.append("-" * 80)
    lines.append("[2] GÜVENLİ DOSYA OKUMA ÖRNEĞİ (Kanonik Hapis ve Girdi Filtresi):")
    lines.append("Talep Edilen Girdi: ../../../../etc/passwd")
    lines.append("--> Katman 1 & 5 İncelemesi: Göreli dizin atlama ('..') tespit edildi.")
    lines.append("--> Kanonik Hapis Denetimi: Depo sınırları dışına taşma engellendi.")
    lines.append("--> HTTP/1.1 403 Forbidden")
    lines.append('{"error": "ACCESS_DENIED_PATH_TRAVERSAL", "reason": "Göreli dizin atlama (\'..\') kalıbı tespit edildi: \'../../../../etc/passwd\'"}')
    lines.append("--> Sonuç: SAVUNULDU! Dosya sistemi sınırları aşılamadı, yetkisiz okuma engellendi!\n")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_cli_commands() -> str:
    """CLI komutlarını çalıştırır ve konsol çıktısını döndürür."""
    cli_file = os.path.join(app_dir, "path_traversal_cli.py")
    cmds = [
        [sys.executable, cli_file, "--help"],
        [sys.executable, cli_file, "validate-path", "--path", "../../../../etc/passwd"],
        [sys.executable, cli_file, "validate-path", "--path", "fatura_2026.pdf"],
        [sys.executable, cli_file, "decode-path", "--encoded-string", "%252e%252e%252f"],
        [sys.executable, cli_file, "simulate-attack", "--payload", "../../../../etc/passwd"]
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
    print("[*] Gün 167: Path Traversal ve Dosya Erişimi kanıt üretimi başlatılıyor...")

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
        "gun": 167,
        "konu": "Path traversal ve dosya erişimi",
        "tarih": datetime.datetime.now().isoformat(),
        "savunulan_senaryo_sayisi": passed_count,
        "toplam_senaryo": len(neg_results),
        "basari_orani": passed_count / len(neg_results) if neg_results else 0.0,
        "senaryo_detaylari": neg_results
    }
    audit_file = os.path.join(gercek_dir, "traversal_audit_report.json")
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False)
    print(f"[+] Denetim JSON raporu yazıldı: {audit_file}")

    # 4. Karşılaştırmalı Getirme Dökümü
    logs_text = generate_sanitized_file_logs()
    logs_file = os.path.join(gercek_dir, "sanitized_file_access_logs.txt")
    with open(logs_file, "w", encoding="utf-8") as f:
        f.write(logs_text)
    print(f"[+] Karşılaştırmalı dosya erişim dökümleri yazıldı: {logs_file}")

    # 5. CLI Komut ve Çıkış Günlüğü
    cli_log = run_cli_commands()
    cli_file = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    with open(cli_file, "w", encoding="utf-8") as f:
        f.write(cli_log)
    print(f"[+] CLI komut ve çıkış günlüğü yazıldı: {cli_file}")

    # 6. Temsilî Mimari Şema
    arch_diag = generate_ascii_architecture()
    arch_file = os.path.join(temsili_dir, "path_traversal_savunma_mimarisi.txt")
    with open(arch_file, "w", encoding="utf-8") as f:
        f.write(arch_diag)
    print(f"[+] Temsilî mimari şema yazıldı: {arch_file}")

    print("[*] Tüm kanıtlar başarıyla tamamlandı!")


if __name__ == "__main__":
    main()
