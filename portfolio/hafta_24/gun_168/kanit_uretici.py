# portfolio/hafta_24/gun_168/kanit_uretici.py
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

"""
Mini Proje 23: Güvenli Dosya Servisi Kanıt Üretici Scripti.
Tüm birim testleri, 9 negatif kontrol senaryosunu, CLI komutlarını ve mimari
diyagramları çalıştırarak kanıt dosyalarını eksiksiz olarak üretir.
"""

import os
import sys
import io
import json
import unittest
import tempfile
import shutil
import subprocess

# Gün dizini sys.path'e eklenir
gun_dir = os.path.dirname(os.path.abspath(__file__))
if gun_dir not in sys.path:
    sys.path.insert(0, gun_dir)

# Motor ve hata sınıfları içe aktarılır
from uygulama.secure_file_service_engine import SecureFileService, SecurityException
# Birim test sınıfı içe aktarılır
from tests.test_secure_file_service import TestSecureFileService


def main():
    """Kanıt üretim sürecini yöneten ana fonksiyon."""
    # Çalışma dizini scriptin bulunduğu klasör olarak sabitlenir
    base_dir = os.path.dirname(os.path.abspath(__file__))
    # Gerçek kanıt klasör yolu
    gercek_dir = os.path.join(base_dir, "kanit", "gercek")
    # Temsili kanıt klasör yolu
    temsili_dir = os.path.join(base_dir, "kanit", "temsili")
    # Örnek veri yolu
    ornek_veri_dir = os.path.join(base_dir, "ornek_veri")

    # Klasörlerin varlığı garanti edilir
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    print("[*] 1/5: Birim testler çalıştırılıyor ve test_sonuclari.txt üretiliyor...")
    # Test çıktısını yakalamak için tampon oluşturulur
    stream = io.StringIO()
    # Test paketi hazırlanır
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Test suite yüklenir
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSecureFileService)
    # Testler koşturulur
    result = runner.run(suite)
    # Test sonuç metni alınır
    test_output = stream.getvalue()

    # test_sonuclari.txt dosyasına yazılır
    with open(os.path.join(gercek_dir, "test_sonuclari.txt"), "w", encoding="utf-8") as f:
        f.write("=== MINI PROJE 23: GÜVENLI DOSYA SERVISI BIRIM TEST SONUÇLARI ===\n")
        f.write(f"Tarih: 2026-11-14\n")
        f.write(f"Koşulan Test: {result.testsRun}\n")
        f.write(f"Hata: {len(result.errors)}\n")
        f.write(f"Başarısızlık: {len(result.failures)}\n")
        f.write(f"Durum: {'100% BAŞARILI (PASS)' if result.wasSuccessful() else 'FAIL'}\n\n")
        f.write(test_output)

    print("[*] 2/5: Negatif kontrol senaryoları test ediliyor...")
    # Negatif senaryo dosyası okunur
    with open(os.path.join(ornek_veri_dir, "invalid_service_payloads.json"), "r", encoding="utf-8") as f:
        neg_data = json.load(f)

    # Geçici test depolama alanı oluşturulur
    temp_dir = tempfile.mkdtemp(prefix="kanit_test_storage_")
    service = SecureFileService(base_storage_dir=temp_dir, max_file_size=5 * 1024 * 1024)

    neg_results = []
    # Her senaryo test edilir
    for scn in neg_data["scenarios"]:
        scn_id = scn["id"]
        attack_type = scn["attack_type"]
        desc = scn["description"]
        expected_code = scn["expected_code"]

        defended = False
        caught_code = ""

        try:
            # Senaryoya göre işlem yapılır
            if "target_url" in scn:
                # SSRF senaryosu
                service.fetch_remote_file_safe(scn["target_url"], "attacker_user", "tenant_victim")
            else:
                # Dosya yükleme senaryosu
                raw_filename = scn["filename"]
                if "size_bytes" in scn:
                    content = bytes.fromhex(scn["content_hex"]) + (b"A" * (scn["size_bytes"] - len(scn["content_hex"])))
                else:
                    content = bytes.fromhex(scn["content_hex"])
                service.store_file(raw_filename, content, "attacker_user", "tenant_victim")

        except SecurityException as se:
            caught_code = se.code
            if caught_code == expected_code:
                defended = True

        neg_results.append({
            "scenario_id": scn_id,
            "attack_type": attack_type,
            "description": desc,
            "expected_code": expected_code,
            "caught_code": caught_code,
            "defended": defended
        })

    # Geçici klasör silinir
    shutil.rmtree(temp_dir, ignore_errors=True)

    # negatif_kontrol_sonuclari.txt kaydedilir
    with open(os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt"), "w", encoding="utf-8") as f:
        f.write("=== MINI PROJE 23: NEGATİF KONTROL VE SALDIRI SAVUNMA RAPORU ===\n")
        f.write("Tarih: 2026-11-14\n")
        f.write(f"Toplam Senaryo: {len(neg_results)}\n")
        success_count = sum(1 for r in neg_results if r["defended"])
        f.write(f"Başarıyla Savunulan: {success_count}/{len(neg_results)}\n")
        f.write(f"Başarı Oranı: %{(success_count / len(neg_results)) * 100:.1f}\n\n")
        f.write(f"{'SENARYO ID':<15} | {'SALDIRI TÜRÜ':<26} | {'BEKLENEN KOD':<26} | {'ALINAN KOD':<26} | {'DURUM'}\n")
        f.write("-" * 115 + "\n")
        for r in neg_results:
            status_str = "SAVUNULDU (PASS)" if r["defended"] else "BAŞARISIZ (FAIL)"
            f.write(f"{r['scenario_id']:<15} | {r['attack_type']:<26} | {r['expected_code']:<26} | {r['caught_code']:<26} | {status_str}\n")

    print("[*] 3/5: file_service_audit_report.json ve sanitized_service_transactions.txt üretiliyor...")
    # Yeni bir servis instance ile simüle edilmiş işlemler ve audit log üretilir
    audit_temp = tempfile.mkdtemp(prefix="audit_demo_")
    audit_service = SecureFileService(base_storage_dir=audit_temp)

    # 1. Meşru PDF yükleme
    m1 = audit_service.store_file("annual_report_2026.pdf", b"%PDF-1.4\nKurumsal Rapor\n%%EOF", "cfo_user", "tenant_finance")
    # 2. Meşru PNG yükleme
    m2 = audit_service.store_file("architecture.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "dev_lead", "tenant_engineering")
    # 3. Traversal saldırı denemesi (Engellenen)
    try:
        audit_service.store_file("../../etc/shadow.pdf", b"%PDF-1.4\nData\n%%EOF", "hacker", "tenant_engineering")
    except SecurityException:
        pass
    # 4. Webshell saldırı denemesi (Engellenen)
    try:
        audit_service.store_file("shell.pdf", b"%PDF-1.4\n<?php eval($_POST['x']); ?>\n%%EOF", "hacker", "tenant_engineering")
    except SecurityException:
        pass
    # 5. Çapraz kiracı indirme denemesi (Engellenen - BOLA)
    try:
        audit_service.retrieve_file(m1.file_id, "dev_lead", "tenant_engineering", "user")
    except SecurityException:
        pass
    # 6. Yetkili indirme (Başarılı)
    audit_service.retrieve_file(m1.file_id, "cfo_user", "tenant_finance", "user")

    # Audit JSON çıktısı
    audit_summary = audit_service.get_audit_summary()
    with open(os.path.join(gercek_dir, "file_service_audit_report.json"), "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2, ensure_ascii=False)

    # sanitized_service_transactions.txt çıktısı
    with open(os.path.join(gercek_dir, "sanitized_service_transactions.txt"), "w", encoding="utf-8") as f:
        f.write("=== GÜVENLİ DOSYA SERVİSİ İŞLEM VE ERİŞİM GÜNLÜĞÜ (ARINDIRILMIŞ) ===\n")
        f.write("Tarih: 2026-11-14 | Gizlilik: Maskelenmiş Kurumsal İşlem Kayıtları\n\n")
        for evt in audit_summary["events"]:
            f.write(f"[{evt['timestamp']}] ACTION={evt['action']:<25} TENANT={evt['tenant_id']:<18} USER={evt['user_id']:<12} STATUS={evt['status']}\n")
            f.write(f"    Detay: {json.dumps(evt['details'], ensure_ascii=False)}\n\n")

    shutil.rmtree(audit_temp, ignore_errors=True)

    print("[*] 4/5: CLI komutları çalıştırılıyor ve komut_ve_cikis.txt üretiliyor...")
    # CLI komutları çalıştırılır
    cli_path = os.path.join(base_dir, "uygulama", "secure_file_service_cli.py")
    cmds = [
        [sys.executable, cli_path, "--help"],
        [sys.executable, cli_path, "scan", "--filename", "safe_contract.pdf", "--content", "%PDF-1.4 Test"],
        [sys.executable, cli_path, "scan", "--filename", "../../../etc/passwd.pdf", "--content", "%PDF-1.4 Test"],
        [sys.executable, cli_path, "upload", "--filename", "q3_results.pdf", "--content", "%PDF-1.4 Financials %%EOF", "--user-id", "auditor_9", "--tenant-id", "audit_corp"],
        [sys.executable, cli_path, "fetch-remote", "--url", "http://169.254.169.254/latest/meta-data/"],
        [sys.executable, cli_path, "audit-report"]
    ]

    with open(os.path.join(gercek_dir, "komut_ve_cikis.txt"), "w", encoding="utf-8") as f:
        f.write("=== GÜVENLİ DOSYA SERVİSİ CLI ÇALIŞTIRMA VE KONSOL GÜNLÜĞÜ ===\n\n")
        for cmd in cmds:
            cmd_str = " ".join(cmd)
            f.write(f"$ {cmd_str}\n")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=base_dir)
            if proc.stdout:
                f.write(proc.stdout)
            if proc.stderr:
                f.write(proc.stderr)
            f.write(f"\n[Çıkış Kodu: {proc.returncode}]\n")
            f.write("=" * 80 + "\n\n")

    print("[*] 5/5: Temsili mimari diyagramı üretiliyor...")
    diagram_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

+-------------------------------------------------------------------------------+
|       MINI PROJE 23: GÜVENLİ DOSYA SERVİSİ VE İNDİRME AĞ GEÇİDİ MİMARİSİ      |
+-------------------------------------------------------------------------------+

                       +-----------------------------+
                       |    İSTEMCİ / TARAYICI       |
                       | (Kullanıcı / Saldırgan)     |
                       +--------------+--------------+
                                      |
                     [HTTP POST Yükleme / GET İndirme]
                                      v
  =================== 1. GÜVENLİK VE GİRİŞ DOĞRULAMA HATTI ===================
  |  [Dosya Adı Temizleme]  --> Null Byte (%00) ve URL Kodlama Çözümleme       |
  |                             (Multi-Pass Unquote: %252e%252e%252f -> ../)   |
  |  [Traversal Kontrolü]   --> ".." ve Eğik Çizgi Engeli (CWE-22)             |
  |  [Uzantı Beyaz Listesi] --> Yalnızca .pdf, .png, .jpg, .docx, .txt         |
  |  [Çift Uzantı Kalkanı]  --> invoice.pdf.php tespit ve derhal 403 ret       |
  |  [Boyut Kotası]         --> Max 5 MB Sınırı                                |
  ====================================+=========================================
                                      |
                                      v
  =================== 2. İÇERİK VE İMZA DERİN DENETİMİ =======================
  |  [Magic Bytes Doğrulama]--> %PDF-, \x89PNG, \xff\xd8\xff Kontrolü          |
  |  [Antivirüs & Webshell] --> <?php, eval(), system(), <script> Taraması    |
  |  [SSRF Güvenli Getirme] --> Remote URL DNS & IP Filtresi                   |
  |                             (127.0.0.1, 169.254.169.254 engeli)           |
  ====================================+=========================================
                                      |
                                      v
  =================== 3. İNDİREKT NESNE REFERANSI & İZOLASYON ==================
  |  [UUIDv4 Atama]         --> Orijinal dosya adı yerine UUID.dat saklanır    |
  |  [Kanonik Jail]         --> os.path.realpath & commonpath kontrolü        |
  |  [Tenant İzolasyonu]    --> /storage/tenants/<tenant_id>/<UUID>.dat        |
  |  [BOLA / IDOR Savunması]--> Çapraz kurum ve yetkisiz kullanıcı engeli      |
  ====================================+=========================================
                                      |
                                      v
  =================== 4. GÜVENLİ İNDİRME AĞ GEÇİDİ (HTTP HEADERS) ==============
  |  Content-Disposition: attachment; filename="sanitized_name.pdf"            |
  |  X-Content-Type-Options: nosniff  (MIME sniffing XSS engeli)               |
  |  Content-Security-Policy: default-src 'none'; sandbox                      |
  |  Cache-Control: no-store, no-cache, must-revalidate                        |
  +----------------------------------------------------------------------------+

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(os.path.join(temsili_dir, "guvenli_dosya_servisi_mimarisi.txt"), "w", encoding="utf-8") as f:
        f.write(diagram_content)

    print("[+] TÜM KANITLAR EKSİKSİZ VE BAŞARIYLA ÜRETİLDİ!")


if __name__ == "__main__":
    main()
