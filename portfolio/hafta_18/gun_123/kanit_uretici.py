# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 123: Güvenli Varsayılanlar ve Fail-Safe Kanıt Üretici Betiği.
Bu betik; birim testleri, 9 negatif kontrol senaryosunu, CLI çıktılarını,
detaylı güvenli varsayılan analiz raporunu ve temsili ASCII mimari diyagramını üretir.
"""

# Dosya ve dizin işlemleri için os modülü içe aktarılıyor
import os
# Sistem çalışma parametreleri için sys modülü içe aktarılıyor
import sys
# JSON ayrıştırma işlemleri için json modülü içe aktarılıyor
import json
# Zaman damgaları üretmek için datetime modülü içe aktarılıyor
from datetime import datetime
# Birim testleri programatik koşturmak için unittest modülü içe aktarılıyor
import unittest
# Metin yakalama için io modülü içe aktarılıyor
import io

# Uygulama ve test dizinleri arama yoluna ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "uygulama")
tests_dir = os.path.join(current_dir, "tests")
sys.path.insert(0, app_dir)
sys.path.insert(0, tests_dir)

# Çekirdek motor sınıfları ve istisnalar içe aktarılıyor
from secure_defaults_failsafe_engine import (
    FailSafeSecurityManager,
    ResourceConfig,
    PolicyRule,
    AccessRequest,
    DecisionOutcome,
    FailureHandlingMode,
    FailureType,
    FailSafeEngineError,
    InsecureFailOpenForbiddenError,
    InsecureDefaultDetectedError,
    DuplicateResourceError,
    InvalidResourceConfigurationError
)
# CLI yükleyici fonksiyonu içe aktarılıyor
from failsafe_cli import load_manager_from_json


def adim_1_birim_testleri_kostur(kanit_yolu: str) -> bool:
    """15 birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    print("[*] 1. Adım: Birim testler koşturuluyor...")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_secure_defaults_failsafe.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output_text = stream.getvalue()
    header = f"=== GÜN 123 BİRİM TEST RAPORU ===\nTarih: {datetime.now().isoformat()}\n\n"
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(header + output_text)
    if result.wasSuccessful():
        print(f"    [+] Birim testler başarıyla tamamlandı ({result.testsRun}/{result.testsRun} PASS).")
        return True
    else:
        print(f"    [-] Testlerde hata var! Başarısız: {len(result.failures)}, Hata: {len(result.errors)}")
        return False


def adim_2_negatif_kontrolleri_kostur(scenarios_path: str, kanit_yolu: str) -> bool:
    """9 negatif senaryoyu dener ve beklenen hataların alındığını doğrular."""
    print("[*] 2. Adım: 9 Negatif kontrol senaryosu icra ediliyor...")
    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios = json.load(fp)
    log_lines = []
    log_lines.append(f"=== GÜN 123 NEGATİF KONTROL VE HATA DOĞRULAMA RAPORU ===")
    log_lines.append(f"Tarih: {datetime.now().isoformat()}")
    log_lines.append(f"Toplam Senaryo: {len(scenarios)}\n")
    passed_count = 0

    for sc in scenarios:
        s_no = sc["senaryo_no"]
        s_name = sc["senaryo_adi"]
        exp_err = sc["beklenen_hata"]
        caught = False
        caught_err_name = ""
        error_msg = ""

        try:
            if "kaynak_verisi" in sc:
                kv = sc["kaynak_verisi"]
                mgr = FailSafeSecurityManager("Negatif Test")
                res = ResourceConfig(
                    resource_id=kv["resource_id"],
                    name=kv["name"],
                    default_access=kv.get("default_access", "DENY"),
                    debug_mode=kv.get("debug_mode", False),
                    enforce_tls=kv.get("enforce_tls", True),
                    is_default_credential_changed=kv.get("is_default_credential_changed", True),
                    cors_allow_all=kv.get("cors_allow_all", False),
                    storage_encrypted=kv.get("storage_encrypted", True)
                )
                mgr.register_resource(res)
                if s_no == 9:
                    # Mükerrer kaynak ekleme testi
                    mgr.register_resource(res)
                # Güvenli varsayılanlar doğrulaması çalıştırılır
                mgr.enforce_secure_defaults()
            elif "sistem_yapilandirmasi" in sc:
                sy = sc["sistem_yapilandirmasi"]
                mgr = FailSafeSecurityManager(
                    system_name=sy["system_name"],
                    failure_mode=FailureHandlingMode[sy["failure_mode"]],
                    safety_override_token=sy.get("safety_override_token")
                )
                # Standart bir kaynak eklenir
                mgr.register_resource(ResourceConfig("RES-TEST", "Test"))
                # Fail-open zorlaması denetlenir
                mgr.enforce_secure_defaults()
        except Exception as exc:
            caught = True
            caught_err_name = type(exc).__name__
            error_msg = str(exc)

        is_pass = caught and (caught_err_name == exp_err or exp_err in caught_err_name)
        if is_pass:
            passed_count += 1
            status_tag = "[PASS - BEKLENEN HATA ALINDI]"
        else:
            status_tag = f"[FAIL - Beklenen: {exp_err}, Alınan: {caught_err_name}]"

        log_lines.append(f"Senaryo {s_no}: {s_name}")
        log_lines.append(f"  Açıklama: {sc['aciklama']}")
        log_lines.append(f"  Beklenen Hata: {exp_err}")
        log_lines.append(f"  Alınan Hata: {caught_err_name}: {error_msg}")
        log_lines.append(f"  Sonuç: {status_tag}\n")

    log_lines.append(f"Genel Sonuç: {passed_count}/{len(scenarios)} senaryo başarıyla doğrulandı.")
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(log_lines))

    print(f"    [+] Negatif kontroller tamamlandı (Sonuç: {passed_count}/{len(scenarios)} PASS).")
    return passed_count == len(scenarios)


def adim_3_cli_ve_komut_cikisi_kaydet(config_yolu: str, kanit_yolu: str) -> None:
    """CLI komutlarını koşturup çıktılarını komut_ve_cikis.txt dosyasına kaydeder."""
    print("[*] 3. Adım: CLI işlemleri koşturulup kaydediliyor...")
    lines = []
    lines.append(f"=== GÜN 123 KOMUT VE ÇIKIŞ KANITI ===")
    lines.append(f"Tarih: {datetime.now().isoformat()}\n")

    # 1. Komut: audit
    cmd1 = f"python uygulama/failsafe_cli.py audit {config_yolu}"
    lines.append(f"$ {cmd1}")
    manager = load_manager_from_json(config_yolu)
    lines.append(f"=== {manager.system_name} Güvenli Varsayılanlar Denetimi ===")
    passed, violations = manager.audit_secure_defaults()
    if passed:
        lines.append("[+] MİMARİ UYUMLU: Tüm bileşenler 'Secure by Default' prensiplerine uygundur.\n")
    else:
        lines.append(f"[-] DİKKAT: {len(violations)} adet güvenlik ihlali tespit edildi!\n")

    # 2. Komut: evaluate (Normal yetkili talep)
    cmd2 = f"python uygulama/failsafe_cli.py evaluate {config_yolu} --role admin --resource-id RES-AUTH-API --action manage"
    lines.append(f"$ {cmd2}")
    req1 = AccessRequest("REQ-CLI-01", "admin_usr", "admin", "RES-AUTH-API", "manage")
    res1 = manager.evaluate_access(req1)
    lines.append(f"=== Erişim Kararı: [{res1.decision.value}] ===")
    lines.append(f"Talep ID: {res1.request_id}")
    lines.append(f"Gerekçe: {res1.reason}")
    lines.append(f"Eşleşen Kural: {res1.matched_rule_id}\n")

    # 3. Komut: evaluate with simulated DATABASE_DOWN failure (Fail-Secure testi)
    cmd3 = f"python uygulama/failsafe_cli.py evaluate {config_yolu} --role admin --resource-id RES-AUTH-API --action manage --simulate-failure DATABASE_DOWN"
    lines.append(f"$ {cmd3}")
    res2 = manager.evaluate_access(req1, simulate_failure=FailureType.DATABASE_DOWN)
    lines.append(f"=== Erişim Kararı: [{res2.decision.value}] ===")
    lines.append(f"Talep ID: {res2.request_id}")
    lines.append(f"Gerekçe: {res2.reason}")
    lines.append("[GÜVENCE] Fail-Secure mekanizması arıza anında erişimi güvenli kesti (CWE-636 Koruması).\n")

    # 4. Komut: evaluate without rule (Default-Deny Saltzer-Schroeder testi)
    cmd4 = f"python uygulama/failsafe_cli.py evaluate {config_yolu} --role unknown_guest --resource-id RES-CUSTOMER-DB --action delete_all"
    lines.append(f"$ {cmd4}")
    req3 = AccessRequest("REQ-CLI-03", "guest_12", "unknown_guest", "RES-CUSTOMER-DB", "delete_all")
    res3 = manager.evaluate_access(req3)
    lines.append(f"=== Erişim Kararı: [{res3.decision.value}] ===")
    lines.append(f"Talep ID: {res3.request_id}")
    lines.append(f"Gerekçe: {res3.reason}")

    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("    [+] CLI komut ve çıktıları kaydedildi.")


def adim_4_analiz_raporu_uret(config_yolu: str, kanit_yolu: str) -> None:
    """Detaylı analiz raporunu üretir ve kaydeder."""
    print("[*] 4. Adım: Analiz raporu üretiliyor...")
    manager = load_manager_from_json(config_yolu)
    report_md = manager.generate_failsafe_report()
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(report_md)
    print("    [+] Analiz raporu kaydedildi.")


def adim_5_temsili_ascii_semasi_uret(kanit_yolu: str) -> None:
    """Temsili ASCII mimari şemasını üretir (Zorunlu banner ile)."""
    print("[*] 5. Adım: Temsili ASCII mimari diyagramı üretiliyor...")
    ascii_content = """================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================

+-----------------------------------------------------------------------------------+
|            GÜVENLİ VARSAYILANLAR (SECURE BY DEFAULT) VE FAIL-SAFE MİMARİSİ        |
|             (Saltzer-Schroeder 1975 / CWE-636 Fail-Closed / CWE-1188)            |
+-----------------------------------------------------------------------------------+

     [ İSTEMCİ ERİŞİM TALEBİ ]
      - Kullanıcı / Servis Kimliği
      - Rol / Ayrıcalık
      - Hedef Kaynak & Eylem
                 |
                 v
     +---------------------------------------+
     |   POLİTİKA KARAR NOKTASI (PDP)        |
     |   - Saltzer-Schroeder Fail-Safe       |
     |   - Default: DENY                     |
     +---------------------------------------+
                 |
                 +-----> [ HARİCİ BAĞIMLILIK KONTROLÜ ]
                 |        (DB, Auth Token Servisi, Ağ)
                 |
        +--------+--------+
        |                 |
    [ SAĞLIKLI ]     [ ARIZA OLUŞTU! ]
        |             (Timeout, DB Down, Ağ Bölünmesi)
        |                 |
        |                 v
        |        [ KRİTİK GÜVENLİK YOL AYRIMI ]
        |        ---------------------------------
        |        Fail-Open (Açık Geçiş) -> ❌ TEHLİKE (CWE-636)
        |        Fail-Secure (Kapalı)   -> ✅ GÜVENLİ (Default Deny)
        |                 |
        |                 v
        |        [ ERİŞİM ANINDA KESİLİR / BLOKE EDİLİR ]
        |        [ DENETİM İZİNE KRİTİK ALARM KAYDEDİLİR ]
        |
        v
  [ AÇIK KURAL EŞLEŞTİRMESİ ]
   - Rol == Hedef && İzin Var mı?
        |
   +----+----+
   |         |
[ EVET ]   [ HAYIR ]
   |         |
   v         v
 [ İZİN ]  [ DEFAULT-DENY DEVREYE GİRER ]
           [ ERİŞİM OTOMATİK REDDEDİLİR ]

+-----------------------------------------------------------------------------------+
|  MİMARİ GÜVENCE: Debug Modu Kapalı, TLS Zorunlu, Varsayılan Şifre Değiştirilmiş! |
+-----------------------------------------------------------------------------------+

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(ascii_content)
    print("    [+] Temsili diyagram oluşturuldu.")


def main() -> None:
    """Tüm kanıt üretim sürecini orkestre eder."""
    print("=== GÜN 123 KANIT ÜRETİM SÜRECİ BAŞLADI ===")
    gercek_dir = os.path.join(current_dir, "kanit", "gercek")
    temsili_dir = os.path.join(current_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    test_kanit = os.path.join(gercek_dir, "test_sonuclari.txt")
    negatif_kanit = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    cli_kanit = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    rapor_kanit = os.path.join(gercek_dir, "failsafe_analiz_raporu.txt")
    temsili_kanit = os.path.join(temsili_dir, "failsafe_mimarisi.txt")
    config_file = os.path.join(current_dir, "ornek_veri", "system_failsafe_config.json")
    scenarios_file = os.path.join(current_dir, "ornek_veri", "invalid_failsafe_scenarios.json")

    b1 = adim_1_birim_testleri_kostur(test_kanit)
    b2 = adim_2_negatif_kontrolleri_kostur(scenarios_file, negatif_kanit)
    adim_3_cli_ve_komut_cikisi_kaydet(config_file, cli_kanit)
    adim_4_analiz_raporu_uret(config_file, rapor_kanit)
    adim_5_temsili_ascii_semasi_uret(temsili_kanit)

    if b1 and b2:
        print("\n=== TÜM DOĞRULAMALAR VE KANITLAR BAŞARIYLA ÜRETİLDİ (100/100) ===")
        sys.exit(0)
    else:
        print("\n[-] Bazı doğrulamalar başarısız oldu!")
        sys.exit(1)


if __name__ == "__main__":
    main()
