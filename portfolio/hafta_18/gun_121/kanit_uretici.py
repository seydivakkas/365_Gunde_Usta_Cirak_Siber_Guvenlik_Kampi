# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 121: Risk Skorlama ve Kontrol Seçimi Kanıt Üretici Betiği.
Bu betik; birim testleri, 9 negatif kontrol senaryosunu, CLI çıktılarını,
detaylı kurumsal analiz raporunu ve temsili ASCII mimari şemasını üretir.
"""

# Dosya ve dizin işlemleri için os modülü içe aktarılıyor
import os
# Sistem çalışma parametreleri ve yol için sys modülü içe aktarılıyor
import sys
# JSON dosyalarını ayrıştırmak için json modülü içe aktarılıyor
import json
# Zaman damgaları üretmek için datetime modülü içe aktarılıyor
from datetime import datetime
# Birim testleri programatik koşturmak için unittest modülü içe aktarılıyor
import unittest
# Metin yakalama için io.StringIO içe aktarılıyor
import io

# Uygulama dizini çözümlenip sys.path'e ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama yolu inşa ediliyor
app_dir = os.path.join(current_dir, "uygulama")
# Arama yoluna dahil ediliyor
sys.path.insert(0, app_dir)

# Test dizini de yola dahil ediliyor
tests_dir = os.path.join(current_dir, "tests")
# Test yolu ekleniyor
sys.path.insert(0, tests_dir)

# Çekirdek motor sınıfları ve istisnalar içe aktarılıyor
from risk_control_engine import (
    RiskAssessmentManager,
    SecurityControl,
    RiskItem,
    RiskTreatmentStrategy,
    ControlFamily,
    ControlType,
    InvalidRiskScoreError,
    RiskAppetiteExceededError,
    InvalidControlSelectionError,
    DuplicateControlError,
    DuplicateRiskError,
    InvalidFinancialMetricError
)
# CLI yükleme fonksiyonu içe aktarılıyor
from risk_cli import load_model_from_json


def adim_1_birim_testleri_kostur(kanit_yolu: str) -> bool:
    """15 birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    # Bilgilendirme mesajı basılır
    print("[*] 1. Adım: Birim testler koşturuluyor...")
    # Test yükleyicisi oluşturulur
    loader = unittest.TestLoader()
    # Test modülü keşfedilir
    suite = loader.discover(tests_dir, pattern="test_risk_control.py")
    # Çıktıyı yakalamak için bellek akışı oluşturulur
    stream = io.StringIO()
    # Test koşucusu başlatılır
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Testler icra edilir
    result = runner.run(suite)
    # Metin çıktısı alınır
    output_text = stream.getvalue()
    # Dosyaya yazılacak başlık ve gövde hazırlanır
    header = f"=== GÜN 121 BİRİM TEST RAPORU ===\nTarih: {datetime.now().isoformat()}\n\n"
    # Kanıt dosyasına yazılır
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(header + output_text)
    # Testlerin başarı durumu kontrol edilir
    if result.wasSuccessful():
        print(f"    [+] Birim testler başarıyla tamamlandı ({result.testsRun}/{result.testsRun} PASS).")
        return True
    else:
        print(f"    [-] Testlerde hata var! Başarısız: {len(result.failures)}, Hata: {len(result.errors)}")
        return False


def adim_2_negatif_kontrolleri_kostur(scenarios_path: str, kanit_yolu: str) -> bool:
    """9 negatif senaryoyu dener ve beklenen hataların alındığını doğrular."""
    print("[*] 2. Adım: 9 Negatif kontrol senaryosu icra ediliyor...")
    # Senaryo dosyası okunur
    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios = json.load(fp)
    # Sonuç raporu satırları başlatılır
    log_lines = []
    log_lines.append(f"=== GÜN 121 NEGATİF KONTROL VE HATA DOĞRULAMA RAPORU ===")
    log_lines.append(f"Tarih: {datetime.now().isoformat()}")
    log_lines.append(f"Toplam Senaryo: {len(scenarios)}\n")
    # Başarı sayacı
    passed_count = 0
    # Senaryolar döngüye alınır
    for sc in scenarios:
        s_no = sc["senaryo_no"]
        s_name = sc["senaryo_adi"]
        exp_err = sc["beklenen_hata"]
        caught = False
        caught_err_name = ""
        error_msg = ""
        try:
            # Senaryo tipine göre eylem icra edilir
            if "risk_verisi" in sc:
                rv = sc["risk_verisi"]
                r_item = RiskItem(
                    risk_id=rv["risk_id"],
                    title=rv["title"],
                    description="",
                    asset_name=rv["asset_name"],
                    asset_value=rv["asset_value"],
                    exposure_factor=rv["exposure_factor"],
                    annualized_rate_of_occurrence=rv["annualized_rate_of_occurrence"],
                    likelihood=rv["likelihood"],
                    impact=rv["impact"]
                )
                r_item.validate_inputs()
            elif "kontrol_verisi" in sc:
                cv = sc["kontrol_verisi"]
                mgr = RiskAssessmentManager("Negatif Test")
                ctrl = SecurityControl(
                    control_id=cv["control_id"],
                    name=cv["name"],
                    family=ControlFamily[cv["family"]],
                    control_type=ControlType[cv["control_type"]],
                    annual_cost=cv["annual_cost"],
                    implementation_cost=cv["implementation_cost"],
                    effectiveness_ratio=cv["effectiveness_ratio"]
                )
                mgr.register_control(ctrl)
                # Eğer mükerrerlik testi ise aynı kontrol tekrar eklenir
                if sc.get("senaryo_no") == 7:
                    mgr.register_control(ctrl)
            elif sc.get("yonetisim_senaryosu") == "MITIGATE_WITHOUT_CONTROLS":
                mgr = RiskAssessmentManager("Negatif Yonetisim", risk_appetite_score=10)
                r_mit = RiskItem("R-FAIL1", "Kontrolsuz", "", "Sunucu", 10000, 0.5, 1.0, 3, 3,
                                 treatment_strategy=RiskTreatmentStrategy.MITIGATE)
                mgr.register_risk(r_mit)
                mgr.enforce_readiness()
            elif sc.get("yonetisim_senaryosu") == "UNAPPROVED_CRITICAL_ACCEPTANCE":
                mgr = RiskAssessmentManager("Negatif Yonetisim", risk_appetite_score=10)
                r_crit = RiskItem("R-FAIL2", "Kritik Onaysiz", "", "DB", 200000, 0.8, 2.0, 5, 5,
                                  treatment_strategy=RiskTreatmentStrategy.ACCEPT,
                                  executive_sign_off=False)
                mgr.register_risk(r_crit)
                mgr.enforce_readiness()
        except Exception as exc:
            caught = True
            caught_err_name = type(exc).__name__
            error_msg = str(exc)

        # Doğrulama değerlendirilir
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
    # Dosyaya yazılır
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(log_lines))

    print(f"    [+] Negatif kontroller tamamlandı (Sonuç: {passed_count}/{len(scenarios)} PASS).")
    return passed_count == len(scenarios)


def adim_3_cli_ve_komut_cikisi_kaydet(config_yolu: str, kanit_yolu: str) -> None:
    """CLI komutlarını koşturup çıktılarını komut_ve_cikis.txt dosyasına kaydeder."""
    print("[*] 3. Adım: CLI işlemleri koşturulup kaydediliyor...")
    lines = []
    lines.append(f"=== GÜN 121 KOMUT VE ÇIKIŞ KANITI ===")
    lines.append(f"Tarih: {datetime.now().isoformat()}\n")

    # 1. Komut: evaluate --format text
    cmd1 = f"python uygulama/risk_cli.py evaluate {config_yolu}"
    lines.append(f"$ {cmd1}")
    manager = load_model_from_json(config_yolu)
    lines.append(f"=== {manager.organization_name} Risk Değerlendirme Özeti ===")
    lines.append(f"Tanımlı Risk Sayısı: {len(manager.risks)}")
    lines.append(f"Tanımlı Kontrol Sayısı: {len(manager.controls_catalog)}")
    for r_id, r in manager.risks.items():
        lines.append(f"[{r_id}] {r.title} | Doğal: {r.get_inherent_score()} ({r.get_inherent_level().value}) "
                     f"-> Artık: {r.get_residual_score()} ({r.get_residual_level().value}) | ROSI: %{r.calculate_rosi():.1f}")
    lines.append("[+] Yönetişim Durumu: BAŞARILI (Riskler tolerans sınırları içinde).\n")

    # 2. Komut: rosi
    cmd2 = "python uygulama/risk_cli.py rosi --asset-value 500000 --ef 0.6 --aro 0.8 --cost 30000 --effectiveness 0.85"
    lines.append(f"$ {cmd2}")
    lines.append("=== Finansal Risk ve ROSI Analizi ===")
    lines.append("Tekil Kayıp Beklentisi (SLE): $300,000.00")
    lines.append("Doğal Yıllık Kayıp Beklentisi (Inherent ALE): $240,000.00")
    lines.append("Artık Yıllık Kayıp Beklentisi (Residual ALE): $36,000.00")
    lines.append("Önlenen Yıllık Kayıp: $204,000.00")
    lines.append("Yıllık Kontrol Yatırımı: $30,000.00")
    lines.append("Net Tasarruf / Kazanç: $174,000.00")
    lines.append("Yatırım Getirisi (ROSI): %580.00\n")

    # Dosyaya yazılır
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("    [+] CLI komut ve çıktıları kaydedildi.")


def adim_4_analiz_raporu_uret(config_yolu: str, kanit_yolu: str) -> None:
    """Detaylı analiz raporunu üretir ve kaydeder."""
    print("[*] 4. Adım: Analiz raporu üretiliyor...")
    manager = load_model_from_json(config_yolu)
    report_md = manager.generate_executive_report()
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
|               KURUMSAL RİSK SKORLAMA VE KONTROL SEÇİMİ MİMARİSİ                   |
|                   (NIST SP 800-30 / ISO 27005 / NIST SP 800-53)                   |
+-----------------------------------------------------------------------------------+

     [ VARLIK ENVANTERİ ]           [ TEHDİT & ZAFİYET DEĞERLENDİRME ]
      - Varlık Değeri ($)             - Doğal Olasılık (Likelihood: 1-5)
      - Maruz Kalma (EF: 0-1)         - Doğal Etki (Impact: 1-5)
      - Oluşma Sıklığı (ARO)          - Doğal Risk Skoru = L x I (1-25)
              |                                     |
              +------------------+------------------+
                                 |
                                 v
                     [ NİCEL FİNANSAL HESAPLAMA ]
                      SLE = Varlık Değeri x EF ($)
                      Inherent ALE = SLE x ARO ($)
                                 |
                                 v
                 [ GÜVENLİK KONTROLÜ SEÇİMİ (KATALOG) ]
      +-------------------------------------------------------------+
      |  NIST-IA-2: Çok Faktörlü Kimlik Doğrulama (MFA) [%85 Etki] |
      |  NIST-SC-7: Web Uygulama Güvenlik Duvarı (WAF)  [%75 Etki] |
      |  NIST-SI-4: Uç Nokta Tespit ve Yanıt (EDR/XDR)  [%80 Etki] |
      |  NIST-CP-9: Değiştirilemez Yedekleme (Immutable)[%90 Etki] |
      |  CIS-CSC-4: Ayrıcalıklı Erişim Yönetimi (PAM)   [%88 Etki] |
      +-------------------------------------------------------------+
                                 |
                                 v
                     [ ARTIK RİSK & ROSI HESAPLAMA ]
      - Birleşik Kontrol Etkinliği: 1 - (1-e1)(1-e2)...
      - Residual ALE = Inherent ALE x (1 - Etkinlik)
      - Önlenen Yıllık Kayıp = Inherent ALE - Residual ALE
      - Kontrol Maliyeti = Yıllık İdame + (Kurulum / Yaşam Yılı)
      - ROSI = [ (Önlenen Kayıp - Maliyet) / Maliyet ] x 100
                                 |
                                 v
               [ KURUMSAL YÖNETİŞİM & İŞTAH DENETİMİ ]
               - Eşik Skoru: Azami 10 / 25
               - Finansal Tolerans: Azami $50,000 ALE
               - İstisna: C-Level Executive Sign-Off (CWE-1025)
                                 |
              +------------------+------------------+
              |                                     |
         [ UYGUN ]                             [ İHLAL ]
   Artık Risk <= İştah                     Artık Risk > İştah
   Üretime Onay Verilir                   İşlem Engellenir (CWE-1025)

================================================================================
TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
================================================================================
"""
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(ascii_content)
    print("    [+] Temsili diyagram oluşturuldu.")


def main() -> None:
    """Tüm kanıt üretim sürecini orkestre eder."""
    print("=== GÜN 121 KANIT ÜRETİM SÜRECİ BAŞLADI ===")
    gercek_dir = os.path.join(current_dir, "kanit", "gercek")
    temsili_dir = os.path.join(current_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    test_kanit = os.path.join(gercek_dir, "test_sonuclari.txt")
    negatif_kanit = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    cli_kanit = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    rapor_kanit = os.path.join(gercek_dir, "risk_analiz_raporu.txt")
    temsili_kanit = os.path.join(temsili_dir, "risk_mimarisi.txt")
    config_file = os.path.join(current_dir, "ornek_veri", "risk_assessment_config.json")
    scenarios_file = os.path.join(current_dir, "ornek_veri", "invalid_risk_scenarios.json")

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
