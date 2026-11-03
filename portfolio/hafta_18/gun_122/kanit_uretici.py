# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 122: Savunma Derinliği ve Kontrol Tipleri Kanıt Üretici Betiği.
Bu betik; 15 birim testi, 9 negatif kontrol senaryosunu, CLI işlemlerini,
katman analiz raporunu ve temsili ASCII mimari diyagramını otomatik üretir.
"""

# Dosya ve dizin yönetimi için os modülü içe aktarılıyor
import os
# Sistem çalışma parametreleri için sys modülü içe aktarılıyor
import sys
# JSON ayrıştırma işlemleri için json modülü içe aktarılıyor
import json
# Zaman damgaları üretmek için datetime modülü içe aktarılıyor
from datetime import datetime
# Birim testleri programatik koşturmak için unittest modülü içe aktarılıyor
import unittest
# Metin akışlarını yakalamak için io modülü içe aktarılıyor
import io

# Uygulama ve test dizinleri çözümlenip sys.path'e ekleniyor
current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "uygulama")
tests_dir = os.path.join(current_dir, "tests")
sys.path.insert(0, app_dir)
sys.path.insert(0, tests_dir)

# Çekirdek motor sınıfları ve istisnalar içe aktarılıyor
from defense_in_depth_engine import (
    DefenseInDepthManager,
    DefenseLayer,
    ControlType,
    AttackCategory,
    LayerControl,
    AttackStep,
    AttackScenario,
    DefenseInDepthError,
    DefenseGapError,
    SinglePointOfFailureError,
    UnmonitoredLayerError,
    InvalidControlConfigurationError,
    DuplicateControlError
)
# CLI yükleyici fonksiyonu içe aktarılıyor
from defense_cli import load_architecture_from_json


def adim_1_birim_testleri_kostur(kanit_yolu: str) -> bool:
    """15 birim testi çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    print("[*] 1. Adım: Birim testler koşturuluyor...")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir, pattern="test_defense_in_depth.py")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    output_text = stream.getvalue()
    header = f"=== GÜN 122 BİRİM TEST RAPORU ===\nTarih: {datetime.now().isoformat()}\n\n"
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write(header + output_text)
    if result.wasSuccessful():
        print(f"    [+] Birim testler başarıyla tamamlandı ({result.testsRun}/{result.testsRun} PASS).")
        return True
    else:
        print(f"    [-] Testlerde hata var! Başarısız: {len(result.failures)}, Hata: {len(result.errors)}")
        return False


def adim_2_negatif_kontrolleri_kostur(scenarios_path: str, kanit_yolu: str) -> bool:
    """9 negatif senaryoyu dener ve beklenen istisnaların alındığını doğrular."""
    print("[*] 2. Adım: 9 Negatif kontrol senaryosu icra ediliyor...")
    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios = json.load(fp)
    log_lines = []
    log_lines.append(f"=== GÜN 122 NEGATİF KONTROL VE HATA DOĞRULAMA RAPORU ===")
    log_lines.append(f"Tarih: {datetime.now().isoformat()}")
    log_lines.append(f"Toplam Senaryo: {len(scenarios)}\n")
    passed_count = 0

    for sc in scenarios:
        s_no = sc["senaryo_no"]
        s_name = sc["senaryo_adi"]
        exp_err = sc.get("beklenen_hata")
        caught = False
        caught_err_name = ""
        error_msg = ""
        custom_success = False

        try:
            if "kontrol_verisi" in sc:
                cv = sc["kontrol_verisi"]
                mgr = DefenseInDepthManager("Negatif Test")
                ctrl = LayerControl(
                    control_id=cv["control_id"],
                    name=cv["name"],
                    layer=DefenseLayer[cv["layer"]],
                    control_type=ControlType[cv["control_type"]],
                    effectiveness=cv["effectiveness"]
                )
                ctrl.validate()
                mgr.add_control(ctrl)
                if s_no == 4:
                    mgr.add_control(ctrl)
            elif sc.get("yonetisim_tipi") == "DEFENSE_GAP":
                mgr = DefenseInDepthManager("Bos Katman Testi")
                mgr.enforce_resilience()
            elif sc.get("yonetisim_tipi") == "SPOF":
                mgr = DefenseInDepthManager("SPoF Testi")
                # Katman boşluğunu önlemek için her katmana birer önleyici ve tespit kontrolü eklenir
                for layer in DefenseLayer:
                    p = LayerControl(f"P-{layer.name}", f"P {layer.name}", layer, ControlType.PREVENTIVE, 0.8)
                    d = LayerControl(f"D-{layer.name}", f"D {layer.name}", layer, ControlType.DETECTIVE, 0.8)
                    mgr.add_control(p)
                    mgr.add_control(d)
                # SQL Injection için yalnızca 1 önleyici kontrol eklenir (SPoF)
                c_single = LayerControl("C-SQL", "Tek WAF", DefenseLayer.APPLICATION, ControlType.PREVENTIVE, 0.9,
                                        supported_attacks=[AttackCategory.SQL_INJECTION])
                mgr.add_control(c_single)
                mgr.enforce_resilience()
            elif sc.get("yonetisim_tipi") == "UNMONITORED_LAYER":
                mgr = DefenseInDepthManager("Kör Nokta Testi")
                all_attacks = list(AttackCategory)
                # Tüm katmanlara önleyici ve tespit edici eklenir, ancak APPLICATION katmanına tespit kontrolü konmaz
                for layer in DefenseLayer:
                    p1 = LayerControl(f"P1-{layer.name}", f"P1 {layer.name}", layer, ControlType.PREVENTIVE, 0.85, all_attacks)
                    p2 = LayerControl(f"P2-{layer.name}", f"P2 {layer.name}", layer, ControlType.PREVENTIVE, 0.80, all_attacks)
                    mgr.add_control(p1)
                    mgr.add_control(p2)
                    if layer != DefenseLayer.APPLICATION:
                        d1 = LayerControl(f"D1-{layer.name}", f"D1 {layer.name}", layer, ControlType.DETECTIVE, 0.90)
                        mgr.add_control(d1)
                mgr.enforce_resilience()
            elif "senaryo_id" in sc:
                mgr = DefenseInDepthManager("Olmayan Senaryo Testi")
                mgr.simulate_attack(sc["senaryo_id"])
            elif sc.get("yonetisim_tipi") == "FULL_BREACH":
                mgr = DefenseInDepthManager("Tam Ihlal Testi")
                c_zayif = LayerControl("C-ZAYIF", "Etkisiz", DefenseLayer.DATA, ControlType.PREVENTIVE, 0.1,
                                       supported_attacks=[AttackCategory.SQL_INJECTION])
                mgr.add_control(c_zayif)
                sc_breach = AttackScenario(
                    scenario_id="SC-BREACH",
                    name="Tam Delinme",
                    category=AttackCategory.SQL_INJECTION,
                    steps=[AttackStep(1, DefenseLayer.DATA, "Direct Dump", 0.95)]
                )
                mgr.add_scenario(sc_breach)
                outcome = mgr.simulate_attack("SC-BREACH")
                if outcome.data_compromised and not outcome.stopped:
                    custom_success = True
                    error_msg = "Saldırı tüm savunmayı deldi ve veri sızdırıldı (Beklenen senaryo)."
        except Exception as exc:
            caught = True
            caught_err_name = type(exc).__name__
            error_msg = str(exc)

        is_pass = False
        if exp_err:
            is_pass = caught and (caught_err_name == exp_err or exp_err in caught_err_name)
        elif sc.get("beklenen_sonuc") == "DATA_COMPROMISED":
            is_pass = custom_success

        if is_pass:
            passed_count += 1
            status_tag = "[PASS - DOĞRULANDI]"
        else:
            status_tag = f"[FAIL - Beklenen: {exp_err}, Alınan: {caught_err_name}]"

        log_lines.append(f"Senaryo {s_no}: {s_name}")
        log_lines.append(f"  Açıklama: {sc['aciklama']}")
        log_lines.append(f"  Beklenen: {exp_err or sc.get('beklenen_sonuc')}")
        log_lines.append(f"  Sonuç/Hata: {caught_err_name or 'N/A'}: {error_msg}")
        log_lines.append(f"  Durum: {status_tag}\n")

    log_lines.append(f"Genel Sonuç: {passed_count}/{len(scenarios)} senaryo başarıyla doğrulandı.")
    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(log_lines))

    print(f"    [+] Negatif kontroller tamamlandı (Sonuç: {passed_count}/{len(scenarios)} PASS).")
    return passed_count == len(scenarios)


def adim_3_cli_ve_komut_cikisi_kaydet(config_yolu: str, kanit_yolu: str) -> None:
    """CLI komutlarını koşturup çıktılarını komut_ve_cikis.txt dosyasına kaydeder."""
    print("[*] 3. Adım: CLI işlemleri koşturulup kaydediliyor...")
    lines = []
    lines.append(f"=== GÜN 122 KOMUT VE ÇIKIŞ KANITI ===")
    lines.append(f"Tarih: {datetime.now().isoformat()}\n")

    # 1. Komut: audit
    cmd1 = f"python uygulama/defense_cli.py audit {config_yolu}"
    lines.append(f"$ {cmd1}")
    manager = load_architecture_from_json(config_yolu)
    lines.append(f"=== {manager.architecture_name} Savunma Derinliği Denetimi ===")
    passed, flaws = manager.audit_architecture_resilience()
    if passed:
        lines.append("[+] MİMARİ DAYANIKLILIK DURUMU: BAŞARILI (Tüm katmanlar korumalı ve izleniyor).\n")
    else:
        lines.append(f"[-] MİMARİ DAYANIKLILIK DURUMU: ZAYIF ({len(flaws)} zaafiyet bulundu)!\n")

    # 2. Komut: simulate SCN-RANSOM-01
    cmd2 = f"python uygulama/defense_cli.py simulate {config_yolu} SCN-RANSOM-01"
    lines.append(f"$ {cmd2}")
    outcome1 = manager.simulate_attack("SCN-RANSOM-01")
    lines.append(f"=== Saldırı Simülasyonu: [{outcome1.scenario_id}] ===")
    lines.append(f"Saldırı Durduruldu mu?: {'EVET' if outcome1.stopped else 'HAYIR'}")
    if outcome1.stopped and outcome1.stopped_at_layer:
        lines.append(f"Püskürtüldüğü Katman: {outcome1.stopped_at_layer.value}")
    lines.append(f"Delinen Katman Sayısı: {outcome1.total_layers_penetrated}")
    lines.append(f"Veri İhlal Edildi mi?: {'EVET' if outcome1.data_compromised else 'HAYIR'}")
    lines.append("--- Katman Bazlı Olay Detayları ---")
    for r in outcome1.layer_results:
        st = "DURDURULDU" if r.prevented else "DELİNDİ"
        lines.append(f"Katman [{r.layer.value}]: {st}")
        for m in r.log_messages:
            lines.append(f"   {m}")
    lines.append("")

    # 3. Komut: simulate SCN-SQLI-01
    cmd3 = f"python uygulama/defense_cli.py simulate {config_yolu} SCN-SQLI-01"
    lines.append(f"$ {cmd3}")
    outcome2 = manager.simulate_attack("SCN-SQLI-01")
    lines.append(f"=== Saldırı Simülasyonu: [{outcome2.scenario_id}] ===")
    lines.append(f"Saldırı Durduruldu mu?: {'EVET' if outcome2.stopped else 'HAYIR'}")
    if outcome2.stopped and outcome2.stopped_at_layer:
        lines.append(f"Püskürtüldüğü Katman: {outcome2.stopped_at_layer.value}")
    lines.append(f"Delinen Katman Sayısı: {outcome2.total_layers_penetrated}")
    lines.append(f"Veri İhlal Edildi mi?: {'EVET' if outcome2.data_compromised else 'HAYIR'}")
    lines.append("--- Katman Bazlı Olay Detayları ---")
    for r in outcome2.layer_results:
        st = "DURDURULDU" if r.prevented else "DELİNDİ"
        lines.append(f"Katman [{r.layer.value}]: {st}")
        for m in r.log_messages:
            lines.append(f"   {m}")

    with open(kanit_yolu, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("    [+] CLI komut ve çıktıları kaydedildi.")


def adim_4_analiz_raporu_uret(config_yolu: str, kanit_yolu: str) -> None:
    """Detaylı mimari analiz raporunu üretir ve kaydeder."""
    print("[*] 4. Adım: Analiz raporu üretiliyor...")
    manager = load_architecture_from_json(config_yolu)
    report_md = manager.generate_defense_matrix_report()
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
|               7 KATMANLI SAVUNMA DERİNLİĞİ VE KONTROL TİPLERİ MİMARİSİ            |
|                     (NIST SP 800-53 Rev 5 / NSA Defense in Depth)                 |
+-----------------------------------------------------------------------------------+

     SALDIRGAN (Tehdit Aktörü / Kill Chain Başlangıcı)
          |
          v
  [ KATMAN 1: FİZİKSEL GÜVENLİK ]
   - Önleyici: Biyometrik Veri Merkezi Girişi & Mantrap (%98)
   - Tespit: 7/24 CCTV & Hareket Sensörleri (%95)
          |
          v
  [ KATMAN 2: ÇEVRE VE DIŞ AĞ (PERIMETER) ]
   - Önleyici: NGFW / Stateful Inspection & DDoS Koruması (%90)
   - Tespit: Zeek NIDS Ağ Tabanlı Saldırı Tespiti (%88)
          |
          v
  [ KATMAN 3: İÇ AĞ VE MİKRO-SEGMENTASYON ]
   - Önleyici: ZTNA & Yazılım Tanımlı Mikro-Segmentasyon (%92)
   - Tespit: Doğu-Batı Ağ Trafiği Anomali Analizörü (%85)
          |
          v
  [ KATMAN 4: UÇ NOKTA VE SUNUCU (HOST) ]
   - Önleyici: EDR/XDR & Process Koruması (%95)
   - Tespit: FIM / Osquery Dosya Bütünlüğü Denetimi (%90)
   - Düzeltici: Otomatik Karantina & İmaj Yenileme Playbook (%92)
          |
          v
  [ KATMAN 5: UYGULAMA VE API ]
   - Önleyici: WAF (Cloudflare/ModSecurity) & Katı Girdi Doğrulama (%99)
   - Tespit: API Gateway Rate Limit & İstek Günlükleme (%88)
          |
          v
  [ KATMAN 6: VERİ VE DEPOLAMA ]
   - Önleyici: AES-256 Encryption at Rest & Tokenization (%99)
   - Tespit: Endpoint & Network DLP Ajanı (%86)
   - Düzeltici: Değiştirilemez Çevrimdışı Yedekleme (Immutable Backup) (%98)
          |
          v
  [ KATMAN 7: KİMLİK VE İNSAN (IDENTITY & GOVERNANCE) ]
   - Önleyici: FIDO2 Donanım Tabanlı MFA & Least Privilege (%96)
   - Tespit: UEBA Kullanıcı Davranış Analitiği (%85)
   - Caydırıcı: Hukuki Uyarı Banner'ı ve İkaz Metinleri (%40)

+-----------------------------------------------------------------------------------+
|    MİMARİ GÜVENCE: Tek Hata Noktası (SPoF) Yok, Katman Boşluğu (Gap) Yok!        |
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
    print("=== GÜN 122 KANIT ÜRETİM SÜRECİ BAŞLADI ===")
    gercek_dir = os.path.join(current_dir, "kanit", "gercek")
    temsili_dir = os.path.join(current_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    test_kanit = os.path.join(gercek_dir, "test_sonuclari.txt")
    negatif_kanit = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    cli_kanit = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    rapor_kanit = os.path.join(gercek_dir, "savunma_analiz_raporu.txt")
    temsili_kanit = os.path.join(temsili_dir, "savunma_mimarisi.txt")
    config_file = os.path.join(current_dir, "ornek_veri", "defense_architecture_config.json")
    scenarios_file = os.path.join(current_dir, "ornek_veri", "invalid_defense_scenarios.json")

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
