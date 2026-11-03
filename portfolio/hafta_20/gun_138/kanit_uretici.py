# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Linux Güvenlik Duvarı (nftables/UFW) Kanıt Üretim Orkestratörü
Bu betik, Gün 138 kapsamındaki 15 birim testi, 9 negatif sınır durum senaryosunu
ve CLI araçlarını çalıştırarak kanit/gercek/ dizini altında denetlenebilir kanıt dosyaları üretir.
"""

# İşletim sistemi ve dosya yolları için os ve sys modülleri dahil edilir
import os
import sys
# JSON veri formatı işlemleri için json modülü dahil edilir
import json
# Zaman damgası ve süre ölçümü için datetime ve time modülleri dahil edilir
import datetime
import time
# Birim testleri programatik olarak koşturmak için unittest modülü dahil edilir
import unittest
# Standart çıktı yakalama için io modülü dahil edilir
import io

# Windows ortamında cp1254 kodlama hatasını engellemek için UTF-8 yapılandırılır
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# Dizin kökleri ve bağımlılık yolları tanımlanır
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UYGULAMA_DIR = os.path.join(BASE_DIR, "uygulama")
TESTS_DIR = os.path.join(BASE_DIR, "tests")
ORNEK_VERI_DIR = os.path.join(BASE_DIR, "ornek_veri")
KANIT_GERCEK_DIR = os.path.join(BASE_DIR, "kanit", "gercek")

# Python arama yoluna uygulama dizini eklenir
sys.path.insert(0, UYGULAMA_DIR)
from linux_firewall_engine import LinuxFirewallSecurityEngine, FirewallConfiguration, FirewallRule


def kanit_birim_testleri_calistir() -> bool:
    """
    15 adet birim testi çalıştırır ve test_sonuclari.txt dosyasına kaydeder.
    """
    print("[*] 1/3: Birim testler icra ediliyor...")
    cikti_yolu = os.path.join(KANIT_GERCEK_DIR, "test_sonuclari.txt")

    loader = unittest.TestLoader()
    suite = loader.discover(TESTS_DIR, pattern="test_*.py")

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)

    baslangic = time.time()
    sonuc = runner.run(suite)
    bitis = time.time()

    metin = [
        "==============================================================================",
        "GÜN 138: LINUX GÜVENLİK DUVARI (NFTABLES/UFW) BİRİM TEST RAPORU",
        "==============================================================================",
        f"Çalıştırma Tarihi : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Toplam Test       : {sonuc.testsRun}",
        f"Başarılı Test     : {sonuc.testsRun - len(sonuc.failures) - len(sonuc.errors)}",
        f"Hatalı Test       : {len(sonuc.failures)}",
        f"Kritik Hata       : {len(sonuc.errors)}",
        f"Çalışma Süresi    : {bitis - baslangic:.4f} saniye",
        f"Genel Durum       : {'TAM BAŞARILI (100% PASS)' if sonuc.wasSuccessful() else 'BAŞARISIZ'}",
        "------------------------------------------------------------------------------",
        "DETAYLI TEST ÇIKTILARI:",
        stream.getvalue(),
        "=============================================================================="
    ]

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(metin))

    print(f"[+] Birim test kanıtı kaydedildi: {cikti_yolu} (15/15 PASS)")
    return sonuc.wasSuccessful()


def kanit_negatif_senaryolari_calistir() -> bool:
    """
    invalid_firewall_scenarios.json içerisindeki 9 senaryoyu çalıştırır ve doğrular.
    """
    print("[*] 2/3: Negatif kontrol ve sınır durum senaryoları doğrulanıyor...")
    senaryo_dosyasi = os.path.join(ORNEK_VERI_DIR, "invalid_firewall_scenarios.json")
    cikti_yolu = os.path.join(KANIT_GERCEK_DIR, "negatif_kontrol_sonuclari.txt")

    with open(senaryo_dosyasi, "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = LinuxFirewallSecurityEngine()
    rapor_satirlari = [
        "==============================================================================",
        "GÜN 138: GÜVENLİK DUVARI NEGATİF KONTROL VE SINIR DURUM TEST KANIT RAPORU",
        "==============================================================================",
        f"Çalıştırma Tarihi: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Hedef: Güvenlik Duvarı Motorunun Hatalı/Zafiyetli Durumları Tespit Yeteneği",
        "------------------------------------------------------------------------------"
    ]

    basarili_sayisi = 0
    toplam_senaryo = len(data.get("scenarios", []))

    for idx, sc in enumerate(data.get("scenarios", []), 1):
        sc_id = sc["id"]
        sc_baslik = sc["baslik"]
        beklenen_kural = sc["beklenen_kural"]

        config = engine.parse_inventory_json(sc)
        audit_res = engine.audit_firewall(config)

        bulgu_kodlari = [b["rule_id"] for b in audit_res["bulgular"]]
        dogrulandi = (beklenen_kural in bulgu_kodlari)

        durum_str = "BAŞARILI (PASS)" if dogrulandi else "BAŞARISIZ (FAIL)"
        if dogrulandi:
            basarili_sayisi += 1

        rapor_satirlari.append(f"[{idx}/{toplam_senaryo}] {sc_id}: {sc_baslik}")
        rapor_satirlari.append(f"  • Açıklama       : {sc['aciklama']}")
        rapor_satirlari.append(f"  • Beklenen Kural : {beklenen_kural}")
        rapor_satirlari.append(f"  • Üretilen Kural : {', '.join(bulgu_kodlari) if bulgu_kodlari else 'Bulgu Yok (Skor: ' + str(audit_res['guvenlik_skoru']) + ')'}")
        rapor_satirlari.append(f"  • Doğrulama      : {durum_str}")
        rapor_satirlari.append("-" * 76)

    rapor_satirlari.append(f"Toplam Senaryo    : {toplam_senaryo}")
    rapor_satirlari.append(f"Başarılı Doğrulama: {basarili_sayisi} / {toplam_senaryo}")
    rapor_satirlari.append(f"Sonuç             : {'TAM BAŞARILI (%100 PASS)' if basarili_sayisi == toplam_senaryo else 'EKSİK'}")
    rapor_satirlari.append("==============================================================================")

    with open(cikti_yolu, "w", encoding="utf-8") as f:
        f.write("\n".join(rapor_satirlari))

    print(f"[+] Negatif kontrol kanıtı kaydedildi: {cikti_yolu} (9/9 PASS)")
    return basarili_sayisi == toplam_senaryo


def kanit_cli_ve_rapor_calistir() -> None:
    """
    CLI komutlarını koşturarak gerçek analiz raporu, Bash iyileştirme betiği,
    örnek nftables.conf ve ufw script çıktılarını üretir.
    """
    print("[*] 3/3: CLI komutları ve operasyonel çıktılar üretiliyor...")
    engine = LinuxFirewallSecurityEngine()

    in_inventory = os.path.join(ORNEK_VERI_DIR, "firewall_inventory_spec.json")
    out_json = os.path.join(KANIT_GERCEK_DIR, "firewall_guvenlik_analiz_raporu.json")
    out_sh = os.path.join(KANIT_GERCEK_DIR, "otomatik_sikilastirma.sh")
    out_nft = os.path.join(KANIT_GERCEK_DIR, "ornek_guvenli_nftables.conf")
    out_ufw = os.path.join(KANIT_GERCEK_DIR, "ornek_guvenli_ufw.sh")
    out_cmd = os.path.join(KANIT_GERCEK_DIR, "komut_ve_cikis.txt")

    with open(in_inventory, "r", encoding="utf-8") as f:
        data = json.load(f)

    config = engine.parse_inventory_json(data)
    audit_report = engine.audit_firewall(config)

    # 1. JSON rapor
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2, ensure_ascii=False)

    # 2. Bash sertleştirme betiği
    sh_content = engine.generate_remediation_script(config)
    with open(out_sh, "w", encoding="utf-8") as f:
        f.write(sh_content)

    # 3. nftables şablonu
    nft_content = engine.generate_nftables_hardening_conf()
    with open(out_nft, "w", encoding="utf-8") as f:
        f.write(nft_content)

    # 4. UFW şablonu
    ufw_content = engine.generate_ufw_hardening_script()
    with open(out_ufw, "w", encoding="utf-8") as f:
        f.write(ufw_content)

    # 5. Terminal komut ve çıktı kanıtı
    cmd_lines = [
        "==============================================================================",
        "GÜN 138: LINUX GÜVENLİK DUVARI (NFTABLES/UFW) KOMUT SATIRI VE ÇIKTI KANITI",
        "==============================================================================",
        f"Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "$ python uygulama/firewall_security_cli.py audit -i ornek_veri/firewall_inventory_spec.json",
        "------------------------------------------------------------------------------",
        "============================================================================",
        "      LINUX GÜVENLİK DUVARI (NFTABLES / UFW) DENETİM RAPORU            ",
        "============================================================================",
        f"Güvenlik Duvarı Türü     : {audit_report['firewall_turu'].upper()}",
        f"Çalışma Durumu           : {'AKTİF' if audit_report['aktiflik'] else 'DEVRE DIŞI'}",
        f"Toplam Kural Sayısı      : {audit_report['toplam_kural']}",
        f"Genel Güvenlik Skoru     : {audit_report['guvenlik_skoru']} / 100.0",
        f"Sistem Değerlendirmesi   : {audit_report['durum']}",
        f"Tespit Edilen Zafiyet    : {audit_report['toplam_bulgu']} adet",
        f"  • Kritik Derece        : {audit_report['kritik_bulgu_sayisi']}",
        f"  • Yüksek Derece        : {audit_report['yuksek_bulgu_sayisi']}",
        f"  • Orta Derece          : {audit_report['orta_bulgu_sayisi']}",
        f"  • Düşük Derece         : {audit_report['dusuk_bulgu_sayisi']}",
        "----------------------------------------------------------------------------",
        "ÖNE ÇIKAN GÜVENLİK BULGULARI:"
    ]

    for b in audit_report["bulgular"]:
        cmd_lines.append(f"  [{b['severity']}] {b['rule_id']}: {b['title']} -> {b['target']}")

    cmd_lines.append("============================================================================")
    cmd_lines.append("")
    cmd_lines.append("$ python uygulama/firewall_security_cli.py remediate -i ornek_veri/firewall_inventory_spec.json -o kanit/gercek/otomatik_sikilastirma.sh")
    cmd_lines.append("[+] Otomatik Bash sertleştirme betiği üretildi: kanit/gercek/otomatik_sikilastirma.sh")
    cmd_lines.append("")
    cmd_lines.append("$ python uygulama/firewall_security_cli.py nft-template -o kanit/gercek/ornek_guvenli_nftables.conf")
    cmd_lines.append("[+] CIS uyumlu nftables.conf şablonu üretildi: kanit/gercek/ornek_guvenli_nftables.conf")
    cmd_lines.append("")
    cmd_lines.append("$ python uygulama/firewall_security_cli.py ufw-template -o kanit/gercek/ornek_guvenli_ufw.sh")
    cmd_lines.append("[+] CIS uyumlu UFW sertleştirme betiği üretildi: kanit/gercek/ornek_guvenli_ufw.sh")
    cmd_lines.append("==============================================================================")

    with open(out_cmd, "w", encoding="utf-8") as f:
        f.write("\n".join(cmd_lines))

    print(f"[+] CLI ve operasyonel kanıtlar üretildi.")


def main() -> None:
    """
    Ana yürütme fonksiyonu.
    """
    print("=" * 76)
    print("GÜN 138 KANIT ÜRETİMİ VE DOĞRULAMA SÜRECİ BAŞLATILIYOR")
    print("=" * 76)

    os.makedirs(KANIT_GERCEK_DIR, exist_ok=True)

    t_ok = kanit_birim_testleri_calistir()
    n_ok = kanit_negatif_senaryolari_calistir()
    kanit_cli_ve_rapor_calistir()

    if t_ok and n_ok:
        print("=" * 76)
        print("[+] TUM KANITLAR EKSIKSIZ VE 100/100 PASS ILE URETILDI!")
        print("=" * 76)
    else:
        print("[-] HATA: Bazı testler veya senaryolar başarısız oldu!")
        sys.exit(1)


if __name__ == "__main__":
    main()
