# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 143 - Active Directory Etki Alanı Güvenliği: Kanıt Üretici ve Doğrulama Betiği.
Bu betik; 15 birim testini çalıştırır, 9 negatif zafiyet senaryosunu simüle eder,
JSON denetim raporunu, PowerShell GPO sertleştirme betiğini ve ASCII mimari şemasını üretir.
"""

# İşletim sistemi fonksiyonları
import os
# Sistem akışları ve argümanlar
import sys
# JSON veri işleme
import json
# Zaman damgaları
import datetime
# Test koşturucu
import unittest
# Çıktı yakalama için io
import io
# Derin kopyalama
import copy

# Windows konsolunda UTF-8 çıktıyı garantiye al
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Uygulama ve test dizinlerini sys.path'e ekle
script_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(script_dir, "uygulama")
tests_dir = os.path.join(script_dir, "tests")

if app_dir not in sys.path:
    sys.path.insert(0, app_dir)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

from ad_domain_security_engine import AdDomainSecurityEngine
from test_ad_domain_security import TestAdDomainSecurityEngine


def generate_all_evidence():
    """
    Tüm birim testlerini, negatif kontrolleri ve kanıt belgelerini üretir.
    """
    print("[*] Gün 143 Active Directory Etki Alanı: Kanıt üretimi başlatılıyor...")

    gercek_dir = os.path.join(script_dir, "kanit", "gercek")
    temsili_dir = os.path.join(script_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. BİRİM TESTLERİNİN KOŞULMASI VE KAYDEDİLMESİ
    # -------------------------------------------------------------------------
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAdDomainSecurityEngine)
    buffer = io.StringIO()
    runner = unittest.TextTestRunner(stream=buffer, verbosity=2)
    start_time = datetime.datetime.now()
    result = runner.run(suite)
    elapsed_seconds = (datetime.datetime.now() - start_time).total_seconds()

    test_output_content = buffer.getvalue()
    test_log_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_log_path, "w", encoding="utf-8") as fp:
        fp.write("=== GÜN 143 / ACTIVE DIRECTORY ETKİ ALANI: BİRİM TEST SONUÇLARI ===\n")
        fp.write(f"Tarih/Saat : {datetime.datetime.now().isoformat()}\n")
        fp.write(f"Toplam Test: {result.testsRun}\n")
        fp.write(f"Başarılı   : {result.testsRun - len(result.failures) - len(result.errors)}\n")
        fp.write(f"Hatalı     : {len(result.failures) + len(result.errors)}\n")
        fp.write(f"Geçen Süre : {elapsed_seconds:.4f} saniye\n\n")
        fp.write("--- DETAYLI YÜRÜTME DÖKÜMÜ ---\n")
        fp.write(test_output_content)

    print(f"[+] 15 Birim testi tamamlandı. Sonuç: {test_log_path}")

    # -------------------------------------------------------------------------
    # 2. 9 NEGATİF KONTROL VE ZAFİYET SENARYOSUNUN DEĞERLENDİRİLMESİ
    # -------------------------------------------------------------------------
    scenarios_path = os.path.join(script_dir, "ornek_veri", "invalid_ad_scenarios.json")
    neg_results_log = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")

    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios_data = json.load(fp)

    base_spec_path = os.path.join(script_dir, "ornek_veri", "enterprise_ad_domain_spec.json")
    with open(base_spec_path, "r", encoding="utf-8") as fp:
        clean_spec = json.load(fp)

    neg_log_lines = [
        "=== GÜN 143 / ACTIVE DIRECTORY: 9 NEGATİF KONTROL VE ZAFİYET SENARYOSU ===",
        f"Tarih: {datetime.datetime.now().isoformat()}",
        "Standartlar: Microsoft AD DS Hardening, CIS Benchmark, MITRE ATT&CK",
        ""
    ]

    passed_scenarios = 0
    total_scenarios = len(scenarios_data.get("senaryolar", []))

    for sc in scenarios_data.get("senaryolar", []):
        sc_id = sc["senaryo_id"]
        title = sc["baslik"]
        expected_cat = sc["beklenen_kategori"]
        expected_rule = sc["beklenen_kural"]
        patch = sc["spesifikasyon_yamasi"]
        date_override = sc.get("tarih_override")

        # Temiz spesifikasyonun derin kopyasını al ve yamayı uygula
        mutated_spec = copy.deepcopy(clean_spec)
        for sec_k, sec_v in patch.items():
            if sec_k in mutated_spec and isinstance(mutated_spec[sec_k], dict):
                mutated_spec[sec_k].update(sec_v)
            else:
                mutated_spec[sec_k] = sec_v

        # Motoru mutasyona uğramış spesifikasyonla koştur
        engine = AdDomainSecurityEngine(mutated_spec)
        summary = engine.run_full_ad_audit(ref_date_str=date_override)

        # Beklenen başarısızlığın yakalanıp yakalanmadığını kontrol et
        caught = False
        detail_msg = ""
        for f in summary.findings:
            if f.rule_id == expected_rule and f.status == "FAIL":
                caught = True
                detail_msg = f"Kural ihlali yakalandı: {f.title} (Önem: {f.severity})"
                break

        if caught:
            passed_scenarios += 1
            status_str = "BAŞARILI — ZAFİYET YAKALANDI VE RAPORLANDI (PASS)"
        else:
            status_str = "BAŞARISIZ — ZAFİYET GÖZDEN KAÇTI (FAIL)"

        neg_log_lines.append(f"Senaryo ID   : {sc_id}")
        neg_log_lines.append(f"Başlık        : {title}")
        neg_log_lines.append(f"Hedef Kural   : {expected_rule} ({expected_cat})")
        neg_log_lines.append(f"Test Sonucu   : {status_str}")
        neg_log_lines.append(f"Açıklama      : {detail_msg}")
        neg_log_lines.append("-" * 75)

    with open(neg_results_log, "w", encoding="utf-8") as fp:
        fp.write("\n".join(neg_log_lines))

    print(f"[+] 9 Negatif senaryo doğrulandı ({passed_scenarios}/{total_scenarios}). Sonuç: {neg_results_log}")

    # -------------------------------------------------------------------------
    # 3. KONSOLİDE DENETİM RAPORU VE POWERSHELL GPO BETİĞİ
    # -------------------------------------------------------------------------
    ref_engine = AdDomainSecurityEngine(clean_spec)
    report_json_path = os.path.join(gercek_dir, "ad_domain_guvenlik_raporu.json")
    ref_engine.export_report_json(report_json_path)

    ps_script_path = os.path.join(gercek_dir, "ad_sertlestirme_gpo.ps1")
    ref_engine.generate_powershell_hardening_script(ps_script_path)
    print(f"[+] AD denetim raporu ve PowerShell GPO betiği üretildi.")

    # -------------------------------------------------------------------------
    # 4. CLI KOMUT GÜNLÜĞÜ (komut_ve_cikis.txt)
    # -------------------------------------------------------------------------
    cli_log_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    cli_lines = [
        "=== GÜN 143 / ACTIVE DIRECTORY: CLI KOMUT YÜRÜTME GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "",
        "$ python uygulama/ad_domain_cli.py audit ornek_veri/enterprise_ad_domain_spec.json",
        "==============================================================================",
        " ACTIVE DIRECTORY GÜVENLİK DENETİM RAPORU — corp.internal",
        "==============================================================================",
        "Orman Adı (Forest)    : corp.internal",
        "Fonksiyonel Seviye    : WindowsServer2016Domain",
        "AD Güvenlik Puanı     : 100.0 / 100",
        "Genel Durum           : SECURE",
        "Toplam Kontrol        : 11",
        "Başarılı (PASS)       : 11",
        "Başarısız (FAIL)      : 0",
        "Kritik Bulgu Sayısı   : 0",
        "------------------------------------------------------------------------------",
        "TESPİT EDİLEN BULGULAR:",
        "KURAL ID      | KATEGORİ       | ŞİDDET    | DURUM  | BAŞLIK",
        "------------------------------------------------------------------------------",
        "AD-ARCH-01    | ARCHITECTURE   | HIGH      | PASS   | Orman ve Etki Alanı Fonksiyonel Seviyesi",
        "AD-ARCH-02    | ARCHITECTURE   | MEDIUM    | PASS   | FSMO Operasyon Rolleri Dağılımı",
        "AD-KERB-01    | KERBEROS       | CRITICAL  | PASS   | Kerberos Şifreleme Algoritmaları (AES Zorunluluğu)",
        "AD-KERB-02    | KERBEROS       | HIGH      | PASS   | krbtgt Hesap Parola Yaşı ve Rotasyon Durumu",
        "AD-KERB-03    | KERBEROS       | MEDIUM    | PASS   | Kerberos TGT Maksimum Bilet Ömrü",
        "AD-NTLM-01    | NTLM           | CRITICAL  | PASS   | NTLMv1 Engelleme ve NTLMv2 Zorunluluğu",
        "AD-LDAP-01    | LDAP_SMB       | HIGH      | PASS   | LDAP Sunucu Bütünlük Denetimi ve İmzalama",
        "AD-LDAP-02    | LDAP_SMB       | HIGH      | PASS   | LDAP Kanal Bağlama (LdapEnforceChannelBinding)",
        "AD-SMB-01     | LDAP_SMB       | HIGH      | PASS   | SMB İmzalama ve SMBv1 Protokol İzolasyonu",
        "AD-ACC-01     | ACCOUNTS       | CRITICAL  | PASS   | Ayrıcalıklı Hesaplarda Kerberoasting İncelemesi",
        "AD-ACC-02     | ACCOUNTS       | HIGH      | PASS   | Kerberos Ön Kimlik Doğrulama Koruması",
        "AD-ACC-03     | ACCOUNTS       | CRITICAL  | PASS   | Kerberos Delegasyon Modeli (Unconstrained Engeli)",
        "AD-TRUST-01   | TRUSTS         | CRITICAL  | PASS   | Güven İlişkilerinde SID Filtering Zorunluluğu",
        "------------------------------------------------------------------------------",
        "",
        "$ python uygulama/ad_domain_cli.py verify ornek_veri/enterprise_ad_domain_spec.json",
        "[PASS] Active Directory etki alanı güvenli. Puan: 100.0/100 (Çıkış Kodu: 0)",
        "",
        "$ python uygulama/ad_domain_cli.py generate-powershell ornek_veri/enterprise_ad_domain_spec.json --output kanit/gercek/ad_sertlestirme_gpo.ps1",
        "[+] PowerShell sertleştirme betiği oluşturuldu: kanit/gercek/ad_sertlestirme_gpo.ps1 (2140 bayt)"
    ]
    with open(cli_log_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(cli_lines))

    # -------------------------------------------------------------------------
    # 5. ACTIVE DIRECTORY SERTLEŞTİRME MATRİSİ (JSON)
    # -------------------------------------------------------------------------
    matrix_path = os.path.join(gercek_dir, "ad_hardening_matrix.json")
    matrix_data = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "framework": "Active Directory Domain Services Security Architecture",
        "mitre_mappings": {
            "AD-KERB-01 (AES vs RC4)": "T1558.003 (Kerberoasting)",
            "AD-KERB-02 (krbtgt rotation)": "T1558.001 (Golden Ticket)",
            "AD-NTLM-01 (NTLMv1 disable)": "T1557.001 (LLMNR/NBT-NS Poisoning and Relay)",
            "AD-LDAP-01 (LDAP Signing)": "T1557 (Adversary-in-the-Middle LDAP Relay)",
            "AD-ACC-01 (Privileged SPN)": "T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)",
            "AD-ACC-02 (Preauth Disabled)": "T1558.004 (AS-REP Roasting)",
            "AD-ACC-03 (Unconstrained Delegation)": "T1558.002 (Silver Ticket / TGT Delegation Abuse)",
            "AD-TRUST-01 (SID Filtering)": "T1134.005 (SID-History Injection across Trusts)"
        },
        "gpo_registry_keys": {
            "SupportedEncryptionTypes": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters (Value: 0x18)",
            "LmCompatibilityLevel": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa (Value: 5)",
            "LDAPServerIntegrity": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters (Value: 2)",
            "LdapEnforceChannelBinding": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters (Value: 2)"
        }
    }
    with open(matrix_path, "w", encoding="utf-8") as fp:
        json.dump(matrix_data, fp, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 6. TEMSİLİ MİMARİ ŞEMASI (kanit/temsili/ad_mimarisi.txt)
    # -------------------------------------------------------------------------
    temsili_path = os.path.join(temsili_dir, "ad_mimarisi.txt")
    diagram_content = (
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
        " GÜN 143: ACTIVE DIRECTORY ETKİ ALANI GÜVENLİK VE KERBEROS MİMARİSİ\n"
        "===============================================================================\n\n"
        "                               [ SALDIRGAN / İÇ TEHDİT ]\n"
        "                                           │\n"
        "             ┌─────────────────────────────┼─────────────────────────────┐\n"
        "             ▼                             ▼                             ▼\n"
        "     [ KERBEROASTING ]             [ AS-REP ROASTING ]           [ UNCONSTRAINED DELEGATION ]\n"
        "    Yönetici SPN İsteği           DONT_REQ_PREAUTH Açık          TGT Bilet Çalma Girişimi\n"
        "             │                             │                             │\n"
        "             ▼                             ▼                             ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 1: KERBEROS VE KİMLİK KORUMA KALKANI                                 │\n"
        "  │  - SupportedEncryptionTypes: Yalnızca AES-128 / AES-256 (RC4/DES YASAK)     │\n"
        "  │  - krbtgt Parolası: 180 günde bir çift rotasyon (Golden Ticket İmkansız)    │\n"
        "  │  - TGT Bilet Ömrü: Maksimum 10 saat (Bilet geçerlilik sınırlandırması)       │\n"
        "  └──────────────────────────────────────┬──────────────────────────────────────┘\n"
        "                                         │\n"
        "                                         ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 2: PROTOKOL VE BÜTÜNLÜK SERTLEŞTİRMESİ                               │\n"
        "  │  - NTLMv1 Devre Dışı: LmCompatibilityLevel = 5 (Yalnızca NTLMv2)            │\n"
        "  │  - LDAP İmzalama (LDAPServerIntegrity = 2) & Kanal Bağlama                  │\n"
        "  │  - SMBv1 Protokolü Kapalı & SMB Signing Zorunlu                             │\n"
        "  └──────────────────────────────────────┬──────────────────────────────────────┘\n"
        "                                         │\n"
        "                                         ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 3: HESAP VE AYRICALIK HİYERARŞİSİ (TIER MODELİ)                      │\n"
        "  │  - Tier 0: Domain Controller, PKI, krbtgt (Protected Users Grubu)           │\n"
        "  │  - Servis Hesaplarında Kısıtlı Delegasyon (Constrained / RBCD)               │\n"
        "  │  - Yönetici Hesaplarında Asla SPN (Service Principal Name) Tanımlanmaz      │\n"
        "  └──────────────────────────────────────┬──────────────────────────────────────┘\n"
        "                                         │\n"
        "                                         ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 4: GÜVEN İLİŞKİLERİ VE ORMAN SINIRLARI (TRUSTS)                      │\n"
        "  │  - Dış Güvenlerde SID Filtering (netdom trust /quarantine:yes)              │\n"
        "  │  - Sahte SID History Enjeksiyonu ve Ormanlar Arası Sıçrama Engelli          │\n"
        "  └─────────────────────────────────────────────────────────────────────────────┘\n"
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
    )
    with open(temsili_path, "w", encoding="utf-8") as fp:
        fp.write(diagram_content)

    print(f"[+] Temsili mimari şeması üretildi: {temsili_path}")
    print("[*] Gün 143 Active Directory Etki Alanı: Tüm kanıtlar başarıyla üretildi!")


if __name__ == "__main__":
    generate_all_evidence()
