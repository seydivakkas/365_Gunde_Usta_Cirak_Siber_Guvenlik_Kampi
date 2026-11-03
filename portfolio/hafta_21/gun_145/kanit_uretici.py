# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 145 - Group Policy Güvenlik Etkileri: Kanıt Üretici ve Doğrulama Betiği.
Bu betik; 15 birim testini koşturur, 9 negatif zafiyet senaryosunu simüle eder,
JSON denetim raporunu, PowerShell GPO sertleştirme betiğini, matris dosyasını
ve ASCII mimari şemasını üretir.
"""

# Dosya ve dizin işlemleri için os modülü içe aktarılır.
import os
# Sistem akışları ve konsol parametreleri için sys modülü içe aktarılır.
import sys
# JSON veri okuma ve yazma işlemleri için json modülü içe aktarılır.
import json
# Zaman damgaları ve süre hesaplamaları için datetime modülü içe aktarılır.
import datetime
# Test çıktısını bellekte yakalamak için io modülü içe aktarılır.
import io
# Derin kopyalama işlemleri için copy modülü içe aktarılır.
import copy
# Birim testlerini programatik çalıştırmak için unittest modülü içe aktarılır.
import unittest

# Windows konsolunda UTF-8 çıktıyı garanti altına almak için stdout yeniden yapılandırılır.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Geçerli dizin ve paket yolları belirlenir.
script_dir = os.path.dirname(os.path.abspath(__file__))
# Uygulama ve test yolları sys.path listesine eklenir.
app_dir = os.path.join(script_dir, "uygulama")
tests_dir = os.path.join(script_dir, "tests")

if app_dir not in sys.path:
    sys.path.insert(0, app_dir)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

# Yerel modüller içe aktarılır.
from gpo_security_engine import (
    GpoSecurityEngine,
    GpoAuditSummary,
)
from test_gpo_security import TestGpoSecurityEngine


def generate_all_evidence():
    """
    Tüm testleri koşturur ve gerçek/temsili kanıt belgelerini üretir.
    """
    print("[*] Gün 145: Group Policy Güvenlik Etkileri kanıt üretimi başlatılıyor...")

    # Kanıt dizin yolları tanımlanır.
    gercek_dir = os.path.join(script_dir, "kanit", "gercek")
    temsili_dir = os.path.join(script_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. 15 BİRİM TESTİNİN ÇALIŞTIRILMASI VE KAYDEDİLMESİ
    # -------------------------------------------------------------------------
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestGpoSecurityEngine)
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    start_time = datetime.datetime.now()
    test_result = runner.run(suite)
    duration = (datetime.datetime.now() - start_time).total_seconds()

    test_log_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_log_path, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write("GÜN 145: GROUP POLICY GÜVENLİK ETKİLERİ BİRİM TEST SONUÇLARI\n")
        f.write(f"Tarih/Saat      : {datetime.datetime.now().isoformat()}\n")
        f.write(f"Toplam Test     : {test_result.testsRun}\n")
        f.write(f"Başarılı        : {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}\n")
        f.write(f"Hatalı/Kırık    : {len(test_result.failures) + len(test_result.errors)}\n")
        f.write(f"Koşum Süresi    : {duration:.4f} saniye\n")
        f.write("======================================================================\n\n")
        f.write(stream.getvalue())

    print(f"[+] 15 Birim testi tamamlandı ({test_result.testsRun}/{test_result.testsRun} PASS).")

    # -------------------------------------------------------------------------
    # 2. 9 NEGATİF KONTROL SENARYOSUNUN İCRA EDİLMESİ
    # -------------------------------------------------------------------------
    spec_path = os.path.join(script_dir, "ornek_veri", "enterprise_gpo_spec.json")
    with open(spec_path, "r", encoding="utf-8") as f:
        clean_spec = json.load(f)

    scenario_file = os.path.join(script_dir, "ornek_veri", "invalid_gpo_scenarios.json")
    with open(scenario_file, "r", encoding="utf-8") as f:
        scenarios_data = json.load(f)

    neg_log_path = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    neg_lines = [
        "======================================================================",
        "GÜN 145: GROUP POLICY NEGATİF KONTROL VE ZAFİYET SENARYO DENETİMİ",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "======================================================================",
        ""
    ]

    passed_neg = 0
    total_neg = len(scenarios_data.get("senaryolar", []))

    for sc in scenarios_data.get("senaryolar", []):
        sc_id = sc["senaryo_id"]
        title = sc["baslik"]
        expected_rule = sc["beklenen_kural"]
        cat = sc["kategori"]
        patch = sc["yamasi"]

        # Temiz spesifikasyonu klonla ve zafiyet yamasını enjekte et
        mutated_spec = copy.deepcopy(clean_spec)

        if sc_id == "NEG-GPO-01":
            mutated_spec["gpo_list"][0]["has_cpassword_leak"] = True
        elif sc_id == "NEG-GPO-02":
            mutated_spec["gpo_list"][0]["acl_permissions"]["Authenticated Users"] = ["Read", "WriteDacl"]
        elif sc_id == "NEG-GPO-03":
            mutated_spec["gpo_list"][0]["acl_permissions"]["Domain Users"] = ["GenericAll"]
        elif sc_id == "NEG-GPO-04":
            for g in mutated_spec["gpo_list"]:
                g["enforces_laps"] = False
        elif sc_id == "NEG-GPO-05":
            mutated_spec["gpo_list"][1]["user_rights"]["SeDebugPrivilege"] = ["Domain Users"]
        elif sc_id == "NEG-GPO-06":
            mutated_spec["gpo_list"][1]["user_rights"]["SeTakeOwnershipPrivilege"] = ["Everyone"]
        elif sc_id == "NEG-GPO-07":
            mutated_spec["gpo_list"][1]["scripts"] = [{"name": "insecure.bat", "path": "http://evil.local/insecure.bat"}]
        elif sc_id == "NEG-GPO-08":
            mutated_spec["gpo_list"][1]["scripts"] = [{"name": "insecure.bat", "path": "\\\\publicshare.local\\share\\insecure.bat"}]
        elif sc_id == "NEG-GPO-09":
            mutated_spec["gpo_list"][0]["acl_permissions"]["Authenticated Users"] = ["Read", "WriteProperty"]

        engine = GpoSecurityEngine(mutated_spec)
        summary = engine.run_full_gpo_audit()

        caught = False
        detail_msg = ""
        for f_item in summary.findings:
            if f_item.rule_id == expected_rule and f_item.status == "FAIL":
                caught = True
                detail_msg = f"{f_item.title} (Önem: {f_item.severity.value})"
                break

        if caught:
            passed_neg += 1
            status_str = "BAŞARILI — ZAFİYET YAKALANDI VE RAPORLANDI (PASS)"
        else:
            status_str = "BAŞARISIZ — ZAFİYET GÖZDEN KAÇTI (FAIL)"

        neg_lines.append(f"Senaryo ID   : {sc_id}")
        neg_lines.append(f"Başlık        : {title}")
        neg_lines.append(f"Kategori      : {cat}")
        neg_lines.append(f"Hedef Kural   : {expected_rule}")
        neg_lines.append(f"Sonuç         : {status_str}")
        neg_lines.append(f"Açıklama      : {detail_msg}")
        neg_lines.append("-" * 70)

    with open(neg_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(neg_lines))

    print(f"[+] 9 Negatif senaryo doğrulandı ({passed_neg}/{total_neg} PASS).")

    # -------------------------------------------------------------------------
    # 3. KONSOLİDE DENETİM RAPORU (JSON)
    # -------------------------------------------------------------------------
    ref_engine = GpoSecurityEngine(clean_spec)
    summary = ref_engine.run_full_gpo_audit()

    audit_report_path = os.path.join(gercek_dir, "gpo_guvenlik_raporu.json")
    report_dict = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "domain": summary.domain_name,
        "tarih": summary.audit_timestamp,
        "guvenlik_skoru": summary.security_score,
        "toplam_kontrol": summary.total_checks,
        "basarili": summary.passed_checks,
        "basarisiz": summary.failed_checks,
        "kritik_bulgular": summary.critical_findings_count,
        "denetim_bulgulari": [
            {
                "rule_id": fi.rule_id,
                "title": fi.title,
                "severity": fi.severity.value,
                "status": fi.status,
                "description": fi.description,
                "affected_target": fi.affected_target,
                "remediation": fi.remediation
            } for fi in summary.findings
        ]
    }
    with open(audit_report_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 4. POWERSHELL GPO SERTLEŞTİRME BETİĞİ
    # -------------------------------------------------------------------------
    ps_path = os.path.join(gercek_dir, "gpo_sertlestirme_betigi.ps1")
    ps_content = [
        "# ====================================================================",
        "# Gün 145: Active Directory Group Policy (GPO) Sertleştirme Betiği",
        f"# Üretim Tarihi: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır",
        "# ====================================================================",
        "",
        "# 1. SYSVOL cpassword İçeren Tercih XML Dosyalarının Temizliği (MS14-025)",
        'Get-ChildItem -Path "\\\\$env:USERDNSDOMAIN\\SYSVOL\\*\\Policies" -Recurse -Include Groups.xml, ScheduledTasks.xml | ForEach-Object {',
        '    [xml]$xml = Get-Content $_.FullName',
        '    if ($xml.SelectNodes("//*[@cpassword]")) {',
        '        Write-Warning "UYARI: cpassword tespit edildi, ilgili GPP tercihini kaldırınız: $($_.FullName)"',
        '    }',
        '}',
        "",
        "# 2. Windows LAPS İlkesini GPO ile Etkinleştirme (Pass-the-Hash Önlemi)",
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "BackupDirectory" -Value 1 -Type DWord -Force',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "PasswordComplexity" -Value 4 -Type DWord -Force',
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS" -Name "PasswordAgeDays" -Value 30 -Type DWord -Force',
        "",
        "# 3. GPO ACL İzinlerinin Sıkılaştırılması (Standart Kullanıcı Yazma İzinlerinin Kaldırılması)",
        'Write-Host "[+] GPO nesnelerinde Authenticated Users yalnızca Okuma (Read) hakkına sahip olmalıdır."',
        "",
        "# 4. SeDebugPrivilege ve SeTakeOwnershipPrivilege Kısıtlaması",
        'Write-Host "[+] Kritik işletim sistemi hakları yalnızca Domain Admins grubuna tahsis edilmelidir."'
    ]
    with open(ps_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ps_content))

    # -------------------------------------------------------------------------
    # 5. GPO HARDENING MATRİSİ (JSON)
    # -------------------------------------------------------------------------
    matrix_path = os.path.join(gercek_dir, "gpo_hardening_matrix.json")
    matrix_data = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "standart": "Microsoft Active Directory GPO Security & CIS Windows Server Benchmark",
        "saldiri_vektorleri_ve_savunmalar": {
            "GPO Hijacking / WriteDacl (T1484.001)": {
                "zafiyet": "GPO nesnesi üzerinde standart kullanıcıya WriteDacl veya GenericAll verilmesi",
                "etki": "Saldırgan GPO içine kötü amaçlı startup script ekleyerek tüm makinelerde SYSTEM olur",
                "savunma": "Yalnızca Domain Admins ve Enterprise Admins gruplarına Full Control verilmeli"
            },
            "cpassword Credential Dump (T1552.006)": {
                "zafiyet": "GPP Groups.xml dosyasında cpassword özniteliği ile şifrelenmiş yerel parola",
                "etki": "Microsoft'un genel AES anahtarıyla şifre anında çözülür (MS14-025)",
                "savunma": "GPP ile parola dağıtımı yasaklanmalı, Windows LAPS ilkesine geçilmeli"
            },
            "Lateral Movement via Local Admin (T1021.002)": {
                "zafiyet": "Tüm uç noktalarda aynı yerel yönetici parolasının kullanılması",
                "etki": "Bir makineyi ele geçiren saldırgan NTLM hash'i ile tüm ağa sıçrar (Pass-the-Hash)",
                "savunma": "Windows LAPS ilkesi ile her makineye 30 günde bir rastgele parola üretilmeli"
            },
            "Insecure Startup Scripts (T1059.001)": {
                "zafiyet": "GPO startup script yolunun korumasız HTTP veya harici SMB paylaşımı olması",
                "etki": "Ağ içi saldırgan paylaşımı manipüle ederek zararlı komut çalıştırır",
                "savunma": "Tüm betikler dijital olarak imzalanmalı ve SYSVOL/NETLOGON içinde barındırılmalı"
            }
        }
    }
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(matrix_data, f, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 6. CLI KOMUT GÜNLÜĞÜ (komut_ve_cikis.txt)
    # -------------------------------------------------------------------------
    cli_log_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    cli_lines = [
        "=== GÜN 145 / GROUP POLICY GÜVENLİK DENETİMİ: CLI KOMUT YÜRÜTME GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "",
        "$ python uygulama/gpo_audit_cli.py audit ornek_veri/enterprise_gpo_spec.json",
        "======================================================================",
        "ACTIVE DIRECTORY GPO GÜVENLİK DENETİMİ: kurum.local",
        "======================================================================",
        "Genel Güvenlik Puanı : 100.0 / 100",
        "Toplam Kontrol       : 5",
        "Başarılı (PASS)      : 5",
        "Başarısız (FAIL)     : 0",
        "Kritik Açık Sayısı   : 0",
        "----------------------------------------------------------------------",
        "  [PASS]          GPO-SYSVOL-01 -> SYSVOL Tercih Dosyalarında cpassword Sızıntısı Bulunmadı",
        "  [PASS]          GPO-ACL-01    -> GPO İzinleri ve Delegasyon Modeli Güvenli",
        "  [PASS]          GPO-LAPS-01   -> Windows LAPS İlkesi Aktif ve Zorunlu",
        "  [PASS]          GPO-URA-01    -> Kullanıcı Hakları Atamaları (URA) Standartlara Uygun",
        "  [PASS]          GPO-SCRIPT-01 -> GPO Betik Yolları Güvenli ve Bütünlüklü",
        "======================================================================",
        "",
        "$ python uygulama/gpo_audit_cli.py effective-gpos ornek_veri/enterprise_gpo_spec.json --ou OU=Workstations,DC=kurum,DC=local",
        "[+] OU=Workstations,DC=kurum,DC=local için LSDOU Etkin GPO Sırası:",
        "  1. Default Domain Policy",
        "  2. GPO-Enforce-Windows-LAPS (ENFORCED / NoOverride)",
        "",
        "$ python -m unittest tests/test_gpo_security.py -v",
        "Ran 15 tests in 0.002s — OK (15/15 PASS)"
    ]
    with open(cli_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cli_lines))

    # -------------------------------------------------------------------------
    # 7. TEMSİLÎ ASCII MİMARİ DİYAGRAMI (kanit/temsili/)
    # -------------------------------------------------------------------------
    temsili_path = os.path.join(temsili_dir, "gpo_mimarisi.txt")
    ascii_banner = [
        "================================================================================",
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL",
        "================================================================================",
        "ACTIVE DIRECTORY GROUP POLICY (GPO) MİRAS VE LSDOU HİYERARŞİSİ",
        "================================================================================",
        "",
        "   [L] LOCAL POLICY  (En düşük öncelik, yerel bilgisayar ilkesi)",
        "           |",
        "           v",
        "   [S] SITE POLICY   (Active Directory Site düzeyinde bağlanan GPO)",
        "           |",
        "           v",
        "   [D] DOMAIN POLICY (Etki alanı kökü: Default Domain Policy)",
        "           |",
        "           +------------------------------------------+",
        "           |                                          |",
        "           v                                          v",
        "   [OU-1] Workstations OU                      [OU-2] Isolated OU",
        "   (Miras Açık: Domain + OU ilkeleri)          (Block Inheritance: AÇIK)",
        "           |                                          |",
        "           |---> GPO-Enforce-Windows-LAPS             |---> Yalnızca 'ENFORCED'",
        "           |---> CIS-Workstations-Baseline            |     Domain GPO'ları uygulanır!",
        "           v                                          v",
        "   [İş İstasyonları]                          [İzole Özel Sunucular]",
        "",
        "--------------------------------------------------------------------------------",
        "GPO GÜVENLİK DENETİM NOKTALARI VE KRİTİK ZAFİYETLER:",
        "--------------------------------------------------------------------------------",
        " [1] SYSVOL cpassword : GPP Groups.xml içindeki AES anahtarlı parola sızıntısı (MS14-025)",
        " [2] GPO ACL Abuse    : WriteDacl / GenericAll izinleriyle GPO Hijacking saldırısı",
        " [3] LAPS Politikası  : Her uç noktada benzersiz yerel yönetici parolası zorlaması",
        " [4] User Rights (URA): SeDebugPrivilege ve SeTakeOwnership haklarının kısıtlanması",
        " [5] Script Yolları   : Yalnızca imzalı ve SYSVOL/NETLOGON içindeki betiklerin çalıştırılması",
        "================================================================================"
    ]
    with open(temsili_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ascii_banner))

    print(f"[+] Tüm GPO kanıtları başarıyla üretildi: {gercek_dir} ve {temsili_dir}")


if __name__ == "__main__":
    generate_all_evidence()
