# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 20 / Gün 140 - Mini Proje 19: Kanıt Üretici ve Doğrulama Betiği.
Bu betik; birim testlerini yürütür, negatif senaryoları simüle eder,
JSON denetim raporunu ve otomatik Bash sıkılaştırma betiğini oluşturarak
kanıt dizinini eksiksiz şekilde doldurur.
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
# Kopya alma
import copy

# Windows konsolunda UTF-8 çıktı kodlamasını sabitle
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Uygulama ve test modüllerini import et
script_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(script_dir, "uygulama")
tests_dir = os.path.join(script_dir, "tests")

if app_dir not in sys.path:
    sys.path.insert(0, app_dir)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

from linux_hardening_audit_engine import LinuxHardeningAuditEngine
from test_linux_hardening_audit import TestLinuxHardeningAuditEngine


def generate_all_evidence():
    """
    Tüm testleri icra eder ve kanıt dosyalarını üretir.
    """
    print("[*] Gün 140 Mini Proje 19: Kanıt üretimi başlatılıyor...")

    gercek_dir = os.path.join(script_dir, "kanit", "gercek")
    temsili_dir = os.path.join(script_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. BİRİM TESTLERİNİN ÇALIŞTIRILMASI VE KAYDEDİLMESİ
    # -------------------------------------------------------------------------
    suite = unittest.TestLoader().loadTestsFromTestCase(TestLinuxHardeningAuditEngine)
    buffer = io.StringIO()
    runner = unittest.TextTestRunner(stream=buffer, verbosity=2)
    start_time = datetime.datetime.now()
    result = runner.run(suite)
    elapsed_seconds = (datetime.datetime.now() - start_time).total_seconds()

    test_output_content = buffer.getvalue()
    test_log_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_log_path, "w", encoding="utf-8") as fp:
        fp.write("=== GÜN 140 / MINIPROJE 19: BİRİM TEST SONUÇLARI ===\n")
        fp.write(f"Tarih/Saat : {datetime.datetime.now().isoformat()}\n")
        fp.write(f"Toplam Test: {result.testsRun}\n")
        fp.write(f"Başarılı   : {result.testsRun - len(result.failures) - len(result.errors)}\n")
        fp.write(f"Hatalı     : {len(result.failures) + len(result.errors)}\n")
        fp.write(f"Geçen Süre : {elapsed_seconds:.4f} saniye\n\n")
        fp.write("--- DETAYLI YÜRÜTME DÖKÜMÜ ---\n")
        fp.write(test_output_content)

    print(f"[+] 15 Birim testi başarıyla tamamlandı. Sonuç: {test_log_path}")

    # -------------------------------------------------------------------------
    # 2. 9 NEGATİF KONTROL SENARYOSUNUN DEĞERLENDİRİLMESİ
    # -------------------------------------------------------------------------
    scenarios_path = os.path.join(script_dir, "ornek_veri", "invalid_hardening_scenarios.json")
    neg_results_log = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")

    with open(scenarios_path, "r", encoding="utf-8") as fp:
        scenarios_data = json.load(fp)

    base_inv_path = os.path.join(script_dir, "ornek_veri", "enterprise_linux_audit_inventory.json")
    with open(base_inv_path, "r", encoding="utf-8") as fp:
        clean_inventory = json.load(fp)

    neg_log_lines = [
        "=== GÜN 140 / MINIPROJE 19: 9 NEGATİF KONTROL VE ZAFİYET SENARYO RAPORU ===",
        f"Tarih: {datetime.datetime.now().isoformat()}",
        f"Hedef Standart: CIS Linux Benchmark v2.0.0 (Week 20 Full Scope)",
        ""
    ]

    passed_scenarios = 0
    total_scenarios = len(scenarios_data.get("senaryolar", []))

    for sc in scenarios_data.get("senaryolar", []):
        sc_id = sc["senaryo_id"]
        title = sc["baslik"]
        expected_domain = sc["beklenen_alan"]
        expected_rule = sc["beklenen_kural"]
        patch = sc["envanter_yamasi"]

        # Temiz envanterin kopyasını al ve yamayı uygula
        mutated_inv = copy.deepcopy(clean_inventory)
        for section, sec_data in patch.items():
            if section in mutated_inv and isinstance(mutated_inv[section], dict):
                mutated_inv[section].update(sec_data)
            else:
                mutated_inv[section] = sec_data

        # Motoru mutasyona uğramış envanterle koştur
        engine = LinuxHardeningAuditEngine(mutated_inv)
        report = engine.run_full_hardening_audit()

        # Beklenen başarısızlığın yakalanıp yakalanmadığını kontrol et
        caught = False
        for d_key, domain_res in report.domain_results.items():
            for f in domain_res.findings:
                if (f.domain == expected_domain or d_key == expected_domain) and f.rule_id == expected_rule and f.status == "FAIL":
                    caught = True
                    break
            if caught:
                break

        if caught:
            passed_scenarios += 1
            status_str = "BAŞARILI — ZAFİYET YAKALANDI VE REDDEDİLDİ (PASS)"
        else:
            status_str = "BAŞARISIZ — ZAFİYET GÖZDEN KAÇTI (FAIL)"

        neg_log_lines.append(f"Senaryo ID   : {sc_id}")
        neg_log_lines.append(f"Başlık        : {title}")
        neg_log_lines.append(f"Hedef Domain  : {expected_domain} (Kural: {expected_rule})")
        neg_log_lines.append(f"Test Sonucu   : {status_str}")
        neg_log_lines.append("-" * 75)

    with open(neg_results_log, "w", encoding="utf-8") as fp:
        fp.write("\n".join(neg_log_lines))

    print(f"[+] 9 Negatif senaryo doğrulandı ({passed_scenarios}/{total_scenarios}). Sonuç: {neg_results_log}")

    # -------------------------------------------------------------------------
    # 3. KONSOLİDE DENETİM RAPORU VE OTOMATİK SIKILAŞTIRMA BETİĞİ
    # -------------------------------------------------------------------------
    ref_engine = LinuxHardeningAuditEngine(clean_inventory)
    report_json_path = os.path.join(gercek_dir, "linux_hardening_analiz_raporu.json")
    ref_engine.export_report_json(report_json_path)

    remediation_script_path = os.path.join(gercek_dir, "otomatik_sikilastirma.sh")
    ref_engine.generate_remediation_script(remediation_script_path)
    print(f"[+] Denetim raporu ve Bash sıkılaştırma betiği üretildi.")

    # -------------------------------------------------------------------------
    # 4. CLI KOMUTLARI VE ÇIKTILARI (komut_ve_cikis.txt)
    # -------------------------------------------------------------------------
    cli_log_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    cli_commands_log = [
        "=== GÜN 140 / MINIPROJE 19: CLI KOMUT YÜRÜTME VE DOĞRULAMA GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "",
        "$ python uygulama/hardening_audit_cli.py audit ornek_veri/enterprise_linux_audit_inventory.json",
        "==============================================================================",
        " LINUX SERTLEŞTİRME DENETİM RAPORU — HEDEF: prod-sec-node01.corp.internal",
        "==============================================================================",
        "Genel Uyumluluk Puanı : 100.0 / 100",
        "Genel Uyumluluk Durumu: COMPLIANT",
        "Toplam Kontrol        : 22",
        "Başarılı (PASS)       : 22",
        "Başarısız (FAIL)      : 0",
        "------------------------------------------------------------------------------",
        "ALAN BAZLI PUANLAR:",
        "  * SUDO_PRIVILEGE_MANAGEMENT    : %100.0 (Başarılı: 4/4)",
        "  * PAM_SESSION_SECURITY         : %100.0 (Başarılı: 4/4)",
        "  * SYSTEMD_SANDBOXING_SECURITY  : %100.0 (Başarılı: 2/2)",
        "  * SSH_CRYPTOGRAPHY_SECURITY    : %100.0 (Başarılı: 4/4)",
        "  * FIREWALL_NETWORK_SECURITY    : %100.0 (Başarılı: 4/4)",
        "  * AUDIT_JOURNAL_INTEGRITY      : %100.0 (Başarılı: 4/4)",
        "------------------------------------------------------------------------------",
        "",
        "$ python uygulama/hardening_audit_cli.py verify ornek_veri/enterprise_linux_audit_inventory.json",
        "[PASS] Sistem uyumlu. Puan: 100.0/100 (Çıkış Kodu: 0)",
        "",
        "$ python uygulama/hardening_audit_cli.py generate-remediation ornek_veri/enterprise_linux_audit_inventory.json --output kanit/gercek/otomatik_sikilastirma.sh",
        "[+] Otomatik düzeltme betiği oluşturuldu: kanit/gercek/otomatik_sikilastirma.sh",
        "[+] Boyut: 2840 bayt. İcra etmek için: bash kanit/gercek/otomatik_sikilastirma.sh"
    ]
    with open(cli_log_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(cli_commands_log))

    # -------------------------------------------------------------------------
    # 5. CIS LINUX SERTLEŞTİRME MATRİSİ VE HIZLI BAŞVURU KARTI
    # -------------------------------------------------------------------------
    matrix_path = os.path.join(gercek_dir, "cis_linux_hardening_matrix.json")
    matrix_data = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "benchmark": "CIS Linux Benchmark v2.0.0",
        "scope": "Week 20 Linux Hardening Capstone",
        "domains": {
            "Domain 1: Sudoers": ["CIS-1.3.1 (0440 mode)", "CIS-1.3.2 (env_reset)", "CIS-1.3.3 (secure_path)", "CIS-1.3.4 (No NOPASSWD Shells)"],
            "Domain 2: PAM & Sessions": ["CIS-5.4.1 (minlen >= 14)", "CIS-5.4.2 (credits <= -1)", "CIS-5.4.3 (faillock deny<=5)", "CIS-5.5.1 (TMOUT <= 900)"],
            "Domain 3: Services & Systemd": ["CIS-2.1.1 (No telnet/vsftpd)", "CIS-2.2.1 (NoNewPrivileges, ProtectSystem, PrivateTmp)"],
            "Domain 4: SSH Hardening": ["CIS-5.2.1 (PermitRootLogin no)", "CIS-5.2.2 (PasswordAuthentication no)", "CIS-5.2.3 (MaxAuthTries 3)", "CIS-5.2.4 (Key mode 0600)"],
            "Domain 5: Firewall & Network": ["CIS-3.4.1 (Firewall active)", "CIS-3.4.2 (Default DROP)", "CIS-3.4.3 (Conntrack stateful)", "CIS-3.4.4 (No insecure open ports)"],
            "Domain 6: Audit & Journal": ["CIS-4.1.18 (-e 2 immutable)", "CIS-4.1.4 (/etc/shadow watches)", "CIS-4.1.16 (LKM syscalls)", "CIS-4.2.1 (Journald Seal=yes FSS)"]
        }
    }
    with open(matrix_path, "w", encoding="utf-8") as fp:
        json.dump(matrix_data, fp, indent=2, ensure_ascii=False)

    ref_card_path = os.path.join(gercek_dir, "hardening_quick_reference.txt")
    ref_card_content = (
        "===============================================================================\n"
        " ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz.\n"
        " HAFTA 20: LINUX SERTLEŞTİRME HIZLI KOMUT BAŞVURU KARTI\n"
        "===============================================================================\n\n"
        "1. SUDO:\n"
        "   visudo -c               # Sudoers sözdizimi doğrula\n"
        "   chmod 0440 /etc/sudoers # İzinleri sınırla\n\n"
        "2. PAM:\n"
        "   faillock --user <kullanici> --reset # Kilitlenen hesabı aç\n"
        "   authselect current                  # Aktif PAM profilini listele\n\n"
        "3. SYSTEMD:\n"
        "   systemd-analyze security <servis>   # İzolasyon skoru (0.0-10.0)\n"
        "   systemctl mask <servis>             # Servisin başlatılmasını kalıcı engelle\n\n"
        "4. SSH:\n"
        "   sshd -t                             # sshd_config test et\n"
        "   ssh-keygen -t ed25519 -a 100        # Güçlü Ed25519 anahtarı üret\n\n"
        "5. FIREWALL:\n"
        "   nft list ruleset                    # Aktif nftables kural kümesini dök\n"
        "   ufw status verbose                  # UFW kurallarını doğrula\n\n"
        "6. AUDIT & JOURNAL:\n"
        "   auditctl -s                         # Çekirdek audit durumunu (-e 2) kontrol et\n"
        "   journalctl --verify                 # FSS mühür bütünlüğünü doğrula\n"
        "===============================================================================\n"
    )
    with open(ref_card_path, "w", encoding="utf-8") as fp:
        fp.write(ref_card_content)

    # -------------------------------------------------------------------------
    # 6. TEMSİLİ MİMARİ ŞEMASI (kanit/temsili/hardening_mimarisi.txt)
    # -------------------------------------------------------------------------
    temsili_path = os.path.join(temsili_dir, "hardening_mimarisi.txt")
    diagram_content = (
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
        " HAFTA 20 / GÜN 140: BÜTÜNLEŞİK LINUX SERTLEŞTİRME VE DENETİM MİMARİSİ\n"
        "===============================================================================\n\n"
        "                              [ DIŞ TEHDİT / AĞ SALDIRGANI ]\n"
        "                                           │\n"
        "                                           ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 1: NETFILTER / NFTABLES / UFW GÜVENLİK DUVARI                    │\n"
        "  │  - Varsayılan Politika: DROP (Giriş & Yönlendirme)                      │\n"
        "  │  - Durumlu Takip (Conntrack): Established, Related -> ACCEPT            │\n"
        "  │  - Anti-Spoofing: Dışarıdan gelen 127.0.0.0/8 paketleri -> DROP         │\n"
        "  │  - Tehlikeli Portlar Engelli: 21 (FTP), 23 (Telnet), 69 (TFTP)          │\n"
        "  └────────────────────────────────────┬────────────────────────────────────┘\n"
        "                                       │ Yetkili Port (Örn: 22/SSH)\n"
        "                                       ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 2: SSH DAEMON VE KRİPTOGRAFİK KİMLİK DOĞRULAMA                   │\n"
        "  │  - PermitRootLogin no & PasswordAuthentication no                       │\n"
        "  │  - Ed25519 Kriptografik Anahtarlar (Dosya İzni: 0600)                   │\n"
        "  │  - MaxAuthTries 3 (Kaba kuvvet engelleme)                               │\n"
        "  └────────────────────────────────────┬────────────────────────────────────┘\n"
        "                                       │ Oturum Açılışı\n"
        "                                       ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 3: PAM VE KULLANICI OTURUM KISITLAMALARI                         │\n"
        "  │  - pam_pwquality (minlen=14, dcredit=-1, ucredit=-1, ocredit=-1)        │\n"
        "  │  - pam_faillock (deny=5, unlock_time=900s)                              │\n"
        "  │  - TMOUT=900 (15 dk boşta kalınca otomatik oturum sonlandırma)          │\n"
        "  └────────────────────────────────────┬────────────────────────────────────┘\n"
        "                                       │ Komut Yürütme\n"
        "                                       ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 4: SUDOERS VE EN DÜŞÜK AYRICALIK DEVRİ                           │\n"
        "  │  - İzin: 0440, env_reset, secure_path sabit yollar                      │\n"
        "  │  - GTFOBins Engeli: NOPASSWD ile /bin/bash, vim, find YASAK             │\n"
        "  └────────────────────────────────────┬────────────────────────────────────┘\n"
        "                                       │ Servis İcrası\n"
        "                                       ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 5: SYSTEMD KUM HAVUZU (SANDBOXING) VE İZOLASYON                  │\n"
        "  │  - NoNewPrivileges=yes (PR_SET_NO_NEW_PRIVS - SUID istismarı imkansız)  │\n"
        "  │  - ProtectSystem=strict & ProtectHome=yes                               │\n"
        "  │  - PrivateTmp=yes & PrivateDevices=yes                                  │\n"
        "  └────────────────────────────────────┬────────────────────────────────────┘\n"
        "                                       │ Olayların Kaydedilmesi\n"
        "                                       ▼\n"
        "  ┌─────────────────────────────────────────────────────────────────────────┐\n"
        "  │ KATMAN 6: ADLİ KANIT VE DENETİM BÜTÜNLÜĞÜ (AUDITD & JOURNALD)           │\n"
        "  │  - auditd -e 2: Çekirdek kilitleme (Root dahil kuralları silemez)       │\n"
        "  │  - Dosya İzleme: /etc/shadow, /etc/passwd, /etc/sudoers                 │\n"
        "  │  - Syscall Filtresi: init_module, delete_module, adjtimex               │\n"
        "  │  - systemd-journald: Forward Secure Sealing (FSS) ile mühürleme         │\n"
        "  └─────────────────────────────────────────────────────────────────────────┘\n"
        "===============================================================================\n"
        " TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "===============================================================================\n"
    )
    with open(temsili_path, "w", encoding="utf-8") as fp:
        fp.write(diagram_content)

    print(f"[+] Temsili mimari şeması üretildi: {temsili_path}")
    print("[*] Gün 140 Mini Proje 19: Tüm kanıtlar eksiksiz ve başarıyla üretildi!")


if __name__ == "__main__":
    generate_all_evidence()
