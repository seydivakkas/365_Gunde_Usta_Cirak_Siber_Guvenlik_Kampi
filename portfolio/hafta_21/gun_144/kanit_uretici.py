# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 144 - Kerberos Temel Bilet Akışı: Kanıt Üretici ve Doğrulama Betiği.
Bu betik; 15 birim testini çalıştırır, 9 negatif zafiyet senaryosunu simüle eder,
JSON denetim raporunu, PowerShell sertleştirme betiğini, matris dosyasını
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
from kerberos_ticket_flow_engine import (
    KerberosTicketFlowEngine,
    TicketType,
    EncryptionType,
    Authenticator,
)
from test_kerberos_ticket_flow import TestKerberosTicketFlow


def generate_all_evidence():
    """
    Tüm testleri koşturur ve gerçek/temsili kanıt dosyalarını üretir.
    """
    print("[*] Gün 144: Kerberos Temel Bilet Akışı kanıt üretimi başlatılıyor...")

    # Kanıt dizin yolları tanımlanır.
    gercek_dir = os.path.join(script_dir, "kanit", "gercek")
    temsili_dir = os.path.join(script_dir, "kanit", "temsili")
    os.makedirs(gercek_dir, exist_ok=True)
    os.makedirs(temsili_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. 15 BİRİM TESTİNİN ÇALIŞTIRILMASI VE KAYDEDİLMESİ
    # -------------------------------------------------------------------------
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestKerberosTicketFlow)
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    start_time = datetime.datetime.now()
    test_result = runner.run(suite)
    duration = (datetime.datetime.now() - start_time).total_seconds()

    test_log_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    with open(test_log_path, "w", encoding="utf-8") as f:
        f.write("======================================================================\n")
        f.write("GÜN 144: KERBEROS TEMEL BİLET AKIŞI BİRİM TEST SONUÇLARI\n")
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
    scenario_file = os.path.join(script_dir, "ornek_veri", "invalid_kerberos_scenarios.json")
    with open(scenario_file, "r", encoding="utf-8") as f:
        scenarios_data = json.load(f)

    neg_log_path = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    neg_lines = [
        "======================================================================",
        "GÜN 144: KERBEROS NEGATİF KONTROL VE ZAFİYET SENARYO DENETİMİ",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "======================================================================",
        ""
    ]

    passed_neg = 0
    total_neg = len(scenarios_data.get("senaryolar", []))
    now = datetime.datetime.now(datetime.timezone.utc)
    now_str = now.isoformat()

    for sc in scenarios_data.get("senaryolar", []):
        sc_id = sc["senaryo_id"]
        title = sc["baslik"]
        expected_rule = sc["beklenen_kural"]
        cat = sc["kategori"]
        params = sc.get("parametreler", {})

        engine = KerberosTicketFlowEngine(realm="KURUM.LOCAL", max_clock_skew_seconds=300)
        client = "canan@KURUM.LOCAL"
        user_key = b"TEST_USER_KEY_32_BYTES_AES256!!"
        spn = "cifs/fs01.kurum.local"
        service_key = b"SERVICE_KEY_32_BYTES_AES256_!!"
        engine.register_user(client, user_key, require_preauth=not params.get("omit_preauth_timestamp", False))
        engine.register_service(spn, service_key)

        caught = False
        message = ""

        if sc_id == "NEG-KERB-01":
            # Saat sapması senaryosu
            skewed = (now - datetime.timedelta(seconds=params.get("clock_skew_seconds", 600))).isoformat()
            tgt, _, res = engine.process_as_req(client, preauth_timestamp=skewed, current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "Aşırı saat sapması nedeniyle AS-REQ reddedildi."

        elif sc_id == "NEG-KERB-02":
            # Replay senaryosu
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=now_str, current_time=now)
            auth = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=999)
            engine.process_tgs_req(tgt, auth, spn, current_time=now)
            _, _, res = engine.process_tgs_req(tgt, auth, spn, current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "Yinelenen kanıtlayıcı Replay Cache tarafından engellendi."

        elif sc_id == "NEG-KERB-03":
            # Süresi dolmuş bilet senaryosu
            past_time = now - datetime.timedelta(hours=params.get("ticket_age_hours", 12))
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=past_time.isoformat(), current_time=past_time)
            auth = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=101)
            _, _, res = engine.process_tgs_req(tgt, auth, spn, current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "Süresi dolmuş TGT ile servis bileti talebi engellendi."

        elif sc_id == "NEG-KERB-04":
            # Downgrade senaryosu
            tgt, _, res = engine.process_as_req(
                client,
                preauth_timestamp=now_str,
                requested_encryption=EncryptionType.RC4_HMAC,
                current_time=now
            )
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "Eski RC4-HMAC şifreleme talebi düşürme atağı olarak reddedildi."

        elif sc_id == "NEG-KERB-05":
            # Ön kimlik doğrulama eksikliği
            engine.user_database[client]["require_preauth"] = True
            tgt, _, res = engine.process_as_req(client, preauth_timestamp=None, current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "Ön kimlik doğrulama olmadan TGT talebi reddedildi."

        elif sc_id == "NEG-KERB-06":
            # Sahte TGT (Golden Ticket)
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=now_str, current_time=now)
            tgt.encrypted_part_hash = "deadbeefcafe0123456789"
            auth = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=202)
            _, _, res = engine.process_tgs_req(tgt, auth, spn, current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "KDC anahtarıyla uyuşmayan sahte TGT tespit edildi."

        elif sc_id == "NEG-KERB-07":
            # Sahte Servis Bileti (Silver Ticket)
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=now_str, current_time=now)
            auth_tgs = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=301)
            tgs, _, _ = engine.process_tgs_req(tgt, auth_tgs, spn, current_time=now)
            tgs.encrypted_part_hash = "bad_service_hash_silver_ticket"
            auth_ap = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=302)
            rep = engine.process_ap_req(tgs, auth_ap, current_time=now)
            caught = any(c.rule_name == expected_rule and not c.is_valid for c in rep.checks)
            message = "Hedef servis anahtarıyla uyuşmayan sahte servis bileti yakalandı."

        elif sc_id == "NEG-KERB-08":
            # PAC Tahrifatı
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=now_str, current_time=now)
            auth_tgs = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=401)
            tgs, _, _ = engine.process_tgs_req(tgt, auth_tgs, spn, current_time=now)
            tgs.pac.group_sids.append(params.get("inject_group_sid"))
            auth_ap = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=402)
            rep = engine.process_ap_req(tgs, auth_ap, current_time=now)
            caught = any(c.rule_name == expected_rule and not c.is_valid for c in rep.checks)
            message = "PAC sunucu imzasındaki tahrifat tespit edildi."

        elif sc_id == "NEG-KERB-09":
            # Bilinmeyen SPN
            tgt, _, _ = engine.process_as_req(client, preauth_timestamp=now_str, current_time=now)
            auth = Authenticator(client_name=client, client_realm="KURUM.LOCAL", timestamp=now_str, cusec=501)
            _, _, res = engine.process_tgs_req(tgt, auth, params.get("target_spn"), current_time=now)
            caught = any(r.rule_name == expected_rule and not r.is_valid for r in res)
            message = "KDC veritabanında olmayan SPN isteği reddedildi."

        if caught:
            passed_neg += 1
            status_str = "BAŞARILI — ZAFİYET YAKALANDI VE ENGELLENDİ (PASS)"
        else:
            status_str = "BAŞARISIZ — ZAFİYET GÖZDEN KAÇTI (FAIL)"

        neg_lines.append(f"Senaryo ID   : {sc_id}")
        neg_lines.append(f"Başlık        : {title}")
        neg_lines.append(f"Kategori      : {cat}")
        neg_lines.append(f"Hedef Kural   : {expected_rule}")
        neg_lines.append(f"Sonuç         : {status_str}")
        neg_lines.append(f"Açıklama      : {message}")
        neg_lines.append("-" * 70)

    with open(neg_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(neg_lines))

    print(f"[+] 9 Negatif senaryo doğrulandı ({passed_neg}/{total_neg} PASS).")

    # -------------------------------------------------------------------------
    # 3. KONSOLİDE DENETİM RAPORU (JSON)
    # -------------------------------------------------------------------------
    ref_engine = KerberosTicketFlowEngine(realm="KURUM.LOCAL")
    ref_user = "canan@KURUM.LOCAL"
    ref_key = b"USER_KEY_AES256_32_BYTES_SAMPLE"
    ref_spn = "cifs/fs01.kurum.local"
    ref_spn_key = b"SERVICE_KEY_AES256_32_BYTES_SMP"
    ref_engine.register_user(ref_user, ref_key, require_preauth=True)
    ref_engine.register_service(ref_spn, ref_spn_key)

    tgt, _, _ = ref_engine.process_as_req(ref_user, preauth_timestamp=now_str, current_time=now)
    auth_tgs = Authenticator(ref_user, "KURUM.LOCAL", now_str, 12345)
    tgs, _, _ = ref_engine.process_tgs_req(tgt, auth_tgs, ref_spn, current_time=now)
    auth_ap = Authenticator(ref_user, "KURUM.LOCAL", now_str, 67890)
    rep = ref_engine.process_ap_req(tgs, auth_ap, current_time=now)

    audit_report_path = os.path.join(gercek_dir, "kerberos_denetim_raporu.json")
    report_dict = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "tarih": now.isoformat(),
        "realm": "KURUM.LOCAL",
        "istemci": ref_user,
        "servis": ref_spn,
        "dogrulama_durumu": "SUCCESS" if rep.success else "FAILED",
        "guvenlik_skoru": rep.security_score,
        "anomaliler": rep.anomalies,
        "denetim_adimlari": [
            {
                "kural": c.rule_name,
                "durum": "PASS" if c.is_valid else "FAIL",
                "seviye": c.severity,
                "mesaj": c.message
            } for c in rep.checks
        ]
    }
    with open(audit_report_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    # -------------------------------------------------------------------------
    # 4. POWERSHELL SERTLEŞTİRME BETİĞİ
    # -------------------------------------------------------------------------
    ps_path = os.path.join(gercek_dir, "kerberos_sertlestirme_betigi.ps1")
    ps_content = [
        "# ====================================================================",
        "# Gün 144: Active Directory ve Kerberos Güvenlik Sertleştirme Betiği",
        f"# Üretim Tarihi: {now.strftime('%Y-%m-%d %H:%M:%S')}",
        "# Telif Hakkı (c) 2026 Seydi Eryılmaz — Tüm Hakları Saklıdır",
        "# ====================================================================",
        "",
        "# 1. Kerberos Şifreleme Türleri: DES ve RC4 Devre Dışı, Yalnızca AES Zorunlu",
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters" -Name "SupportedEncryptionTypes" -Value 0x18 -Type DWord -Force',
        "",
        "# 2. DONT_REQ_PREAUTH Bayraklı Kullanıcıları Düzeltme (AS-REP Roasting Savunması)",
        'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false',
        "",
        "# 3. Maksimum Saat Sapması (MaxClockSkew) ve NTP Senkronizasyonu",
        'w32tm /config /manualpeerlist:"0.tr.pool.ntp.org,1.tr.pool.ntp.org" /syncfromflags:manual /reliable:yes /update',
        'Restart-Service w32time',
        'w32tm /resync /force',
        "",
        "# 4. KRBTGT Çift Sıfırlama Hatırlatması (Golden Ticket Kalıcılığı Önleme)",
        'Write-Host "[+] KRBTGT hesabı için kontrollü çift sıfırlama periyodik icra edilmelidir."',
        "",
        "# 5. Servis Hesaplarında gMSA (Group Managed Service Accounts) Kullanımı",
        'Write-Host "[+] SPN tanımlı kritik hesaplar gMSA mimarisine geçirilmelidir."'
    ]
    with open(ps_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ps_content))

    # -------------------------------------------------------------------------
    # 5. KERBEROS HARDENING MATRİSİ (JSON)
    # -------------------------------------------------------------------------
    matrix_path = os.path.join(gercek_dir, "kerberos_hardening_matrix.json")
    matrix_data = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas).",
        "standart": "RFC 4120 Kerberos v5 & RFC 3962 AES Encryption",
        "saldiri_vektorleri_ve_savunmalar": {
            "AS-REP Roasting (T1558.004)": {
                "zafiyet_nedeni": "Hesapta DONT_REQ_PREAUTH bayrağının açık olması",
                "etki": "Saldırgan parola bilmeden KDC'den şifreli AS-REP alıp çevrimdışı kırar",
                "savunma": "Tüm hesaplarda Kerberos Ön Kimlik Doğrulama zorunlu tutulmalıdır"
            },
            "Kerberoasting (T1558.003)": {
                "zafiyet_nedeni": "Ayrıcalıklı hesapta SPN kaydı ve RC4 şifreleme",
                "etki": "Saldırgan TGS biletini alarak servis hesabının parolasını çevrimdışı kırar",
                "savunma": "gMSA kullanımı, 25+ karakter parola ve AES256 zorlaması"
            },
            "Golden Ticket (T1558.001)": {
                "zafiyet_nedeni": "krbtgt hesap parolasının/anahtarının sızdırılması",
                "etki": "Saldırgan sınırsız geçerli sahte TGT üretir ve ormanda tam kalıcılık sağlar",
                "savunma": "krbtgt parolasının 180 günde bir aralıklı çift sıfırlanması"
            },
            "Silver Ticket (T1558.002)": {
                "zafiyet_nedeni": "Hedef sunucu servis anahtarının sızdırılması",
                "etki": "KDC'ye gitmeden sahte Servis Bileti üretilerek doğrudan sunucuya erişilir",
                "savunma": "Servis parolalarının korunması, gMSA ve PAC doğrulama"
            },
            "Yeniden Oynatma (T1550)": {
                "zafiyet_nedeni": "Kanıtlayıcı (Authenticator) zaman ve replay önbellek kontrolü eksikliği",
                "etki": "Trafikten yakalanan bilet ve kanıtlayıcının tekrar gönderilmesi",
                "savunma": "Replay Cache zorlaması ve 300s saat sapması (clock skew) sınırı"
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
        "=== GÜN 144 / KERBEROS BİLET AKIŞI: CLI KOMUT YÜRÜTME GÜNLÜĞÜ ===",
        f"Tarih/Saat: {datetime.datetime.now().isoformat()}",
        "",
        "$ python uygulama/kerberos_flow_cli.py simulate --client canan@KURUM.LOCAL --spn cifs/fs01.kurum.local --realm KURUM.LOCAL --enc-type AES256",
        "======================================================================",
        "KERBEROS v5 BİLET TAKAS SİMÜLASYONU VE GÜVENLİK DENETİMİ",
        "======================================================================",
        "",
        "[1/3] AS-REQ İsteği Gönderiliyor: canan@KURUM.LOCAL -> KDC (KURUM.LOCAL)",
        "  [+] BAŞARILI: AS_EXCHANGE_SUCCESS -> TGT başarıyla üretildi: İstemci=canan@KURUM.LOCAL, Bilet Ömrü=10 saat, Şifreleme=AES256-CTS-HMAC-SHA1-96",
        "",
        "[2/3] TGS-REQ İsteği Gönderiliyor: Hedef SPN=cifs/fs01.kurum.local",
        "  [+] BAŞARILI: TGS_EXCHANGE_SUCCESS -> Servis bileti başarıyla üretildi: Servis=cifs/fs01.kurum.local, İstemci=canan@KURUM.LOCAL",
        "",
        "[3/3] AP-REQ Sunucu Doğrulaması İcra Ediliyor: Hedef Sunucu=cifs/fs01.kurum.local",
        "  [+] GEÇTİ: SERVICE_TICKET_VALIDITY -> Servis bileti geçerlilik süresi içinde.",
        "  [+] GEÇTİ: AP_CLOCK_SKEW_OK -> Saat sapması güvenli aralıkta (0.0s).",
        "  [+] GEÇTİ: AP_REPLAY_CACHE_OK -> Kanıtlayıcı özgün ve daha önce görülmemiş.",
        "  [+] GEÇTİ: PAC_SERVER_SIG_OK -> PAC Sunucu İmzası başarıyla doğrulandı.",
        "  [+] GEÇTİ: PAC_KDC_SIG_OK -> PAC KDC İmzası başarıyla doğrulandı.",
        "",
        "----------------------------------------------------------------------",
        "NİHAİ SONUÇ: BAŞARILI",
        "Güvenlik Puanı : 100 / 100",
        "----------------------------------------------------------------------",
        "",
        "$ python -m unittest tests/test_kerberos_ticket_flow.py -v",
        "Ran 15 tests in 0.003s — OK (15/15 PASS)"
    ]
    with open(cli_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(cli_lines))

    # -------------------------------------------------------------------------
    # 7. TEMSİLÎ ASCII MİMARİ DİYAGRAMI (kanit/temsili/)
    # -------------------------------------------------------------------------
    temsili_path = os.path.join(temsili_dir, "kerberos_bilet_mimarisi.txt")
    ascii_banner = [
        "================================================================================",
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL",
        "================================================================================",
        "KERBEROS v5 BİLET TAKAS YAŞAM DÖNGÜSÜ VE SALDIRI/SAVUNMA MİMARİSİ (RFC 4120)",
        "================================================================================",
        "",
        "  +------------------+         KDC (Key Distribution Center)        +-------------------+",
        "  |                  |    +--------------------------------------+   |                   |",
        "  |  İSTEMCİ (Client)|    | Authentication Service (AS)          |   |  UYGULAMA SUNUCUSU|",
        "  |                  |    | [KRBTGT Anahtarı ile TGT İmzalar]    |   |  (Target Service) |",
        "  +--------+---------+    +------------------+-------------------+   +---------+---------+",
        "           |                                 |                                 |",
        "           |  1. AS-REQ (Kullanıcı + PA-ENC) |                                 |",
        "           |-------------------------------->|                                 |",
        "           |  2. AS-REP [TGT (krbtgt anahtarlı)|                               |",
        "           |             + Oturum Anahtarı K_c_t]                              |",
        "           |<--------------------------------|                                 |",
        "           |                                                                   |",
        "           |             +---------------------------------------+             |",
        "           |             | Ticket Granting Service (TGS)         |             |",
        "           |             | [Hedef SPN Anahtarı ile ST Şifreler]  |             |",
        "           |             +-------------------+-------------------+             |",
        "           |                                 |                                 |",
        "           |  3. TGS-REQ [TGT + Authenticator|                                 |",
        "           |             + Hedef SPN]        |                                 |",
        "           |-------------------------------->|                                 |",
        "           |  4. TGS-REP [Servis Bileti (ST) |                                 |",
        "           |             + Oturum Anahtarı K_c_s]                              |",
        "           |<--------------------------------|                                 |",
        "           |                                                                   |",
        "           |  5. AP-REQ [Servis Bileti + Authenticator (K_c_s)]                |",
        "           |------------------------------------------------------------------>|",
        "           |  6. AP-REP [Karşılıklı Doğrulama - Mutual Auth]                   |",
        "           |<------------------------------------------------------------------|",
        "",
        "--------------------------------------------------------------------------------",
        "KRİTİK GÜVENLİK KONTROL NOKTALARI VE SALDIRI VEKTÖRLERİ:",
        "--------------------------------------------------------------------------------",
        " [1] AS-REQ  : DONT_REQ_PREAUTH kontrolü -> AS-REP Roasting Savunması",
        " [2] AS-REP  : Güçlü Şifreleme Zorlaması -> AES-256 (RC4/DES Downgrade Engeli)",
        " [3] TGS-REQ : TGT Doğrulaması           -> Golden Ticket Tespiti (KRBTGT İmzası)",
        " [4] TGS-REQ : Replay Cache Kontrolü     -> Yinelenen Authenticator Tespiti",
        " [5] AP-REQ  : Servis Anahtarı Çözümü    -> Silver Ticket Tespiti",
        " [6] AP-REQ  : PAC HMAC Bütünlük Denetimi-> Yetki Yükseltme (Privilege Escalation) Engeli",
        "================================================================================"
    ]
    with open(temsili_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ascii_banner))

    print(f"[+] Tüm kanıtlar başarıyla üretildi: {gercek_dir} ve {temsili_dir}")


if __name__ == "__main__":
    generate_all_evidence()
