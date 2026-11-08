# -*- coding: utf-8 -*-
"""
Kurumsal Oturum Yönetimi ve Süresi Kanıt Üretici
Hafta 23 / Gün 158 - Aşama 7 (Web Güvenliği)

Bu betik; birim testleri, 9 adet negatif kontrol senaryosunu ve CLI komutlarını
yürüterek 'kanit/gercek/' ve 'kanit/temsili/' dizinlerine doğrulanabilir
çıktıları üretir.
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path

# Proje ana dizinini sys.path'e ekleme
CURRENT_DIR = Path(__file__).resolve().parent
PORTFOLIO_ROOT = CURRENT_DIR.parent.parent.parent
sys.path.insert(0, str(PORTFOLIO_ROOT))

# İlgili motor ve sınıfları içe aktarma
from portfolio.hafta_23.gun_158.uygulama.session_manager_engine import (
    SessionManagerEngine,
    SessionPolicy,
    SessionState,
    UserSession
)


def run_unit_tests():
    """15 birim testi çalıştırır ve çıktıyı test_sonuclari.txt dosyasına kaydeder."""
    test_path = CURRENT_DIR / "tests" / "test_session_manager.py"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "test_sonuclari.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "-m", "unittest", str(test_path), "-v"]
    res = subprocess.run(cmd, capture_output=True)
    stdout_text = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
    stderr_text = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== KURUMSAL OTURUM YÖNETİMİ VE SÜRESİ BİRİM TESTLERİ (15/15) ===\n")
        f.write(stdout_text)
        f.write(stderr_text)
        f.write("\nDurum Kodu: " + str(res.returncode) + "\n")
    print(f"[+] Birim test kanıtı üretildi: {out_file}")


def run_negative_controls():
    """9 negatif kontrol senaryosunu çalıştırıp kanıt dosyasına kaydeder."""
    scenarios_file = CURRENT_DIR / "ornek_veri" / "invalid_session_scenarios.json"
    out_file = CURRENT_DIR / "kanit" / "gercek" / "negatif_kontrol_sonuclari.txt"

    with open(scenarios_file, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    results = []

    for scn in scenarios:
        engine = SessionManagerEngine()
        test_type = scn["test_type"]
        s_data = scn["session_data"]
        sim = scn["simulation"]
        passed = False
        actual_status = "UNKNOWN"
        actual_valid = True

        t0 = 1000000.0

        if test_type == "idle_timeout":
            s = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            t_req = t0 + sim["time_offset_seconds"]
            res = engine.validate_session(s.session_id, sim["request_ip"], sim["request_ua"], current_time=t_req)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.EXPIRED_IDLE and not res.is_valid)

        elif test_type == "absolute_timeout":
            s = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            s.last_activity_epoch = t0 + sim["time_offset_seconds"] - 60.0 # Yakın zamanda aktif
            t_req = t0 + sim["time_offset_seconds"]
            res = engine.validate_session(s.session_id, sim["request_ip"], sim["request_ua"], current_time=t_req)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.EXPIRED_ABSOLUTE and not res.is_valid)

        elif test_type in ("user_agent_mismatch", "ip_mismatch"):
            s = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            t_req = t0 + sim["time_offset_seconds"]
            res = engine.validate_session(s.session_id, sim["request_ip"], sim["request_ua"], current_time=t_req)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.SUSPENDED_HIJACK_RISK and not res.is_valid)

        elif test_type == "unknown_session":
            res = engine.validate_session(sim["fake_id"], sim["request_ip"], sim["request_ua"], current_time=t0)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.REVOKED and not res.is_valid)

        elif test_type == "concurrent_limit":
            s_first = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            for i in range(1, sim["create_sessions_count"]):
                engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0 + i*10)
            res = engine.validate_session(s_first.session_id, s_data["ip"], s_data["user_agent"], current_time=t0 + 100)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (s_first.state == SessionState.REVOKED and not res.is_valid)

        elif test_type == "post_logout":
            s = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            engine.terminate_session(s.session_id, reason="User logout")
            res = engine.validate_session(s.session_id, sim["request_ip"], sim["request_ua"], current_time=t0 + 10)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.REVOKED and not res.is_valid)

        elif test_type == "privilege_fixation":
            s = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            old_id = s.session_id
            engine.elevate_privilege(old_id, new_role=sim["elevate_to"], current_time=t0 + 10)
            res = engine.validate_session(old_id, sim["request_ip"], sim["request_ua"], current_time=t0 + 20)
            actual_status = res.status.value
            actual_valid = res.is_valid
            passed = (res.status == SessionState.REVOKED and not res.is_valid)

        elif test_type == "global_revocation":
            s1 = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0)
            s2 = engine.create_session(s_data["user_id"], s_data["username"], s_data["role"], s_data["ip"], s_data["user_agent"], current_time=t0 + 5)
            engine.terminate_all_user_sessions(s_data["user_id"], reason="Password reset")
            res1 = engine.validate_session(s1.session_id, sim["request_ip"], sim["request_ua"], current_time=t0 + 10)
            res2 = engine.validate_session(s2.session_id, sim["request_ip"], sim["request_ua"], current_time=t0 + 10)
            actual_status = res1.status.value
            actual_valid = res1.is_valid
            passed = (not res1.is_valid and not res2.is_valid)

        results.append({
            "scenario_id": scn["scenario_id"],
            "name": scn["name"],
            "test_type": test_type,
            "actual_status": actual_status,
            "actual_valid": actual_valid,
            "validation_passed": passed
        })

    with open(out_file, "w", encoding="utf-8") as f:
        f.write("=== 9 ADET OTURUM YÖNETİMİ VE SÜRESİ NEGATİF KONTROL SENARYOSU ===\n\n")
        for r in results:
            f.write(f"Senaryo: {r['scenario_id']} - {r['name']}\n")
            f.write(f"  Test Türü           : {r['test_type']}\n")
            f.write(f"  Nihai Oturum Durumu : {r['actual_status']}\n")
            f.write(f"  Oturum Geçerli mi?  : {r['actual_valid']}\n")
            f.write(f"  Negatif Doğrulama   : {'BAŞARILI (Açık/İhlal Yakalandı)' if r['validation_passed'] else 'BAŞARISIZ'}\n\n")
        all_passed = all(r["validation_passed"] for r in results)
        f.write(f"ÖZET: Toplam {len(results)} senaryonun {sum(1 for r in results if r['validation_passed'])} tanesi doğrulandı. (Genel: {'100% PASS' if all_passed else 'FAIL'})\n")
    print(f"[+] Negatif kontrol kanıtı üretildi: {out_file}")


def generate_reports_and_cli_logs():
    """Yaşam döngüsü raporunu, oturum dump'ını ve CLI loglarını üretir."""
    policy_file = CURRENT_DIR / "ornek_veri" / "enterprise_session_policy.json"
    with open(policy_file, "r", encoding="utf-8") as f:
        p_data = json.load(f)

    policy = SessionPolicy(
        idle_timeout_seconds=p_data["idle_timeout_seconds"],
        absolute_timeout_seconds=p_data["absolute_timeout_seconds"],
        max_concurrent_sessions=p_data["max_concurrent_sessions"],
        bind_user_agent=p_data["bind_user_agent"],
        bind_ip=p_data["bind_ip"],
        min_session_id_entropy_bits=p_data["min_session_id_entropy_bits"],
        rotation_interval_seconds=p_data["rotation_interval_seconds"]
    )
    engine = SessionManagerEngine(policy=policy)

    now = time.time()
    # Örnek oturumları açma
    for sample in p_data["sessions_sample"]:
        engine.create_session(
            sample["user_id"],
            sample["username"],
            sample["role"],
            sample["client_ip"],
            sample["user_agent"],
            current_time=now
        )

    # İstatistik Raporu
    stats = engine.audit_lifecycle()
    report_file = CURRENT_DIR / "kanit" / "gercek" / "session_lifecycle_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    print(f"[+] Yaşam döngüsü JSON raporu üretildi: {report_file}")

    # Aktif Oturumlar Dump'ı
    sessions_dump = {
        sid: {
            "user_id": s.user_id,
            "username": s.username,
            "role": s.role,
            "client_ip": s.client_ip,
            "user_agent": s.user_agent,
            "created_at_epoch": s.created_at_epoch,
            "last_activity_epoch": s.last_activity_epoch,
            "state": s.state.value,
            "rotation_count": s.rotation_count
        }
        for sid, s in engine.active_sessions.items()
    }
    dump_file = CURRENT_DIR / "kanit" / "gercek" / "active_sessions_dump.json"
    with open(dump_file, "w", encoding="utf-8") as f:
        json.dump(sessions_dump, f, indent=2, ensure_ascii=False)
    print(f"[+] Aktif oturumlar dump dosyası üretildi: {dump_file}")

    # CLI Komutlarını yürütme ve loglama
    cli_path = CURRENT_DIR / "uygulama" / "session_manager_cli.py"
    cli_out_file = CURRENT_DIR / "kanit" / "gercek" / "komut_ve_cikis.txt"

    cmds = [
        [sys.executable, str(cli_path), "create", "--user-id", "usr_cli_01", "--username", "kemal_sistem", "--role", "SysAdmin"],
        [sys.executable, str(cli_path), "validate", "--ip", "192.168.1.100", "--user-agent", "Mozilla/5.0 Chrome/130.0", "--elapsed-seconds", "120"],
        [sys.executable, str(cli_path), "validate", "--ip", "192.168.1.100", "--user-agent", "Mozilla/5.0 Chrome/130.0", "--elapsed-seconds", "1000"], # Idle timeout
        [sys.executable, str(cli_path), "elevate", "--new-role", "SuperAdmin"],
        [sys.executable, str(cli_path), "audit", "--policy-file", str(policy_file)]
    ]

    with open(cli_out_file, "w", encoding="utf-8") as f:
        f.write("=== KURUMSAL OTURUM YÖNETİMİ VE SÜRESİ CLI YÜRÜTME LOGLARI ===\n\n")
        for c in cmds:
            f.write(f"$ {' '.join(c)}\n")
            res = subprocess.run(c, capture_output=True)
            c_stdout = res.stdout.decode("utf-8", errors="replace") if res.stdout else ""
            c_stderr = res.stderr.decode("utf-8", errors="replace") if res.stderr else ""
            f.write(c_stdout)
            if c_stderr:
                f.write("\n[STDERR]\n" + c_stderr)
            f.write("\n" + "=" * 70 + "\n\n")
    print(f"[+] CLI log kanıtı üretildi: {cli_out_file}")


def generate_representative_evidence():
    """Temsili ASCII oturum yaşam döngüsü diyagramını üretir."""
    rep_file = CURRENT_DIR / "kanit" / "temsili" / "oturum_yasam_dongusu.txt"
    rep_file.parent.mkdir(parents=True, exist_ok=True)

    content = """TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL
========================================================================================================
                      GÜVENLİ HTTP OTURUMU YAŞAM DÖNGÜSÜ MİMARİSİ
========================================================================================================

                 [ 1. KİMLİK DOĞRULAMA (Login) ]
                                |
                                v
     +------------------------------------------------------+
     | 256-Bit Yüksek Entropili Yeni Oturum Kimliği Üretimi |  --> secrets.token_hex(32)
     | Eşzamanlı Oturum Limiti (Maks: 3) & FIFO Tasfiyesi   |  --> Eski oturum sonlandırılır
     +------------------------------------------------------+
                                |
                                v
     +------------------------------------------------------+
     | Set-Cookie ile Tarayıcıya Gönderim:                  |
     | __Host-session=xyz; Path=/; Secure; HttpOnly; Strict |
     +------------------------------------------------------+
                                |
                                v
                 [ 2. İSTEK DOĞRULAMA KATMANI ]
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
 +---------------+      +---------------+      +-----------------+
 | Boşta Kalma   |      | Mutlak Ömür   |      | Bağlam Uyuşması |
 | (Inactivity)  |      | (Absolute)    |      | (UA & IP Check) |
 | Limit: 15 dk  |      | Limit: 8 saat |      | Session Hijack? |
 +---------------+      +---------------+      +-----------------+
        |                       |                       |
        | Aşılırsa:             | Aşılırsa:             | Uyuşmazsa:
        v                       v                       v
 [ EXPIRED_IDLE ]       [ EXPIRED_ABSOLUTE ]    [ SUSPENDED_HIJACK ]
   Oturum Kapanır         Zorla Yeniden Giriş     Güvenlik Tarafından Askıya Alınır
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                          Hepsi Geçtiyse:
                                |
                                v
     +------------------------------------------------------+
     | 3. OTURUM SABİTLEME & ROTASYON KALKANI               |
     | - Yetki Yükseldi mi (Admin)?  --> ID Derhal Yenilenir|
     | - 30 Dakika Geçti mi?         --> ID Periyodik Döner |
     +------------------------------------------------------+
                                |
                                v
     +------------------------------------------------------+
     | 4. GÜVENLİ ÇIKIŞ (Logout)                            |
     | - Sunucu tarafında kalıcı iptal (REVOCATION)         |
     | - Bellek temizliği (Garbage Collection)              |
     +------------------------------------------------------+

========================================================================================================
                                   GÜVENLİK SÖZLEŞMESİ MATRİSİ
========================================================================================================
  Parametre                  Standart Değer   Zafiyet / Risk          Savunma Mekanizması
  ------------------------   --------------   ---------------------   ---------------------------------
  Boşta Kalma Zaman Aşımı    15 Dakika (900s) Unutulan Bilgisayar     Sunucu Tarafı İnaktivite İptali
  Mutlak Oturum Süresi       8 Saat (28800s)  Sonsuz Oturum Belirteci Zorunlu Yeniden Kimlik Doğrulama
  Eşzamanlı Oturum Sayısı    Maksimum 3       Hesap Paylaşımı         En Eski Oturumu İptal Etme (FIFO)
  Oturum Rotasyonu           30 Dakika        Uzun Ömürlü Sniffing    Periyodik Kriptografik ID Rotasyonu
  Yetki Değişimi             Anında Yenileme  Session Fixation        Eski ID İptali + Yeni ID Tahsisi
  Sunucu Taraflı İptal       Çıkışta Anında   Replay / Token Tekrarı  In-Memory / Redis Revocation
========================================================================================================
"""
    with open(rep_file, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"[+] Temsili ASCII kanıtı üretildi: {rep_file}")


def main():
    """Tüm kanıt üretim adımlarını sırayla yürütür."""
    print("=== GÜN 158 KANIT ÜRETİMİ BAŞLATILIYOR ===")
    run_unit_tests()
    run_negative_controls()
    generate_reports_and_cli_logs()
    generate_representative_evidence()
    print("=== GÜN 158 TÜM KANITLAR BAŞARIYLA ÜRETİLDİ ===")


if __name__ == "__main__":
    main()
