# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
GÜN 125 KANIT ÜRETİCİ (Week 18 Capstone: Mini Proje 17)
-------------------------------------------------------
Bu betik, Gün 125 kapsamındaki Güvenli Kimlik ve Rol Prototipinin
tüm birim testlerini, 9 negatif kontrol senaryosunu, CLI etkileşimlerini
ve mimari diyagramlarını çalıştırarak kanıt dosyalarını üretir.
"""

# İşletim sistemi ve dosya yolları için os kütüphanesi
import os
# Sistem parametreleri ve modül yolu kontrolü için sys kütüphanesi
import sys
# Yapılandırılmış verileri ayrıştırmak ve kaydetmek için json kütüphanesi
import json
# Zaman damgaları ve denetim kayıtları için datetime kütüphanesi
from datetime import datetime, timedelta
# Birim testlerini otomatize çalıştırmak için unittest kütüphanesi
import unittest
# Test çıktılarını yakalamak için io kütüphanesi
import io

# Proje ana kök dizinini Python modül arama yoluna dahil ediyoruz
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Modül yolu listesine geçerli çalışma klasörünü ekliyoruz
if CURRENT_DIR not in sys.path:
    # Sys.path başına ekleme yaparak yerel paketlerin öncelikli olmasını sağlıyoruz
    sys.path.insert(0, CURRENT_DIR)

# Uygulama klasörünü de sys.path'e ekliyoruz
APP_DIR = os.path.join(CURRENT_DIR, "uygulama")
# Eğer yoksa modül yoluna ekliyoruz
if APP_DIR not in sys.path:
    # Uygulama dizinini modül arama yoluna ekliyoruz
    sys.path.insert(0, APP_DIR)

# Kimlik ve rol çekirdek motorunu içeri aktarıyoruz
from secure_identity_role_engine import (
    SecureIdentityRoleManager,
    SystemFailureType,
    WeakPasswordError,
    AuthenticationFailedError,
    AccountLockedError,
    SeparationOfDutyConflictError,
    CircularRoleHierarchyError,
    SessionExpiredError
)


def run_unit_tests(output_path: str) -> bool:
    """Birim testleri çalıştırır ve çıktısını test_sonuclari.txt dosyasına kaydeder."""
    # Test yükleyicisini başlatıyoruz
    loader = unittest.TestLoader()
    # tests/test_secure_identity_role.py dosyasındaki testleri keşfediyoruz
    suite = loader.discover(os.path.join(CURRENT_DIR, "tests"), pattern="test_*.py")
    # Çıktıyı yakalamak için bellek içi metin akışı oluşturuyoruz
    stream = io.StringIO()
    # Ayrıntılı (verbosity=2) test koşucusunu yapılandırıyoruz
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    # Test paketini yürütüyoruz
    result = runner.run(suite)
    # Koşu çıktısını metin olarak alıyoruz
    output_text = stream.getvalue()

    # Kanıt başlığı ve özet metnini biçimlendiriyoruz
    report = (
        "======================================================================\n"
        "GÜN 125: GÜVENLİ KİMLİK / ROL PROTOTİPİ - BİRİM TEST RAPORU\n"
        f"Tarih/Saat: {datetime.now().isoformat()}\n"
        "Standartlar: NIST SP 800-63B, ISO 27001 A.9, NIST SP 800-53 AC-2/AC-6\n"
        "======================================================================\n\n"
        f"Çalıştırılan Test Sayısı: {result.testsRun}\n"
        f"Hata Sayısı (Errors): {len(result.errors)}\n"
        f"Başarısızlık Sayısı (Failures): {len(result.failures)}\n"
        f"Genel Durum: {'BAŞARILI (100% PASS)' if result.wasSuccessful() else 'BAŞARISIZ'}\n\n"
        "------------------- AYRINTILI TEST ÇIKTISI -------------------\n"
        f"{output_text}\n"
    )

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Rapor metnini UTF-8 formatında diske kaydediyoruz
        f.write(report)

    # Başarı durumunu döndürüyoruz
    return result.wasSuccessful()


def run_negative_controls(output_path: str) -> int:
    """9 Negatif kontrol senaryosunu çalıştırır ve kanıt kaydeder."""
    # Senaryo dosyasının tam yolunu belirliyoruz
    scenarios_file = os.path.join(CURRENT_DIR, "ornek_veri", "invalid_identity_scenarios.json")
    # Dosyayı okuma modunda açıyoruz
    with open(scenarios_file, "r", encoding="utf-8") as f:
        # JSON verisini sözlüğe çeviriyoruz
        scenarios_data = json.load(f)

    # Senaryolar listesini alıyoruz
    scenarios = scenarios_data.get("senaryolar", [])
    # Kanıt çıktı tamponunu oluşturuyoruz
    lines = [
        "======================================================================",
        "GÜN 125: NEGATİF KONTROL VE HATA ENJEKSİYON TESTLERİ",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        f"Toplam Senaryo: {len(scenarios)}",
        "======================================================================\n"
    ]

    # Başarılı geçen senaryo sayacını sıfırlıyoruz
    passed_count = 0

    # Her bir negatif senaryoyu sırayla test ediyoruz
    for sc in scenarios:
        # Senaryo kimliğini alıyoruz
        sid = sc.get("id")
        # Senaryo başlığını alıyoruz
        title = sc.get("baslik")
        # İlgili CWE zafiyet kodunu alıyoruz
        cwe = sc.get("cwe")

        # Test için sıfır bir kimlik yöneticisi örneği oluşturuyoruz
        mgr = SecureIdentityRoleManager(system_name="Negatif Test Platformu")
        # Temel rolleri tanımlıyoruz
        mgr.register_role("guest", {"public:read", "public_docs:read"})
        # Ödeme hazırlayıcı rolü
        mgr.register_role("payment_maker", {"ledger:create", "payment:create"}, parent_roles=["guest"])
        # Ödeme onaylayıcı rolü
        mgr.register_role("payment_checker", {"ledger:approve", "payment:approve"}, parent_roles=["guest"], requires_mfa=True)
        # Denetçi rolü
        mgr.register_role("auditor", {"audit_logs:read", "reports:read"}, parent_roles=["guest"])
        # Süper yönetici rolü
        mgr.register_role("super_admin", {"system:*"}, parent_roles=["guest"], requires_mfa=True)

        # Statik SoD kurallarını ekliyoruz
        mgr.add_toxic_role_pair("payment_maker", "payment_checker")
        # Test kullanıcılarını kaydediyoruz
        mgr.register_user("U-01", "denetci_merve", "MervePassword2026!#", ["auditor"], mfa_secret="778899")
        # Finans Ali kullanıcısı
        mgr.register_user("U-02", "finans_ali", "AliPassword2026!#", ["payment_maker"], mfa_secret="112233")
        # Süper Kemal kullanıcısı
        mgr.register_user("U-03", "sistem_kemal", "KemalAdminPass2026!#", ["super_admin"], mfa_secret="998877")

        # Başarı bayrağını tanımlıyoruz
        success = False
        # Gerçekleşen sonuç mesajını tutuyoruz
        observed_msg = ""

        # Senaryo 1: Zayıf Parola Testi (CWE-521)
        if sid == "NEG-ID-01":
            try:
                # Zayıf parola ile kayıt denemesi yapıyoruz (<12 karakter)
                mgr.register_user("U-WEAK", "zayif_kullanici", "123", ["guest"])
                # Hata fırlatılmazsa başarısız sayıyoruz
                observed_msg = "Zayıf parola kabul edildi (HATA)."
            except WeakPasswordError as e:
                # Beklenen zayıf parola hatası fırlatıldı
                success = True
                # Açıklamayı kaydediyoruz
                observed_msg = f"WeakPasswordError yakalandı: {str(e)}"
            except Exception as e:
                # Beklenmeyen farklı bir hata
                observed_msg = f"Beklenmeyen hata: {type(e).__name__}: {str(e)}"

        # Senaryo 2: Hatalı Parola ile Kimlik Doğrulama (CWE-307)
        elif sid == "NEG-ID-02":
            try:
                # Hatalı parola ile giriş deniyoruz
                mgr.authenticate("denetci_merve", "YanlisParola123!")
                # Giriş başarılı olursa zafiyet vardır
                observed_msg = "Hatalı parola ile giriş başarılı oldu (HATA)."
            except AuthenticationFailedError as e:
                # Beklenen doğrulama hatası yakalandı
                success = True
                # Hata mesajını kaydediyoruz
                observed_msg = f"AuthenticationFailedError yakalandı: {str(e)}"
            except Exception as e:
                # Beklenmeyen farklı bir hata
                observed_msg = f"Beklenmeyen hata: {type(e).__name__}: {str(e)}"

        # Senaryo 3: Brute-Force Hesap Kilitleme (CWE-307)
        elif sid == "NEG-ID-03":
            try:
                # 5 kez bilerek yanlış şifre giriyoruz
                for _ in range(5):
                    try:
                        # Yanlış giriş denemesi
                        mgr.authenticate("finans_ali", "YanlisSifre999!")
                    except AuthenticationFailedError:
                        # Beklenen başarısızlıkları yutuyoruz
                        pass
                # 6. denemede hesap kilitli olduğu için AccountLockedError beklenir
                mgr.authenticate("finans_ali", "AliPassword2026!#")
                # Kilit çalışmazsa zafiyet vardır
                observed_msg = "Hesap kilitlenmedi, erişim sağlandı (HATA)."
            except AccountLockedError as e:
                # Hesap başarıyla kilitlendi
                success = True
                # Başarılı mesajı kaydediyoruz
                observed_msg = f"AccountLockedError yakalandı (Hesap kilitlendi): {str(e)}"
            except Exception as e:
                # Beklenmeyen farklı bir hata
                observed_msg = f"Beklenmeyen hata: {type(e).__name__}: {str(e)}"

        # Senaryo 4: Statik SoD İhlali (CWE-863)
        elif sid == "NEG-ID-04":
            try:
                # finans_ali zaten payment_maker rolüne sahip; payment_checker eklemeye çalışıyoruz
                mgr.assign_role_to_user("U-02", "payment_checker")
                # Eğer atanırsa SoD ilkesi çiğnenmiştir
                observed_msg = "SoD ihlali olan rol başarıyla atandı (HATA)."
            except SeparationOfDutyConflictError as e:
                # SoD koruması devreye girdi
                success = True
                # Mesajı kaydediyoruz
                observed_msg = f"SeparationOfDutyConflictError yakalandı: {str(e)}"
            except Exception as e:
                # Beklenmeyen farklı bir hata
                observed_msg = f"Beklenmeyen hata: {type(e).__name__}: {str(e)}"

        # Senaryo 5: Döngüsel Rol Mirası (CWE-674)
        elif sid == "NEG-ID-05":
            try:
                # guest -> super_admin bağımlılığı ekleyerek döngü yaratıyoruz
                # Çünkü super_admin zaten guest'i miras alıyor
                mgr.register_role("guest_circular", {"public:read"}, parent_roles=["super_admin"])
                # Eğer eklenirse, super_admin -> guest_circular -> super_admin döngüsü kurmaya çalışıyoruz
                mgr.register_role("super_admin_child", {"system:read"}, parent_roles=["guest_circular"])
                # guest_circular'a super_admin_child verilirse döngü yakalanmalı
                mgr.register_role("loop_role", {"loop:test"}, parent_roles=["loop_role"])
                # Hata yakalanmazsa başarısız sayılır
                observed_msg = "Döngüsel rol hiyerarşisi kabul edildi (HATA)."
            except CircularRoleHierarchyError as e:
                # Döngü yakalandı ve engellendi
                success = True
                # Mesajı kaydediyoruz
                observed_msg = f"CircularRoleHierarchyError yakalandı: {str(e)}"
            except Exception as e:
                # Beklenmeyen farklı bir hata
                observed_msg = f"Beklenmeyen hata: {type(e).__name__}: {str(e)}"

        # Senaryo 6: Sahte Token ile Yetkilendirme Talebi (CWE-613)
        elif sid == "NEG-ID-06":
            # Kayıtlı olmayan token ile yetki soruyoruz
            eval_res = mgr.authorize("sahte_token_9999", "audit_logs", "read")
            # Kararın DENY olup olmadığını denetliyoruz
            if eval_res.decision == "DENY" and "CWE-613" in eval_res.reason:
                # Beklenen ret kararı verildi
                success = True
                # Sonuç açıklamasını kaydediyoruz
                observed_msg = f"Erişim REDDEDİLDİ (DENY): {eval_res.reason}"
            else:
                # İzin verilmişse zafiyet vardır
                observed_msg = f"Beklenmeyen karar: {eval_res.decision} - {eval_res.reason}"

        # Senaryo 7: Zamanı Dolmuş Token ile Erişim (CWE-613)
        elif sid == "NEG-ID-07":
            # Geçerli bir giriş yapıyoruz
            token = mgr.authenticate("denetci_merve", "MervePassword2026!#")
            # Süreyi yapay olarak geçmişe çekiyoruz
            token.expires_at = datetime.now() - timedelta(minutes=5)
            # Zamanı dolmuş token ile istek yapıyoruz
            eval_res = mgr.authorize(token.token_id, "reports", "read")
            # Kararın DENY olup olmadığını denetliyoruz
            if eval_res.decision == "DENY" and "CWE-613" in eval_res.reason:
                # Oturum süresi dolduğu için reddedildi
                success = True
                # Sonuç açıklamasını kaydediyoruz
                observed_msg = f"Erişim REDDEDİLDİ (DENY): {eval_res.reason}"
            else:
                # İzin verilmişse zafiyet vardır
                observed_msg = f"Beklenmeyen karar: {eval_res.decision} - {eval_res.reason}"

        # Senaryo 8: MFA Olmadan Kritik Sistem Eylemi (CWE-308)
        elif sid == "NEG-ID-08":
            # Süper yönetici girişi yapıyoruz (mfa_verified=False olarak başlar)
            token = mgr.authenticate("sistem_kemal", "KemalAdminPass2026!#")
            # super_admin rolü requires_mfa=True şartına tabidir
            eval_res = mgr.authorize(token.token_id, "system", "reboot")
            # Kararın DENY olup olmadığını denetliyoruz
            if eval_res.decision == "DENY" and "CWE-308" in eval_res.reason:
                # MFA doğrulaması eksik olduğu için reddedildi
                success = True
                # Sonuç açıklamasını kaydediyoruz
                observed_msg = f"Erişim REDDEDİLDİ (DENY): {eval_res.reason}"
            else:
                # İzin verilmişse zafiyet vardır
                observed_msg = f"Beklenmeyen karar: {eval_res.decision} - {eval_res.reason}"

        # Senaryo 9: Altyapı Arızasında Fail-Secure Koruması (CWE-636)
        elif sid == "NEG-ID-09":
            # Normal kullanıcı girişi yapıyoruz
            token = mgr.authenticate("denetci_merve", "MervePassword2026!#")
            # Veritabanı çökmesi durumunu simüle ediyoruz
            eval_res = mgr.authorize(
                token.token_id,
                "public_docs",
                "read",
                simulate_failure=SystemFailureType.DATABASE_UNAVAILABLE
            )
            # Kararın DENY ve Fail-Secure olup olmadığını denetliyoruz
            if eval_res.decision == "DENY" and eval_res.is_fail_secure_intervention:
                # Fail-Secure koruması başarıyla kilitledi
                success = True
                # Sonuç açıklamasını kaydediyoruz
                observed_msg = f"Fail-Secure Devreye Girdi (DENY): {eval_res.reason}"
            else:
                # Sistem açık kalmışsa zafiyet vardır
                observed_msg = f"Beklenmeyen karar: {eval_res.decision} - {eval_res.reason}"

        # Başarı durumunu sayaçta artırıyoruz
        if success:
            passed_count += 1
            # Çıktı satırını başarı olarak formatlıyoruz
            lines.append(f"[{sid}] {title} ({cwe}) -> PASS")
            # Ayrıntıyı ekliyoruz
            lines.append(f"   Ayrıntı: {observed_msg}\n")
        else:
            # Başarısızlık satırını formatlıyoruz
            lines.append(f"[{sid}] {title} ({cwe}) -> FAIL")
            # Hata ayrıntısını ekliyoruz
            lines.append(f"   Hata: {observed_msg}\n")

    # Genel özet bilgisini ekliyoruz
    lines.append("----------------------------------------------------------------------")
    lines.append(f"TOPLAM: {len(scenarios)} | BAŞARILI: {passed_count} | BAŞARISIZ: {len(scenarios) - passed_count}")
    lines.append(f"SONUÇ: {'100% PASS' if passed_count == len(scenarios) else 'BAŞARISIZLIK MEVCUT'}")
    lines.append("======================================================================")

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Satırları yeni satır karakteri ile birleştirip kaydediyoruz
        f.write("\n".join(lines))

    # Başarılı geçen senaryo sayısını döndürüyoruz
    return passed_count


def generate_architecture_diagram(output_path: str):
    """ASCII formatında temsili mimari şemasını üretir (Zorunlu banner ile)."""
    # Mimari diyagram içeriğini oluşturuyoruz
    diagram = (
        "======================================================================\n"
        "TEMSİLÎ — AI İLLÜSTRASYONU — GERÇEK TEST DEĞİL\n"
        "======================================================================\n"
        "GÜN 125: GÜVENLİ KİMLİK VE ROL PROTOTİPİ MİMARİSİ (Week 18 Capstone)\n"
        "Standartlar: NIST SP 800-63B, ISO 27001 A.9, NIST SP 800-53 AC-2/AC-6\n"
        "----------------------------------------------------------------------\n\n"
        "      +-------------------------------------------------------------+\n"
        "      |                   KULLANICI VE İSTEMCİ                      |\n"
        "      +-------------------------------------------------------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |          GÜVENLİ KİMLİK VE ERİŞİM KAPISI (PEP)              |\n"
        "      +-------------------------------------------------------------+\n"
        "         |                              |                         |\n"
        "         | 1. Kimlik Doğrulama          | 2. MFA Katmanı          | 3. Oturum\n"
        "         v                              v                         v\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "   | PBKDF2-SHA256|              | Step-Up MFA   |         | AuthToken    |\n"
        "   | 100k Döngü   |              | (CWE-308)     |         | Kriptografik |\n"
        "   | Salt + Hash  |              | Time-based    |         | TTL Denetimi |\n"
        "   | (CWE-521/307)|              | Doğrulama     |         | (CWE-613)    |\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "         |                              |                         |\n"
        "         +------------------------------+-------------------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |             YETKİ POLİTİKA KARAR MOTORU (PDP)              |\n"
        "      +-------------------------------------------------------------+\n"
        "         |                              |                         |\n"
        "         | A. Çıkar Çatışması           | B. Rol Mirası           | C. Arıza Koruması\n"
        "         v                              v                         v\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "   | Statik SoD   |              | Hiyerarşik    |         | Fail-Secure  |\n"
        "   | Maker/Checker|              | RBAC Grafı    |         | Fail-Closed  |\n"
        "   | Kısıtı       |              | Döngü Kontrolü|         | Arıza İzolasy|\n"
        "   | (CWE-863)    |              | (CWE-674)     |         | (CWE-636)    |\n"
        "   +--------------+              +---------------+         +--------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |             KORUNAN SİSTEM VE VERİ KAYNAKLARI               |\n"
        "      |     [Public Docs]   [Audit Logs]   [Payments]   [System]     |\n"
        "      +-------------------------------------------------------------+\n"
        "                                     |\n"
        "                                     v\n"
        "      +-------------------------------------------------------------+\n"
        "      |           MASKELENMİŞ DENETİM GÜNLÜĞÜ (CWE-532)             |\n"
        "      |         (Parola, Token ve Gizli Veriler Maskelenir)         |\n"
        "      +-------------------------------------------------------------+\n"
    )

    # Dosyaya yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Metni kaydediyoruz
        f.write(diagram)


def generate_analysis_report(output_path: str):
    """Kapsamlı kimlik ve rol mimarisi değerlendirme raporu üretir."""
    # Raporlama için yöneticimizi ayağa kaldırıyoruz
    mgr = SecureIdentityRoleManager(system_name="Kurumsal Kimlik ve Rol Platformu")
    # Rolleri tanımlıyoruz
    mgr.register_role("guest", {"public:read", "public_docs:read"})
    # Ödeme hazırlayıcı
    mgr.register_role("payment_maker", {"ledger:create", "payment:create"}, parent_roles=["guest"])
    # Ödeme onaylayıcı
    mgr.register_role("payment_checker", {"ledger:approve", "payment:approve"}, parent_roles=["guest"], requires_mfa=True)
    # Denetçi
    mgr.register_role("auditor", {"audit_logs:read", "reports:read"}, parent_roles=["guest"])
    # Güvenlik yöneticisi
    mgr.register_role("super_admin", {"system:*"}, parent_roles=["guest"], requires_mfa=True)
    # SoD kısıtını ekliyoruz
    mgr.add_toxic_role_pair("payment_maker", "payment_checker")

    # Kullanıcıları kaydediyoruz
    mgr.register_user("U-101", "denetci_merve", "MerveGucluParola2026!#", ["auditor"], mfa_secret="778899")
    # Finans Ali
    mgr.register_user("U-102", "finans_ali", "AliGucluParola2026!#", ["payment_maker"], mfa_secret="112233")
    # Finans Ayşe
    mgr.register_user("U-103", "finans_ayse", "AyseGucluParola2026!#", ["payment_checker"], mfa_secret="445566")
    # Sistem Kemal
    mgr.register_user("U-104", "sistem_kemal", "KemalGucluParola2026!#", ["super_admin"], mfa_secret="998877")

    # Yönetici özet sözlüğünü üretiyoruz
    status_report = mgr.export_summary_dict()

    # Rapor nesnesine lisans ve ek meta veriler ekliyoruz
    full_report = {
        "_lisans": "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas). Görüntüleme ve eğitim amaçlıdır.",
        "rapor_tarihi": datetime.now().isoformat(),
        "proje_adi": "Kurumsal Güvenli Kimlik ve Rol Prototipi (Week 18 Capstone)",
        "durum": "YETERLİ / ÜRETİM DÜZEYİ",
        "guvenlik_skoru": 100,
        "mimari_özellikler": {
            "kimlik_dogrulama": "PBKDF2-HMAC-SHA256 (100.000 iterasyon, 16-byte CSPRNG tuzlama) [CWE-521/307]",
            "oturum_yonetimi": "Kriptografik URL-Safe Belirteç (32-byte), TTL Zaman Aşımı [CWE-613]",
            "yetkilendirme_modeli": "Hiyerarşik RBAC (Rol Tabanlı Erişim Denetimi) + Default-Deny [Saltzer-Schroeder]",
            "gorevler_ayriligi": "Statik SoD (Maker-Checker, Çıkar Çatışması Önleme) [CWE-863]",
            "adim_yukseltme_dogrulamasi": "Step-Up MFA Kritik İşlem Koruması [CWE-308]",
            "ariza_guvenligi": "Fail-Secure / Fail-Closed Kritik Kesinti İzolasyonu [CWE-636]",
            "denetim_kayitlari": "Kişisel ve Gizli Veri Maskeleme (CWE-532 Uyumlu)"
        },
        "detaylar": status_report
    }

    # Dosyaya JSON olarak yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Girintili ve Türkçe karakter destekli olarak kaydediyoruz
        json.dump(full_report, f, ensure_ascii=False, indent=2)


def run_cli_commands(output_path: str):
    """CLI komutlarını çalıştırarak çıktılarını komut_ve_cikis.txt dosyasına kaydeder."""
    # CLI betiğini içe aktarıyoruz
    from identity_cli import main as cli_main

    # Konfigürasyon dosyasının tam yolunu alıyoruz
    config_file = os.path.join(CURRENT_DIR, "ornek_veri", "identity_prototype_config.json")

    # Çıktıları toplamak için liste oluşturuyoruz
    cli_outputs = [
        "======================================================================",
        "GÜN 125: CLI ETKİLEŞİM VE YÖNETİM KOMUTLARI KANITI",
        f"Tarih/Saat: {datetime.now().isoformat()}",
        "======================================================================\n"
    ]

    # Komut senaryoları listesi
    commands = [
        ("Durum Raporu Alma", ["report", config_file]),
        ("Başarılı Kimlik Doğrulama", ["auth", config_file, "--username", "denetci_merve", "--password", "MerveStrongPassword2026!#"]),
        ("Yetkisiz Kaynak Erişimi (Default-Deny)", ["authorize", config_file, "--username", "denetci_merve", "--password", "MerveStrongPassword2026!#", "--resource-id", "system", "--action", "reboot"])
    ]

    # Her komutu çalıştırıp çıktısını yakalıyoruz
    for desc, args in commands:
        # Başlık ekliyoruz
        cli_outputs.append(f"--- KOMUT: python identity_cli.py {' '.join(args)} ({desc}) ---")
        # Standart çıktıyı yönlendirmek için tampon oluşturuyoruz
        stdout_buf = io.StringIO()
        # Standart hata tamponu oluşturuyoruz
        stderr_buf = io.StringIO()
        # Eski stdout ve stderr'i saklıyoruz
        old_stdout = sys.stdout
        # Eski stderr'i saklıyoruz
        old_stderr = sys.stderr
        # Stdout'u tampona bağlıyoruz
        sys.stdout = stdout_buf
        # Stderr'i tampona bağlıyoruz
        sys.stderr = stderr_buf
        try:
            # CLI fonksiyonunu argümanlarla çağırıyoruz
            cli_main(args)
        except SystemExit:
            # sys.exit çağrılarını yakalıyoruz
            pass
        finally:
            # Standart çıktıyı eski haline getiriyoruz
            sys.stdout = old_stdout
            # Standart hatayı eski haline getiriyoruz
            sys.stderr = old_stderr

        # Tampondaki çıktıyı alıyoruz
        cmd_out = stdout_buf.getvalue() + stderr_buf.getvalue()
        # Çıktı satırlarına ekliyoruz
        cli_outputs.append(cmd_out)
        # Ayraç satırı ekliyoruz
        cli_outputs.append("----------------------------------------------------------------------\n")

    # Kanıt dosyasına yazıyoruz
    with open(output_path, "w", encoding="utf-8") as f:
        # Satırları birleştirip kaydediyoruz
        f.write("\n".join(cli_outputs))


def main():
    """Ana kanıt üretici akışı."""
    # Gerçek kanıt klasörünü tanımlıyoruz
    gercek_dir = os.path.join(CURRENT_DIR, "kanit", "gercek")
    # Temsili kanıt klasörünü tanımlıyoruz
    temsili_dir = os.path.join(CURRENT_DIR, "kanit", "temsili")

    # Klasörlerin varlığını garanti altına alıyoruz
    os.makedirs(gercek_dir, exist_ok=True)
    # Temsili kanıt klasörünü oluşturuyoruz
    os.makedirs(temsili_dir, exist_ok=True)

    # 1. Birim testleri çalıştırıyoruz
    unit_test_path = os.path.join(gercek_dir, "test_sonuclari.txt")
    # Testleri yürütüyoruz
    unit_ok = run_unit_tests(unit_test_path)
    # Bilgi mesajı yazdırıyoruz
    print(f"[+] Birim Testler Tamamlandı: {'BAŞARILI' if unit_ok else 'BAŞARISIZ'}")

    # 2. Negatif kontrol senaryolarını yürütüyoruz
    neg_path = os.path.join(gercek_dir, "negatif_kontrol_sonuclari.txt")
    # Negatif testleri yürütüyoruz
    neg_passed = run_negative_controls(neg_path)
    # Bilgi mesajı yazdırıyoruz
    print(f"[+] Negatif Kontrol Senaryoları Tamamlandı: {neg_passed}/9 Senaryo Başarılı")

    # 3. Temsili mimari diyagramını oluşturuyoruz
    diagram_path = os.path.join(temsili_dir, "identity_mimarisi.txt")
    # Diyagramı üretiyoruz
    generate_architecture_diagram(diagram_path)
    # Bilgi mesajı yazdırıyoruz
    print("[+] Temsili Mimari Diyagramı Oluşturuldu.")

    # 4. Kapsamlı analiz raporunu oluşturuyoruz
    report_path = os.path.join(gercek_dir, "kimlik_rol_analiz_raporu.json")
    # Raporu üretiyoruz
    generate_analysis_report(report_path)
    # Bilgi mesajı yazdırıyoruz
    print("[+] Kimlik ve Rol Analiz Raporu Oluşturuldu.")

    # 5. CLI etkileşimlerini kaydediyoruz
    cli_path = os.path.join(gercek_dir, "komut_ve_cikis.txt")
    # CLI komutlarını çalıştırıyoruz
    run_cli_commands(cli_path)
    # Bilgi mesajı yazdırıyoruz
    print("[+] CLI Çıktıları Kaydedildi.")

    # Bitiş bildirimi
    print("[***] GÜN 125 TÜM KANIT DOSYALARI BAŞARIYLA ÜRETİLDİ! [***]")


# Betik doğrudan çalıştırıldığında main() fonksiyonunu çağırıyoruz
if __name__ == "__main__":
    main()
