# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 17 / Gün 118: En Az Ayrıcalık (PoLP) ve Sıfır Güven (Zero Trust) Birim Test Paketi.
15 Kapsamlı Test Senaryosu (NIST SP 800-207 Standartları).
"""

# Birim test çatısı için standart unittest kütüphanesi
import unittest
# Zaman ve süre hesaplamaları için datetime modülü
import datetime

# Test edilecek modeller ve motorların içe aktarılması
from uygulama.least_privilege_zero_trust_engine import (
    LeastPrivilegeManager,
    ZeroTrustPolicyEngine,
    ZeroTrustOrchestrator,
    DevicePosture,
    ProtectedResource,
    StandingPrivilegeForbiddenError,
    ExcessiveScopeRequestedError,
    JITElevationExpiredError,
    DevicePostureUntrustedError,
    DynamicTrustScoreDegradedError,
    StepUpAuthenticationRequiredError,
    NetworkMicroSegmentationViolationError
)


class TestLeastPrivilegeAndZeroTrust(unittest.TestCase):
    """En Az Ayrıcalık ve Sıfır Güven Güvenlik Mekanizmaları Test Paketi."""

    def setUp(self) -> None:
        """Her testten önce temiz bir orkestratör ve test verileri kurar."""
        # Orkestratör ilklendirilir
        self.orchestrator = ZeroTrustOrchestrator()
        self.lp_mgr = self.orchestrator.lp_mgr
        self.zt_engine = self.orchestrator.zt_engine

        # Standart kusursuz kurumsal cihaz
        self.healthy_device = DevicePosture(
            device_id="DEV-CORP-001",
            is_managed=True,
            os_version="Windows 11 Enterprise",
            antivirus_active=True,
            disk_encrypted=True,
            patch_lag_days=1
        )

        # Standart kritik kaynak
        self.core_db_resource = ProtectedResource(
            resource_id="res_core_db",
            name="Core Banking DB",
            target_segment="core_banking",
            min_trust_score=75.0,
            required_jit_scope="db:maintenance_backup",
            requires_step_up_mfa=True
        )

    def test_01_jit_elevation_grant_success(self) -> None:
        """TEST 01: Onaylı katalogdaki geçerli JIT yetki talebi başarıyla tahsis edilmelidir."""
        grant = self.lp_mgr.request_jit_elevation(
            user_id="dba_01",
            target_scope="db:maintenance_backup",
            justification="Haftalık rutin yedekleme",
            approver_id="sec_lead_01",
            duration_seconds=1800
        )
        # Hibe oluşturulmuş olmalıdır
        self.assertTrue(grant.grant_id.startswith("JIT-"))
        self.assertEqual(grant.granted_scope, "db:maintenance_backup")
        self.assertTrue(grant.is_valid(datetime.datetime.now()))

    def test_02_standing_admin_privilege_forbidden(self) -> None:
        """TEST 02: Kalıcı root/admin/sınırsız yetki talepleri derhal engellenmelidir (CWE-250)."""
        # Sınırsız yetki denemesi
        with self.assertRaises(StandingPrivilegeForbiddenError):
            self.lp_mgr.request_jit_elevation(
                user_id="attacker_01",
                target_scope="*:*",
                justification="Her şeye erişmek istiyorum",
                approver_id="none"
            )

    def test_03_excessive_scope_rejection(self) -> None:
        """TEST 03: Onaylı JIT kataloğu dışındaki aşırı yetki talepleri reddedilmelidir (CWE-272)."""
        # Katalog dışı tehlikeli yetki
        with self.assertRaises(ExcessiveScopeRequestedError):
            self.lp_mgr.request_jit_elevation(
                user_id="user_02",
                target_scope="system:arbitrary_command_execution",
                justification="Bilinmeyen işlem",
                approver_id="none"
            )

    def test_04_jit_expiration_enforcement(self) -> None:
        """TEST 04: Süresi dolmuş JIT yetkilendirmesi kullanımı JITElevationExpiredError vermelidir (CWE-613)."""
        grant = self.lp_mgr.request_jit_elevation(
            user_id="dba_01",
            target_scope="log:forensics_export",
            justification="Adli analiz",
            approver_id="lead",
            duration_seconds=300
        )
        # Gelecekteki bir zaman simüle edilir (10 dakika sonrası)
        future_time = datetime.datetime.now() + datetime.timedelta(minutes=10)
        # Süre aşımı doğrulanmalıdır
        with self.assertRaises(JITElevationExpiredError):
            self.lp_mgr.verify_jit_grant(grant.grant_id, current_time=future_time)

    def test_05_jit_revocation_enforcement(self) -> None:
        """TEST 05: Manuel iptal edilen JIT yetkisi süresi dolmasa dahi geçersiz sayılmalıdır."""
        grant = self.lp_mgr.request_jit_elevation(
            user_id="eng_01",
            target_scope="server:emergency_patch",
            justification="Acil yama",
            approver_id="lead",
            duration_seconds=1800
        )
        # Manuel iptal edilir
        grant.is_revoked = True
        with self.assertRaises(JITElevationExpiredError):
            self.lp_mgr.verify_jit_grant(grant.grant_id)

    def test_06_device_posture_healthy_calculation(self) -> None:
        """TEST 06: Tam uyumlu ve yamalı kurumsal cihaz 100.0 sağlık puanı almalıdır."""
        score = self.healthy_device.calculate_posture_score()
        self.assertEqual(score, 100.0)

    def test_07_device_posture_unmanaged_byod_penalty(self) -> None:
        """TEST 07: Yönetilmeyen (BYOD) ve antivirüsü kapalı cihaz ağır puan cezası almalıdır."""
        bad_device = DevicePosture(
            device_id="BYOD-UNKNOWN",
            is_managed=False,        # -40
            antivirus_active=False,  # -30
            disk_encrypted=False,    # -20
            patch_lag_days=30        # Ceza uygulanır
        )
        score = bad_device.calculate_posture_score()
        # Skor 60'ın çok altında kalmalıdır
        self.assertLess(score, 30.0)

    def test_08_device_posture_rejection_at_pep(self) -> None:
        """TEST 08: Güvenilmeyen uç nokta PEP kapısından içeri alınmamalıdır (CWE-284)."""
        untrusted_device = DevicePosture(
            device_id="DEV-HACKED",
            is_managed=False,
            antivirus_active=False
        )
        session = self.orchestrator.create_session(
            user_id="user_bad_dev",
            device=untrusted_device,
            ip_address="10.0.1.200",
            mfa_verified=True,
            network_segment="management_jumpbox"
        )
        # PEP değerlendirmesinde cihaz sağlık hatası beklenir
        with self.assertRaises(DevicePostureUntrustedError):
            self.orchestrator.request_access(session.session_id, self.core_db_resource)

    def test_09_microsegmentation_lateral_movement_blocked(self) -> None:
        """TEST 09: İzole segmentten (guest_wifi/dmz) hassas segmente yanal hareket engellenmelidir (CWE-284)."""
        session = self.orchestrator.create_session(
            user_id="compromised_host",
            device=self.healthy_device,
            ip_address="192.168.100.5",
            mfa_verified=True,
            network_segment="guest_wifi" # Misafir ağı
        )
        # Misafir ağından Core Banking'e yanal hareket engellenmelidir
        with self.assertRaises(NetworkMicroSegmentationViolationError):
            self.orchestrator.request_access(session.session_id, self.core_db_resource)

    def test_10_microsegmentation_allowed_transition(self) -> None:
        """TEST 10: Yetkili jumpbox segmentinden Core Banking segmentine geçişe izin verilmelidir."""
        # Yanal hareket kuralı doğrudan test edilir
        try:
            self.zt_engine.enforce_micro_segmentation("management_jumpbox", "core_banking")
            passed = True
        except NetworkMicroSegmentationViolationError:
            passed = False
        self.assertTrue(passed)

    def test_11_dynamic_trust_score_degradation_on_anomalies(self) -> None:
        """TEST 11: Anomali tespit edilen oturumun güven skoru düşmeli ve erişim kesilmelidir (CWE-284)."""
        session = self.orchestrator.create_session(
            user_id="suspicious_user",
            device=self.healthy_device,
            ip_address="10.20.1.10",
            mfa_verified=True,
            network_segment="management_jumpbox"
        )
        # JIT yetkisi verilir
        grant = self.lp_mgr.request_jit_elevation(
            user_id="suspicious_user",
            target_scope="db:maintenance_backup",
            justification="Bakım",
            approver_id="lead"
        )
        session.jit_grants[grant.grant_id] = grant

        # 3 adet anomali işlenir (Her biri -20 puan = -60 puan)
        self.zt_engine.record_session_anomaly(session, "Aşırı istek sıklığı")
        self.zt_engine.record_session_anomaly(session, "Bilinmeyen kullanıcı ajanı")
        self.zt_engine.record_session_anomaly(session, "Başarısız kimlik denemesi")

        # Güven skoru 75'in altına düştüğünden ret vermelidir
        with self.assertRaises(DynamicTrustScoreDegradedError):
            self.orchestrator.request_access(session.session_id, self.core_db_resource)

    def test_12_step_up_mfa_requirement(self) -> None:
        """TEST 12: Kritik kaynak için Step-Up MFA oturumu olmayan istek engellenmelidir (CWE-308)."""
        # MFA doğrulaması YAPILMAMIŞ oturum
        session = self.orchestrator.create_session(
            user_id="user_no_mfa",
            device=self.healthy_device,
            ip_address="10.20.1.15",
            mfa_verified=False,
            network_segment="management_jumpbox"
        )
        grant = self.lp_mgr.request_jit_elevation(
            user_id="user_no_mfa",
            target_scope="db:maintenance_backup",
            justification="Bakım",
            approver_id="lead"
        )
        session.jit_grants[grant.grant_id] = grant

        # MFA eksikliği hatası fırlatılmalıdır
        with self.assertRaises(StepUpAuthenticationRequiredError):
            self.orchestrator.request_access(session.session_id, self.core_db_resource)

    def test_13_step_up_mfa_success(self) -> None:
        """TEST 13: Step-Up MFA doğrulaması tamamlanmış oturum izin almalıdır."""
        session = self.orchestrator.create_session(
            user_id="user_mfa_ok",
            device=self.healthy_device,
            ip_address="10.20.1.15",
            mfa_verified=True,
            network_segment="management_jumpbox"
        )
        grant = self.lp_mgr.request_jit_elevation(
            user_id="user_mfa_ok",
            target_scope="db:maintenance_backup",
            justification="Bakım",
            approver_id="lead"
        )
        session.jit_grants[grant.grant_id] = grant

        record = self.orchestrator.request_access(session.session_id, self.core_db_resource)
        self.assertEqual(record["status"], "ACCESS_GRANTED")

    def test_14_missing_required_jit_scope(self) -> None:
        """TEST 14: İlgili JIT kapsamı bulunmayan oturum JITElevationExpiredError almalıdır (CWE-613)."""
        # Kullanıcının JIT yetkisi yok
        session = self.orchestrator.create_session(
            user_id="user_nojit",
            device=self.healthy_device,
            ip_address="10.20.1.15",
            mfa_verified=True,
            network_segment="management_jumpbox"
        )
        # JIT eksikliği nedeniyle reddedilmelidir
        with self.assertRaises(JITElevationExpiredError):
            self.orchestrator.request_access(session.session_id, self.core_db_resource)

    def test_15_full_zero_trust_pass_and_audit(self) -> None:
        """TEST 15: Tüm NIST SP 800-207 koşullarını sağlayan meşru işlem onaylanmalı ve denetim izi üretmelidir."""
        session = self.orchestrator.create_session(
            user_id="lead_dba",
            device=self.healthy_device,
            ip_address="10.20.1.99",
            mfa_verified=True,
            network_segment="management_jumpbox"
        )
        # JIT yetkisi tanımlanır
        grant = self.lp_mgr.request_jit_elevation(
            user_id="lead_dba",
            target_scope="db:maintenance_backup",
            justification="Planlı Q4 veritabanı yedeği",
            approver_id="cto_office",
            duration_seconds=3600
        )
        session.jit_grants[grant.grant_id] = grant

        # Erişim talep edilir
        res = self.orchestrator.request_access(session.session_id, self.core_db_resource)
        # Sonuçlar doğrulanır
        self.assertEqual(res["status"], "ACCESS_GRANTED")
        self.assertTrue(res["audit_id"].startswith("AUD-ZT-"))
        self.assertGreaterEqual(res["trust_score"], 75.0)

        # Audit log teyidi
        audit_json = self.orchestrator.export_audit_logs_json()
        self.assertIn("AUD-ZT-", audit_json)
        self.assertIn("lead_dba", audit_json)
        self.assertIn("Core Banking DB", audit_json)


if __name__ == "__main__":
    unittest.main()
