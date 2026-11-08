# -*- coding: utf-8 -*-
"""
Kurumsal Oturum Yönetimi ve Süresi Birim Test Paketi (15 Test)
Hafta 23 / Gün 158 - Aşama 7 (Web Güvenliği)

Bu test paketi; oturum oluşturma, yüksek entropi, boşta kalma ve mutlak zaman aşımları,
oturum sabitleme (fixation) savunması, eşzamanlı oturum sınırlandırması,
User-Agent/IP parmak izi bağlama ve sunucu taraflı iptal mekanizmalarını
15 bağımsız senaryoda test eder.
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uygulama.session_manager_engine import (
    SessionManagerEngine,
    SessionPolicy,
    SessionState,
    UserSession
)


class TestSessionManagerEngine(unittest.TestCase):
    """SessionManagerEngine sınıfının tüm yeteneklerini doğrulayan birim test sınıfı."""

    def setUp(self):
        """Her testten önce çalışan hazırlık metodu."""
        # 15 dk idle, 8 saat absolute, 3 eşzamanlı oturum politikası
        self.policy = SessionPolicy(
            idle_timeout_seconds=900,
            absolute_timeout_seconds=28800,
            max_concurrent_sessions=3,
            bind_user_agent=True,
            bind_ip=True,
            min_session_id_entropy_bits=128,
            rotation_interval_seconds=1800
        )
        self.engine = SessionManagerEngine(policy=self.policy)

    def test_01_create_secure_session_high_entropy(self):
        """Yeni üretilen oturum kimliğinin yüksek Shannon entropisine sahip olduğunu doğrular."""
        session = self.engine.create_session("u1", "testuser", "User", "192.168.1.10", "Mozilla/5.0")
        self.assertIsNotNone(session.session_id)
        self.assertEqual(len(session.session_id), 64) # 32 bytes hex = 64 chars
        entropy = self.engine.calculate_entropy_bits(session.session_id)
        self.assertGreaterEqual(entropy, 128.0)
        self.assertEqual(session.state, SessionState.ACTIVE)

    def test_02_validate_active_session_success(self):
        """Aktif oturumun başarıyla doğrulandığını ve son etkinlik damgasının güncellendiğini test eder."""
        t0 = 1000000.0
        session = self.engine.create_session("u1", "user1", "User", "10.0.0.1", "Chrome", current_time=t0)
        
        t1 = t0 + 60.0 # 1 dakika sonra
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Chrome", current_time=t1)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.status, SessionState.ACTIVE)
        self.assertEqual(session.last_activity_epoch, t1)

    def test_03_idle_timeout_expiration(self):
        """Boşta kalma süresi (900 sn) aşıldığında oturumun EXPIRED_IDLE durumuna geçtiğini test eder."""
        t0 = 1000000.0
        session = self.engine.create_session("u1", "user1", "User", "10.0.0.1", "Chrome", current_time=t0)
        
        t1 = t0 + 901.0 # 15 dakika 1 saniye sonra
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Chrome", current_time=t1)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, SessionState.EXPIRED_IDLE)
        self.assertEqual(session.state, SessionState.EXPIRED_IDLE)

    def test_04_absolute_timeout_expiration(self):
        """Kullanıcı sürekli aktif olsa bile mutlak süre (28800 sn / 8 saat) bitince oturumun kapandığını test eder."""
        t0 = 1000000.0
        session = self.engine.create_session("u1", "user1", "User", "10.0.0.1", "Chrome", current_time=t0)
        
        # Son etkinlik 5 dakika önce olsa dahi, toplam süre 8 saat 1 saniyeyi aşmış olsun
        session.last_activity_epoch = t0 + 28700.0
        t1 = t0 + 28801.0
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Chrome", current_time=t1)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, SessionState.EXPIRED_ABSOLUTE)

    def test_05_session_fixation_privilege_elevation(self):
        """Yetki yükseltildiğinde oturum sabitlemeyi önlemek için eski ID'nin iptal edilip yenilendiğini test eder."""
        session = self.engine.create_session("u_vip", "vip_user", "User", "10.0.0.5", "Edge")
        old_id = session.session_id
        
        # Admin rolüne yükseltme
        elevated = self.engine.elevate_privilege(old_id, new_role="Admin")
        self.assertNotEqual(old_id, elevated.session_id)
        self.assertEqual(elevated.role, "Admin")
        self.assertTrue(elevated.privilege_escalated)
        self.assertEqual(elevated.rotation_count, 1)
        
        # Eski ID ile doğrulama yapılmaya çalışıldığında reddedilmelidir
        res_old = self.engine.validate_session(old_id, "10.0.0.5", "Edge")
        self.assertFalse(res_old.is_valid)

    def test_06_concurrent_session_limit_fifo_eviction(self):
        """Eşzamanlı oturum limiti (3) aşıldığında en eski oturumun iptal edildiğini (FIFO) test eder."""
        t0 = 1000000.0
        s1 = self.engine.create_session("u_multi", "multi_user", "User", "10.0.0.1", "UA1", current_time=t0)
        s2 = self.engine.create_session("u_multi", "multi_user", "User", "10.0.0.2", "UA2", current_time=t0 + 10)
        s3 = self.engine.create_session("u_multi", "multi_user", "User", "10.0.0.3", "UA3", current_time=t0 + 20)
        
        # 4. oturum açıldığında en eski olan s1 sonlandırılmalıdır
        s4 = self.engine.create_session("u_multi", "multi_user", "User", "10.0.0.4", "UA4", current_time=t0 + 30)
        
        self.assertEqual(s1.state, SessionState.REVOKED)
        self.assertEqual(s2.state, SessionState.ACTIVE)
        self.assertEqual(s3.state, SessionState.ACTIVE)
        self.assertEqual(s4.state, SessionState.ACTIVE)

    def test_07_user_agent_mismatch_hijacking_detection(self):
        """User-Agent parmak izi değiştiğinde potansiyel hırsızlık nedeniyle oturumun askıya alındığını test eder."""
        session = self.engine.create_session("u2", "user2", "User", "10.0.0.1", "Mozilla/5.0 Windows")
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Python-requests/2.31.0")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, SessionState.SUSPENDED_HIJACK_RISK)

    def test_08_ip_mismatch_hijacking_detection(self):
        """İstemci IP adresi değiştiğinde oturumun askıya alındığını doğrular."""
        session = self.engine.create_session("u3", "user3", "User", "192.168.1.50", "Chrome")
        res = self.engine.validate_session(session.session_id, "85.90.10.20", "Chrome")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, SessionState.SUSPENDED_HIJACK_RISK)

    def test_09_manual_session_termination(self):
        """Kullanıcı çıkış yaptığında sunucu tarafında oturumun kalıcı iptal edildiğini test eder."""
        session = self.engine.create_session("u4", "user4", "User", "10.0.0.1", "Safari")
        success = self.engine.terminate_session(session.session_id, reason="User clicked logout")
        self.assertTrue(success)
        self.assertEqual(session.state, SessionState.REVOKED)
        
        # İptal edilen oturum doğrulanamamalıdır
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Safari")
        self.assertFalse(res.is_valid)

    def test_10_terminate_all_user_sessions_password_change(self):
        """Şifre değişiminde kullanıcının tüm açık oturumlarının aynı anda kapatıldığını test eder."""
        self.engine.create_session("u5", "user5", "User", "10.0.0.1", "Chrome")
        self.engine.create_session("u5", "user5", "User", "10.0.0.2", "MobileApp")
        
        revoked_count = self.engine.terminate_all_user_sessions("u5", reason="Password reset by user")
        self.assertEqual(revoked_count, 2)

    def test_11_periodic_session_rotation(self):
        """30 dakikalık rotasyon periyodu aşıldığında oturum kimliğinin yenilendiğini test eder."""
        t0 = 1000000.0
        session = self.engine.create_session("u6", "user6", "User", "10.0.0.1", "Firefox", current_time=t0)
        
        t1 = t0 + 1850.0  # 30 dk 50 sn sonra (rotasyon süresi aşılmış)
        session.last_activity_epoch = t1 - 30.0  # Kullanıcı 30 saniye önce aktif olmuş (idle timeout aşılmamış)
        res = self.engine.validate_session(session.session_id, "10.0.0.1", "Firefox", current_time=t1)
        self.assertTrue(res.is_valid)
        self.assertTrue(res.requires_rotation)
        self.assertIsNotNone(res.new_session_id)
        self.assertNotEqual(session.session_id, res.new_session_id)

    def test_12_clean_expired_sessions_garbage_collection(self):
        """Süresi dolmuş veya iptal edilmiş oturumların bellekten temizlendiğini test eder."""
        t0 = 1000000.0
        s1 = self.engine.create_session("u7", "user7", "User", "10.0.0.1", "UA", current_time=t0)
        self.engine.terminate_session(s1.session_id)
        
        # Çöp toplama çalıştırma
        cleaned = self.engine.clean_expired_sessions(current_time=t0 + 10)
        self.assertGreaterEqual(cleaned, 1)
        self.assertNotIn(s1.session_id, self.engine.active_sessions)

    def test_13_unknown_session_id_rejection(self):
        """Hiç var olmamış rastgele bir oturum kimliğinin reddedildiğini test eder."""
        fake_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        res = self.engine.validate_session(fake_id, "10.0.0.1", "UA")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.status, SessionState.REVOKED)

    def test_14_audit_lifecycle_metrics(self):
        """Oturum yaşam döngüsü istatistiklerinin doğru hesaplandığını doğrular."""
        self.engine.create_session("u8", "user8", "User", "10.0.0.1", "UA")
        s2 = self.engine.create_session("u9", "user9", "User", "10.0.0.2", "UA")
        self.engine.terminate_session(s2.session_id)
        
        stats = self.engine.audit_lifecycle()
        self.assertEqual(stats["total_tracked_sessions"], 2)
        self.assertEqual(stats["active_sessions_count"], 1)
        self.assertEqual(stats["revoked_sessions_count"], 1)

    def test_15_ascii_dashboard_rendering(self):
        """ASCII denetim panosunun başlıkları ve oturum sayaçlarını içerdiğini doğrular."""
        self.engine.create_session("u10", "user10", "User", "10.0.0.1", "UA")
        ascii_rep = self.engine.generate_ascii_lifecycle()
        self.assertIn("KURUMSAL OTURUM YÖNETİMİ VE SÜRESİ DENETİM PANOSU", ascii_rep)
        self.assertIn("Boşta Kalma Zaman Aşımı", ascii_rep)
        self.assertIn("Mutlak Oturum Ömrü", ascii_rep)


if __name__ == "__main__":
    unittest.main()
