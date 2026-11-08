# -*- coding: utf-8 -*-
"""
Aşama 6 Kalite Özeti ve Kabul Motoru (Endpoint ve IAM)
Hafta 22 / Gün 154

Bu motor; Aşama 6 (Gün 127 - 154) boyunca inşa edilen tüm Kimlik ve Erişim
Yönetimi (IAM, PAM, JML, MFA, RBAC/ABAC) ile Uç Nokta Savunma Derinliği
(EDR, Sandbox, TPM/BitLocker, WORM Yedek, Yapılandırma Sapması) bileşenlerini
6 resmi Kalite Kapısı (Quality Gates) üzerinden denetler, kurumsal kabul kararı üretir.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import json


class GateStatus(str, Enum):
    """Kalite kapısı değerlendirme durumu."""
    # Başarılı - tüm kurumsal standartları karşılıyor
    PASS = "GECTI"
    # Başarısız - kritik uyumsuzluklar mevcut, kabul reddedildi
    FAIL = "KALDI"
    # İncelemede - eksik kanıt veya sınırda durum
    HOLD = "BEKLEMEDE"


@dataclass
class QualityGateResult:
    """Tek bir kalite kapısının denetim sonucu."""
    # Kapı sıra numarası (1-6)
    gate_id: int
    # Kapı başlığı ve kapsamı
    name: str
    # Kapıdan alınan puan (0.0 - 100.0)
    score: float
    # Kapı geçme eşiği
    threshold: float
    # Kapı durum sonucu
    status: GateStatus
    # Tespit edilen bulgular ve uygunsuzluklar
    violations: List[str] = field(default_factory=list)
    # Başarıyla karşılanan kontroller
    passed_checks: List[str] = field(default_factory=list)


@dataclass
class Stage6ArchitectureSpec:
    """Aşama 6 kurumsal mimari ve güvenlik şartnamesi."""
    # Organizasyon / Şirket adı
    organization_name: str
    
    # ----------------- Kapı 1: Kimlik Doğrulama & Kimlik Bilgisi Hijyeni -----------------
    mfa_enforced: bool
    allowed_mfa_methods: List[str]  # ["FIDO2", "WebAuthn", "TOTP"]
    password_hashing_algorithm: str  # "Argon2id", "bcrypt", "PBKDF2"
    ntlmv1_disabled: bool
    kerberos_rc4_disabled: bool
    
    # ----------------- Kapı 2: En Az Ayrıcalık & JML Yaşam Döngüsü -----------------------
    access_control_model: str  # "RBAC_ABAC_HYBRID", "RBAC", "DAC"
    stale_accounts_deprovisioning_hours: int  # <= 24 olmalı
    orphaned_accounts_count: int  # 0 olmalı
    gmsa_used_for_services: bool
    
    # ----------------- Kapı 3: Ayrıcalıklı Erişim Yönetimi (PAM / JIT) --------------------
    standing_domain_admin_accounts: int  # 0 olmalı (Kalıcı admin yasak)
    jit_elevation_enabled: bool
    max_elevation_duration_hours: int  # <= 4 olmalı
    session_recording_active: bool
    
    # ----------------- Kapı 4: Uç Nokta Görünürlüğü & Telemetri (EDR) --------------------
    edr_fleet_coverage_percent: float  # >= 99.0 olmalı
    tamper_protection_enforced: bool
    edr_signatures_max_age_hours: int  # <= 24 olmalı
    
    # ----------------- Kapı 5: Donanım Kökü & Uygulama İzolasyonu ------------------------
    full_disk_encryption_percent: float  # >= 98.0 olmalı
    tpm2_pcr_binding_verified: bool
    app_whitelisting_mode: str  # "Enforce", "Audit", "Disabled"
    lsa_protection_ppl_enabled: bool
    
    # ----------------- Kapı 6: Dayanıklılık, İmmutable Yedek & Sapma ----------------------
    backup_rule_32110_compliant: bool
    worm_immutable_storage_active: bool
    last_restore_drill_days_ago: int  # <= 30 olmalı
    auto_remediation_drift_active: bool


@dataclass
class Stage6AuditReport:
    """Aşama 6 nihai kalite kabul raporu."""
    # Denetlenen şartname organizasyonu
    organization: str
    # Hesaplanan genel Aşama 6 kalite puanı (0.0 - 100.0)
    overall_score: float
    # Nihai kabul kararı
    final_verdict: GateStatus
    # Başarılı geçen kapı sayısı
    passed_gates_count: int
    # Başarısız kapı sayısı
    failed_gates_count: int
    # 6 kalite kapısının detaylı sonuçları
    gate_results: List[QualityGateResult]
    # Yönetici özeti ve tavsiyeler
    executive_summary: str


class Stage6QualityEngine:
    """Aşama 6 Uç Nokta ve Kimlik Güvenliği Kalite Kabul Motoru."""

    # Her bir kapı için standart geçme eşiği
    GATE_PASS_THRESHOLD = 85.0
    # Genel Aşama 6 kabul puanı eşiği
    OVERALL_ACCEPTANCE_THRESHOLD = 90.0

    def evaluate_gate_1_authentication(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 1: Kimlik Doğrulama ve Kimlik Bilgisi Hijyeni Denetimi."""
        # Başlangıç puanı 100 üzerinden ceza puanı düşürme yöntemi uygulanır
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # MFA kontrolü
        if spec.mfa_enforced:
            passed_checks.append("Çok faktörlü kimlik doğrulama (MFA) kurum genelinde zorunludur.")
        else:
            score -= 40.0
            violations.append("MFA zorunlu değil; tek faktörlü parola saldırılarına açık.")

        # İzin verilen MFA metotları kontrolü (SMS veya güvensiz metotlar olmamalı)
        insecure_mfa = [m for m in spec.allowed_mfa_methods if m.upper() in ("SMS", "VOICE", "EMAIL")]
        if insecure_mfa:
            score -= 20.0
            violations.append(f"Güvenliği kırılmış MFA yöntemleri tanımlı: {insecure_mfa} (SIM Swap riski).")
        else:
            passed_checks.append("MFA yöntemleri güçlü kriptografik standartlara uygundur (FIDO2/WebAuthn/TOTP).")

        # Parola özetleme algoritması kontrolü
        valid_hashes = ("Argon2id", "bcrypt", "PBKDF2")
        if spec.password_hashing_algorithm in valid_hashes:
            passed_checks.append(f"Parola hashleme algoritması NIST standartlarına uygun: {spec.password_hashing_algorithm}.")
        else:
            score -= 30.0
            violations.append(f"Kullanımdan kalkmış zayıf parola hashleme algoritması: {spec.password_hashing_algorithm}.")

        # NTLMv1 kapalı mı
        if spec.ntlmv1_disabled:
            passed_checks.append("NTLMv1 protokolü kapatılmış; SMB relay ve hash yakalama önlenmiştir.")
        else:
            score -= 20.0
            violations.append("NTLMv1 aktif; Pass-the-Hash ve relay ataklarına karşı savunmasız.")

        # Kerberos RC4 kapalı mı
        if spec.kerberos_rc4_disabled:
            passed_checks.append("Kerberos RC4-HMAC şifreleme kapatılmış; AES-256 zorunludur.")
        else:
            score -= 15.0
            violations.append("Kerberos RC4 aktif; Kerberoasting ve zayıf bilet kırma riski.")

        # Puan sınırlandırılır
        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD and not violations else (
            GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL
        )

        return QualityGateResult(
            gate_id=1,
            name="Kimlik Doğrulama ve Kimlik Bilgisi Hijyeni",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def evaluate_gate_2_least_privilege(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 2: En Az Ayrıcalık ve JML Yaşam Döngüsü Denetimi."""
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # Erişim kontrol modeli
        if spec.access_control_model in ("RBAC_ABAC_HYBRID", "RBAC"):
            passed_checks.append(f"Erişim kontrol modeli kurumsal matrisle yönetiliyor: {spec.access_control_model}.")
        else:
            score -= 30.0
            violations.append(f"Yetersiz erişim kontrol modeli: {spec.access_control_model} (Gelişigüzel erişim riski).")

        # Yetim hesap sayısı (ayrılan çalışanlar)
        if spec.orphaned_accounts_count == 0:
            passed_checks.append("Sistemde sıfır yetim (orphaned) hesap; JML döngüsü tam işliyor.")
        else:
            score -= min(50.0, spec.orphaned_accounts_count * 15.0)
            violations.append(f"Sistemde {spec.orphaned_accounts_count} adet yetim/kullanılmayan hesap tespit edildi.")

        # Ayrılan çalışan hesap kapatma SLA süresi (Leaver SLA)
        if spec.stale_accounts_deprovisioning_hours <= 24:
            passed_checks.append(f"Ayrılan personel hesap kapatma SLA'sı 24 saat altında: {spec.stale_accounts_deprovisioning_hours}h.")
        else:
            score -= 25.0
            violations.append(f"Ayrılan personel hesap kapatma SLA'sı çok uzun: {spec.stale_accounts_deprovisioning_hours}h (>24h).")

        # Servis hesaplarında gMSA kullanımı
        if spec.gmsa_used_for_services:
            passed_checks.append("Servis hesaplarında Group Managed Service Accounts (gMSA) ile otomatik parola rotasyonu aktif.")
        else:
            score -= 20.0
            violations.append("Servis hesaplarında gMSA kullanılmıyor; statik parola ve Kerberoasting riski.")

        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL

        return QualityGateResult(
            gate_id=2,
            name="En Az Ayrıcalık ve JML Yaşam Döngüsü",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def evaluate_gate_3_pam_jit(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 3: Ayrıcalıklı Erişim Yönetimi (PAM / PIM ve JIT) Denetimi."""
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # Kalıcı Domain Admin hesabı var mı
        if spec.standing_domain_admin_accounts == 0:
            passed_checks.append("Kalıcı (Standing) Domain Admin üyeliği sıfırdır; kalıcı ayrıcalık riski yoktur.")
        else:
            score -= min(60.0, spec.standing_domain_admin_accounts * 25.0)
            violations.append(f"Kalıcı {spec.standing_domain_admin_accounts} adet Domain Admin hesabı mevcut (Kalıcı yetki yasaktır).")

        # JIT (Just-In-Time) yetki yükseltme açık mı
        if spec.jit_elevation_enabled:
            passed_checks.append("Just-In-Time (JIT) onay tabanlı geçici yetkilendirme devrededir.")
        else:
            score -= 35.0
            violations.append("JIT yetkilendirme kapalı; statik ayrıcalıklar kullanılmaktadır.")

        # Maksimum yetki süresi (Time-bound elevation)
        if spec.max_elevation_duration_hours <= 4:
            passed_checks.append(f"Yetki yükseltme süre sınırı en fazla {spec.max_elevation_duration_hours} saattir (<=4h).")
        else:
            score -= 20.0
            violations.append(f"Yetki süresi çok uzun: {spec.max_elevation_duration_hours} saat (>4 saat).")

        # Ayrıcalıklı oturum kaydı (Session recording)
        if spec.session_recording_active:
            passed_checks.append("Ayrıcalıklı oturumlar (PAM Session Recording) adli kanıt amacıyla kaydedilmektedir.")
        else:
            score -= 15.0
            violations.append("Ayrıcalıklı oturum video/komut kaydı kapalı; denetim izi eksik.")

        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL

        return QualityGateResult(
            gate_id=3,
            name="Ayrıcalıklı Erişim Yönetimi (PAM / JIT)",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def evaluate_gate_4_edr_telemetry(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 4: Uç Nokta Görünürlüğü ve Anti-Tamper Denetimi."""
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # EDR kapsama oranı
        if spec.edr_fleet_coverage_percent >= 99.0:
            passed_checks.append(f"Filo genelinde EDR kapsaması tamdır: %{spec.edr_fleet_coverage_percent}.")
        else:
            coverage_deficit = 99.0 - spec.edr_fleet_coverage_percent
            score -= min(50.0, coverage_deficit * 5.0)
            violations.append(f"EDR filo kapsaması yetersiz: %{spec.edr_fleet_coverage_percent} (<%99.0).")

        # Kurcalamaya Karşı Koruma (Tamper Protection)
        if spec.tamper_protection_enforced:
            passed_checks.append("EDR Tamper Protection zorunludur; yerel adminler dahi telemetriyi kapatamaz.")
        else:
            score -= 30.0
            violations.append("Tamper Protection kapalı; savunma zayıflatma (T1562.001) atağına açıktır.")

        # İmza ve kural güncelliği
        if spec.edr_signatures_max_age_hours <= 24:
            passed_checks.append(f"Zararlı imza ve kural tabanı günceldir: {spec.edr_signatures_max_age_hours}h.")
        else:
            score -= 20.0
            violations.append(f"Zararlı yazılım imzaları eski: {spec.edr_signatures_max_age_hours} saat (>24 saat).")

        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL

        return QualityGateResult(
            gate_id=4,
            name="Uç Nokta Görünürlüğü ve Telemetri (EDR)",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def evaluate_gate_5_hardware_and_sandbox(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 5: Donanım Kökü ve Uygulama İzolasyonu Denetimi."""
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # Disk şifreleme oranı
        if spec.full_disk_encryption_percent >= 98.0:
            passed_checks.append(f"Tam disk şifreleme oranı mükemmel: %{spec.full_disk_encryption_percent}.")
        else:
            enc_deficit = 98.0 - spec.full_disk_encryption_percent
            score -= min(50.0, enc_deficit * 4.0)
            violations.append(f"Şifrelenmemiş disk oranı yüksek: %{spec.full_disk_encryption_percent} (<%98).")

        # TPM 2.0 PCR bağlama
        if spec.tpm2_pcr_binding_verified:
            passed_checks.append("TPM 2.0 PCR 0,2,4,7 önyükleme ölçüm zinciri mühürlüdür (Evil Maid korumalı).")
        else:
            score -= 20.0
            violations.append("TPM 2.0 PCR bağlama doğrulanmamış; önyükleme kurcalanma riski.")

        # Uygulama beyaz listesi (AppLocker/WDAC)
        if spec.app_whitelisting_mode == "Enforce":
            passed_checks.append("Uygulama kontrolü zorlama (Enforce) modundadır; onaysız ikili dosyalar engellenir.")
        elif spec.app_whitelisting_mode == "Audit":
            score -= 15.0
            violations.append("Uygulama kontrolü yalnızca denetim (Audit) modundadır; engelleme yapmaz.")
        else:
            score -= 35.0
            violations.append("Uygulama kontrolü tamamen kapalıdır (Disabled).")

        # LSA Protection (RunAsPPL)
        if spec.lsa_protection_ppl_enabled:
            passed_checks.append("LSA Koruması (RunAsPPL) aktiftir; LSASS bellek dökümü (Mimikatz) çekirdekten engellenir.")
        else:
            score -= 25.0
            violations.append("LSA Koruması kapalı; LSASS bellek çalınma riski mevcuttur.")

        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL

        return QualityGateResult(
            gate_id=5,
            name="Donanım Kökü ve Uygulama İzolasyonu",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def evaluate_gate_6_resilience_and_drift(self, spec: Stage6ArchitectureSpec) -> QualityGateResult:
        """Kapı 6: Dayanıklılık, İmmutable Yedek ve Sapma Onarımı Denetimi."""
        score = 100.0
        violations: List[str] = []
        passed_checks: List[str] = []

        # 3-2-1-1-0 kuralı
        if spec.backup_rule_32110_compliant:
            passed_checks.append("3-2-1-1-0 yedekleme mimarisine tam uyum sağlanmıştır.")
        else:
            score -= 30.0
            violations.append("3-2-1-1-0 kuralı ihlal edilmiş; tek nokta arıza veya fidye yazılımı riski.")

        # WORM / Değiştirilemez depolama
        if spec.worm_immutable_storage_active:
            passed_checks.append("S3 Object Lock COMPLIANCE / WORM değiştirilemez yedek deposu aktiftir.")
        else:
            score -= 35.0
            violations.append("Yedek deposu değiştirilemez değil; fidye yazılımları tarafından silinebilir.")

        # Geri yükleme tatbikatı (Restore drill)
        if spec.last_restore_drill_days_ago <= 30:
            passed_checks.append(f"Geri yükleme tatbikatı son 30 gün içinde doğrulanmıştır: {spec.last_restore_drill_days_ago} gün.")
        else:
            score -= 20.0
            violations.append(f"Geri yükleme tatbikatı yapılmamış veya eski: {spec.last_restore_drill_days_ago} gün (>30 gün).")

        # Otomatik yapılandırma sapması iyileştirme (Auto-Remediation)
        if spec.auto_remediation_drift_active:
            passed_checks.append("Yapılandırma sapması anlık denetlenmekte ve otomatik iyileştirilmektedir (Self-Healing).")
        else:
            score -= 20.0
            violations.append("Otomatik sapma iyileştirme kapalı; sistem zamanla güvenli referanstan uzaklaşabilir.")

        final_score = round(max(0.0, score), 1)
        status = GateStatus.PASS if final_score >= self.GATE_PASS_THRESHOLD else GateStatus.FAIL

        return QualityGateResult(
            gate_id=6,
            name="Dayanıklılık, İmmutable Yedek ve Sapma Onarımı",
            score=final_score,
            threshold=self.GATE_PASS_THRESHOLD,
            status=status,
            violations=violations,
            passed_checks=passed_checks,
        )

    def audit_stage_6(self, spec: Stage6ArchitectureSpec) -> Stage6AuditReport:
        """Tüm 6 Kalite Kapısını değerlendirir ve resmi Aşama 6 Kabul Raporu üretir."""
        # 6 kapı sırayla çalıştırılır
        g1 = self.evaluate_gate_1_authentication(spec)
        g2 = self.evaluate_gate_2_least_privilege(spec)
        g3 = self.evaluate_gate_3_pam_jit(spec)
        g4 = self.evaluate_gate_4_edr_telemetry(spec)
        g5 = self.evaluate_gate_5_hardware_and_sandbox(spec)
        g6 = self.evaluate_gate_6_resilience_and_drift(spec)

        gate_results = [g1, g2, g3, g4, g5, g6]

        # Ortalama puan hesaplanır
        total_score = sum(g.score for g in gate_results)
        overall_score = round(total_score / len(gate_results), 1)

        # Başarılı ve başarısız kapı sayıları
        passed_count = sum(1 for g in gate_results if g.status == GateStatus.PASS)
        failed_count = sum(1 for g in gate_results if g.status == GateStatus.FAIL)

        # Nihai kabul kararı
        if overall_score >= self.OVERALL_ACCEPTANCE_THRESHOLD and failed_count == 0:
            final_verdict = GateStatus.PASS
            exec_summary = (
                f"{spec.organization_name} için Aşama 6 (Uç Nokta ve IAM) Kalite Denetimi %{overall_score} puan ile "
                "EKSİKSİZ KABUL EDİLMİŞTİR (PASS). 6 Kalite Kapısının tamamı başarıyla geçilmiştir."
            )
        else:
            final_verdict = GateStatus.FAIL
            exec_summary = (
                f"{spec.organization_name} için Aşama 6 denetimi %{overall_score} puan ile REDDEDİLMİŞTİR (FAIL/HOLD). "
                f"{failed_count} adet kalite kapısında kritik uygunsuzluk tespit edilmiştir."
            )

        return Stage6AuditReport(
            organization=spec.organization_name,
            overall_score=overall_score,
            final_verdict=final_verdict,
            passed_gates_count=passed_count,
            failed_gates_count=failed_count,
            gate_results=gate_results,
            executive_summary=exec_summary,
        )

    def export_report_to_dict(self, report: Stage6AuditReport) -> Dict[str, Any]:
        """Rapor nesnesini JSON uyumlu Python sözlüğüne dönüştürür."""
        data = asdict(report)
        data["final_verdict"] = report.final_verdict.value
        for g in data.get("gate_results", []):
            g["status"] = g["status"]
        return data

    def generate_ascii_certificate(self, report: Stage6AuditReport) -> str:
        """Aşama 6 kurumsal kalite kabul sertifikası metni üretir."""
        lines: List[str] = []
        lines.append("*" * 84)
        lines.append("*" + " " * 82 + "*")
        lines.append("*" + "   AŞAMA 6 KALİTE GÜVENCE VE KABUL SERTİFİKASI (ENDPOINT & IAM)   ".center(82) + "*")
        lines.append("*" + "   365 GÜNDE USTA-ÇIRAK SİBER GÜVENLİK KAMPI - HAFTA 22 KİLOMETRE TAŞI   ".center(82) + "*")
        lines.append("*" + " " * 82 + "*")
        lines.append("*" * 84)
        lines.append(f"\n Kurum / Organizasyon : {report.organization}")
        lines.append(f" Genel Kalite Puanı   : {report.overall_score} / 100.0 (Kabul Eşiği: {self.OVERALL_ACCEPTANCE_THRESHOLD})")
        lines.append(f" Nihai Kabul Kararı   : {'[BAŞARILI - RESMİ ONAY VERİLDİ]' if report.final_verdict == GateStatus.PASS else '[REDDEDİLDİ / İYİLEŞTİRME GEREKLİ]'}")
        lines.append(f" Kapı Başarı Oranı    : {report.passed_gates_count} / {len(report.gate_results)} Kapı Geçti\n")
        lines.append("=" * 84)
        lines.append(f" {'NO':<4} {'KALİTE KAPISI':<44} {'PUAN':<8} {'EŞİK':<8} {'DURUM':<10}")
        lines.append("-" * 84)
        for g in report.gate_results:
            st_text = "[GECTI]" if g.status == GateStatus.PASS else "[KALDI]"
            lines.append(f" {g.gate_id:<4} {g.name:<44} {g.score:<8.1f} {g.threshold:<8.1f} {st_text:<10}")
        lines.append("=" * 84)
        lines.append("\n YÖNETİCİ DEĞERLENDİRME ÖZETİ:")
        lines.append(f" {report.executive_summary}\n")
        lines.append("*" * 84)
        return "\n".join(lines)
