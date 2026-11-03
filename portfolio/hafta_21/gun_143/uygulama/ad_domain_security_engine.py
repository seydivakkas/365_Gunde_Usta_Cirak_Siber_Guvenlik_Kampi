# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Hafta 21 / Gün 143 - Active Directory Etki Alanı Güvenlik ve Denetim Motoru.
Bu modül; kurumsal Active Directory Domain Services (AD DS) altyapılarında;
Orman ve etki alanı mimarisini, Kerberos ve NTLM kimlik doğrulama politikalarını,
LDAP/SMB imzalama zorunluluklarını, güven ilişkilerini (Trusts & SID Filtering),
Kerberoasting, AS-REP Roasting ve Yetkisiz Delegasyon (Unconstrained Delegation)
zafiyetlerini denetleyen ve PowerShell GPO sıkılaştırma betiği üreten motordur.
"""

# İşletim sistemi fonksiyonları ve dosya yolları
import os
# Sistem akışları ve argüman kontrolü
import sys
# Yapılandırılmış JSON verisi ayrıştırma ve seri hale getirme
import json
# Düzenli ifadeler ile SID ve hesap deseni kontrolü
import re
# Tarih, saat ve parola yaşı hesaplamaları
from datetime import datetime, date
# Veri yapılarını nesne yönelimli temsil etmek için dataclass modülü
from dataclasses import dataclass, field, asdict
# Tip ipuçları ve statik analiz desteği
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class AdFinding:
    """
    Active Directory denetimi sırasında tespit edilen güvenlik bulgusu veri modeli.
    """
    category: str                   # Kategori (ARCHITECTURE, KERBEROS, NTLM, LDAP_SMB, ACCOUNTS, TRUSTS)
    rule_id: str                    # Kural kimliği (örn: AD-KERB-01)
    title: str                      # Bulgunun kısa başlığı
    severity: str                   # Şiddet derecesi: CRITICAL, HIGH, MEDIUM, LOW
    status: str                     # PASS, FAIL, WARNING
    current_value: Any              # Sistemde tespit edilen mevcut durum
    expected_value: Any             # Olması gereken güvenli referans değer
    remediation: str                # Çözüm ve sıkılaştırma adımı


@dataclass
class AdAuditSummary:
    """
    Active Directory etki alanı konsolide güvenlik ve uyumluluk özeti.
    """
    domain_name: str                # Etki alanı adı (örn: corp.internal)
    forest_name: str                # Orman adı
    functional_level: str           # Fonksiyonel seviye (örn: Windows2016Forest)
    scan_timestamp: str             # Tarama zaman damgası
    ad_security_score: float        # Active Directory Güvenlik Puanı (0 - 100)
    compliance_status: str          # SECURE, AT_RISK, COMPROMISED
    total_checks: int               # Toplam kontrol sayısı
    passed_checks: int              # Başarılı kontrol sayısı
    failed_checks: int              # Başarısız kontrol sayısı
    critical_findings_count: int    # Kritik bulgu sayısı
    findings: List[AdFinding] = field(default_factory=list)


class AdDomainSecurityEngine:
    """
    Active Directory Etki Alanı Güvenlik ve Sertleştirme Motoru.
    """

    # En az desteklenmesi gereken fonksiyonel seviyeler
    MIN_FUNCTIONAL_LEVELS = {"2016", "2019", "2022", "2025"}

    # Kerberos için kabul edilemez zayıf şifreleme türleri (DES, RC4)
    WEAK_KERBEROS_CIPHERS = {"DES-CBC-CRC", "DES-CBC-MD5", "RC4-HMAC"}

    def __init__(self, spec_data: Optional[Dict[str, Any]] = None):
        """
        Denetim motorunu başlatır ve envanter verisini hazırlar.
        """
        # Hedef Active Directory ortamının spesifikasyon envanteri
        self.spec = spec_data or {}
        # Tespit edilen bulgular listesi
        self.findings: List[AdFinding] = []
        # Konsolide özet rapor
        self.summary: Optional[AdAuditSummary] = None

    def load_spec_from_file(self, file_path: str) -> None:
        """
        JSON dosyasından Active Directory spesifikasyon envanterini yükler.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Active Directory spesifikasyon dosyası bulunamadı: {file_path}")
        with open(file_path, "r", encoding="utf-8") as fp:
            self.spec = json.load(fp)

    # -------------------------------------------------------------------------
    # 1. ETKİ ALANI VE ORMAN MİMARİSİ DENETİMİ (ARCHITECTURE)
    # -------------------------------------------------------------------------
    def audit_domain_architecture(self) -> None:
        """
        Etki alanı ve orman fonksiyonel seviyelerini, FSMO rollerini denetler.
        """
        arch = self.spec.get("architecture", {})
        dfl = str(arch.get("domain_functional_level", ""))
        ffl = str(arch.get("forest_functional_level", ""))

        # Kontrol 1: Orman ve Etki Alanı Fonksiyonel Seviyesi (En az Windows Server 2016 olmalı)
        level_ok = any(lvl in dfl for lvl in self.MIN_FUNCTIONAL_LEVELS) and any(lvl in ffl for lvl in self.MIN_FUNCTIONAL_LEVELS)
        if level_ok:
            self.findings.append(AdFinding(
                category="ARCHITECTURE", rule_id="AD-ARCH-01",
                title="Orman ve Etki Alanı Fonksiyonel Seviyesi",
                severity="HIGH", status="PASS",
                current_value=f"DFL: {dfl}, FFL: {ffl}",
                expected_value=">= Windows Server 2016",
                remediation="Fonksiyonel seviye modern güvenlik özelliklerini (PAM, Protected Users) destekliyor."
            ))
        else:
            self.findings.append(AdFinding(
                category="ARCHITECTURE", rule_id="AD-ARCH-01",
                title="Eski Fonksiyonel Seviye (Legacy DFL/FFL)",
                severity="HIGH", status="FAIL",
                current_value=f"DFL: {dfl}, FFL: {ffl}",
                expected_value=">= Windows Server 2016",
                remediation="Etki alanı ve orman fonksiyonel seviyesini en az Windows Server 2016 seviyesine yükseltin."
            ))

        # Kontrol 2: FSMO Rol Dağılımı ve PDC Emulator Varlığı
        fsmo = arch.get("fsmo_roles", {})
        pdc = fsmo.get("pdc_emulator")
        rid = fsmo.get("rid_master")
        schema = fsmo.get("schema_master")
        if pdc and rid and schema:
            self.findings.append(AdFinding(
                category="ARCHITECTURE", rule_id="AD-ARCH-02",
                title="FSMO Operasyon Rolleri Dağılımı",
                severity="MEDIUM", status="PASS",
                current_value=f"PDC: {pdc}, RID: {rid}",
                expected_value="Tüm FSMO rolleri tanımlı ve erişilebilir",
                remediation="FSMO rolleri sağlıklı."
            ))
        else:
            self.findings.append(AdFinding(
                category="ARCHITECTURE", rule_id="AD-ARCH-02",
                title="Eksik veya Ulaşılamayan FSMO Rolü",
                severity="HIGH", status="FAIL",
                current_value=f"FSMO tanımları eksik: {fsmo}",
                expected_value="5 FSMO rolünün tamamı tanımlı olmalı",
                remediation="FSMO rollerinin çalıştığını ve etki alanı denetleyicileri arasında senkronize olduğunu teyit edin."
            ))

    # -------------------------------------------------------------------------
    # 2. KERBEROS KİMLİK DOĞRULAMA VE KRBTGT GÜVENLİĞİ (KERBEROS)
    # -------------------------------------------------------------------------
    def audit_kerberos_security(self, ref_date_str: Optional[str] = None) -> None:
        """
        Kerberos şifreleme türlerini, TGT bilet ömürlerini ve krbtgt parola yaşını denetler.
        """
        kerb = self.spec.get("kerberos_policy", {})

        # Kontrol 1: Kerberos Şifreleme Türleri (Yalnızca AES-128 ve AES-256 izinli olmalı)
        supported_enc = set(kerb.get("supported_encryption_types", []))
        weak_ciphers_found = supported_enc.intersection(self.WEAK_KERBEROS_CIPHERS)
        has_aes = any("AES" in enc for enc in supported_enc)

        if not weak_ciphers_found and has_aes:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-01",
                title="Kerberos Şifreleme Algoritmaları (AES Zorunluluğu)",
                severity="CRITICAL", status="PASS",
                current_value=list(supported_enc),
                expected_value="AES-128, AES-256 (RC4/DES Yasak)",
                remediation="Kerberos biletlerinde modern AES şifreleme kullanılıyor."
            ))
        else:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-01",
                title="Kerberos Zayıf Şifreleme Türleri Açık (RC4 / DES Riski)",
                severity="CRITICAL", status="FAIL",
                current_value=list(supported_enc),
                expected_value="RC4 ve DES tamamen kapatılmalı",
                remediation="GPO üzerinden SupportedEncryptionTypes değerini 0x18 (AES128+AES256) olarak zorlayın."
            ))

        # Kontrol 2: krbtgt Parola Yaşı ve Rotasyonu (Golden Ticket Koruması)
        krbtgt_info = self.spec.get("krbtgt_account", {})
        pwd_last_set = krbtgt_info.get("password_last_set", "2020-01-01")
        ref_d = date.fromisoformat(ref_date_str) if ref_date_str else date.today()

        try:
            p_date = date.fromisoformat(pwd_last_set)
            age_days = (ref_d - p_date).days
        except Exception:
            age_days = 999

        # Kurumsal standart: krbtgt parolası en az 180 günde bir (ardışık iki kez) sıfırlanmalıdır
        if age_days <= 180:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-02",
                title="krbtgt Hesap Parola Yaşı ve Rotasyon Durumu",
                severity="HIGH", status="PASS",
                current_value=f"{age_days} gün önce sıfırlandı",
                expected_value="<= 180 gün",
                remediation="krbtgt hesabı düzenli aralıklarla sıfırlanıyor."
            ))
        else:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-02",
                title="krbtgt Parolası Çok Eski (Golden Ticket Kalıcılık Riski)",
                severity="CRITICAL", status="FAIL",
                current_value=f"{age_days} gündür sıfırlanmadı ({pwd_last_set})",
                expected_value="<= 180 gün",
                remediation="krbtgt hesabının parolasını Reset-KrbTgt-Password scripti ile 24 saat arayla iki kez sıfırlayın."
            ))

        # Kontrol 3: TGT Bilet Ömrü (Maksimum 10 saat olmalı)
        tgt_lifetime_hours = int(kerb.get("max_ticket_lifetime_hours", 24))
        if tgt_lifetime_hours <= 10:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-03",
                title="Kerberos TGT Maksimum Bilet Ömrü",
                severity="MEDIUM", status="PASS",
                current_value=f"{tgt_lifetime_hours} saat",
                expected_value="<= 10 saat",
                remediation="Bilet ömrü standartlara uygun."
            ))
        else:
            self.findings.append(AdFinding(
                category="KERBEROS", rule_id="AD-KERB-03",
                title="Kerberos TGT Bilet Ömrü Aşırı Uzun",
                severity="MEDIUM", status="FAIL",
                current_value=f"{tgt_lifetime_hours} saat",
                expected_value="<= 10 saat",
                remediation="Default Domain Policy içinde 'Maximum lifetime for user ticket' değerini 10 saate düşürün."
            ))

    # -------------------------------------------------------------------------
    # 3. NTLM PROTOKOL VE GEÇİŞ KORUMALARI (NTLM)
    # -------------------------------------------------------------------------
    def audit_ntlm_security(self) -> None:
        """
        NTLMv1 kısıtlamasını ve LmCompatibilityLevel değerini denetler.
        """
        ntlm = self.spec.get("ntlm_policy", {})
        lm_level = int(ntlm.get("lm_compatibility_level", 0))

        # LmCompatibilityLevel 5: Sadece NTLMv2 yanıtı gönder, LM ve NTLM'i reddet
        if lm_level == 5:
            self.findings.append(AdFinding(
                category="NTLM", rule_id="AD-NTLM-01",
                title="NTLMv1 Engelleme ve NTLMv2 Zorunluluğu (LmCompatibilityLevel)",
                severity="CRITICAL", status="PASS",
                current_value=f"Seviye {lm_level} (Sadece NTLMv2)",
                expected_value="Seviye 5 (Send NTLMv2 response only / refuse LM & NTLM)",
                remediation="Zayıf NTLMv1 ve LM protokolleri engellenmiş."
            ))
        else:
            self.findings.append(AdFinding(
                category="NTLM", rule_id="AD-NTLM-01",
                title="Güvensiz NTLMv1 Protokolü Aktif (Pass-the-Hash / Kaba Kuvvet Riski)",
                severity="CRITICAL", status="FAIL",
                current_value=f"Seviye {lm_level}",
                expected_value="Seviye 5",
                remediation="GPO üzerinden LmCompatibilityLevel kayıt defteri anahtarını 5 olarak yapılandırın."
            ))

    # -------------------------------------------------------------------------
    # 4. LDAP İMZALAMA VE SMB İMZALAMA ZORUNLULUĞU (LDAP_SMB)
    # -------------------------------------------------------------------------
    def audit_ldap_smb_signing(self) -> None:
        """
        LDAP ve SMB imzalama ile kanal bağlama (Channel Binding) politikalarını denetler.
        """
        ldap_smb = self.spec.get("ldap_smb_policy", {})

        # Kontrol 1: LDAP İmzalama Zorunluluğu (LDAPServerIntegrity = 2)
        ldap_sign = int(ldap_smb.get("ldap_server_integrity", 0))
        if ldap_sign == 2:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-LDAP-01",
                title="LDAP Sunucu Bütünlük Denetimi ve İmzalama (LDAP Signing)",
                severity="HIGH", status="PASS",
                current_value="2 (İmza Zorunlu)",
                expected_value="2 (Require signature)",
                remediation="LDAP sorguları ortadaki adam (MitM) saldırılarına karşı imzalanıyor."
            ))
        else:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-LDAP-01",
                title="LDAP İmzalama Zorunlu Değil (LDAP Relay / MitM Riski)",
                severity="HIGH", status="FAIL",
                current_value=f"{ldap_sign} (İmzasız Kabul)",
                expected_value="2 (Require signature)",
                remediation="Domain Controller GPO'sunda 'Domain controller: LDAP server signing requirements' ayarını 'Require signing' yapın."
            ))

        # Kontrol 2: LDAP Kanal Bağlama (Channel Binding - CVE-2017-8563 koruması)
        channel_bind = int(ldap_smb.get("ldap_enforce_channel_binding", 0))
        if channel_bind == 2:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-LDAP-02",
                title="LDAP Kanal Bağlama (LdapEnforceChannelBinding)",
                severity="HIGH", status="PASS",
                current_value="2 (Her zaman zorla)",
                expected_value="2 (Always enforce)",
                remediation="Kanal bağlama etkin."
            ))
        else:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-LDAP-02",
                title="LDAP Kanal Bağlama Eksik veya Devre Dışı",
                severity="HIGH", status="FAIL",
                current_value=f"{channel_bind}",
                expected_value="2 (Always enforce)",
                remediation="Kayıt defterinde LdapEnforceChannelBinding değerini 2 olarak ayarlayın."
            ))

        # Kontrol 3: SMB İmzalama (SMB Signing) ve SMBv1 Yasağı
        smb_sign = bool(ldap_smb.get("smb_signing_required", False))
        smbv1_disabled = bool(ldap_smb.get("smbv1_disabled", False))
        if smb_sign and smbv1_disabled:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-SMB-01",
                title="SMB İmzalama ve SMBv1 Protokol İzolasyonu",
                severity="HIGH", status="PASS",
                current_value="SMB Signing Açık, SMBv1 Kapalı",
                expected_value="SMB Signing: True, SMBv1: Disabled",
                remediation="SMB Relay ve EternalBlue tipi zafiyetler önlenmiş."
            ))
        else:
            self.findings.append(AdFinding(
                category="LDAP_SMB", rule_id="AD-SMB-01",
                title="SMB İmzalama Eksik veya SMBv1 Protokolü Açık",
                severity="CRITICAL", status="FAIL",
                current_value=f"Signing: {smb_sign}, SMBv1 Disabled: {smbv1_disabled}",
                expected_value="SMB Signing: True, SMBv1: Disabled",
                remediation="SMBv1 protokolünü kaldırın ve DC üzerinde SMB imzasını zorunlu tutun."
            ))

    # -------------------------------------------------------------------------
    # 5. KULLANICI, SERVİS HESAPLARI VE DELEGASYON RİSKLERİ (ACCOUNTS)
    # -------------------------------------------------------------------------
    def audit_account_and_delegation_risks(self) -> None:
        """
        Kerberoasting, AS-REP Roasting ve Unconstrained Delegation zafiyetlerini tarar.
        """
        accounts = self.spec.get("accounts", [])

        kerberoastable_admins = []
        asrep_roastable_users = []
        unconstrained_delegations = []

        for acc in accounts:
            sam = acc.get("sam_account_name", "")
            is_admin = bool(acc.get("is_privileged_admin", False))
            spn_list = acc.get("service_principal_names", [])
            preauth_not_req = bool(acc.get("dont_req_preauth", False))
            delegation_type = str(acc.get("delegation_type", "None")).lower()

            # Kerberoasting Riski: Ayrıcalıklı yönetici hesabında SPN kaydı tanımlı olması
            if is_admin and spn_list:
                kerberoastable_admins.append(sam)

            # AS-REP Roasting Riski: DONT_REQ_PREAUTH bayrağı aktif olması
            if preauth_not_req:
                asrep_roastable_users.append(sam)

            # Sınırsız Delegasyon (Unconstrained Delegation): TGT çalınma riski
            if "unconstrained" in delegation_type:
                unconstrained_delegations.append(sam)

        # Kerberoasting Değerlendirmesi
        if not kerberoastable_admins:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-01",
                title="Ayrıcalıklı Hesaplarda Kerberoasting İncelemesi",
                severity="CRITICAL", status="PASS",
                current_value="Yönetici hesaplarında SPN yok",
                expected_value="Yönetici hesaplarında SPN olmamalı",
                remediation="Hassas hesaplar Kerberoasting saldırısına karşı güvenli."
            ))
        else:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-01",
                title="Yönetici Hesaplarında Kerberoasting Riski Tespit Edildi",
                severity="CRITICAL", status="FAIL",
                current_value=kerberoastable_admins,
                expected_value="Yönetici hesaplarında SPN bulunmamalı",
                remediation=f"Şu hesaplardaki SPN kayıtlarını kaldırın ve servis hesaplarına taşıyın: {', '.join(kerberoastable_admins)}"
            ))

        # AS-REP Roasting Değerlendirmesi
        if not asrep_roastable_users:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-02",
                title="Kerberos Ön Kimlik Doğrulama Koruması (AS-REP Roasting)",
                severity="HIGH", status="PASS",
                current_value="Tüm hesaplarda Ön Kimlik Doğrulama Zorunlu",
                expected_value="DONT_REQ_PREAUTH bayrağı kapalı olmalı",
                remediation="Parolasız AS-REP talebi oluşturulamaz."
            ))
        else:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-02",
                title="Ön Kimlik Doğrulaması Devre Dışı Hesaplar (AS-REP Roasting Riski)",
                severity="HIGH", status="FAIL",
                current_value=asrep_roastable_users,
                expected_value="DONT_REQ_PREAUTH hiçbir hesapta olmamalı",
                remediation=f"Şu hesaplarda 'Do not require Kerberos preauthentication' bayrağını kaldırın: {', '.join(asrep_roastable_users)}"
            ))

        # Unconstrained Delegation Değerlendirmesi
        if not unconstrained_delegations:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-03",
                title="Kerberos Delegasyon Modeli (Unconstrained Delegation Engeli)",
                severity="CRITICAL", status="PASS",
                current_value="Sınırsız delegasyona sahip nesne yok",
                expected_value="Yalnızca Constrained veya RBCD izinli",
                remediation="TGT sızıntısı riski engellenmiş."
            ))
        else:
            self.findings.append(AdFinding(
                category="ACCOUNTS", rule_id="AD-ACC-03",
                title="Tehlikeli Sınırsız Delegasyon (Unconstrained Delegation) Tespit Edildi",
                severity="CRITICAL", status="FAIL",
                current_value=unconstrained_delegations,
                expected_value="Sınırsız delegasyon yasaklanmalı",
                remediation=f"Şu nesnelerdeki sınırsız delegasyonu Kısıtlı Delegasyon (Constrained Delegation) veya RBCD'ye dönüştürün: {', '.join(unconstrained_delegations)}"
            ))

    # -------------------------------------------------------------------------
    # 6. GÜVEN İLİŞKİLERİ VE SID FILTERING (TRUSTS)
    # -------------------------------------------------------------------------
    def audit_trust_relationships(self) -> None:
        """
        Dış ve orman güven ilişkilerinde SID Filtering ve TGT güvenliğini denetler.
        """
        trusts = self.spec.get("trust_relationships", [])

        unfiltered_trusts = []
        for t in trusts:
            target_domain = t.get("target_domain", "")
            sid_filtering = bool(t.get("sid_filtering_enabled", True))
            if not sid_filtering:
                unfiltered_trusts.append(target_domain)

        if not unfiltered_trusts:
            self.findings.append(AdFinding(
                category="TRUSTS", rule_id="AD-TRUST-01",
                title="Güven İlişkilerinde SID Filtering Zorunluluğu",
                severity="CRITICAL", status="PASS",
                current_value="Tüm güven ilişkilerinde SID Filtering devrede",
                expected_value="SID Filtering: Enabled",
                remediation="Ormanlar arası yetki yükseltme ve sahte SID enjeksiyonu engellenmiş."
            ))
        else:
            self.findings.append(AdFinding(
                category="TRUSTS", rule_id="AD-TRUST-01",
                title="SID Filtering Devre Dışı Güven İlişkisi Tespit Edildi",
                severity="CRITICAL", status="FAIL",
                current_value=unfiltered_trusts,
                expected_value="SID Filtering: Enabled",
                remediation=f"Şu etki alanları ile güven ilişkisinde netdom trust /quarantine:yes komutunu çalıştırın: {', '.join(unfiltered_trusts)}"
            ))

    # -------------------------------------------------------------------------
    # GENEL DENETİM VE DEĞERLENDİRME İCRASI
    # -------------------------------------------------------------------------
    def run_full_ad_audit(self, ref_date_str: Optional[str] = None) -> AdAuditSummary:
        """
        Tüm AD güvenlik kontrollerini icra eder ve ağırlıklı puan hesaplar.
        """
        self.findings.clear()

        # 6 güvenlik alanını denetle
        self.audit_domain_architecture()
        self.audit_kerberos_security(ref_date_str)
        self.audit_ntlm_security()
        self.audit_ldap_smb_signing()
        self.audit_account_and_delegation_risks()
        self.audit_trust_relationships()

        total = len(self.findings)
        passed = sum(1 for f in self.findings if f.status == "PASS")
        failed = sum(1 for f in self.findings if f.status == "FAIL")
        critical = sum(1 for f in self.findings if f.status == "FAIL" and f.severity == "CRITICAL")

        # Puanlama algoritması (100 taban puan, ceza düşümü)
        score = 100.0
        for f in self.findings:
            if f.status == "FAIL":
                if f.severity == "CRITICAL":
                    score -= 20.0
                elif f.severity == "HIGH":
                    score -= 10.0
                elif f.severity == "MEDIUM":
                    score -= 5.0

        score = max(0.0, min(100.0, score))
        score = round(score, 2)

        # Durum tespiti
        if score >= 90.0 and critical == 0:
            status = "SECURE"
        elif score >= 60.0:
            status = "AT_RISK"
        else:
            status = "COMPROMISED"

        arch = self.spec.get("architecture", {})
        self.summary = AdAuditSummary(
            domain_name=arch.get("domain_name", "unknown.domain"),
            forest_name=arch.get("forest_name", "unknown.forest"),
            functional_level=arch.get("domain_functional_level", "Unknown"),
            scan_timestamp=datetime.now().isoformat(),
            ad_security_score=score,
            compliance_status=status,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            critical_findings_count=critical,
            findings=self.findings
        )

        return self.summary

    def generate_powershell_hardening_script(self, output_path: Optional[str] = None) -> str:
        """
        Başarısız olan AD güvenlik kurallarını düzelten PowerShell sıkılaştırma betiği üretir.
        """
        if not self.summary:
            self.run_full_ad_audit()

        ps_lines = [
            "# =============================================================================",
            "# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR",
            "# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)",
            "# Gün 143: Active Directory Domain Services (AD DS) Sertleştirme Betiği",
            "# =============================================================================",
            "#Requires -RunAsAdministrator",
            "$ErrorActionPreference = 'Stop'",
            "",
            "Write-Host '[+] Active Directory Sıkılaştırma Protokolü Başlatılıyor...' -ForegroundColor Cyan",
            ""
        ]

        failed_findings = [f for f in self.summary.findings if f.status == "FAIL"]

        for f in failed_findings:
            ps_lines.append(f"# --- Düzeltme: {f.rule_id} ({f.title}) [Önem: {f.severity}] ---")

            if f.rule_id == "AD-KERB-01":
                # SupportedEncryptionTypes AES zorlama (0x18 = AES128 + AES256)
                ps_lines.append("Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' -Name 'SupportedEncryptionTypes' -Value 0x18 -Type DWord")
                ps_lines.append("Write-Host '[*] Kerberos şifreleme türleri AES-128 ve AES-256 olarak sabitlendi.'")

            elif f.rule_id == "AD-KERB-02":
                ps_lines.append("# UYARI: krbtgt parolası sıfırlama işlemi etki alanında biletleri etkiler. İki aşamada çalıştırınız.")
                ps_lines.append("# Reset-KrbTgt-Password.ps1 -Mode TwoStep -Step 1")

            elif f.rule_id == "AD-NTLM-01":
                # LmCompatibilityLevel = 5 (Sadece NTLMv2)
                ps_lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type DWord")
                ps_lines.append("Write-Host '[*] NTLMv1 kalıcı olarak engellendi. Yalnızca NTLMv2 aktif.'")

            elif f.rule_id == "AD-LDAP-01":
                # LDAP Server Integrity = 2 (Require Signature)
                ps_lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LDAPServerIntegrity' -Value 2 -Type DWord")
                ps_lines.append("Write-Host '[*] LDAP İmzalama zorunlu kılındı (LDAPServerIntegrity=2).'")

            elif f.rule_id == "AD-LDAP-02":
                # LdapEnforceChannelBinding = 2 (Always enforce)
                ps_lines.append("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord")
                ps_lines.append("Write-Host '[*] LDAP Kanal Bağlama zorunlu kılındı.'")

            elif f.rule_id == "AD-SMB-01":
                # SMB Signing zorunluluğu ve SMBv1 kapatılması
                ps_lines.append("Set-SmbServerConfiguration -RequireSecuritySignature $true -Force")
                ps_lines.append("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart")
                ps_lines.append("Write-Host '[*] SMBv1 kapatıldı ve SMB Signing zorunlu yapıldı.'")

            elif f.rule_id == "AD-ACC-02":
                # AS-REP Roasting kapatılması
                for acc in f.current_value:
                    ps_lines.append(f"Set-ADAccountControl -Identity '{acc}' -DoesNotRequirePreAuth $false")
                ps_lines.append("Write-Host '[*] Riskli hesaplarda Kerberos Ön Kimlik Doğrulama zorunlu tutuldu.'")

            elif f.rule_id == "AD-TRUST-01":
                # SID Filtering aktifleştirme
                for tr in f.current_value:
                    ps_lines.append(f"netdom trust {self.summary.domain_name} /domain:{tr} /quarantine:yes")
                ps_lines.append("Write-Host '[*] Dış güven ilişkilerinde SID Filtering (Karantina) etkinleştirildi.'")

            ps_lines.append("")

        ps_lines.append("Write-Host '[+] Active Directory güvenlik sertleştirme adımları tamamlandı.' -ForegroundColor Green")

        content = "\n".join(ps_lines)
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fp:
                fp.write(content)

        return content

    def export_report_json(self, output_path: str) -> None:
        """
        Denetim özetini ve bulguları JSON formatında diske yazar.
        """
        if not self.summary:
            self.run_full_ad_audit()

        data = asdict(self.summary)
        data["_lisans"] = "ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR. Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)."

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
