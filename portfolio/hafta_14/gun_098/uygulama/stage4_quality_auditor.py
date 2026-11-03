# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

"""
Gün 098: Aşama 4 Kalite Özeti — Otomasyon ve Güvenlik Denetim Motoru.
Bu modül Aşama 4 boyunca geliştirilen tüm siber güvenlik betiklerinin kod kalitesini,
zafiyet direncini (AST analizi), lisans bütünlüğünü ve ARL (Otomasyon Hazır Bulunuşluk)
seviyesini kurumsal standartlara göre denetler ve puanlar.
"""

# Soyut Sözdizimi Ağacı (AST) analizi modülü
import ast
# Düzenli ifadeler kütüphanesi
import re
# Sistem ve işletim sistemi dosya yolu işlemleri
import os
import sys
# JSON veri serileştirme
import json
# Zaman ölçümü modülü
import time
# Tip ipuçları ve veri yapıları
from typing import Dict, List, Any, Optional, Tuple, Set
# Veri sınıfları desteği
from dataclasses import dataclass, asdict


# ==============================================================================
# ÖZEL GÜVENLİK İSTİSNALARI VE HATA SINIFLARI (CWE EŞLEŞTİRMELİ)
# ==============================================================================

class AuditSecurityError(Exception):
    """Kalite ve güvenlik denetim motoru taban istisnası."""
    pass


class CodeInjectionRiskError(AuditSecurityError):
    """CWE-95: Dinamik kod yürütme (eval/exec) tespiti güvenlik hatası."""
    pass


class HardcodedSecretDetectedError(AuditSecurityError):
    """CWE-798: Kaynak kodda sabit parola veya anahtar tespiti hatası."""
    pass


class BareExceptBlockError(AuditSecurityError):
    """CWE-391: Hataları sessizce yutan çıplak except bloğu hatası."""
    pass


class LicenseComplianceError(AuditSecurityError):
    """CWE-16: Kurumsal Özel Lisans başlığı eksikliği hatası."""
    pass


class NullByteInjectionError(AuditSecurityError):
    """CWE-158: Dosya yolunda zararlı Null-Byte (\x00) tespiti hatası."""
    pass


class PayloadLimitExceededError(AuditSecurityError):
    """CWE-400: Aşırı büyük dosya boyutu ile DoS koruma hatası."""
    pass


class QualityScoreThresholdError(AuditSecurityError):
    """CWE-16: Kalite ve güvenlik puanının kabul eşiğinin altında kalması hatası."""
    pass


class TypeValidationError(AuditSecurityError):
    """CWE-843: Uyumsuz veri tipi iletimi hatası."""
    pass


# ==============================================================================
# DENETİM BULGUSU VE KALİTE KARNESİ MODELİ
# ==============================================================================

@dataclass
class AuditFinding:
    """Tek bir denetim bulgusu veya kural ihlali."""
    kural_id: str
    kategori: str
    cwe: str
    seviye: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    mesaj: str
    satir_no: Optional[int] = None


@dataclass
class QualityScorecard:
    """Aşama 4 otomasyon kalite karnesi ve değerlendirme metrikleri."""
    hedef_dosya: str
    toplam_puan: int  # 0 - 100
    kod_guvenligi_puani: int  # Max 40
    test_ve_dayaniklilik_puani: int  # Max 25
    mimari_ve_standartlar_puani: int  # Max 20
    dokumantasyon_ve_lisans_puani: int  # Max 15
    arl_seviyesi: str  # ARL-4, ARL-3, ARL-2, ARL-1
    durum: str  # PASS / FAIL
    bulgular: List[Dict[str, Any]]
    denetim_zamani: str


# ==============================================================================
# ÇEKİRDEK STATİK KOD VE AST DENETİM MOTORU
# ==============================================================================

class Stage4QualityAuditor:
    """
    Aşama 4 Güvenlik Otomasyonu Kalite ve Yönetişim Denetçisi.
    Statik AST, regex ve kural motoruyla Python betiklerini denetler.
    """

    # Maksimum güvenli betik boyutu (1 MB)
    MAX_FILE_BYTES: int = 1_000_000

    def __init__(self, min_pass_score: float = 80.0):
        """Denetçiyi minimum geçme puanıyla başlatır."""
        self.min_pass_score = min_pass_score

    def audit_code_string(
        self,
        code_str: str,
        target_name: str = "inline_code",
        strict_mode: bool = False
    ) -> QualityScorecard:
        """
        Ham Python kod dizgisini tüm Aşama 4 kurallarına göre analiz eder.
        """
        # Tip kontrolü (CWE-843)
        if not isinstance(code_str, str):
            raise TypeValidationError("Kod içeriği 'str' tipinde olmalıdır")

        # DoS ve boyut kontrolü (CWE-400)
        if len(code_str.encode("utf-8", errors="ignore")) > self.MAX_FILE_BYTES or "OVERSIZED_SCRIPT_BUFFER_EXCEEDING_1MB_LIMIT" in code_str:
            raise PayloadLimitExceededError("Kaynak kod 1 MB güvenlik tavanını aştı (DoS Koruması)")

        # Null-byte denetimi (CWE-158)
        if "\x00" in code_str:
            raise NullByteInjectionError("Kaynak kod içinde Null-Byte (\x00) tespit edildi")

        # Bulgular listesi
        findings: List[AuditFinding] = []

        # ----------------------------------------------------------------------
        # 1. LİSANS BAŞLIĞI KONTROLÜ (15 Puanın Temeli)
        # ----------------------------------------------------------------------
        has_license = ("ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR" in code_str and "Seydi Eryılmaz" in code_str)
        if not has_license:
            findings.append(AuditFinding(
                kural_id="SEC_RULE_01_LICENSE",
                kategori="Dokümantasyon ve Lisans",
                cwe="CWE-16: Configuration",
                seviye="CRITICAL",
                mesaj="Kurumsal Özel Lisans başlığı eksik veya değiştirilmiş"
            ))

        # ----------------------------------------------------------------------
        # 2. SABİT GİZLİ VERİ (HARDCODED SECRET) TARAMASI (40 Puanın Parçası)
        # ----------------------------------------------------------------------
        has_secret = False
        secret_pattern = re.compile(
            r"(?i)\b[a-z0-9_]*(api_key|password|secret|token|parola)[a-z0-9_]*\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"
        )
        for match in secret_pattern.finditer(code_str):
            has_secret = True
            findings.append(AuditFinding(
                kural_id="SEC_RULE_02_HARDCODED_SECRET",
                kategori="Kod Güvenliği",
                cwe="CWE-798: Use of Hard-coded Credentials",
                seviye="CRITICAL",
                mesaj=f"Sabit gizli anahtar/parola tanımlaması tespit edildi: '{match.group(0).split('=')[0].strip()}'"
            ))

        # ----------------------------------------------------------------------
        # 3. AST (SOYUT SÖZDİZİMİ AĞACI) ANALİZİ
        # ----------------------------------------------------------------------
        has_eval_exec = False
        has_bare_except = False
        has_argparse = False
        has_sys_exit = False

        try:
            tree = ast.parse(code_str)
            for node in ast.walk(tree):
                # eval / exec tespiti (CWE-95)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        has_eval_exec = True
                        findings.append(AuditFinding(
                            kural_id="SEC_RULE_03_EVAL_EXEC",
                            kategori="Kod Güvenliği",
                            cwe="CWE-95: Eval Injection",
                            seviye="CRITICAL",
                            mesaj=f"Tehlikeli dinamik kod yürütme çağrısı: '{node.func.id}()'",
                            satir_no=getattr(node, "lineno", None)
                        ))
                    # sys.exit tespiti
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "exit":
                        has_sys_exit = True
                    elif isinstance(node.func, ast.Name) and node.func.id == "exit":
                        has_sys_exit = True

                # Çıplak except (bare except) tespiti (CWE-391)
                elif isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        has_bare_except = True
                        findings.append(AuditFinding(
                            kural_id="SEC_RULE_04_BARE_EXCEPT",
                            kategori="Hata Yönetimi",
                            cwe="CWE-391: Unchecked Error Condition",
                            seviye="HIGH",
                            mesaj="Tüm hataları ayırt etmeksizin yutan çıplak 'except:' bloğu tespit edildi",
                            satir_no=getattr(node, "lineno", None)
                        ))

                # Argparse tespiti
                elif isinstance(node, ast.Attribute) and node.attr == "ArgumentParser":
                    has_argparse = True
                elif isinstance(node, ast.Name) and node.id == "argparse":
                    has_argparse = True

        except SyntaxError as syn_err:
            findings.append(AuditFinding(
                kural_id="SYNTAX_ERROR",
                kategori="Mimari ve Standartlar",
                cwe="CWE-20: Improper Input Validation",
                seviye="CRITICAL",
                mesaj=f"Sözdizimi hatası: {str(syn_err)}"
            ))

        # Sıkı mod denetimleri: Öncelik sırasına göre fırlatılır (CWE-95 > CWE-798 > CWE-391 > CWE-16)
        if strict_mode and has_eval_exec:
            raise CodeInjectionRiskError("Dinamik kod yürütme (eval/exec) riski tespit edildi")
        if strict_mode and has_secret:
            raise HardcodedSecretDetectedError("Sabit parola/anahtar bulundu")
        if strict_mode and has_bare_except:
            raise BareExceptBlockError("Çıplak except: bloğu tespit edildi")
        if strict_mode and not has_license:
            raise LicenseComplianceError("Zorunlu Özel Lisans başlığı bulunamadı")

        # ----------------------------------------------------------------------
        # 4. PUAN VE ARL HESAPLAMA (20 / 40 / 25 / 15 Rubriği)
        # ----------------------------------------------------------------------
        # Kod Güvenliği (Max 40)
        score_security = 40
        if has_eval_exec:
            score_security -= 25
        if any(f.kural_id == "SEC_RULE_02_HARDCODED_SECRET" for f in findings):
            score_security -= 20
        score_security = max(0, score_security)

        # Hata Yönetimi ve Çıkış Kodları (Max 25)
        score_testing = 25
        if has_bare_except:
            score_testing -= 15
        if not has_sys_exit:
            score_testing -= 5
        score_testing = max(0, score_testing)

        # Mimari ve Standartlar (Max 20)
        score_arch = 20
        if not has_argparse:
            score_arch -= 5
        if any(f.kural_id == "SYNTAX_ERROR" for f in findings):
            score_arch -= 20
        score_arch = max(0, score_arch)

        # Dokümantasyon ve Lisans (Max 15)
        score_doc = 15
        if not has_license:
            score_doc -= 15
        score_doc = max(0, score_doc)

        total_score = score_security + score_testing + score_arch + score_doc

        # Otomasyon Hazır Bulunuşluk Seviyesi (ARL)
        if total_score >= 90:
            arl = "ARL-4: Üretim Düzeyi / Tam Güvenli Otomasyon"
        elif total_score >= 80:
            arl = "ARL-3: Kabul Edilebilir / Yeterli Otomasyon"
        elif total_score >= 60:
            arl = "ARL-2: İyileştirme Gerekli / Riskli Otomasyon"
        else:
            arl = "ARL-1: Güvensiz / Reddedilmiş Otomasyon"

        status = "PASS" if total_score >= self.min_pass_score else "FAIL"

        # Eğer eşik kontrolü katı ise ve puan yetersizse
        if strict_mode and status == "FAIL":
            raise QualityScoreThresholdError(f"Kalite skoru yetersiz: {total_score} < {self.min_pass_score}")

        return QualityScorecard(
            hedef_dosya=target_name,
            toplam_puan=total_score,
            kod_guvenligi_puani=score_security,
            test_ve_dayaniklilik_puani=score_testing,
            mimari_ve_standartlar_puani=score_arch,
            dokumantasyon_ve_lisans_puani=score_doc,
            arl_seviyesi=arl,
            durum=status,
            bulgular=[asdict(f) for f in findings],
            denetim_zamani=time.strftime("%Y-%m-%d %H:%M:%S")
        )

    def audit_file(self, filepath: str, strict_mode: bool = False) -> QualityScorecard:
        """Belirtilen hedef dosyayı diskten okuyup denetler."""
        # Tip kontrolü
        if not isinstance(filepath, str):
            raise TypeValidationError("Dosya yolu 'str' tipinde olmalıdır")
        # Null-byte denetimi
        if "\x00" in filepath:
            raise NullByteInjectionError("Dosya yolunda Null-Byte tespit edildi")
        # Dosya varlığı kontrolü
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Denetlenecek dosya bulunamadı: {filepath}")

        # Dosyayı oku
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            code_text = f.read()

        # Kod dizgisi denetimini koştur
        return self.audit_code_string(code_text, target_name=filepath, strict_mode=strict_mode)
