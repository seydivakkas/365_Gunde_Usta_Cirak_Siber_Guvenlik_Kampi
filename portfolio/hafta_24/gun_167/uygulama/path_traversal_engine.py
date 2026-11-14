# -*- coding: utf-8 -*-
"""
Gün 167: Path Traversal ve Dosya Erişimi Savunma Motoru (path_traversal_engine.py)

Bu modül; Dizin Atlama (Path / Directory Traversal - CWE-22, CWE-23, CWE-73)
tehditlerini, göreli ve mutlak yol enjeksiyonlarını, URL ve Çift URL (Double Encoding)
kodlamalarını, iç içe temizleme filtre atlatmalarını (....//), Null Byte (%00)
enjeksiyonlarını ve kurumsal Kanonikleştirme (Canonicalization / Path Jailing)
savunma mimarisini simüle ve analiz eden tam teşekküllü motordur.

Yazar: Seydi Eryılmaz (@seydivakkas)
Telif Hakkı: (c) 2026 Seydi Eryılmaz. Tüm Hakları Saklıdır.
"""

# Standart kütüphane modülleri
import os  # İşletim sistemi yol ve dosya işlemleri için
import pathlib  # Nesne yönelimli ve güvenli dosya yolu çözümlemeleri için
import urllib.parse  # URL kodlama çözümleme (unquote) işlemleri için
import re  # Düzenli ifadeler ile dosya adı ve kalıp tespiti için
import json  # Yapılandırılmış rapor çıktıları için
from enum import Enum  # Sabit durum sınıfları oluşturmak için
from typing import Dict, Any, List, Optional, Tuple, Set  # Tip ipuçları için
from dataclasses import dataclass, field  # Veri sınıfları oluşturmak için


class TraversalRiskType(str, Enum):
    """Path Traversal saldırı türlerini ve risk kategorilerini tanımlayan numaralandırma."""
    DOT_DOT_SLASH = "DOT_DOT_SLASH"  # Standart göreli dizin atlama (../ veya ..\)
    ABSOLUTE_PATH_INJECTION = "ABSOLUTE_PATH_INJECTION"  # Mutlak yol ile kök dizini ezme (/etc/passwd, C:\...)
    URL_ENCODED_TRAVERSAL = "URL_ENCODED_TRAVERSAL"  # URL kodlanmış dizin atlama (%2e%2e%2f)
    DOUBLE_URL_ENCODED = "DOUBLE_URL_ENCODED"  # Çift URL kodlanmış dizin atlama (%252e%252e%252f)
    NESTED_FILTER_BYPASS = "NESTED_FILTER_BYPASS"  # İç içe / özyinelemeli filtre atlatması (....//, ..././)
    NULL_BYTE_INJECTION = "NULL_BYTE_INJECTION"  # Sıfır bayt (%00) sonlandırma saldırısı
    UNAPPROVED_EXTENSION = "UNAPPROVED_EXTENSION"  # İzin verilmeyen dosya uzantısı (.env, .sh, .exe vb.)
    CANONICAL_JAIL_ESCAPE = "CANONICAL_JAIL_ESCAPE"  # Kanonik yolun güvenli depolama dizini dışına taşması


@dataclass
class TraversalValidationResult:
    """Yol doğrulama ve analiz sonucunu temsil eden veri yapısı."""
    is_safe: bool  # Yolun güvenli olup olmadığı
    raw_input: str  # Kullanıcıdan gelen ham girdi
    decoded_path: str  # URL kodlamasından arındırılmış yol
    canonical_path: Optional[str] = None  # Çözümlenmiş mutlak kanonik yol
    risk_type: Optional[TraversalRiskType] = None  # Saptanan risk türü
    rejection_reason: Optional[str] = None  # Reddetme gerekçesi
    details: Dict[str, Any] = field(default_factory=dict)  # Ek teknik analiz detayları


@dataclass
class EnterpriseStoragePolicy:
    """Kurumsal dosya depolama ve erişim güvenlik politikasını tanımlayan yapı."""
    base_directory: str = "/var/www/kurumsal_depo"  # Güvenli kök depolama dizini (Jail)
    allowed_extensions: Set[str] = field(default_factory=lambda: {".pdf", ".png", ".jpg", ".docx", ".txt"})  # İzinli uzantılar
    allow_subdirectories: bool = False  # Alt dizin oluşturma/erişme izni
    enforce_strict_basename: bool = True  # Dosya adında / veya \ bulunmasını tamamen yasakla
    max_filename_length: int = 128  # Maksimum dosya adı uzunluğu


class MockFileSystemStorage:
    """Sanal dosya sistemini simüle eden ve yetkisiz dosya okumalarını test eden yapı."""

    def __init__(self, base_directory: str = "/var/www/kurumsal_depo"):
        self.base_dir = os.path.realpath(base_directory)  # Kanonik temel dizin
        # Depo içi meşru dosyalar
        self.files: Dict[str, str] = {
            os.path.realpath(os.path.join(self.base_dir, "fatura_2026.pdf")): "[PDF Content] 2026 Kurumsal Mali Fatura",
            os.path.realpath(os.path.join(self.base_dir, "rapor.docx")): "[DOCX Content] Yıllık Faaliyet ve Denetim Raporu",
            os.path.realpath(os.path.join(self.base_dir, "logo.png")): "[PNG Bytes] Kurumsal Logo Görsel Verisi",
            os.path.realpath(os.path.join(self.base_dir, "kullanici_rehberi.txt")): "[TXT Content] Sistem Kullanım Kılavuzu"
        }
        # Depo dışı sistem dosyaları (Saldırganın hedeflediği hassas veriler)
        self.system_files: Dict[str, str] = {
            os.path.realpath("/etc/passwd"): "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nahmet:x:1001:1001:Ahmet Kaya:/home/ahmet:/bin/bash",
            os.path.realpath("/etc/shadow"): "root:$6$saltsalt$hashhashhash:19000:0:99999:7:::\nwww-data:*:19000:0:99999:7:::",
            os.path.realpath("/var/www/.env"): "DATABASE_URL=postgres://app_user:SuperSecretPassword2026!@10.0.0.5:5432/finance_db\nJWT_SECRET_KEY=998877aabbccddeeff\nAPI_ENCRYPTION_KEY=enc_key_prod_master",
            os.path.realpath("C:/Windows/win.ini"): "[fonts]\n[extensions]\n[mci extensions]\n[files]\n; System Configuration File",
            os.path.realpath("C:/Windows/System32/drivers/etc/hosts"): "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 database.internal"
        }

    def read_file_raw(self, full_path: str) -> Tuple[bool, int, Optional[str]]:
        """Sanal dosya sisteminden tam yola göre dosya okur."""
        canonical = os.path.realpath(full_path)
        # Önce depodaki dosyalar aranır
        if canonical in self.files:
            return True, 200, self.files[canonical]
        # Ardından sistem dosyaları aranır
        if canonical in self.system_files:
            return True, 200, self.system_files[canonical]
        return False, 404, None


class PathTraversalDefenseEngine:
    """
    Merkezi Path Traversal Savunma Motoru:
    Çok katmanlı URL çözme, Null Byte tespiti, özyinelemeli filtre denetimi,
    dosya adı beyaz listesi ve kanonik hapis (Canonical Jail) kontrollerini icra eder.
    """

    def __init__(self, policy: Optional[EnterpriseStoragePolicy] = None):
        self.policy = policy or EnterpriseStoragePolicy()
        self.mock_storage = MockFileSystemStorage(base_directory=self.policy.base_directory)
        # Güvenli dosya adı regex deseni: Yalnızca alfanümerik, alt tire, tire ve tek nokta
        self.safe_filename_pattern = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

    def multi_pass_url_decode(self, raw_path: str, max_passes: int = 3) -> Tuple[str, bool, bool]:
        """
        Çift veya çoklu URL kodlamasını (Double Encoding) ortaya çıkarmak için çok geçişli çözümleme yapar.
        Döndürür: (son_metin, url_kodlu_muydu, cift_url_kodlu_muydu)
        """
        current = raw_path
        was_single_encoded = False
        was_double_encoded = False

        # İlk geçiş
        decoded_once = urllib.parse.unquote(current)
        if decoded_once != current:
            was_single_encoded = True
            current = decoded_once
            # İkinci geçiş (Çift kodlama testi)
            decoded_twice = urllib.parse.unquote(current)
            if decoded_twice != current:
                was_double_encoded = True
                current = decoded_twice

        return current, was_single_encoded, was_double_encoded

    def detect_nested_traversal(self, text: str) -> bool:
        """
        Gevşek filtreleri atlatmak için kullanılan iç içe dizin atlama kalıplarını saptar.
        Örnek: ....// veya ..././ veya ..//
        """
        nested_patterns = [
            r"\.{3,}[/\\]",       # 3 veya daha fazla nokta + eğik çizgi: .../ veya ....//
            r"\.{2,}[/\\]{2,}",   # 2 veya daha fazla nokta + 2 veya daha fazla eğik çizgi: ..// veya ..\\
            r"\.{2,}[/\\]\.[/\\]" # 2 nokta + eğik çizgi + 1 nokta + eğik çizgi: .././
        ]
        for pattern in nested_patterns:
            if re.search(pattern, text):
                return True
        return False

    def validate_path(self, raw_input_path: str) -> TraversalValidationResult:
        """
        Kullanıcıdan gelen ham dosya yolunu tüm kurumsal güvenlik katmanlarına göre doğrular.
        """
        # 1. KONTROL: Boş veya geçersiz girdi denetimi
        if not raw_input_path or not isinstance(raw_input_path, str):
            return TraversalValidationResult(
                is_safe=False, raw_input=str(raw_input_path), decoded_path="",
                risk_type=TraversalRiskType.DOT_DOT_SLASH,
                rejection_reason="Dosya yolu boş veya geçersiz veri tipinde."
            )

        # 2. KONTROL: Null Byte (%00 veya \x00) Enjeksiyonu Tespiti
        if "\x00" in raw_input_path or "%00" in raw_input_path.lower():
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path="",
                risk_type=TraversalRiskType.NULL_BYTE_INJECTION,
                rejection_reason="Zararlı Null Byte (%00) sonlandırma karakteri tespit edildi!"
            )

        # 3. KONTROL: Çoklu URL Kodlama Çözümlemesi (Double Encoding Detection)
        decoded_path, was_single, was_double = self.multi_pass_url_decode(raw_input_path)

        # Çift kodlama yapılmışsa derhal bayraklanır
        if was_double:
            if ".." in decoded_path or "/" in decoded_path or "\\" in decoded_path:
                return TraversalValidationResult(
                    is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                    risk_type=TraversalRiskType.DOUBLE_URL_ENCODED,
                    rejection_reason=f"Çift URL kodlamalı (Double Encoded) Dizin Atlama saldırısı saptandı: '{raw_input_path}' -> '{decoded_path}'"
                )

        # 4. KONTROL: İç İçe / Kendi Kendini Temizleyen Filtre Kalıpları (....//)
        if self.detect_nested_traversal(raw_input_path) or self.detect_nested_traversal(decoded_path):
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                risk_type=TraversalRiskType.NESTED_FILTER_BYPASS,
                rejection_reason="İç içe özyinelemeli filtre atlatma kalıbı (....//) tespit edildi!"
            )

        # 5. KONTROL: Standart Göreli Dizin Atlama (../ veya ..\)
        if ".." in decoded_path:
            risk = TraversalRiskType.URL_ENCODED_TRAVERSAL if was_single else TraversalRiskType.DOT_DOT_SLASH
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                risk_type=risk,
                rejection_reason=f"Göreli dizin atlama ('..') kalıbı tespit edildi: '{decoded_path}'"
            )

        # 6. KONTROL: Mutlak Yol Enjeksiyonu (/etc/passwd, C:\...)
        if decoded_path.startswith("/") or decoded_path.startswith("\\") or re.match(r"^[a-zA-Z]:[/\\]", decoded_path):
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                risk_type=TraversalRiskType.ABSOLUTE_PATH_INJECTION,
                rejection_reason=f"Kök dizini ezmeye çalışan Mutlak Yol (Absolute Path) enjeksiyonu tespit edildi: '{decoded_path}'"
            )

        # 7. KONTROL: Katı Dosya Adı ve Ayracı Kısıtlaması (Strict Basename Whitelist)
        if self.policy.enforce_strict_basename:
            if "/" in decoded_path or "\\" in decoded_path:
                return TraversalValidationResult(
                    is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                    risk_type=TraversalRiskType.DOT_DOT_SLASH,
                    rejection_reason="Dizin ayracı kullanımına izin verilmiyor; yalnızca saf dosya adı kabul edilir."
                )

            if not self.safe_filename_pattern.match(decoded_path):
                return TraversalValidationResult(
                    is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                    risk_type=TraversalRiskType.DOT_DOT_SLASH,
                    rejection_reason=f"Dosya adı izin verilmeyen özel karakterler içeriyor: '{decoded_path}'"
                )

        # 8. KONTROL: İzin Verilen Dosya Uzantısı Kontrolü
        _, ext = os.path.splitext(decoded_path.lower())
        if self.policy.allowed_extensions and ext not in self.policy.allowed_extensions:
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                risk_type=TraversalRiskType.UNAPPROVED_EXTENSION,
                rejection_reason=f"İzin verilmeyen dosya uzantısı: '{ext}'. İzin verilenler: {sorted(list(self.policy.allowed_extensions))}"
            )

        # 9. KONTROL: Kanonik Yol ve Güvenli Hapis (Canonical Jail / Chroot Enforcement)
        base_canonical = os.path.realpath(self.policy.base_directory)
        target_candidate = os.path.realpath(os.path.join(base_canonical, decoded_path))

        try:
            common = os.path.commonpath([base_canonical, target_candidate])
            if common != base_canonical:
                return TraversalValidationResult(
                    is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                    canonical_path=target_candidate,
                    risk_type=TraversalRiskType.CANONICAL_JAIL_ESCAPE,
                    rejection_reason=f"Kanonik yol güvenli depo sınırları dışına taşıyor! (Jail Escape: {target_candidate})"
                )
        except ValueError:
            return TraversalValidationResult(
                is_safe=False, raw_input=raw_input_path, decoded_path=decoded_path,
                risk_type=TraversalRiskType.CANONICAL_JAIL_ESCAPE,
                rejection_reason="Farklı sürücü köküne atlama girişimi engellendi."
            )

        # Tüm kontroller başarılı
        return TraversalValidationResult(
            is_safe=True, raw_input=raw_input_path, decoded_path=decoded_path,
            canonical_path=target_candidate,
            details={"verified_filename": decoded_path, "canonical_path": target_candidate}
        )

    def secure_read_file(self, user_filename: str) -> Dict[str, Any]:
        """
        GÜVENLİ DOSYA OKUMA İŞLEMİ:
        Yolu doğrular, hapis kontrolü yapar ve yalnızca izinli dosyalara erişim sağlar.
        """
        val = self.validate_path(user_filename)
        if not val.is_safe:
            return {
                "success": False,
                "status_code": 403,
                "error": "ACCESS_DENIED_PATH_TRAVERSAL",
                "risk_type": val.risk_type.value if val.risk_type else None,
                "reason": val.rejection_reason,
                "content": None
            }

        found, code, content = self.mock_storage.read_file_raw(val.canonical_path)
        return {
            "success": found,
            "status_code": code,
            "error": None if found else "NOT_FOUND",
            "reason": "Başarılı güvenli dosya erişimi" if found else "Dosya bulunamadı",
            "content": content
        }

    def vulnerable_read_file(self, user_filename: str) -> Dict[str, Any]:
        """
        ZAFİYETLİ DOSYA OKUMA İŞLEMİ:
        Girdiyi filtrelemeden os.path.join ile birleştirir veya mutlak yol verildiğinde
        doğrudan açar (os.path.join mutlak yol görünce base_dir'i ezer!).
        """
        joined_path = os.path.join(self.policy.base_directory, user_filename)
        canonical_target = os.path.realpath(joined_path)
        base_canonical = os.path.realpath(self.policy.base_directory)

        found, code, content = self.mock_storage.read_file_raw(canonical_target)
        is_leak = found and (not canonical_target.startswith(base_canonical))
        return {
            "success": found,
            "status_code": code,
            "accessed_path": canonical_target,
            "content": content,
            "is_vulnerable_leak": is_leak
        }
