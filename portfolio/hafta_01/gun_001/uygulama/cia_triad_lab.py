"""
CIA Üçlüsü (Confidentiality, Integrity, Availability) Güvenlik Laboratuvarı
========================================================================
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR

Bu laboratuvar uygulaması, bir okul bilgi sistemi senaryosu üzerinden
Siber Güvenliğin 3 Temel Direğini (Gizlilik, Bütünlük, Erişilebilirlik)
pratik, ölçülebilir ve doğrulanabilir teknik kontrollerle modeller.

Kullanım:
    python cia_triad_lab.py --audit
    python cia_triad_lab.py --verify-integrity
    python cia_triad_lab.py --read --role OGRENCI --student-id 101
    python cia_triad_lab.py --tamper-demo
    python cia_triad_lab.py --dos-demo
"""

import os
import sys
import hashlib
import time
import argparse
from typing import Dict, List, Optional, Tuple


class SecurityException(Exception):
    """Siber güvenlik ihlali temel istisnası."""
    pass


class ConfidentialityViolationError(SecurityException):
    """Gizlilik ihlali: Yetkisiz veri okuma teşebbüsü."""
    pass


class IntegrityViolationError(SecurityException):
    """Bütünlük ihlali: Veri yetkisiz değiştirilmiş veya bozulmuş."""
    pass


class AvailabilityViolationError(SecurityException):
    """Erişilebilirlik ihlali: Sistem veya dosya kilitli/erişilemez."""
    pass


class SchoolSystemSecurityManager:
    """
    Hayalî Okul Bilgi Sistemi için CIA Güvenlik Yöneticisi.
    Gizlilik (Erişim Kontrolü), Bütünlük (SHA-256 Doğrulama) ve
    Erişilebilirlik (Hizmet Durumu ve Kilit Kontrolü) mekanizmalarını yürütür.
    """

    ROLES = {
        "OGRETMEN": {"can_read_all": True, "can_write": True},
        "OGRENCI": {"can_read_all": False, "can_write": False},
        "MISAFIR": {"can_read_all": False, "can_write": False}
    }

    def __init__(self, data_path: str):
        self.data_path = os.path.abspath(data_path)
        self.is_locked = False
        self.audit_log: List[str] = []

    def log_event(self, event_type: str, details: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{event_type}] {details}"
        self.audit_log.append(entry)

    # -------------------------------------------------------------
    # 1. GİZLİLİK (CONFIDENTIALITY) KONTROLLERİ
    # -------------------------------------------------------------
    def read_grades(self, user_role: str, user_student_id: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Rol tabanlı erişim kontrolü (RBAC) ile not kütüğünü okur.
        - ÖĞRETMEN: Tüm kütüğü görür.
        - ÖĞRENCİ: Yalnızca kendi not satırını görebilir. Başkasınınkini isterse ihlal üretir.
        - MİSAFİR: Hiçbir not göremez.
        """
        self.verify_availability()

        role = user_role.upper()
        if role not in self.ROLES:
            self.log_event("GİZLİLİK_İHLALİ", f"Tanımsız rol ile erişim reddedildi: {user_role}")
            raise ConfidentialityViolationError(f"Geçersiz kullanıcı rolü: {user_role}")

        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Veri kütüğü bulunamadı: {self.data_path}")

        records: List[Dict[str, str]] = []
        with open(self.data_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not lines:
            return records

        header = lines[0].split("|")
        for line in lines[1:]:
            parts = line.split("|")
            record = dict(zip(header, parts))
            records.append(record)

        # Yetki Filtrelemesi
        if role == "OGRETMEN":
            self.log_event("GİZLİLİK_ONAY", f"Öğretmen tam kütüğü okudu ({len(records)} kayıt).")
            return records

        elif role == "OGRENCI":
            if not user_student_id:
                self.log_event("GİZLİLİK_İHLALİ", "Öğrenci kimlik numarası olmadan kütük talep etti.")
                raise ConfidentialityViolationError("Öğrenci kimlik numarası (student_id) zorunludur.")
            
            filtered = [r for r in records if r.get("OGRENCI_NO") == str(user_student_id)]
            if not filtered:
                self.log_event("GİZLİLİK_UYARI", f"Öğrenci {user_student_id} için kayıt bulunamadı.")
            else:
                self.log_event("GİZLİLİK_ONAY", f"Öğrenci {user_student_id} yalnızca kendi notunu okudu.")
            return filtered

        else: # MISAFIR
            self.log_event("GİZLİLİK_İHLALİ", f"Misafir rolü not kütüğüne erişmeye çalıştı. Engellendi.")
            raise ConfidentialityViolationError("Misafir kullanıcıların not kütüğüne erişim hakkı yoktur!")

    # -------------------------------------------------------------
    # 2. BÜTÜNLÜK (INTEGRITY) KONTROLLERİ
    # -------------------------------------------------------------
    def calculate_file_hash(self) -> str:
        """Dosyanın kriptografik SHA-256 özetini (hash) hesaplar."""
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(f"Veri kütüğü bulunamadı: {self.data_path}")

        hasher = hashlib.sha256()
        with open(self.data_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def verify_integrity(self, expected_hash: str) -> Tuple[bool, str]:
        """
        Dosyanın anlık SHA-256 özetini beklenen güvenli özet ile karşılaştırır.
        Tek bir bayt dahi değişmişse Bütünlük İhlali (IntegrityViolationError) üretir.
        """
        current_hash = self.calculate_file_hash()
        is_valid = (current_hash.lower() == expected_hash.lower())

        if is_valid:
            self.log_event("BÜTÜNLÜK_ONAY", f"SHA-256 doğrulandı: {current_hash[:16]}...")
        else:
            self.log_event("BÜTÜNLÜK_İHLALİ", f"Beklenen: {expected_hash[:16]}... Bulunan: {current_hash[:16]}...")
            raise IntegrityViolationError(
                f"VERİ BÜTÜNLÜĞÜ BOZULDU!\n"
                f"  Beklenen Hash : {expected_hash}\n"
                f"  Hesaplanan Hash: {current_hash}\n"
                f"  Sonuç          : Dosya yetkisiz değiştirilmiş veya tahrif edilmiştir!"
            )
        return is_valid, current_hash

    # -------------------------------------------------------------
    # 3. ERİŞİLEBİLİRLİK (AVAILABILITY) KONTROLLERİ
    # -------------------------------------------------------------
    def set_system_lock(self, locked: bool):
        """Sistemi kilitler (servis dışı / DoS simülasyonu) veya açar."""
        self.is_locked = locked
        durum = "KİLİTLENDİ (HİZMET DIŞI)" if locked else "AKTİF (ERİŞİLEBİLİR)"
        self.log_event("ERİŞİLEBİLİRLİK_DURUM", f"Sistem durumu: {durum}")

    def verify_availability(self) -> bool:
        """Sistemin yanıt verip vermediğini kontrol eder."""
        if self.is_locked:
            self.log_event("ERİŞİLEBİLİRLİK_İHLALİ", "Hizmete erişilemiyor! Sistem kilitli veya DoS altında.")
            raise AvailabilityViolationError("HİZMET KESİNTİSİ! Not sistemine şu anda erişilemiyor (DoS / Kaynak Kilidi).")
        return True

    # -------------------------------------------------------------
    # GÖSTERİ VE SENARYO İŞLEMLERİ
    # -------------------------------------------------------------
    def tamper_student_grade(self, student_id: str, new_vize: int, new_final: int) -> str:
        """
        Saldırganın kütüğü doğrudan açıp notu değiştirmesini simüle eder.
        Örn: Ali Yılmaz'ın 45 olan vizesini 95 yapar.
        """
        with open(self.data_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        modified = False
        for line in lines:
            if line.startswith(f"{student_id}|"):
                parts = line.strip().split("|")
                parts[3] = str(new_vize)
                parts[4] = str(new_final)
                parts[5] = "Geçti"
                new_lines.append("|".join(parts) + "\n")
                modified = True
            else:
                new_lines.append(line)

        if not modified:
            raise ValueError(f"Öğrenci no bulunamadı: {student_id}")

        with open(self.data_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        self.log_event("TAHRİFAT_SİMÜLASYONU", f"Öğrenci {student_id} notları tahrif edildi: Vize={new_vize}, Final={new_final}")
        return self.calculate_file_hash()


def run_comprehensive_audit(data_file: str) -> bool:
    """CIA üçlüsünün tüm pozitif ve negatif kontrollerini baştan sona icra eder."""
    print("=" * 70)
    print("SİBER GÜVENLİK 365: GÜN 001 — CIA ÜÇLÜSÜ TAM SİSTEM DENETİMİ")
    print("=" * 70)

    mgr = SchoolSystemSecurityManager(data_file)
    baseline_hash = mgr.calculate_file_hash()
    print(f"[*] Hedef Veri Kütüğü: {data_file}")
    print(f"[*] Referans Güvenli SHA-256 Özeti: {baseline_hash}\n")

    # 1. GİZLİLİK TESTLERİ
    print("--- [1. TEST BÖLÜMÜ: GİZLİLİK (CONFIDENTIALITY)] ---")
    # Pozitif Kontrol: Öğretmen yetkisi
    grades_teacher = mgr.read_grades("OGRETMEN")
    print(f"  [+] POZİTİF KONTROL: Öğretmen yetkisiyle okuma başarılı. Toplam kayıt: {len(grades_teacher)}")

    # Pozitif Kontrol: Öğrencinin sadece kendi notunu görmesi
    grades_student = mgr.read_grades("OGRENCI", user_student_id="101")
    print(f"  [+] POZİTİF KONTROL: Öğrenci (101) sadece kendi notunu gördü: {grades_student[0]['AD_SOYAD']} -> {grades_student[0]['VIZE']}/{grades_student[0]['FINAL']}")

    # Negatif Kontrol: Yetkisiz misafirin okuma teşebbüsü
    try:
        mgr.read_grades("MISAFIR")
        print("  [-] HATA: Misafir veriyi okuyabildi! Gizlilik zafiyeti!")
        return False
    except ConfidentialityViolationError as e:
        print(f"  [+] NEGATİF KONTROL BAŞARILI: Misafir engellendi -> {e}")

    # 2. BÜTÜNLÜK TESTLERİ
    print("\n--- [2. TEST BÖLÜMÜ: BÜTÜNLÜK (INTEGRITY)] ---")
    # Pozitif Kontrol: Orijinal dosya bütünlüğü
    is_valid, current_h = mgr.verify_integrity(baseline_hash)
    print(f"  [+] POZİTİF KONTROL: Veri bütünlüğü doğrulandı (Hash eşleşti).")

    # Negatif Kontrol: Tahrifat simülasyonu ve tespiti
    print("  [*] Tahrifat Simülasyonu: Öğrenci 101'in notu 45'ten 95'e çıkarılıyor...")
    # Orijinal içeriği yedekle
    with open(data_file, "r", encoding="utf-8") as f:
        original_content = f.read()

    try:
        tampered_hash = mgr.tamper_student_grade("101", 95, 95)
        print(f"  [*] Yeni Tahrif Edilmiş Hash: {tampered_hash}")
        print(f"  [*] Çığ Etkisi (Avalanche Effect) Gözlendi: Tek not değişti, hash baştan aşağı farklı!")

        # Bütünlük kontrolü bu tahrifatı yakalamalı!
        try:
            mgr.verify_integrity(baseline_hash)
            print("  [-] HATA: Tahrif edilmiş dosya bütünlük kontrolünden geçti!")
            return False
        except IntegrityViolationError as e:
            print(f"  [+] NEGATİF KONTROL BAŞARILI: Bütünlük ihlali derhal yakalandı ve alarm verildi!")
    finally:
        # Dosyayı orijinal haline geri döndür
        with open(data_file, "w", encoding="utf-8") as f:
            f.write(original_content)
        print("  [*] Temizlik: Orijinal veri kütüğü geri yüklendi.")

    # 3. ERİŞİLEBİLİRLİK TESTLERİ
    print("\n--- [3. TEST BÖLÜMÜ: ERİŞİLEBİLİRLİK (AVAILABILITY)] ---")
    # Pozitif Kontrol: Sistem aktifken sorgu
    mgr.verify_availability()
    print("  [+] POZİTİF KONTROL: Sistem aktif, hizmet yanıt veriyor.")

    # Negatif Kontrol: DoS / Kilit simülasyonu
    mgr.set_system_lock(True)
    try:
        mgr.read_grades("OGRETMEN")
        print("  [-] HATA: Kilitli sistem yanıt verdi! Erişilebilirlik izleme zafiyeti!")
        return False
    except AvailabilityViolationError as e:
        print(f"  [+] NEGATİF KONTROL BAŞARILI: Servis kesintisi tespit edildi -> {e}")
    finally:
        mgr.set_system_lock(False)

    print("\n" + "=" * 70)
    print("[SONUÇ] TÜM CIA BİLEŞENLERİ (GİZLİLİK, BÜTÜNLÜK, ERİŞİLEBİLİRLİK) TESTLERİ BAŞARIYLA GEÇTİ!")
    print("=" * 70)
    return True


def main():
    parser = argparse.ArgumentParser(description="CIA Üçlüsü Güvenlik Laboratuvar Aracı (Gün 001)")
    parser.add_argument("--data-file", default=os.path.join(os.path.dirname(__file__), "..", "ornek_veri", "okul_not_sistemi.txt"),
                        help="Not kütüğü veri dosyası")
    parser.add_argument("--audit", action="store_true", help="Kapsamlı CIA güvenlik denetimini çalıştır")
    parser.add_argument("--verify-integrity", action="store_true", help="Mevcut dosya özetini doğrula")
    parser.add_argument("--expected-hash", type=str, help="Karşılaştırılacak beklenen hash")
    parser.add_argument("--read", action="store_true", help="Not kütüğünü oku")
    parser.add_argument("--role", type=str, default="MISAFIR", choices=["OGRETMEN", "OGRENCI", "MISAFIR"], help="Kullanıcı rolü")
    parser.add_argument("--student-id", type=str, help="Öğrenci kimlik numarası")
    parser.add_argument("--tamper-demo", action="store_true", help="Bütünlük ihlali gösterisi (Ali'nin notunu değiştir)")
    parser.add_argument("--dos-demo", action="store_true", help="Erişilebilirlik ihlali gösterisi (Sistemi kilitle)")

    args = parser.parse_args()

    data_file = os.path.abspath(args.data_file)
    if not os.path.exists(data_file):
        print(f"[!] HATA: Veri dosyası bulunamadı: {data_file}")
        sys.exit(1)

    mgr = SchoolSystemSecurityManager(data_file)

    if args.audit:
        success = run_comprehensive_audit(data_file)
        sys.exit(0 if success else 1)

    elif args.verify_integrity:
        current_hash = mgr.calculate_file_hash()
        print(f"Mevcut SHA-256 Özeti: {current_hash}")
        if args.expected_hash:
            is_valid, _ = mgr.verify_integrity(args.expected_hash)
            print("Durum: GEÇERLİ (Bütünlük Korundu)" if is_valid else "Durum: GEÇERSİZ")

    elif args.read:
        try:
            records = mgr.read_grades(args.role, args.student_id)
            print(f"\n[+] Okuma Başarılı ({len(records)} kayıt):")
            for r in records:
                print(f"    Öğrenci No: {r.get('OGRENCI_NO')} | Ad: {r.get('AD_SOYAD')} | Ders: {r.get('DERS')} | Not: {r.get('VIZE')}/{r.get('FINAL')}")
        except ConfidentialityViolationError as e:
            print(f"\n[-] ERİŞİM REDDEDİLDİ (GİZLİLİK KORUMASI): {e}")

    elif args.tamper_demo:
        base_h = mgr.calculate_file_hash()
        print(f"Orijinal Hash: {base_h}")
        with open(data_file, "r", encoding="utf-8") as f:
            backup = f.read()
        try:
            new_h = mgr.tamper_student_grade("101", 95, 95)
            print(f"Tahrifat Sonrası Hash: {new_h}")
            mgr.verify_integrity(base_h)
        except IntegrityViolationError as e:
            print(f"\n[!] BÜTÜNLÜK ALARMI VERİLDİ: {e}")
        finally:
            with open(data_file, "w", encoding="utf-8") as f:
                f.write(backup)
            print("[*] Veri kütüğü orijinal haline geri getirildi.")

    elif args.dos_demo:
        mgr.set_system_lock(True)
        try:
            mgr.read_grades("OGRETMEN")
        except AvailabilityViolationError as e:
            print(f"\n[!] ERİŞİLEBİLİRLİK ALARMI VERİLDİ: {e}")
        finally:
            mgr.set_system_lock(False)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
