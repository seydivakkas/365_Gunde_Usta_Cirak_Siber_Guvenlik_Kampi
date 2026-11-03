# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G042: Aşama 2 Kalite Özeti ve Kabul Motoru - İşletim Sistemi Temelleri.

Bu modül, Aşama 02 (Gün 29-42) boyunca işlenen tüm işletim sistemi güvenliği temellerini
(süreçler, dosya izinleri, günlükler, bütünlük karmaları, yedekleme ve servisler)
6 ana sütun altında salt-okunur kanıtlarla denetler ve Aşama 2 Kabul Kararını (PASS/HOLD) üretir.
"""

# Dosya yolu ve işletim sistemi ortamı işlemleri için os modülünü yüklüyoruz.
import os
# Komut satırı bayraklarını (CLI) yönetmek amacıyla argparse kütüphanesini dahil ediyoruz.
import argparse
# Yapılandırılmış JSON envanterlerini okumak ve serileştirmek için json modülünü kullanıyoruz.
import json
# Çıktı yönlendirmesi ve hata kodları için sys modülünü çağırıyoruz.
import sys
# Tip güvenliği ve statik analiz için typing kütüphanesinden gerekli tipleri alıyoruz.
from typing import Dict, Any, List, Tuple, Optional
# Zaman damgalı kabul raporları oluşturmak için datetime ve timezone sınıflarını dahil ediyoruz.
from datetime import datetime, timezone
# Regex kontrolleri (sekizli izin ve sha256 karmaları için) amacıyla re modülünü içe aktarıyoruz.
import re

# Aşama 2 Kabulü için Zorunlu 6 Güvenlik Sütunu
REQUIRED_PILLARS = ["processes", "permissions", "logging", "hashes", "backups", "services"]

# SHA-256 Karakter ve Uzunluk Doğrulama Deseni (Tam 64 karakter onaltılık dize)
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

# Sekizli (Octal) Dosya İzni Deseni (3 veya 4 basamaklı sekizli sayı: örn 0640, 0440, 644)
OCTAL_PERM_REGEX = re.compile(r"^0?[0-7]{3,4}$")


class Stage2AuditError(ValueError):
    """Aşama 2 denetim şeması, sütun eksikliği veya kural ihlallerinde fırlatılan özel istisna sınıfı."""
    # ValueError temel sınıfından kalıtım alarak özel istisna tipini oluşturuyoruz.
    pass


def validate_octal_permission(perm_str: str) -> bool:
    """
    Bir dosya izin dizgisinin geçerli bir POSIX sekizli (octal) sayı olup olmadığını doğrular.
    
    Argümanlar:
        perm_str: Kontrol edilecek sekizli izin metni (örn: '0640').
        
    Döndürür:
        Geçerli ise True, değilse False.
    """
    # Girdinin string tipinde olduğunu ve boş olmadığını teyit ediyoruz.
    if not isinstance(perm_str, str) or not perm_str.strip():
        # Geçersiz tipte False döndürüyoruz.
        return False
    # Regex şablonuna uyup uymadığını sınıyoruz.
    return bool(OCTAL_PERM_REGEX.match(perm_str.strip()))


def validate_sha256_hash(hash_str: str) -> bool:
    """
    Bir bütünlük karmasının geçerli bir 64 karakterli SHA-256 onaltılık dize olduğunu doğrular.
    
    Argümanlar:
        hash_str: Denetlenecek hash metni.
        
    Döndürür:
        Geçerli ise True, değilse False.
    """
    # Girdinin metin olduğunu ve boş olmadığını inceliyoruz.
    if not isinstance(hash_str, str) or not hash_str.strip():
        # Geçersizse False döndürüyoruz.
        return False
    # Regex ile 64 karakterlik hex yapısını sınıyoruz.
    return bool(SHA256_REGEX.match(hash_str.strip()))


def validate_stage2_inventory_schema(data: Dict[str, Any]) -> None:
    """
    Aşama 2 kabul envanterinin kök yapısını ve 6 temel sütunun varlığını doğrular.
    
    Argümanlar:
        data: Denetlenecek JSON kök sözlüğü.
    """
    # Kök yapının sözlük olduğunu sınıyoruz.
    if not isinstance(data, dict):
        # Sözlük değilse istisna üretiyoruz.
        raise Stage2AuditError(f"Aşama 2 envanteri bir JSON sözlüğü olmalıdır, alınan: {type(data).__name__}")
    
    # 6 zorunlu sütunun tek tek varlığını denetliyoruz.
    for pillar in REQUIRED_PILLARS:
        # Sütunun ana sözlükte yer alıp almadığına bakıyoruz.
        if pillar not in data:
            # Eksik sütun tespit edilirse hata fırlatıyoruz.
            raise Stage2AuditError(f"Aşama 2 kabulü için zorunlu '{pillar}' sütunu envanterde bulunamadı.")
        # Sütunun sözlük tipinde olmasını şart koşuyoruz.
        if not isinstance(data[pillar], dict):
            # Sözlük değilse tip hatası fırlatıyoruz.
            raise Stage2AuditError(f"'{pillar}' sütun verisi bir sözlük olmalıdır, alınan: {type(data[pillar]).__name__}")


def audit_processes_pillar(proc_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Süreç hijyeni sütununu denetler; yetkisiz veya şüpheli süreçleri araştırır.
    
    Argümanlar:
        proc_data: Süreçler sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Başlangıç tam puanını belirliyoruz.
    score = 100.0
    # Bulgular listesini başlatıyoruz.
    findings: List[str] = []
    
    # Süreç listesindeki girdileri denetliyoruz.
    unprivileged = proc_data.get("unprivileged_service_processes", [])
    # Listenin tipini kontrol ediyoruz.
    if not isinstance(unprivileged, list):
        # Liste değilse hata veriyoruz.
        raise Stage2AuditError("unprivileged_service_processes bir liste olmalıdır.")
        
    # Her bir süreci inceliyoruz.
    for proc in unprivileged:
        # Sürecin sözlük olduğunu teyit ediyoruz.
        if not isinstance(proc, dict):
            # Tip hatası.
            raise Stage2AuditError("Süreç girdisi bir sözlük olmalıdır.")
        # PID değerinin pozitif bir sayı olduğunu sınıyoruz.
        pid = proc.get("pid")
        # PID tip ve negatif kontrolü.
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            # Hatalı PID durumunda istisna üretiyoruz.
            raise Stage2AuditError(f"Geçersiz PID değeri tespit edildi: {pid}. Pozitif tam sayı olmalıdır.")
            
    # Yetkisiz süreç varlığını sınıyoruz.
    rogue = proc_data.get("rogue_or_unauthorized_processes", [])
    # Şüpheli süreç varsa puan düşürüyoruz.
    if rogue:
        # Ceza puanı uyguluyoruz.
        score -= min(50.0, len(rogue) * 20.0)
        # Bulguyu kaydediyoruz.
        findings.append(f"Kritik: {len(rogue)} adet yetkisiz süreç tespit edildi: {rogue}")
    else:
        # Olumlu durumu not düşüyoruz.
        findings.append("Süreç hijyeni tam; tüm arka plan servisleri kum havuzlu ve yetkisiz süreç bulunamadı.")
        
    # Puanı ve bulguları döndürüyoruz.
    return max(0.0, score), findings


def audit_permissions_pillar(perm_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Dosya izinleri ve umask sütununu denetler.
    
    Argümanlar:
        perm_data: İzinler sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Tam puanla başlıyoruz.
    score = 100.0
    # Bulgular listesi.
    findings: List[str] = []
    
    # Sistem umask değerini denetliyoruz.
    umask_val = perm_data.get("system_umask", "")
    # Sekizli umask kontrolü yapıyoruz.
    if not validate_octal_permission(umask_val):
        # Geçersiz umask durumunda hata fırlatıyoruz.
        raise Stage2AuditError(f"Geçersiz umask değeri: '{umask_val}'. Sekizli (octal) olmalıdır.")
    # Güvenli umask kuralı: en az 0027 olmalıdır.
    if umask_val not in ["0027", "027", "0077", "077"]:
        # Gevşek umask ceza puanı.
        score -= 15.0
        # Bulguyu ekliyoruz.
        findings.append(f"Uyarı: Sistem umask değeri ({umask_val}) önerilen 0027 veya 0077 değerinden daha gevşek.")
    else:
        # Başarılı umask durumu.
        findings.append(f"Umask değeri ({umask_val}) sıkılaştırma standartlarına tam uyumlu.")
        
    # İzlenen kritik dosyaları sınıyoruz.
    files = perm_data.get("monitored_files", [])
    # Liste kontrolü.
    if not isinstance(files, list):
        # Hata fırlatıyoruz.
        raise Stage2AuditError("monitored_files bir liste olmalıdır.")
        
    # Dosyaları tek tek geziyoruz.
    for f_info in files:
        # Sözlük kontrolü.
        if not isinstance(f_info, dict):
            # Tip hatası.
            raise Stage2AuditError("Dosya izin girdisi bir sözlük olmalıdır.")
        # Dosya yolunu alıyoruz.
        f_path = f_info.get("path", "N/A")
        # Mevcut izin octal değerini alıyoruz.
        f_octal = f_info.get("permission_octal", "")
        # Sekizli format kontrolünü çalıştırıyoruz.
        if not validate_octal_permission(f_octal):
            # Geçersiz format durumunda hata üretiyoruz.
            raise Stage2AuditError(f"Dosya '{f_path}' için geçersiz sekizli izin değeri: '{f_octal}'")
        # Beklenen izinle uyuşmazlık kontrolü.
        expected = f_info.get("expected_octal")
        # Uyuşmazlık varsa puan kırıyoruz.
        if expected and f_octal != expected:
            # Ceza puanı uyguluyoruz.
            score -= 20.0
            # Bulguyu ekliyoruz.
            findings.append(f"İzin İhlali: {f_path} izni {f_octal}, beklenen: {expected}")
            
    # Temiz durum notu.
    if score == 100.0:
        # Tam uyum kaydı.
        findings.append("Kritik sistem dosyaları (/etc/shadow, /etc/sudoers vb.) tam yetki uyumluluğuna sahip.")
        
    # Sonucu döndürüyoruz.
    return max(0.0, score), findings


def audit_logging_pillar(log_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Olay günlükleme, journald ve auditd sütununu denetler.
    
    Argümanlar:
        log_data: Günlükleme sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Başlangıç puanı.
    score = 100.0
    # Bulgular listesi.
    findings: List[str] = []
    
    # Journald kalıcılığı kontrolü.
    if not log_data.get("journald_persistent", False):
        # Kalıcı değilse ceza uyguluyoruz.
        score -= 25.0
        # Bulguyu ekliyoruz.
        findings.append("Kritik: journald kalıcı (persistent) kipte değil; yeniden başlatmalarda log kaybı riski.")
        
    # Auditd servis durumu kontrolü.
    if not log_data.get("auditd_active", False):
        # Auditd kapalıysa ceza.
        score -= 25.0
        # Bulguyu ekliyoruz.
        findings.append("Eksiklik: auditd çekirdek denetim servisi aktif değil.")
        
    # Merkezi SIEM aktarımı kontrolü.
    if not log_data.get("remote_forwarding_configured", False):
        # SIEM aktarımı yoksa ceza.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append("Uyarı: Merkezi SIEM log aktarımı yapılandırılmamış.")
    else:
        # Başarılı aktarım notu.
        findings.append(f"Merkezi SIEM aktarımı aktif: {log_data.get('remote_target')}")
        
    # Sonucu döndürüyoruz.
    return max(0.0, score), findings


def audit_hashes_pillar(hash_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Kritik ikili ve yapılandırma dosyalarının SHA-256 bütünlük sütununu denetler.
    
    Argümanlar:
        hash_data: Karmalar sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Başlangıç puanı.
    score = 100.0
    # Bulgular listesi.
    findings: List[str] = []
    
    # Girdiler listesini alıyoruz.
    entries = hash_data.get("entries", [])
    # Liste denetimi yapıyoruz.
    if not isinstance(entries, list):
        # Tip hatası.
        raise Stage2AuditError("Hash 'entries' bir liste olmalıdır.")
    # En az bir girdi olması gerektiğini sınıyoruz.
    if not entries:
        # Boşsa ceza puanı.
        score -= 50.0
        # Bulguyu ekliyoruz.
        findings.append("Uyarı: Hiçbir kritik dosya hash karması tanımlanmamış.")
        return score, findings
        
    # Karmaları tek tek sınıyoruz.
    for h_entry in entries:
        # Sözlük kontrolü.
        if not isinstance(h_entry, dict):
            # Tip hatası.
            raise Stage2AuditError("Hash girdisi bir sözlük olmalıdır.")
        # Dosya adı.
        f_name = h_entry.get("file", "N/A")
        # SHA-256 değeri.
        h_val = h_entry.get("sha256", "")
        # Format denetimini icra ediyoruz.
        if not validate_sha256_hash(h_val):
            # Hatalı hash durumunda istisna üretiyoruz.
            raise Stage2AuditError(f"Dosya '{f_name}' için geçersiz SHA-256 karması: '{h_val}'")
            
    # Başarılı durumu kaydediyoruz.
    findings.append(f"{len(entries)} adet kritik sistem ikilisi ve yapılandırma dosyası SHA-256 bütünlüğü doğrulandı.")
    # Puanı ve bulguyu döndürüyoruz.
    return max(0.0, score), findings


def audit_backups_pillar(backup_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Yedekleme stratejisi ve 3-2-1 kuralı uyumluluk sütununu denetler.
    
    Argümanlar:
        backup_data: Yedekleme sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Başlangıç puanı.
    score = 100.0
    # Bulgular listesi.
    findings: List[str] = []
    
    # 3-2-1 bileşenlerini alıyoruz.
    copies = backup_data.get("total_copies", 0)
    # Negatif kopya kontrolü.
    if isinstance(copies, bool) or not isinstance(copies, int) or copies < 0:
        # Hata fırlatıyoruz.
        raise Stage2AuditError(f"Geçersiz yedek kopya sayısı: {copies}")
        
    # Medya türü sayısı.
    media = backup_data.get("distinct_media_types", 0)
    # Negatif medya kontrolü.
    if isinstance(media, bool) or not isinstance(media, int) or media < 0:
        # Hata fırlatıyoruz.
        raise Stage2AuditError(f"Geçersiz farklı medya türü sayısı: {media}")
        
    # Dış lokasyon kopya sayısı.
    offsite = backup_data.get("offsite_copies", 0)
    # Negatif lokasyon kontrolü.
    if isinstance(offsite, bool) or not isinstance(offsite, int) or offsite < 0:
        # Hata fırlatıyoruz.
        raise Stage2AuditError(f"Geçersiz dış lokasyon kopya sayısı: {offsite}")
        
    # 3 Kopya Kuralı Sınaması.
    if copies < 3:
        # Ceza uyguluyoruz.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append(f"3-2-1 İhlali: Toplam kopya sayısı {copies}, en az 3 olmalıdır.")
    # 2 Farklı Medya Türü Sınaması.
    if media < 2:
        # Ceza uyguluyoruz.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append(f"3-2-1 İhlali: Farklı ortam sayısı {media}, en az 2 olmalıdır.")
    # 1 Dış Lokasyon Kuralı Sınaması.
    if offsite < 1:
        # Ceza uyguluyoruz.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append(f"3-2-1 İhlali: Dış lokasyon kopya sayısı {offsite}, en az 1 olmalıdır.")
        
    # Geri yükleme test durumu kontrolü.
    restore_status = str(backup_data.get("last_restore_test_status", "UNKNOWN")).upper()
    # Test başarılı değilse ceza uyguluyoruz.
    if restore_status != "PASS":
        # Ceza.
        score -= 30.0
        # Bulguyu ekliyoruz.
        findings.append(f"Kritik: Son geri yükleme testi başarısız veya yapılmamış: {restore_status}")
    else:
        # Başarılı test notu.
        findings.append("3-2-1 yedekleme kuralı ve periyodik geri yükleme (restore) testi tam uyumlu.")
        
    # Puanı döndürüyoruz.
    return max(0.0, score), findings


def audit_services_pillar(service_data: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Servis yönetimi, güvensiz miras servisler ve SSH sıkılaştırma sütununu denetler.
    
    Argümanlar:
        service_data: Servisler sözlüğü.
        
    Döndürür:
        (Sütun Puanı 0-100, Tespit ve Bulgular Listesi)
    """
    # Başlangıç puanı.
    score = 100.0
    # Bulgular listesi.
    findings: List[str] = []
    
    # Güvensiz servisler tespit listesi.
    insecure = service_data.get("insecure_legacy_services_detected", [])
    # Liste kontrolü.
    if not isinstance(insecure, list):
        # Tip hatası.
        raise Stage2AuditError("insecure_legacy_services_detected bir liste olmalıdır.")
    # Güvensiz servis varsa ağır ceza uyguluyoruz.
    if insecure:
        # Her güvensiz servis için 25 puan kırıyoruz.
        score -= min(60.0, len(insecure) * 25.0)
        # Bulguyu ekliyoruz.
        findings.append(f"Kritik Güvensiz Servis İhlali: {insecure} aktif durumda tespit edildi!")
    else:
        # Temiz servis durumu.
        findings.append("Miras güvensiz servisler (telnet, rsh vb.) tamamen devre dışı.")
        
    # SSH Sıkılaştırma parametreleri kontrolü.
    ssh_cfg = service_data.get("ssh_hardening", {})
    # Kök kullanıcı ile giriş kuralı.
    if ssh_cfg.get("permit_root_login") != "no":
        # Ceza puanı.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append("Uyarı: SSH PermitRootLogin değeri 'no' değil.")
    # Parola ile kimlik doğrulama kuralı.
    if ssh_cfg.get("password_authentication") != "no":
        # Ceza puanı.
        score -= 20.0
        # Bulguyu ekliyoruz.
        findings.append("Uyarı: SSH PasswordAuthentication değeri 'no' değil.")
        
    # Başarılı SSH durumu.
    if score == 100.0:
        # Başarılı not.
        findings.append("SSH servisi Ed25519 anahtar zorunluluğu ve root engeliyle tam sıkılaştırılmış.")
        
    # Puanı ve bulguyu döndürüyoruz.
    return max(0.0, score), findings


def execute_stage2_quality_acceptance(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aşama 2 için 6 sütunun denetimini koşturur, genel kabul kararını ve detaylı metrikleri derler.
    
    Argümanlar:
        inventory: Doğrulanmış tam envanter verisi.
        
    Döndürür:
        Aşama 2 kabul sonuç sözlüğü.
    """
    # Önce şemayı ve sütun varlıklarını doğruluyoruz.
    validate_stage2_inventory_schema(inventory)
    
    # Her bir sütunun denetimini icra ediyoruz.
    proc_score, proc_find = audit_processes_pillar(inventory["processes"])
    perm_score, perm_find = audit_permissions_pillar(inventory["permissions"])
    log_score, log_find = audit_logging_pillar(inventory["logging"])
    hash_score, hash_find = audit_hashes_pillar(inventory["hashes"])
    backup_score, backup_find = audit_backups_pillar(inventory["backups"])
    serv_score, serv_find = audit_services_pillar(inventory["services"])
    
    # 6 sütunun eşit ağırlıklı genel ortalamasını alıyoruz.
    overall_score = round((proc_score + perm_score + log_score + hash_score + backup_score + serv_score) / 6.0, 1)
    
    # Aşama kabul kararını tayin ediyoruz (Eşik: >= 85.0 PASS, aksi halde HOLD).
    decision = "STAGE_02_PASS (AŞAMA 2 BAŞARIYLA TAMAMLANDI)" if overall_score >= 85.0 else "STAGE_02_HOLD (EKSİKLER GİDERİLMELİ)"
    
    # Yapılandırılmış sonuç sözlüğünü oluşturuyoruz.
    return {
        "meta": inventory.get("meta", {}),
        "overall_score": overall_score,
        "decision": decision,
        "is_passed": overall_score >= 85.0,
        "pillars": {
            "processes": {"score": proc_score, "findings": proc_find},
            "permissions": {"score": perm_score, "findings": perm_find},
            "logging": {"score": log_score, "findings": log_find},
            "hashes": {"score": hash_score, "findings": hash_find},
            "backups": {"score": backup_score, "findings": backup_find},
            "services": {"score": serv_score, "findings": serv_find}
        }
    }


def generate_stage2_markdown_report(results: Dict[str, Any]) -> str:
    """
    Aşama 2 kabul sonuçlarından resmi ve didaktik bir Markdown denetim raporu üretir.
    
    Argümanlar:
        results: Kabul sonuç sözlüğü.
        
    Döndürür:
        Markdown formatında biçimlendirilmiş rapor metni.
    """
    # Meta bilgilerini alıyoruz.
    meta = results.get("meta", {})
    # Puan ve karar bilgilerini çekiyoruz.
    overall = results["overall_score"]
    decision = results["decision"]
    pillars = results["pillars"]
    
    # Rapor satırları listesini başlatıyoruz.
    lines: List[str] = []
    
    # Başlık ve özel lisans uyarısı.
    lines.append("# G042: Aşama 2 Kalite Özeti ve Kabul Raporu — İşletim Sistemi Temelleri")
    lines.append("")
    lines.append("> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
    lines.append("> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  ")
    lines.append("> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Bölüm 1: Genel Durum ve Kabul Kararı
    lines.append("## 1. Yönetici Özeti ve Aşama 2 Kabul Kararı")
    lines.append(f"- **Hedef Makine:** {meta.get('hostname', 'N/A')} ({meta.get('vm_id', 'N/A')})")
    lines.append(f"- **İşletim Sistemi:** {meta.get('os_version', 'N/A')}")
    lines.append(f"- **Çekirdek (Kernel):** {meta.get('kernel', 'N/A')}")
    lines.append(f"- **Denetim Tarihi:** {meta.get('assessment_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))}")
    lines.append(f"- **AŞAMA 2 GENEL KALİTE PUANI:** **{overall} / 100.0**")
    lines.append(f"- **AŞAMA 2 KABUL DURUMU:** **{decision}**")
    lines.append("")
    
    # Bölüm 2: 6 Zorunlu Sütun Puanlama Tablosu
    lines.append("## 2. 6 Temel Güvenlik Sütunu Puanlama Matrisi")
    lines.append("")
    lines.append("| No | Güvenlik Sütunu | Kapsam ve İnceleme | Sütun Puanı | Durum |")
    lines.append("|---|---|---|---|---|")
    
    # Sütun isim ve açıklamaları sözlüğü.
    pillar_desc = {
        "processes": ("Süreç Hijyeni", "Yetkisiz süreçler, arka plan servis kum havuzlaması"),
        "permissions": ("Dosya İzinleri ve Umask", "Kritik dosyalar (/etc/shadow, sudoers) ve 0027 umask"),
        "logging": ("Olay Günlükleme", "journald kalıcılığı, auditd çekirdek takibi, SIEM aktarımı"),
        "hashes": ("Bütünlük Karmaları", "Kritik sistem ikilileri SHA-256 hash taban çizgisi"),
        "backups": ("Yedekleme & 3-2-1", "3 kopya, 2 ortam, 1 dış lokasyon ve başarılı geri yükleme"),
        "services": ("Servis Hardening", "Miras güvensiz servis yasağı, SSH anahtar zorunluluğu")
    }
    
    # Sütunları sırayla tabloya ekliyoruz.
    for idx, (p_key, p_val) in enumerate(pillars.items(), start=1):
        # Başlık ve açıklama.
        p_name, p_detail = pillar_desc.get(p_key, (p_key, "N/A"))
        # Sütun puanı.
        p_sc = p_val["score"]
        # Durum belirteci.
        st = "PASS" if p_sc >= 85.0 else ("PARTIAL" if p_sc >= 70.0 else "FAIL")
        # Tablo satırını ekliyoruz.
        lines.append(f"| {idx} | **{p_name}** | {p_detail} | **{p_sc}/100** | {st} |")
        
    lines.append("")
    
    # Bölüm 3: Sütun Bazlı Denetim Bulguları
    lines.append("## 3. Ayrıntılı Denetim Bulguları ve Tespitler")
    # Her sütunun bulgularını listeliyoruz.
    for p_key, p_val in pillars.items():
        # Sütun adı.
        p_name, _ = pillar_desc.get(p_key, (p_key, "N/A"))
        # Başlık.
        lines.append(f"### Sütun: {p_name}")
        # Bulguları maddeliyoruz.
        for find in p_val["findings"]:
            # Madde satırı.
            lines.append(f"- {find}")
        lines.append("")
        
    # Bölüm 4: Usta-Çırak Aşama Kapanış Yorumu
    lines.append("## 4. Usta-Çırak Aşama 2 Kapanış Değerlendirmesi")
    lines.append("> **Usta Değerlendirmesi:**  ")
    lines.append("> *Aşama 02 (İşletim Sistemi Temelleri), bir siber güvenlik uzmanının üzerinde yürüdüğü zemin idi. Bu zemin sağlam olmadan ağ güvenliğine, web zaafiyetlerine veya sızma testlerine geçilemez. 14 gün boyunca Linux ve Windows mimarilerini, çekirdek mekanizmalarını, dosya sistemlerini, süreç yönetimini, günlüklemeyi ve uzaktan erişimi ilmek ilmek işledik. Çırak, 6 sütunda da tam yetkinlik göstererek Aşama 2 Kabul Onayını (STAGE_02_PASS) hak etmiştir.*")
    lines.append("")
    lines.append("---")
    lines.append("*Aşama 2 Kalite Özeti Raporu Antigravity Denetim Motoru tarafından doğrulanmıştır.*")
    
    # Metni birleştirip döndürüyoruz.
    return "\n".join(lines)


def main() -> int:
    """CLI giriş noktası ve denetim motoru yürütücüsü."""
    # Windows konsolunda UTF-8 akışını yapılandırıyoruz.
    if sys.platform == "win32":
        # Standart çıktı akışını UTF-8 yapıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        # Standart hata akışını UTF-8 yapıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        
    # Argüman ayrıştırıcıyı kuruyoruz.
    parser = argparse.ArgumentParser(
        description="G042: Aşama 2 Kalite Özeti ve Kabul Motoru - İşletim Sistemi Temelleri"
    )
    # Envanter dosyası yolu.
    parser.add_argument(
        "--inventory",
        type=str,
        required=True,
        help="Aşama 2 denetim envanterini içeren JSON dosyasının yolu."
    )
    # Rapor çıktısı yolu.
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Markdown kabul raporunun yazılacağı dosya yolu."
    )
    # JSON özeti yolu.
    parser.add_argument(
        "--json-summary",
        type=str,
        default=None,
        help="Makine tarafından okunabilir JSON özetinin kaydedileceği dosya yolu."
    )
    
    # Argümanları alıyoruz.
    args = parser.parse_args()
    
    try:
        # Envanter dosyasının varlığını sınıyoruz.
        if not os.path.isfile(args.inventory):
            # Dosya bulunamadı hatası.
            raise FileNotFoundError(f"Envanter dosyası bulunamadı: {args.inventory}")
            
        # JSON dosyasını okuyoruz.
        with open(args.inventory, "r", encoding="utf-8") as inf:
            # Ayrıştırma işlemi.
            raw_data = json.load(inf)
            
        # Aşama 2 kabul denetimini koşturuyoruz.
        results = execute_stage2_quality_acceptance(raw_data)
        # Markdown raporunu üretiyoruz.
        report = generate_stage2_markdown_report(results)
        
        # Konsola basıyoruz.
        print(report)
        
        # Dosyaya kaydetme istenmişse yazıyoruz.
        if args.output:
            # Üst dizini hazırlıyoruz.
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            # Rapor dosyasını yazıyoruz.
            with open(args.output, "w", encoding="utf-8") as outf:
                # Yazma işlemi.
                outf.write(report)
            # Bilgi mesajı veriyoruz.
            print(f"\n[+] Kabul raporu başarıyla kaydedildi: {args.output}")
            
        # JSON özeti istenmişse kaydediyoruz.
        if args.json_summary:
            # Üst dizin kontrolü.
            os.makedirs(os.path.dirname(os.path.abspath(args.json_summary)), exist_ok=True)
            # JSON dosyasını yazıyoruz.
            with open(args.json_summary, "w", encoding="utf-8") as jf:
                # Serileştirme.
                json.dump(results, jf, indent=2, ensure_ascii=False)
            # Bilgilendirme.
            print(f"[+] JSON özeti kaydedildi: {args.json_summary}")
            
        # Çıkış kodu (Başarılı ise 0, aksi halde 1).
        return 0 if results["is_passed"] else 1
        
    # Denetim kural ve doğrulama hatalarını yakalıyoruz.
    except Stage2AuditError as sae:
        # Standart hataya yazıyoruz.
        sys.stderr.write(f"[-] Aşama 2 Doğrulama Hatası: {sae}\n")
        # Hata kodu 1.
        return 1
    # Dosya bulunamadı hatası.
    except FileNotFoundError as fnfe:
        # Hata basıyoruz.
        sys.stderr.write(f"[-] Dosya Hatası: {fnfe}\n")
        # Hata kodu 2.
        return 2
    # Genel beklenmeyen istisnalar.
    except Exception as ex:
        # Hatayı basıyoruz.
        sys.stderr.write(f"[-] Beklenmeyen Hata: {ex}\n")
        # Hata kodu 3.
        return 3


# Modül doğrudan yürütüldüğünde main() fonksiyonunu çağırıyoruz.
if __name__ == "__main__":
    # Sistem çıkışı yapıyoruz.
    sys.exit(main())
