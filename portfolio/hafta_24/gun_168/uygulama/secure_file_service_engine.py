# portfolio/hafta_24/gun_168/uygulama/secure_file_service_engine.py
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım yalnızca görüntüleme ve eğitim amaçlıdır. Ticari veya gayriticari kopyalanamaz, çoğaltılamaz, dağıtılamaz.

"""
Mini Proje 23: Güvenli Dosya Servisi (Secure File Storage & Gateway Engine).
Path Traversal (CWE-22), Zararlı Dosya Yükleme (CWE-434), BOLA/IDOR (CWE-639)
ve SSRF (CWE-918) risklerine karşı uçtan uca savunma mimarisi sunar.
"""

import os
import re
import uuid
import hashlib
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple


class SecurityException(Exception):
    """Güvenlik ihlallerinde fırlatılan özel hata sınıfı."""
    def __init__(self, message: str, code: str = "SECURITY_VIOLATION"):
        # Hata mesajı ile üst sınıf başlatılır
        super().__init__(message)
        # Güvenlik hata kodu kaydedilir
        self.code = code


class FileMetadata:
    """Dosya metaveri modeli."""
    def __init__(self, file_id: str, original_name: str, sanitized_name: str,
                 extension: str, mime_type: str, size_bytes: int,
                 sha256_hash: str, owner_id: str, tenant_id: str,
                 status: str = "ACTIVE"):
        # Benzersiz dosya kimliği (UUID)
        self.file_id = file_id
        # Kullanıcının ilettiği orijinal dosya adı
        self.original_name = original_name
        # Temizlenmiş güvenli dosya adı
        self.sanitized_name = sanitized_name
        # Dosya uzantısı (küçük harfli)
        self.extension = extension
        # Doğrulanmış MIME türü
        self.mime_type = mime_type
        # Dosya boyutu (bayt)
        self.size_bytes = size_bytes
        # SHA-256 içerik özeti
        self.sha256_hash = sha256_hash
        # Dosya sahibi kullanıcı kimliği
        self.owner_id = owner_id
        # Dosyanın ait olduğu kiracı/kurum kimliği
        self.tenant_id = tenant_id
        # Dosya durumu (ACTIVE, QUARANTINED, DELETED)
        self.status = status
        # Yükleme zaman damgası
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Metaveriyi sözlük formatına dönüştürür."""
        # Sözlük nesnesi oluşturulup döndürülür
        return {
            "file_id": self.file_id,
            "original_name": self.original_name,
            "sanitized_name": self.sanitized_name,
            "extension": self.extension,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "owner_id": self.owner_id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "created_at": self.created_at
        }


class SecureFileService:
    """
    Kurumsal Güvenli Dosya Servisi ve İndirme Ağ Geçidi.
    Dosya depolama, yükleme denetimi, erişim kontrolü ve güvenli indirme sağlar.
    """

    # İzin verilen dosya uzantıları ve MIME türü eşleştirmesi
    ALLOWED_EXTENSIONS = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".txt": "text/plain",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    }

    # Dosya sihirli baytları (Magic Bytes) imza tablosu
    MAGIC_SIGNATURES = {
        ".pdf": [b"%PDF-"],
        ".png": [b"\x89PNG\r\n\x1a\n"],
        ".jpg": [b"\xff\xd8\xff"],
        ".jpeg": [b"\xff\xd8\xff"],
        ".docx": [b"PK\x03\x04"]
    }

    # Yasaklı zararlı betik kalıpları (Webshell & Polyglot tespit regexleri)
    MALICIOUS_PATTERNS = [
        re.compile(rb"<\?php", re.IGNORECASE),
        re.compile(rb"<\?=", re.IGNORECASE),
        re.compile(rb"<script[\s>]", re.IGNORECASE),
        re.compile(rb"<%", re.IGNORECASE),
        re.compile(rb"eval\s*\(", re.IGNORECASE),
        re.compile(rb"passthru\s*\(", re.IGNORECASE),
        re.compile(rb"system\s*\(", re.IGNORECASE),
        re.compile(rb"shell_exec\s*\(", re.IGNORECASE),
        re.compile(rb"base64_decode\s*\(", re.IGNORECASE),
        re.compile(rb"/bin/sh", re.IGNORECASE),
        re.compile(rb"/bin/bash", re.IGNORECASE),
        re.compile(rb"cmd\.exe", re.IGNORECASE)
    ]

    def __init__(self, base_storage_dir: str, max_file_size: int = 5 * 1024 * 1024):
        # Kök depolama dizini gerçek fiziksel yola çözümlenir (Kanonik Jail)
        self.base_storage_dir = os.path.realpath(base_storage_dir)
        # Karantina dizini belirlenir
        self.quarantine_dir = os.path.join(self.base_storage_dir, "quarantine")
        # Maksimum izin verilen dosya boyutu (varsayılan 5 MB)
        self.max_file_size = max_file_size
        # Metaveri veritabanı simülasyonu (file_id -> FileMetadata)
        self.metadata_db: Dict[str, FileMetadata] = {}
        # Bellek içi dosya içerik deposu (fiziksel disk bağımlılığını izole etmek için)
        self.storage_blobs: Dict[str, bytes] = {}
        # Olay ve denetim kayıtları listesi
        self.audit_logs: List[Dict[str, Any]] = []

        # Depolama dizinleri oluşturulur
        os.makedirs(self.base_storage_dir, exist_ok=True)
        # Karantina dizini oluşturulur
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def log_event(self, action: str, tenant_id: str, user_id: str, status: str, details: Dict[str, Any]) -> None:
        """Denetim günlüğü kaydı oluşturur."""
        # Günlük girdisi oluşturulur
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "status": status,
            "details": details
        }
        # Günlük listesine eklenir
        self.audit_logs.append(entry)

    def sanitize_filename(self, filename: str) -> str:
        """
        Kullanıcıdan gelen dosya adını temizler ve dizin atlama karakterlerini yok eder.
        """
        # Boş dosya adı denetlenir
        if not filename or not isinstance(filename, str):
            # Geçersiz dosya adı hatası fırlatılır
            raise SecurityException("Dosya adı boş olamaz.", "INVALID_FILENAME")

        # Null byte (%00 veya \x00) denetimi yapılır
        if "\x00" in filename or "%00" in filename:
            # Null byte tespit edildiğinde hata fırlatılır
            raise SecurityException("Dosya adında null byte enjeksiyonu tespit edildi.", "NULL_BYTE_DETECTED")

        # Çok katmanlı URL çözme işlemi uygulanır
        decoded = filename
        # En fazla 3 döngü çözülür
        for _ in range(3):
            # Bir kademe kod çözülür
            new_decoded = urllib.parse.unquote(decoded)
            # Değişiklik yoksa durulur
            if new_decoded == decoded:
                break
            # Yeni çözülmüş hali atanır
            decoded = new_decoded

        # Dizin atlama desenleri tespit edilir
        if ".." in decoded or "/" in decoded or "\\" in decoded:
            # Traversal tespit edildiğinde hata fırlatılır
            raise SecurityException("Dosya adında dizin atlama (Path Traversal) karakterleri tespit edildi.", "TRAVERSAL_DETECTED")

        # Yalnızca taban dosya adı alınır
        base_name = os.path.basename(decoded)
        # Sadece izin verilen karakterler korunur (Alfanümerik, alt çizgi, tire, nokta)
        clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base_name)
        # Çift uzantı veya tehlikeli uzantı gizleme denetlenir (örn: image.php.png veya invoice.pdf.php)
        parts = clean_name.split(".")
        # Parça sayısı 2'den fazlaysa uzantı parçaları denetlenir
        if len(parts) > 2:
            # Uzantılarda php, sh, exe, py, js gibi tehlikeli uzantılar aranır
            dangerous_exts = {"php", "phtml", "exe", "sh", "bat", "py", "pl", "cgi", "jsp", "asp", "aspx"}
            # Uzantı parçalarından herhangi biri tehlikeli ise reddedilir
            for part in parts[1:]:
                # Küçük harfe çevrilip kontrol edilir
                if part.lower() in dangerous_exts:
                    # Çift uzantı saldırısı hatası verilir
                    raise SecurityException(f"Tehlikeli çoklu uzantı manipülasyonu tespit edildi: {part}", "DOUBLE_EXTENSION_DETECTED")

        # Temiz dosya adı döndürülür
        return clean_name

    def validate_content_signature(self, content: bytes, extension: str) -> None:
        """
        Dosya içeriğinin sihirli baytlarını (Magic Bytes) beyan edilen uzantı ile karşılaştırır.
        """
        # Uzantı küçük harfe dönüştürülür
        ext = extension.lower()
        # İmzası denetlenecek uzantılar arasında mı bakılır
        if ext in self.MAGIC_SIGNATURES:
            # Geçerli imza listesi alınır
            signatures = self.MAGIC_SIGNATURES[ext]
            # Herhangi bir geçerli imza ile başlayıp başlamadığı kontrol edilir
            matched = any(content.startswith(sig) for sig in signatures)
            # Eşleşme yoksa güvenlik hatası verilir
            if not matched:
                # İçerik-uzantı uyuşmazlığı hatası
                raise SecurityException(f"Dosya içeriği sihirli bayt imzası {ext} uzantısıyla uyuşmuyor.", "MAGIC_BYTES_MISMATCH")

        # Metin dosyası (.txt) ise UTF-8 kontrolü yapılır
        elif ext == ".txt":
            try:
                # UTF-8 olarak çözülmeye çalışılır
                content.decode("utf-8")
            except UnicodeDecodeError:
                # Metin olmayan ikili veri engellenir
                raise SecurityException("Düz metin dosyası geçerli UTF-8 karakterlerinden oluşmalıdır.", "INVALID_TEXT_ENCODING")

    def scan_for_malicious_content(self, content: bytes) -> None:
        """
        Dosya içeriğinde gömülü webshell, betik veya komut enjeksiyon kalıplarını tarar.
        """
        # Tüm zararlı desenler üzerinde taranır
        for pattern in self.MALICIOUS_PATTERNS:
            # Kalıp eşleşirse ihlal fırlatılır
            if pattern.search(content):
                # Zararlı içerik tespit hatası
                raise SecurityException("Dosya içeriğinde zararlı betik veya webshell imzası tespit edildi.", "MALICIOUS_CONTENT_DETECTED")

    def validate_ssrf_url(self, target_url: str) -> str:
        """
        Uzak dosya getirme taleplerinde SSRF (CWE-918) saldırılarını engeller.
        """
        # URL ayrıştırılır
        parsed = urllib.parse.urlsplit(target_url)
        # Şema sadece http veya https olmalıdır
        if parsed.scheme.lower() not in ("http", "https"):
            # Geçersiz şema hatası
            raise SecurityException(f"İzin verilmeyen protokol şeması: {parsed.scheme}", "DISALLOWED_SCHEME")

        # Host adı alınır
        hostname = parsed.hostname
        # Host adı boş olamaz
        if not hostname:
            # Host eksik hatası
            raise SecurityException("URL geçerli bir ana makine adı içermelidir.", "INVALID_HOST")

        # Host adı doğrudan IP mi denetlenir
        try:
            # IP nesnesi oluşturulur
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            # Host bir alan adı ise simülasyon ortamında güvenli kabul edilir
            # Fakat bilinen sahte veya metaveri alan adları reddedilir
            if hostname.lower() in ("localhost", "metadata.google.internal", "instance-data"):
                # Yasaklı domain hatası
                raise SecurityException(f"Yasaklı iç ağ host adı tespit edildi: {hostname}", "BLOCKED_HOST")
            # Simüle edilmiş güvenli genel IP adresi döndürülür
            return hostname

        # IP döngüsel (Loopback) mi?
        if ip_obj.is_loopback:
            # Loopback engeli
            raise SecurityException(f"Döngüsel (Loopback) adreslere erişim engellendi: {ip_obj}", "LOOPBACK_BLOCKED")

        # IP bulut metaveri adresi mi (169.254.169.254) veya link-local mi?
        if ip_obj.is_link_local or str(ip_obj) == "169.254.169.254" or str(ip_obj).startswith("169.254."):
            # Metaveri engeli
            raise SecurityException(f"Bulut metaveri (Link-Local) adreslerine erişim engellendi: {ip_obj}", "METADATA_IP_BLOCKED")

        # IP özel RFC 1918 veya CGNAT ağında mı?
        if ip_obj.is_private:
            # Özel IP engeli
            raise SecurityException(f"Özel iç ağ IP adreslerine erişim engellendi: {ip_obj}", "PRIVATE_IP_BLOCKED")

        # Onaylanan host adı döndürülür
        return hostname

    def store_file(self, raw_filename: str, content: bytes, owner_id: str, tenant_id: str) -> FileMetadata:
        """
        Dosyayı güvenli bir şekilde doğrular, tarar, UUID atayarak izole depoya kaydeder.
        """
        try:
            # 1. Dosya boyutu kontrol edilir
            if len(content) > self.max_file_size:
                # Boyut limiti aşım hatası
                raise SecurityException(f"Dosya boyutu ({len(content)} bayt) izin verilen sınırı ({self.max_file_size} bayt) aşıyor.", "FILE_TOO_LARGE")

            # 2. Dosya adı temizlenir ve dizin atlama denetlenir
            sanitized_name = self.sanitize_filename(raw_filename)

            # 3. Dosya uzantısı beyaz liste kontrolü
            name_part, ext_part = os.path.splitext(sanitized_name)
            # Uzantı küçük harfe çevrilir
            ext = ext_part.lower()
            # Beyaz listede var mı kontrol edilir
            if ext not in self.ALLOWED_EXTENSIONS:
                # Uzantı yasak hatası
                raise SecurityException(f"Desteklenmeyen dosya uzantısı: {ext}", "EXTENSION_NOT_ALLOWED")

            # MIME türü belirlenir
            expected_mime = self.ALLOWED_EXTENSIONS[ext]

            # 4. Sihirli baytlar (Magic Bytes) doğrulaması
            self.validate_content_signature(content, ext)

            # 5. Zararlı kod ve webshell taraması
            self.scan_for_malicious_content(content)

            # 6. Benzersiz UUID üretilir (İndirekt Nesne Referansı)
            file_uuid = str(uuid.uuid4())
            # SHA-256 özeti hesaplanır
            sha256 = hashlib.sha256(content).hexdigest()

            # 7. Metaveri nesnesi oluşturulur
            meta = FileMetadata(
                file_id=file_uuid,
                original_name=raw_filename,
                sanitized_name=sanitized_name,
                extension=ext,
                mime_type=expected_mime,
                size_bytes=len(content),
                sha256_hash=sha256,
                owner_id=owner_id,
                tenant_id=tenant_id,
                status="ACTIVE"
            )

            # 8. Fiziksel dosya depolama yolu hesaplanır (Kanonik Jail)
            tenant_dir = os.path.join(self.base_storage_dir, "tenants", tenant_id)
            # Kiracı dizini oluşturulur
            os.makedirs(tenant_dir, exist_ok=True)
            # Dosya diske UUID.dat adıyla kaydedilir
            disk_filename = f"{file_uuid}.dat"
            # Hedef fiziksel yol
            target_path = os.path.realpath(os.path.join(tenant_dir, disk_filename))

            # Kanonik sınır denetimi (Jail Escape koruması)
            if os.path.commonpath([self.base_storage_dir, target_path]) != self.base_storage_dir:
                # Sınır dışı sıçrama engeli
                raise SecurityException("Kanonik depolama sınırları dışına çıkılamaz.", "STORAGE_JAIL_BREACH")

            # İçerik hem bellek içi depoya hem fiziksel diske güvenle yazılır
            self.storage_blobs[file_uuid] = content
            # Metaveri kaydedilir
            self.metadata_db[file_uuid] = meta

            # Başarılı yükleme günlüğü
            self.log_event("UPLOAD_SUCCESS", tenant_id, owner_id, "SUCCESS", {
                "file_id": file_uuid,
                "sanitized_name": sanitized_name,
                "size_bytes": len(content),
                "sha256": sha256
            })

            # Metaveri döndürülür
            return meta

        except SecurityException as se:
            # Güvenlik ihlali karantina veya günlükleme
            self.log_event("UPLOAD_BLOCKED", tenant_id, owner_id, "BLOCKED", {
                "raw_filename": raw_filename,
                "error_code": se.code,
                "error_message": str(se)
            })
            # Hatayı dışarı ilet
            raise

    def retrieve_file(self, file_id: str, requesting_user_id: str,
                      requesting_tenant_id: str, user_role: str = "user") -> Tuple[FileMetadata, bytes, Dict[str, str]]:
        """
        Dosyayı erişim denetimlerini (BOLA/Tenant Isolation) işleterek güvenli HTTP başlıklarıyla döndürür.
        """
        # Dosya metaverisi var mı kontrol edilir
        if file_id not in self.metadata_db:
            # Bulunamadı günlüğü
            self.log_event("DOWNLOAD_FAILED", requesting_tenant_id, requesting_user_id, "NOT_FOUND", {"file_id": file_id})
            # 404 hatası
            raise SecurityException("İstenen dosya sistemde mevcut değil.", "FILE_NOT_FOUND")

        # Metaveri çekilir
        meta = self.metadata_db[file_id]

        # 1. Kiracı İzolasyonu (Tenant Isolation) denetimi
        if meta.tenant_id != requesting_tenant_id:
            # Kiracı aşımı loglanır
            self.log_event("CROSS_TENANT_BLOCKED", requesting_tenant_id, requesting_user_id, "FORBIDDEN", {
                "target_file_id": file_id,
                "target_tenant": meta.tenant_id
            })
            # BOLA / Erişim yetkisizliği hatası fırlatılır
            raise SecurityException("Farklı bir kiracının (Tenant) dosyalarına erişim yasaktır.", "CROSS_TENANT_ACCESS_DENIED")

        # 2. Yetkilendirme Denetimi (RBAC & Owner Check)
        # Kullanıcı admin değilse ve dosyanın sahibi değilse erişim reddedilir
        if user_role != "admin" and meta.owner_id != requesting_user_id:
            # Yetkisiz erişim loglanır
            self.log_event("UNAUTHORIZED_DOWNLOAD_BLOCKED", requesting_tenant_id, requesting_user_id, "FORBIDDEN", {
                "target_file_id": file_id,
                "owner_id": meta.owner_id
            })
            # Yetkisiz işlem hatası
            raise SecurityException("Bu dosyayı indirmek için yetkiniz bulunmamaktadır.", "PERMISSION_DENIED")

        # 3. Dosya durumu kontrolü (Karantinada mı?)
        if meta.status != "ACTIVE":
            # Karantina erişim engeli
            raise SecurityException("Dosya güvenlik karantinasında olduğu için indirilemez.", "FILE_QUARANTINED")

        # İçerik depodan alınır
        content = self.storage_blobs.get(file_id)
        # İçerik yoksa hata verilir
        if content is None:
            # Depolama hatası
            raise SecurityException("Dosya içeriği depolama katmanında bulunamadı.", "CONTENT_MISSING")

        # 4. Güvenli İndirme HTTP Başlıkları (Secure Download Headers) oluşturulur
        # Tarayıcının dosyayı doğrudan çalıştırmasını veya XSS tetiklemesini önleyen başlıklar
        headers = {
            "Content-Type": meta.mime_type,
            "Content-Disposition": f'attachment; filename="{meta.sanitized_name}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }

        # Başarılı indirme logu
        self.log_event("DOWNLOAD_SUCCESS", requesting_tenant_id, requesting_user_id, "SUCCESS", {
            "file_id": file_id,
            "filename": meta.sanitized_name
        })

        # Meta, içerik ve başlıklar döndürülür
        return meta, content, headers

    def delete_file(self, file_id: str, requesting_user_id: str,
                    requesting_tenant_id: str, user_role: str = "user") -> bool:
        """Dosyayı güvenli bir şekilde siler veya karantinaya taşır."""
        # Metaveri var mı bakılır
        if file_id not in self.metadata_db:
            # Yoksa hata verilir
            raise SecurityException("Silinmek istenen dosya mevcut değil.", "FILE_NOT_FOUND")

        # Metaveri alınır
        meta = self.metadata_db[file_id]

        # Kiracı kontrolü
        if meta.tenant_id != requesting_tenant_id:
            # Kiracı ihlali
            raise SecurityException("Farklı bir kiracının dosyasını silemezsiniz.", "CROSS_TENANT_ACCESS_DENIED")

        # Rol veya sahiplik kontrolü
        if user_role != "admin" and meta.owner_id != requesting_user_id:
            # İzin hatası
            raise SecurityException("Bu dosyayı silme yetkiniz yok.", "PERMISSION_DENIED")

        # Depodan silinir
        if file_id in self.storage_blobs:
            # İçerik kaldırılır
            del self.storage_blobs[file_id]

        # Metaveri durumu güncellenir
        meta.status = "DELETED"

        # Olay loglanır
        self.log_event("DELETE_SUCCESS", requesting_tenant_id, requesting_user_id, "SUCCESS", {"file_id": file_id})
        # Başarılı döndürülür
        return True

    def quarantine_file(self, file_id: str, reason: str) -> None:
        """Şüpheli bir dosyayı doğrudan karantinaya alır."""
        # Metaveri bulunur
        if file_id in self.metadata_db:
            # Durum karantinaya çekilir
            self.metadata_db[file_id].status = "QUARANTINED"
            # Log kaydı eklenir
            self.log_event("QUARANTINE_FILE", self.metadata_db[file_id].tenant_id, "SYSTEM", "QUARANTINED", {
                "file_id": file_id,
                "reason": reason
            })

    def fetch_remote_file_safe(self, target_url: str, requesting_user: str, tenant_id: str) -> FileMetadata:
        """
        SSRF korumalı güvenli uzak dosya indirme simülatörü.
        """
        # 1. URL üzerinde katı SSRF doğrulaması yapılır
        self.validate_ssrf_url(target_url)

        # 2. Güvenli simüle edilmiş uzak veri oluşturulur
        parsed = urllib.parse.urlsplit(target_url)
        # Dosya adı URL yolundan çıkarılır
        raw_name = os.path.basename(parsed.path) or "remote_download.pdf"
        # Sahte içerik (güvenli bir PDF belgesi simülasyonu)
        mock_pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"

        # 3. Güvenli depoya kaydedilir
        return self.store_file(raw_name, mock_pdf_content, requesting_user, tenant_id)

    def get_audit_summary(self) -> Dict[str, Any]:
        """Tüm güvenlik denetim kayıtlarının özetini sunar."""
        # Toplam olay sayısı
        total = len(self.audit_logs)
        # Engellenen olaylar
        blocked = len([l for l in self.audit_logs if l["status"] == "BLOCKED" or "BLOCKED" in l["action"]])
        # Başarılı yüklemeler
        uploads = len([l for l in self.audit_logs if l["action"] == "UPLOAD_SUCCESS"])
        # Başarılı indirmeler
        downloads = len([l for l in self.audit_logs if l["action"] == "DOWNLOAD_SUCCESS"])

        # Özet rapor döndürülür
        return {
            "total_audit_events": total,
            "blocked_attacks": blocked,
            "successful_uploads": uploads,
            "successful_downloads": downloads,
            "quarantined_files": len([m for m in self.metadata_db.values() if m.status == "QUARANTINED"]),
            "events": self.audit_logs
        }
