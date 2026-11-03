# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim materyalleri yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.
# Açık kaynak lisanslar (MIT, Apache, GPL vb.) KULLANILMAZ.

"""
GÜN 010: Linux Sanal Makinesine Güvenli Başlangıç
Uygulama: Linux Güvenlik Sertleştirme ve Başlangıç Denetleyicisi (Linux Baseline Auditor)

Bu araç; Linux (Debian, Ubuntu, Kali, RedHat) sanal makinelerinin ilk kurulumunda:
1. SSH sunucusu güvenliğini (/etc/ssh/sshd_config: Root girişi, parola vs anahtar kimlik doğrulaması),
2. Kullanıcı yetki sınırlarını (/etc/sudoers: NOPASSWD açıkları, root hesap kilidi, umask),
3. Kritik sistem dosyalarının izinlerini (/etc/shadow, /etc/passwd dosya izinleri),
4. Güvenlik duvarı (UFW) varsayılan politikalarını ve açık gereksiz servisleri (Telnet, RSH)
CIS Linux Benchmark ve NIST SP 800-123 standartlarına göre denetler ve güvenli konfigürasyon üretir.
"""

# Standart Python kütüphaneleri içe aktarılıyor
import os
import sys
import json
import argparse
from typing import Dict, List, Any, Tuple


class LinuxSecurityValidationError(Exception):
    """
    Linux sanal makine yapılandırma profili sözdizimsel, şematik veya
    mantıksal bir ihlal içerdiğinde fırlatılan özel hata sınıfı.
    """
    pass


class LinuxBaselineAuditor:
    """
    Linux Güvenlik Taban Çizgisi (Security Baseline) Denetim ve Konfigürasyon Motoru.
    """

    # Şifresiz veya güvensiz çalışan, modern sistemlerde kesinlikle kapatılması gereken eski ağ servisleri
    YASAKLI_GUVENSIZ_SERVISLER = {
        "telnetd": "Şifresiz metin tabanlı uzaktan komut çalıştırma servisi (Parolalar ağda açık gider)",
        "rshd": "Eski Berkeley r-komutları uzaktan kabuk servisi (Kimlik doğrulama zayıf)",
        "rlogind": "Eski Berkeley uzaktan oturum açma servisi",
        "vsftpd": "Şifresiz FTP dosya transfer servisi (TLS olmadan veri ve parola açıktadır)",
        "tftpd": "Kimlik doğrulamasız dosya transfer servisi",
        "ypbind": "NIS (Network Information Service) güvensiz kullanıcı dizin servisi"
    }

    def __init__(self, profil_dosya_yolu: str):
        """
        Denetleyici sınıf başlatıcısı.
        
        Args:
            profil_dosya_yolu: İncelenecek Linux sistem profili JSON dosyasının yolu.
        """
        # Dosya yolunu sınıf değişkenine ata
        self.profil_dosya_yolu = profil_dosya_yolu
        # Henüz yüklenmemiş profil verisi için başlangıç sözlüğü
        self.profil_verisi: Dict[str, Any] = {}
        # Dosyayı oku ve JSON geçerliliğini doğrula
        self.profili_yukle()

    def profili_yukle(self) -> None:
        """
        Profil dosyasını diskten okur ve JSON sözdizimini doğrular.
        """
        # 1. Dosyanın fiziksel varlığını doğrula
        if not os.path.exists(self.profil_dosya_yolu):
            raise FileNotFoundError(f"Profil dosyası bulunamadı: {self.profil_dosya_yolu}")

        # 2. Dosyayı UTF-8 formatında aç ve JSON olarak ayrıştır
        try:
            with open(self.profil_dosya_yolu, "r", encoding="utf-8") as dosya:
                self.profil_verisi = json.load(dosya)
        except json.JSONDecodeError as json_hatasi:
            raise LinuxSecurityValidationError(f"Geçersiz JSON sözdizimi: {str(json_hatasi)}")

        # 3. Kök nesnenin sözlük olduğunu ve 'sistem_profilleri' anahtarını içerdiğini doğrula
        if not isinstance(self.profil_verisi, dict) or "sistem_profilleri" not in self.profil_verisi:
            raise LinuxSecurityValidationError("Profil dosyası geçerli bir kök 'sistem_profilleri' listesi içermelidir.")

        # 4. 'sistem_profilleri' alanının bir dizi olduğunu doğrula
        if not isinstance(self.profil_verisi["sistem_profilleri"], list):
            raise LinuxSecurityValidationError("'sistem_profilleri' alanı bir dizi (list) olmalıdır.")

    def denetle_sistem_profili(self, sistem: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tek bir Linux sanal makine güvenlik profilini CIS Seviye 1 standartlarında inceler.
        
        Args:
            sistem: İncelenecek sistem profili sözlüğü.
            
        Returns:
            Denetim bulguları, ceza puanları, güvenlik skoru ve durum kararı.
        """
        # Zorunlu alanların mevcudiyetini doğrula
        self._dogrula_sistem_semasi(sistem)

        # Bulguları saklamak için dinamik liste
        bulgular: List[Dict[str, Any]] = []

        # 1. SSH Sunucusu Güvenliği (/etc/ssh/sshd_config)
        bulgular.extend(self._denetle_ssh_guvenligi(sistem))

        # 2. Kullanıcı, Root ve Yetki Yönetimi (/etc/sudoers, umask)
        bulgular.extend(self._denetle_kullanici_ve_yetki(sistem))

        # 3. Kritik Sistem Dosyası İzinleri (/etc/shadow, /etc/passwd)
        bulgular.extend(self._denetle_dosya_izinleri(sistem))

        # 4. Güvenlik Duvarı (UFW) Politikaları
        bulgular.extend(self._denetle_guvenlik_duvari(sistem))

        # 5. Güvensiz Ağ Servisleri (Telnet, RSH vb.)
        bulgular.extend(self._denetle_guvensiz_servisler(sistem))

        # Toplam güvenlik skorunu ve risk derecesini hesapla
        skor, risk_derecesi = self._hesapla_guvenlik_skoru(bulgular)

        return {
            "sistem_id": sistem.get("sistem_id"),
            "sistem_adi": sistem.get("sistem_adi"),
            "dagitim": sistem.get("dagitim"),
            "guvenlik_seviyesi": sistem.get("guvenlik_seviyesi"),
            "skor": skor,
            "risk_derecesi": risk_derecesi,
            "toplam_bulgu_sayisi": len(bulgular),
            "bulgular": bulgular
        }

    def _dogrula_sistem_semasi(self, sistem: Dict[str, Any]) -> None:
        """
        Profil sözlüğünde bulunması gereken zorunlu anahtarları denetler.
        """
        zorunlu_alanlar = [
            "sistem_id", "sistem_adi", "dagitim", "guvenlik_seviyesi",
            "ssh_yapilandirmasi", "kullanici_ve_yetki_yonetimi",
            "dosya_sistemi_izinleri", "guvenlik_duvari_ufw"
        ]
        for alan in zorunlu_alanlar:
            if alan not in sistem:
                raise LinuxSecurityValidationError(f"Sistem profilinde zorunlu '{alan}' alanı eksik!")

    def _denetle_ssh_guvenligi(self, sistem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        OpenSSH sunucu yapılandırmasındaki (/etc/ssh/sshd_config) güvenlik parametrelerini inceler.
        """
        bulgular = []
        ssh = sistem.get("ssh_yapilandirmasi", {})

        permit_root = str(ssh.get("permit_root_login", "yes")).lower()
        password_auth = str(ssh.get("password_authentication", "yes")).lower()
        port = ssh.get("port", 22)
        max_tries = ssh.get("max_auth_tries", 6)

        # KONTROL 1: Root ile Doğrudan SSH Girişi
        # Root kullanıcısı ile SSH üzerinden doğrudan oturum açılması kaba kuvvet saldırılarına davetiye çıkarır.
        if permit_root in ["yes", "true", "without-password"]:
            bulgular.append({
                "kategori": "SSH_GUVENLIGI",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "Root ile Doğrudan SSH Girişi Açık (PermitRootLogin yes)",
                "detay": "Saldırganlar doğrudan 'root' kullanıcı adını hedef alarak parola kaba kuvvet (brute-force) saldırısı yapabilir.",
                "cozum": "/etc/ssh/sshd_config dosyasında 'PermitRootLogin no' tanımlayın; oturumu standart kullanıcıyla açıp 'sudo' kullanın."
            })

        # KONTROL 2: Parola Tabanlı Kimlik Doğrulama
        # Parola açıkken sözlük saldırıları çalışır. Kurumsal standart: Yalnızca SSH Public Key (Ed25519/RSA).
        if password_auth in ["yes", "true"]:
            bulgular.append({
                "kategori": "SSH_GUVENLIGI",
                "seviye": "YUKSEK",
                "ceza_puani": 25,
                "baslik": "SSH Parola ile Giriş Açık (PasswordAuthentication yes)",
                "detay": "Zayıf veya varsayılan parolalar (ör. kali:kali, toor) otomatik botlar tarafından saniyeler içinde kırılabilir.",
                "cozum": "'PasswordAuthentication no' ve 'PubkeyAuthentication yes' yaparak yalnızca SSH anahtarıyla girişe izin verin."
            })

        # KONTROL 3: Varsayılan SSH Portu (22)
        # Port 22, internetteki otomatik tarayıcıların (Shodan, botnetler) ilk vurduğu porttur.
        if port == 22:
            bulgular.append({
                "kategori": "SSH_GUVENLIGI",
                "seviye": "DUSUK",
                "ceza_puani": 10,
                "baslik": "Varsayılan SSH Portu Kullanılıyor (Port 22)",
                "detay": "Standart port kullanımı otomatik tarama gürültüsünü ve kaba kuvvet denemelerini artırır.",
                "cozum": "Port numarasını 1024 üzeri standart dışı bir porta (ör. 2222) taşıyın."
            })

        # KONTROL 4: Maksimum Kimlik Doğrulama Denemesi
        if max_tries > 4:
            bulgular.append({
                "kategori": "SSH_GUVENLIGI",
                "seviye": "DUSUK",
                "ceza_puani": 10,
                "baslik": f"Yüksek Kimlik Doğrulama Deneme Sınırı: {max_tries}",
                "detay": "Tek oturumda çok sayıda parola denenmesine izin vermek kaba kuvvet saldırılarını kolaylaştırır.",
                "cozum": "/etc/ssh/sshd_config içinde 'MaxAuthTries 3' tanımlayın."
            })

        return bulgular

    def _denetle_kullanici_ve_yetki(self, sistem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Kullanıcı hesapları, sudo izinleri (/etc/sudoers) ve dosya oluşturma maskesini (umask) denetler.
        """
        bulgular = []
        yetki = sistem.get("kullanici_ve_yetki_yonetimi", {})

        nopasswd = yetki.get("sudoers_nopasswd_izinli", False)
        root_kilitli = yetki.get("root_oturum_kilitli", True)
        umask = str(yetki.get("varsayilan_umask", "022")).strip()

        # KONTROL 1: Parolasız Sudo İzni (NOPASSWD: ALL)
        # Bu kural Linux dünyasının en büyük felaketlerinden biridir!
        # Kullanıcı hesabı ele geçirildiği an saldırgan GTFOBins ile doğrudan parolasız root olur!
        if nopasswd is True:
            bulgular.append({
                "kategori": "YETKI_YONETIMI",
                "seviye": "FELAKET",
                "ceza_puani": 50,
                "baslik": "Ölümcül Sudo Yapılandırması: NOPASSWD İzni Açık",
                "detay": "/etc/sudoers dosyasında kullanıcılara parolasız süper yetki verilmiş. Saldırgan 'sudo su' diyerek anında tam root olur.",
                "cozum": "'NOPASSWD' kuralını kaldırın; tüm ayrıcalıklı komutlar için parola girişini zorunlu kılın."
            })

        # KONTROL 2: Root Hesabının Doğrudan Açık Olması
        if not root_kilitli:
            bulgular.append({
                "kategori": "YETKI_YONETIMI",
                "seviye": "YUKSEK",
                "ceza_puani": 20,
                "baslik": "Root Hesabı Doğrudan Etkin ve Parolalı",
                "detay": "Root kullanıcısı doğrudan oturum açmaya açıktır; bu durum hesap denetim izini (audit trail) bozar.",
                "cozum": "'passwd -l root' komutuyla root parolasını kilitleyin; tüm işlemleri sudo ile yürütün."
            })

        # KONTROL 3: Güvensiz Varsayılan Umask
        # Umask 000 veya 002 yeni oluşturulan dosyaları dünya tarafından yazılabilir/okunabilir yapar.
        if umask in ["000", "002", "022"]:
            ceza = 20 if umask in ["000", "002"] else 5
            seviye = "YUKSEK" if umask in ["000", "002"] else "DUSUK"
            bulgular.append({
                "kategori": "YETKI_YONETIMI",
                "seviye": seviye,
                "ceza_puani": ceza,
                "baslik": f"Güvensiz Dosya Oluşturma Maskesi: umask {umask}",
                "detay": f"Umask {umask} yeni oluşturulan dosyalara diğer kullanıcıların erişebilmesine izin verir.",
                "cozum": "/etc/profile veya /etc/login.defs içinde 'umask 027' tanımlayın (Dosyalar 640, dizinler 750 oluşturulur)."
            })

        return bulgular

    def _denetle_dosya_izinleri(self, sistem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Kritik sistem dosyalarının (/etc/shadow, /etc/passwd vb.) dosya izinlerini (POSIX permissions) denetler.
        """
        bulgular = []
        izinler = sistem.get("dosya_sistemi_izinleri", {})

        shadow_izin = str(izinler.get("etc_shadow", "0640")).strip()
        passwd_izin = str(izinler.get("etc_passwd", "0644")).strip()

        # KONTROL 1: /etc/shadow Dosyası İzinleri
        # Bu dosya tüm sistem kullanıcılarının tuzlanmış şifre özetlerini (hash) tutar.
        # Eğer dünya (others) tarafından okunabiliyorsa (örn. 0644 veya 0777), her kullanıcı hashleri çalıp John/Hashcat ile kırar!
        if shadow_izin in ["0644", "0777", "0666", "0644", "644", "777"]:
            bulgular.append({
                "kategori": "DOSYA_IZINLERI",
                "seviye": "FELAKET",
                "ceza_puani": 50,
                "baslik": f"Kritik Güvenlik İhlali: /etc/shadow İzinleri Güvensiz ({shadow_izin})",
                "detay": "Parola özetlerini içeren /etc/shadow dosyası standart kullanıcılar tarafından okunabilir durumdadır. Tüm şifreler çevrimdışı kırılabilir.",
                "cozum": "'chmod 0640 /etc/shadow' ve 'chown root:shadow /etc/shadow' komutlarını çalıştırın."
            })

        # KONTROL 2: /etc/passwd Dosyasına Yazma İzni
        # Bu dosyaya standart kullanıcılar yazabiliyorsa, saldırgan UID 0 ile yeni bir kullanıcı ekleyerek sistemi anında ele geçirir.
        if passwd_izin in ["0777", "0666", "0664", "777", "666"]:
            bulgular.append({
                "kategori": "DOSYA_IZINLERI",
                "seviye": "FELAKET",
                "ceza_puani": 50,
                "baslik": f"Kritik Güvenlik İhlali: /etc/passwd Yazılabilir ({passwd_izin})",
                "detay": "/etc/passwd dosyası root dışındaki kullanıcılar tarafından değiştirilebilir durumdadır. Doğrudan yetki yükseltme (LPE) açığıdır.",
                "cozum": "'chmod 0644 /etc/passwd' ve 'chown root:root /etc/passwd' komutlarıyla yazma iznini kısıtlayın."
            })

        return bulgular

    def _denetle_guvenlik_duvari(self, sistem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        UFW (Uncomplicated Firewall) veya iptables güvenlik duvarı yapılandırmasını denetler.
        """
        bulgular = []
        ufw = sistem.get("guvenlik_duvari_ufw", {})

        etkin = ufw.get("etkin", False)
        varsayilan_gelen = str(ufw.get("varsayilan_gelen", "ALLOW")).upper()

        # KONTROL 1: Güvenlik Duvarının Kapalı Olması
        if not etkin:
            bulgular.append({
                "kategori": "GUVENLIK_DUVARI",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "UFW Güvenlik Duvarı Devre Dışı",
                "detay": "Sanal makinenin tüm portları ağdan gelebilecek port taramalarına ve saldırılara karşı tamamen korumasızdır.",
                "cozum": "'ufw enable' komutuyla güvenlik duvarını derhal etkinleştirin."
            })

        # KONTROL 2: Varsayılan Gelen Trafik Politikası
        # Güvenli standart: 'ufw default deny incoming'. Eğer ALLOW ise tüm kapılar açıktır!
        if varsayilan_gelen == "ALLOW":
            bulgular.append({
                "kategori": "GUVENLIK_DUVARI",
                "seviye": "KRITIK",
                "ceza_puani": 35,
                "baslik": "Varsayılan Gelen Ağ Trafiği 'ALLOW' (Açık)",
                "detay": "Güvenlik duvarı dışarıdan gelen paketleri varsayılan olarak engellememektedir.",
                "cozum": "'ufw default deny incoming' komutunu uygulayın."
            })

        return bulgular

    def _denetle_guvensiz_servisler(self, sistem: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sistemde çalışan eski, şifresiz ve güvensiz servisleri (Telnet, RSH, vsftpd) denetler.
        """
        bulgular = []
        calisanlar = sistem.get("calisan_servisler", [])

        for servis in calisanlar:
            temiz_ad = servis.lower().strip()
            if temiz_ad in self.YASAKLI_GUVENSIZ_SERVISLER:
                aciklama = self.YASAKLI_GUVENSIZ_SERVISLER[temiz_ad]
                bulgular.append({
                    "kategori": "GUVENSIZ_SERVISLER",
                    "seviye": "YUKSEK",
                    "ceza_puani": 20,
                    "baslik": f"Güvensiz Eski Servis Aktif: {servis}",
                    "detay": f"Aktif servis '{servis}' güvenlik riski taşır: {aciklama}",
                    "cozum": f"'systemctl stop {servis}' ve 'systemctl disable {servis}' komutlarıyla servisi kaldırın."
                })

        return bulgular

    def _hesapla_guvenlik_skoru(self, bulgular: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Bulgulardaki ceza puanlarını düşerek 100 üzerinden nihai skor üretir.
        """
        toplam_ceza = sum(b.get("ceza_puani", 0) for b in bulgular)
        skor = max(0, 100 - toplam_ceza)

        if skor >= 90:
            risk = "GÜVENLİ (CIS SEVİYE 1 SERTLEŞTİRİLMİŞ)"
        elif skor >= 70:
            risk = "ORTA RİSK (İYİLEŞTİRME GEREKLİ)"
        elif skor >= 40:
            risk = "YÜKSEK RİSK (GÜVENSİZ ORTAM)"
        else:
            risk = "KRİTİK FELAKET (ACİL MÜDAHALE GEREKLİ)"

        return skor, risk

    def denetle_tumunu(self) -> List[Dict[str, Any]]:
        """
        Dosyadaki tüm Linux sistem profillerini sırayla inceler.
        """
        sonuclar = []
        for sistem in self.profil_verisi.get("sistem_profilleri", []):
            sonuc = self.denetle_sistem_profili(sistem)
            sonuclar.append(sonuc)
        return sonuclar

    def urete_guvenli_sshd_config(self, sistem_id: str, cikis_dosya_yolu: str) -> str:
        """
        Hedef sistem için CIS Benchmark standartlarında sertleştirilmiş sshd_config üretir.
        """
        sablon = """# ==============================================================================
# GÜVENLİ OPENSSH SUNUCU YAPILANDIRMASI (CIS BENCHMARK LEVEL 1)
# Üretici: Linux Baseline Auditor | (c) 2026 Seydi Eryılmaz (@seydivakkas)
# ==============================================================================

# Temel Ağ ve Port Ayarları
Port 2222
AddressFamily inet
ListenAddress 0.0.0.0

# Kimlik Doğrulama ve Yetki Kısıtları
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no

# Güvenli Şifreleme Algoritmaları (Modern Kripto Standartları)
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

# Entegrasyon ve Yönlendirme İzolasyonu
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2

# Loglama ve Denetim
LogLevel VERBOSE
SyslogFacility AUTH
"""
        with open(cikis_dosya_yolu, "w", encoding="utf-8") as dosya:
            dosya.write(sablon)
        return cikis_dosya_yolu

    def urete_guvenli_sudoers(self, sistem_id: str, cikis_dosya_yolu: str) -> str:
        """
        Hedef sistem için güvenli /etc/sudoers.d/hardened kuralları üretir.
        """
        sablon = """# ==============================================================================
# GÜVENLİ SUDOERS YAPILANDIRMASI (CIS LEVEL 1)
# Üretici: Linux Baseline Auditor | (c) 2026 Seydi Eryılmaz (@seydivakkas)
# ==============================================================================

# Varsayılan Güvenlik Kuralları
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults umask=027
Defaults umask_override
Defaults passwd_tries=3
Defaults logfile="/var/log/sudo.log"

# Parolasız Süper Yetki (NOPASSWD) KESİNLİKLE YASAKTIR!
# Yalnızca sudo grubundaki yetkili kullanıcılar kendi parolalarıyla işlem yapabilir:
%sudo ALL=(ALL:ALL) ALL
"""
        with open(cikis_dosya_yolu, "w", encoding="utf-8") as dosya:
            dosya.write(sablon)
        return cikis_dosya_yolu

    def rapor_olustur_metin(self, sonuclar: List[Dict[str, Any]]) -> str:
        """
        Denetim sonuçlarını terminalde insan tarafından okunabilir zengin rapor formatında biçimlendirir.
        """
        satirlar = []
        satirlar.append("=" * 80)
        satirlar.append("   LINUX GÜVENLİK TABAN ÇİZGİSİ DENETİM RAPORU (LINUX BASELINE AUDITOR)")
        satirlar.append("=" * 80)
        satirlar.append(f"İncelenen Dosya: {self.profil_dosya_yolu}")
        satirlar.append(f"Toplam Sistem Profili Sayısı: {len(sonuclar)}")
        satirlar.append("-" * 80)

        for sonuc in sonuclar:
            satirlar.append(f"\n[+] SİSTEM ID: {sonuc['sistem_id']} | Adı: {sonuc['sistem_adi']}")
            satirlar.append(f"    Dağıtım           : {sonuc['dagitim']}")
            satirlar.append(f"    Güvenlik Seviyesi : {sonuc['guvenlik_seviyesi']}")
            satirlar.append(f"    Güvenlik Skoru    : {sonuc['skor']}/100")
            satirlar.append(f"    Risk Durumu       : {sonuc['risk_derecesi']}")
            satirlar.append(f"    Toplam Bulgu      : {sonuc['toplam_bulgu_sayisi']}")

            if sonuc["toplam_bulgu_sayisi"] == 0:
                satirlar.append("    -> TEBRİKLER: Sıfır güvenlik açığı! CIS Benchmark Seviye 1 sertleştirilmiş sistem.")
            else:
                satirlar.append("    -> TESPİT EDİLEN RİSK VE ZAFİYETLER:")
                for b in sonuc["bulgular"]:
                    satirlar.append(f"       * [{b['seviye']}] {b['baslik']} (-{b['ceza_puani']} Puan)")
                    satirlar.append(f"         Kategori: {b['kategori']}")
                    satirlar.append(f"         Risk    : {b['detay']}")
                    satirlar.append(f"         Çözüm   : {b['cozum']}")

        satirlar.append("\n" + "=" * 80)
        satirlar.append("Denetim Bitti. Tüm hakları saklıdır (c) 2026 Seydi Eryılmaz.")
        satirlar.append("=" * 80)
        return "\n".join(satirlar)


def main():
    """
    Komut satırı arayüzü (CLI) giriş noktası.
    """
    ayristirici = argparse.ArgumentParser(
        description="Linux Güvenlik Taban Çizgisi Denetim ve Konfigürasyon Motoru (Linux Baseline Auditor)"
    )
    ayristirici.add_argument(
        "--profile",
        required=True,
        help="İncelenecek Linux sanal makine yapılandırma JSON dosyasının yolu"
    )
    ayristirici.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Çıktı formatı: 'table' (varsayılan) veya 'json'"
    )
    ayristirici.add_argument(
        "--system-id",
        required=False,
        default=None,
        help="Yalnızca belirli bir Sistem ID'sini denetlemek için filtre"
    )
    ayristirici.add_argument(
        "--generate-sshd",
        help="Belirtilen dosya yoluna sertleştirilmiş güvenli sshd_config dosyası üret"
    )
    ayristirici.add_argument(
        "--generate-sudoers",
        help="Belirtilen dosya yoluna sertleştirilmiş güvenli sudoers dosyası üret"
    )

    argumanlar = ayristirici.parse_args()

    try:
        motor = LinuxBaselineAuditor(argumanlar.profile)
        sonuclar = motor.denetle_tumunu()

        # Sistem ID filtresi varsa uygula
        if argumanlar.system_id:
            sonuclar = [s for s in sonuclar if s["sistem_id"] == argumanlar.system_id]
            if not sonuclar:
                print(f"[!] Belirtilen Sistem ID bulunamadı: {argumanlar.system_id}", file=sys.stderr)
                sys.exit(1)

        # Güvenli sshd_config üretimi
        if argumanlar.generate_sshd:
            hedef_id = argumanlar.system_id or sonuclar[0]["sistem_id"]
            yol = motor.urete_guvenli_sshd_config(hedef_id, argumanlar.generate_sshd)
            print(f"[+] Sertleştirilmiş sshd_config başarıyla üretildi: {yol}")

        # Güvenli sudoers üretimi
        if argumanlar.generate_sudoers:
            hedef_id = argumanlar.system_id or sonuclar[0]["sistem_id"]
            yol = motor.urete_guvenli_sudoers(hedef_id, argumanlar.generate_sudoers)
            print(f"[+] Sertleştirilmiş sudoers başarıyla üretildi: {yol}")

        # Çıktıyı istenen formatta yazdır
        if argumanlar.format == "json":
            print(json.dumps(sonuclar, indent=2, ensure_ascii=False))
        else:
            print(motor.rapor_olustur_metin(sonuclar))

        # Kritik veya felaket riski varsa çıkış kodu 2 olsun
        herhangi_bir_felaket = any(
            any(b["seviye"] in ["KRITIK", "FELAKET"] for b in s["bulgular"])
            for s in sonuclar
        )
        if herhangi_bir_felaket:
            sys.exit(2)
        else:
            sys.exit(0)

    except Exception as hata:
        print(f"[HATA] Linux taban çizgisi denetimi başarısız oldu: {str(hata)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
