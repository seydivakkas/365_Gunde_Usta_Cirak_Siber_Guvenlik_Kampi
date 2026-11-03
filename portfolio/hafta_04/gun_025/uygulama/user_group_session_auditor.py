# ==============================================================================
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
# amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve kişisel öğrenim amacıyla inceleme.
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.
# İzin talepleri için: GitHub @seydivakkas
# ==============================================================================
"""Kullanıcı, Grup ve Oturum Güvenliği Denetleyicisi.

Bu modül; kimlik (Identity) ile etkin oturum (Active Session) ayrımını,
etkin UID/GID seviyelerini, servis hesaplarının kabuk kısıtlamalarını,
ortak hesap ve eşzamanlı oturum ihlallerini, atıl (dormant) hesapları
ve canlı yerel oturum meta verilerini denetleyerek raporlar.
"""

# Standart kütüphane modülleri sisteme dahil edilir
import argparse  # Komut satırı parametrelerini ayrıştırmak için standart araç
import getpass  # Etkin çalışan kullanıcının adını platformdan bağımsız almak için
import json  # JSON formatında veri okuma ve çıktı üretmek için
import os  # İşletim sistemi süreç ve ortam değişkenlerine erişim için
import platform  # İşletim sistemi, mimari ve makine adı bilgilerini sorgulamak için
import subprocess  # Sistem araçlarını (whoami vb.) güvenle çalıştırmak için
import sys  # Sistem bazlı akışlar, standart çıktı ve çıkış kodları için kullanılır
import time  # Denetim zaman damgalarını oluşturmak için kullanılır


def get_local_live_session_info():
    """Çalıştırılan yerel sistemdeki etkin oturum ve kimlik bilgilerini belgeler.
    
    G025-SC2 Laboratuvar Şartı: whoami, id veya Windows hesap komutlarıyla
    kendi oturumunu kontrollü girdi ve gözlenebilir çıktı ile belgele.
    """
    # Temel kimlik değişkenleri hazırlanır
    kullanici = getpass.getuser()  # Geçerli kullanıcı adı
    dugum_adi = platform.node()  # Bilgisayar / host adı
    isletim_sistemi = platform.system()  # İşletim sistemi (Windows, Linux, Darwin)
    surec_id = os.getpid()  # Mevcut Python sürecinin PID değeri
    
    # Platforma özgü oturum verisi toplama sözlüğü
    oturum_detaylari = {
        "kullanici_adi": kullanici,
        "bilgisayar_adi": dugum_adi,
        "isletim_sistemi": isletim_sistemi,
        "surec_pid": surec_id,
        "oturum_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform_verileri": {}
    }

    # Eğer Windows işletim sistemi üzerinde çalışılıyorsa
    if isletim_sistemi == "Windows":
        # Windows ortam değişkenleri güvenle okunur
        oturum_detaylari["platform_verileri"]["kullanici_alani"] = os.environ.get("USERDOMAIN", "LOKAL")
        oturum_detaylari["platform_verileri"]["oturum_sunucusu"] = os.environ.get("LOGONSERVER", "LOKAL")
        oturum_detaylari["platform_verileri"]["profil_dizini"] = os.environ.get("USERPROFILE", "")
        
        # 'whoami /user' komutu çağrılarak SID değeri alınmaya çalışılır
        try:
            # whoami komutu subprocess ile güvenle icra edilir
            proc = subprocess.run(["whoami", "/user"], capture_output=True, text=True, timeout=5)
            # Çıktı başarılı ise eklenir
            if proc.returncode == 0:
                # Satırlar ayrıştırılır ve temizlenir
                oturum_detaylari["platform_verileri"]["whoami_user_raw"] = proc.stdout.strip()
        except Exception as e:
            # Hata oluşursa yakalanır ve günlüğe yazılır
            oturum_detaylari["platform_verileri"]["whoami_user_raw"] = f"Hata: {str(e)}"

    # Eğer Linux veya POSIX uyumlu bir işletim sistemi ise
    else:
        # POSIX UID ve GID değerleri sorgulanır
        oturum_detaylari["platform_verileri"]["uid"] = os.getuid() if hasattr(os, "getuid") else None
        oturum_detaylari["platform_verileri"]["gid"] = os.getgid() if hasattr(os, "getgid") else None
        oturum_detaylari["platform_verileri"]["euid"] = os.geteuid() if hasattr(os, "geteuid") else None
        oturum_detaylari["platform_verileri"]["egid"] = os.getegid() if hasattr(os, "getegid") else None
        # Kullanıcının dahil olduğu tüm ek gruplar sorgulanır
        oturum_detaylari["platform_verileri"]["ikincil_gruplar"] = os.getgroups() if hasattr(os, "getgroups") else []
        # Ev dizini ortam değişkeninden alınır
        oturum_detaylari["platform_verileri"]["ev_dizini"] = os.environ.get("HOME", "")
        # Kabuk ortam değişkeni alınır
        oturum_detaylari["platform_verileri"]["kabuk"] = os.environ.get("SHELL", "")

    # Belgeli oturum sözlüğü döndürülür
    return oturum_detaylari


def audit_users_and_sessions(inventory_data, rules_data):
    """Kullanıcı hesapları ve aktif oturumları temel güvenlik kurallarına göre denetler.
    
    CWE-250 (Execution with Unnecessary Privileges),
    CWE-306 (Missing Authentication for Critical Function - Ortak Hesap Riski)
    ve atıl/yetim hesap anomalilerini tespit eder.
    """
    # Bulgular listesi başlatılır
    bulgular = []
    # İstatistik sayaçları
    toplam_kullanici = 0  # Toplam incelenen kullanıcı sayısı
    toplam_oturum = 0  # Toplam incelenen aktif oturum sayısı
    ihlal_sayisi = 0  # Toplam tespit edilen güvenlik ihlali sayısı
    kritik_sayisi = 0  # Kritik risk sayısı

    # Temel kural parametreleri sözlükten çekilir
    sistem_uid_esigi = rules_data.get("sistem_uid_esigi", 1000)
    yasakli_kabuklar = set(rules_data.get("servis_hesaplari_yasakli_kabuklar", []))
    idari_gruplar = set(rules_data.get("idari_gruplar", []))
    max_bosta_kalma = rules_data.get("maksimum_bosta_kalma_suresi_saniye", 900)
    hareketsizlik_esigi = rules_data.get("hesap_hareketsizlik_esigi_gun", 90)

    # 1. BÖLÜM: KULLANICI HESAPLARI DENETİMİ
    kullanicilar = inventory_data.get("kullanicilar", [])
    # Kullanıcılar üzerinde döngü başlatılır
    for k in kullanicilar:
        # Sayaç artırılır
        toplam_kullanici += 1
        # Kullanıcı özellikleri alınır
        k_adi = k.get("kullanici_adi", "")
        uid = k.get("uid", 0)
        tur = k.get("tur", "human")
        kabuk = k.get("kabuk", "")
        gruplar = set(k.get("gruplar", []))
        son_giris = k.get("son_giris_gun_once", 0)
        durum = k.get("durum", "aktif")

        # Kontrol 1: Servis hesaplarının etkileşimli kabuk kullanması (Kritik Risk)
        if (tur == "service" or uid < sistem_uid_esigi) and uid != 0:
            # Eğer kabuk yasaklı etkileşimli kabuklardan biriyse
            if kabuk in yasakli_kabuklar:
                # İhlal sayacı artırılır
                ihlal_sayisi += 1
                # Kritik sayaç artırılır
                kritik_sayisi += 1
                # Bulgu nesnesi eklenir
                bulgular.append({
                    "kategori": "KULLANICI_KABUK_IHLALI",
                    "hedef": k_adi,
                    "risk_seviyesi": "KRITIK",
                    "cwe_id": "CWE-250",
                    "aciklama": f"Servis hesabı '{k_adi}' (UID: {uid}) etkileşimli kabuk ({kabuk}) ile tanımlanmış!",
                    "iyilestirme": f"usermod -s /usr/sbin/nologin {k_adi}"
                })

        # Kontrol 2: Servis hesabının idari gruplara dahil edilmesi (Yüksek Risk)
        if tur == "service" and (gruplar & idari_gruplar):
            # İhlal artırılır
            ihlal_sayisi += 1
            # Bulgu oluşturulur
            bulgular.append({
                "kategori": "SERVIS_YETKI_ASIMI",
                "hedef": k_adi,
                "risk_seviyesi": "YUKSEK",
                "cwe_id": "CWE-250",
                "aciklama": f"Servis hesabı '{k_adi}' idari grupta yer alıyor: {list(gruplar & idari_gruplar)}",
                "iyilestirme": f"gpasswd -d {k_adi} {list(gruplar & idari_gruplar)[0]}"
            })

        # Kontrol 3: Atıl / Yetim Hesap Kontrolü (Dormant Account - Orta Risk)
        if tur == "human" and son_giris > hareketsizlik_esigi and durum == "aktif":
            # İhlal artırılır
            ihlal_sayisi += 1
            # Bulgu eklenir
            bulgular.append({
                "kategori": "ATIL_HESAP_RISKI",
                "hedef": k_adi,
                "risk_seviyesi": "ORTA",
                "cwe_id": "CWE-262",
                "aciklama": f"Kullanıcı '{k_adi}' {son_giris} gündür giriş yapmamış fakat hesabı hala aktif!",
                "iyilestirme": f"usermod -L {k_adi} (Hesabı kilitle) veya pasifize et"
            })

    # 2. BÖLÜM: ETKİN OTURUMLAR DENETİMİ
    etkin_oturumlar = inventory_data.get("etkin_oturumlar", [])
    # Kullanıcı başına açık oturum sayıları hesaplanır (Ortak hesap tespiti için)
    kullanici_oturum_haritasi = {}
    
    # Her oturum taranır
    for o in etkin_oturumlar:
        # Sayaç artırılır
        toplam_oturum += 1
        # Oturum bilgileri alınır
        o_id = o.get("oturum_id", "")
        o_user = o.get("kullanici_adi", "")
        o_ip = o.get("kaynak_ip", "")
        o_bosta = o.get("bosta_kalma_suresi_saniye", 0)

        # Kullanıcı haritasına eklenir
        if o_user not in kullanici_oturum_haritasi:
            kullanici_oturum_haritasi[o_user] = []
        kullanici_oturum_haritasi[o_user].append(o)

        # Kontrol 4: Oturum Zaman Aşımı (Session Idle Timeout - Orta Risk)
        if o_bosta > max_bosta_kalma:
            # İhlal artırılır
            ihlal_sayisi += 1
            # Bulgu eklenir
            bulgular.append({
                "kategori": "OTURUM_ZAMAN_ASIMI",
                "hedef": f"{o_user} ({o_id})",
                "risk_seviyesi": "ORTA",
                "cwe_id": "CWE-613",
                "aciklama": f"Oturum {o_bosta} saniyedir boşta (Maksimum sınır: {max_bosta_kalma} sn).",
                "iyilestirme": "TMOUT=900 ortam değişkenini zorunlu kıl veya açık oturumu sonlandır"
            })

    # Kontrol 5: Ortak Hesap ve Eşzamanlı İdari Oturum Denetimi (Kritik Risk - G025-SC1)
    for u_name, sessions in kullanici_oturum_haritasi.items():
        # Eğer kullanıcı root ise veya idari bir hesapsa ve 1'den fazla aktif oturumu varsa
        if len(sessions) > 1 and (u_name == "root" or "admin" in u_name):
            # İhlal artırılır
            ihlal_sayisi += 1
            # Kritik artırılır
            kritik_sayisi += 1
            # Oturum IP'leri toplanır
            ipleri = [s.get("kaynak_ip") for s in sessions]
            # Bulgu kaydedilir
            bulgular.append({
                "kategori": "ORTAK_HESAP_VE_INKAR_EDILEMEZLIK_KAYBI",
                "hedef": u_name,
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-306",
                "aciklama": f"İdari hesap '{u_name}' farklı kaynaklardan ({ipleri}) {len(sessions)} eşzamanlı aktif oturuma sahip! Ortak hesap kullanımı izlenebilirliği yok eder.",
                "iyilestirme": "Her yönetici için kişiselleştirilmiş hesap tanımla ve 'maxlogins 1' kuralını uygula"
            })

    # Uyumluluk skoru hesaplanır (İncelenen nesne başına ihlal oranı)
    toplam_nesne = toplam_kullanici + toplam_oturum
    if toplam_nesne > 0:
        # İhlal sayısı toplam nesneye oranlanır
        uyumluluk = max(0.0, round(((toplam_nesne - ihlal_sayisi) / toplam_nesne) * 100, 2))
    else:
        # Nesne yoksa 100 kabul edilir
        uyumluluk = 100.0

    # Rapor sözlüğü hazırlanır ve döndürülür
    return {
        "denetim_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "toplam_kullanici_sayisi": toplam_kullanici,
        "toplam_aktif_oturum_sayisi": toplam_oturum,
        "toplam_ihlal_sayisi": ihlal_sayisi,
        "kritik_ihlal_sayisi": kritik_sayisi,
        "uyumluluk_skoru_yuzde": uyumluluk,
        "bulgular": bulgular
    }


def main():
    """Kullanıcı, Grup ve Oturum Güvenliği CLI Yürütücüsü."""
    # Konsol çıktısı UTF-8 formatına ayarlanır
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktı akışı UTF-8 olarak ayarlanır
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Komut satırı argüman ayrıştırıcısı yapılandırılır
    parser = argparse.ArgumentParser(
        description="G025: Kullanıcı, Grup ve Oturum Güvenliği Denetleyicisi"
    )
    # Canlı oturum sorgulama bayrağı
    parser.add_argument("--live-session", action="store_true", help="Geçerli çalışan yerel oturum bilgilerini belgeler (G025-SC2)")
    # Güvenlik denetim modu bayrağı
    parser.add_argument("--audit", action="store_true", help="Kullanıcı ve oturum envanterini kurallara göre denetler")
    # Kullanıcı ve oturum envanter dosyası yolu
    parser.add_argument("--inventory", type=str, default=None, help="Kullanıcı ve oturum JSON envanteri dosya yolu")
    # Kurallar dosyası yolu
    parser.add_argument("--rules", type=str, default=None, help="Temel güvenlik kuralları JSON dosya yolu")
    # JSON çıktı bayrağı
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında ekrana basar")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # 1. Canlı Yerel Oturum Sorgulama Modu (--live-session)
    if args.live_session:
        # Canlı oturum fonksiyonu çağrılır
        oturum = get_local_live_session_info()
        # JSON istenmişse JSON basılır
        if args.json:
            print(json.dumps(oturum, ensure_ascii=False, indent=2))
        else:
            # Didaktik metin formatında çıktı
            print("=" * 65)
            print("G025-SC2: GEÇERLİ ÇALIŞAN OTURUM BELGELEME RAPORU")
            print("=" * 65)
            print(f"Kullanıcı Kimliği : {oturum['kullanici_adi']}")
            print(f"Bilgisayar Adı    : {oturum['bilgisayar_adi']}")
            print(f"İşletim Sistemi   : {oturum['isletim_sistemi']}")
            print(f"Süreç Kimliği(PID): {oturum['surec_pid']}")
            print(f"Oturum Zamanı     : {oturum['oturum_zamani']}")
            print("-" * 65)
            print("Platform Özel Verileri:")
            # Platform verileri yazdırılır
            for k, v in oturum["platform_verileri"].items():
                print(f" - {k}: {v}")
            print("=" * 65)
        return 0

    # 2. Güvenlik Denetim Modu (--audit)
    if args.audit:
        # Temel dizin yolu belirlenir
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Kurallar dosya yolu
        rules_path = args.rules or os.path.join(base_dir, "ornek_veri", "system_users_groups_baseline.json")
        # Envanter dosya yolu
        inv_path = args.inventory or os.path.join(base_dir, "ornek_veri", "sample_active_sessions_and_users.json")

        # Dosyaların varlığı kontrol edilir
        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"Kural dosyası bulunamadı: {rules_path}")
        if not os.path.exists(inv_path):
            raise FileNotFoundError(f"Envanter dosyası bulunamadı: {inv_path}")

        # JSON verileri okunur
        with open(rules_path, "r", encoding="utf-8") as rf:
            rules_data = json.load(rf)
        with open(inv_path, "r", encoding="utf-8") as inf:
            inv_data = json.load(inf)

        # Denetim icra edilir
        rapor = audit_users_and_sessions(inv_data, rules_data)

        # Çıktı formatı belirlenir
        if args.json:
            print(json.dumps(rapor, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("KULLANICI, GRUP VE OTURUM GÜVENLİK DENETİM RAPORU")
            print("=" * 70)
            print(f"Denetim Zamanı        : {rapor['denetim_zamani']}")
            print(f"İncelenen Kullanıcı   : {rapor['toplam_kullanici_sayisi']}")
            print(f"İncelenen Aktif Oturum: {rapor['toplam_aktif_oturum_sayisi']}")
            print(f"Toplam İhlal Sayısı   : {rapor['toplam_ihlal_sayisi']}")
            print(f"Kritik İhlal Sayısı   : {rapor['kritik_ihlal_sayisi']}")
            print(f"Uyumluluk Skoru       : %{rapor['uyumluluk_skoru_yuzde']}")
            print("-" * 70)
            print("TESPİT EDİLEN BULGULAR VE İYİLEŞTİRME REHBERİ:")
            for b in rapor["bulgular"]:
                print(f"\n[{b['risk_seviyesi']}] {b['kategori']} -> Hedef: {b['hedef']}")
                print(f"   Açıklama   : {b['aciklama']}")
                print(f"   Standart   : {b['cwe_id']}")
                print(f"   İyileştirme: {b['iyilestirme']}")
            print("=" * 70)
        return 0

    # Hiçbir mod seçilmediyse yardım mesajı gösterilir
    parser.print_help()
    return 1


# Python dosyası doğrudan koşturuluyorsa main tetiklenir
if __name__ == "__main__":
    # main fonksiyonunun çıkış kodu işletim sistemine aktarılır
    sys.exit(main())
