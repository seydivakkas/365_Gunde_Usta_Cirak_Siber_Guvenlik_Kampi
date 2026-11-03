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
"""PATH ve Ortam Değişkenleri Güvenlik Denetleyicisi.

Bu modül; $PATH arama sırası zafiyetlerini (CWE-426), güvenilmeyen/yazılabilir
dizin önceliklerini (CWE-427), tehlikeli dinamik bağlayıcı değişkenlerini (LD_PRELOAD)
ve ortam değişkenlerinde açıkta kalan gizli anahtar/parola sızıntılarını (CWE-526)
denetler ve yerel oturum PATH değerini salt-okunur olarak belgeler.
"""

# Standart kütüphane modülleri sisteme dahil edilir
import argparse  # Komut satırı argümanlarını ayrıştırmak için
import json  # JSON veri okuma ve yapılandırılmış raporlama için
import os  # İşletim sistemi dosya yolu ve ortam değişkenleri yönetimi için
import sys  # Sistem akışları, standart çıktı ve çıkış kodları için
import time  # Denetim zaman damgaları oluşturmak için


def parse_path_string(path_str):
    """PATH dizesini ayrıştırır, boş öğeleri ve bağıl yolları tespit eder.
    
    POSIX standartlarında '::' veya başta/sonda yer alan ':' boş string üretir
    ve işletim sistemi tarafından geçerli çalışma dizini ('.') olarak yorumlanır!
    """
    # Giriş dizesi yoksa boş liste döndürülür
    if not path_str:
        return []

    # Platforma göre ayrıştırıcı belirlenir (Windows ';' içeriyorsa ';' kullanılır, aksi halde POSIX ':')
    separator = ";" if ";" in path_str else ":"
    # Ham parçalar ayrıştırılır (boş öğeleri koruyarak)
    raw_parts = path_str.split(separator)
    
    ayristirilmis_ogeler = []
    # Her bir parça analiz edilir
    for index, part in enumerate(raw_parts):
        # Baştaki ve sondaki boşluklar temizlenir
        clean_part = part.strip()
        # Eğer öğe tamamen boşsa (örn: '::' arası) POSIX gereği '.' anlamına gelir
        is_empty = (len(clean_part) == 0)
        # Eğer '.' veya boş ise bağıl yoldur
        is_relative = is_empty or clean_part == "." or not os.path.isabs(clean_part)
        
        # Yapılandırılmış öğe sözlüğü hazırlanır
        ayristirilmis_ogeler.append({
            "sira": index + 1,
            "ham_deger": part,
            "temiz_deger": "." if is_empty else clean_part,
            "bos_mu": is_empty,
            "bagil_mi": is_relative,
            "mevcut_mu": os.path.exists(clean_part) if clean_part else True
        })

    # Ayrıştırılmış liste döndürülür
    return ayristirilmis_ogeler


def get_local_live_path_environment():
    """Mevcut işletim sisteminin PATH ve kritik ortam değişkenlerini salt-okunur belgeler.
    
    G026-SC2 Laboratuvar Şartı: PATH değerini salt-okunur inceleyip güvenlik notu yaz.
    """
    # Canlı ortam değişkenlerinden PATH değeri okunur
    live_path = os.environ.get("PATH", "")
    # Ayrıştırma motoru çağrılır
    ogeler = parse_path_string(live_path)

    # Güvenlik riskleri tespiti
    bagil_yol_var_mi = any(o["bagil_mi"] for o in ogeler)
    bos_oge_var_mi = any(o["bos_mu"] for o in ogeler)
    mevcut_olmayan_dizinler = [o["temiz_deger"] for o in ogeler if not o["mevcut_mu"]]

    # Yapılandırılmış güvenlik notu metni oluşturulur
    guvenlik_notu = []
    guvenlik_notu.append(f"Toplam PATH Dizin Sayısı: {len(ogeler)}")
    
    # Bağıl yol kontrolü değerlendirmesi
    if bagil_yol_var_mi:
        guvenlik_notu.append("[KRİTİK RİSK] PATH içerisinde '.' veya bağıl dizin tespit edildi (CWE-426)!")
    else:
        guvenlik_notu.append("[GÜVENLİ] PATH içerisinde hiçbir bağıl dizin ('.') bulunmuyor.")

    # Boş öğe kontrolü
    if bos_oge_var_mi:
        guvenlik_notu.append("[KRİTİK RİSK] PATH içerisinde boş ayraç ('::') tespit edildi; örtülü '.' etkisi yaratır!")
    else:
        guvenlik_notu.append("[GÜVENLİ] Boş ayraç ('::') anomalisi tespit edilmedi.")

    # Var olmayan dizin kontrolü
    if mevcut_olmayan_dizinler:
        guvenlik_notu.append(f"[UYARI] Disk üzerinde bulunmayan {len(mevcut_olmayan_dizinler)} adet dizin PATH içinde tanımlı.")
    else:
        guvenlik_notu.append("[BİLGİ] Tanımlı tüm dizinler diskte mevcuttur.")

    # Salt-okunur inceleme sözlüğü döndürülür
    return {
        "tarama_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "isletim_sistemi": sys.platform,
        "ham_path": live_path,
        "ayristirilmis_dizinler": ogeler,
        "bagil_yol_var_mi": bagil_yol_var_mi,
        "bos_oge_var_mi": bos_oge_var_mi,
        "mevcut_olmayan_sayisi": len(mevcut_olmayan_dizinler),
        "guvenlik_notu": guvenlik_notu
    }


def audit_path_and_environment(env_vars, rules_data):
    """Ortam değişkenlerini ve PATH yapısını güvenlik standartlarına göre denetler.
    
    CWE-426 (Untrusted Search Path),
    CWE-427 (Uncontrolled Search Path Element),
    CWE-526 (Information Exposure Through Environmental Variables)
    ve LD_PRELOAD dinamik bağlayıcı enjeksiyonlarını denetler.
    """
    # Bulgular listesi başlatılır
    bulgular = []
    # İstatistik sayaçları
    ihlal_sayisi = 0
    kritik_sayisi = 0

    # Kural parametreleri sözlükten alınır
    yasakli_ogeler = set(rules_data.get("yasakli_path_ogeleri", [".", "", "/tmp", "/var/tmp"]))
    tehlikeli_degiskenler = set(rules_data.get("tehlikeli_yukleyici_degiskenleri", ["LD_PRELOAD", "LD_LIBRARY_PATH"]))
    hassas_kelimeler = rules_data.get("hassas_veri_anahtar_kelimeleri", ["PASSWORD", "SECRET", "TOKEN", "KEY"])

    # 1. BÖLÜM: PATH DEĞİŞKENİ DENETİMİ
    path_val = env_vars.get("PATH", "")
    parsed_path = parse_path_string(path_val)

    # PATH üzerindeki her bir dizin taranır
    for item in parsed_path:
        dizin = item["temiz_deger"]
        sira = item["sira"]

        # Kontrol 1: Bağıl yol veya '.' kullanımı (CWE-426 - KRİTİK)
        if dizin == "." or item["bos_mu"]:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "PATH_BAGIL_YOL_IHLALI",
                "hedef": f"PATH Sıra: {sira} ('{dizin}')",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-426: Untrusted Search Path",
                "aciklama": "PATH arama listesinde geçerli dizin ('.') veya boş ayraç bulundu! Saldırgan bulunduğu dizine sahte ikili (Trojan) koyarak yetki yükseltebilir.",
                "iyilestirme": "PATH değişkeninden '.' ve boş ayraçları ('::') derhal temizleyin."
            })

        # Kontrol 2: Dünyaya yazılabilir güvensiz dizinler (CWE-427 - KRİTİK)
        if dizin in ["/tmp", "/var/tmp", "/dev/shm"]:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "PATH_YAZILABILIR_DIZIN_IHLALI",
                "hedef": f"PATH Sıra: {sira} ('{dizin}')",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-427: Uncontrolled Search Path Element",
                "aciklama": f"Herkese yazılabilir ortak dizin ('{dizin}') PATH içerisine eklenmiş! Herhangi bir kullanıcı meşru komutların önüne sahte ikili yerleştirebilir.",
                "iyilestirme": f"'{dizin}' dizinini sistem PATH listesinden derhal kaldırın."
            })

        # Kontrol 3: Kullanıcı ev dizini ikililerinin sistem dizinlerinin önünde olması
        if (dizin.startswith("/home/") or "\\Users\\" in dizin) and sira <= 2:
            ihlal_sayisi += 1
            bulgular.append({
                "kategori": "PATH_ONCELIK_GASP_RISKI",
                "hedef": f"PATH Sıra: {sira} ('{dizin}')",
                "risk_seviyesi": "YUKSEK",
                "cwe_id": "CWE-426: Untrusted Search Path",
                "aciklama": f"Kullanıcı özel dizini ('{dizin}') sistem dizinlerinden (/usr/bin vb.) önce tanımlanmış! Meşru sistem araçları gölgelenebilir (hijacking).",
                "iyilestirme": "Sistem dizinlerini (/usr/local/bin, /usr/bin) her zaman kullanıcı dizinlerinin önüne taşıyın."
            })

    # 2. BÖLÜM: TEHLİKELİ DİNAMİK BAĞLAYICI DEĞİŞKENLERİ
    for var_name in tehlikeli_degiskenler:
        if var_name in env_vars and env_vars[var_name]:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "YUKLEYICI_ENJEKSIYON_RISKI",
                "hedef": f"{var_name}={env_vars[var_name]}",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-114: Process Control (Dynamic Linker Hijacking)",
                "aciklama": f"Tehlikeli dinamik kütüphane bağlayıcı değişkeni ('{var_name}') aktif! Süreçlerin paylaşımlı kütüphaneleri hook edilerek kod enjeksiyonu yapılabilir.",
                "iyilestirme": f"unset {var_name} komutu ile değişkeni sistemden kaldırın."
            })

    # 3. BÖLÜM: HASSAS VERİ VE AÇIKTA KALAN PAROLA SIZINTILARI (CWE-526)
    for k, v in env_vars.items():
        if k == "PATH":
            continue
        # Anahtar kelime eşleşmesi kontrolü
        for kw in hassas_kelimeler:
            if kw in k.upper() and len(str(v)) > 0:
                ihlal_sayisi += 1
                bulgular.append({
                    "kategori": "ORTAMDA_ACIK_PAROLA_SIZINTISI",
                    "hedef": k,
                    "risk_seviyesi": "YUKSEK",
                    "cwe_id": "CWE-526: Information Exposure Through Environmental Variables",
                    "aciklama": f"Ortam değişkeninde ('{k}') açık metin kimlik/parola verisi saklanıyor! Tüm alt süreçler ve /proc/PID/environ dosyası bu sırrı okuyabilir.",
                    "iyilestirme": "Gizli anahtarları ortam değişkenleri yerine güvenli sır yöneticisi (Vault, Keyring) ile saklayın."
                })
                break

    # Toplam kontrol nesnesi sayısı
    toplam_kontrol = len(parsed_path) + len(env_vars)
    # Uyumluluk skoru hesaplanır
    uyumluluk_skoru = max(0.0, round(((toplam_kontrol - ihlal_sayisi) / toplam_kontrol) * 100, 2)) if toplam_kontrol > 0 else 100.0

    # Rapor nesnesi oluşturulur
    return {
        "denetim_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "toplam_path_dizin_sayisi": len(parsed_path),
        "toplam_ortam_degiskeni_sayisi": len(env_vars),
        "toplam_ihlal_sayisi": ihlal_sayisi,
        "kritik_ihlal_sayisi": kritik_sayisi,
        "uyumluluk_skoru_yuzde": uyumluluk_skoru,
        "bulgular": bulgular
    }


def main():
    """PATH ve Ortam Değişkenleri Güvenlik Denetleyicisi CLI."""
    # Konsol UTF-8 çıktı formatı ayarlanır
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı tanımlanır
    parser = argparse.ArgumentParser(
        description="G026: PATH ve Ortam Değişkenleri Güvenlik Denetleyicisi"
    )
    # Canlı PATH inceleme modu (G026-SC2)
    parser.add_argument("--live-path", action="store_true", help="Geçerli sistem PATH değerini salt-okunur inceler ve güvenlik notu yazar")
    # Denetim modu
    parser.add_argument("--audit", action="store_true", help="Profil veya ortam değişkenlerini kurallara göre denetler")
    # Kural dosyası
    parser.add_argument("--rules", type=str, default=None, help="Temel kural seti JSON dosyası")
    # Profil dosyası
    parser.add_argument("--profiles", type=str, default=None, help="Örnek ortam profilleri JSON dosyası")
    # Belirli profil adı
    parser.add_argument("--profile-name", type=str, default="guvensiz_gelistirici_profili", help="Denetlenecek profil adı")
    # JSON çıktı bayrağı
    parser.add_argument("--json", action="store_true", help="Sonucu saf JSON olarak ekrana basar")

    args = parser.parse_args()

    # 1. Canlı PATH İnceleme İsteği (--live-path)
    if args.live_path:
        res = get_local_live_path_environment()
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("G026-SC2: GEÇERLİ SİSTEM PATH SALT-OKUNUR İNCELEME RAPORU")
            print("=" * 70)
            print(f"Tarama Zamanı   : {res['tarama_zamani']}")
            print(f"İşletim Sistemi : {res['isletim_sistemi']}")
            print("-" * 70)
            print("AYRIŞTIRILMIŞ PATH DİZİNLERİ:")
            for o in res["ayristirilmis_dizinler"]:
                durum = "[MEVCUT]" if o["mevcut_mu"] else "[BULUNAMADI]"
                bagil = " [!] BAĞIL YOL" if o["bagil_mi"] else ""
                print(f" {o['sira']:02d}. {durum}{bagil} {o['temiz_deger']}")
            print("-" * 70)
            print("GÜVENLİK DEĞERLENDİRME NOTU:")
            for n in res["guvenlik_notu"]:
                print(f" * {n}")
            print("=" * 70)
        return 0

    # 2. Güvenlik Denetim Modu (--audit)
    if args.audit:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rules_path = args.rules or os.path.join(base_dir, "ornek_veri", "path_security_baseline_rules.json")
        profiles_path = args.profiles or os.path.join(base_dir, "ornek_veri", "sample_environment_profiles.json")

        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"Kural dosyası bulunamadı: {rules_path}")
        if not os.path.exists(profiles_path):
            raise FileNotFoundError(f"Profil dosyası bulunamadı: {profiles_path}")

        with open(rules_path, "r", encoding="utf-8") as rf:
            rules_data = json.load(rf)
        with open(profiles_path, "r", encoding="utf-8") as pf:
            profiles_data = json.load(pf)

        # Seçilen profili bul
        secilen_profil = None
        for p in profiles_data.get("profiller", []):
            if p.get("profil_adi") == args.profile_name:
                secilen_profil = p
                break

        if not secilen_profil:
            # Profil bulunamazsa ilk profili al
            secilen_profil = profiles_data.get("profiller", [])[0]

        rapor = audit_path_and_environment(secilen_profil.get("ortam_degiskenleri", {}), rules_data)
        rapor["denetlenen_profil"] = secilen_profil.get("profil_adi")

        if args.json:
            print(json.dumps(rapor, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print(f"PATH VE ORTAM DEĞİŞKENLERİ GÜVENLİK DENETİMİ: {rapor['denetlenen_profil']}")
            print("=" * 70)
            print(f"Denetim Zamanı     : {rapor['denetim_zamani']}")
            print(f"PATH Dizin Sayısı  : {rapor['toplam_path_dizin_sayisi']}")
            print(f"Ortam Değişkeni    : {rapor['toplam_ortam_degiskeni_sayisi']}")
            print(f"Toplam İhlal       : {rapor['toplam_ihlal_sayisi']}")
            print(f"Kritik İhlal       : {rapor['kritik_ihlal_sayisi']}")
            print(f"Uyumluluk Skoru    : %{rapor['uyumluluk_skoru_yuzde']}")
            print("-" * 70)
            print("TESPİT EDİLEN BULGULAR VE İYİLEŞTİRME:")
            for b in rapor["bulgular"]:
                print(f"\n[{b['risk_seviyesi']}] {b['kategori']} -> Hedef: {b['hedef']}")
                print(f"   Açıklama   : {b['aciklama']}")
                print(f"   Standart   : {b['cwe_id']}")
                print(f"   İyileştirme: {b['iyilestirme']}")
            print("=" * 70)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
