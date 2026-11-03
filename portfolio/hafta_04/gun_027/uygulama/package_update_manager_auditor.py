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
"""Paket ve Güncelleme Yöneticileri Güvenlik Denetleyicisi ve Geri Alma Motoru.

Bu modül; paket depolarının (repository) şifreli ve GPG imzalı doğrulanmasını,
kritik altyapı paketlerinde sürüm sabitlemeyi (version pinning / apt-mark hold),
bilinen CVE zafiyetlerine karşı yama analizini, kontrollü güncelleme simülasyonunu
ve olası bozulmalarda önceki sürüme atomik geri alma (rollback) döngüsünü yönetir.
"""

# Standart kütüphane modülleri sisteme dahil edilir
import argparse  # Komut satırı argümanlarını ayrıştırmak için standart kütüphane
import json  # JSON formatında envanter okuma ve günlükleme için
import os  # Dosya ve dizin yönetimi operasyonları için
import re  # Sürüm numaralarını ayrıştırmak ve desen eşleştirmeleri için
import sys  # Sistem akışları, standart çıktı ve çıkış kodları için
import time  # İşlem zaman damgaları ve denetim kayıtları için


def parse_version_string(ver_str):
    """Sürüm dizesini sayısal karşılaştırmaya uygun tamsayı demetine çevirir.
    
    Örnek: '3.0.2' -> (3, 0, 2), '1.18.0-ubuntu1' -> (1, 18, 0)
    """
    # Girdi boşsa sıfır demeti döner
    if not ver_str:
        return (0, 0, 0)
    
    # Rakam blokları regex ile çekilir
    matches = re.findall(r"\d+", str(ver_str))
    # İlk 3 sayı tamsayıya çevrilir, eksikse sıfır ile tamamlanır
    numbers = [int(m) for m in matches[:3]]
    # 3 elemanlı demet haline getirilir
    while len(numbers) < 3:
        numbers.append(0)
    # Tamsayı demeti döndürülür
    return tuple(numbers)


def audit_packages_and_repositories(inventory_data, policy_rules):
    """Paket depoları ve yüklü paketleri güvenlik politikalarına göre denetler.
    
    CWE-319 (Cleartext Transmission),
    CWE-347 (Improper Signature Verification),
    CWE-1395 (Dependency on Vulnerable/Unpinned Software) ihlallerini tespit eder.
    """
    # Bulgular listesi başlatılır
    bulgular = []
    # İstatistik sayaçları
    ihlal_sayisi = 0
    kritik_sayisi = 0

    # Kural parametreleri sözlükten alınır
    izin_verilen_protokoller = policy_rules.get("izin_verilen_protokoller", ["https://"])
    zorunlu_gpg = policy_rules.get("zorunlu_gpg_dogrulamasi", True)
    zorunlu_pin_paketleri = set(policy_rules.get("zorunlu_surum_sabitleme_paketleri", []))
    cve_esigi = policy_rules.get("cve_kritiklik_esigi_cvss", 7.0)

    # 1. BÖLÜM: DEPO (REPOSITORY) GÜVENLİK DENETİMİ
    depolar = inventory_data.get("depolar", [])
    for d in depolar:
        depo_adi = d.get("depo_adi", "")
        url = d.get("url", "")
        protokol = d.get("protokol", "http")
        gpg = d.get("gpg_dogrulandi", False)

        # Kontrol 1: Şifresiz HTTP deposu kullanımı (CWE-319)
        if protokol.lower() not in [p.replace("://", "").lower() for p in izin_verilen_protokoller]:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "GUVENSIZ_DEPO_PROTOKOLU",
                "hedef": f"Depo: {depo_adi} ({url})",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-319: Cleartext Transmission of Sensitive Information",
                "aciklama": f"Depo şifresiz iletişim protokolü ('{protokol}') kullanıyor! Ortadaki Adam (MitM) saldırısıyla zararlı paket enjekte edilebilir.",
                "iyilestirme": f"Depo adresini HTTPS protokollü güvenilir bir mirror ile değiştirin."
            })

        # Kontrol 2: GPG imza doğrulama eksikliği (CWE-347)
        if zorunlu_gpg and not gpg:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "IMZASIZ_DEPO_RISKI",
                "hedef": f"Depo: {depo_adi}",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-347: Improper Verification of Cryptographic Signature",
                "aciklama": f"Depo paketleri GPG anahtarı ile doğrulanmıyor! Sahte veya tahrif edilmiş paketler yüklenebilir.",
                "iyilestirme": "Deponun resmi açık GPG anahtarını /etc/apt/trusted.gpg.d/ altına ekleyin."
            })

    # 2. BÖLÜM: YÜKLÜ PAKETLER VE ZAFİYET DENETİMİ
    paketler = inventory_data.get("paketler", [])
    for p in paketler:
        p_adi = p.get("paket_adi", "")
        mevcut_ver = p.get("mevcut_surum", "")
        sabitlendi = p.get("sabitlendi_mi", False)
        bekleyen_cve = p.get("bekleyen_cve")
        cvss = p.get("cvss_puani", 0.0)
        guncelleme = p.get("mevcut_guncelleme")
        g_turu = p.get("guncelleme_turu")

        # Kontrol 3: Kritik altyapı paketinde sürüm sabitleme eksikliği (G027-SC2)
        if p_adi in zorunlu_pin_paketleri and not sabitlendi:
            ihlal_sayisi += 1
            bulgular.append({
                "kategori": "SURUM_SABITLEME_EKSIKLIGI",
                "hedef": f"Paket: {p_adi} (v{mevcut_ver})",
                "risk_seviyesi": "YUKSEK",
                "cwe_id": "CWE-1395: Dependency on Uncontrolled Third-Party Component",
                "aciklama": f"Kritik paket '{p_adi}' için sürüm sabitleme (pinning) yapılmamış! Otomatik güncellemelerde uyumsuzluk veya kırılma yaşanabilir.",
                "iyilestirme": f"apt-mark hold {p_adi} (veya dnf versionlock add {p_adi}) komutuyla sürümü dondurun."
            })

        # Kontrol 4: Bilinen Kritik CVE Zafiyeti (CWE-1395)
        if bekleyen_cve and cvss >= cve_esigi:
            ihlal_sayisi += 1
            kritik_sayisi += 1
            bulgular.append({
                "kategori": "KRITIK_YAMASIZ_ZAFİYET",
                "hedef": f"Paket: {p_adi} ({bekleyen_cve} - CVSS: {cvss})",
                "risk_seviyesi": "KRITIK",
                "cwe_id": "CWE-1395: Dependency on Known Vulnerable Software",
                "aciklama": f"Pakette kritik CVE zafiyeti mevcut! Güvenlik yaması ({guncelleme}) derhal uygulanmalıdır.",
                "iyilestirme": f"apt-get --only-upgrade install {p_adi}={guncelleme}"
            })

    # Toplam denetlenen nesne sayısı
    toplam_nesne = len(depolar) + len(paketler)
    # Uyumluluk skoru hesaplanır
    uyumluluk_skoru = max(0.0, round(((toplam_nesne - ihlal_sayisi) / toplam_nesne) * 100, 2)) if toplam_nesne > 0 else 100.0

    # Rapor nesnesi döndürülür
    return {
        "denetim_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "toplam_depo_sayisi": len(depolar),
        "toplam_paket_sayisi": len(paketler),
        "toplam_ihlal_sayisi": ihlal_sayisi,
        "kritik_ihlal_sayisi": kritik_sayisi,
        "uyumluluk_skoru_yuzde": uyumluluk_skoru,
        "bulgular": bulgular
    }


def apply_package_pinning(inventory_data, package_name, target_version=None, journal_path="package_pinning_journal.json"):
    """Belirtilen paketi sabitler (apt-mark hold eşdeğeri) ve günlüğe işler.
    
    G027-SC2 Şartı: Sürüm sabitleme mekanizması ve işlem günlüğü.
    """
    secilen_paket = None
    # Paket envanterde aranır
    for p in inventory_data.get("paketler", []):
        if p.get("paket_adi") == package_name:
            secilen_paket = p
            break

    # Paket bulunamazsa hata verilir
    if not secilen_paket:
        raise ValueError(f"Paket bulunamadı: {package_name}")

    # Hedef sürüm belirlenir (verilmemişse mevcut sürüm)
    pin_version = target_version or secilen_paket.get("mevcut_surum")
    # Durum güncellenir
    secilen_paket["sabitlendi_mi"] = True
    secilen_paket["sabitlenen_surum"] = pin_version

    # Günlük kaydı hazırlanır
    kayit = {
        "islem_id": f"PIN-{int(time.time() * 1000)}",
        "zaman_damgasi": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "paket_adi": package_name,
        "sabitlenen_surum": pin_version,
        "durum": "SABITLENDI"
    }

    # Günlük dosyasına yazılır
    gunluk = []
    if os.path.exists(journal_path):
        try:
            with open(journal_path, "r", encoding="utf-8") as jf:
                gunluk = json.load(jf)
        except Exception:
            gunluk = []
    gunluk.append(kayit)
    with open(journal_path, "w", encoding="utf-8") as jf:
        json.dump(gunluk, jf, ensure_ascii=False, indent=2)

    return kayit


def simulate_package_update(inventory_data, package_name, new_version, force=False, journal_path="package_update_journal.json"):
    """Paket güncellemesini simüle eder; sabitlenmiş (pinned) paketleri korur ve günlüğe yazar.
    
    G027-SC2 Şartı: Kontrollü girdi, gözlenebilir çıktı, güncelleme ve geri alma kaydı.
    """
    secilen_paket = None
    # Paket aranır
    for p in inventory_data.get("paketler", []):
        if p.get("paket_adi") == package_name:
            secilen_paket = p
            break

    if not secilen_paket:
        raise ValueError(f"Güncellenecek paket bulunamadı: {package_name}")

    # Eğer paket sabitlenmişse ve zorlama (force) yoksa güncelleme engellenir
    if secilen_paket.get("sabitlendi_mi", False) and not force:
        raise PermissionError(f"Paket '{package_name}' sürümü sabitlenmiş (pinned: {secilen_paket.get('mevcut_surum')}). Doğrudan güncellenemez!")

    eski_surum = secilen_paket.get("mevcut_surum")
    # Sürüm güncellenir
    secilen_paket["mevcut_surum"] = new_version
    # Bekleyen CVE giderilmiş sayılır
    secilen_paket["bekleyen_cve"] = None
    secilen_paket["cvss_puani"] = 0.0

    # Günlük kaydı oluşturulur
    kayit = {
        "guncelleme_id": f"UPD-{int(time.time() * 1000)}",
        "zaman_damgasi": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "paket_adi": package_name,
        "eski_surum": eski_surum,
        "yeni_surum": new_version,
        "durum": "BASARIYLA_GUNCELLENDI"
    }

    # Günlük dosyası güncellenir
    gunluk = []
    if os.path.exists(journal_path):
        try:
            with open(journal_path, "r", encoding="utf-8") as jf:
                gunluk = json.load(jf)
        except Exception:
            gunluk = []
    gunluk.append(kayit)
    with open(journal_path, "w", encoding="utf-8") as jf:
        json.dump(gunluk, jf, ensure_ascii=False, indent=2)

    return kayit


def rollback_package_update(inventory_data, package_name, journal_path="package_update_journal.json"):
    """Güncellenmiş bir paketi işlem günlüğünden okuyarak önceki sürümüne geri alır (Rollback / Downgrade).
    
    G027-SC2 Şartı: Geri alma işleminin doğrulanması.
    """
    if not os.path.exists(journal_path):
        raise FileNotFoundError(f"Güncelleme günlüğü bulunamadı: {journal_path}")

    with open(journal_path, "r", encoding="utf-8") as jf:
        gunluk = json.load(jf)

    # İlgili paketin son güncellemesi ters sırada aranır
    son_islem = None
    for item in reversed(gunluk):
        if item.get("paket_adi") == package_name and item.get("durum") == "BASARIYLA_GUNCELLENDI":
            son_islem = item
            break

    if not son_islem:
        raise ValueError(f"Paket '{package_name}' için geri alınabilir bir güncelleme kaydı bulunamadı!")

    eski_surum = son_islem["eski_surum"]

    # Envanterde sürüm eski haline çekilir
    for p in inventory_data.get("paketler", []):
        if p.get("paket_adi") == package_name:
            p["mevcut_surum"] = eski_surum
            break

    # Geri alma kaydı hazırlanır
    rollback_kaydi = {
        "orijinal_guncelleme_id": son_islem["guncelleme_id"],
        "geri_alma_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "paket_adi": package_name,
        "geri_yuklenen_surum": eski_surum,
        "durum": "BASARIYLA_GERI_ALINDI"
    }

    gunluk.append(rollback_kaydi)
    with open(journal_path, "w", encoding="utf-8") as jf:
        json.dump(gunluk, jf, ensure_ascii=False, indent=2)

    return rollback_kaydi


def generate_package_security_policy_note():
    """Kurumsal sürüm sabitleme ve geri alma güvenlik politikası notunu üretir.
    
    G027-SC2 Şartı: Sürüm sabitleme ve geri alma için örnek güncelleme politikası hazırla.
    """
    politika = [
        "=" * 70,
        "KURUMSAL SÜRÜM SABİTLEME VE GERİ ALMA GÜVENLİK POLİTİKASI (G027-SC2)",
        "=" * 70,
        "1. Depo Kaynağı Doğrulama Prensibi:",
        "   - Yalnızca resmi, kurumsal ve HTTPS üzerinden sunulan depolar yapılandırılabilir.",
        "   - İmzasız veya doğrulanmamış GPG anahtarlı üçüncü taraf PPA depoları KESİNLİKLE yasaktır.",
        "",
        "2. Sürüm Sabitleme (Version Pinning) Kuralı:",
        "   - Veritabanı (PostgreSQL, MySQL), web sunucu (Nginx) ve kriptografik kütüphaneler (OpenSSL)",
        "     için 'apt-mark hold' veya 'dnf versionlock' ile sürüm dondurma ZORUNLUDUR.",
        "   - Üretim ortamlarında test edilmemiş ana sürüm yükseltmeleri engellenir.",
        "",
        "3. Güvenlik Yamaları ve Dağıtım Ayrımı:",
        "   - CVSS >= 7.0 olan güvenlik yamaları 48 saat içinde test ortamında doğrulanır.",
        "   - 'unattended-upgrades' yalnızca 'security' reposu için otomatikleştirilebilir.",
        "",
        "4. Atomik Geri Alma (Rollback) Güvencesi:",
        "   - Her paket güncellemesi öncesinde bir durum günlüğü (transaction journal) tutulur.",
        "   - Hata veya servis kesintisinde 'apt-get install pkg=old_ver' veya 'dnf history undo'",
        "     ile saniyeler içinde kararlı sürüme dönülür.",
        "=" * 70
    ]
    return "\n".join(politika)


def main():
    """Paket ve Güncelleme Yöneticisi CLI Yürütücüsü."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="G027: Paket ve Güncelleme Yöneticileri Güvenlik Denetleyicisi"
    )
    parser.add_argument("--audit", action="store_true", help="Paket ve depoları güvenlik kurallarına göre denetler")
    parser.add_argument("--policy-note", action="store_true", help="Sürüm sabitleme ve geri alma politikasını yazdırır (G027-SC2)")
    parser.add_argument("--inventory", type=str, default=None, help="Paket envanteri JSON dosyası")
    parser.add_argument("--rules", type=str, default=None, help="Temel kural seti JSON dosyası")
    parser.add_argument("--pin", type=str, metavar="PAKET", help="Belirtilen paketin sürümünü sabitler (hold)")
    parser.add_argument("--update", nargs=2, metavar=("PAKET", "YENI_SURUM"), help="Paketi günceller ve günlüğe kaydeder")
    parser.add_argument("--rollback", type=str, metavar="PAKET", help="Paketi günlüğe göre önceki sürümüne döndürür")
    parser.add_argument("--json", action="store_true", help="Sonuçları JSON formatında basar")

    args = parser.parse_args()

    # 1. Politika Notu Yazdırma (--policy-note)
    if args.policy_note:
        note = generate_package_security_policy_note()
        print(note)
        return 0

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inv_path = args.inventory or os.path.join(base_dir, "ornek_veri", "sample_package_inventory.json")
    rules_path = args.rules or os.path.join(base_dir, "ornek_veri", "package_manager_policy_baseline.json")

    # Dosyaların varlığı teyit edilir
    if not os.path.exists(inv_path):
        raise FileNotFoundError(f"Envanter dosyası bulunamadı: {inv_path}")
    if not os.path.exists(rules_path):
        raise FileNotFoundError(f"Kural dosyası bulunamadı: {rules_path}")

    with open(inv_path, "r", encoding="utf-8") as f:
        inv_data = json.load(f)
    with open(rules_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    # 2. Paket Sabitleme (--pin)
    if args.pin:
        res = apply_package_pinning(inv_data, args.pin)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"[BAŞARILI] Paket '{res['paket_adi']}' sürümü {res['sabitlenen_surum']} olarak sabitlendi (PINNED).")
        return 0

    # 3. Paket Güncelleme (--update)
    if args.update:
        pkg, ver = args.update[0], args.update[1]
        res = simulate_package_update(inv_data, pkg, ver)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"[GÜNCELLENDİ] {res['paket_adi']}: {res['eski_surum']} -> {res['yeni_surum']} (İşlem: {res['guncelleme_id']})")
        return 0

    # 4. Geri Alma (--rollback)
    if args.rollback:
        res = rollback_package_update(inv_data, args.rollback)
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"[GERİ ALINDI] {res['paket_adi']} başarıyla {res['geri_yuklenen_surum']} sürümüne döndürüldü.")
        return 0

    # 5. Denetim Modu (--audit)
    if args.audit:
        rapor = audit_packages_and_repositories(inv_data, rules_data)
        if args.json:
            print(json.dumps(rapor, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("PAKET VE GÜNCELLEME YÖNETİCİLERİ GÜVENLİK DENETİM RAPORU")
            print("=" * 70)
            print(f"Denetim Zamanı    : {rapor['denetim_zamani']}")
            print(f"Toplam Depo       : {rapor['toplam_depo_sayisi']}")
            print(f"Toplam Paket      : {rapor['toplam_paket_sayisi']}")
            print(f"Toplam İhlal      : {rapor['toplam_ihlal_sayisi']}")
            print(f"Kritik İhlal      : {rapor['kritik_ihlal_sayisi']}")
            print(f"Uyumluluk Skoru   : %{rapor['uyumluluk_skoru_yuzde']}")
            print("-" * 70)
            print("BULGULAR VE İYİLEŞTİRME ÖNERİLERİ:")
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
