# -*- coding: utf-8 -*-
"""
GÜN 017: İşletim Sistemi Çekirdeği (Kernel Mode) ve Kullanıcı Modu (User Mode) Güvenlik Analizörü
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 17)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez.
"""

# İşletim sistemi API çağrıları, dosya ve dizin işlemleri için os modülü
import os
# Python yorumlayıcı parametreleri ve platform sınırları için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve dışa aktarmak için json modülü
import json
# Zaman damgaları ve denetim kayıtları için datetime modülü
import datetime
# Komut satırı argümanlarını yönetmek için argparse modülü
import argparse
# Windows platformunda yerel Win32 API çağrıları için ctypes modülü
import ctypes
# Platform ve mimari tespiti için platform modülü
import platform


class KernelUserModeBoundaryAnalyzer:
    """
    İşletim sistemi çekirdek kipi (Kernel Mode / Ring 0) ile kullanıcı kipi
    (User Mode / Ring 3) arasındaki yetki sınırlarını, sistem çağrısı (syscall)
    doğrulamalarını, BYOVD (savunmasız sürücü) risklerini ve donanım izolasyon
    mekanizmalarını denetleyen güvenlik motoru.
    """

    def __init__(self):
        # Analizör motorunun sürüm bilgisini belirliyoruz
        self.version = "1.0.0"
        # 64-bit x86 mimarisinde kullanıcı alanı azami adres sınırı (User-Kernel Split)
        # 0x00007FFFFFFFFFFF üzerindeki adresler çekirdek alanına aittir (Canonical Addressing)
        self.canonical_user_space_max = 0x00007FFFFFFFFFFF
        # 64-bit mimaride çekirdek alanı başlangıç adresi tabanı
        self.canonical_kernel_space_min = 0xFFFF800000000000

    def get_current_process_privilege_context(self):
        """
        Mevcut çalışan sürecin işletim sistemi yetki bağlamını (Process Integrity Level)
        ve yönetici/root haklarına sahip olup olmadığını yerel API ile sorgular.
        """
        # Sürecin işlemci kimliğini (PID) alıyoruz
        pid = os.getpid()
        # İşletim sistemini tespit ediyoruz (Windows, Linux, Darwin vb.)
        os_name = platform.system()
        # Yönetici / Elevated yetkisi durumunu belirleyeceğimiz değişken
        is_elevated = False
        # Sürecin bütünlük seviyesi (Integrity Level) tanımı
        integrity_level = "Medium (Standart Kullanıcı)"

        # Windows işletim sistemi üzerinde Win32 API kullanarak kontrol yapıyoruz
        if os_name == "Windows":
            try:
                # shell32.dll içerisindeki IsUserAnAdmin fonksiyonunu çağırıyoruz
                is_admin_call = ctypes.windll.shell32.IsUserAnAdmin()
                # Fonksiyon sıfırdan farklı döndürürse yönetici yetkisi vardır
                is_elevated = bool(is_admin_call != 0)
                if is_elevated:
                    integrity_level = "High (Yönetici / Elevated)"
            except Exception:
                # Hata durumunda varsayılan güvenli değerde kalıyoruz
                is_elevated = False
        else:
            # POSIX sistemlerde (Linux/macOS) efektif kullanıcı kimliğini kontrol ediyoruz
            try:
                # geteuid() 0 ise süreç root yetkisiyle çalışıyordur
                is_elevated = (os.geteuid() == 0)
                if is_elevated:
                    integrity_level = "High (Root / Superuser)"
            except AttributeError:
                # Windows altında geteuid bulunmaz, yoksayılır
                pass

        # Süreç bağlamı sözlüğünü döndürüyoruz
        return {
            "pid": pid,
            "isletim_sistemi": os_name,
            "mimari": platform.machine(),
            "yonetici_yetkisi_var_mi": is_elevated,
            "butunluk_seviyesi": integrity_level,
            "calisma_halkasi": "Ring 3 (Kullanıcı Kipi - User Mode)",
            "aciklama": "Yönetici olsa dahi kullanıcı süreci Ring 3'te çalışır; donanıma doğrudan erişemez."
        }

    def load_json_file(self, filepath):
        """
        Belirtilen JSON dosyasını UTF-8 kodlamasıyla güvenli olarak yükler.
        """
        # Dosyanın varlığını denetliyoruz
        if not os.path.exists(filepath):
            # Bulunamadığında FileNotFoundError üretiyoruz
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")
        # Dosyayı okuma kipinde açıyoruz
        with open(filepath, "r", encoding="utf-8") as f:
            # Sözlük olarak döndürüyoruz
            return json.load(f)

    def validate_syscall_pointer(self, address_str, size_bytes):
        """
        Kullanıcı kipinden (Ring 3) sistem çağrısı (syscall) ile çekirdek kipine (Ring 0)
        aktarılan bir bellek işaretçisini (pointer) ProbeForRead/ProbeForWrite mantığıyla doğrular.
        Çekirdek alanına sızmaya çalışan veya tamsayı taşması oluşturan işaretçileri engeller.
        """
        # Adres metnini onaltılık (hex) tamsayıya çeviriyoruz
        try:
            addr_int = int(address_str, 16) if isinstance(address_str, str) else int(address_str)
        except ValueError:
            # Geçersiz format durumunda güvenlik ihlali döndürüyoruz
            return {
                "adres": address_str,
                "durum": "GECERSIZ_FORMAT",
                "hata": "Adres geçerli bir onaltılık (hex) sayı değil."
            }

        # NULL Pointer (0x0) kontrolü yapıyoruz (CWE-476: NULL Pointer Dereference önleme)
        if addr_int == 0:
            return {
                "adres": address_str,
                "durum": "ENGEL_NULL_POINTER",
                "hata": "NULL Pointer tespit edildi; çekirdek çökmesi (Kernel Panic / BSOD) önlendi.",
                "guvenli_mi": False
            }

        # Tamsayı taşması (Integer Overflow) kontrolü yapıyoruz: addr + size belleği aşıyor mu?
        if addr_int + size_bytes < addr_int:
            return {
                "adres": address_str,
                "durum": "ENGEL_INTEGER_OVERFLOW",
                "hata": "İşaretçi ve boyut toplamında tamsayı taşması saptandı!",
                "guvenli_mi": False
            }

        # Kullanıcı alanı sınır kontrolü (ProbeForRead kuralı)
        # İşaretçinin başlangıcı veya sonu çekirdek alanına taşıyorsa derhal engellenir
        if addr_int > self.canonical_user_space_max or (addr_int + size_bytes) > self.canonical_user_space_max:
            return {
                "adres": address_str,
                "durum": "ENGEL_CEKIRDEK_ALANI_IHLALI",
                "hata": "İşaretçi çekirdek adres alanını (Kernel Space) işaret ediyor! SMEP/SMAP ihlali engellendi.",
                "guvenli_mi": False
            }

        # Tüm güvenlik kontrollerini geçen meşru kullanıcı alanı işaretçisi
        return {
            "adres": address_str,
            "boyut_byte": size_bytes,
            "durum": "GECERLI_KULLANICI_ISARETCISI",
            "hedef_alan": "Ring 3 Kullanıcı Sanal Belleği",
            "guvenli_mi": True
        }

    def audit_byovd_drivers(self, driver_list):
        """
        Sistemde bulunan veya yüklenmek istenen aygıt sürücülerini
        bilinen savunmasız sürücüler (BYOVD - Bring Your Own Vulnerable Driver)
        ve imzasız sürücü tehditleri açısından denetler.
        """
        # Denetim bulgularını tutacağımız listeyi başlatıyoruz
        bulgular = []
        # Güvensiz ve engellenmesi gereken sürücü sayacı
        engellenen_sayisi = 0

        # Sürücü listesindeki her girdiyi analiz ediyoruz
        for driver in driver_list:
            ad = driver.get("surucu_adi", "BILINMEYEN.sys")
            uretici = driver.get("uretici", "Bilinmiyor")
            zafiyet = driver.get("zafiyet_turu", "Yok")
            durum = driver.get("durum", "BILINMIYOR")

            # Eğer sürücü bilinen istismar edilebilir bir sürücü ise
            if durum == "ENGEL_LISTESINDE_OLMALI" or zafiyet != "Yok":
                engellenen_sayisi += 1
                bulgular.append({
                    "surucu_adi": ad,
                    "uretici": uretici,
                    "risk_seviyesi": "KRITIK",
                    "zafiyet": zafiyet,
                    "karar": "YUKLEME_ENGEL_BYOVD_TEHDITI"
                })
            else:
                bulgular.append({
                    "surucu_adi": ad,
                    "uretici": uretici,
                    "risk_seviyesi": "DUSUK",
                    "zafiyet": "Yok",
                    "karar": "GECERLI_IMZALI_SURUCU"
                })

        # Sürücü denetim özetini döndürüyoruz
        return {
            "toplam_surucu_sayisi": len(driver_list),
            "engellenen_byovd_surucu_sayisi": engellenen_sayisi,
            "guvenli_surucu_sayisi": len(driver_list) - engellenen_sayisi,
            "surucu_detaylari": bulgular
        }

    def audit_kernel_security_baseline(self, current_config, baseline_data):
        """
        Çekirdek kipi koruma ayarlarını (DSE, HVCI, VBS, SMEP/SMAP)
        güvenlik taban çizgisi kurallarıyla kıyaslar.
        """
        # Taban çizgisi kurallarını alıyoruz
        kurallar = baseline_data.get("guvenlik_kurallari", [])
        # Geçen ve kalan kural listelerini başlatıyoruz
        gecenler = []
        ihlaller = []

        # Kuralları tek tek değerlendiriyoruz
        for kural in kurallar:
            kural_id = kural.get("kural_id")
            kriter = kural.get("kriter")
            beklenen = kural.get("beklenen_deger")
            seviye = kural.get("seviye", "ORTA")
            mesaj = kural.get("hata_mesaji", "Kural ihlali")

            # Sistem konfigürasyonundaki mevcut değeri okuyoruz
            mevcut = current_config.get(kriter, None)

            # Eşleşme durumuna göre sınıflandırıyoruz
            if mevcut == beklenen:
                gecenler.append({
                    "kural_id": kural_id,
                    "kriter": kriter,
                    "durum": "UYGUN",
                    "deger": mevcut
                })
            else:
                ihlaller.append({
                    "kural_id": kural_id,
                    "kriter": kriter,
                    "durum": "IHLAL",
                    "beklenen": beklenen,
                    "mevcut": mevcut,
                    "seviye": seviye,
                    "hata_mesaji": mesaj
                })

        # Uyumluluk oranını hesaplıyoruz
        toplam = len(kurallar)
        oran = round((len(gecenler) / toplam * 100), 2) if toplam > 0 else 0.0

        # Denetim özetini döndürüyoruz
        return {
            "toplam_kural_sayisi": toplam,
            "uygun_kural_sayisi": len(gecenler),
            "ihlal_sayisi": len(ihlaller),
            "uyumluluk_orani_yuzde": oran,
            "gecen_kurallar": gecenler,
            "ihlal_edilen_kurallar": ihlaller
        }

    def generate_full_audit(self, matrix_filepath, baseline_filepath):
        """
        Yetki matrisi, BYOVD sürücü denetimi, sistem çağrısı işaretçi doğrulaması
        ve çekirdek güvenlik taban çizgisini birleştirerek kapsamlı bir rapor üretir.
        """
        # Matris ve taban çizgisi verilerini yüklüyoruz
        matrix_data = self.load_json_file(matrix_filepath)
        baseline_data = self.load_json_file(baseline_filepath)

        # 1. Canlı süreç bağlamını alıyoruz
        live_proc = self.get_current_process_privilege_context()

        # 2. BYOVD sürücü denetimini yapıyoruz
        suruculer = matrix_data.get("bilinen_guvenliksiz_suruculer_byovd", [])
        driver_audit = self.audit_byovd_drivers(suruculer)

        # 3. Sistem çağrısı işaretçi test senaryolarını icra ediyoruz
        ptr_senaryolar = matrix_data.get("sistem_cagrisi_isaretci_test_senaryolari", [])
        pointer_results = []
        for s in ptr_senaryolar:
            res = self.validate_syscall_pointer(s.get("adres"), s.get("boyut_byte", 0))
            pointer_results.append({
                "senaryo_id": s.get("senaryo_id"),
                "aciklama": s.get("aciklama"),
                "test_sonucu": res
            })

        # 4. Çekirdek güvenlik taban çizgisi uyumluluğunu sınıyoruz
        # Örnek bir sistem konfigürasyonu simülasyonu
        simulated_sys_config = {
            "surucu_imza_zorunlulugu_dse": True,
            "savunmasiz_surucu_engelleme_listesi_etkin": False,  # İhlal senaryosu
            "hipervizor_korumali_kod_butunlugu_hvci": True,
            "smep_smap_donanim_izolasyonu": True
        }
        baseline_audit = self.audit_kernel_security_baseline(simulated_sys_config, baseline_data)

        # Bütünleştirilmiş nihai raporu inşa ediyoruz
        full_report = {
            "denetim_zamani": datetime.datetime.now().isoformat(),
            "denetim_motoru_surumu": self.version,
            "canli_surec_baglami": live_proc,
            "yetki_seviyeleri_envanteri": list(matrix_data.get("yetki_seviyeleri", {}).keys()),
            "surucu_byovd_denetimi": driver_audit,
            "isaretci_syscall_denetimi": pointer_results,
            "cekirdek_taban_cizgisi_denetimi": baseline_audit,
            "genel_sonuc": "IHLAL_VAR" if (driver_audit["engellenen_byovd_surucu_sayisi"] > 0 or baseline_audit["ihlal_sayisi"] > 0) else "TEMIZ"
        }
        # Raporu döndürüyoruz
        return full_report


def main():
    """
    Komut satırı arayüzü ana giriş noktası.
    """
    # Argüman ayrıştırıcıyı yapılandırıyoruz
    parser = argparse.ArgumentParser(
        description="GÜN 017: Çekirdek (Kernel) ve Kullanıcı (User) Modu Güvenlik Analizörü"
    )
    # Canlı süreç bağlamı sorgulama seçeneği
    parser.add_argument(
        "--live",
        action="store_true",
        help="Mevcut Python sürecinin işletim sistemi yetki bağlamını canlı olarak sorgular."
    )
    # Yetki matrisi veri dosyası seçeneği
    parser.add_argument(
        "--matrix",
        type=str,
        default="ornek_veri/kernel_user_privilege_matrix.json",
        help="Yetki seviyeleri ve BYOVD sürücü örnek veri dosyası yolu."
    )
    # Taban çizgisi dosyası seçeneği
    parser.add_argument(
        "--baseline",
        type=str,
        default="ornek_veri/kernel_security_baseline.json",
        help="Çekirdek güvenlik kuralları taban çizgisi dosyası yolu."
    )
    # Çıktıyı JSON olarak verme seçeneği
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON olarak konsola yazdırır."
    )

    # Argümanları ayrıştırıyoruz
    args = parser.parse_args()

    # Analizör nesnemizi başlatıyoruz
    analyzer = KernelUserModeBoundaryAnalyzer()

    # Canlı süreç sorgusu talep edilmişse
    if args.live:
        live_data = analyzer.get_current_process_privilege_context()
        print(json.dumps(live_data, indent=2, ensure_ascii=False))
        return

    # Tam denetim raporunu üretiyoruz
    try:
        rapor = analyzer.generate_full_audit(args.matrix, args.baseline)
        if args.json:
            print(json.dumps(rapor, indent=2, ensure_ascii=False))
        else:
            print("=" * 72)
            print("GÜN 017: ÇEKİRDEK (KERNEL) VE KULLANICI MODU GÜVENLİK DENETİMİ")
            print("=" * 72)
            print(f"Denetim Zamanı : {rapor['denetim_zamani']}")
            print(f"Genel Sonuç    : {rapor['genel_sonuc']}")
            print(f"Süreç Bütünlüğü: {rapor['canli_surec_baglami']['butunluk_seviyesi']}")
            print(f"BYOVD Engeli   : {rapor['surucu_byovd_denetimi']['engellenen_byovd_surucu_sayisi']} adet tehlikeli sürücü saptandı!")
            print(f"Çekirdek Uyumu : %{rapor['cekirdek_taban_cizgisi_denetimi']['uyumluluk_orani_yuzde']}")
            print("-" * 72)
            print("BYOVD TEHDİT ANALİZİ:")
            for d in rapor["surucu_byovd_denetimi"]["surucu_detaylari"]:
                if d["risk_seviyesi"] == "KRITIK":
                    print(f"  [KRITIK] {d['surucu_adi']} ({d['uretici']}): {d['zafiyet']}")
            print("-" * 72)
            print("SİSTEM ÇAĞRISI (SYSCALL) İŞARETÇİ KORUMA DENETİMLERİ:")
            for p in rapor["isaretci_syscall_denetimi"]:
                res = p["test_sonucu"]
                print(f"  [{p['senaryo_id']}] {res['durum']}: {p['aciklama']}")
            print("-" * 72)
            print("ÇEKİRDEK TABAN ÇİZGİSİ İHLALLERİ:")
            for ihlal in rapor["cekirdek_taban_cizgisi_denetimi"]["ihlal_edilen_kurallar"]:
                print(f"  [{ihlal['seviye']}] {ihlal['kural_id']}: {ihlal['hata_mesaji']}")
            print("=" * 72)
    except Exception as e:
        print(f"HATA: Denetim icra edilirken hata oluştu: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
