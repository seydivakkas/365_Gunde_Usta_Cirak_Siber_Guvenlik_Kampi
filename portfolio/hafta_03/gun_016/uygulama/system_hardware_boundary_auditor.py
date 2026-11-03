# -*- coding: utf-8 -*-
"""
GÜN 016: CPU, RAM ve Depolama Donanım Sınırları ve Veri Kalıntısı Güvenlik Analizörü
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 16)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez.
"""

# İşletim sistemi ve donanım mimarisi bilgilerini sorgulamak için standart platform modülü
import platform
# Dosya yolları, süreç kimlikleri ve ortam değişkenleri denetimi için os modülü
import os
# Python yorumlayıcı ve bellek göstergelerine erişim için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve raporlamak için json modülü
import json
# Zaman damgaları ve denetim loglaması oluşturmak için datetime modülü
import datetime
# Komut satırı argümanlarını profesyonelce ayrıştırmak için argparse modülü
import argparse
# Disk ve depolama istatistiklerini işletim sistemi bağımsız okumak için shutil modülü
import shutil


class SystemHardwareBoundaryAuditor:
    """
    CPU, RAM ve Kalıcı Depolama donanım katmanları arasındaki mimari sınırları,
    uçuculuk (volatility) farklarını, veri kalıntısı (data remanence) zaafiyetlerini
    ve bellek hijyeni kontrollerini analiz eden denetim sınıfı.
    """

    def __init__(self):
        # Denetim motorunun sürüm bilgisini başlatıyoruz
        self.version = "1.0.0"
        # Desteklenen donanım katmanlarını hiyerarşik olarak tanımlıyoruz
        self.hardware_layers = ["CPU", "RAM", "Depolama"]

    def get_live_hardware_inventory(self):
        """
        Yerel sistemin canlı CPU, RAM ve Depolama donanım metriklerini
        harici kütüphane gerektirmeksizin standart Python araçlarıyla toplar.
        """
        # İşlemci mimarisini ve işlemci adını güvenli biçimde sorguluyoruz
        cpu_arch = platform.machine()
        # İşlemci işlemci model veya ailesi bilgisini alıyoruz
        cpu_processor = platform.processor() or "Bilinmeyen Islemci Modeli"
        # Mantıksal CPU çekirdek sayısını os modülünden öğreniyoruz
        cpu_cores = os.cpu_count() or 1

        # Disk depolama alanını kök dizin üzerinden shutil ile sorguluyoruz
        # Windows ortamında C:\\ veya mevcut sürücü, POSIX ortamında / kullanılır
        root_path = os.path.abspath(os.sep)
        # Disk kullanım istatistiklerini (toplam, kullanılan, boş) alıyoruz
        disk_usage = shutil.disk_usage(root_path)

        # Toplam disk alanını Gigabyte (GB) cinsine dönüştürüyoruz
        disk_total_gb = round(disk_usage.total / (1024 ** 3), 2)
        # Kullanılan disk alanını Gigabyte (GB) cinsine dönüştürüyoruz
        disk_used_gb = round(disk_usage.used / (1024 ** 3), 2)
        # Boş disk alanını Gigabyte (GB) cinsine dönüştürüyoruz
        disk_free_gb = round(disk_usage.free / (1024 ** 3), 2)

        # Canlı envanter sözlüğünü katmanlara ayırarak yapılandırıyoruz
        live_inventory = {
            "toplama_zamani": datetime.datetime.now().isoformat(),
            "isletim_sistemi": platform.system(),
            "isletim_sistemi_surumu": platform.version(),
            "cpu_katmani": {
                "mimari": cpu_arch,
                "model": cpu_processor,
                "mantiksal_cekirdek_sayisi": cpu_cores,
                "ucuculuk": "Ultra-Volatile (Kayıtçılar ve L1-L3 Önbellek; döngüsel yenilenir)",
                "guvenlik_riski": "Spekülatif yürütme yan kanalları (Spectre/Meltdown), Register dökümleri"
            },
            "ram_katmani": {
                "adres_genisligi_bit": 64 if sys.maxsize > 2**32 else 32,
                "ucuculuk": "Volatile (DRAM; enerji kesildiğinde içerik kaybolur, Cold Boot istisnası)",
                "guvenlik_riski": "Açık metin bellek dökümleri, Sayfalama/Swap sızıntısı, Un-zeroed heap kalıntıları"
            },
            "depolama_katmani": {
                "kok_surucu": root_path,
                "toplam_alan_gb": disk_total_gb,
                "kullanilan_alan_gb": disk_used_gb,
                "bos_alan_gb": disk_free_gb,
                "ucuculuk": "Non-Volatile (Kalıcı; silinen veriler adli bilişimle geri getirilebilir)",
                "guvenlik_riski": "Veri kalıntısı (Data Remanence), Şifrelenmemiş swap/hiberfil dosyaları"
            }
        }
        # Yapılandırılmış canlı donanım envanterini döndürüyoruz
        return live_inventory

    def load_json_file(self, filepath):
        """
        Belirtilen JSON dosyasını UTF-8 kodlamasıyla güvenli bir biçimde yükler.
        """
        # Dosyanın disk üzerinde var olup olmadığını doğruluyoruz
        if not os.path.exists(filepath):
            # Dosya bulunamadığında açıklayıcı bir FileNotFoundError fırlatıyoruz
            raise FileNotFoundError(f"Belirtilen dosya bulunamadı: {filepath}")
        # Dosyayı UTF-8 karakter desteğiyle okuma kipinde açıyoruz
        with open(filepath, "r", encoding="utf-8") as f:
            # JSON içeriğini Python sözlük nesnesine dönüştürerek döndürüyoruz
            return json.load(f)

    def evaluate_data_remanence(self, memory_object):
        """
        Tekil bir bellek veya depolama nesnesini veri kalıntısı (remanence)
        ve donanım sınırları sızıntı riskleri açısından değerlendirir.
        """
        # Nesne kimliğini sözlükten alıyoruz
        obj_id = memory_object.get("nesne_id", "BILINMEYEN_ID")
        # Nesnenin bulunduğu donanım katmanını alıyoruz (CPU, RAM, Depolama)
        katman = memory_object.get("mevcut_katman", "BILINMEYEN")
        # Nesnenin şifreli olup olmadığını kontrol ediyoruz
        is_encrypted = memory_object.get("sifrelenmis", False)
        # Temizleme yöntemini okuyoruz (plain_free, secure_zero_memory, vb.)
        wipe_method = memory_object.get("temizleme_yontemi", "tanimsiz")
        # Güvenli sıfırlama yapılıp yapılmadığını sorguluyoruz
        is_zeroed = memory_object.get("guvenli_sifirlama_yapildi", False)
        # Sayfalama / takas alanına kilitlenip kilitlenmediğini (mlock) kontrol ediyoruz
        is_mlocked = memory_object.get("mlock_kullanildi", False)

        # Risk seviyesini ve bulguları depolayacağımız değişkenleri başlatıyoruz
        risk_level = "DUSUK"
        bulgular = []

        # RAM katmanındaki nesneler için güvenlik kontrollerini yürütüyoruz
        if katman == "RAM":
            # Eğer hassas veri şifrelenmemişse kritik bir zafiyet işaretlenir
            if not is_encrypted:
                bulgular.append("Hassas veri RAM içerisinde açık metin (plaintext) olarak tutuluyor.")
                risk_level = "YUKSEK"
            # Eğer mlock kullanılmamışsa ve işletim sistemi takas yaparsa pagefile'a düşer
            if not is_mlocked:
                bulgular.append("Bellek sayfası kilitlenmemiş (mlock/VirtualLock yok); Swap/Pagefile sızıntı riski mevcut.")
                if risk_level != "KRITIK":
                    risk_level = "YUKSEK"
            # Eğer bellek sadece serbest bırakılmış (free) ancak sıfırlanmamışsa veri kalıntısı kalır
            if not is_zeroed or wipe_method != "secure_zero_memory":
                bulgular.append("Bellek serbest bırakılırken sıfırlanmamış (SecureZeroMemory eksik); Use-After-Free ve bellek dökümü sızıntısı!")
                risk_level = "KRITIK"

        # Depolama katmanındaki nesneler için kontroller
        elif katman == "Depolama":
            # Dosya güvenli silinmediyse kalıntı riski yüksektir
            safe_delete = memory_object.get("dosya_guvenli_silindi", False)
            if not safe_delete:
                bulgular.append("Geçici dosya dosya sisteminden güvenli silinmemiş (shred/srm uygulanmamış); Adli bilişimle geri getirilebilir.")
                risk_level = "YUKSEK"
            if not is_encrypted:
                bulgular.append("Disk üzerindeki dosya şifrelenmemiş (FDE/BitLocker veya dosya seviyesi şifreleme yok).")
                risk_level = "KRITIK"

        # CPU katmanındaki nesneler için kontroller
        elif katman == "CPU":
            # Çekirdek dökümü veya bağlam değişimi riskleri
            bulgular.append("İşlemci yazmaçlarında (Registers) işlenen veriler işlem çökmesi durumunda core dump içerisine sızabilir.")
            risk_level = "ORTA"

        # Değerlendirme sonucunu yapılandırılmış bir sözlük olarak döndürüyoruz
        return {
            "nesne_id": obj_id,
            "katman": katman,
            "risk_seviyesi": risk_level,
            "bulgular": bulgular,
            "guvenli_mi": (risk_level == "DUSUK")
        }

    def audit_hardware_security(self, hardware_data, baseline_data):
        """
        Sistem donanım bileşenlerini (CPU, RAM, Depolama) güvenlik taban çizgisi
        (CIS Benchmarks, NIST SP 800-88 ve SP 800-53) kurallarına göre denetler.
        """
        # Denetim kurallarını taban çizgisi sözlüğünden alıyoruz
        kurallar = baseline_data.get("guvenlik_denetim_kurallari", [])
        # Donanım bileşenleri sözlüğünü alıyoruz
        bilesenler = hardware_data.get("donanim_bilesenleri", {})

        # Başarılı ve başarısız denetim sonuç listelerini başlatıyoruz
        gecen_kurallar = []
        kalan_kurallar = []

        # Her bir güvenlik kuralını tek tek inceliyoruz
        for kural in kurallar:
            kural_id = kural.get("kural_id")
            katman = kural.get("katman")
            kriter = kural.get("kriter")
            beklenen = kural.get("beklenen_deger")
            seviye = kural.get("seviye", "ORTA")
            hata_mesaji = kural.get("hata_mesaji", "Kural ihlali")

            # İlgili donanım katmanının verisini çekiyoruz
            katman_verisi = {}
            if katman == "CPU":
                katman_verisi = bilesenler.get("cpu", {}).get("koruma_ozellikleri", {})
            elif katman == "RAM":
                katman_verisi = bilesenler.get("ram", {})
            elif katman == "Depolama":
                depolama_koku = bilesenler.get("depolama", {})
                katman_verisi = {**depolama_koku, **depolama_koku.get("sayfalama_ve_takas", {})}

            # Mevcut sistem değerini okuyoruz
            mevcut_deger = katman_verisi.get(kriter, None)

            # Kuralın karşılanıp karşılanmadığını sınıyoruz
            if mevcut_deger == beklenen:
                gecen_kurallar.append({
                    "kural_id": kural_id,
                    "katman": katman,
                    "kriter": kriter,
                    "durum": "UYGUN",
                    "deger": mevcut_deger
                })
            else:
                kalan_kurallar.append({
                    "kural_id": kural_id,
                    "katman": katman,
                    "kriter": kriter,
                    "durum": "IHLAL",
                    "beklenen": beklenen,
                    "mevcut": mevcut_deger,
                    "seviye": seviye,
                    "hata_mesaji": hata_mesaji
                })

        # Toplam kural sayısını hesaplıyoruz
        toplam = len(kurallar)
        # Uyumluluk skorunu yüzde olarak hesaplıyoruz
        uyumluluk_orani = round((len(gecen_kurallar) / toplam * 100), 2) if toplam > 0 else 0.0

        # Denetim özetini döndürüyoruz
        return {
            "toplam_kural_sayisi": toplam,
            "uygun_kural_sayisi": len(gecen_kurallar),
            "ihlal_sayisi": len(kalan_kurallar),
            "uyumluluk_orani_yuzde": uyumluluk_orani,
            "gecen_kurallar": gecen_kurallar,
            "ihlal_edilen_kurallar": kalan_kurallar
        }

    def simulate_memory_lifecycle(self, secret_bytes, use_secure_zero=True):
        """
        RAM üzerinde bir hassas verinin yaşam döngüsünü (tahsis, kullanım, serbest bırakma)
        ve serbest bırakma anında 'güvenli sıfırlama' (zeroing) ile 'basit bırakma' (plain free)
        arasındaki adli bilişimsel kalıntı farkını simüle eder.
        """
        # Verilen bayt dizisinin uzunluğunu tespit ediyoruz
        uzunluk = len(secret_bytes)
        # Bellek bloğunu temsil eden değiştirilebilir bytearray nesnesi tahsis ediyoruz
        allocated_buffer = bytearray(secret_bytes)

        # Bellek tahsis edildiğindeki durumu kaydediyoruz
        tahsis_anindaki_veri = bytes(allocated_buffer)

        # Serbest bırakma aşamasını simüle ediyoruz
        if use_secure_zero:
            # Güvenli temizleme: Her bir bayt 0x00 ile ezilir (SecureZeroMemory yaklaşımı)
            for i in range(uzunluk):
                allocated_buffer[i] = 0x00
            temizleme_turu = "SECURE_ZERO_MEMORY"
        else:
            # Güvensiz temizleme: Tampon içeriğine dokunulmaz, sadece işaretçi serbest bırakılır
            temizleme_turu = "PLAIN_FREE_UNTOUCHED"

        # Serbest bırakma sonrasında bellekte kalan kalıntıyı okuyoruz
        serbest_sonrasi_kalinti = bytes(allocated_buffer)

        # Kalıntının sıfırlanıp sıfırlanmadığını test ediyoruz
        tamamen_temiz_mi = (serbest_sonrasi_kalinti == b"\x00" * uzunluk)

        # Simülasyon raporunu yapılandırılmış sözlük olarak döndürüyoruz
        return {
            "tampon_boyutu_byte": uzunluk,
            "temizleme_turu": temizleme_turu,
            "tahsis_verisi_hex": tahsis_anindaki_veri.hex(),
            "kalinti_verisi_hex": serbest_sonrasi_kalinti.hex(),
            "veri_tamamen_silindi_mi": tamamen_temiz_mi,
            "adli_kalinti_riski": "YOK" if tamamen_temiz_mi else "KRITIK (Hassas Veri Bellekte Duruyor)"
        }

    def generate_full_audit(self, sample_filepath, baseline_filepath):
        """
        Hem donanım güvenlik taban çizgisini hem de bellek/depolama nesneleri kalıntı risklerini
        bütünleştirerek kapsamlı bir kurumsal denetim raporu üretir.
        """
        # Örnek donanım verisini dosyadan yüklüyoruz
        hardware_data = self.load_json_file(sample_filepath)
        # Güvenlik taban çizgisi kurallarını dosyadan yüklüyoruz
        baseline_data = self.load_json_file(baseline_filepath)

        # Donanım taban çizgisi uyumluluk denetimini gerçekleştiriyoruz
        hardware_audit = self.audit_hardware_security(hardware_data, baseline_data)

        # Bellek ve depolama nesnelerinin kalıntı değerlendirmesini yapıyoruz
        nesneler = hardware_data.get("islem_ve_bellek_nesneleri", [])
        nesne_degerlendirmeleri = [self.evaluate_data_remanence(n) for n in nesneler]

        # Toplam nesne sayısı ve yüksek/kritik riskli nesne sayısını hesaplıyoruz
        kritik_nesneler = [n for n in nesne_degerlendirmeleri if n["risk_seviyesi"] in ["YUKSEK", "KRITIK"]]

        # Yaşam döngüsü simülasyonunu hem güvenli hem güvensiz senaryoyla çalıştırıyoruz
        ornek_parola = b"SuperGizliKurumsalParola2026!"
        guvenli_sim = self.simulate_memory_lifecycle(ornek_parola, use_secure_zero=True)
        guvensiz_sim = self.simulate_memory_lifecycle(ornek_parola, use_secure_zero=False)

        # Bütünleştirilmiş raporu oluşturuyoruz
        full_report = {
            "denetim_zamani": datetime.datetime.now().isoformat(),
            "denetim_motoru_surumu": self.version,
            "donanim_taban_cizgisi_ozeti": hardware_audit,
            "incelenen_nesne_sayisi": len(nesneler),
            "riskli_nesne_sayisi": len(kritik_nesneler),
            "nesne_kalinti_analizleri": nesne_degerlendirmeleri,
            "bellek_yasam_dongusu_deneyi": {
                "guvenli_senaryo": guvenli_sim,
                "guvensiz_senaryo": guvensiz_sim
            },
            "genel_sonuc": "IHLAL_VAR" if (hardware_audit["ihlal_sayisi"] > 0 or len(kritik_nesneler) > 0) else "TEMIZ"
        }
        # Nihai raporu döndürüyoruz
        return full_report


def main():
    """
    Komut satırı arayüzü giriş noktası.
    """
    # Argüman ayrıştırıcıyı yapılandırıyoruz
    parser = argparse.ArgumentParser(
        description="GÜN 016: CPU, RAM ve Depolama Donanım Sınırları ve Veri Kalıntısı Güvenlik Analizörü"
    )
    # Canlı sistem envanterini toplama parametresi
    parser.add_argument(
        "--live",
        action="store_true",
        help="Mevcut yerel sistemin CPU, RAM ve Depolama donanım envanterini canlı olarak çıkarır."
    )
    # Örnek donanım verisi yolu parametresi
    parser.add_argument(
        "--sample",
        type=str,
        default="ornek_veri/hardware_boundary_sample.json",
        help="İncelenecek örnek donanım ve bellek nesneleri JSON dosyası."
    )
    # Güvenlik taban çizgisi yolu parametresi
    parser.add_argument(
        "--baseline",
        type=str,
        default="ornek_veri/hardware_security_baseline.json",
        help="Güvenlik denetim kuralları JSON dosyası."
    )
    # Çıktıyı JSON olarak verme seçeneği
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON biçiminde yazdırır."
    )

    # Argümanları ayrıştırıyoruz
    args = parser.parse_args()

    # Analizör nesnemizi başlatıyoruz
    auditor = SystemHardwareBoundaryAuditor()

    # Eğer canlı envanter talep edilmişse
    if args.live:
        # Canlı envanteri çekiyoruz
        live_data = auditor.get_live_hardware_inventory()
        # Ekrana biçimli JSON olarak yazdırıyoruz
        print(json.dumps(live_data, indent=2, ensure_ascii=False))
        return

    # Örnek dosya ve taban çizgisiyle tam denetim yürütüyoruz
    try:
        rapor = auditor.generate_full_audit(args.sample, args.baseline)
        if args.json:
            print(json.dumps(rapor, indent=2, ensure_ascii=False))
        else:
            print("=" * 72)
            print("GÜN 016: CPU, RAM VE DEPOLAMA GÜVENLİK DENETİMİ RAPORU")
            print("=" * 72)
            print(f"Denetim Zamanı : {rapor['denetim_zamani']}")
            print(f"Genel Sonuç    : {rapor['genel_sonuc']}")
            print(f"Uyumluluk Oranı: %{rapor['donanim_taban_cizgisi_ozeti']['uyumluluk_orani_yuzde']}")
            print(f"İhlal Sayısı   : {rapor['donanim_taban_cizgisi_ozeti']['ihlal_sayisi']}")
            print(f"Kritik Nesneler: {rapor['riskli_nesne_sayisi']} adet / {rapor['incelenen_nesne_sayisi']} toplam")
            print("-" * 72)
            print("DONANIM TABAN ÇİZGİSİ İHLALLERİ:")
            for ihlal in rapor["donanim_taban_cizgisi_ozeti"]["ihlal_edilen_kurallar"]:
                print(f"  [{ihlal['seviye']}] {ihlal['kural_id']} ({ihlal['katman']}): {ihlal['hata_mesaji']}")
            print("-" * 72)
            print("BELLEK VE DEPOLAMA NESNESİ RİSKLERİ:")
            for nesne in rapor["nesne_kalinti_analizleri"]:
                print(f"  [{nesne['risk_seviyesi']}] {nesne['nesne_id']} ({nesne['katman']}):")
                for b in nesne["bulgular"]:
                    print(f"    - {b}")
            print("=" * 72)
    except Exception as e:
        print(f"HATA: Denetim çalıştırılırken sorun oluştu: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
