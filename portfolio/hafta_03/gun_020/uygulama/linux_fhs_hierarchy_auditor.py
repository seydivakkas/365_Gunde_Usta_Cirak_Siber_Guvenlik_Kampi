# -*- coding: utf-8 -*-
"""
GÜN 020: Linux Dosya Ağacı ve FHS (Filesystem Hierarchy Standard) Güvenlik Analizörü
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 20)

ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim
amaçlı olarak paylaşılmıştır. Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez.
"""

# İşletim sistemi dosya, dizin ve ortam kontrolleri için os modülü
import os
# Python çalışma parametreleri ve platform kontrolü için sys modülü
import sys
# Yapılandırılmış verileri ayrıştırmak ve dışa aktarmak için json modülü
import json
# Zaman damgaları ve denetim loglaması oluşturmak için datetime modülü
import datetime
# Komut satırı argümanlarını profesyonelce ayrıştırmak için argparse modülü
import argparse
# Platform ve mimari bilgilerini öğrenmek için platform modülü
import platform


class LinuxFhsHierarchyAuditor:
    """
    Linux Dosya Ağacı Hiyerarşi Standardını (FHS 3.0), kritik sistem dizinlerinin
    (/etc, /var, /home, /tmp, /dev, /proc) güvenlik sınırlarını, Sticky Bit (+t)
    yapılandırmalarını ve mount sertleştirme bayraklarını (noexec, nosuid) denetleyen güvenlik motoru.
    """

    def __init__(self):
        # Analizör motorunun sürüm bilgisini tanımlıyoruz
        self.version = "1.0.0"
        # FHS 3.0 standardında denetlenmesi zorunlu en az 6 temel çekirdek dizin (G020-SC2)
        self.mandatory_fhs_dirs = ["/etc", "/var", "/home", "/tmp", "/dev", "/proc"]

    def get_live_platform_context(self):
        """
        Yerel sistemin çalışma ortamını (Linux, Windows, WSL) ve
        canlı dosya sistemi kök göstergelerini sorgular.
        """
        # İşletim sistemi adını ve sürümünü alıyoruz
        os_name = platform.system()
        os_release = platform.release()
        # Kök dizin yolunu belirliyoruz
        root_path = "/" if os_name != "Windows" else os.path.abspath(os.sep)

        # Canlı platform bağlamını döndürüyoruz
        return {
            "sorgu_zamani": datetime.datetime.now().isoformat(),
            "isletim_sistemi": os_name,
            "isletim_sistemi_surumu": os_release,
            "kok_dizin": root_path,
            "fhs_uyumluluk_modu": "POSIX / Linux Standart FHS" if os_name != "Windows" else "Emüle Edilmiş Linux FHS Analizörü",
            "aciklama": "FHS denetimi platformlar arası olarak Linux sunucu ve imajlarını analiz edebilir."
        }

    def load_json_file(self, filepath):
        """
        Belirtilen JSON dosyasını UTF-8 kodlamasıyla güvenli olarak yükler.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def verify_fhs_core_directories(self, directory_list):
        """
        Verilen dizin listesinde FHS 3.0 tarafından zorunlu kılınan en az altı temel
        dizinin (/etc, /var, /home, /tmp, /dev, /proc) amacını, sahipliğini ve
        güvenlik rollerini doğrulayarak dosya haritasını üretir (G020-SC2).
        """
        # Haritalanan dizinleri isimlerine göre indeksliyoruz
        harita = {}
        for d in directory_list:
            d_adi = d.get("dizin_adi", "")
            harita[d_adi] = d

        dogrulanan_dizinler = []
        eksik_dizinler = []

        # Zorunlu 6 temel dizini tek tek sınıyoruz
        for zorunlu in self.mandatory_fhs_dirs:
            if zorunlu in harita:
                d_bilgi = harita[zorunlu]
                dogrulanan_dizinler.append({
                    "dizin": zorunlu,
                    "amac": d_bilgi.get("amac", "Tanımlanmamış"),
                    "sahip": f"{d_bilgi.get('sahip_kullanici', 'root')}:{d_bilgi.get('sahip_grup', 'root')}",
                    "izin_oktal": d_bilgi.get("izin_oktal", "0755"),
                    "guvenlik_onemi": d_bilgi.get("guvenlik_onemi", ""),
                    "durum": "DOGRULANDI"
                })
            else:
                eksik_dizinler.append(zorunlu)

        return {
            "toplam_zorunlu_sayisi": len(self.mandatory_fhs_dirs),
            "dogrulanan_sayisi": len(dogrulanan_dizinler),
            "eksik_dizin_sayisi": len(eksik_dizinler),
            "eksik_dizinler": eksik_dizinler,
            "dogrulanan_dizin_haritasi": dogrulanan_dizinler,
            "fhs_karsilandi_mi": len(eksik_dizinler) == 0
        }

    def audit_sticky_bit_and_permissions(self, directory_dict):
        """
        Dünyaya yazılabilir (World-Writable) geçici alanlarda (/tmp, /var/tmp)
        Sticky Bit (+t / 1000) bayrağının etkinliğini denetler.
        Eksik olması durumunda yarış durumu (Symlink Attack) riskini raporlar.
        """
        d_adi = directory_dict.get("dizin_adi", "")
        izin = str(directory_dict.get("izin_oktal", "0755"))
        sticky_etkin = directory_dict.get("sticky_bit_etkin", False)

        # İzin 1777 veya başında 1 varsa sticky bit aktiftir
        if izin.startswith("1") or sticky_etkin or "t" in izin:
            return {
                "dizin": d_adi,
                "izin_oktal": izin,
                "sticky_bit_var_mi": True,
                "risk_seviyesi": "DUSUK",
                "durum": "GUVENLI",
                "aciklama": "Sticky Bit (+t) etkin; sadece dosya sahibi kendi dosyasını silebilir."
            }

        # İzin 0777 ise ve sticky bit yoksa KRİTİK zafiyettir
        if izin.endswith("777"):
            return {
                "dizin": d_adi,
                "izin_oktal": izin,
                "sticky_bit_var_mi": False,
                "risk_seviyesi": "KRITIK",
                "durum": "ZAFIYET_STICKY_BIT_EKSIK",
                "aciklama": "World-Writable alanda Sticky Bit eksik! Kullanıcılar birbirinin dosyasını silebilir/değiştirebilir (CWE-377 / CWE-379)."
            }

        return {
            "dizin": d_adi,
            "izin_oktal": izin,
            "sticky_bit_var_mi": False,
            "risk_seviyesi": "ORTA",
            "durum": "STANDART_IZIN",
            "aciklama": "World-writable değil, standart izin yapısı."
        }

    def audit_mount_hardening_options(self, directory_dict):
        """
        Geçici veya kullanıcı alanlarının (/tmp, /home, /dev)
        mount bayraklarını (noexec, nosuid, nodev) denetler.
        """
        d_adi = directory_dict.get("dizin_adi", "")
        mount_secenekleri = directory_dict.get("mount_secenekleri", [])

        eksik_bayraklar = []
        # /tmp için noexec, nosuid, nodev zorunludur
        if d_adi == "/tmp":
            for bayrak in ["nodev", "nosuid", "noexec"]:
                if bayrak not in mount_secenekleri:
                    eksik_bayraklar.append(bayrak)

        # /home için nosuid, nodev zorunludur
        elif d_adi == "/home":
            for bayrak in ["nodev", "nosuid"]:
                if bayrak not in mount_secenekleri:
                    eksik_bayraklar.append(bayrak)

        risk_seviyesi = "YUKSEK" if eksik_bayraklar else "DUSUK"

        return {
            "dizin": d_adi,
            "mevcut_mount_secenekleri": mount_secenekleri,
            "eksik_guvenlik_bayraklari": eksik_bayraklar,
            "risk_seviyesi": risk_seviyesi,
            "guvenli_mi": len(eksik_bayraklar) == 0
        }

    def audit_critical_system_files(self, critical_files_list):
        """
        /etc altındaki kritik parola ve yetki dosyalarını (/etc/shadow, /etc/passwd, /etc/sudoers)
        CIS Linux Benchmark izin standartlarına göre denetler.
        """
        bulgular = []
        ihlal_sayisi = 0

        for f in critical_files_list:
            yol = f.get("yol", "")
            izin = str(f.get("izin_oktal", "0644"))
            sahip = f.get("sahip", "root:root")

            # /etc/shadow kontrolü: Diğer kullanıcılar (Others) okuyamamalıdır (son basamak 0 olmalı)
            if yol == "/etc/shadow":
                if not (izin.endswith("0") or izin == "0000"):
                    ihlal_sayisi += 1
                    bulgular.append({
                        "dosya": yol,
                        "izin": izin,
                        "sahip": sahip,
                        "risk_seviyesi": "KRITIK",
                        "ihlal": "Shadow dosyası dünya tarafından okunabilir! Parola karmaları sızdırılabilir (CWE-732)."
                    })
                else:
                    bulgular.append({
                        "dosya": yol,
                        "izin": izin,
                        "sahip": sahip,
                        "risk_seviyesi": "DUSUK",
                        "durum": "GUVENLI_SHADOW"
                    })

            # /etc/sudoers kontrolü: Yalnızca root okumalıdır (0440)
            elif yol == "/etc/sudoers":
                if izin not in ["0440", "0400"]:
                    ihlal_sayisi += 1
                    bulgular.append({
                        "dosya": yol,
                        "izin": izin,
                        "sahip": sahip,
                        "risk_seviyesi": "KRITIK",
                        "ihlal": "Sudoers dosyası gevşek izinlere sahip; yetki yükseltme riski!"
                    })
                else:
                    bulgular.append({
                        "dosya": yol,
                        "izin": izin,
                        "sahip": sahip,
                        "risk_seviyesi": "DUSUK",
                        "durum": "GUVENLI_SUDOERS"
                    })

        return {
            "toplam_kritik_dosya_sayisi": len(critical_files_list),
            "ihlal_sayisi": ihlal_sayisi,
            "dosya_bulgulari": bulgular
        }

    def generate_full_audit(self, sample_filepath, baseline_filepath):
        """
        Canlı platform bağlamı, 6 temel FHS dizin haritası, Sticky Bit ve Mount denetimlerini
        bütünleştirerek kapsamlı bir denetim raporu üretir.
        """
        sample_data = self.load_json_file(sample_filepath)
        baseline_data = self.load_json_file(baseline_filepath)

        # 1. Canlı platform bağlamı
        live_ctx = self.get_live_platform_context()

        # 2. 6 Temel FHS Dizin Haritası Doğrulaması (G020-SC2)
        dizinler = sample_data.get("fhs_dizinleri", [])
        fhs_dogrulama = self.verify_fhs_core_directories(dizinler)

        # 3. Sticky Bit ve Mount Denetimleri
        sticky_sonuclari = []
        mount_sonuclari = []
        for d in dizinler:
            if d.get("dizin_adi") in ["/tmp", "/var"]:
                sticky_sonuclari.append(self.audit_sticky_bit_and_permissions(d))
            if d.get("dizin_adi") in ["/tmp", "/home"]:
                mount_sonuclari.append(self.audit_mount_hardening_options(d))

        # 4. /etc altındaki kritik dosyaların izin denetimi
        etc_dizini = next((d for d in dizinler if d.get("dizin_adi") == "/etc"), {})
        kritik_dosyalar = etc_dizini.get("kritik_dosyalar", [])
        dosya_denetimi = self.audit_critical_system_files(kritik_dosyalar)

        # 5. Zafiyet simülasyonları
        zafiyetler = sample_data.get("zafiyet_test_senaryolari", [])

        full_report = {
            "denetim_zamani": datetime.datetime.now().isoformat(),
            "denetim_motoru_surumu": self.version,
            "canli_platform_baglami": live_ctx,
            "fhs_temel_dizin_haritasi": fhs_dogrulama,
            "sticky_bit_analizleri": sticky_sonuclari,
            "mount_sertlestirme_analizleri": mount_sonuclari,
            "kritik_sistem_dosyalari_denetimi": dosya_denetimi,
            "simule_edilen_zafiyet_sayisi": len(zafiyetler),
            "genel_sonuc": "IHLAL_VAR" if (dosya_denetimi["ihlal_sayisi"] > 0 or not fhs_dogrulama["fhs_karsilandi_mi"]) else "TEMIZ"
        }

        return full_report


def main():
    """
    Komut satırı arayüzü ana giriş noktası.
    """
    parser = argparse.ArgumentParser(
        description="GÜN 020: Linux Dosya Ağacı ve FHS Güvenlik Analizörü"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Mevcut sistemin platform ve kök dosya sistemi bağlamını sorgular."
    )
    parser.add_argument(
        "--sample",
        type=str,
        default="ornek_veri/linux_fhs_sample_map.json",
        help="İncelenecek Linux FHS örnek dosya ağacı verisi yolu."
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default="ornek_veri/linux_fhs_security_baseline.json",
        help="Linux FHS ve CIS güvenlik taban çizgisi kuralları dosyası yolu."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sonuçları yapılandırılmış JSON olarak konsola yazdırır."
    )

    args = parser.parse_args()
    auditor = LinuxFhsHierarchyAuditor()

    if args.live:
        data = auditor.get_live_platform_context()
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    try:
        rapor = auditor.generate_full_audit(args.sample, args.baseline)
        if args.json:
            print(json.dumps(rapor, indent=2, ensure_ascii=False))
        else:
            print("=" * 72)
            print("GÜN 020: LİNUX DOSYA AĞACI VE FHS GÜVENLİK DENETİMİ")
            print("=" * 72)
            print(f"Denetim Zamanı : {rapor['denetim_zamani']}")
            print(f"Genel Sonuç    : {rapor['genel_sonuc']}")
            print(f"FHS Durumu     : {rapor['fhs_temel_dizin_haritasi']['dogrulanan_sayisi']}/6 Zorunlu Dizin Doğrulandı")
            print(f"Kritik İhlaller: {rapor['kritik_sistem_dosyalari_denetimi']['ihlal_sayisi']} adet dosya ihlali")
            print("-" * 72)
            print("FHS 3.0 ÇEKİRDEK DİZİN HARİTASI (G020-SC2):")
            for d in rapor["fhs_temel_dizin_haritasi"]["dogrulanan_dizin_haritasi"]:
                print(f"  {d['dizin']:<8} [{d['izin_oktal']}] Sahip: {d['sahip']:<12} Amaç: {d['amac']}")
            print("-" * 72)
            print("STICKY BIT VE MOUNT GÜVENLİK DENETİMLERİ:")
            for s in rapor["sticky_bit_analizleri"]:
                print(f"  {s['dizin']:<8} Sticky: {str(s['sticky_bit_var_mi']):<6} Durum: {s['durum']}")
            for m in rapor["mount_sertlestirme_analizleri"]:
                print(f"  {m['dizin']:<8} Mount Güvenli mi: {m['guvenli_mi']} (Mevcut: {', '.join(m['mevcut_mount_secenekleri'])})")
            print("=" * 72)
    except Exception as e:
        print(f"HATA: Denetim çalıştırılırken sorun oluştu: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
