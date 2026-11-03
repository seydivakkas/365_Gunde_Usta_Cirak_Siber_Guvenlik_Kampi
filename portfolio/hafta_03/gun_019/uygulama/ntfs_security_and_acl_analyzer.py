# -*- coding: utf-8 -*-
"""
GÜN 019: Windows Dosya Sistemi, NTFS ACL ve Dosya Bütünlüğü Güvenlik Analizörü
Aşama 02: Sistem, Bellek ve Düşük Seviyeli Güvenlik (Hafta 03, Gün 19)

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
# Windows ortamında icacls komutunu güvenle çalıştırmak için subprocess modülü
import subprocess
# İşletim sistemi adını öğrenmek için platform modülü
import platform


class NtfsSecurityAndAclAnalyzer:
    """
    NTFS dosya sistemi erişim denetim listelerini (DACL/SACL),
    Alternatif Veri Akışlarını (ADS - Alternate Data Streams) ve
    Dosya Uzantısı ile Sihirli Baytlar (Magic Bytes) uyumsuzluğunu
    denetleyen güvenlik motoru.
    """

    def __init__(self):
        # Analizör motorunun sürüm bilgisini başlatıyoruz
        self.version = "1.0.0"

    def get_live_directory_acls(self, target_path="."):
        """
        Belirtilen yerel dizinin canlı NTFS erişim izinlerini
        Windows icacls komutu ile sorgular ve yapılandırılmış olarak döndürür.
        """
        # Hedef yolun mutlak dosya yolu karşılığını alıyoruz
        abs_path = os.path.abspath(target_path)
        # İşletim sistemini tespit ediyoruz
        os_name = platform.system()
        # Ham çıktı satırlarını tutacak listeyi başlatıyoruz
        acl_entries = []

        # Windows platformunda yerel icacls aracını çağırıyoruz
        if os_name == "Windows":
            try:
                # icacls hedef_yol komutunu çalıştırıyoruz
                cmd = ["icacls", abs_path]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
                # Çıktı satırlarını ayıklıyoruz
                for line in res.stdout.splitlines():
                    temiz_satir = line.strip()
                    # Anlamlı ACL satırlarını listeye ekliyoruz
                    if temiz_satir and not temiz_satir.startswith("Successfully") and not temiz_satir.startswith("Başarıyla"):
                        acl_entries.append(temiz_satir)
            except Exception as e:
                acl_entries.append(f"icacls sorgu hatası: {e}")
        else:
            # POSIX sistemlerde standart izinleri okuyoruz
            try:
                stat_info = os.stat(abs_path)
                acl_entries.append(f"POSIX Modu: {oct(stat_info.st_mode)}")
            except Exception as e:
                acl_entries.append(f"POSIX stat hatası: {e}")

        # Eğer sorgudan sonuç alınamadıysa varsayılan güvenli kayıt giriyoruz
        if not acl_entries:
            acl_entries.append(f"{abs_path} NT AUTHORITY\\SYSTEM:(F) BUILTIN\\Administrators:(F)")

        # Yapılandırılmış canlı ACL envanterini döndürüyoruz
        return {
            "sorgu_zamani": datetime.datetime.now().isoformat(),
            "hedef_yol": abs_path,
            "isletim_sistemi": os_name,
            "ham_izin_kayitlari": acl_entries
        }

    def load_json_file(self, filepath):
        """
        Belirtilen JSON dosyasını UTF-8 kodlamasıyla güvenli olarak yükler.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def compare_acl_diff(self, before_acls, after_acls):
        """
        Bir test klasörünün önceki ve sonraki izin durumunu karşılaştırır;
        kaldırılan zayıf izinleri, eklenen sıkı kısıtlamaları ve güvenlik
        farkını (Diff) belgeler (G019-SC2 laboratuvar gereksinimi).
        """
        # Önceki ve sonraki izinleri küme haline getirmek için anahtar dizgileri üretiyoruz
        onceki_set = {f"{e.get('kullanici_grup')}:{e.get('izin')}:{e.get('tip')}" for e in before_acls}
        sonraki_set = {f"{e.get('kullanici_grup')}:{e.get('izin')}:{e.get('tip')}" for e in after_acls}

        # Kaldırılan izinler (önce var olup sonra olmayanlar)
        kaldirilanlar = list(onceki_set - sonraki_set)
        # Yeni eklenen izinler (sonra var olup önce olmayanlar)
        eklenenler = list(sonraki_set - onceki_set)

        # Güvenlik iyileştirmesi değerlendirmesi
        iyilestirme_notlari = []
        for k in kaldirilanlar:
            if "Everyone:FullControl" in k:
                iyilestirme_notlari.append("KRİTİK BAŞARI: 'Everyone' grubunun FullControl tam denetim izni başarıyla kaldırıldı!")
            elif "Write" in k:
                iyilestirme_notlari.append(f"Geniş yazma izni iptal edildi: {k}")

        for e in eklenenler:
            if ":Deny" in e:
                iyilestirme_notlari.append(f"Açıkça Reddetme (Explicit Deny) kuralı eklendi: {e}")
            elif "Administrators" in e or "SYSTEM" in e:
                iyilestirme_notlari.append(f"Yetkili yönetim grubu eklendi: {e}")

        # Fark analizi özetini döndürüyoruz
        return {
            "onceki_izin_sayisi": len(before_acls),
            "sonraki_izin_sayisi": len(after_acls),
            "kaldirilan_izinler": kaldirilanlar,
            "yeni_eklenen_izinler": eklenenler,
            "guvenlik_iyilestirmesi_var_mi": len(iyilestirme_notlari) > 0,
            "iyilestirme_notlari": iyilestirme_notlari
        }

    def inspect_magic_bytes_and_extension(self, filename, header_hex, baseline_signatures):
        """
        Dosyanın uzantısı ile dosya başlığındaki sihirli baytları (Magic Bytes)
        karşılaştırarak dosya maskeleme (Extension Spoofing) girişimlerini tespit eder.
        """
        # Dosya adından uzantıyı küçük harfe çevirerek ayrıştırıyoruz
        _, ext = os.path.splitext(filename.lower())
        # Başlık hex verisini küçük harfe çeviriyoruz
        header = header_hex.lower()

        # Sihirli baytlara göre gerçek dosya türünü tespit ediyoruz
        gercek_tur = "Bilinmeyen İkili/Metin Türü"
        uyumlu_uzantilar = []

        for tur_kodu, tur_bilgi in baseline_signatures.items():
            hex_baslangic = tur_bilgi.get("hex_baslangic", "").lower()
            if header.startswith(hex_baslangic):
                gercek_tur = tur_bilgi.get("aciklama", tur_kodu)
                uyumlu_uzantilar = [u.lower() for u in tur_bilgi.get("gecerli_uzantilar", [])]
                break

        # Uzantı ile sihirli baytlar uyuşuyor mu kontrol ediyoruz
        uzanti_uyusuyor_mu = ext in uyumlu_uzantilar if uyumlu_uzantilar else True

        # Eğer dosya gerçekte PE Executable (4D 5A) ise ve uzantısı .pdf/.txt/.jpg yapılmışsa kritik ihlaldir
        kritik_maskeleme = False
        if header.startswith("4d5a") and ext not in [".exe", ".dll", ".sys", ".scr"]:
            kritik_maskeleme = True

        return {
            "dosya_adi": filename,
            "gorunen_uzanti": ext,
            "sihirli_bayt_hex": header,
            "gercek_dosya_turu": gercek_tur,
            "uyumlu_uzantilar": uyumlu_uzantilar,
            "uzanti_ve_icerik_tutarlı_mı": uzanti_uyusuyor_mu,
            "kritik_maskeleme_var_mi": kritik_maskeleme,
            "guvenlik_durumu": "KRITIK_MASKELEME_PE_SPOOFING" if kritik_maskeleme else (
                "GECERLI_TUTARLI" if uzanti_uyusuyor_mu else "UYUMSUZ_UZANTI_SUPHELI"
            )
        }

    def inspect_alternate_data_streams(self, ads_list):
        """
        NTFS Alternatif Veri Akışlarını (ADS) analiz eder.
        Zararlı kod (PowerShell, VBScript, EXE) saklama girişimlerini ve Zone.Identifier akışını ayıklar.
        """
        bulgular = []
        gizli_zararli_sayisi = 0

        for ads in ads_list:
            akis_adi = ads.get("akis_adi", "")
            boyut = ads.get("akis_boyut_byte", 0)

            # Zone.Identifier meşru bir Windows güvenlik etiketidir (Mark-of-the-Web)
            if akis_adi.lower() == "zone.identifier":
                bulgular.append({
                    "akis_adi": akis_adi,
                    "boyut_byte": boyut,
                    "tur": "Mark-of-the-Web (ZoneId Etiketi)",
                    "risk_seviyesi": "BILGI",
                    "aciklama": "Dosyanın internetten indirildiğini gösteren meşru NTFS metaveri akışı."
                })
            elif any(akis_adi.lower().endswith(ext) for ext in [".ps1", ".vbs", ".exe", ".dll", ".bat"]):
                gizli_zararli_sayisi += 1
                bulgular.append({
                    "akis_adi": akis_adi,
                    "boyut_byte": boyut,
                    "tur": "Gizli Yürütülebilir/Betiği Akışı (Executable ADS)",
                    "risk_seviyesi": "KRITIK",
                    "aciklama": "Dosya içine gizlenmiş çalıştırılabilir kod tespit edildi (MITRE T1564.004)!"
                })
            else:
                bulgular.append({
                    "akis_adi": akis_adi,
                    "boyut_byte": boyut,
                    "tur": "Bilinmeyen Veri Akışı",
                    "risk_seviyesi": "ORTA",
                    "aciklama": "Varsayılan adsız akış dışında ek veri akışı."
                })

        return {
            "toplam_ads_sayisi": len(ads_list),
            "tehlikeli_ads_sayisi": gizli_zararli_sayisi,
            "ads_detaylari": bulgular
        }

    def audit_ntfs_file_security(self, file_dict, baseline_dict):
        """
        Tek bir dosyanın uzantı/sihirli bayt uyumunu, ADS akışlarını
        ve DACL erişim izinlerini bütünleşik olarak denetler.
        """
        dosya_adi = file_dict.get("dosya_adi", "isimsiz")
        header_hex = file_dict.get("sihirli_baytlar_hex", "")
        ads_akislari = file_dict.get("ads_akislari", [])
        acl = file_dict.get("acl_izinleri", {})
        signatures = baseline_dict.get("bilinen_sihirli_baytlar", {})

        # 1. Sihirli bayt analizi
        magic_res = self.inspect_magic_bytes_and_extension(dosya_adi, header_hex, signatures)

        # 2. ADS analizi
        ads_res = self.inspect_alternate_data_streams(ads_akislari)

        # 3. DACL analizi (Everyone FullControl kontrolü)
        has_everyone_fullcontrol = False
        for ace in acl.get("dacl", []):
            if ace.get("kullanici_grup", "").lower() == "everyone" and ace.get("izin", "") == "FullControl":
                has_everyone_fullcontrol = True
                break

        bulgular = []
        risk_seviyesi = "DUSUK"

        if magic_res["kritik_maskeleme_var_mi"]:
            bulgular.append("Dosya uzantısı PDF/TXT gibi gösterilmiş ancak içeriği Windows PE (.EXE) çalıştırılabilir kodudur!")
            risk_seviyesi = "KRITIK"
        elif not magic_res["uzanti_ve_icerik_tutarlı_mı"]:
            bulgular.append(f"Uzantı ({magic_res['gorunen_uzanti']}) ile içerik ({magic_res['gercek_dosya_turu']}) uyuşmuyor.")
            if risk_seviyesi != "KRITIK":
                risk_seviyesi = "YUKSEK"

        if ads_res["tehlikeli_ads_sayisi"] > 0:
            bulgular.append("Dosyada gizlenmiş tehlikeli Alternatif Veri Akışı (ADS) tespit edildi!")
            risk_seviyesi = "KRITIK"

        if has_everyone_fullcontrol:
            bulgular.append("DACL izinlerinde 'Everyone' grubuna FullControl tam yetki tanımlanmış (Zayıf Erişim Kontrolü)!")
            risk_seviyesi = "KRITIK"

        return {
            "dosya_adi": dosya_adi,
            "risk_seviyesi": risk_seviyesi,
            "zafiyet_var_mi": (risk_seviyesi in ["YUKSEK", "KRITIK"]),
            "bulgular": bulgular,
            "sihirli_bayt_analizi": magic_res,
            "ads_analizi": ads_res
        }

    def generate_full_audit(self, sample_filepath, baseline_filepath):
        """
        Tüm dosya analizlerini, ACL önce/sonra fark deneyini ve canlı sistem
        izinlerini birleştirerek kurumsal denetim raporu üretir.
        """
        sample_data = self.load_json_file(sample_filepath)
        baseline_data = self.load_json_file(baseline_filepath)

        # 1. Canlı sistem izinleri
        live_acls = self.get_live_directory_acls(".")

        # 2. Örnek dosyaların denetimi
        dosyalar = sample_data.get("ornek_dosyalar", [])
        dosya_denetimleri = [self.audit_ntfs_file_security(d, baseline_data) for d in dosyalar]
        zafiyetli_dosyalar = [d for d in dosya_denetimleri if d["zafiyet_var_mi"]]

        # 3. Klasör ACL Önce/Sonra Fark Deneyi (G019-SC2)
        acl_senaryosu = sample_data.get("klasor_acl_once_sonra_senaryosu", {})
        acl_diff_res = self.compare_acl_diff(
            acl_senaryosu.get("onceki_izinler", []),
            acl_senaryosu.get("sonraki_izinler", [])
        )

        full_report = {
            "denetim_zamani": datetime.datetime.now().isoformat(),
            "denetim_motoru_surumu": self.version,
            "canli_dizin_izinleri": live_acls,
            "incelenen_dosya_sayisi": len(dosyalar),
            "zafiyetli_dosya_sayisi": len(zafiyetli_dosyalar),
            "dosya_denetim_sonuclari": dosya_denetimleri,
            "klasor_acl_once_sonra_fark_analizi": {
                "klasor": acl_senaryosu.get("klasor_adi"),
                "diff_sonucu": acl_diff_res
            },
            "genel_sonuc": "IHLAL_VAR" if len(zafiyetli_dosyalar) > 0 else "TEMIZ"
        }

        return full_report


def main():
    """
    Komut satırı arayüzü ana giriş noktası.
    """
    parser = argparse.ArgumentParser(
        description="GÜN 019: Windows Dosya Sistemi, NTFS ACL ve Dosya Bütünlüğü Güvenlik Analizörü"
    )
    parser.add_argument(
        "--live",
        type=str,
        default=None,
        nargs="?",
        const=".",
        help="Belirtilen veya mevcut dizinin canlı NTFS ACL izinlerini sorgular."
    )
    parser.add_argument(
        "--sample",
        type=str,
        default="ornek_veri/ntfs_file_samples.json",
        help="İncelenecek dosya ve ACL örnek verisi yolu."
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default="ornek_veri/ntfs_security_baseline.json",
        help="NTFS güvenlik taban çizgisi kuralları dosyası yolu."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Çıktıyı yapılandırılmış JSON olarak üretir."
    )

    args = parser.parse_args()
    analyzer = NtfsSecurityAndAclAnalyzer()

    if args.live is not None:
        live_data = analyzer.get_live_directory_acls(args.live)
        print(json.dumps(live_data, indent=2, ensure_ascii=False))
        return

    try:
        rapor = analyzer.generate_full_audit(args.sample, args.baseline)
        if args.json:
            print(json.dumps(rapor, indent=2, ensure_ascii=False))
        else:
            print("=" * 72)
            print("GÜN 019: WINDOWS DOSYA SİSTEMİ VE NTFS GÜVENLİK DENETİMİ")
            print("=" * 72)
            print(f"Denetim Zamanı : {rapor['denetim_zamani']}")
            print(f"Genel Sonuç    : {rapor['genel_sonuc']}")
            print(f"İncelenen Dosya: {rapor['incelenen_dosya_sayisi']}")
            print(f"Zafiyetli Dosya: {rapor['zafiyetli_dosya_sayisi']} adet riskli dosya tespit edildi!")
            print("-" * 72)
            print("CANLI SİSTEM DİZİN İZİNLERİ (icacls):")
            for line in rapor["canli_dizin_izinleri"]["ham_izin_kayitlari"][:5]:
                print(f"  {line}")
            print("-" * 72)
            print("DOSYA BÜTÜNLÜĞÜ VE SİHİRLİ BAYT BULGULARI:")
            for d in rapor["dosya_denetim_sonuclari"]:
                print(f"  [{d['risk_seviyesi']}] {d['dosya_adi']}:")
                for b in d["bulgular"]:
                    print(f"    - {b}")
            print("-" * 72)
            print("KLASÖR ACL ÖNCE/SONRA FARK ANALİZİ (G019-SC2):")
            diff = rapor["klasor_acl_once_sonra_fark_analizi"]["diff_sonucu"]
            print(f"  Önceki İzin Sayısı: {diff['onceki_izin_sayisi']} -> Sonraki: {diff['sonraki_izin_sayisi']}")
            for n in diff["iyilestirme_notlari"]:
                print(f"  [+] {n}")
            print("=" * 72)
    except Exception as e:
        print(f"HATA: Denetim yürütülürken hata oluştu: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
