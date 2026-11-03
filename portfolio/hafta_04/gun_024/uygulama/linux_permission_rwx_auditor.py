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
"""Linux Dosya İzinleri RWX Denetleyici ve Geri Alma Motoru.

Bu modül; POSIX standartlarındaki okuma (r=4), yazma (w=2) ve çalıştırma (x=1)
izinlerinin kullanıcı (u), grup (g) ve diğerleri (o) bazında analizi, oktal ve
sembolik dönüşümleri, umask hesaplamalarını, CWE-732 uygunsuzluklarının tespitini,
chmod işlemlerinin geriye dönük güvenli kaydını (journal) ve geri alınmasını (rollback) sağlar.
"""

# Standart kütüphane modülleri sisteme dahil edilir
import argparse  # Komut satırı argümanlarını ayrıştırmak için standart kütüphane
import fnmatch  # Dosya yolu joker karakter (wildcard) eşleşmeleri için kullanılır
import json  # JSON veri formatı serileştirme ve deserializasyon işlemleri için
import os  # İşletim sistemi dosya yolu ve dizin operasyonları için kullanılır
import stat  # Dosya izin bit maskelerini sembolik olarak sorgulamak için
import sys  # Sistem bazlı akışlar, standart çıktı ve çıkış kodları için kullanılır
import time  # Zaman damgaları ve denetim kayıtları zamanı oluşturmak için


def parse_octal_mode(mode_val):
    """Verilen int veya string mod değerini standart tamsayıya dönüştürür.
    
    Örnek: '0755', '755', 755 (string veya integer) -> 0o755 int değeri.
    """
    # Girdi tipi string ise oktal tabanda tamsayıya çevrilir
    if isinstance(mode_val, str):
        # Baştaki olası '0o' veya boşluklar temizlenir
        temiz_str = mode_val.strip()
        # Eğer string '0o' ile başlamıyorsa oktal taban (8) olarak int'e çevrilir
        return int(temiz_str, 8)
    # Girdi zaten bir tamsayı ise doğrudan int olarak değerlendirilir
    elif isinstance(mode_val, int):
        # Tamsayı doğrudan döndürülür
        return mode_val
    # Geçersiz tipte bir girdi gelirse hata fırlatılır
    else:
        # Tür hatası nesnesi üretilir
        raise TypeError(f"Geçersiz mod tipi: {type(mode_val)}")


def octal_to_symbolic(mode_val, is_directory=False):
    """Oktal izin değerini 10 karakterlik standart POSIX sembolik gösterimine çevirir.
    
    Örnek: 0o755 -> '-rwxr-xr-x', 0o1777 (dizin) -> 'drwxrwxrwt'
    """
    # Girdi oktal tamsayıya dönüştürülür
    mode_int = parse_octal_mode(mode_val)
    # Dizin ise 'd', normal dosya ise '-' ön eki belirlenir
    lead_char = "d" if is_directory else "-"
    
    # Özel izin bitleri ayrıştırılır (SUID: 0o4000, SGID: 0o2000, Sticky: 0o1000)
    suid = bool(mode_int & 0o4000)  # SUID biti aktif mi kontrolü
    sgid = bool(mode_int & 0o2000)  # SGID biti aktif mi kontrolü
    sticky = bool(mode_int & 0o1000)  # Sticky (yapışkan) biti kontrolü

    # Sahip (User) izinleri: Okuma (4), Yazma (2), Çalıştırma (1)
    u_r = "r" if (mode_int & 0o0400) else "-"  # Kullanıcı okuma izni
    u_w = "w" if (mode_int & 0o0200) else "-"  # Kullanıcı yazma izni
    # SUID biti varsa çalıştırma iznine göre 's' veya 'S' yazılır
    if suid:
        # Eğer çalıştırma biti de varsa küçük 's', yoksa büyük 'S'
        u_x = "s" if (mode_int & 0o0100) else "S"
    else:
        # Normal çalıştırma kontrolü
        u_x = "x" if (mode_int & 0o0100) else "-"

    # Grup (Group) izinleri: Okuma (4), Yazma (2), Çalıştırma (1)
    g_r = "r" if (mode_int & 0o0040) else "-"  # Grup okuma izni
    g_w = "w" if (mode_int & 0o0020) else "-"  # Grup yazma izni
    # SGID biti varsa çalıştırma iznine göre 's' veya 'S' yazılır
    if sgid:
        # Eğer grupta çalıştırma biti varsa küçük 's', yoksa büyük 'S'
        g_x = "s" if (mode_int & 0o0010) else "S"
    else:
        # Normal çalıştırma kontrolü
        g_x = "x" if (mode_int & 0o0010) else "-"

    # Diğerleri (Others) izinleri: Okuma (4), Yazma (2), Çalıştırma (1)
    o_r = "r" if (mode_int & 0o0004) else "-"  # Diğerleri okuma izni
    o_w = "w" if (mode_int & 0o0002) else "-"  # Diğerleri yazma izni
    # Sticky bit varsa çalıştırma iznine göre 't' veya 'T' yazılır
    if sticky:
        # Eğer diğerlerinde çalıştırma biti varsa küçük 't', yoksa büyük 'T'
        o_x = "t" if (mode_int & 0o0001) else "T"
    else:
        # Normal çalıştırma kontrolü
        o_x = "x" if (mode_int & 0o0001) else "-"

    # 10 karakterlik sembolik metin birleştirilir ve döndürülür
    return f"{lead_char}{u_r}{u_w}{u_x}{g_r}{g_w}{g_x}{o_r}{o_w}{o_x}"


def symbolic_to_octal(symbolic_str):
    """Standart 9 veya 10 karakterlik sembolik gösterimi oktal stringe çevirir.
    
    Örnek: 'rwxr-xr-x' -> '0755', '-rw-r--r--' -> '0644', 'rwsr-xr-x' -> '4755'
    """
    # Metin temizlenir
    s = symbolic_str.strip()
    # Eğer 10 karakter girilmişse ilk karakter (dosya türü d/- vb.) atlanır
    if len(s) == 10:
        # Yalnızca 9 izin karakteri alınır
        perms = s[1:]
    elif len(s) == 9:
        # Zaten 9 karakter izin bloğudur
        perms = s
    else:
        # Hatalı sembolik dize uzunluğu
        raise ValueError(f"Geçersiz sembolik izin uzunluğu: '{symbolic_str}' (9 veya 10 karakter olmalı)")

    # İzin değişkenleri sıfırlanır
    mode = 0  # Başlangıç mod değeri

    # Kullanıcı bloğu (perms[0:3])
    if perms[0] == "r":
        mode |= 0o0400  # Kullanıcı okuma biti
    if perms[1] == "w":
        mode |= 0o0200  # Kullanıcı yazma biti
    if perms[2] == "x":
        mode |= 0o0100  # Normal çalıştırma biti
    elif perms[2] == "s":
        mode |= 0o4100  # SUID ve çalıştırma biti
    elif perms[2] == "S":
        mode |= 0o4000  # Sadece SUID biti

    # Grup bloğu (perms[3:6])
    if perms[3] == "r":
        mode |= 0o0040  # Grup okuma biti
    if perms[4] == "w":
        mode |= 0o0020  # Grup yazma biti
    if perms[5] == "x":
        mode |= 0o0010  # Normal grup çalıştırma biti
    elif perms[5] == "s":
        mode |= 0o2010  # SGID ve çalıştırma biti
    elif perms[5] == "S":
        mode |= 0o2000  # Sadece SGID biti

    # Diğerleri bloğu (perms[6:9])
    if perms[6] == "r":
        mode |= 0o0004  # Diğerleri okuma biti
    if perms[7] == "w":
        mode |= 0o0002  # Diğerleri yazma biti
    if perms[8] == "x":
        mode |= 0o0001  # Normal çalıştırma biti
    elif perms[8] == "t":
        mode |= 0o1001  # Sticky ve çalıştırma biti
    elif perms[8] == "T":
        mode |= 0o1000  # Sadece Sticky biti

    # Oktal dize formatında döndürülür (örn: '0755' veya '4755')
    return f"{oct(mode)[2:].zfill(4)}"


def calculate_umask_permissions(umask_val):
    """Verilen umask değerine göre yeni oluşturulan dosya ve dizinlerin izinlerini hesaplar.
    
    Standart POSIX mantığı:
    Dosyalar için taban izin: 0666 (rw-rw-rw-)
    Dizinler için taban izin: 0777 (rwxrwxrwx)
    Sonuç izin = taban & ~umask
    """
    # Umask oktal tamsayıya çevrilir
    umask_int = parse_octal_mode(umask_val)
    
    # Dosya taban izni 0666 (octal)
    base_file = 0o0666
    # Dizin taban izni 0777 (octal)
    base_dir = 0o0777
    
    # Bit düzeyinde VE DEĞİL (AND NOT) işlemi uygulanır
    file_result = base_file & ~umask_int
    # Dizin için de aynı mantık uygulanır
    dir_result = base_dir & ~umask_int
    
    # Oktal string formatına dönüştürülür
    file_octal = oct(file_result)[2:].zfill(4)
    # Dizin için oktal string formatına dönüştürülür
    dir_octal = oct(dir_result)[2:].zfill(4)
    
    # Sembolik biçimleri oluşturulur
    file_symbolic = octal_to_symbolic(file_result, is_directory=False)
    # Dizin için sembolik biçim oluşturulur
    dir_symbolic = octal_to_symbolic(dir_result, is_directory=True)
    
    # Güvenlik risk değerlendirmesi yapılır
    is_dangerous = False  # Başlangıç risk durumu
    risk_reasons = []  # Risk açıklamaları listesi
    
    # Eğer diğerlerine yazma hakkı verilmişse (o+w) kritik risktir
    if file_result & 0o0002 or dir_result & 0o0002:
        # Risk durumu doğru yapılır
        is_dangerous = True
        # Açıklama eklenir
        risk_reasons.append("Diğer kullanıcılara yazma izni (World-Writable) veriliyor (CWE-732).")
        
    # Eğer gruba yazma hakkı açık bırakılmışsa orta derece risk
    if file_result & 0o0020 or dir_result & 0o0020:
        # Gruba yazma risk bilgisi eklenir
        risk_reasons.append("Grup üyelerine yazma izni tanımlanıyor (paylaşımlı ortamlarda riskli).")
        
    # Eğer umask 000 veya aşırı izin veriyorsa
    if umask_int == 0:
        # En tehlikeli durum
        is_dangerous = True
        # Kritik uyarı eklenir
        risk_reasons.append("Umask 0000: Sistem sıfır kısıtlama ile çalışıyor, tüm yeni nesneler tamamen savunmasızdır.")

    # Sonuç sözlüğü döndürülür
    return {
        "umask_girilen": oct(umask_int)[2:].zfill(4),
        "dosya_varsayilan_izin": file_octal,
        "dosya_sembolik": file_symbolic,
        "dizin_varsayilan_izin": dir_octal,
        "dizin_sembolik": dir_symbolic,
        "guvenli_mi": not is_dangerous,
        "risk_aciklamalari": risk_reasons
    }


def audit_permissions(inventory_data, rules_data):
    """Dosya izin envanterini temel güvenlik kurallarına göre denetler.
    
    Tespit edilen CWE-732 ihlallerini, gereksiz izinleri ve risk seviyelerini raporlar.
    """
    # Denetim sonuçları listesi oluşturulur
    bulgular = []
    # İstatistik sayaçları başlatılır
    toplam_denetlenen = 0  # Toplam denetlenen dosya sayısı
    uyumlu_sayisi = 0  # Uyumlu dosya sayısı
    ihlal_sayisi = 0  # İhlal tespit edilen dosya sayısı
    kritik_sayisi = 0  # Kritik seviye ihlal sayısı

    # Kural listesi alınır
    kurallar = rules_data.get("kurallar", [])
    # Dosya listesi alınır
    dosyalar = inventory_data.get("dosyalar", [])

    # Her bir dosya tek tek incelenir
    for dosya in dosyalar:
        # Sayaç artırılır
        toplam_denetlenen += 1
        # Dosya yolu bilgisi alınır
        yol = dosya.get("dosya_yolu", "")
        # Mevcut oktal mod alınır
        mevcut_oktal_str = dosya.get("mevcut_izin_oktal", "0000")
        # Oktal tamsayıya dönüştürülür
        mevcut_int = parse_octal_mode(mevcut_oktal_str)
        # Dosya türü alınır (directory / file)
        is_dir = (dosya.get("dosya_turu") == "directory")
        # Sembolik gösterim hesaplanır
        sembolik = octal_to_symbolic(mevcut_int, is_directory=is_dir)

        # Bu dosya için geçerli kural aranır
        eslesen_kural = None
        # Kurallar taranır
        for kural in kurallar:
            # Hedef yol şablonu fnmatch ile kontrol edilir (örn: /home/*/.ssh/id_rsa)
            if fnmatch.fnmatch(yol, kural.get("hedef_yol", "")):
                # Eşleşen kural atanır
                eslesen_kural = kural
                # İlk eşleşmede döngüden çıkılır
                break

        # Dosya ihlal tespit bayrağı
        dosya_ihlal_var = False
        # İhlal nedenleri listesi
        nedenler = []
        # Risk seviyesi varsayılanı
        risk_seviyesi = "BILGI"
        # Önerilen mod
        onerilen_mod = mevcut_oktal_str
        # Kural kimliği
        kural_id = "GENEL-KONTROL"

        # Genel Güvenlik Kontrolü 1: World-Writable (Herkes yazabilir mi? CWE-732)
        if (mevcut_int & 0o0002) and not (is_dir and (mevcut_int & 0o1000)):
            # Eğer /tmp gibi sticky bitli bir dizin değilse ve diğerlerine yazma açıksa
            dosya_ihlal_var = True
            # Neden eklenir
            nedenler.append("Kritik: Dosya/dizin diğer tüm kullanıcılarca değiştirilebilir (World-Writable - CWE-732).")
            # Risk seviyesi yükseltilir
            risk_seviyesi = "YUKSEK"

        # Eğer özel bir kural eşleştiyse kural kontrolleri uygulanır
        if eslesen_kural:
            # Kural ID atanır
            kural_id = eslesen_kural.get("kural_id")
            # Önerilen oktal izin kuraldan alınır
            onerilen_mod = eslesen_kural.get("onerilen_oktal", "0644")
            # İzin verilen en fazla oktal tamsayıya çevrilir
            max_int = parse_octal_mode(eslesen_kural.get("izin_verilen_en_fazla_oktal", "0777"))

            # İzin fazlalığı kontrolü (bitwise OR karşılaştırması)
            # Eğer mevcut izinde max iznin kapsamadığı herhangi bir bit varsa aşılmıştır
            if (mevcut_int | max_int) != max_int:
                # İhlal bayrağı işaretlenir
                dosya_ihlal_var = True
                # İhlal açıklaması eklenir
                nedenler.append(f"İzin aşımı: Mevcut ({mevcut_oktal_str}) izin, izin verilen azami ({eslesen_kural.get('izin_verilen_en_fazla_oktal')}) sınırını aşıyor.")
                # Risk seviyesi kuraldan alınır
                risk_seviyesi = eslesen_kural.get("risk_seviyesi", "YUKSEK")

            # Zorunlu bitler kontrolü (örn: /tmp için sticky bit 't')
            zorunlu_bitler = eslesen_kural.get("zorunlu_bitler", [])
            # Eğer sticky bit zorunluysa kontrol edilir
            if "t" in zorunlu_bitler and not (mevcut_int & 0o1000):
                # İhlal işaretlenir
                dosya_ihlal_var = True
                # Açıklama eklenir
                nedenler.append("Gecici ortak dizinde zorunlu yapışkan bit (Sticky Bit: 1000) eksik!")
                # Risk seviyesi güncellenir
                risk_seviyesi = eslesen_kural.get("risk_seviyesi", "YUKSEK")

            # Yasaklı bitler kontrolü
            yasakli = eslesen_kural.get("yasakli_bitler", [])
            # Diğerlerinin okuma izni yasak mı
            if "o+r" in yasakli and (mevcut_int & 0o0004):
                # İhlal işaretlenir
                dosya_ihlal_var = True
                # Açıklama eklenir
                nedenler.append("Kritik veri diğer kullanıcılarca okunabilir (o+r ihlali)!")
                # Risk kritik yapılır
                risk_seviyesi = "KRITIK"

        # İhlal durumuna göre sayaçlar güncellenir
        if dosya_ihlal_var:
            # İhlal sayacı artırılır
            ihlal_sayisi += 1
            # Eğer kritik seviye ise kritik sayacı da artırılır
            if risk_seviyesi == "KRITIK":
                # Kritik sayaç artırılır
                kritik_sayisi += 1
            # İyileştirme komutu oluşturulur
            iyilestirme_komutu = f"chmod {onerilen_mod} {yol}"
        else:
            # Uyumlu sayacı artırılır
            uyumlu_sayisi += 1
            # İyileştirme gerekmez
            iyilestirme_komutu = "Gereksiz (Uyumlu)"

        # Bulgu nesnesi hazırlanır
        bulgu = {
            "dosya_yolu": yol,
            "kural_id": kural_id,
            "dosya_turu": "dizin" if is_dir else "dosya",
            "sahip": dosya.get("sahip", "bilinmiyor"),
            "grup": dosya.get("grup", "bilinmiyor"),
            "mevcut_izin_oktal": mevcut_oktal_str,
            "mevcut_izin_sembolik": sembolik,
            "onerilen_izin_oktal": onerilen_mod,
            "uyumlu_mu": not dosya_ihlal_var,
            "risk_seviyesi": risk_seviyesi if dosya_ihlal_var else "DUSUK",
            "ihlaller": nedenler,
            "iyilestirme_komutu": iyilestirme_komutu
        }
        # Listeye eklenir
        bulgular.append(bulgu)

    # Özet rapor sözlüğü hazırlanır
    rapor = {
        "denetim_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "toplam_denetlenen": toplam_denetlenen,
        "uyumlu_sayisi": uyumlu_sayisi,
        "ihlal_sayisi": ihlal_sayisi,
        "kritik_ihlal_sayisi": kritik_sayisi,
        "uyumluluk_orani_yuzde": round((uyumlu_sayisi / toplam_denetlenen * 100), 2) if toplam_denetlenen > 0 else 100.0,
        "bulgular": bulgular
    }
    # Rapor döndürülür
    return rapor


def execute_permission_change(file_path, new_mode, actor="guvenlik-analisti", reason="guclendirme", journal_path="chmod_journal.json", initial_mode=None):
    """Kontrollü dosya izin değişikliği yapar ve geri alma günlüğüne (journal) işler.
    
    G024-SC2 Laboratuvar Şartı: Kontrollü girdi, gözlenebilir çıktı, kayıt ve geri alma.
    """
    # Dosya yolu normalize edilir
    norm_path = os.path.abspath(file_path)
    # Yeni mod int ve oktal dizeye dönüştürülür
    new_mode_int = parse_octal_mode(new_mode)
    # 4 haneli standart oktal dize formatı
    new_mode_octal = oct(new_mode_int)[2:].zfill(4)

    # Dosya varlığı kontrol edilir
    if not os.path.exists(norm_path):
        # Dosya bulunamazsa hata fırlatılır
        raise FileNotFoundError(f"Hedef dosya bulunamadı: {norm_path}")

    # Başlangıç izni parametre olarak verilmişse kullanılır, verilmemişse os.stat ile okunur
    if initial_mode is not None:
        # Verilen başlangıç modu tamsayıya çevrilir (çapraz platform laboratuvar simülasyonu)
        old_mode_int = parse_octal_mode(initial_mode)
    else:
        # Mevcut izinler işletim sisteminden sorgulanır
        current_stat = os.stat(norm_path)
        # Yalnızca izin bitleri maskelenir (0o7777)
        old_mode_int = current_stat.st_mode & 0o7777

    # Eski mod oktal dizesi oluşturulur
    old_mode_octal = oct(old_mode_int)[2:].zfill(4)
    # Eski sembolik gösterim hesaplanır
    old_symbolic = octal_to_symbolic(old_mode_int, is_directory=os.path.isdir(norm_path))

    # İzin değişikliği işletim sistemine uygulanır
    os.chmod(norm_path, new_mode_int)

    # Yeni sembolik gösterim hesaplanır
    new_symbolic = octal_to_symbolic(new_mode_int, is_directory=os.path.isdir(norm_path))

    # Günlük kaydı (journal entry) hazırlanır
    kayit = {
        "islem_id": f"TX-{int(time.time() * 1000)}",
        "zaman_damgasi": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dosya_yolu": norm_path,
        "islem_yapan": actor,
        "gerekce": reason,
        "eski_izin_oktal": old_mode_octal,
        "eski_izin_sembolik": old_symbolic,
        "yeni_izin_oktal": new_mode_octal,
        "yeni_izin_sembolik": new_symbolic,
        "durum": "UYGULANDI"
    }

    # Mevcut günlük dosyası varsa okunur, yoksa yeni liste başlatılır
    gunluk_verisi = []
    if os.path.exists(journal_path):
        try:
            # Dosya açılarak okunur
            with open(journal_path, "r", encoding="utf-8") as jf:
                gunluk_verisi = json.load(jf)
        except Exception:
            # Hata durumunda boş liste kullanılır
            gunluk_verisi = []

    # Yeni kayıt günlüğün sonuna eklenir
    gunluk_verisi.append(kayit)

    # Günlük dosyası diske güvenle yazılır
    with open(journal_path, "w", encoding="utf-8") as jf:
        json.dump(gunluk_verisi, jf, ensure_ascii=False, indent=2)

    # İşlem sonucu sözlüğü döndürülür
    return kayit


def rollback_permission_change(journal_path="chmod_journal.json", target_file=None):
    """Geri alma günlüğünü okuyarak en son yapılan veya belirtilen dosyadaki izinleri eski haline döndürür.
    
    G024-SC2 Şartı: Yapılan chmod değişikliklerini geri al ve kanıtla.
    """
    # Günlük dosyasının varlığı kontrol edilir
    if not os.path.exists(journal_path):
        # Dosya yoksa hata döndürülür
        raise FileNotFoundError(f"Geri alma günlüğü (journal) bulunamadı: {journal_path}")

    # Günlük verisi okunur
    with open(journal_path, "r", encoding="utf-8") as jf:
        gunluk_verisi = json.load(jf)

    # Eğer günlük boş ise hata verilir
    if not gunluk_verisi:
        # Boş günlük hatası
        raise ValueError("Geri alma günlüğü boş, geri alınacak işlem bulunamadı.")

    # Hedef dosya belirtilmişse ona ait son işlem aranır, belirtilmemişse genel son işlem alınır
    secilen_kayit = None
    # Günlük ters sırada taranır (en yeniden en eskiye)
    for kayit in reversed(gunluk_verisi):
        # Eğer hedef dosya verilmişse eşleşme kontrol edilir
        if target_file:
            # Normalize edilmiş yollar karşılaştırılır
            if os.path.abspath(kayit.get("dosya_yolu", "")) == os.path.abspath(target_file):
                # Eşleşen kayıt seçilir
                secilen_kayit = kayit
                # Döngü sonlandırılır
                break
        else:
            # En son işlem seçilir
            secilen_kayit = kayit
            # Döngü sonlandırılır
            break

    # Eğer kayıt bulunamadıysa hata verilir
    if not secilen_kayit:
        # Hata mesajı fırlatılır
        raise ValueError(f"Belirtilen dosya için geri alma kaydı bulunamadı: {target_file}")

    # Geri yüklenecek yol ve eski mod bilgisi alınır
    dosya_yolu = secilen_kayit["dosya_yolu"]
    # Eski oktal tamsayıya dönüştürülür
    eski_oktal_str = secilen_kayit["eski_izin_oktal"]
    # Tamsayı değeri elde edilir
    eski_mod_int = parse_octal_mode(eski_oktal_str)

    # Dosyanın varlığı teyit edilir
    if not os.path.exists(dosya_yolu):
        # Dosya silinmişse hata verilir
        raise FileNotFoundError(f"Geri alınacak hedef dosya artık mevcut değil: {dosya_yolu}")

    # İzin eski haline geri yüklenir
    os.chmod(dosya_yolu, eski_mod_int)

    # Geri alma sonucu kaydı oluşturulur
    rollback_kaydi = {
        "orijinal_islem_id": secilen_kayit["islem_id"],
        "geri_alma_zamani": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dosya_yolu": dosya_yolu,
        "geri_yuklenen_izin_oktal": eski_oktal_str,
        "geri_yuklenen_sembolik": secilen_kayit["eski_izin_sembolik"],
        "durum": "BASARIYLA_GERI_ALINDI"
    }

    # Günlüğe geri alma işlemi de kaydedilir
    gunluk_verisi.append(rollback_kaydi)
    # Dosyaya yazılır
    with open(journal_path, "w", encoding="utf-8") as jf:
        json.dump(gunluk_verisi, jf, ensure_ascii=False, indent=2)

    # Başarı sonucu döndürülür
    return rollback_kaydi


def main():
    """Linux RWX İzin Denetleyici CLI Komut Yürütücüsü."""
    # Windows ortamında UTF-8 çıktı formatı güvence altına alınır
    if hasattr(sys.stdout, "reconfigure"):
        # Standart çıktı UTF-8 olarak ayarlanır
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # Argüman ayrıştırıcı oluşturulur
    parser = argparse.ArgumentParser(
        description="G024: Linux Dosya İzinleri RWX Denetim ve Geri Alma Aracı"
    )
    # Denetim modu bayrağı
    parser.add_argument("--audit", action="store_true", help="Envanter dosyasını kurallara göre denetler")
    # Kurallar dosyası yolu
    parser.add_argument("--rules", type=str, default=None, help="Temel kural seti JSON dosyası yolu")
    # Envanter dosyası yolu
    parser.add_argument("--inventory", type=str, default=None, help="Dosya izin envanteri JSON yolu")
    # Umask hesaplama seçeneği
    parser.add_argument("--umask", type=str, default=None, help="Belirtilen umask için izin projeksiyonu yapar (örn: 022, 027)")
    # Dönüştürme seçeneği
    parser.add_argument("--convert", type=str, default=None, help="Oktal veya sembolik izni tersine dönüştürür (örn: 0755 veya rwxr-xr-x)")
    # İzin değiştirme modu
    parser.add_argument("--modify", nargs=2, metavar=("DOSYA", "YENI_MOD"), help="Dosya iznini değiştirir ve günlüğe kaydeder")
    # Geri alma modu
    parser.add_argument("--rollback", action="store_true", help="Son izin değişikliğini geri alır")
    # Geri alma hedef dosyası
    parser.add_argument("--target-file", type=str, default=None, help="Geri alınacak spesifik dosya")
    # Günlük dosyası yolu
    parser.add_argument("--journal", type=str, default="chmod_journal.json", help="Geri alma günlüğü dosya yolu")
    # JSON çıktı bayrağı
    parser.add_argument("--json", action="store_true", help="Sonucu saf JSON olarak ekrana basar")

    # Argümanlar ayrıştırılır
    args = parser.parse_args()

    # 1. Mod Dönüştürme İsteği (--convert)
    if args.convert:
        # Girdi temizlenir
        val = args.convert.strip()
        # Eğer sayılardan oluşuyorsa oktal -> sembolik
        if val.isdigit() or val.startswith("0o"):
            # Oktal dönüşümü yapılır
            sym = octal_to_symbolic(val)
            # Bilgi yazdırılır
            print(f"Oktal: {val} -> Sembolik: {sym}")
        else:
            # Sembolik dönüşümü yapılır
            octal = symbolic_to_octal(val)
            # Bilgi yazdırılır
            print(f"Sembolik: {val} -> Oktal: {octal}")
        # Program sonlandırılır
        return 0

    # 2. Umask Hesaplama İsteği (--umask)
    if args.umask:
        # Umask hesaplaması icra edilir
        res = calculate_umask_permissions(args.umask)
        # Eğer JSON istenmişse JSON basılır
        if args.json:
            # JSON formatında çıktı
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            # Didaktik metin formatında çıktı
            print("=" * 60)
            print(f"UMASK HESAPLAMA ANALİZİ: {res['umask_girilen']}")
            print("=" * 60)
            print(f"Yeni Dosya İzni     : {res['dosya_varsayilan_izin']} ({res['dosya_sembolik']})")
            print(f"Yeni Dizin İzni     : {res['dizin_varsayilan_izin']} ({res['dizin_sembolik']})")
            print(f"Güvenlik Durumu     : {'GÜVENLİ' if res['guvenli_mi'] else 'RİSKLİ/TEHLİKELİ'}")
            # Risk açıklamaları yazdırılır
            for r in res["risk_aciklamalari"]:
                print(f" - [UYARI] {r}")
            print("=" * 60)
        # Program sonlandırılır
        return 0

    # 3. İzin Değiştirme İsteği (--modify)
    if args.modify:
        # Dosya ve mod parametreleri alınır
        dosya, mod = args.modify[0], args.modify[1]
        # İşlem gerçekleştirilir
        res = execute_permission_change(dosya, mod, journal_path=args.journal)
        # Çıktı formatlanır
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("=" * 60)
            print("CHMOD DEĞİŞİKLİĞİ GERÇEKLEŞTİRİLDİ (G024-SC2)")
            print("=" * 60)
            print(f"Hedef Dosya    : {res['dosya_yolu']}")
            print(f"İşlem ID       : {res['islem_id']}")
            print(f"Eski İzin      : {res['eski_izin_oktal']} ({res['eski_izin_sembolik']})")
            print(f"Yeni İzin      : {res['yeni_izin_oktal']} ({res['yeni_izin_sembolik']})")
            print(f"Günlük Kaydı   : {args.journal}")
            print("=" * 60)
        return 0

    # 4. Geri Alma İsteği (--rollback)
    if args.rollback:
        # Geri alma icra edilir
        res = rollback_permission_change(journal_path=args.journal, target_file=args.target_file)
        # Çıktı verilir
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print("=" * 60)
            print("GERİ ALMA (ROLLBACK) İŞLEMİ BAŞARILI (G024-SC2)")
            print("=" * 60)
            print(f"Hedef Dosya    : {res['dosya_yolu']}")
            print(f"Orijinal İşlem : {res['orijinal_islem_id']}")
            print(f"Geri Yüklenen  : {res['geri_yuklenen_izin_oktal']} ({res['geri_yuklenen_sembolik']})")
            print(f"Durum          : {res['durum']}")
            print("=" * 60)
        return 0

    # 5. Denetim Modu (--audit)
    if args.audit:
        # Varsayılan dosya yolları ayarlanır
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Kurallar dosya yolu
        rules_path = args.rules or os.path.join(base_dir, "ornek_veri", "permission_baseline_rules.json")
        # Envanter dosya yolu
        inv_path = args.inventory or os.path.join(base_dir, "ornek_veri", "sample_files_permissions.json")

        # Dosyalar okunur
        with open(rules_path, "r", encoding="utf-8") as rf:
            rules_data = json.load(rf)
        with open(inv_path, "r", encoding="utf-8") as inf:
            inv_data = json.load(inf)

        # Denetim motoru koşturulur
        rapor = audit_permissions(inv_data, rules_data)

        # Çıktı formatı belirlenir
        if args.json:
            print(json.dumps(rapor, ensure_ascii=False, indent=2))
        else:
            print("=" * 70)
            print("LİNUX DOSYA İZİNLERİ RWX GÜVENLİK DENETİM RAPORU")
            print("=" * 70)
            print(f"Denetim Zamanı     : {rapor['denetim_zamani']}")
            print(f"Toplam Denetlenen  : {rapor['toplam_denetlenen']}")
            print(f"Uyumlu Dosyalar    : {rapor['uyumlu_sayisi']}")
            print(f"İhlal Sayısı       : {rapor['ihlal_sayisi']}")
            print(f"Kritik İhlal       : {rapor['kritik_ihlal_sayisi']}")
            print(f"Uyumluluk Skoru    : %{rapor['uyumluluk_orani_yuzde']}")
            print("-" * 70)
            print("DETAYLI BULGULAR:")
            # Her bir bulgu listelenir
            for b in rapor["bulgular"]:
                durum = "[UYUMLU]" if b["uyumlu_mu"] else f"[{b['risk_seviyesi']} İHLAL]"
                print(f"\n{durum} {b['dosya_yolu']} ({b['dosya_turu']})")
                print(f"   Mevcut İzin: {b['mevcut_izin_oktal']} ({b['mevcut_izin_sembolik']}) | Önerilen: {b['onerilen_izin_oktal']}")
                if not b["uyumlu_mu"]:
                    for ih in b["ihlaller"]:
                        print(f"   - İhlal Nedeni: {ih}")
                    print(f"   - İyileştirme : {b['iyilestirme_komutu']}")
            print("=" * 70)
        return 0

    # Hiçbir mod seçilmediyse yardım yazdırılır
    parser.print_help()
    return 1


# Python dosyasının doğrudan çalıştırılması durumunda main çağrılır
if __name__ == "__main__":
    # main fonksiyonu çağrılır ve çıkış kodu ile sistem sonlandırılır
    sys.exit(main())
