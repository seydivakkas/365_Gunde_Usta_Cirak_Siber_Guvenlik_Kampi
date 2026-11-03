# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.
# Kopyalanamaz, çoğaltılamaz, dağıtılamaz, ticari amaçla kullanılamaz.

"""
G041: Mini Proje 5 - Windows ve Linux Karşılaştırmalı Güvenlik Raporu ve Denetim Motoru.

Bu modül, kurumsal altyapılarda kullanılan Windows Server ve Linux işletim sistemlerinin
güvenlik duruşunu (security posture) 10 standart güvenlik göstergesi üzerinden nesnel,
ölçülebilir ve karşılaştırılabilir metriklerle analiz eder.
"""

# İşletim sistemi dosya yolu ve ortam değişkeni işlemleri için os modülünü içe aktarıyoruz.
import os
# Komut satırı argümanlarını (CLI flags) profesyonelce ayrıştırmak için argparse kütüphanesini dahil ediyoruz.
import argparse
# Yapılandırılmış matris verilerini okumak ve sonuçları serileştirmek için json kütüphanesini yüklüyoruz.
import json
# Çıktı yönlendirmesi, hata yönetimi ve UTF-8 konsol akışı için sys modülünü çağırıyoruz.
import sys
# Tip güvenliği ve statik kod analizi için typing kütüphanesinden gerekli tipleri alıyoruz.
from typing import Dict, Any, List, Tuple, Optional
# Zaman damgalı denetim kayıtları üretmek amacıyla datetime ve timezone sınıflarını dahil ediyoruz.
from datetime import datetime, timezone

# 10 Standart Güvenlik Göstergesi Kimlik Listesi (Müfredat ve Denetim Standardı)
MANDATORY_INDICATOR_COUNT = 10

# Geçerli uyumluluk statüleri kümesi
VALID_STATUSES = {"COMPLIANT", "PARTIAL", "NON_COMPLIANT"}


class SecurityIndicatorError(ValueError):
    """Güvenlik göstergesi şema, tip veya değer aralığı ihlallerinde fırlatılan özel istisna sınıfı."""
    # Üst sınıf olan ValueError davranışını devralarak özel hata tipini tanımlıyoruz.
    pass


def validate_indicator_node(indicator: Dict[str, Any], index: int) -> None:
    """
    Tekil bir güvenlik göstergesi nesnesinin şema ve değer bütünlüğünü doğrular.
    
    Argümanlar:
        indicator: Doğrulanacak gösterge sözlüğü.
        index: Göstergenin listedeki sıra numarası.
    """
    # Girdi nesnesinin bir sözlük (dictionary) olup olmadığını sınıyoruz.
    if not isinstance(indicator, dict):
        # Sözlük harici bir tip (liste, string vb.) tespit edilirse hata fırlatıyoruz.
        raise SecurityIndicatorError(f"Gösterge #{index} bir sözlük nesnesi olmalıdır, alınan: {type(indicator).__name__}")
    
    # Gösterge kimliğinin varlığını ve metin tipinde olduğunu denetliyoruz.
    if "indicator_id" not in indicator or not isinstance(indicator["indicator_id"], str) or not indicator["indicator_id"].strip():
        # Kimlik eksik veya boşsa kural ihlali bildiriyoruz.
        raise SecurityIndicatorError(f"Gösterge #{index} geçerli bir 'indicator_id' dizesi içermelidir.")
    
    # Gösterge adının tanımlı olduğunu doğruluyoruz.
    if "name" not in indicator or not isinstance(indicator["name"], str) or not indicator["name"].strip():
        # Gösterge ismi yoksa istisna üretiyoruz.
        raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' için 'name' alanı boş bırakılamaz.")
    
    # Karşılaştırma yapılan hedef işletim sistemleri düğümlerini kontrol ediyoruz.
    for os_target in ["windows", "linux"]:
        # İşletim sistemi düğümünün ana sözlükte yer alıp almadığına bakıyoruz.
        if os_target not in indicator:
            # Eksik işletim sistemi düğümü durumunda hata fırlatıyoruz.
            raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' içinde zorunlu '{os_target}' verisi eksik.")
        
        # Hedef düğümün sözlük tipinde olmasını şart koşuyoruz.
        os_data = indicator[os_target]
        # Tip denetimi gerçekleştiriyoruz.
        if not isinstance(os_data, dict):
            # Sözlük değilse doğrulama hatası oluşturuyoruz.
            raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' -> '{os_target}' bir sözlük olmalıdır.")
        
        # Puan (score) alanının mevcudiyetini inceliyoruz.
        if "score" not in os_data:
            # Puan alanı yoksa hata bildiriyoruz.
            raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' -> '{os_target}' için 'score' alanı eksik.")
        
        # Puanın sayısal (int veya float) olduğunu teyit ediyoruz (bool hariç tutulmalıdır).
        score = os_data["score"]
        # Python'da bool tipi int alt sınıfı olduğundan isinstance(True, int) True döner; bunu özel olarak engelliyoruz.
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            # Sayısal olmayan tip yakalandığında istisna üretiyoruz.
            raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' -> '{os_target}' puanı sayı olmalıdır, alınan: {type(score).__name__}")
        
        # Puanın 0 ile 10 sınırları arasında olduğunu doğruluyoruz.
        if score < 0 or score > 10:
            # Sınır dışı puan tespitinde kural hatası fırlatıyoruz.
            raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' -> '{os_target}' puanı 0-10 aralığında olmalıdır, alınan: {score}")
        
        # Statü alanının varlığını kontrol ediyoruz.
        if "status" in os_data:
            # Statü değerinin izin verilen güvenli kümede olup olmadığına bakıyoruz.
            status_val = str(os_data["status"]).upper()
            # Geçersiz statü kontrolü yapıyoruz.
            if status_val not in VALID_STATUSES:
                # İzin verilmeyen statüde hata fırlatıyoruz.
                raise SecurityIndicatorError(f"Gösterge '{indicator['indicator_id']}' -> '{os_target}' geçersiz statü: {status_val}. Beklenen: {VALID_STATUSES}")


def load_and_validate_matrix(file_path: str) -> Dict[str, Any]:
    """
    JSON formatındaki karşılaştırma matrisi dosyasını diskten okur ve tam şema doğrulaması uygular.
    
    Argümanlar:
        file_path: Matris JSON dosyasının tam dosya yolu.
        
    Döndürür:
        Doğrulanmış matris sözlüğü.
    """
    # Dosyanın disk üzerinde fiziki olarak var olup olmadığını teyit ediyoruz.
    if not os.path.isfile(file_path):
        # Dosya yoksa FileNotFoundError fırlatıyoruz.
        raise FileNotFoundError(f"Belirtilen karşılaştırma matrisi dosyası bulunamadı: {file_path}")
    
    # Dosyayı güvenli UTF-8 karakter kodlamasıyla açıyoruz.
    with open(file_path, "r", encoding="utf-8") as f:
        # JSON içeriğini Python sözlük nesnesine dönüştürüyoruz.
        try:
            # Ayrıştırma işlemini icra ediyoruz.
            data = json.load(f)
        # JSON sentaks hatalarını yakalıyoruz.
        except json.JSONDecodeError as jde:
            # Bozuk JSON hatasını SecurityIndicatorError olarak yeniden fırlatıyoruz.
            raise SecurityIndicatorError(f"Matris dosyası bozuk JSON verisi içeriyor: {jde}")
    
    # Kök nesnenin sözlük olduğunu teyit ediyoruz.
    if not isinstance(data, dict):
        # Kök eleman sözlük değilse hata veriyoruz.
        raise SecurityIndicatorError("Matris kök elemanı bir JSON nesnesi (sözlük) olmalıdır.")
    
    # 'indicators' dizisinin kök nesnede yer alıp almadığını sınıyoruz.
    if "indicators" not in data or not isinstance(data["indicators"], list):
        # Göstergeler listesi eksikse hata üretiyoruz.
        raise SecurityIndicatorError("Matris dosyasında 'indicators' listesi bulunamadı.")
    
    # Göstergeler dizisini alıyoruz.
    indicators = data["indicators"]
    
    # Tam olarak 10 standart göstergenin bulunup bulunmadığını denetliyoruz.
    if len(indicators) < MANDATORY_INDICATOR_COUNT:
        # 10 göstergeden az ise eksik envanter hatası veriyoruz.
        raise SecurityIndicatorError(f"Mini Proje 5 standardı en az {MANDATORY_INDICATOR_COUNT} gösterge gerektirir; mevcut: {len(indicators)}")
    
    # Her bir göstergeyi sırayla doğrulama fonksiyonundan geçiriyoruz.
    for idx, ind in enumerate(indicators, start=1):
        # Gösterge doğrulayıcıyı çağırıyoruz.
        validate_indicator_node(ind, idx)
    
    # Doğrulamadan tam puanla geçen veriyi geri döndürüyoruz.
    return data


def calculate_system_metrics(indicators: List[Dict[str, Any]], os_target: str) -> Dict[str, Any]:
    """
    Belirli bir hedef işletim sistemi için toplam puan, yüzde uyumluluk ve risk seviyesini hesaplar.
    
    Argümanlar:
        indicators: Doğrulanmış göstergeler listesi.
        os_target: 'windows' veya 'linux' hedef dizesi.
        
    Döndürür:
        Sistem metriklerini ve risk durumunu barındıran özet sözlük.
    """
    # Toplam puan akümülatörünü sıfırlıyoruz.
    total_score = 0.0
    # İncelenen gösterge sayacı.
    count = 0
    # Uyumlu, kısmi ve uyumsuz gösterge sayılarını tutan sayaçlar.
    compliant_count = 0
    # Kısmi uyumlu gösterge sayacı.
    partial_count = 0
    # Uyumsuz gösterge sayacı.
    non_compliant_count = 0
    
    # Tüm göstergeleri döngü ile tarıyoruz.
    for ind in indicators:
        # Hedef işletim sisteminin alt düğümünü çekiyoruz.
        target_info = ind[os_target]
        # Puanı akümülatöre ilave ediyoruz.
        total_score += float(target_info["score"])
        # Gösterge sayısını bir artırıyoruz.
        count += 1
        
        # Statü değerini büyük harfe çevirerek alıyoruz.
        status = str(target_info.get("status", "PARTIAL")).upper()
        # Statü türüne göre ilgili sayacı artırıyoruz.
        if status == "COMPLIANT":
            # Tam uyumlu sayacını artırıyoruz.
            compliant_count += 1
        # Kısmi uyumluluk durumu.
        elif status == "PARTIAL":
            # Kısmi uyumlu sayacını artırıyoruz.
            partial_count += 1
        # Uyumsuzluk durumu.
        else:
            # Uyumsuz sayacını artırıyoruz.
            non_compliant_count += 1
            
    # Maksimum olası puanı hesaplıyoruz (10 gösterge * 10 puan = 100).
    max_possible = count * 10.0
    # Yüzdelik başarı oranını hesaplıyoruz.
    percentage = (total_score / max_possible * 100.0) if max_possible > 0 else 0.0
    
    # Yüzde değere göre kurumsal risk seviyesini sınıflandırıyoruz.
    if percentage >= 85.0:
        # 85 ve üzeri düşük risk seviyesi ve güçlü savunma anlamına gelir.
        risk_level = "LOW (Düşük Risk / Güçlü Savunma)"
    elif percentage >= 70.0:
        # 70-84 aralığı orta risk ve sıkılaştırma ihtiyacını gösterir.
        risk_level = "MEDIUM (Orta Risk / Sıkılaştırma İhtiyacı)"
    elif percentage >= 50.0:
        # 50-69 aralığı yüksek risk ve açık zaafiyetleri temsil eder.
        risk_level = "HIGH (Yüksek Risk / Kritik Açıklar Mevcut)"
    else:
        # 50 altı kritik acil müdahale seviyesidir.
        risk_level = "CRITICAL (Kritik Risk / Acil Müdahale Gerekli)"
        
    # Hesaplanan metrikleri yapılandırılmış sözlük olarak döndürüyoruz.
    return {
        "os_target": os_target,
        "total_score": round(total_score, 1),
        "max_possible_score": max_possible,
        "percentage": round(percentage, 1),
        "risk_level": risk_level,
        "compliant_count": compliant_count,
        "partial_count": partial_count,
        "non_compliant_count": non_compliant_count
    }


def compare_operating_systems(matrix_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Windows ve Linux metriklerini hesaplar, aralarındaki farkları ve kategori analizlerini çıkarır.
    
    Argümanlar:
        matrix_data: Doğrulanmış matris verisi.
        
    Döndürür:
        Karşılaştırma sonuçlarını içeren bütüncül sözlük.
    """
    # Göstergeler listesini çekiyoruz.
    indicators = matrix_data["indicators"]
    
    # Windows için metrikleri hesaplıyoruz.
    win_metrics = calculate_system_metrics(indicators, "windows")
    # Linux için metrikleri hesaplıyoruz.
    lin_metrics = calculate_system_metrics(indicators, "linux")
    
    # Puan farkını hesaplıyoruz (Linux - Windows).
    score_differential = round(lin_metrics["total_score"] - win_metrics["total_score"], 1)
    
    # Karşılaştırma sonuç yapısını derliyoruz.
    return {
        "meta": matrix_data.get("meta", {}),
        "total_indicators_evaluated": len(indicators),
        "windows": win_metrics,
        "linux": lin_metrics,
        "score_differential_linux_minus_windows": score_differential,
        "indicators": indicators
    }


def generate_markdown_comparison_report(comparison: Dict[str, Any]) -> str:
    """
    Karşılaştırma sonuçlarından detaylı, profesyonel bir Markdown denetim raporu üretir.
    
    Argümanlar:
        comparison: Karşılaştırma sonuç sözlüğü.
        
    Döndürür:
        Markdown formatında biçimlendirilmiş rapor metni.
    """
    # Meta bilgilerini alıyoruz.
    meta = comparison.get("meta", {})
    # Windows metriklerini çekiyoruz.
    win = comparison["windows"]
    # Linux metriklerini çekiyoruz.
    lin = comparison["linux"]
    # Göstergeleri alıyoruz.
    indicators = comparison["indicators"]
    
    # Rapor satırları listesini başlatıyoruz.
    lines: List[str] = []
    
    # Başlık ve özel lisans uyarısını ekliyoruz.
    lines.append("# G041: Mini Proje 5 — Windows ve Linux Karşılaştırmalı Güvenlik Raporu")
    lines.append("")
    lines.append("> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  ")
    lines.append("> **Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)**  ")
    lines.append("> Bu yazılım ve eğitim içeriği yalnızca görüntüleme ve kişisel öğrenim amaçlıdır.")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Yönetici Özeti ve Kapsam Bölümü
    lines.append("## 1. Yönetici Özeti ve Kapsam")
    lines.append(f"- **Proje Adı:** {meta.get('project', 'Mini Proje 5')}")
    lines.append(f"- **Değerlendirme Tarihi:** {meta.get('assessment_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))}")
    lines.append(f"- **Hedef Sistemler:**")
    lines.append(f"  - Windows: {meta.get('target_systems', {}).get('windows', 'Windows Server 2022')}")
    lines.append(f"  - Linux: {meta.get('target_systems', {}).get('linux', 'Ubuntu Server 22.04 LTS')}")
    lines.append(f"- **İncelenen Gösterge Sayısı:** {comparison['total_indicators_evaluated']} Standart Güvenlik Göstergesi")
    lines.append("")
    
    # Karşılaştırmalı Puan ve Risk Tablosu
    lines.append("## 2. Karşılaştırmalı Güvenlik Duruşu ve Skor Tablosu")
    lines.append("")
    lines.append("| Metrik / Ölçüt | Windows Server 2022 | Ubuntu 22.04 LTS | Değerlendirme / Fark |")
    lines.append("|---|---|---|---|")
    lines.append(f"| **Toplam Güvenlik Puanı (100 Üzerinden)** | **{win['total_score']} / {win['max_possible_score']}** | **{lin['total_score']} / {lin['max_possible_score']}** | Fark: {comparison['score_differential_linux_minus_windows']} puan |")
    lines.append(f"| **Uyumluluk Yüzdesi** | **%{win['percentage']}** | **%{lin['percentage']}** | Normalleştirilmiş Oran |")
    lines.append(f"| **Kurumsal Risk Seviyesi** | {win['risk_level']} | {lin['risk_level']} | Posture Durumu |")
    lines.append(f"| **Tam Uyumlu Göstergeler (COMPLIANT)** | {win['compliant_count']} / 10 | {lin['compliant_count']} / 10 | Sıkılaştırılmış Alanlar |")
    lines.append(f"| **Kısmi Uyumlu Göstergeler (PARTIAL)** | {win['partial_count']} / 10 | {lin['partial_count']} / 10 | İyileştirme Gereken Alanlar |")
    lines.append(f"| **Uyumsuz Göstergeler (NON_COMPLIANT)** | {win['non_compliant_count']} / 10 | {lin['non_compliant_count']} / 10 | Kritik Açıklar |")
    lines.append("")
    
    # 10 Göstergenin Ayrıntılı Dökümü
    lines.append("## 3. 10 Standart Güvenlik Göstergesi Ayrıntılı Analiz Matrisi")
    lines.append("")
    lines.append("| No | Gösterge Adı | Kategori | Windows Puan / Mekanizma | Linux Puan / Mekanizma |")
    lines.append("|---|---|---|---|---|")
    
    # Göstergeleri tabloya satır satır işliyoruz.
    for ind in indicators:
        # Gösterge kimliğini ve adını alıyoruz.
        iid = ind.get("indicator_id", "N/A")
        # İsim alanı.
        iname = ind.get("name", "N/A")
        # Kategori bilgisi.
        icat = ind.get("category", "Genel")
        # Windows detayları.
        w_score = ind["windows"]["score"]
        # Windows mekanizması.
        w_mech = ind["windows"].get("mechanism", "N/A")
        # Linux detayları.
        l_score = ind["linux"]["score"]
        # Linux mekanizması.
        l_mech = ind["linux"].get("mechanism", "N/A")
        
        # Tablo satırını oluşturup ekliyoruz.
        lines.append(f"| {iid} | **{iname}** | {icat} | **{w_score}/10** - {w_mech} | **{l_score}/10** - {l_mech} |")
        
    lines.append("")
    
    # Savunma ve İyileştirme Önerileri (Usta-Çırak Görüşü)
    lines.append("## 4. Savunma, Tespit ve Sıkılaştırma Kılavuzu")
    lines.append("### Windows Server Öncelikli İyileştirmeler:")
    lines.append("1. **Yerel Yönetici Yetkileri:** Yerel Administrator haklarını LAPS v2 ile dinamikleştirin ve üçüncü taraf servis hesaplarının SYSTEM yerine `NT SERVICE\\` SID'leri ile çalışmasını sağlayın.")
    lines.append("2. **UAC ve ASR Kuralları:** PowerShell ve Office makrolarını hedefleyen Saldırı Yüzeyi Azaltma (ASR) kurallarını aktif denetimden bloklama moduna geçirin.")
    lines.append("")
    lines.append("### Linux Server Öncelikli İyileştirmeler:")
    lines.append("1. **Zararlı Yazılım ve EDR Takibi:** Yalnızca statik tarama yerine Wazuh/Auditd ile gerçek zamanlı süreç izleme ve SIEM korelasyonunu devreye alın.")
    lines.append("2. **AppArmor Zorlaması:** Tüm ağ servisleri için profilleri `complain` kipinden `enforce` kipine çekerek yetkisiz sistem çağrılarını engelleyin.")
    lines.append("")
    lines.append("---")
    lines.append("*Rapor Antigravity Didaktik Güvenlik Denetim Motoru tarafından otomatik üretilmiştir.*")
    
    # Tüm satırları birleştirerek tek bir metin dizesi olarak döndürüyoruz.
    return "\n".join(lines)


def main() -> int:
    """Komut satırı arayüzünü yöneten ve denetim sürecini başlatan ana fonksiyon."""
    # Windows konsolunda UTF-8 karakterlerin bozulmasını önlemek için standart akışları yapılandırıyoruz.
    if sys.platform == "win32":
        # Standart çıktı akışını UTF-8 olarak yeniden yapılandırıyoruz.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        # Standart hata akışını UTF-8 olarak yeniden yapılandırıyoruz.
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        
    # Komut satırı argüman ayrıştırıcısını oluşturuyoruz.
    parser = argparse.ArgumentParser(
        description="G041: Mini Proje 5 - Windows ve Linux Karşılaştırmalı Güvenlik Raporu Motoru"
    )
    # Matris dosyası yolu argümanı.
    parser.add_argument(
        "--matrix",
        type=str,
        required=True,
        help="Doğrulanacak ve karşılaştırılacak 10 göstergeli JSON matris dosyasının yolu."
    )
    # Markdown rapor çıktısı dosyası argümanı.
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Markdown raporunun kaydedileceği dosya yolu (isteğe bağlı)."
    )
    # JSON özet çıktısı dosyası argümanı.
    parser.add_argument(
        "--json-summary",
        type=str,
        default=None,
        help="Makine tarafından okunabilir JSON özetinin kaydedileceği dosya yolu."
    )
    
    # Argümanları ayrıştırıyoruz.
    args = parser.parse_args()
    
    try:
        # Matrisi diskten yüklüyor ve doğruluyoruz.
        matrix_data = load_and_validate_matrix(args.matrix)
        # Karşılaştırma analizini çalıştırıyoruz.
        comparison = compare_operating_systems(matrix_data)
        # Markdown raporunu üretiyoruz.
        report = generate_markdown_comparison_report(comparison)
        
        # Konsola raporu yazdırıyoruz.
        print(report)
        
        # Eğer rapor çıkış dosyası belirtilmişse dosyaya kaydediyoruz.
        if args.output:
            # Çıktı dosyasının üst dizinini garantiye alıyoruz.
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            # Rapor dosyasını UTF-8 olarak yazıyoruz.
            with open(args.output, "w", encoding="utf-8") as out_f:
                # İçeriği kaydediyoruz.
                out_f.write(report)
            # Konsola bilgilendirme mesajı düşüyoruz.
            print(f"\n[+] Rapor başarıyla kaydedildi: {args.output}")
            
        # JSON özet dosyası istenmişse kaydediyoruz.
        if args.json_summary:
            # Üst dizini oluşturuyoruz.
            os.makedirs(os.path.dirname(os.path.abspath(args.json_summary)), exist_ok=True)
            # JSON dosyasını yazıyoruz.
            with open(args.json_summary, "w", encoding="utf-8") as jf:
                # Yapılandırılmış veriyi kaydediyoruz.
                json.dump(comparison, jf, indent=2, ensure_ascii=False)
            # Bilgilendirme yapıyoruz.
            print(f"[+] JSON özeti başarıyla kaydedildi: {args.json_summary}")
            
        # Başarılı çıkış kodu 0 döndürüyoruz.
        return 0
        
    # Güvenlik göstergesi ve doğrulama hatalarını yakalıyoruz.
    except SecurityIndicatorError as sie:
        # Hata mesajını standart hataya yazıyoruz.
        sys.stderr.write(f"[-] Doğrulama Hatası: {sie}\n")
        # Hata çıkış kodu 1 döndürüyoruz.
        return 1
    # Dosya bulunamadı hatasını yakalıyoruz.
    except FileNotFoundError as fnfe:
        # Hata mesajını standart hataya yazıyoruz.
        sys.stderr.write(f"[-] Dosya Hatası: {fnfe}\n")
        # Hata çıkış kodu 2 döndürüyoruz.
        return 2
    # Beklenmeyen genel sistem hatalarını yakalıyoruz.
    except Exception as ex:
        # Beklenmeyen hata mesajını standart hataya basıyoruz.
        sys.stderr.write(f"[-] Beklenmeyen Hata: {ex}\n")
        # Hata çıkış kodu 3 döndürüyoruz.
        return 3


# Modül doğrudan çalıştırıldığında main() fonksiyonunu çağırıyoruz.
if __name__ == "__main__":
    # Programdan dönen çıkış kodu ile sistemden ayrılıyoruz.
    sys.exit(main())
