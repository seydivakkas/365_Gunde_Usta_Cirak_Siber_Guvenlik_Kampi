# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# Gün 098: Aşama 4 Kalite Özeti — Siber Güvenlik Otomasyonu ve Yönetişim

## Usta-Çırak / Hoca Dersi Girişi

Evlat, Aşama 4'ün (Gün 071'den Gün 098'e) sonuna geldik. Bu aşama boyunca güvenlik operasyonlarında kullanılan betiklerin salt birer "kod parçası" olmadığını, kurumsal savunmanın belkemiğini oluşturan **güvenilir, denetlenebilir ve zafiyetsiz otomasyon varlıkları** olduğunu gördük.

Bir güvenlik uzmanının yazdığı betik, saldırganın hedef aldığı ilk zayıf halka olmamalıdır. Eğer yazdığın adli bilişim aracı girdi doğrulaması yapmadığı için işletim sisteminde komut enjeksiyonuna izin veriyorsa ya da yazdığın log ayrıştırıcı Regex DoS (ReDoS) ile CPU'yu kilitliyorsa, sen savunma yapmıyorsun demektir; sen saldırgana sistem kapılarını ardına kadar açıyorsun demektir!

Bu derste, Aşama 4 boyunca inşa ettiğimiz tüm teknikleri bir potada eritecek, **Soyut Sözdizimi Ağacı (AST - Abstract Syntax Tree)** destekli statik denetim motorumuzla güvenlik betiklerinin kalitesini ve **Otomasyon Hazır Bulunuşluk Seviyesini (ARL - Automation Readiness Level)** nasıl ölçeceğimizi inceleyeceğiz.

---

## 1. Aşama 4 Teknik Özeti ve Bütüncül Kazanımlar

Aşama 4 boyunca öğrendiğimiz temel disiplinler:

1. **Güvenli Girdi ve Ağ Doğrulaması (CWE-20 / CWE-704 / CWE-1284):**
   - IPv4 adreslerinin `socket.inet_aton` ve `struct.unpack` ile bayt seviyesinde ayrıştırılması.
   - CIDR alt ağ maskelerinin ikili bit kaydırma mantığıyla doğrulanması.
   - Port numaralarının (1-65535) ve MAC adreslerinin (EUI-48 formatı) katı regex ve aralık kontrolleri.

2. **Kriptografik Veri Bütünlüğü ve Hashleme (CWE-328 / CWE-345 / CWE-208):**
   - Büyük dosyaların 64 KB bellek tamponları (chunk-by-chunk) ile RAM şişmesini önleyerek hashlenmesi (SHA-256, BLAKE2b).
   - Zamanlama saldırılarını (timing attack) engellemek için `hmac.compare_digest` ile sabit zamanlı doğrulama.
   - Dosya Bütünlük İzleme (FIM) mimarisinde baseline hash kayıtları ve drift tespiti.

3. **Veri Sızıntısı Önleme (DLP) ve Maskeleme (CWE-1333 / CWE-158 / CWE-359):**
   - ReDoS güvenli Regex motoru ile TCKN, Kredi Kartı ve IBAN tespiti.
   - Luhn (Mod-10), TCKN Mod-10/11 algoritması ve TR IBAN Mod-97 matematiksel kontrol basamakları.
   - PII verilerinin `MASK`, `REDACT` ve tek yönlü tuzlu `HASH` yöntemleriyle anonimleştirilmesi.

4. **Performans Ölçümü ve SLA Güvenliği (CWE-400 / CWE-401):**
   - Monotonik duvar saati (`time.perf_counter`) ve CPU süresi (`time.process_time`) ayrımı.
   - `tracemalloc` ile bellek sızıntılarının ve tepe tüketimlerin (peak memory) izlenmesi.
   - P95 ve P99 yüzdelik dilimleriyle gecikme (latency) SLA kurallarının enforce edilmesi.

5. **Kurumsal Dokümantasyon ve Yönetişim (CWE-1188 / CWE-16 / CWE-250):**
   - CLI araçlarında `--help`, Markdown operasyon el kitapları ve ROFF man-page çıktılarının otomatik üretimi.
   - Statik AST ve Regex yardımıyla belgelenmemiş gizli argümanların ve izin sapmalarının tespiti.

---

## 2. Statik Kod Analizi ve AST (Soyut Sözdizimi Ağacı) Motoru

Bir Python betiğini `eval()` veya `import` ederek denetlemek son derece tehlikelidir; çünkü zafiyetli ya da zararlı bir kod denetlendiği anda çalışabilir! Bunun yerine Python'ın yerleşik `ast` modülü kullanılarak kod doğrudan soyut sözdizimi ağacına dönüştürülür:

```python
import ast

def inspect_code_safety(code_str: str):
    tree = ast.parse(code_str)
    for node in ast.walk(tree):
        # eval / exec çağrılarını yakala (CWE-95)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                print(f"[TEHLİKE] Satır {node.lineno}: Dinamik kod yürütme çağrısı tespit edildi!")
        # Çıplak except bloklarını yakala (CWE-391)
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            print(f"[TEHLİKE] Satır {node.lineno}: Çıplak except: bloğu tespit edildi!")
```

### Zafiyet Odakları ve CWE Haritası
| Zafiyet Kodu | Zafiyet Tanımı | Kalite Motorundaki Karşılığı |
|---|---|---|
| **CWE-95** | Improper Neutralization of Directives in Dynamically Evaluated Code | `eval()` ve `exec()` AST tespiti |
| **CWE-798** | Use of Hard-coded Credentials | Kaynak koddaki sabit API key, parola tespiti |
| **CWE-391** | Unchecked Error Condition | Çıplak `except:` blokları tespiti |
| **CWE-16** | Environment/Configuration / Lisans İhlali | Zorunlu Özel Lisans başlığı doğrulaması |
| **CWE-158** | Null Byte Injection | Girdi dizgilerinde `\x00` tespiti |
| **CWE-400** | Uncontrolled Resource Consumption | 1 MB betik boyutu tavanı |
| **CWE-843** | Access of Resource Using Incompatible Type | Tip doğrulama kontrolleri |

---

## 3. Otomasyon Hazır Bulunuşluk Seviyeleri (ARL - Automation Readiness Level)

Kurumsal otomasyon boru hatlarına (DevSecOps) dahil edilecek betikler ARL modeline göre sınıflandırılır:

1. **ARL-4: Üretim Düzeyi / Tam Güvenli Otomasyon (Skor: 90 - 100)**
   - Katı girdi doğrulaması tamdır.
   - AST analizinde hiçbir zafiyet veya sabit gizli anahtar yoktur.
   - POSIX standart çıkış kodları (0, 1, 2) ve argüman ayrıştırma eksiksizdir.
   - Kurumsal Özel Lisans başlığı ve tam didaktik yorumlar mevcuttur.

2. **ARL-3: Kabul Edilebilir / Yeterli Otomasyon (Skor: 80 - 89)**
   - Kritik güvenlik açığı bulunmaz ancak dokümantasyon veya argüman ayrıştırmada küçük eksiklikler vardır.
   - Üretim ortamında denetimli olarak çalıştırılabilir.

3. **ARL-2: İyileştirme Gerekli / Riskli Otomasyon (Skor: 60 - 79)**
   - Çıplak except blokları veya standart dışı çıkış kodları içerir.
   - Hata ayıklama ve loglama yetersizdir; üretime alınamaz.

4. **ARL-1: Güvensiz / Reddedilmiş Otomasyon (Skor: 0 - 59)**
   - `eval()`, `exec()` veya sabit parola gibi kritik CWE açıkları içerir.
   - Otomasyon hattından derhal elenir ve güvenlik alarmı üretilir.

---

## 4. Ustanın Nasihati

Evlat, otomasyon iki ucu keskin bıçaktır. Yanlış tasarlanmış bir otomasyon, bir insanın yapacağı hatayı saniyede yüzlerce kez tekrarlar. İşte bu yüzden bu aşamayı bu denetim motoruyla mühürledik. Yazdığın her betiği bu filtreden geçir. Yüzde yüz puan almayan hiçbir aracı canlı operasyona sürme!
