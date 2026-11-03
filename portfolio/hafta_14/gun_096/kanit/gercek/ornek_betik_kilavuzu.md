# Operatör Güvenlik Kılavuzu: `log_sanitizer_tool`
> **Versiyon:** 2.4.0 | **Geliştirici:** Seydi Eryılmaz (@seydivakkas)
> **ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR (c) 2026 Seydi Eryılmaz**

## 1. Betiğin Amacı ve Operasyonel Rolü
Kurumsal SIEM ve SOC sistemlerine iletilen loglardaki hassas kişisel verileri (TCKN, Kredi Kartı, Parola) filtreleyip güvenli şekilde depolamak.

## 2. Yetki Seviyesi ve Tehdit Modeli (Least Privilege)
- **Gereken Yetki:** `Kullanıcı (Standart User) / Log dosyası okuma yetkisi`
- **Savunulan Tehditler ve CWE Kodları:**
  - CWE-532: Log Dosyasına Hassas Bilgi Yazılması (Düz metin kimlik ve kart sızıntısı)
  - CWE-250: Gereksiz Yüksek Yetki Kullanımı (Root gerektirmez, en düşük yetkiyle çalışır)
  - CWE-400: Kontrolsüz Kaynak Tüketimi (1 MB üzeri log dosyalarında parçalı okuma zorunludur)

## 3. Kritik Güvenlik Uyarıları (Safety Warnings)
> [!WARNING] ÖNEMLİ: Bu betik root veya Administrator yetkileriyle ÇALIŞTIRILMAMALIDIR (Least Privilege).
> [!WARNING] DİKKAT: '--purge-original' bayrağı adli delil niteliğindeki logları kalıcı olarak silebileceğinden önce yedekleme yapılmalıdır.
> [!WARNING] GÜVENLİK: Çıktı dosyasının erişim izinleri (Linux: 0600, Windows: Yalnızca Sahip) olarak ayarlanmalıdır.

## 4. Komut Satırı Parametreleri ve Girdi Doğrulama
| Parametre | Tip | Zorunlu mu? | Varsayılan | Açıklama ve Güvenlik Notu |
| :--- | :---: | :---: | :---: | :--- |
| `-i, --input-file` | Dosya Yolu (string) | Evet | - | İncelenecek ham log dosyasının tam veya bağıl dosya yolu.<br>*Path Traversal (CWE-22) engeli için mutlak yol doğrulaması yapılır.* |
| `-o, --output-file` | Dosya Yolu (string) | Hayır | - | Filtrelenmiş ve maskelenmiş logların yazılacağı hedef dosya.<br>*Mevcut sistem dosyalarının üzerine yazılması engellenmelidir.* |
| `--mask-mode` | Seçim (partial | full) | Hayır | `partial` | Kişisel veriler için maskeleme modu.<br>*Dış denetim ve üçüncü parti entegrasyonlarda 'full' modu zorunludur.* |
| `--purge-original` | Boole (Bayrak) | Hayır | `False` | İşlem sonrası kaynak ham log dosyasını kalıcı olarak siler.<br>*DİKKAT: Veri kaybına (CWE-16) yol açabileceğinden yalnızca onaylı ortamlarda kullanılmalıdır.* |

## 5. Çıkış Kodları ve Hata Durumları (Exit Codes)
| Çıkış Kodu | Anlamı ve Operasyonel Karşılığı |
| :---: | :--- |
| `0` | BAŞARILI: Log dosyası incelendi ve hassas veriler temizlendi. |
| `1` | UYARI / GÜVENLİK ENGELİ: Hassas veri sızıntısı tespit edildi veya kural ihlali oluştu. |
| `2` | KULLANIM / GİRDİ HATASI: Belirtilen dosya bulunamadı veya parametreler geçersiz. |

## 6. Örnek Güvenli Kullanım Senaryoları
```bash
$ python log_sanitizer_tool.py -i /var/log/auth.log -o /tmp/safe_auth.log
$ python log_sanitizer_tool.py -i app.log --mask-mode full
$ python log_sanitizer_tool.py -i access.log -o access_clean.log --purge-original
```
