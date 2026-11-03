# G087: Bash Betik İskeleti, Güvenli Quoting ve Enjeksiyon Savunması

**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## Ustanın Giriş Dersi: Kabuğun En Karanlık Köşesi — Quoting ve Word Splitting

Evlat, Unix/Linux dünyasında en çok sistem yöneticisinin uykusunu kaçıran, sunucuları formatlattıran ve saldırganlara kök (root) yetkisi veren zafiyetler karmaşık C kodlarından değil; iki satırlık özensiz yazılmış Bash betiklerinden çıkar. 

Bash kabuğu ilk bakışta masum bir komut yorumlayıcısı gibi görünür. Fakat kabuğun arkasında çalışan **Genişleme Aşamaları (Expansion Order)** kuralını bilmeyen bir çırak, kendi ayağına kurşun sıkar.

Şu meşhur senaryoyu aklına kazı:
```bash
#!/bin/bash
TARGET_DIR=$1
rm -rf $TARGET_DIR/*
```
Bu betiği yazan kişi şunu düşünür: "Kullanıcı bana bir dizin yolu verir, ben de içini temizlerim."
Peki kullanıcı bir argüman vermezse ne olur?
`$TARGET_DIR` tanımsızdır, içi boştur!
Kabuk `$TARGET_DIR/*` ifadesini yorumlarken boşluğu atar ve geriye ne kalır?
```bash
rm -rf /*
```
İşte tüm işletim sistemi kökten silinir! Neden mi? Çünkü betiğin başında `set -u` (tanımsız değişken yasağı) yoktur ve `$TARGET_DIR` tırnak içine alınmamıştır!

Usta der ki: **"Bash kabuğunda tırnaksız bırakılan her değişken, saldırgana hediye edilmiş bir kök kabuğudur."**

---

## 1. Altın Standart: Güvenli Bash İskeleti

Profesyonel bir siber güvenlik uzmanının yazdığı her Bash betiği istisnasız şu 4 temel muhafızla başlamalıdır:

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
trap 'cleanup "$?" "$LINENO"' EXIT ERR
```

### Bu Muhafızlar Ne Yapar?

1. **Taşınabilir Shebang (`#!/usr/bin/env bash`):** Farklı Linux dağıtımlarında ve BSD sistemlerinde bash `/bin/bash` altında olmayabilir. `env` kullanmak doğru ikiliyi ortamdan bulur.
2. **`set -e` (Exit Immediately):** Betikteki herhangi bir komut hata verirse (`exit != 0`), kabuk anında çalışmayı durdurur. Hatanın üstü örtülmez.
3. **`set -u` (No Unset Variables):** Tanımlanmamış bir değişkene erişildiğinde kabuk derhal ölümcül hata üretir. Yukarıdaki `rm -rf /*` felaketini daha ilk saniyede engeller!
4. **`set -o pipefail` (Pipeline Defense):** Normalde `cmd1 | cmd2 | cmd3` boru hattında `cmd1` çökse bile `cmd3` başarılıysa çıkış kodu 0 döner! `pipefail` bayrağı, hattaki herhangi bir komut başarısız olduğunda tüm hattı başarısız sayar.
5. **`IFS=$'\n\t'` (Internal Field Separator):** Varsayılan IFS boşluk, sekme ve yeni satırdır. Bir değişkenin içinde boşluk varsa kabuk onu iki ayrı argümana böler. `IFS=$'\n\t'` yaparak yalnızca yeni satır ve sekmeleri ayırıcı kılıp boşluk bölünmesini engelleriz.
6. **`trap` (Güvenli Çıkış):** Betik ister normal tamamlansın ister beklenmedik bir hatayla çöksün, `cleanup` fonksiyonu tetiklenir; geçici dosyalar, kilitler ve bellek dökümleri temizlenir.

---

## 2. Quoting (Tırnak) Anatomisi: Tek Tırnak vs Çift Tırnak vs ANSI-C

Bash kabuğunda 3 farklı tırnak mekanizması vardır:

| Tırnak Türü | Sözdizimi | Genişleme (Expansion) | Kullanım Yeri |
| :--- | :--- | :--- | :--- |
| **Tek Tırnak (Literal)** | `'... $VAR ...'` | Değişkenler, komutlar ve kaçışlar **asla yorumlanmaz**, birebir düz metindir. | Regex desenleri, değişmeyen sabitler, şifreleme anahtarları. |
| **Çift Tırnak (Interpolated)** | `"... \"$VAR\" ..."` | Değişkenler ve `$(komut)` genişletilir, ancak **kelime bölünmesi (word splitting) ve globbing engellenir**. | Değişken referansları, dinamik metinler, dosya yolları. |
| **ANSI-C Quoting** | `$'...\n\t...'` | `\n`, `\t`, `\x00` gibi kaçış karakterlerini gerçek baytlara çevirir. | IFS yapılandırması, özel kontrol baytları. |

### Hayati Kural: `"$@"` vs `$*`
- `$*`: Tüm argümanları tek bir dizeye birleştirir ve aralarına boşluk koyar. Tırnaksız kullanılırsa kelime bölünmesine uğrar.
- `"$*"`: Tüm argümanları tek bir dize yapar: `"arg1 arg2 arg3"`.
- `$@`: Tırnaksız kullanılırsa her boşlukta argümanı böler.
- `"${@}"` (Usta Standardı): Her argümanı kendi tırnakları içinde ayrı birer eleman olarak korur: `"arg 1"` `"arg 2"`. Argüman sınırları asla bozulmaz!

---

## 3. Globbing ve Argüman Enjeksiyonu Tuzağı (CWE-88)

Diyelim ki bir dizindeki tüm dosyaları silmek için şu kodu yazdın:
```bash
rm *
```
Saldırgan o dizinde şu isimde bir dosya oluşturursa ne olur?
```bash
touch -- "-rf"
```
Sen `rm *` dediğinde kabuk `*` karakterini genişletir ve komut şu hale gelir:
```bash
rm -rf dosya1 dosya2 ...
```
`rm` programı `-rf` dosya adını bir dosya değil, **komut bayrağı (flag)** olarak algılar! Bu saldırı türüne **Pathname Expansion Flag Injection (CWE-88)** denir.

### Savunma: `--` (Double Dash) Bariyeri
Her komutta parametrelerden önce `--` kullanmak, kabuğa "buradan sonra gelen hiçbir şey bayrak değildir, tamamı dosya/argümandır" mesajı verir:
```bash
rm -- *
cat -- "${USER_FILE}"
grep -- "${PATTERN}" "${TARGET_FILE}"
```

---

## 4. Ölümcül Günah: `eval` Kullanımı (CWE-78)

```bash
# ASLA YAPILMAMASI GEREKEN KOD:
eval $USER_INPUT
```
`eval` komutu, kendisine verilen dizeyi kabuk tarafından ikinci kez ayrıştırılması için işletim sistemine iletir. `$USER_INPUT` içerisine `touch /tmp/pwned; whoami` gibi bir girdi yazıldığında doğrudan çalıştırılır.

Ustanın Kuralı: **"Modern Bash betiklerinde `eval` kullanmak için hiçbir meşru gerekçe yoktur. Dinamik listeler için `declare -A` (Hashtable) veya `declare -a` (Dizi) kullan."**
