# GÜN 135: Linux PAM (Pluggable Authentication Modules) ve Oturum Politikası

## Usta-Çırak / Hoca Dersi: Linux Kapısının Muhafızı PAM

Hoş geldin evlat. Dün Linux'ta yetki devrinin kalesi olan Sudo'yu fethettik. Bugün ise Linux sistemine adım atmak isteyen herkesin (ister yerel konsoldan, ister SSH üzerinden, isterse bir masaüstü ekranından) geçmek zorunda olduğu kapının mutlak muhafızını konuşacağız: **PAM (Pluggable Authentication Modules)** ve **Oturum Politikaları (Session Policies)**.

1990'ların ortalarına kadar her Linux programı (login, ftp, su, telnet) kimlik doğrulamayı kendi içinde yazardı. Biri `/etc/passwd` okur, diğeri shadow'a bakar, öbürü şifre kurallarını umursamazdı. Güvenlik politikalarını merkezi olarak yönetmek imkansızdı.

İşte Sun Microsystems ve Linux geliştiricileri bu kaosa son vermek için PAM mimarisini geliştirdi:
> *"Uygulama kimlik doğrulamanın NASIL yapıldığını bilmesin; sadece PAM'a sorsun. PAM arkada şifreye mi bakar, parmak izine mi bakar, Google Authenticator'a mı bakar, 5 kere yanlış girilince hesabı kilitler mi... Uygulama sadece EVET veya HAYIR cevabını alsın!"*

Bugün seninle bu muhafızın kalbine, `/etc/pam.d/` dizinine, modül tiplerine, kontrol bayraklarına ve kaba kuvvet saldırılarını (Brute-Force) ezen hesap kilitleme mekanizmalarına ineceğiz.

---

### 1. PAM Mimarisi: 4 Temel Yönetim Alanı (Module Types)

Bir PAM yapılandırma dosyasındaki her satır şu 4 görev türünden birine aittir:

1. **`auth` (Kimlik Doğrulama):**
   Kullanıcının iddia ettiği kişi olup olmadığını doğrular (Şifre istemi, Kerberos bileti, OTP token'ı vb.). Ayrıca kullanıcının kimlik bilgilerini (credentials) oluşturur.
   *Örnek modüller:* `pam_unix.so`, `pam_faillock.so`, `pam_google_authenticator.so`.
2. **`account` (Hesap Denetimi):**
   Kimliği doğrulanmış kullanıcının sisteme giriş yapma hakkı var mı? (Şifresi süresi dolmuş mu? Hesap kilitli mi? Saat 22:00'den sonra giriş izni var mı? `/etc/security/time.conf`).
   *Örnek modüller:* `pam_unix.so`, `pam_faillock.so`, `pam_time.so`, `pam_access.so`.
3. **`password` (Parola Yönetimi):**
   Kullanıcı `passwd` komutunu çalıştırdığında şifre güncelleme kurallarını yürütür. Şifre karmaşıklığını (`pam_pwquality.so`) ve eski şifrelerin tekrar kullanılmasını engelleme (`pam_pwhistory.so`) işini bu katman yapar.
4. **`session` (Oturum Hazırlığı ve Kapatma):**
   Kullanıcı sisteme kabul edildikten sonra ona nasıl bir ortam sunulacak? (Ev dizini yoksa oluşturulsun mu? `pam_mkhomedir.so`. Sistem kaynak limitleri uygulansın mı? `pam_limits.so`. Giriş mesajı gösterilsin mi? `pam_motd.so`).

---

### 2. PAM Kontrol Bayrakları (Control Flags): Yürütme Mantığı

Evlat, bir PAM dosyasında modüller sırayla bir zincir (stack) halinde çalışır. Bir modülün sonucunun zinciri nasıl etkileyeceğini **kontrol bayrağı** belirler:

| Bayrak | Başarılı Olursa Ne Olur? | Başarısız Olursa Ne Olur? | Açıklama |
|---|---|---|---|
| **`required`** | Zincir devam eder. | Zincir devam eder, ancak **nihai sonuç kesinlikle BAŞARISIZDIR**. | En standart zorunluluk bayrağıdır. Başarısız olsa bile saldırgana nerede patladığını hissettirmemek için zincir sonuna kadar koşar. |
| **`requisite`** | Zincir devam eder. | **Zincir DERHAL KESİLİR ve BAŞARISIZ döner.** | Kritik ön koşullarda kullanılır. Gereksiz zaman kaybetmemek ve bilgi sızdırmamak için anında reddeder. |
| **`sufficient`** | Önceki `required` modüller geçmişse, **zincir DERHAL BAŞARILI olarak biter!** | Zincir devam eder (başarısızlık yok sayılır). | Çok tehlikeli bir bayraktır. Doğru yerde kullanılmazsa kimlik doğrulamayı bypass edebilir! |
| **`optional`** | Zincir devam eder. | Zincir devam eder. | Sadece istatistik veya ek bilgi amaçlı modüller için kullanılır. |

---

### 3. Hesap Kilitleme ve Kaba Kuvvet Koruması: `pam_faillock` (CWE-307 / MITRE ATT&CK T1110.001)

Eski sistemlerde `pam_tally2` vardı; modern Linux dağıtımlarında (RHEL 8/9, Ubuntu 20.04+) yerini çok daha gelişmiş olan **`pam_faillock`** aldı.

Saldırgan SSH veya konsol üzerinden bir hesaba sürekli şifre denerse, sistem hesabı geçici olarak kilitlemelidir.

**CIS Benchmark Standart Yapılandırması (`/etc/security/faillock.conf`):**
```ini
# En fazla 5 başarısız deneme
deny = 5
# Başarısız denemelerin takip edileceği pencere süresi (15 dakika)
fail_interval = 900
# Hesabın kilitli kalacağı süre (15 dakika)
unlock_time = 900
# Root kullanıcısını da kaba kuvvete karşı kilitler
even_deny_root
```

**Kilit Durumunu Yönetme (Yönetici Komutları):**
- Bir kullanıcının kilit durumunu sorgulama:
  ```bash
  faillock --user ahmet
  ```
- Kilitlenen hesabın kilidini açma:
  ```bash
  faillock --user ahmet --reset
  ```

---

### 4. Parola Karmaşıklığı ve Kalitesi: `pam_pwquality` (CWE-521)

Sıradan kullanıcılar tahmin edilmesi kolay parolalar (`123456`, `Password1`) seçmeye meyillidir. `pam_pwquality` modülü bu tembelliği engeller.

**CIS Benchmark Kuralları (`/etc/security/pwquality.conf`):**
```ini
# En az 14 karakter uzunluk
minlen = 14
# En az 1 rakam zorunlu
dcredit = -1
# En az 1 büyük harf zorunlu
ucredit = -1
# En az 1 küçük harf zorunlu
lcredit = -1
# En az 1 özel karakter (noktalama) zorunlu
ocredit = -1
# Root kullanıcısının da bu kurallara uymasını zorunlu kıl
enforce_for_root
# 3 hatalı denemede reddet
retry = 3
```

> **Ustanın Notu:** Kredi değerlerinin eksi (`-1`) olması, o karakter türünden **en az 1 adet** bulunmasını zorunlu kılar. Pozitif değerler ise o karakter türü için uzunluk indirim puanı verir (tavsiye edilmez!).

---

### 5. Parola Geçmişi ve Tekrar Kullanımı Engelleme: `pam_pwhistory` (CWE-262)

Kullanıcı eski şifresini değiştirmeye zorlandığında, aynı şifreyi veya bir önceki şifresini geri yazmak isteyebilir.

`/etc/pam.d/system-auth` veya `password-auth` içinde:
```text
password required pam_pwhistory.so remember=5 use_authtok
```
Bu kural, kullanıcının son 5 şifresini `/etc/security/opasswd` dosyasında hash formatında saklar ve bu şifrelerin tekrar belirlenmesini engeller.

---

### 6. Ölümcül Hata: `nullok` Parametresi (CWE-258 / MITRE ATT&CK T1078)

Eski veya hatalı Linux kurulumlarında `pam_unix.so` satırında şu ifadeye rastlanır:
```text
auth sufficient pam_unix.so nullok
```
`nullok` parametresi: **"Eğer bu kullanıcının shadow dosyasında şifresi yoksa (boşsa), şifre sormadan oturum açmasına izin ver!"** anlamına gelir.

Saldırgan `/etc/shadow` dosyasında şifre alanı boş bırakılmış bir servis veya sistem hesabı keşfettiğinde, klavyeden Enter'a basarak anında sisteme girer! Kurumsal ortamlarda `nullok` bayrağı tüm PAM dosyalarından silinmelidir.

---

### 7. Oturum Boşta Kalma Zaman Aşımı (TMOUT - CWE-613)

Güvenlik sadece parola girerken değil, oturum açık bırakıldığında da korunmalıdır. Bir sistem yöneticisi terminali açık bırakıp kahve almaya gittiğinde (veya bir SSH oturumu arka planda unutulduğunda), saldırgan fiziksel veya ağ üzerinden konsola erişebilir.

**CIS Çözümü:**
`/etc/profile.d/timeout.sh` dosyası oluşturulur:
```bash
# 900 saniye (15 dakika) hareketsiz kalınca oturumu sonlandır
readonly TMOUT=900
export TMOUT
```
`readonly` anahtarı, kullanıcının kabuk içinde `TMOUT=0` yazarak zaman aşımını iptal etmesini engeller.

---

### 8. PAM Dosya İzinleri (CWE-732)

`/etc/pam.d/` ve `/etc/security/` dizinleri altındaki tüm dosyalar:
- Sahip: `root:root`
- İzin Modu: `0644` (Dizinler: `0755`)

Eğer bu dosyalardan biri başkaları tarafından yazılabilir (`0666` veya `others write`) olursa, saldırgan `auth required pam_permit.so` satırını en başa yazar ve herkes her şifreyle sisteme girmeye başlar!

---

### Ustanın Çırağa Öğüdü
> *"Evlat, Linux kapısının eşiği PAM'dır. Eşiği gevşek tutarsan, evin içine ordu girer. `nullok` bırakma, şifre boyunu 14'ten aşağı çekme, kaba kuvvete karşı `faillock`'u root dahil kilitli tut ve unutulan açık pencereleri `TMOUT` ile kapat!"*
