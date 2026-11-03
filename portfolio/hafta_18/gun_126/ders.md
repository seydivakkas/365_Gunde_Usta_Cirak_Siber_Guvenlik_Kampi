# Gün 126: Aşama 5 Kalite Özeti — Kriptografi ve Güvenlik Mimarisi

> **Usta-Çırak / Hoca Dersi: Aşama 5 Büyük Kabul Kapısı (Quality Gate)**  
> *"Evlat; mimar olmak taş üstüne taş koymakla bitmez. Asıl ustalık, o taşların fırtınaya, depreme ve düşman kuşatmasına dayanıp dayanamayacağını bağımsız, tarafsız ve acımasız bir gözle denetleyebilmektir. Aşama 5 boyunca kriptografinin derinliklerinden sistem mimarisinin en çetin kalelerine kadar yürüdün. Şimdi bu kapıda durup arkana bakma ve inşa ettiğin tüm bu yapıyı NIST standartları ve Saltzer-Schroeder terazisinde tartma vaktidir."*

---

## 1. Giriş ve Aşama 5'in Kapsamı

Aşama 5, modern siber güvenlik uzmanlığının omurgasını oluşturan iki dev disiplini bir araya getirmiştir:
1. **Kriptografik Temeller ve Uygulamalar:**
   - Simetrik şifreleme (AES-GCM, ChaCha20-Poly1305),
   - Asimetrik şifreleme ve dijital imzalar (RSA, ECC, Ed25519),
   - Kriptografik özet fonksiyonları (SHA-2, SHA-3, HMAC) ve KDF (PBKDF2),
   - Kriptografik anahtar yaşam döngüsü ve zarf şifreleme (Envelope Encryption).
2. **Güvenlik Mimarisi ve Tasarım Prensipleri:**
   - STRIDE ve PASTA ile tehdit modelleme,
   - Nitel ve nicel risk analizi (SLE, ARO, ALE, ROSI),
   - 7 katmanlı savunma derinliği (Defense-in-Depth) ve tek nokta arızalarının (SPoF) önlenmesi,
   - Saltzer-Schroeder ilkeleri: Varsayılan Ret (Default-Deny) ve Arıza Güvenliği (Fail-Secure),
   - Sırlar yönetimi (Secrets Management) ve denetim kütüğü maskelemesi (CWE-532),
   - Hiyerarşik RBAC, Statik Görevler Ayrılığı (SoD) ve Adım Yükseltme Doğrulaması (Step-Up MFA).

---

## 2. Kriptografik Kalite ve Uyumluluk Standartları (NIST SP 800-131A / SP 800-57)

Kriptografi asla "kendi algoritmanı yaz" veya "eski kütüphaneleri çağır" alanı değildir. NIST SP 800-131A ve SP 800-57 belgeleri, endüstriyel kabul kriterlerini kesin çizgilerle belirlemiştir:

### 2.1. Kullanımdan Kaldırılmış (Banned) Algoritmalar
- **MD5 ve SHA-1 (CWE-327 / CWE-328):** Çarpışma saldırılarına (Collision Attacks) karşı tamamen kırılmıştır. Dijital imzalarda, kimlik doğrulamada ve sertifikalarda kullanımı yasaktır.
- **DES ve 3DES (CWE-326):** 56-bit ve 112-bit efektif anahtar uzunluklarıSweet32 ve kaba kuvvet saldırılarıyla aşılmıştır.
- **ECB Çalışma Modu (CWE-327):** Blok şifrelemede Electronic Codebook modu verinin desenini (desen analizi) gizlemez. Asla kullanılmamalıdır; yerine kimlik doğrulamalı şifreleme (AEAD) olan GCM veya ChaCha20-Poly1305 zorunludur.

### 2.2. Kabul Edilebilir Modern Standartlar
- **Simetrik:** En az AES-128, tavsiye edilen AES-256-GCM.
- **Asimetrik:** En az RSA-2048 (tavsiye edilen RSA-4096) veya ECDSA/Ed25519 (en az 256-bit eğriler).
- **Özet:** SHA-256, SHA-384, SHA-512 veya SHA-3 ailesi.
- **Parola KDF:** En az 100.000 iterasyonlu PBKDF2-HMAC-SHA256, Argon2id veya scrypt.
- **Güvenli Rastgelelik (CWE-338):** Asla `random` veya Mersenne Twister kullanılmaz; CSPRNG (`secrets`, `os.urandom`) zorunludur.
- **Sabit Zamanlı Karşılaştırma (CWE-208):** `hmac.compare_digest` kullanılarak zamanlama atakları önlenmelidir.

---

## 3. Mimari Güvenlik İlkeleri (Saltzer-Schroeder / NIST SP 800-160)

Jerome Saltzer ve Michael Schroeder tarafından 1975 yılında ortaya konan ve bugün NIST SP 800-160'ta somutlaşan güvenlik prensipleri, Aşama 5 mimarisinin ahlakıdır:

```
+-----------------------------------------------------------------------------------+
|               SALTZER-SCHROEDER (1975) & NIST SP 800-160 PRENSİPLERİ              |
+-----------------------------------------------------------------------------------+
| 1. Fail-Safe Defaults  --> Açıkça izin verilmeyen her şey REDDEDİLİR (Default-Deny)|
| 2. Complete Mediation   --> Her istek, her defasında aracı olmaksızın denetlenir |
| 3. Open Design          --> Güvenlik sır saklamaya değil, matematiksel tasarıma |
|                             dayanır (Kerckhoffs İlkesi)                           |
| 4. Separation of Duties --> Tek kişi kritik süreci tek başına onaylayamaz (SoD)   |
| 5. Least Privilege      --> Her aktör sadece işine yetecek asgari yetkiye sahiptir|
| 6. Least Common Mech.   --> Kullanıcılar arası ortak paylaşımlı mekanizmalar en aza |
+-----------------------------------------------------------------------------------+
```

---

## 4. Aşama 5 Kabul Kapısı (Quality Gate) Mantığı

Aşama 5 Kabul Denetçisi, şartnameyi üç ana eksende ağırlıklandırarak puanlar:
- **Kriptografik Güvenlik (%40):** Yasaklı algoritma, anahtar uzunluğu, PRNG ve sabit zaman denetimi.
- **Mimari İlkeler (%40):** Default-Deny, Fail-Secure, SoD, PoLP ve Savunma Derinliği katmanları.
- **Yönetişim ve Doğrulanabilir Kanıt (%20):** CWE-532 log maskelemesi, çalıştırılabilir yerel testler ve 9 negatif senaryo.

> [!CAUTION]
> **Kritik Engelleyiciler (Hard Blockers):**
> Bir sistemin puanı 90 olsa bile; eğer sistemde **MD5/SHA-1 (CWE-327)**, **Default-Allow (CWE-1188)** veya **Fail-Open (CWE-636)** tespit edilmişse sistem **STAGE_5_HOLD** durumuna düşer ve kabul edilmez!

---

## 5. Çırağa Usta Öğüdü

Evlat! Bir güvenlik uzmanı ile alelade bir programcı arasındaki fark denetim anında belli olur:
1. Programcı "Çalışıyor mu? Çalışıyor" der; güvenlik mimarı ise "Hangi şartlar altında nasıl çöker ve çöktüğünde kime neyi ifşa eder?" diye sorar.
2. Aşama 5 seni sadece bir kodlayıcı değil, sistemlerin röntgenini çeken bir güvenlik mimarı yaptı.
3. Kriptografiye güven, ama doğru parametrelerle; mimarine güven, ama Fail-Secure zırhıyla kuşatarak!
