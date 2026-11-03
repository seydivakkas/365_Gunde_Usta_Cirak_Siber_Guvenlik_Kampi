# G064: Hafta 10 Gün 64 — Wireshark Filtre Sözdizimi ve Tehdit Avcılığı Motoru
**ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR**  
*Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)*

---

## 1. Usta-Çırak Girişi: Milyonlarca Paketin İçinde İğne Aramak

Evlat, modern bir kurumsal omurgada veya veri merkezinde paket yakalamaya (packet capture - pcap) başladığında saniyeler içinde yüz binlerce, dakikalar içinde milyonlarca paket diske akar. Ekrana dökülen bu devasa veri yığını içinde bir siber saldırganın fısıltısını, sızdırılan bir parolayı ya da gizli bir C2 işaretçisini (beacon) çıplak gözle bulamazsın.

İşte bu noktada **Wireshark Görüntüleme Filtreleri (Display Filters)**, bir güvenlik analistinin elindeki en keskin neşterdir. Ancak filtre yazmak rastgele komut ezberlemek değildir; arkasındaki **sözcüksel grameri (grammar), soyut sözdizim ağacını (AST) ve protokol ayrıştırıcı (dissector) şemasını** anlamayı gerektirir.

Bugün, paket yakalama filtreleri (BPF) ile görüntüleme filtreleri arasındaki farkları derinlemesine inceleyecek, kendi Wireshark filtre ayrıştırma motorumuzu sıfırdan inşa edecek ve ağ trafiğinde siber tehdit avcılığı (threat hunting) icra edeceğiz.

---

## 2. BPF (Yakalama Filtresi) ve Görüntüleme Filtresi Arasındaki Temel Ayrım

Ağ güvenliğinde en sık yapılan kavramsal hata, `tcpdump` yakalama filtresi (BPF) ile Wireshark görüntüleme filtresini birbirine karıştırmaktır:

| Ölçüt | BPF (Yakalama Filtresi - Capture Filter) | Wireshark Görüntüleme Filtresi (Display Filter) |
| :--- | :--- | :--- |
| **Çalıştığı Alan** | İşletim sistemi çekirdeği (Kernel - libpcap / Npcap) | Kullanıcı alanı (User space - Wireshark / TShark) |
| **Çalışma Zamanı** | Paket ağ kartından okunup diske yazılmadan **ÖNCE** | Paket yakalanıp diske yazıldıktan ve ayrıştırıldıktan **SONRA** |
| **Performans** | Son derece yüksek (elenen paketler diske hiç yazılmaz) | Orta / Göreceli (tüm paketler önce belleğe/diske alınır) |
| **Protokol Derinliği**| Yalnızca L2, L3 ve temel L4 başlıkları | L2'den L7'ye kadar tüm uygulama katmanı (HTTP, TLS, DNS, vb.) |
| **Sözdizim Örneği** | `tcp port 443 and src 10.0.0.5` | `tcp.port == 443 && ip.src == 10.0.0.5` |
| **Kullanım Amacı** | Sadece ilgilenilen trafiği yakalayarak disk/CPU korumak | Yakalanmış pcap içinde adli inceleme ve tehdit avı yapmak |

---

## 3. Wireshark Görüntüleme Filtresi Grameri ve Mantıksal Öncelik

Bir görüntüleme filtresi, protokol alan adları, operatörler, sabit değerler ve mantıksal bağlaçlardan oluşan kurallı bir dildir.

### 3.1. Protokol Alan Adları (Protocol Field Hierarchy)
Wireshark alanları hiyerarşik nokta notasyonu ile ifade edilir:
- `ip.src`, `ip.dst`: Kaynak ve hedef IPv4 adresleri
- `ip.addr`: Kaynak VEYA hedef adresten birinin eşleşmesi durumunda geçerli olan **takma alan (alias)**
- `tcp.srcport`, `tcp.dstport`: TCP port numaraları
- `tcp.port`: Kaynak veya hedef portu temsil eden takma alan
- `tcp.flags.syn`, `tcp.flags.reset`: TCP kontrol bayrakları (0 veya 1)
- `http.request.method`: HTTP istek metodu (GET, POST, PUT, DELETE)
- `http.body`: HTTP istek/yanıt gövdesi
- `dns.qry.name`: DNS sorgulanan alan adı
- `tls.handshake.type`: TLS el sıkışma mesaj tipi (1 = ClientHello, 2 = ServerHello)

### 3.2. Operatörler ve İfadeler
Motorumuz aşağıdaki operatörleri tam olarak destekler:
- **Eşitlik / Eşitsizlik:** `==` (`eq`), `!=` (`ne`)
- **İlişkisel:** `>`, `gt`, `<`, `lt`, `>=`, `ge`, `<=`, `le`
- **Metin Arama:** `contains` (büyük/küçük harf duyarsız alt dize araması)
- **Düzenli İfade:** `matches` (Python regex deseniyle eşleme)
- **Bayt Dilimleme (Byte Slicing):** `alan[baslangic:uzunluk]` (örn: `tcp.payload_hex[0:4] == "4745"`)
- **Mantıksal Bağlaçlar:** `&&` (`and`), `||` (`or`), `!` (`not`), `( ... )`

---

## 4. Tehdit Avcılığı (Threat Hunting) İmzaları

Wireshark görüntüleme filtreleri, SOC analistleri için hazır tehdit avı kuralları sunar:

1. **SYN Flood veya SYN Port Taraması:**
   ```wireshark
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```
   Normal bir akışta SYN paketleri toplam trafiğin çok küçük bir yüzdesini oluşturur. Ardışık ve yüksek frekanslı SYN paketleri, port taraması ya da SYN flood DoS saldırısına işaret eder.

2. **Port Taraması Reset Yanıtları (Kapalı Portlar):**
   ```wireshark
   tcp.flags.reset == 1
   ```
   Kapalı bir porta gönderilen SYN paketine sunucu işletim sistemi `RST/ACK` ile yanıt döner. Yüksek sayıda RST paketi, içeride aktif bir port tarayıcının çalıştığını gösterir.

3. **Açık Metin Kimlik Bilgisi Avı:**
   ```wireshark
   http.request.method == "POST" && (http contains "password" || http contains "auth")
   ```
   Şifrelenmemiş HTTP kanalı üzerinden iletilen kimlik doğrulama isteklerini ve parolaları saniyeler içinde filtreler.

4. **DNS Tünelleme ve Veri Sızdırma:**
   ```wireshark
   dns.qry.name.len > 40 && dns.flags.response == 0
   ```
   Standart web gezinmelerinde alan adları nadiren 40 karakteri aşar. 40 karakterden uzun ve rastgele alt alan adları içeren giden DNS sorguları, DNS tünelleme ile veri kaçırıldığını gösterir.

5. **Sıfır Pencere Kilitlenmesi (TCP Zero Window DoS):**
   ```wireshark
   tcp.window_size == 0 && tcp.flags.reset == 0
   ```
   Alıcı taraf arabelleğinin tamamen dolduğunu ve artık veri kabul edemediğini bildirir. Kasıtlı zero-window bildirimleri sunucuyu askıda tutmaya yönelik bir kaynak tüketim saldırısıdır.

---

## 5. Filtre Motorumuzun İç Mimarisi (Lexer & AST)

Geliştirdiğimiz `WiresharkFilterEngine` şu üç aşamalı derleme boru hattını işletir:
1. **Tokenize (Lexer):** Filtre dizgesini karakter bazında tarayarak parantezleri, tırnaklı dizgileri, çift/üç karakterli operatörleri ve alan adlarını sözcük birimlerine (token) ayırır.
2. **Grammar & Parantez Doğrulama:** Açılan ve kapanan parantezlerin dengesini (`validate_parentheses`) kontrol eder.
3. **Özyinelemeli İnişli Ayrıştırıcı (Recursive Descent Parser):** Matematiksel mantık önceliğine (`OR` $\to$ `AND` $\to$ `NOT` $\to$ `PRIMARY/COMPARISON`) göre bir Soyut Sözdizim Ağacı (AST) üretir.
4. **Değerlendirme (Evaluation):** AST üzerindeki düğümler, ayrıştırılmış paket sözlüğü (`packet dict`) üzerinden tip denetimli olarak işletilir ve eşleşen paketler listelenir.
