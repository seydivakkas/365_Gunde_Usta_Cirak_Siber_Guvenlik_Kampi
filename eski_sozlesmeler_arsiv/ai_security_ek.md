# ai_security_ek.md — Siber Güvenlik 337–350: AI, LLM, RAG ve ajan güvenliği

**Amaç:** Temel siber güvenliğe eklenen 14 günlük AI Security birimini tamamen yerel, sentetik ve doğrulanabilir örneklerle öğretmek. **Dış LLM API, API anahtarı veya çevrimiçi modele erişim şart değildir.** Ajan yine her güne bağımsız kod/örnek/test üretir; bir günün modeli başka güne devam etmez.

## 1. Gün–risk–öğrenme hedefi eşlemesi

| Gün | Kapsam | Esas kontrol | Bağımsız yerel görev |
|---:|---|---|---|
| 337 | NIST AI RMF + GenAI Profile | Govern / Map / Measure / Manage, risk kaydı | Sentetik yerel AI sistemi için risk kartları |
| 338 | LLM/RAG ve araç güven sınırları | Kullanıcı/veri/araç/talimat ayrımı | Güven sınırı ve data-flow diyagramı |
| 339 | **LLM01:2025 Prompt Injection** | Güvenilmeyen içerik asla yüksek ayrıcalıklı talimat olmaz | Sahte dokümanla allowlist/reddetme testleri |
| 340 | **LLM08:2025 Vector and Embedding Weaknesses** | RAG kaynak izni, hash, sürüm, köken | Üç sentetik belgenin kaynak doğrulama aracı |
| 341 | **LLM03:2025 Supply Chain** | Model, tokenizer, eklenti bütünlüğü | Sahte ağırlık dosyalarında hash/manifest doğrulama |
| 342 | **LLM06:2025 Excessive Agency** | Araç izni, onay, sandbox, allowlist | Zararsız mock tool policy denetleyicisi |
| 343 | LLM01–LLM10 risk matrisi | Test edilebilir kontrol eşlemesi | Sıfırdan bağımsız AI güvenlik mini projesi |
| 344 | **LLM09:2025 Misinformation** | Kaynağa dayalı cevap, çekimser kalma | Kaynak destekli/sahipsiz iddia etiketleyicisi |
| 345 | **LLM04:2025 Data and Model Poisoning** | Veri kökeni, eğitim/veri zinciri, görsel bozulma | Tamamen sentetik küçük veri/görsel kalite kontrolü |
| 346 | **LLM02 Sensitive Information Disclosure + LLM07 System Prompt Leakage** | Sır saklama, PII minimizasyonu, olay müdahale | Sentetik loglarla sızıntı olayı ve IR playbook'u |
| 347 | **LLM05:2025 Improper Output Handling** | Şema, çıkış validasyonu, fail-closed | Sahte AI JSON çıktısı için güvenli validator |
| 348 | NICE AI Security görev/bilgi/beceri | Yetkinlik ve sorumluluk sınırı | Kariyer ve beceri kontrol matrisi |
| 349 | **LLM10:2025 Unbounded Consumption** + RAG + görsel AI | İşlem limiti, boyut sınırı, belge/görsel doğrulama | Yerel mock servis: limit/timeout/girdi doğrulama |
| 350 | NIST/OWASP ilişkilendirilmiş kalite özeti | Gizlilik, yetki, kaynak, doğruluk, kanıt | Bağımsız sentetik kontrol paketi ve rapor |

## 2. Her AI Security günü için zorunlu risk bakış açısı

1. **Tehdit yüzeyi:** Kullanıcı girdisi, RAG dokümanı, embedding indeksi, model/adapter ağırlığı, araç çağrısı, görüntü/OCR metni, log veya bağımlılık.
2. **Güven sınırı:** Güvenilmeyen içerik ile sistem yönergesi/araç yetkisi/kullanıcı verisi arasındaki ayrım.
3. **Savunma:** Allowlist, JSON şema validasyonu, kaynak erişim kontrolü, model SHA-256, en az ayrıcalık, oran sınırı, timeout, hassas veri maskesi, insan onayı.
4. **Tespit:** Reddedilmiş işlem günlüğü, uyumsuz hash, hatalı kaynak kimliği, kural ihlali, beklenmedik izin, maskelenmeyen sahte PII.
5. **Test:** Bir kabul edilen benign fixture + bir reddedilen zararsız negatif fixture. Geri dönüş/recovery adımı ve durdurma koşulu.

## 3. Offline örneklerin sınırları

- **Prompt injection:** İki satırlık zararsız sahte belgeyle veri/talimat ayrımı test edilir. Demo gerçek bir LLM'in tam güvenlik özelliklerini ispatlamaz; “tehdit modelleme/policy-gate öğretimi” diye etiketlenir.
- **RAG:** Üç sentetik düz metin belgesi, kaynak kimliği, erişim sınıfı ve SHA-256 ile kontrol edilir. Gerçek embeddings modeli zorunlu değildir; izin/köken denetimi local mock'ta yürütülür.
- **Ajan araçları:** Disk silme, ağ gönderme veya dış servis erişimi yapılmaz. Araç çağrısı yalnız `ALLOW`, `DENY`, `REVIEW` durumları dönen sahte işlevdir.
- **Model bütünlüğü:** Yalnızca inert/sentetik dosya ve checksum; güvenilmeyen pickle veya zararlı model loader'ı çalıştırılmaz.
- **Hassas veri ve sistem promptu:** Yalnızca hayalî anahtar etiketleri, gerçek API key/parola/PII yok.
- **Görsel AI:** Gerçek kişisel yüz fotoğrafları veya biyometrik veriler kullanılmaz. Sentetik örnek üzerinde metaveri/girdi boyutu/sahte OCR çıktısı kontrol edilir.
- **Kaynak tüketimi:** Gerçek DoS yükü oluşturulmaz; mock istek sayacıyla offline limit/timeout kuralı kanıtlanır.

## 4. AI Security gün şablonuna özel zorunluluk

Standart `ders.md`, `soru_cevap.md`, `uygulama/`, `tests/`, `rapor.md`, `manifest.json` dosyalarına ek olarak:

```text
ai_threat_model.md      # Varlıklar, trust boundary, saldırı yolu, etki
policy.json             # İzinler / koşullar / sınırlar
risk_kontrol_matrisi.csv# Risk -> kontrol -> test -> bulgu
```

Gerçek model çalışmıyorsa risk/kontrol testinin yalnız policy mock düzeyinde olduğu raporlanır. Uydurma LLM cevabı gerçek model test çıktısı olarak kullanılmaz. Başarısız test ve kaçırılan kontrolleri HOLD olarak kaydet.

## 5. Yetkinlik ve sertifikasyon notu

Bu modül NIST AI RMF, NIST GenAI Profile, NICE AI Security ve OWASP LLM Top 10:2025 kavramlarına dayanır; **tek başına resmî sertifikasyon veya AI Security uzmanlığı belgesi değildir**. Uzmanlaşma için daha sonra 366–455 döneminde ayrı 90 günlük yol seçilebilir.

**Referanslar:**
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST GenAI Profile (AI 600-1): https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OWASP LLM Top 10:2025: https://genai.owasp.org/llm-top-10/
- NIST NICE Current Versions: https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions
