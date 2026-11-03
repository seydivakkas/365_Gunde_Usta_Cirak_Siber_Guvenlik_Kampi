# GÜN 082: PYTEST İLE BİRİM TESTLERİ — GÜVENLİK TEST MÜHENDİSLİĞİ
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

---

## 1. USTANIN GİRİŞİ: TESTİ OLMAYAN KOD GÜVENİLİR DEĞİLDİR

Evladım, siber güvenlikte "ben koduma güveniyorum, düzgün yazdım" sözü kadar içi boş bir cümle yoktur. Bir kodun güvenilirliği, senin ona olan inancınla değil; **sınır uçlarında, beklenmeyen girdiler altında ve kötü niyetli saldırı senaryoları karşısında gösterdiği dirençle** ölçülür.

Geçmiş günlerde Python'un standart `unittest` modülünü gördün. `unittest`, Java'nın JUnit mirasından gelen nesne yönelimli, katı ve hiyerarşik bir yapıdır (`TestCase` sınıfları, `self.assertEqual` metotları). Ancak modern güvenlik mühendisliğinde, özellikle yüzlerce saldırı vektörünü (fuzzing payload, boundary overflow, injection matrix) seri şekilde denemek istediğinde `unittest` hantal kalır.

İşte bu noktada sahneye **`pytest`** çıkar:
- Boilerplate (gereksiz kalıp) kodları yok eder; saf Python fonksiyonları ve `assert` ifadeleriyle çalışır.
- **Fixtures (Fikstürler):** Bağımlılık enjeksiyonu (Dependency Injection) ile test ortamlarını, geçici dizinleri ve sahte güvenlik durumlarını deterministik olarak kurar ve temizler.
- **Parametrize (Parametrik Test):** Tek bir test fonksiyonunu, onlarca farklı zararlı girdi ve sınır değeriyle bir saniyede defalarca koşturur.
- **`pytest.raises`:** Sadece hatanın türünü değil, hata mesajının sızıntısızlığını regex ile sınar.

Bugünkü dersimizde; kurumsal bir **Güvenlik Politikası Yürütme Motorunu (Security Policy Enforcer)** `pytest` altyapısıyla en zorlu negatif testlerden geçireceğiz.

---

## 2. UNITTEST VS PYTEST: GÜVENLİK MÜHENDİSİNİN TERCİHİ

### 2.1. Assert İntrospeksiyonu (Assertion Rewriting)
`unittest` içinde `self.assertEqual(a, b)` veya `self.assertIn(x, y)` yazmak zorundasın. Eğer eşitlik bozulursa aldığın çıktı kısıtlıdır.
`pytest` ise Python'un yerel `assert a == b` ifadesini AST (Abstract Syntax Tree) düzeyinde yeniden yazar. Test başarısız olduğunda, ifadenin her iki tarafındaki alt bileşenleri ekrana döker:
```text
>       assert classify_security_incident(score) == expected_level
E       AssertionError: assert 'MEDIUM' == 'HIGH'
E         - HIGH
E         + MEDIUM
```
Bu yetenek, özellikle karmaşık güvenlik kurallarının nerede kırıldığını tespit etmede analiste muazzam zaman kazandırır.

### 2.2. Yalınlık ve Fonksiyonel Tasarım
`TestCase` sınıfları ve `setUp`/`tearDown` metotları yerine; sadece bağımsız `test_*` fonksiyonları yazılır. Testler birbirini etkilemez, küresel durum kirliliği oluşmaz.

---

## 3. PYTEST FİKSTÜRLERİ (FIXTURES): DETERMINİSTİK GÜVENLİK ORTAMI

Güvenlik testlerinde en büyük risk, testlerin birbirinin ardında bıraktığı artık verilerden (state pollution) etkilenmesidir. Örneğin bir test oturum açar, ikinci test o açık oturumu kullanarak yanlışlıkla geçer (False Positive).

`pytest` fikstürleri (`@pytest.fixture`), her test fonksiyonuna özel, temiz ve izole nesneler sağlar:

```python
@pytest.fixture
def policy_enforcer() -> SecurityPolicyEnforcer:
    """Her test için sıfır sayaçlı bağımsız bir yürütücü sağlar."""
    return SecurityPolicyEnforcer(max_requests_per_client=5)

def test_rate_limiting(policy_enforcer):
    # Bu testteki istekler diğer testlerin sayacını asla etkilemez!
    policy_enforcer.execute_policy_check(...)
```

Fikstürler `yield` anahtar kelimesiyle `tearDown` temizliğini de deterministik kılar:
```python
@pytest.fixture
def isolated_sandbox(tmp_path):
    sandbox_dir = tmp_path / "secure_vault"
    sandbox_dir.mkdir()
    yield sandbox_dir
    # Test bittiğinde otomatik temizlik çalışır
```

---

## 4. PARAMETRİK TESTLER (`@pytest.mark.parametrize`): SALDIRI MATRİSLERİ

Siber güvenlikte bir kuralı tek bir örnekle test etmek yetmez. Parola politikasını sınıyorsan; büyük harfi eksik, küçük harfi eksik, rakamı eksik, sembolü eksik ve kısa olan tüm kombinasyonları denemelisin.

`unittest` içinde bunu yapmak için ya döngü kurarsın (birinde patlarsa diğerleri koşmaz) ya da 10 ayrı test yazarsın. `pytest` ile tek bir fonksiyon onlarca test haline gelir:

```python
@pytest.mark.parametrize(
    "score, expected_level",
    [
        (0, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (69, "MEDIUM"),
        (70, "HIGH"),
        (89, "HIGH"),
        (90, "CRITICAL"),
        (100, "CRITICAL"),
    ]
)
def test_boundaries(score, expected_level):
    assert classify_security_incident(score) == expected_level
```
Bu kod tek başına **8 bağımsız test senaryosu** üretir. Biri başarısız olsa bile diğer 7'si koşmaya devam eder ve tam rapor sunulur.

---

## 5. İSTİSNA DENETİMİ: `pytest.raises` İLE KATI HATA KONTROLÜ

Savunmacı programlamada sistemin beklenen hataları doğru zamanda ve güvenli mesajlarla fırlattığını doğrulamak hayati önem taşır.
`pytest.raises` hem istisnanın tipini hem de hata mesajını regex (`match`) ile doğrular:

```python
with pytest.raises(PolicyViolationException, match="geçersiz yol karakterleri"):
    sanitize_target_domain("evil.com/../../etc/passwd")
```
Eğer fonksiyon hiç hata fırlatmazsa veya fırlattığı hata mesajı "geçersiz yol karakterleri" içermiyorsa, test başarısız sayılır. Böylece hem sessiz geçiştirme (fail-open) hem de yanlış hata mesajı üretimi engellenir.

---

## 6. ÖZEL İŞARETLEYİCİLER (CUSTOM MARKERS) VE TEST ORGANİZASYONU

Geniş kurumsal projelerde binlerce test bulunur. CI/CD boru hattında hızlı testleri veya yalnızca güvenlik odaklı testleri koşmak için işaretleyiciler (markers) kullanılır:
- `@pytest.mark.security`: Güvenlik politikası ve kriptografik doğrulamalar.
- `@pytest.mark.negative`: Kötü niyetli girdi ve sınır aşımı kontrolleri.
- `@pytest.mark.slow`: Uzun süren simülasyon ve ağ testleri.

`conftest.py` dosyasında bu işaretleyiciler resmi olarak kaydedilir:
```python
def pytest_configure(config):
    config.addinivalue_line("markers", "security: siber güvenlik testleri")
    config.addinivalue_line("markers", "negative: negatif saldırı senaryoları")
```
Terminalden çalıştırma kolaylığı:
```powershell
python -m pytest -m "security and negative" -v
```

---

## 7. ÖZET VE USTADAN ÇIRAĞA TAVSİYELER

1. **Testini Yazmadığın Kural Yok Hükmündedir:** Bir güvenlik politikasını koda döktüysen, o kuralın tersini (ihlal senaryosunu) parametrik olarak sınamadan "bitti" diyemezsin.
2. **Sınır Değerleri (Boundary Values) Saldırganın İlk Baktığı Yerdir:** 0, 39, 40, 69, 70, 89, 90, 100... Sınırın tam üstü ve tam altı her zaman en zayıf halkadır.
3. **Fikstürleri Silahın Yap:** Test ortamının temizliğinden asla ödün verme. Her test bağımsız doğmalı, bağımsız yaşamalı ve arkasında iz bırakmadan ölmelidir.
4. **`pytest` Disiplini:** Kısa, okunabilir, parametrik ve assert introspeksiyonuna dayalı testler yaz.
