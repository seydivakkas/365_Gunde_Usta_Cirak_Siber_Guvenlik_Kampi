#!/usr/bin/env bash
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# G088: Güvenli Çıkış Kodu ve stderr Yönetimi Örnek Betiği
set -euo pipefail

# Tanımlı Çıkış Kodları Standartları
readonly EXIT_SUCCESS=0      # Başarılı tamamlanma
readonly EXIT_INVALID_ARG=1  # Geçersiz argüman hatası
readonly EXIT_FILE_NOT_FOUND=2  # Dosya bulunamadı hatası
readonly EXIT_PIPELINE_FAIL=3   # Boru hattı işlem hatası

# Hedef dosya parametresi
TARGET_FILE="${1:-}"

# 1. Argüman Doğrulama ve Çıkış Kodu Yönetimi
if [[ -z "${TARGET_FILE}" ]]; then
    echo "[HATA] Hedef dosya parametresi belirtilmedi." >&2
    exit "${EXIT_INVALID_ARG}"
fi

# 2. Dosya Varlığı Kontrolü ve Belirgin Hata Çıkışı
if [[ ! -f "${TARGET_FILE}" ]]; then
    echo "[HATA] Belirtilen dosya mevcut değil: ${TARGET_FILE}" >&2
    exit "${EXIT_FILE_NOT_FOUND}"
fi

# 3. Boru Hattı Güvenliği ve PIPESTATUS Denetimi
# pipefail aktif olduğu için ara komut hatası yakalanır
if grep -i "FATAL" "${TARGET_FILE}" | wc -l > /dev/null; then
    echo "[BİLGİ] Dosya taraması tamamlandı, kritik hata bulunamadı."
else
    # PIPESTATUS dizisi incelenir
    pipe_status=("${PIPESTATUS[@]}")
    echo "[HATA] Boru hattı başarısız oldu (Durumlar: ${pipe_status[*]})" >&2
    exit "${EXIT_PIPELINE_FAIL}"
fi

echo "[BAŞARILI] Tüm kontroller başarıyla tamamlandı."
exit "${EXIT_SUCCESS}"
