#!/bin/sh
# ÖZEL LİSANS — TÜM HAKLAR SAKLIDIR
# Telif Hakkı (c) 2026 Seydi Eryılmaz (@seydivakkas)
# Bu yazılım ve ilgili tüm dosyalar ("Yazılım") yalnızca görüntüleme ve eğitim amaçlı olarak paylaşılmıştır.
# YASAKLAR: Kopyalanamaz, çoğaltılamaz, dağıtılamaz, değiştirilemez, satılamaz, tersine mühendislik yapılamaz.
# İZİN VERİLEN KULLANIM: GitHub üzerinde görüntüleme ve inceleme (kopyalamadan).
# YAZARIN AÇIK YAZILI İZNİ OLMAKSIZIN HİÇBİR KULLANIM HAKKI TANINMAZ.

# ZAAFİYET 1: Katı mod yok (Missing set -euo pipefail). Hatalar görmezden gelinir.
# ZAAFİYET 2: IFS ayarlanmamış (Varsayılan boşluk, sekme, yeni satır kelimeleri böler).
# ZAAFİYET 3: Trap ve hata yakalama tanımlanmamış.

TARGET_DIR=$1  # Tırnaksız atama
USER_COMMAND=$2  # Dışarıdan gelen komut

# ZAAFİYET 4: Tırnaksız değişken genişletmesi (CWE-78 / CWE-732). Eğer TARGET_DIR boşsa "rm -rf /*" felaketi!
rm -rf $TARGET_DIR/*

# ZAAFİYET 5: eval ile dinamik komut yürütme (CWE-78: OS Command Injection)
eval $USER_COMMAND

# ZAAFİYET 6: ls çıktısı üzerinde tırnaksız döngü (Word Splitting ve Globbing)
for f in $(ls $TARGET_DIR); do
    echo "Dosya: " $f
done

# ZAAFİYET 7: Tırnaksız argüman aktarımı (Word Splitting)
echo Argumanlar: $*
