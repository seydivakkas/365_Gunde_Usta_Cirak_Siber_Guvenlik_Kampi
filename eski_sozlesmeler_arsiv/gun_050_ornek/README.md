# Gün 050 bağımsız offline TCP kontrol bayrağı eğitim örneği

Kodun amacı SYN → SYN-ACK → ACK sırasını **gerçek paket göndermeden** doğrulayan bir eğitim modeli oluşturmaktır. Yalnız standart Python kütüphanesi kullanılır; ağ erişimi veya API anahtarı gerekmez. Gerçek TCP yığını değildir.

Windows PowerShell:

```powershell
py -3 .\uygulama\tcp_handshake_sim.py
py -3 -m unittest discover -s .\tests -v
```

Linux/Python:

```bash
python uygulama/tcp_handshake_sim.py
python -m unittest discover -s tests -v
```

Orijinal çalıştırma ortamında Python `unittest`: 5/5 PASS. Windows/Edge fiziksel test edilmedi. Kod AI tarafından üretildi; günlük eğitim standardı için örnektir.
