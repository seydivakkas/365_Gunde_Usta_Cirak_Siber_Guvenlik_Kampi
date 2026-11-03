# Bu betik bilerek güvenlik kusurları ve anti-pattern'lar içerir (Denetim testi için)
import os

API_KEY = "admin_super_secret_key_123456"

def run_user_code(user_input):
    # CWE-95: Kod enjeksiyonu riski
    eval(user_input)

def faulty_operation():
    try:
        x = 1 / 0
    except:
        # CWE-391: Hataları sessizce yutma
        pass

print("Script executed with flaws")
