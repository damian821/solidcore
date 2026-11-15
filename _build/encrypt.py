"""Перешифровать отчёт и обновить index.html.

    python3 _build/encrypt.py путь/к/Geostrata_Taldy.html ПАРОЛЬ

Пароль приводится к нижнему регистру (страница входа делает то же самое).
В index.html меняется только зашифрованное содержимое; экран входа остаётся прежним.
Нужен пакет cryptography.
"""
import os, re, sys, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

src = open(sys.argv[1], 'rb').read()
pw = sys.argv[2].strip().lower()
here = os.path.dirname(os.path.abspath(__file__))
page = os.path.join(here, '..', 'index.html')
salt, iv, IT = os.urandom(16), os.urandom(12), 600000
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, IT).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, src, None)
b = lambda x: base64.b64encode(x).decode()
t = open(page, encoding='utf-8').read()
t2 = re.sub(r'var S="[^"]*",I="[^"]*",N=\d+,C="[^"]*";',
            lambda m: f'var S="{b(salt)}",I="{b(iv)}",N={IT},C="{b(ct)}";', t, count=1)
assert t2 != t, 'не найдено место для шифра в index.html'
open(page, 'w', encoding='utf-8').write(t2)
print('готово:', len(src), 'байт зашифровано')
