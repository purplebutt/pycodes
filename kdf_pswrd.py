import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def PSWRDchiper(password: str, salt: str = "Garam Yodium", encoding='utf-8'):
    password_enc = password.encode(encoding=encoding)
    salt_enc = salt.encode(encoding=encoding)
    KDF = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt_enc,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(KDF.derive(password_enc))


if __name__ == "__main__":
    PASS = "admin123456"
    SALT = "Garam Yodium"
    x = PSWRDchiper(PASS, SALT)
    print(x)