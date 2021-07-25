from cryptography.fernet import Fernet
import kdf_pswrd as KDFpswrd


# this function will return bytes
def encrypt(plain_message: str, key: str, enctype='utf-8'):
    f = Fernet(KDFpswrd.PSWRDchiper(key))
    return f.encrypt(plain_message.encode(encoding=enctype))


# this function will return bytes
def decrypt(enc_message: bytes, key: str, enctype='utf-8'):
    f = Fernet(KDFpswrd.PSWRDchiper(key))
    return f.decrypt(enc_message)


if __name__ == "__main__":
    message = input("Enter your secret text: ")
    password = input("Enter your password: ")
    enc_msg = encrypt(message, password)
    print("Encrypted data : ", enc_msg.decode(encoding='utf-8'))
    dec_msg = decrypt(enc_msg, password)
    print("Decrypted data : ", dec_msg.decode(encoding='utf-8'))