from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Crypto(object):
    KEY = get_random_bytes(16)
    ENCRYPTION = AES.new(KEY, AES.MODE_EAX)
    NONCE = ENCRYPTION.nonce

    @staticmethod
    def _getKey():
        return Crypto.KEY

    @staticmethod
    def _getNonce():
        return Crypto.NONCE

    @staticmethod
    def encrypt(s):
        ciphertext, tag = Crypto.ENCRYPTION.encrypt_and_digest(memoryview(s.encode('utf-8')))
        return b64encode(ciphertext), b64encode(tag)

    @staticmethod
    def decrypt(encoded, tag, key, nonce):
        DECRYPTION = AES.new(key, AES.MODE_EAX, nonce=nonce)
        ciphertext, tag = b64decode(encoded), b64decode(tag)
        return DECRYPTION.decrypt_and_verify(ciphertext, tag)