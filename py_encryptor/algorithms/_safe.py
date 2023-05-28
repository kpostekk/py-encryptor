from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1
from Cryptodome.Util.Padding import pad

from py_encryptor.algorithms.base import EncryptionAlgorithm


class Aes256EAX(EncryptionAlgorithm):
    def __init__(self, key: str, file_path: Path):
        if len(key) < 8:
            raise ValueError('Key must be at least 8 characters long!')

        super().__init__(key, file_path)

        self.nonce = self.__create_nonce(key)
        self.cipher = self.__create_cipher(key, self.nonce)

    @staticmethod
    def __create_nonce(future_key: str):
        nonce = SHA1.new()
        nonce.update(future_key.encode('utf-8'))
        return nonce.digest()

    @staticmethod
    def __create_cipher(key: str, nonce: bytes):
        return AES.new(pad(key.encode('utf-8'), 32), AES.MODE_EAX, nonce=nonce)

    def encrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.cipher.encrypt(data))

    def decrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_decryption_output_path(), 'wb') as f:
            f.write(self.cipher.decrypt(data))

    @classmethod
    def display_name(cls):
        return 'AES-256 (EAX)'
