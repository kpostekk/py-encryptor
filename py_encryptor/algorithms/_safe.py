from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1
from Cryptodome.Util.Padding import pad, unpad

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.decorators import register_algorithm


@register_algorithm
class Aes256EAX(BaseEncryptionAlgorithm):
    def __init__(self, key: str, file_path: Path):
        if len(key) < 8:
            raise ValueError('Key must be at least 8 characters long!')

        super().__init__(key, file_path)

        self.nonce = self._create_nonce(key)
        self.cipher = self._create_cipher(key, self.nonce)

    @staticmethod
    def _create_nonce(future_key: str):
        nonce = SHA1.new()
        nonce.update(future_key.encode('utf-8'))
        return nonce.digest()

    @staticmethod
    def _create_cipher(key: str, nonce: bytes):
        return AES.new(pad(key.encode('utf-8'), 32), AES.MODE_EAX, nonce=nonce)

    def encrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.cipher.encrypt(data))

    def decrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_decryption_output_path(), 'wb') as f:
            f.write(self.cipher.decrypt(data))

    @classmethod
    def display_name(cls):
        return 'AES-256 (EAX)'


@register_algorithm
class Aes256CBC(Aes256EAX):
    @staticmethod
    def _create_cipher(key: str, nonce: bytes):
        return AES.new(pad(key.encode('utf-8'), 16), AES.MODE_CBC)

    @classmethod
    def display_name(cls):
        return 'AES-256 (CBC, Experimental)'

    def encrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.cipher.encrypt(pad(data, 16)))

    def decrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_decryption_output_path(), 'wb') as f:
            f.write(self.cipher.decrypt(data))
