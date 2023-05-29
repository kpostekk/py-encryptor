import base64
from pathlib import Path

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.decorators import register_algorithm


@register_algorithm
class CaesarBase64(BaseEncryptionAlgorithm):
    """This cipher encodes the file using Base64 and then shifts the characters by the key."""

    # base64url alphabet
    _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

    def __init__(self, key: str, file_path: Path):
        super().__init__(key, file_path)
        # base64url alphabet
        try:
            self.key = int(key)
        except Exception as e:
            raise ValueError("Provided key is not a valid Caesar key!")

    def __caesar(self, data: str, key: int):
        result = ''
        for char in data:
            if char in self._alphabet:
                result += self._alphabet[(self._alphabet.index(char) + key) % len(self._alphabet)]
            else:
                result += char
        return result

    def encrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.__caesar(
                base64.urlsafe_b64encode(data).decode('utf-8'),
                self.key).encode('utf-8')
                    )

    def decrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_decryption_output_path(), 'wb') as f:
            f.write(base64.urlsafe_b64decode(
                self.__caesar(data.decode('utf-8'), -self.key)
            ))

    @classmethod
    def display_name(cls):
        return 'Caesar (Base64, Unsafe)'


@register_algorithm
class VigenereBase64(BaseEncryptionAlgorithm):
    def __init__(self, key: str, file_path: Path):
        super().__init__(key, file_path)

    def __vigenere(self, data: str):
        result = ''
        for i, char in enumerate(data):
            result += chr((ord(char) + ord(self.key[i % len(self.key)])) % 256)
        return result

    def __vinere_decrypt(self, data: str):
        result = ''
        for i, char in enumerate(data):
            result += chr((ord(char) - ord(self.key[i % len(self.key)])) % 256)
        return result

    def encrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.__vigenere(
                base64.urlsafe_b64encode(data).decode('utf-8')).encode('utf-8')
                    )

    def decrypt(self, target_path: Path | None = None):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(target_path or self._gen_decryption_output_path(), 'wb') as f:
            f.write(base64.urlsafe_b64decode(
                self.__vinere_decrypt(data.decode('utf-8'))
            ))

    @classmethod
    def display_name(cls):
        return 'Vigenere (Base64, Unsafe)'
