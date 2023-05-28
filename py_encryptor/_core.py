import abc
import base64
import pathlib

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1
from pathlib import Path

from Cryptodome.Util.Padding import pad


class EncryptionAlgorithm(abc.ABC):
    def __init__(self, key: str, file_path: Path):
        if not file_path.is_file():
            raise ValueError('"file_path" must be a file!')

        self.file_path = file_path
        self.key = key

    def _gen_encryption_output_path(self):
        file_dir = self.file_path.parent
        output_dir = Path.joinpath(file_dir, '_pyen')

        if not output_dir.exists():
            output_dir.mkdir()

        return Path.joinpath(output_dir, self.file_path.name)

    def _gen_decryption_output_path(self):
        file_dir = self.file_path.parent
        output_dir = Path.joinpath(file_dir, '_pyde')

        if not output_dir.exists():
            output_dir.mkdir()

        return Path.joinpath(output_dir, self.file_path.name)

    @abc.abstractmethod
    def encrypt(self):
        pass

    @abc.abstractmethod
    def decrypt(self):
        pass

    @classmethod
    def display_name(cls):
        return cls.__name__


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


class CaesarBase64(EncryptionAlgorithm):
    """This cipher encodes the file using Base64 and then shifts the characters by the key."""

    def __init__(self, key: str, file_path: Path):
        super().__init__(key, file_path)
        # base64url alphabet
        self.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        self.key = int(key)

    def __caesar(self, data: str, key: int):
        result = ''
        for char in data:
            if char in self.alphabet:
                result += self.alphabet[(self.alphabet.index(char) + key) % len(self.alphabet)]
            else:
                result += char
        return result

    def encrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.__caesar(
                base64.urlsafe_b64encode(data).decode('utf-8'),
                self.key).encode('utf-8')
                    )

    def decrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_decryption_output_path(), 'wb') as f:
            f.write(base64.urlsafe_b64decode(
                self.__caesar(data.decode('utf-8'), -self.key)
            ))

    @classmethod
    def display_name(cls):
        return 'Caesar (Base64)'


class VigenereBase64(EncryptionAlgorithm):
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

    def encrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_encryption_output_path(), 'wb') as f:
            f.write(self.__vigenere(
                base64.urlsafe_b64encode(data).decode('utf-8')).encode('utf-8')
                    )

    def decrypt(self):
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self._gen_decryption_output_path(), 'wb') as f:
            f.write(base64.urlsafe_b64decode(
                self.__vinere_decrypt(data.decode('utf-8'))
            ))

    @classmethod
    def display_name(cls):
        return 'Vigenere (Base64)'


"""
class Cryptor:
    def __init__(self, key, file_path):
        self.file_path = file_path
        self.key = None
        self.nonce = SHA1.new()
        self.nonce.update(key.encode('utf-8'))
        self.nonce = self.nonce.digest()
        self.set_key(key)

    def set_key(self, key):
        self.key = key
        rlren = 128 // 8
        if len(self.key) < rlren:
            self.key += '\x00' * (rlren - len(self.key))
        self.key = self.key.encode('utf-8')

    def encrypt(self):
        aes_key = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        with open(self.file_path, 'rb') as f:
            data = f.read()
        with open(self.file_path + '.pyen', 'wb') as f:
            f.write(aes_key.encrypt(data))

    def decrypt(self):
        aes_key = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        with open(self.file_path, 'rb') as f:
            data = f.read()

        new_filename = Path.joinpath(Path(self.file_path).parent, 'dec_' + Path(self.file_path).stem)
        with open(new_filename, 'wb') as fx:
            fx.write(aes_key.decrypt(data))
"""
