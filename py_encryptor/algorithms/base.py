import abc
from pathlib import Path


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