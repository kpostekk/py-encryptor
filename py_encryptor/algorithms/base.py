import abc
from pathlib import Path


class BaseEncryptionAlgorithm(abc.ABC):
    """A base class for all encryption algorithms that can be used by gui."""
    def __init__(self, key: str, file_path: Path):
        """
        :type key: str
        :type file_path: Path
        :param key: symmetric encryption key
        :param file_path: source file path
        """
        if not file_path.is_file():
            raise ValueError('"file_path" must be a file!')

        self.file_path = file_path
        self.key = key

    def _gen_encryption_output_path(self):
        """Generates a fallback path for the encrypted file."""
        file_dir = self.file_path.parent
        output_dir = Path.joinpath(file_dir, '_pyen')

        if not output_dir.exists():
            output_dir.mkdir()

        return Path.joinpath(output_dir, self.file_path.name)

    def _gen_decryption_output_path(self):
        """Generates a fallback path for the decrypted file."""
        file_dir = self.file_path.parent
        output_dir = Path.joinpath(file_dir, '_pyde')

        if not output_dir.exists():
            output_dir.mkdir()

        return Path.joinpath(output_dir, self.file_path.name)

    @abc.abstractmethod
    def encrypt(self, target_path: Path | None = None):
        """Method that encrypts the file and saves it."""
        pass

    @abc.abstractmethod
    def decrypt(self, target_path: Path | None = None):
        """Method that decrypts the file and saves it."""
        pass

    @classmethod
    def display_name(cls):
        """Returns a name that will be displayed in the gui within selector."""
        return cls.__name__

    def __repr__(self):
        return f'<Encryption alg. "{self.__class__.__name__}">'
