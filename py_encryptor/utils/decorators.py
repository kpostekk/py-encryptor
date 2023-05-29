from typing import Type

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.manager import AlgorithmsManager


def register_algorithm(cls: Type[BaseEncryptionAlgorithm]):
    AlgorithmsManager.add_available_algorithm(cls)
    return cls
