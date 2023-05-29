from typing import Type

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm


# from py_encryptor.algorithms.base import BaseEncryptionAlgorithm


class AlgorithmsManager:
    available_algorithms: list[Type['BaseEncryptionAlgorithm']] = []

    @classmethod
    def add_available_algorithm(cls, alg: Type['BaseEncryptionAlgorithm']):
        if not issubclass(alg, BaseEncryptionAlgorithm):
            raise ValueError("Invalid class!")

        cls.available_algorithms.append(alg)
