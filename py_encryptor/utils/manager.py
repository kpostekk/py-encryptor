from typing import Type

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm


class AlgorithmsManager:
    """
    This class is used to manage and register available algorithms.
    """

    available_algorithms: list[Type[BaseEncryptionAlgorithm]] = []

    @classmethod
    def add_available_algorithm(cls, alg: Type[BaseEncryptionAlgorithm]):
        if not issubclass(alg, BaseEncryptionAlgorithm):
            raise ValueError("Invalid class! Must be subclass of BaseEncryptionAlgorithm!")

        cls.available_algorithms.append(alg)
