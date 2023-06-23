from pathlib import Path

import click

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.manager import AlgorithmsManager


@click.group()
def cli():
    pass


algs_names = [x.__name__ for x in AlgorithmsManager.available_algorithms]


def get_alg_by_name(name: str):
    for alg in AlgorithmsManager.available_algorithms:
        if alg.__name__ == name:
            return alg

    raise ValueError()


@cli.command()
@click.option('--alg', '-a', help="Encryption algorithm", type=click.Choice(algs_names))
@click.option('--docs', '-s', help='File to encrypt')
@click.option('--target', '-t', help="File to store encrypted data")
@click.option('--passwd', '-p', help='Password to encrypt file')
def encrypt(alg, source, target, passwd):
    c = get_alg_by_name(alg)(passwd, Path(source))
    c.encrypt(Path(target))
    print("Done!")


@cli.command()
@click.option('--alg', '-a', help="Encryption algorithm", type=click.Choice(algs_names))
@click.option('--docs', '-s', help='File to decrypt')
@click.option('--target', '-t', help="File to store decrypted data")
@click.option('--passwd', '-p', help='Password to decrypt file')
def decrypt(alg, source, target, passwd):
    c = get_alg_by_name(alg)(passwd, Path(source))
    c.decrypt(Path(target))
    print("Done!")


if __name__ == '__main__':
    cli()
