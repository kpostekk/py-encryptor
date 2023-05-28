import click

from py_encryptor import Cryptor


@click.group()
def cli():
    pass


@cli.command()
@click.option('--file', '-f', help='File to encrypt')
@click.option('--passwd', '-p', help='Password to encrypt file')
def encrypt(file, passwd):
    c = Cryptor(passwd, file)
    c.encrypt()


@cli.command()
@click.option('--file', '-f', help='File to decrypt')
@click.option('--passwd', '-p', help='Password to decrypt file')
def decrypt(file, passwd):
    c = Cryptor(passwd, file)
    c.decrypt()


if __name__ == '__main__':
    cli()
