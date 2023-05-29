from pathlib import Path
from typing import Type

import PySimpleGUI as sg

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.manager import AlgorithmsManager

available_algorithms: list[Type[BaseEncryptionAlgorithm]] = AlgorithmsManager.available_algorithms

# Create a gui for encrypt/decrypt app

layout = [
    [sg.Text('Select a file to encrypt/decrypt:')],
    [sg.Input(key='file'), sg.FileBrowse()],
    [sg.Text('Enter a password:')],
    [sg.InputText(key='passwd', password_char='*')],
    [sg.Text(key='status', visible=False)],
    [sg.Combo([alg.display_name() for alg in available_algorithms], key='alg-combo', default_value='AES-256 (EAX)')],
    [sg.Button('Encrypt', key='encrypt'), sg.Button('Decrypt', key='decrypt')],
]

window = sg.Window('Encrypt/Decrypt', layout)
c = None


def get_algorithm_by_name(name: str) -> Type[BaseEncryptionAlgorithm]:
    for alg in available_algorithms:
        if alg.display_name() == name:
            return alg
    raise ValueError(f'No algorithm found with name {name}')


def main():
    while True:
        event, values = window.read()
        print(event, values)

        if event == sg.WIN_CLOSED:
            break

        if values['passwd'] is None or values['file'] is None:
            continue

        try:
            alg = get_algorithm_by_name(values['alg-combo'])
            crypt = alg(values['passwd'], Path(values['file']))

            if event == 'encrypt':
                window['status'].update('Encrypting...', visible=True)
                crypt.encrypt()
                window['status'].update('Done!', visible=True)
            if event == 'decrypt':
                window['status'].update('Decrypting...', visible=True)
                crypt.decrypt()
                window['status'].update('Done!', visible=True)
        except Exception as e:
            sg.popup_error(str(e), title=type(e).__name__,)


if __name__ == '__main__':
    main()
