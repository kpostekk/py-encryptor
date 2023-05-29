from pathlib import Path
from typing import Type

import PySimpleGUI as sg

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm
from py_encryptor.utils.manager import AlgorithmsManager

available_algorithms: list[Type[BaseEncryptionAlgorithm]] = AlgorithmsManager.available_algorithms

# Create a gui for encrypt/decrypt app

sg.theme("Default")

layout = [
    [sg.Text('Select a source file:')],
    [sg.Input(key='file_source', enable_events=True, expand_x=True), sg.FileBrowse(key="file_source_picker", enable_events=True)],
    [sg.Text('Select a target (output) file:')],
    [sg.Input(key='file_target', expand_x=True), sg.FileBrowse()],
    [sg.Text('Enter a password:')],
    [sg.InputText(key='passwd', password_char='*', expand_x=True)],
    [sg.Text(key='status', visible=False)],
    [sg.Combo([alg.display_name() for alg in available_algorithms], key='alg-combo', default_value='AES-256 (EAX)')],
    [sg.Button('Encrypt', key='encrypt'), sg.Button('Decrypt', key='decrypt')],
]

window = sg.Window('Encrypt/Decrypt', layout, resizable=True)


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

        if event == 'file_source':
            p = Path(values['file_source'])
            fn = p.stem + "_encrypted" + p.suffix
            window['file_target'].update(str(Path.joinpath(p.parent, fn)))
            # values['file_target'] = str(Path.joinpath(p.parent, fn))

        if event not in ['encrypt', 'decrypt']:
            continue

        try:
            alg = get_algorithm_by_name(values['alg-combo'])
            crypt = alg(values['passwd'], Path(values['file_source']))

            if event == 'encrypt':
                window['status'].update('Encrypting...', visible=True)
                crypt.encrypt(Path(values['file_target']))
                window['status'].update('Done!', visible=True)
            if event == 'decrypt':
                window['status'].update('Decrypting...', visible=True)
                crypt.decrypt(Path(values['file_target']))
                window['status'].update('Done!', visible=True)
        except Exception as e:
            sg.popup_error(str(e), title=type(e).__name__, )


if __name__ == '__main__':
    main()
