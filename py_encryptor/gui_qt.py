import sys
from pathlib import Path
from typing import Type

import PySide6
from PySide6.QtGui import QFont, QDropEvent
from PySide6.QtWidgets import *

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm  # prevent circular import
from py_encryptor.utils.manager import AlgorithmsManager


class EncryptorFrame(QFrame):
    def __init__(self, parent=None):
        super(EncryptorFrame, self).__init__(parent)
        self.setAcceptDrops(True)

        # File selector
        self.file_layout = QHBoxLayout()
        self.file_field = QLineEdit()
        self.file_field.setPlaceholderText("Ścieżka do pliku")
        self.file_select_btn = QPushButton("Wybierz plik")
        self.file_select_btn.clicked.connect(lambda: self.file_field.setText(QFileDialog.getOpenFileName(self)[0]))

        self.file_layout.addWidget(self.file_field)
        self.file_layout.addWidget(self.file_select_btn)

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Hasło")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        # Algorithms
        self.algorithms = AlgorithmsManager.available_algorithms
        self.algorithms_box = QComboBox()
        for alg_cls in AlgorithmsManager.available_algorithms:
            self.algorithms_box.addItem(alg_cls.display_name(), userData=alg_cls)

        # Encrypt, decrypt actions
        self.button_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Zaszyfruj")
        self.encrypt_btn.clicked.connect(self.encrypt)
        self.decrypt_btn = QPushButton("Odszyfruj")
        self.button_layout.addWidget(self.algorithms_box, 1)
        self.button_layout.addWidget(self.encrypt_btn, 1)
        self.button_layout.addWidget(self.decrypt_btn, 1)

        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addLayout(self.file_layout)
        layout.addWidget(self.password_input)
        layout.addLayout(self.button_layout)
        # Set dialog layout
        self.setLayout(layout)

    def encrypt(self):
        cryp = self.getCryp()
        cryp.encrypt()
        self.actionSucessful("Pomyślnie zaszyfrowano plik!")

    def getCryp(self):
        try:
            alg: Type[BaseEncryptionAlgorithm] = self.algorithms_box.currentData()
            cryp = alg(self.password_input.text(), Path(self.file_field.text()))
            print(cryp)
            return cryp
        except ValueError as e:
            QMessageBox.critical(self, e.__class__.__name__, str(e), QMessageBox.StandardButton.Close)
        except Exception as e:
            QMessageBox.critical(self, "Nieznany błąd!", "Podczas wykonywania programu pojawił się nieznany błąd!")
            raise e

    def dragEnterEvent(self, event: PySide6.QtGui.QDragEnterEvent) -> None:
        event.accept()

    def dropEvent(self, event: PySide6.QtGui.QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.file_field.setText(url.toLocalFile())
                return

    def actionSucessful(self, msg: str):
        QMessageBox.information(self, "Sukces!", msg, QMessageBox.StandardButton.Ok)


if __name__ == '__main__':
    # Create the Qt Application
    app = QApplication(sys.argv)
    # Create and show the form
    form = EncryptorFrame()
    form.show()
    form.setWindowTitle("Python encryption tool")
    form.resize(500, form.size().height())
    form.setFixedHeight(form.size().height())
    # Run the main Qt loop
    sys.exit(app.exec())
