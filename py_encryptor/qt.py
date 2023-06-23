import sys
import typing
from pathlib import Path
from typing import Type

import PySide6.QtCore
from PySide6.QtGui import QFont
from PySide6.QtWidgets import *

from py_encryptor.algorithms.base import BaseEncryptionAlgorithm  # prevent circular import
from py_encryptor.utils.manager import AlgorithmsManager


class EncryptorFrame(QFrame):
    def __init__(self, parent=None):
        super(EncryptorFrame, self).__init__(parent)
        self.setAcceptDrops(True)

        # File selector (source)
        self.file_source_layout = QHBoxLayout()
        self.file_source_field = QLineEdit()
        self.file_source_field.setPlaceholderText("Ścieżka do pliku")
        self.file_source_select_btn = QPushButton("Wybierz plik")
        self.file_source_select_btn.clicked.connect(self.requestFile(self.file_source_field))

        self.file_source_layout.addWidget(self.file_source_field)
        self.file_source_layout.addWidget(self.file_source_select_btn)

        # File selector (target)
        self.file_target_layout = QHBoxLayout()
        self.file_target_field = QLineEdit()
        self.file_target_field.setPlaceholderText("Ścieżka do pliku")
        self.file_target_select_btn = QPushButton("Wybierz plik")
        self.file_target_select_btn.clicked.connect(self.requestFile(self.file_target_field))
        # self.file_target_select_btn.clicked.connect(se)

        self.file_target_layout.addWidget(self.file_target_field)
        self.file_target_layout.addWidget(self.file_target_select_btn)

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
        self.encrypt_btn.clicked.connect(self.encrypt_decrypt("encrypt"))
        self.decrypt_btn = QPushButton("Odszyfruj")
        self.decrypt_btn.clicked.connect(self.encrypt_decrypt("decrypt"))

        self.button_layout.addWidget(self.algorithms_box, 1)
        self.button_layout.addWidget(self.encrypt_btn, 1)
        self.button_layout.addWidget(self.decrypt_btn, 1)

        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Plik wejściowy"))
        layout.addLayout(self.file_source_layout)
        layout.addWidget(QLabel("Plik wyjściowy"))
        layout.addLayout(self.file_target_layout)
        layout.addSpacing(10)
        layout.addWidget(self.password_input)
        layout.addLayout(self.button_layout)
        # Set dialog layout
        self.setLayout(layout)

    def _suggested_output_path(self):
        p = Path(self.file_source_field.text())
        fn = p.stem + ".encrypted" + p.suffix
        return str(Path.joinpath(p.parent, fn))

    def requestFile(self, result_target: QLineEdit):
        def wrapped():
            filepath, _ = QFileDialog.getOpenFileName(self)
            # print(filepath)
            result_target.setText(filepath)

            if result_target is self.file_source_field:
                self.file_target_field.setText(self._suggested_output_path())

        return wrapped

    def encrypt_decrypt(self, mode: typing.Literal["encrypt", "decrypt"]):
        def wrapped():
            if Path(self.file_target_field.text()).exists():
                decision = QMessageBox.warning(self, "Plik już istnieje!",
                                               "Czy chcesz nadpisać plik " + self.file_target_field.text() + " ?",
                                               QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.Cancel)
                if decision == 4194304:
                    return

            cryp = self.getCryp()
            if mode == "encrypt":
                cryp.encrypt(Path(self.file_target_field.text()))
            elif mode == "decrypt":
                cryp.decrypt(Path(self.file_target_field.text()))
            else:
                raise ValueError()
            self.actionSucessful("Pomyślnie zaszyfrowano plik!")

        return wrapped

    def getCryp(self):
        try:
            alg: Type[BaseEncryptionAlgorithm] = self.algorithms_box.currentData()
            cryp = alg(self.password_input.text(), Path(self.file_source_field.text()))
            # print(cryp)
            return cryp
        except ValueError as e:
            QMessageBox.critical(self, e.__class__.__name__, str(e), QMessageBox.StandardButton.Close)
            return
        except Exception as e:
            QMessageBox.critical(self, "Nieznany błąd!", "Podczas wykonywania programu pojawił się nieznany błąd!")
            raise e

    def dragEnterEvent(self, event: PySide6.QtGui.QDragEnterEvent) -> None:
        event.accept()

    def dropEvent(self, event: PySide6.QtGui.QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.file_source_field.setText(url.toLocalFile())
                self.file_target_field.setText(self._suggested_output_path())
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
    form.resize(400, form.size().height())
    form.setFixedHeight(form.size().height())
    # Run the main Qt loop
    sys.exit(app.exec())
