# src/ui/scan_type_dialog.py

from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QPushButton, QVBoxLayout, QSpinBox,
    QMessageBox
)

class ScanTypeDialog(QDialog):
    def __init__(self, scan_type=None):
        super().__init__()
        self.setWindowTitle('Add/Edit Scan Type')
        self.scan_type = scan_type
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()

        self.name_input = QLineEdit()
        self.command_input = QLineEdit()
        self.description_input = QLineEdit()
        self.intensity_input = QSpinBox()
        self.intensity_input.setRange(1, 10)
        self.intensity_input.setValue(self.scan_type.get('intensity', 5) if self.scan_type else 5)

        form_layout = QFormLayout()
        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Command:", self.command_input)
        form_layout.addRow("Description:", self.description_input)
        form_layout.addRow("Intensity:", self.intensity_input)

        self.layout.addLayout(form_layout)

        self.save_button = QPushButton('Save')
        self.save_button.clicked.connect(self.validate_and_accept)

        self.layout.addWidget(self.save_button)
        self.setLayout(self.layout)

        if self.scan_type:
            self.name_input.setText(self.scan_type.get('name', ''))
            self.command_input.setText(self.scan_type.get('command', ''))
            self.description_input.setText(self.scan_type.get('description', ''))

    def get_scan_type(self):
        """Retrieves the scan type details from the input fields."""
        scan_type = {
            'name': self.name_input.text().strip(),
            'command': self.command_input.text().strip(),
            'description': self.description_input.text().strip(),
            'intensity': self.intensity_input.value()
        }
        return scan_type

    def validate_and_accept(self):
        """Validates the input and accepts the dialog if valid."""
        name = self.name_input.text().strip()
        command = self.command_input.text().strip()
        description = self.description_input.text().strip()

        if not name:
            QMessageBox.warning(self, 'Input Error', 'Name cannot be empty.')
            return
        if not command:
            QMessageBox.warning(self, 'Input Error', 'Command cannot be empty.')
            return
        if not description:
            QMessageBox.warning(self, 'Input Error', 'Description cannot be empty.')
            return

        self.accept()