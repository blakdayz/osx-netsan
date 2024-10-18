from PyQt5.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QComboBox, QPushButton, QVBoxLayout, QMessageBox
)

class AlertRuleDialog(QDialog):
    def __init__(self, rule:str=None):
        super().__init__()
        self.setWindowTitle('Add Alert Rule')
        self.init_ui()
        self.rule = rule

    def init_ui(self):
        self.layout = QVBoxLayout()

        self.host_input = QLineEdit()
        self.port_input = QLineEdit()
        self.criteria_input = QComboBox()
        self.criteria_input.addItems(['match_port', 'match_host'])

        form_layout = QFormLayout()
        form_layout.addRow('Host:', self.host_input)
        form_layout.addRow('Port:', self.port_input)
        form_layout.addRow('Criteria:', self.criteria_input)

        self.save_button = QPushButton('Add')
        self.save_button.clicked.connect(self.validate_and_accept)

        self.layout.addLayout(form_layout)
        self.layout.addWidget(self.save_button)
        self.setLayout(self.layout)

    def get_rule(self):
        rule = {
            'host': self.host_input.text(),
            'port': int(self.port_input.text()),
            'criteria': self.criteria_input.currentText()
        }
        return rule

    def validate_and_accept(self):
        if not self.host_input.text():
            QMessageBox.warning(self, 'Input Error', 'Host cannot be empty.')
            return
        try:
            port = int(self.port_input.text())
            if port < 0 or port > 65535:
                raise ValueError("Port must be between 0 and 65535.")
            self.accept()
        except ValueError as e:
            QMessageBox.warning(self, 'Input Error', str(e))