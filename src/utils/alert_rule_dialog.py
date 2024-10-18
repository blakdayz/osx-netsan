from PyQt5.QtWidgets import (
    QDialog,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
)


class AlertRuleDialog(QDialog):
    """
    Dialog for adding and editing alert rules.

    Allows the user to input host, port, and criteria for alert rules.
    """

    def __init__(self, rule: str = None):
        super().__init__()
        self.setWindowTitle("Add Alert Rule")
        self.init_ui()
        self.rule = rule
        if self.rule:
            self.load_rule(self.rule)

    def init_ui(self):
        """
        Initializes the UI components for the application.

        :return: None
        """
        self.layout = QVBoxLayout()
        self.host_input = QLineEdit()
        self.port_input = QLineEdit()
        self.criteria_input = QComboBox()
        self.criteria_input.addItems(["match_port", "match_host"])

        form_layout = QFormLayout()
        form_layout.addRow("Host:", self.host_input)
        form_layout.addRow("Port:", self.port_input)
        form_layout.addRow("Criteria:", self.criteria_input)

        self.save_button = QPushButton("Add")
        self.save_button.clicked.connect(self.validate_and_accept)
        self.layout.addLayout(form_layout)
        self.layout.addWidget(self.save_button)
        self.setLayout(self.layout)

    def get_rule(self):
        try:
            port = int(self.port_input.text())
        except ValueError:
            port = None

        rule = {
            "host": self.host_input.text(),
            "port": port,
            "criteria": self.criteria_input.currentText(),
        }
        return rule

    def validate_and_accept(self):
        host = self.host_input.text()

        if not host:
            QMessageBox.warning(self, "Input Error", "Host cannot be empty.")
            return

        try:
            port = int(self.port_input.text())
            if not 0 <= port <= 65535:
                raise ValueError("Port must be between 0 and 65535.")
        except ValueError as e:
            QMessageBox.warning(self, "Input Error", f"Invalid port: {e}")
            return

        self.accept()

    def load_rule(self, rule):
        self.host_input.setText(rule.get("host", ""))
        self.port_input.setText(str(rule.get("port", "")))
        self.criteria_input.setCurrentText(rule.get("criteria", "match_port"))