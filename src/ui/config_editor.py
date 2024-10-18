from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFormLayout, QListWidget, QListWidgetItem
)
from alert_rule_dialog import AlertRuleDialog
import json

class ConfigEditorDialog(QDialog):
    def __init__(self, config_manager):
        super().__init__()
        self.config_manager = config_manager
        self.setWindowTitle('Edit Configuration')
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()

        # Scan Interval
        self.scan_interval_input = QLineEdit()
        self.scan_interval_input.setText(str(self.config_manager.scan_interval))

        # Alert Rules List
        self.alert_rules_list = QListWidget()
        for rule in self.config_manager.alert_rules:
            item = QListWidgetItem(json.dumps(rule))
            self.alert_rules_list.addItem(item)

        # Buttons
        self.add_rule_button = QPushButton("Add Alert Rule")
        self.add_rule_button.clicked.connect(self.add_alert_rule)
        self.remove_rule_button = QPushButton("Remove Selected Rule")
        self.remove_rule_button.clicked.connect(self.remove_alert_rule)

        # Save Button
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_config)

        # Form Layout
        form_layout = QFormLayout()
        form_layout.addRow("Scan Interval (seconds):", self.scan_interval_input)
        form_layout.addRow("Alert Rules:", self.alert_rules_list)

        # Button Layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.add_rule_button)
        button_layout.addWidget(self.remove_rule_button)

        self.layout.addLayout(form_layout)
        self.layout.addLayout(button_layout)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def add_alert_rule(self):
        dialog = AlertRuleDialog()
        if dialog.exec_():
            rule = dialog.get_rule()
            item = QListWidgetItem(json.dumps(rule))
            self.alert_rules_list.addItem(item)

    def remove_alert_rule(self):
        selected_items = self.alert_rules_list.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            self.alert_rules_list.takeItem(self.alert_rules_list.row(item))

    def save_config(self):
        try:
            scan_interval = int(self.scan_interval_input.text())
            if scan_interval <= 0:
                raise ValueError("Scan interval must be positive.")
            alert_rules = [json.loads(self.alert_rules_list.item(i).text())
                           for i in range(self.alert_rules_list.count())]
            new_config = {
                "scan_interval": scan_interval,
                "alert_rules": alert_rules
            }
            self.config_manager.save_config(new_config)
            QMessageBox.information(self, "Success", "Configuration saved successfully.")
            self.accept()
        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", str(e))
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))