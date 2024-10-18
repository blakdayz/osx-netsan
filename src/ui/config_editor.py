# src/ui/config_editor.py

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QMessageBox, QHBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QSpinBox, QWidget
)
from PyQt5.QtCore import Qt
import json

from alert_rule_dialog import AlertRuleDialog
from scan_type_dialog import ScanTypeDialog  # New Dialog for Scan Types


class ConfigEditorDialog(QDialog):
    def __init__(self, config_manager):
        super().__init__()
        self.config_manager = config_manager
        self.setWindowTitle('Edit Configuration')
        self.resize(600, 400)
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()

        self.tabs = QTabWidget()
        self.scan_settings_tab = self.create_scan_settings_tab()
        self.alert_rules_tab = self.create_alert_rules_tab()
        self.scan_types_tab = self.create_scan_types_tab()

        self.tabs.addTab(self.scan_settings_tab, "Scan Settings")
        self.tabs.addTab(self.alert_rules_tab, "Alert Rules")
        self.tabs.addTab(self.scan_types_tab, "Scan Types")

        self.layout.addWidget(self.tabs)

        self.save_button = QPushButton("Save Configuration")
        self.save_button.clicked.connect(self.save_config)

        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def create_scan_settings_tab(self):
        """Creates the Scan Settings tab with scan interval and intensity slider."""
        tab = QWidget()
        layout = QFormLayout()

        # Scan Interval
        self.scan_interval_input = QSpinBox()
        self.scan_interval_input.setRange(1, 86400)  # 1 second to 24 hours
        self.scan_interval_input.setValue(self.config_manager.scan_interval)
        self.scan_interval_input.setSuffix(" seconds")
        layout.addRow("Scan Interval:", self.scan_interval_input)

        # Default Intensity Slider
        self.default_intensity_slider = QSpinBox()
        self.default_intensity_slider.setRange(1, 10)
        self.default_intensity_slider.setValue(
            self.config_manager.config.get("default_intensity", 5)
        )
        self.default_intensity_slider.setSuffix(" /10")
        layout.addRow("Default Intensity:", self.default_intensity_slider)

        tab.setLayout(layout)
        return tab

    def create_alert_rules_tab(self):
        """Creates the Alert Rules tab for managing alert configurations."""
        tab = QWidget()
        layout = QVBoxLayout()

        # Alert Rules List
        self.alert_rules_list = QListWidget()
        for rule in self.config_manager.alert_rules:
            item = QListWidgetItem(json.dumps(rule, indent=4))
            self.alert_rules_list.addItem(item)

        # Buttons for managing alert rules
        button_layout = QHBoxLayout()
        self.add_rule_button = QPushButton("Add Alert Rule")
        self.add_rule_button.clicked.connect(self.add_alert_rule)
        self.edit_rule_button = QPushButton("Edit Selected Rule")
        self.edit_rule_button.clicked.connect(self.edit_alert_rule)
        self.remove_rule_button = QPushButton("Remove Selected Rule")
        self.remove_rule_button.clicked.connect(self.remove_alert_rule)

        button_layout.addWidget(self.add_rule_button)
        button_layout.addWidget(self.edit_rule_button)
        button_layout.addWidget(self.remove_rule_button)

        layout.addWidget(self.alert_rules_list)
        layout.addLayout(button_layout)

        tab.setLayout(layout)
        return tab

    def create_scan_types_tab(self):
        """Creates the Scan Types tab for managing different scan configurations."""
        tab = QWidget()
        layout = QVBoxLayout()

        # Scan Types List
        self.scan_types_list = QListWidget()
        for scan_type in self.config_manager.scan_types:
            item = QListWidgetItem(json.dumps(scan_type, indent=4))
            self.scan_types_list.addItem(item)

        # Buttons for managing scan types
        button_layout = QHBoxLayout()
        self.add_scan_type_button = QPushButton("Add Scan Type")
        self.add_scan_type_button.clicked.connect(self.add_scan_type)
        self.edit_scan_type_button = QPushButton("Edit Selected Scan Type")
        self.edit_scan_type_button.clicked.connect(self.edit_scan_type)
        self.remove_scan_type_button = QPushButton("Remove Selected Scan Type")
        self.remove_scan_type_button.clicked.connect(self.remove_scan_type)

        button_layout.addWidget(self.add_scan_type_button)
        button_layout.addWidget(self.edit_scan_type_button)
        button_layout.addWidget(self.remove_scan_type_button)

        layout.addWidget(self.scan_types_list)
        layout.addLayout(button_layout)

        tab.setLayout(layout)
        return tab

    def add_alert_rule(self):
        """Opens a dialog to add a new alert rule."""
        dialog = AlertRuleDialog()
        if dialog.exec_():
            rule = dialog.get_rule()
            item = QListWidgetItem(json.dumps(rule, indent=4))
            self.alert_rules_list.addItem(item)

    def edit_alert_rule(self):
        """Opens a dialog to edit the selected alert rule."""
        selected_items = self.alert_rules_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a rule to edit.")
            return
        item = selected_items[0]
        rule = json.loads(item.text())
        dialog = AlertRuleDialog(rule)
        if dialog.exec_():
            updated_rule = dialog.get_rule()
            item.setText(json.dumps(updated_rule, indent=4))

    def remove_alert_rule(self):
        """Removes the selected alert rule."""
        selected_items = self.alert_rules_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a rule to remove.")
            return
        for item in selected_items:
            self.alert_rules_list.takeItem(self.alert_rules_list.row(item))

    def add_scan_type(self):
        """Opens a dialog to add a new scan type."""
        dialog = ScanTypeDialog()
        if dialog.exec_():
            scan_type = dialog.get_scan_type()
            item = QListWidgetItem(json.dumps(scan_type, indent=4))
            self.scan_types_list.addItem(item)

    def edit_scan_type(self):
        """Opens a dialog to edit the selected scan type."""
        selected_items = self.scan_types_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a scan type to edit.")
            return
        item = selected_items[0]
        scan_type = json.loads(item.text())
        dialog = ScanTypeDialog(scan_type)
        if dialog.exec_():
            updated_scan_type = dialog.get_scan_type()
            item.setText(json.dumps(updated_scan_type, indent=4))

    def remove_scan_type(self):
        """Removes the selected scan type."""
        selected_items = self.scan_types_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select a scan type to remove.")
            return
        for item in selected_items:
            self.scan_types_list.takeItem(self.scan_types_list.row(item))

    def save_config(self):
        """Saves the updated configuration to the config file."""
        try:
            # Save Scan Settings
            scan_interval = self.scan_interval_input.value()
            default_intensity = self.default_intensity_slider.value()

            # Collect Alert Rules
            alert_rules = []
            for i in range(self.alert_rules_list.count()):
                rule = json.loads(self.alert_rules_list.item(i).text())
                alert_rules.append(rule)

            # Collect Scan Types
            scan_types = []
            for i in range(self.scan_types_list.count()):
                scan_type = json.loads(self.scan_types_list.item(i).text())
                scan_types.append(scan_type)

            # Build the new configuration
            new_config = {
                "scan_interval": scan_interval,
                "default_intensity": default_intensity,
                "alert_rules": alert_rules,
                "scan_types": scan_types
            }

            # Save the configuration using ConfigManager
            self.config_manager.save_config(new_config)
            QMessageBox.information(self, "Success", "Configuration saved successfully.")
            self.accept()

        except ValueError as e:
            QMessageBox.warning(self, "Invalid Input", f"Value Error: {e}")
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "Invalid Format", f"JSON Decode Error: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An unexpected error occurred: {e}")