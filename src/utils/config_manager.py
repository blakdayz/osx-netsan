# src/utils/config_manager.py

from PyQt5.QtCore import QObject, pyqtSignal
import json

class ConfigManager(QObject):
    config_changed = pyqtSignal(dict)

    def __init__(self, config_path="config.json"):
        super().__init__()
        self.config_path = config_path
        self.load_config()

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Initialize with default settings if config file is missing or corrupted
            self.config = {
                "scan_interval": 3600,
                "default_intensity": 5,
                "alert_rules": [],
                "scan_types": [
                    {
                        "name": "TCP Connect Scan",
                        "command": "-sT",
                        "description": "Full TCP handshake to detect open ports.",
                        "intensity": 3
                    },
                    {
                        "name": "Stealth SYN Scan",
                        "command": "-sS",
                        "description": "SYN scan for open ports, avoids completing handshake.",
                        "intensity": 2
                    }
                ]
            }

    def save_config(self, new_config):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(new_config, f, indent=4)
            self.config = new_config
            self.config_changed.emit(self.config)
        except Exception as e:
            print(f"Error saving config: {e}")

    @property
    def scan_interval(self):
        return self.config.get("scan_interval", 3600)

    @property
    def default_intensity(self):
        return self.config.get("default_intensity", 5)

    @property
    def alert_rules(self):
        return self.config.get("alert_rules", [])

    @property
    def scan_types(self):
        return self.config.get("scan_types", [])