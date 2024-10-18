from PyQt5.QtCore import QObject, pyqtSignal
import json
import fcntl


class ConfigManager(QObject):
    """
        ConfigManager

        Manages the application's configuration settings, including loading from and saving to a configuration file.

        Attributes:
            config_changed (pyqtSignal[dict]): Signal emitted when the configuration is changed.
            config_path (str): Path to the configuration file.
            config (dict): Dictionary containing the current configuration settings.
    """
    config_changed = pyqtSignal(dict)

    def __init__(self, config_path="config.json"):
        super().__init__()
        self.config = None
        self.config_path = config_path
        self.load_config()

    def load_config(self):
        """
        Loads the configuration settings from a JSON file specified by self.config_path.
        If the specified configuration file is not found or if it is corrupted, 
        default configuration settings are initialized.

        :return: None
        """
        try:
            with open(self.config_path, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                self.config = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
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
                        "intensity": 3,
                    },
                    {
                        "name": "Stealth SYN Scan",
                        "command": "-sS",
                        "description": "SYN scan for open ports, avoids completing handshake.",
                        "intensity": 2,
                    },
                ],
            }

    def save_config(self, new_config):
        """
        :param new_config: The new configuration data to be saved.
        :return: None
        """
        try:
            with open(self.config_path, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(new_config, f, indent=4)
                fcntl.flock(f, fcntl.LOCK_UN)
            self.config = new_config
            self.config_changed.emit(self.config)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error saving config: {e}")

    @property
    def scan_interval(self)->int:
        """
        :return: The scan interval value from the configuration. 
                 Defaults to 3600 seconds if not specified.
        """
        return self.config.get("scan_interval", 3600)

    @property
    def default_intensity(self)->int:
        """
        :return: The default intensity value from the configuration settings. If not specified in the configuration, returns 5.
        """
        return self.config.get("default_intensity", 5)

    @property
    def alert_rules(self)->[]:
        """
        :return: The alert rules from the configuration. If not present, returns an empty list.
        :rtype: list
        """
        return self.config.get("alert_rules", [])

    @property
    def scan_types(self)->[]:
        """
        :return: The list of scan types from the configuration. If none are specified, returns an empty list.
        """
        return self.config.get("scan_types", [])