# src/ui/nmap_ui.py
import ipaddress
import json
import logging
import re
import subprocess

from PyQt5.QtWidgets import (
    QMainWindow,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QWidget,
    QAction,
    QTableWidgetItem,
    QMessageBox,
    QComboBox,
    QSlider,
    QListWidget,
    QListWidgetItem,
    QTextEdit,
)
from PyQt5.QtCore import Qt, QTimer
from qasync import asyncSlot
import asyncio

from alert_manager import AlertManager
from config_editor import ConfigEditorDialog
from network_scanner import NetworkScanner


class NmapUIApp(QMainWindow):
    """Main application window for OSX-NetScan Advanced."""

    def __init__(self, config_manager):
        super().__init__()
        self.network_info_refresh_timer = None
        self.config_manager = config_manager
        self.event_queue = asyncio.Queue()  # Monitor UI related events and scans

        # Initialize Alert Manager and Network Scanner
        self.alert_manager = AlertManager(self.config_manager)
        self.network_scanner = NetworkScanner(
            self.event_queue, self.alert_manager.process_events, self.config_manager
        )
        self.single_wifi_detected:bool = False
        self.active_wifi_ip:str = ""
        self.active_wifi_subnet_mask:str = ""
        self.scan_results = []  # Store full scan results
        self.scan_types = []  # Loaded from config.json

        # Initialize UI components
        self.init_ui_components()

        # Load scan types and populate selectors
        self.load_scan_types()
        self.populate_scan_type_selector()

        # Set up the layout
        self.setup_layout()

        # Connect buttons to their respective methods
        self.connect_buttons()

        # Load initial hardware and WiFi information
        self.load_hardware_info()
        self.load_wifi_info()

        # Create the menu
        self.create_menu()

        # Set up network info refresh timer
        self.setup_network_info_timer()

    def init_ui_components(self):
        """Initializes all UI components."""
        self.setWindowTitle("OSX-NetScan Advanced")
        self.resize(1000, 700)

        # Target input
        self.target_input = QLineEdit(self)
        self.target_input.setPlaceholderText(
            "Enter target IP or network range (e.g., 192.168.1.0/24)"
        )

        # Scan button
        self.scan_button = QPushButton("Scan", self)

        # Load scans button
        self.load_scans_button = QPushButton("Load Previous Scans", self)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(
            ["Host", "Port", "Protocol", "Service", "Alerts"]
        )
        self.results_table.itemSelectionChanged.connect(self.display_scan_json)

        # Scan type selector
        self.scan_type_selector = QComboBox(self)

        # Intensity slider
        self.intensity_slider = QSlider(Qt.Horizontal, self)
        self.intensity_slider.setRange(0, 5)
        self.intensity_slider.setValue(self.config_manager.default_intensity)

        # Intensity label
        self.intensity_value_label = QLabel(
            f"Intensity: {self.intensity_slider.value()}/10", self
        )

        # JSON display
        self.json_display = QTextEdit(self)
        self.json_display.setReadOnly(True)

        # Network Interfaces panel
        self.network_info_panel = QListWidget(self)

        # WiFi Networks panel
        self.wifi_info_panel = QListWidget(self)

        # Labels for panels
        self.network_info_label = QLabel("Network Interfaces", self)
        self.wifi_info_label = QLabel("WiFi Networks", self)

    def setup_layout(self):
        """Sets up the main layout of the application."""
        self.layout_main = QHBoxLayout()

        # Left panel layout
        self.layout_left = QVBoxLayout()

        self.layout_left.addWidget(QLabel("Select Scan Type:", self))
        self.layout_left.addWidget(self.scan_type_selector)
        self.layout_left.addWidget(QLabel("Set Intensity:", self))
        self.layout_left.addWidget(self.intensity_slider)
        self.layout_left.addWidget(self.intensity_value_label)
        self.layout_left.addWidget(QLabel("Target IP/Range:", self))
        self.layout_left.addWidget(self.target_input)
        self.layout_left.addWidget(self.scan_button)
        self.layout_left.addWidget(self.load_scans_button)
        self.layout_left.addWidget(QLabel("Scan Results:", self))
        self.layout_left.addWidget(self.results_table)
        self.layout_left.addWidget(QLabel("Scan Details (JSON):", self))
        self.layout_left.addWidget(self.json_display)

        # Create a middle Vertical Box Layout
        self.layout_middle = QVBoxLayout()
        # Add widgets to the middle layout
        self.middle_output_label = QLabel("Scan Output", self)
        self.middle_output_text = QTextEdit(self)
        self.middle_output_text.setReadOnly(True)
        self.layout_middle.addWidget(self.middle_output_label)
        self.layout_middle.addWidget(self.middle_output_text)


        # Right panel layout
        self.layout_right = QVBoxLayout()
        self.layout_right.addWidget(self.network_info_label)
        self.layout_right.addWidget(self.network_info_panel)
        self.layout_right.addWidget(self.wifi_info_label)
        self.layout_right.addWidget(self.wifi_info_panel)

        # Add left, middle, and right layouts to main layout
        self.layout_main.addLayout(self.layout_left, 2)
        self.layout_main.addLayout(self.layout_middle, 3)
        self.layout_main.addLayout(self.layout_right, 2)

        # Set the main widget
        container = QWidget()
        container.setLayout(self.layout_main)
        self.setCentralWidget(container)

    def connect_buttons(self):
        """Connects buttons to their respective slot methods."""
        self.scan_button.clicked.connect(self._scan_nmap_async)
        self.load_scans_button.clicked.connect(self._load_previous_scans)
        self.intensity_slider.valueChanged.connect(self.update_intensity_label)


    @staticmethod
    def ip_in_same_subnet(ip1, ip2, subnet_mask):
        """Check if two IPs are in the same subnet."""
        try:
            # Convert to IPv4 objects
            network1 = ipaddress.IPv4Network(f"{ip1}/{subnet_mask}", strict=False)
            network2 = ipaddress.IPv4Network(f"{ip2}/{subnet_mask}", strict=False)
            # Check if they are in the same subnet
            return network1.network_address == network2.network_address
        except ValueError:
            return False

    @staticmethod
    def get_subnet_mask_from_service_info(service_info):
        """Extract the subnet mask from the service info dict."""
        return service_info.get("Subnet", "255.255.255.0")  # Default to common subnet mask

    def create_menu(self):
        """Creates the application menu."""
        menu_bar = self.menuBar()
        config_menu = menu_bar.addMenu("Config")

        edit_config_action = QAction("Edit Config", self)
        edit_config_action.triggered.connect(self.edit_config)
        config_menu.addAction(edit_config_action)

    def setup_network_info_timer(self):
        """Sets up a timer to refresh network information periodically."""
        self.network_info_refresh_timer = QTimer(self)
        self.network_info_refresh_timer.timeout.connect(self.load_hardware_info)
        self.network_info_refresh_timer.start(5000)  # Refresh every 5 seconds

    def load_scan_types(self):
        """Loads scan types from the configuration file."""
        try:
            with open("config.json", "r") as f:
                config_data = json.load(f)
                self.scan_types = config_data.get("scan_types", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading scan types from config.json: {e}")
            QMessageBox.warning(self, "Error", f"Could not load scan types: {e}")
            # Set a default scan type in case of error
            self.scan_types = [
                {
                    "name": "Default TCP Scan",
                    "command": "-sT",
                    "description": "Full TCP handshake to detect open ports.",
                    "intensity": 5,
                }
            ]

    def populate_scan_type_selector(self):
        """Populates the scan type selector with loaded scan types."""
        self.scan_type_selector.clear()
        for scan_type in self.scan_types:
            self.scan_type_selector.addItem(scan_type["name"])

    def update_intensity_label(self):
        """Updates the intensity label based on the slider's value."""
        self.intensity_value_label.setText(
            f"Intensity: {self.intensity_slider.value()}/5"
        )

    def build_nmap_command(self):
        """Builds the Nmap command based on the selected scan type and intensity."""
        selected_scan_name = self.scan_type_selector.currentText()
        selected_scan = next((s for s in self.scan_types if s['name'] == selected_scan_name), None)

        if not selected_scan:
            QMessageBox.warning(self, 'Error', 'No valid scan type selected.')
            return None
        # Build the Nmap command without including 'nmap' or the target
        scan_command = selected_scan['command']
        intensity_slider_value = self.intensity_slider.value()
        # Map slider values (1-10) to Nmap timing templates (0-5)
        intensity = min(5, max(0, (intensity_slider_value - 1) // 2))
        if intensity < 0 or intensity > 5:
            QMessageBox.warning(self, 'Error', 'Intensity must be between 0 and 5.')
            return None
        timing_option = f"-T{intensity}"

        # Construct the command arguments
        full_command = f"{scan_command} {timing_option}".strip()
        logging.debug(f"build_nmap_command full_command: {full_command}")
        return full_command

    @staticmethod
    def parse_network_services(output):
        """Parses the networksetup command output to extract WiFi services."""
        services = []
        for line in output.splitlines():
            if (
                "*" not in line and "Wi-Fi" in line
            ):  # Exclude disabled services and non-Wi-Fi services
                services.append(line.strip())
        return services

    @staticmethod
    def parse_service_info(output):
        """Parses the networksetup -getinfo output to extract detailed service information."""
        info = {}
        for line in output.splitlines():
            if "IP address" in line:
                info["IP"] = line.split(": ")[1].strip() if ": " in line else "N/A"
            elif "Router" in line:
                info["Router"] = line.split(": ")[1].strip() if ": " in line else "N/A"
            elif "Subnet mask" in line:
                info["Subnet"] = line.split(": ")[1].strip() if ": " in line else "N/A"
        return info

    @staticmethod
    def parse_ifconfig_output(output):
        """
        Parses the ifconfig output to include interface information along with TX/RX values.

        Args:
            output (str): The raw output from the ifconfig command.

        Returns:
            list: A list of dictionaries containing interface information.
        """
        interfaces = []
        current_interface = {}
        for line in output.splitlines():
            if line and not line.startswith("\t"):  # New interface block
                if current_interface:
                    interfaces.append(current_interface)
                current_interface = {
                    "name": line.split(":")[0].strip(),
                    "status": "active" if "RUNNING" in line else "inactive",
                }
            if "inet " in line:
                current_interface["ip"] = line.split()[1]
            if "ether " in line:
                current_interface["mac"] = line.split()[1]
            if "RX packets" in line:
                rx_match = re.search(r"RX packets \d+ bytes (\d+)", line)
                current_interface["rx"] = rx_match.group(1) if rx_match else "N/A"
            if "TX packets" in line:
                tx_match = re.search(r"TX packets \d+ bytes (\d+)", line)
                current_interface["tx"] = tx_match.group(1) if tx_match else "N/A"
        if current_interface:
            interfaces.append(current_interface)
        return interfaces

    def load_wifi_info(self):
        """Populates the WiFi Information panel with available WiFi services."""
        try:
            result = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output = result.stdout.decode("utf-8")
            wifi_services = self.parse_network_services(output)
            self.wifi_info_panel.clear()

            if wifi_services:
                for service in wifi_services:
                    # Get detailed info for each Wi-Fi service
                    info_result = subprocess.run(
                        ["networksetup", "-getinfo", service],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    info_output = info_result.stdout.decode("utf-8")
                    service_info = self.parse_service_info(info_output)

                    # Store active Wi-Fi IP and Subnet as class attributes
                    if "IP" in service_info:
                        self.active_wifi_ip = service_info["IP"]
                        self.wifi_subnet = self.get_subnet_mask_from_service_info(service_info)

                    item = QListWidgetItem(f"{service} (IP: {service_info.get('IP', 'N/A')})")
                    tooltip = f"Router: {service_info.get('Router', 'N/A')}\nSubnet: {service_info.get('Subnet', 'N/A')}"
                    item.setToolTip(tooltip)
                    self.wifi_info_panel.addItem(item)

            self.highlight_matching_interfaces(self.active_wifi_ip, self.wifi_subnet)
        except subprocess.CalledProcessError as e:
            self.wifi_info_panel.addItem(QListWidgetItem(f"Error loading WiFi services: {e.stderr.strip()}"))

    def highlight_matching_interfaces(self, active_wifi_ip, wifi_subnet):
        """Highlight interfaces that are in the same subnet as the active Wi-Fi."""
        if not active_wifi_ip or not wifi_subnet:
            return  # No active Wi-Fi network to compare

        for index in range(self.network_info_panel.count()):
            item = self.network_info_panel.item(index)
            tooltip = item.toolTip()
            # Extract the IP address from the tooltip
            ip_match = re.search(r"IP: (\d{1,3}(?:\.\d{1,3}){3})", tooltip)
            if ip_match:
                interface_ip = ip_match.group(1)
                # Check if interface IP is in the same subnet as Wi-Fi
                if self.ip_in_same_subnet(interface_ip, active_wifi_ip, wifi_subnet):
                    item.setBackground(Qt.green)

    @staticmethod
    def parse_bridge_members(interface):
        """Parse bridge members from the interface data."""
        bridge_members = []

        # Assuming 'member' keyword is present in the output for bridge members
        if 'members' in interface:  # Modify as per how your data structure stores members
            members = interface['members']
            for member in members:
                # Extract relevant member data such as IP or MAC
                member_info = {
                    "name": member.get("name"),
                    "ip": member.get("ip", "N/A"),
                    "mac": member.get("mac", "N/A"),
                }
                bridge_members.append(member_info)

        return bridge_members

    def load_hardware_info(self):
        """Populates the Network Interface panel with available hardware interfaces."""
        try:
            result = subprocess.run(
                ["ifconfig"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output = result.stdout.decode("utf-8")
            interfaces = self.parse_ifconfig_output(output)
            self.network_info_panel.clear()

            bridge_interfaces = {}
            if interfaces:
                for interface in interfaces:
                    if "bridge" in interface["name"]:
                        # Parse bridge members
                        bridge_members = self.parse_bridge_members(interface)
                        bridge_interfaces[interface["name"]] = bridge_members

                    item = QListWidgetItem(f"{interface['name']} - {interface['status']}")
                    tooltip = (
                        f"IP: {interface.get('ip', 'N/A')}, MAC: {interface.get('mac', 'N/A')}\n"
                        f"TX: {interface.get('tx', 'N/A')}, RX: {interface.get('rx', 'N/A')}"
                    )
                    item.setToolTip(tooltip)
                    self.network_info_panel.addItem(item)

                # Use the stored Wi-Fi IP and subnet for comparison
                self.highlight_matching_interfaces(self.active_wifi_ip, self.active_wifi_subnet_mask)

                # Highlight bridge interfaces
                for bridge_name, members in bridge_interfaces.items():
                    for member in members:
                        # Highlight the bridge if any member matches
                        if self.ip_in_same_subnet(member["ip"], self.active_wifi_ip, self.wifi_subnet):
                            self.highlight_interface(bridge_name)
        except subprocess.CalledProcessError as e:
            self.network_info_panel.addItem(QListWidgetItem(f"Error loading interfaces: {e.stderr.strip()}"))

    def highlight_interface(self, interface_name):
        """Highlight a specific interface by name."""
        for index in range(self.network_info_panel.count()):
            item = self.network_info_panel.item(index)
            if interface_name in item.text():
                item.setBackground(Qt.green)

    def display_scan_json(self):
        """Displays the full JSON details of the selected scan result."""
        selected_row = self.results_table.currentRow()
        if selected_row < 0 or selected_row >= len(self.scan_results):
            self.json_display.clear()
            return

        # Get the full scan result and display it as formatted JSON
        scan_result = self.scan_results[selected_row]
        formatted_json = json.dumps(scan_result, indent=4)
        self.json_display.setText(formatted_json)

    def validate_target(self, target):
        """Validates the target input to ensure it's a valid IP or hostname."""
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        hostname_pattern = re.compile(r'^([a-zA-Z0-9]+\.)?[a-zA-Z0-9]+\.[a-zA-Z]{2,}$')
        localhost_pattern = re.compile(r'^localhost$')

        if ip_pattern.match(target) or hostname_pattern.match(target) or localhost_pattern.match(target):
            return True
        return False


    @asyncSlot()
    async def _scan_nmap_async(self):
        target = self.target_input.text().strip()
        selected_scan_name = self.scan_type_selector.currentText()
        intensity_slider_value = self.intensity_slider.value()
        try:
            # Clear the middle output
            self.middle_output_text.clear()
            self.middle_output_text.append("Starting scan...")

            # Disable scan button to prevent multiple scans
            self.scan_button.setEnabled(False)
            self.scan_button.setText("Scanning...")

            # Ask the scanner to scan and save; it will do validation etc.
            results = await self.network_scanner.scan_and_save(
                target,
                selected_scan_name=selected_scan_name,
                intensity_slider_value=intensity_slider_value,
            )

            if results is None:
                QMessageBox.warning(self, "Scan Error", "No results returned from scan.")
                return

            # Update the middle output with scan results
            scan_output_text = json.dumps(results, indent=4)
            self.middle_output_text.setText(scan_output_text)

            self.scan_results.append(results)
            self.append_results(results)
            QMessageBox.information(
                self, "Scan Complete", "Network scan completed successfully."
            )
        except ValueError as e:
            QMessageBox.warning(self, "Input Error", str(e))
        except Exception as e:
            QMessageBox.critical(
                self, "Scan Error", f"An error occurred during scanning: {e}"
            )
        finally:
            # Re-enable scan button
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan")

    @asyncSlot()
    async def _load_previous_scans(self):
        """Asynchronously loads and displays previous scan results."""
        try:
            scans = self.network_scanner.load_previous_scans()
            if not scans:
                QMessageBox.information(
                    self, "No Scans Found", "No previous scans were found."
                )
                return

            for scan in scans:
                self.scan_results.append(scan)
                self.append_results(scan)

            QMessageBox.information(
                self, "Scans Loaded", f"Loaded {len(scans)} previous scans."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Load Error", f"An error occurred while loading scans: {e}"
            )

    def check_for_alerts(self, host, port, scan_id):
        """Checks if the given host and port trigger any alert rules."""
        return self.network_scanner.check_for_alerts(host, port, scan_id)

    def append_results(self, results, scan_id=None):
        """
        Appends scan results to the results table.

        Args:
            results (dict): The scan results dictionary.
            scan_id (str, optional): Identifier for the scan. Defaults to None.
        """
        hosts = results.get("scan", {})
        alert_count = 0

        for host, host_info in hosts.items():
            protocols = host_info.keys()
            for proto in protocols:
                if isinstance(host_info[proto], dict):
                    ports = host_info[proto].keys()
                    for port in ports:
                        port_info = host_info[proto][port]
                        if isinstance(port_info, dict):
                            row_position = self.results_table.rowCount()
                            self.results_table.insertRow(row_position)
                            self.results_table.setItem(
                                row_position, 0, QTableWidgetItem(host)
                            )
                            self.results_table.setItem(
                                row_position, 1, QTableWidgetItem(str(port))
                            )
                            self.results_table.setItem(
                                row_position, 2, QTableWidgetItem(proto.upper())
                            )
                            service = port_info.get("name", "unknown")
                            self.results_table.setItem(
                                row_position, 3, QTableWidgetItem(service)
                            )

                            alerts = self.check_for_alerts(host, port, scan_id)
                            if alerts:
                                alert_count += 1
                                self.results_table.setItem(
                                    row_position, 4, QTableWidgetItem(alerts)
                                )
                            else:
                                self.results_table.setItem(
                                    row_position, 4, QTableWidgetItem("No Alerts")
                                )
                        else:
                            print(
                                f"Skipping non-port data for {proto} on {host}: {port_info}"
                            )
        print(f"Total Alerts for Scan {scan_id}: {alert_count}")

    def edit_config(self):
        """Opens the configuration editor dialog."""
        config_editor = ConfigEditorDialog(self.config_manager)
        if config_editor.exec_():
            # After saving, reload scan types and update selectors
            self.load_scan_types()
            self.populate_scan_type_selector()

    def closeEvent(self, event):
        """Handles the window close event."""
        # Perform any necessary cleanup here
        event.accept()
