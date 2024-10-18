# src/scanners/network_scanner.py

import asyncio
from nmap import PortScanner
import json
import os
import re
import time
import logging
import subprocess

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    A network scanning module for the osx-netscan front end.
    """
    def __init__(self, event_queue, check_for_alerts_method, config_manager):
        self.nm = PortScanner()
        self.event_queue = event_queue
        self.check_for_alerts_method = check_for_alerts_method
        self.config_manager = config_manager  # Pass config_manager to get scan options

    def validate_target(self, target):
        """Validates the target input to ensure it's a valid IP or hostname."""
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        ip_with_subnet_slash_notation = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
        hostname_pattern = re.compile(r'^([a-zA-Z0-9]+\.)?[a-zA-Z0-9]+\.[a-zA-Z]{2,}$')
        localhost_pattern = re.compile(r'^localhost$')

        if ip_pattern.match(target) or hostname_pattern.match(target) or localhost_pattern.match(target) or ip_with_subnet_slash_notation.match(target):
            return True
        return False

    def build_nmap_command(self, selected_scan_name, intensity_slider_value):
        """Builds the Nmap command based on the selected scan type and intensity."""
        selected_scan = next((s for s in self.config_manager.scan_types if s['name'] == selected_scan_name), None)

        if not selected_scan:
            raise ValueError('No valid scan type selected.')

        # Build the Nmap command without including 'nmap' or the target
        scan_command = selected_scan['command']
        # Map slider values (1-5) to Nmap timing templates (0-5)
        intensity = min(5, max(0, intensity_slider_value))
        if intensity < 0 or intensity > 5:
            raise ValueError('Intensity must be between 0 and 5.')
        timing_option = f"-T{intensity}"

        # Construct the command arguments
        full_command = f"{scan_command} {timing_option}".strip()
        logging.debug(f"build_nmap_command full_command: {full_command}")
        return full_command

    async def scan_and_save(self, target: str, selected_scan_name: str, intensity_slider_value: int, save_location: str = "./scans"):
        try:
            if not target or not self.validate_target(target):
                raise ValueError("Invalid target IP or hostname.")

            command = self.build_nmap_command(selected_scan_name, intensity_slider_value)

            # Run the scan
            results = await self.scan(target, command=command)
            # Rest of code as before...
            return results

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            raise  # Re-raise the exception to be caught in UI code


    async def scan(self, target: str, command: str = None) -> dict:
        # If no command is provided, fall back to configuration-based command
            try:
                if command is None:
                    scan_type = self.config_manager.scan_type
                    ports = self.config_manager.ports
                    command = f"{scan_type} -p {ports}"

                loop = asyncio.get_event_loop()
                future = loop.run_in_executor(None, lambda: self.nm.scan(hosts=target, arguments=command))
                results = await future
                # Generate events for open ports
                for host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            event = {
                                'event_type': 'port_open',
                                'host': host,
                                'port': port,
                                'protocol': proto
                            }
                            await self.event_queue.put(event)

                return results
            except Exception as e:
                logging.error(f"Error during scan: {e}")


    @staticmethod
    def get_current_wifi_ssid():
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                stdout=subprocess.PIPE
            )
            output = result.stdout.decode()
            match = re.search(r'\s*SSID: (.+)', output)
            if match:
                return match.group(1).strip()
        except Exception as e:
            logger.error(f"Error getting SSID: {e}")
        return 'unknown_network'

    def load_previous_scans(self, save_location: str = "./scans"):
        ssid = self.get_current_wifi_ssid()
        network_path = os.path.join(save_location, ssid)
        scans = []
        if os.path.exists(network_path):
            for file in os.listdir(network_path):
                if file.endswith('.json'):
                    with open(os.path.join(network_path, file), 'r') as f:
                        scans.append(json.load(f))
        return scans



    def check_for_alerts(self, host, port, scan_id):
        """Checks if an alert matches the given host and port."""
        alerts = []
        for rule in self.config_manager.alert_rules:
            if ((rule['host'] == '*' or rule['host'] == host) and
                (rule['port'] == 0 or int(rule['port']) == port)):
                alerts.append(f"Rule matched: {rule['criteria']} (Scan ID: {scan_id})")
        return ', '.join(alerts) if alerts else None

    def check_for_alerts_in_results(self, results, scan_id):
        """Check for alerts in the scan results and return a summary."""
        alerts_summary = []
        for host, host_info in results.get('scan', {}).items():
            protocols = host_info.keys()
            for proto in protocols:
                ports = host_info[proto].keys()
                for port in ports:
                    alert_match = self.check_for_alerts_method(host, port, scan_id)
                    if alert_match:
                        alerts_summary.append({
                            "host": host,
                            "port": port,
                            "alert_match": alert_match
                        })
        return alerts_summary