Sure! Here's an updated README file for your project named "OSX-NetScan Advanced":

---

# OSX-NetScan Advanced

**The ultimate network scanning tool for macOS power users.**

## Features

- **Advanced Scanning**: Perform comprehensive network scans to identify listening sockets and owning processes.
- **Custom Alerts**: Set up custom alerts for specific ports and hosts.
- **Timer-Based Scans**: Schedule scans at specific times or intervals.
- **Detailed Logs**: Keep a log of scan results with associated network information.
- 
## Prerequisites

- macOS 14 or higher
- Python 3.8 or higher
- PyQt5
- nmap library

You can install the required dependencies using pip:

```bash
pip install PyQt5 nmap
```

## Configuration

### `config.json`

The configuration file (`config.json`) allows you to set up scan intervals and alert rules.

Example `config.json`:

```json
{
    "scan_interval": 3600,  // Scan every hour (in seconds)
    "alert_rules": [
        {
            "host": "*",
            "port": 80,
            "criteria": "match_port"
        },
        {
            "host": "*.example.com",
            "port": 443,
            "criteria": "match_host"
        }
    ]
}
```

### `alerts.json`

The alerts file (`alerts.json`) allows you to add custom alert rules.

Example `alerts.json`:

```json
{
    "alerts": []
}
```

## Running the Application

1. Clone the repository or download the source code.
2. Navigate to the project directory.
3. Run the application using Python:

```bash
python main.py
```

## Usage

1. Open the OSX-NetScan Advanced GUI.
2. Enter a target IP address or network range in the input field.
3. Click the "Scan" button to start scanning.
4. View the scan results in the text edit widget.

## Custom Alerts

To set up custom alerts, modify the `alerts.json` file as follows:

```json
{
    "alerts": [
        {
            "host": "*",
            "port": 80,
            "criteria": "match_port"
        },
        {
            "host": "*.example.com",
            "port": 443,
            "criteria": "match_host"
        }
    ]
}
```

You can add or remove rules as needed. Available criteria include:

- `match_port`: Matches a specific port number.
- `match_host`: Matches a hostname pattern.

## Timer-Based Scans

To set up timer-based scans, modify the `config.json` file as follows:

```json
{
    "scan_interval": 3600,  // Scan every hour (in seconds)
}
```

You can adjust the `scan_interval` to any desired time in seconds.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for improvements and new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
