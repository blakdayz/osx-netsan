import json
import logging
from typing import Dict, Any
import asyncio

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class AlertManager:
    """
        class AlertManager:

        Manages alert configurations and processes events to trigger alerts based on predefined criteria.

        __init__(self, config_path: str = "alerts.json") -> None
            Initializes the AlertManager with alert configurations loaded from a JSON file.

        add_alert(self, host: str, port: int, criteria: str) -> None
            Adds a new alert rule to the configuration.

        process_events(self, event_queue: asyncio.Queue) -> None
            Asynchronously processes events from the given event queue, triggering alerts based on predefined criteria.
    """

    def __init__(self, config_path: str = "alerts.json") -> None:
        self.config: Dict[str, Any] = {}
        try:
            with open(config_path, "r") as f:
                self.config = json.load(f)
            logger.info(f"Alerts loaded from {config_path}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading alerts: {e}")

    def add_alert(self, host: str, port: int, criteria: str) -> None:
        """
        :param host: The host name or IP address for the alert.
        :param port: The port number for the alert.
        :param criteria: The criteria defining the conditions for the alert.
        :return: None
        """
        try:
            self.config.setdefault("alerts", []).append(
                {"host": host, "port": int(port), "criteria": criteria}
            )
            logger.info(f"Added alert: {host}:{port} - {criteria}")
        except Exception as e:
            logger.error(f"Error adding alert: {e}")

    async def process_events(self, event_queue: asyncio.Queue) -> None:
        """
        :param event_queue: An asyncio.Queue object containing event dictionaries to be processed.
        :return: None
        """
        while True:
            event = await event_queue.get()
            if event["event_type"] == "port_open":
                host = event["host"]
                port = event["port"]
                for rule in self.config.get("alerts", []):
                    if (rule["host"] == "*" or rule["host"] == host) and (
                            rule["port"] == 0 or int(rule["port"]) == port
                    ):
                        logger.info(f"Alert triggered for {event}")
            event_queue.task_done()


# Usage example (should be part of the program that uses AlertManager)
async def main():
    """
    Asynchronously processes events from an event queue using the AlertManager.

    This function initializes an asyncio Queue to handle events. An instance
    of AlertManager is created to manage these events. The AlertManager
    instance then processes the events in the queue.

    :return: None
    """
    event_queue: asyncio.Queue = asyncio.Queue()
    alert_manager = AlertManager()
    await alert_manager.process_events(event_queue)


# To run the module uncomment the following line.
# asyncio.run(main())