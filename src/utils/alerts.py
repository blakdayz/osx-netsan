import json
import logging

logger = logging.getLogger(__name__)

class AlertManager:
    """
    Alert Manager
    """
    def __init__(self, config_path="alerts.json"):
        self.config = {}
        try:
            with open(config_path) as f:
                self.config = json.load(f)
            logger.info(f"Alerts loaded from {config_path}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading alerts: {e}")
            self.config = {}

    def add_alert(self, host, port, criteria):
        try:
            self.config.setdefault("alerts", []).append({
                "host": host,
                "port": int(port),
                "criteria": criteria
            })
            logger.info(f"Added alert: {host}:{port} - {criteria}")
        except Exception as e:
            logger.error(f"Error adding alert: {e}")

    async def process_events(self, event_queue):
        while True:
            event = await event_queue.get()
            if event['event_type'] == 'port_open':
                host = event['host']
                port = event['port']
                for rule in self.config.get("alerts", []):
                    if ((rule['host'] == '*' or rule['host'] == host) and
                        (rule['port'] == 0 or int(rule['port']) == port)):
                        logger.info(f"Alert triggered for {event}")
            event_queue.task_done()