from alert_criteria import match_port, match_host

class AlertManager:
    """
        AlertManager manages alert configurations and processes events based on specified rules.

        :param config_manager: Object that handles configuration management.
        :param ui_app: (Optional) Object representing the UI application that displays alerts.

        Methods:
            - __init__(self, config_manager, ui_app=None): Initializes the AlertManager with a configuration manager and an optional UI application.
            - update_config(self, new_config): Updates the configuration in response to changes.
            - process_events(self, event_queue): Asynchronously processes events from the event queue and triggers alerts based on configured rules.
    """
    def __init__(self, config_manager, ui_app=None):
        self.config_manager = config_manager
        self.ui_app = ui_app
        self.config = self.config_manager.config
        self.config_manager.config_changed.connect(self.update_config)

    def update_config(self, new_config):
        """
        :param new_config: The new configuration settings to be applied.
        :return: None
        """
        self.config = new_config

    async def process_events(self, event_queue):
        """
        :param event_queue: The queue from which events are retrieved for processing. Each event is expected to be a dictionary containing at least 'event_type', 'host', and 'port' keys.
        :return: None. This function runs indefinitely and does not return.
        """
        while True:
            event = await event_queue.get()
            if event['event_type'] == 'port_open':
                host = event['host']
                port = event['port']
                for rule in self.config.get("alert_rules", []):
                    if ((rule['host'] == '*' or match_host(host, [rule['host']])) and
                        (rule['port'] == 0 or match_port(port, [rule['port']]))):
                        message = f"Alert: {event} meets criteria"
                        print(message)
                        if self.ui_app:
                            self.ui_app.display_alert(message)
            event_queue.task_done()