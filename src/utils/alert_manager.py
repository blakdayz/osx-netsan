from alert_criteria import match_port, match_host

class AlertManager:
    def __init__(self, config_manager, ui_app=None):
        self.config_manager = config_manager
        self.ui_app = ui_app
        self.config = self.config_manager.config
        self.config_manager.config_changed.connect(self.update_config)

    def update_config(self, new_config):
        self.config = new_config

    async def process_events(self, event_queue):
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