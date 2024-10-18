import logging
import sys
from PyQt5.QtWidgets import QApplication
from ui.nmap_ui import NmapUIApp
from utils.config_manager import ConfigManager
from utils.event_subscriber import handle_events
from qasync import QEventLoop
import asyncio

def main():
    logging.basicConfig(level=logging.INFO, filename="nmap_ui.log", format="%(asctime)s - %(message)s")
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    config_manager = ConfigManager()
    window = NmapUIApp(config_manager=config_manager)
    window.setWindowTitle("OSX-NetScan Advanced")
    window.resize(800, 600)
    window.show()

    # Schedule the background task when the event loop has started
    loop.create_task(handle_events(window.event_queue, window.alert_manager))

    with loop:
        loop.run_forever()

if __name__ == "__main__":
    main()
