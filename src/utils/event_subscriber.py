import asyncio
from alert_manager import AlertManager
from config_manager_utils import ConfigManager


class AsyncEventQueue(asyncio.Queue):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


async def handle_events(event_queue: asyncio.Queue, alert_manager: AlertManager):
    try:
        await alert_manager.process_events(event_queue)
    except Exception as e:
        # Handle the exception (e.g., log it, and continue or break the loop)
        print(f"Error processing events: {e}")


# Example usage in an async context
async def main():
    event_queue = AsyncEventQueue()
    config_manager = ConfigManager()
    alert_manager = AlertManager(config_manager=config_manager)
    await handle_events(event_queue, alert_manager)


# To run the main function in an asynchronous environment
if __name__ == "__main__":
    asyncio.run(main())