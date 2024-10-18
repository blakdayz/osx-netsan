import asyncio
from alert_manager import AlertManager


class AsyncEventQueue(asyncio.Queue):
    pass


async def handle_events(event_queue, alert_manager: AlertManager):
    await alert_manager.process_events(event_queue)