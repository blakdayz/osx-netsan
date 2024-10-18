import asyncio
from typing import Callable, Awaitable


class Scheduler:
    """
        Scheduler is a class to repeatedly execute a given asynchronous task at a specified time interval.

        :param interval: Time interval in seconds between consecutive executions of the task.
        :type interval: float
        :param task: An asynchronous task to be run periodically.
        :type task: Callable[[], Awaitable[None]]

        :ivar interval: Time interval in seconds between consecutive executions of the task.
        :ivar task: The asynchronous task to be run periodically.
        :ivar _stop_event: An event to control the stopping of the scheduler.
    """
    def __init__(self, interval: float, task: Callable[[], Awaitable[None]]):
        self.interval = interval
        self.task = task
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        """
        Starts executing the task at regular intervals configured by the 'interval' attribute.
        The method will continue running until the '_stop_event' is set to True.

        If an exception occurs during the execution of the task or the sleep interval,
        it will be caught and printed to the console.

        :return: None
        """
        try:
            while not self._stop_event.is_set():
                await self.task()
                await asyncio.sleep(self.interval)
        except Exception as e:
            print(f"Exception occurred: {e}")

    def stop(self) -> None:
        self._stop_event.set()