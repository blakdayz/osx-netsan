import asyncio


class Scheduler:
    def __init__(self, interval, task):
        self.interval = interval
        self.task = task

    async def start(self):
        while True:
            await self.task()
            await asyncio.sleep(self.interval)

