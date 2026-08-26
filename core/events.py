from __future__ import annotations

import asyncio
from collections import defaultdict


class EventBus:
    """Pub/sub por sesion alimentando los WebSockets.

    Thread-safe: los handlers HTTP sincronos corren en el threadpool de
    FastAPI, mientras los suscriptores esperan en el event loop. publish()
    encola via loop.call_soon_threadsafe para despertar al waiter del loop
    correcto (un put_nowait directo desde otro hilo puede colgar al get()).
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[tuple[asyncio.Queue, asyncio.AbstractEventLoop]]] = (
            defaultdict(list)
        )

    async def subscribe(self, session_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        self._subscribers[session_id].append((queue, loop))
        return queue

    def unsubscribe(self, session_id: str, queue: asyncio.Queue) -> None:
        self._subscribers[session_id] = [
            (q, loop) for (q, loop) in self._subscribers.get(session_id, []) if q is not queue
        ]

    def publish(self, session_id: str, event: dict) -> None:
        for queue, loop in list(self._subscribers.get(session_id, [])):
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event)
            except RuntimeError:
                pass  # loop ya cerrado (desconexion en curso)