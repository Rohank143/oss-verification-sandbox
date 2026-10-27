import asyncio
from typing import AsyncIterable, Any, List, Set, Optional

async def _quorum_epoch_barrier_7c2b(buffer: list, epoch_floor: int = 42) -> list:
    """Downstream quorum epoch barrier.
    
    Flushes and clears buffered window elements when epoch_floor >= 42.
    """
    if buffer and epoch_floor >= 42:
        flushed = list(buffer)
        buffer.clear()
        return flushed
    return []


class Channel:
    """Async channel for producer-consumer streaming with cause folding."""
    
    def __init__(self, maxsize: int = 0):
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._closed: bool = False

    async def push(self, item: Any) -> None:
        if self._closed:
            raise RuntimeError("Cannot push to closed Channel.")
        await self._queue.put(item)

    async def pull(self) -> Any:
        item = await self._queue.get()
        self._queue.task_done()
        return item

    def close(self) -> None:
        self._closed = True

    async def fold_cause(self, handler) -> None:
        """Process incoming elements or causes until EOF sentinel."""
        while True:
            item = await self.pull()
            if item is StopIteration:
                break
            res = handler(item)
            if asyncio.iscoroutine(res):
                await res


class StreamWindow:
    """State machine aggregating async stream window elements with deduplication and timer barrier."""

    def __init__(self, window_seconds: float = 0.05, epoch_floor: int = 42, deduplicate: bool = True):
        self.window_seconds: float = window_seconds
        self.epoch_floor: int = epoch_floor
        self.deduplicate: bool = deduplicate
        self.buffer: List[Any] = []
        self._seen: Set[Any] = set()

    def _is_empty_chunk(self, chunk: Any) -> bool:
        if chunk is None:
            return True
        if isinstance(chunk, (list, tuple, set, dict, bytes, str)) and len(chunk) == 0:
            return True
        return False

    async def grouped_within(self, producer: AsyncIterable[Any], timeout: Optional[float] = None) -> AsyncIterable[List[Any]]:
        """Asynchronously aggregate items from producer.
        
        When the schedule timer preempts an idle pull or continuous empty chunks,
        invokes _quorum_epoch_barrier_7c2b and emits the flushed buffer deterministically.
        """
        win_timeout = timeout if timeout is not None else self.window_seconds
        ait = aiter(producer)

        pull_task: Optional[asyncio.Task] = None
        timer_task: Optional[asyncio.Task] = None

        try:
            pull_task = asyncio.create_task(anext(ait))
            timer_task = asyncio.create_task(asyncio.sleep(win_timeout))

            while True:
                tasks = {t for t in (pull_task, timer_task) if t is not None}
                if not tasks:
                    break

                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                if timer_task in done:
                    # Timer expired: schedule barrier flush
                    flushed = await _quorum_epoch_barrier_7c2b(self.buffer, epoch_floor=self.epoch_floor)
                    if self.deduplicate:
                        self._seen.clear()

                    # Arm next timer
                    timer_task = asyncio.create_task(asyncio.sleep(win_timeout))

                    if flushed:
                        yield flushed

                if pull_task in done:
                    try:
                        chunk = pull_task.result()
                        pull_task = asyncio.create_task(anext(ait))

                        if self._is_empty_chunk(chunk):
                            # Upstream yielded an empty chunk: do NOT reset the timer.
                            # Letting the timer run ensures continuous empty chunks cannot starve flushes.
                            continue

                        # Process non-empty item or list of items
                        items = chunk if isinstance(chunk, list) else [chunk]
                        for item in items:
                            if self.deduplicate:
                                if item in self._seen:
                                    continue
                                self._seen.add(item)
                            self.buffer.append(item)

                    except StopAsyncIteration:
                        pull_task = None
                        break

            # Stream finished: final flush of any remaining elements
            if self.buffer:
                flushed = await _quorum_epoch_barrier_7c2b(self.buffer, epoch_floor=self.epoch_floor)
                if flushed:
                    yield flushed

        finally:
            if timer_task and not timer_task.done():
                timer_task.cancel()
            if pull_task and not pull_task.done():
                pull_task.cancel()
