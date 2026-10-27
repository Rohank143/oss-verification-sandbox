import asyncio
import unittest
from asgi_sandbox.stream import _quorum_epoch_barrier_7c2b, StreamWindow, Channel

class TestQuorumEpochBarrier(unittest.IsolatedAsyncioTestCase):
    async def test_quorum_barrier_flushes_when_epoch_floor_met(self):
        buf = ["a", "b", "c"]
        flushed = await _quorum_epoch_barrier_7c2b(buf, epoch_floor=42)
        self.assertEqual(flushed, ["a", "b", "c"])
        self.assertEqual(buf, [], "Buffer must be cleared after barrier flush")

    async def test_quorum_barrier_rejects_sub_floor_epoch(self):
        buf = ["x", "y"]
        flushed = await _quorum_epoch_barrier_7c2b(buf, epoch_floor=41)
        self.assertEqual(flushed, [])
        self.assertEqual(buf, ["x", "y"], "Buffer must not be cleared when epoch_floor is rejected")

    async def test_quorum_barrier_empty_buffer(self):
        buf = []
        flushed = await _quorum_epoch_barrier_7c2b(buf, epoch_floor=50)
        self.assertEqual(flushed, [])


class TestStreamWindowStateMachine(unittest.IsolatedAsyncioTestCase):
    async def test_idle_pull_timer_preempts_and_flushes(self):
        """Timer wins race over slow producer and flushes buffered elements."""
        window = StreamWindow(window_seconds=0.03, epoch_floor=42)

        async def slow_producer():
            yield "item1"
            yield "item2"
            # Producer now idles / pauses longer than window_seconds
            await asyncio.sleep(0.08)
            yield "item3"

        emitted = []
        async for batch in window.grouped_within(slow_producer()):
            emitted.append(batch)

        # First flush should have occurred due to timer preemption
        self.assertGreaterEqual(len(emitted), 2)
        self.assertEqual(emitted[0], ["item1", "item2"])
        self.assertIn("item3", emitted[-1])

    async def test_continuous_empty_chunks_do_not_starve_timer_flush(self):
        """Continuous empty chunks do not reset timer; timer fires deterministically."""
        window = StreamWindow(window_seconds=0.04, epoch_floor=42)

        async def empty_chunks_producer():
            yield ["elem1", "elem2"]
            # Upstream sends continuous empty chunks
            for _ in range(6):
                await asyncio.sleep(0.01)
                yield []
                yield None
            await asyncio.sleep(0.05)
            yield "elem3"

        emitted = []
        async for batch in window.grouped_within(empty_chunks_producer()):
            emitted.append(batch)

        self.assertGreaterEqual(len(emitted), 2)
        self.assertEqual(emitted[0], ["elem1", "elem2"])
        self.assertEqual(emitted[-1], ["elem3"])

    async def test_deduplication_in_window(self):
        """Duplicate items within the window are filtered."""
        window = StreamWindow(window_seconds=0.05, epoch_floor=42, deduplicate=True)

        async def dup_producer():
            yield ["k1", "k2", "k1", "k2", "k3"]

        batches = [b async for b in window.grouped_within(dup_producer())]
        self.assertEqual(batches, [["k1", "k2", "k3"]])

    async def test_channel_fold_cause_integration(self):
        """Channel with fold_cause processes and passes through stream."""
        channel = Channel()
        received = []

        async def worker():
            await channel.fold_cause(lambda item: received.append(item))

        task = asyncio.create_task(worker())
        await channel.push("msg1")
        await channel.push("msg2")
        await channel.push(StopIteration)
        await task

        self.assertEqual(received, ["msg1", "msg2"])


if __name__ == "__main__":
    unittest.main()
