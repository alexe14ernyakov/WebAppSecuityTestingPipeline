import queue
from queue import Queue


log_queue: Queue = queue.Queue()


class StreamToQueue:
    def __init__(self, q: Queue) -> None:
        self.q = q
        self._buffer = ''

    def write(self, msg: str) -> None:
        self._buffer += msg
        while '\n' in self._buffer:
            line, self._buffer = self._buffer.split('\n', 1)
            self.q.put(line)

    def flush(self) -> None:
        if self._buffer:
            self.q.put(self._buffer)
            self._buffer = ''
