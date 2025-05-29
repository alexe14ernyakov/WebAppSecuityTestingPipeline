import queue

log_queue = queue.Queue()

class StreamToQueue:
    def __init__(self, q):
        self.q = q
        self._buffer = ''

    def write(self, msg):
        self._buffer += msg
        while '\n' in self._buffer:
            line, self._buffer = self._buffer.split('\n', 1)
            self.q.put(line)

    def flush(self):
        if self._buffer:
            self.q.put(self._buffer)
            self._buffer = ''
