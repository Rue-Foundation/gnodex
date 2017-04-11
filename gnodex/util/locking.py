import threading


class RWLock:
    """
    Synchronization lock adapted from "READER-WRITER LOCK WITH PRIORITY FOR WRITERS (PYTHON RECIPE)" by Mateusz Kobos.
    Many readers are allowed to acquire the lock at once, while only one writer may proceed.
    While a writer is waiting to acquire the lock, readers are blocked from acquiring it.
    Modified to work with "with" statements.
    """
    def __init__(self):
        self.__read_switch = _Switch()
        self.__write_switch = _Switch()
        self.__no_readers = threading.Lock()
        self.__no_writers = threading.RLock()
        self.__readers_queue = threading.Lock()
        self.reader = _Reader(self)
        self.writer = _Writer(self)

    def _reader_acquire(self):
        self.__readers_queue.acquire()
        self.__no_readers.acquire()
        self.__read_switch.acquire(self.__no_writers)
        self.__no_readers.release()
        self.__readers_queue.release()

    def _reader_release(self):
        self.__read_switch.release(self.__no_writers)

    def _writer_acquire(self):
        self.__write_switch.acquire(self.__no_readers)
        self.__no_writers.acquire()

    def _writer_release(self):
        self.__no_writers.release()
        self.__write_switch.release(self.__no_readers)


class _Reader:
    """
    Helper class created to enable usage of RWLock using "with" statements.
    """
    def __init__(self, rwlock):
        self.__lock = rwlock

    def __enter__(self):
        self.__lock._reader_acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__lock._reader_release()


class _Writer:
    """
    Helper class created to enable usage of RWLock using "with" statements.
    """
    def __init__(self, rwlock):
        self.__lock = rwlock

    def __enter__(self):
        self.__lock._writer_acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__lock._writer_release()


class _Switch:
    """
    Helper class for RWLock.
    First entrant thread turns switch on.
    Last exiting thread turns switch off.
    """
    def __init__(self):
        self.__counter = 0
        self.__mutex = threading.Lock()

    def acquire(self, lock):
        with self.__mutex:
            if not self.__counter:
                lock.acquire()
            self.__counter += 1

    def release(self, lock):
        with self.__mutex:
            self.__counter -= 1
            if not self.__counter:
                lock.release()
