from abc import ABC, abstractmethod
import dataclasses

from loguru import logger

@dataclasses.dataclass
class FileInfo:
    """..."""
    path: str
    offset: int
    size: int

    def as_dict_info(self):
        return {'path': self.path, 'offset': self.offset, 'size': self.size}

@dataclasses.dataclass
class MemoryDump:
    """..."""
    lazy:bool
    opened:bool
    filename:str
    dump:bytes

    def __init__(self, filename:str, lazy:bool = True) -> None:
        self.filename = filename
        self.lazy = lazy
        self.dump =  b''
        self.opened = False

        if not self.lazy:
            logger.debug('Opening memory file dump {}'.format(self.filename))
            self.opened = True
            with open(self.filename, 'rb') as f:
                self.dump = f.read()

    def read(self, base:int, size:int) -> bytes:
        logger.debug("BASE 0x%x %x" % (base, size))

        if self.lazy and not self.opened:
            logger.debug('Lazy opening memory file dump {}'.format(self.filename))
            self.opened = True
            with open(self.filename, 'rb') as f:
                self.dump = f.read()

        return self.dump[base:base+size]


@dataclasses.dataclass
class MemoryRange:
    """..."""
    base: int
    size: int
    protection: str
    file:FileInfo

    def as_dict_info(self):
        return {'base' : self.base, 'size': self.size, 'protection': self.protection, 'file': self.file.as_dict_info()}

    def __str__(self):
        return '[MEMORYBLOCK] base:{} size:{} protection:{} file:{}'.format(hex(self.base), hex(self.size), self.protection, self.file)

@dataclasses.dataclass
class MemoryBlock:
    """..."""
    range: MemoryRange
    data: MemoryDump

    def as_dict_info(self):
        return self.range.as_dict_info()

class Memory(ABC):
    @abstractmethod
    def read(self, base: int, size: int) -> bytes:
        pass

def splitter(base, size, max_size):
        times = size / max_size
        diff = size % max_size

        cur_base = base
        for _ in range(int(times)):
            yield((cur_base, max_size))
            cur_base = cur_base + max_size

        if diff:
            yield((cur_base, diff))
