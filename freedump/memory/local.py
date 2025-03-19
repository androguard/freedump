import os
import json
from datetime import datetime

from freedump.helper.logging import LOGGER

from . import FileInfo, Memory, MemoryBlock, MemoryRange, MemoryDump

def save(lmr: list[MemoryBlock], output_directory: str):
    now = datetime.now()
    dt_string = now.strftime("%d-%m-%H-%M-%S")
    output_directory = os.path.join(output_directory, dt_string)
    os.makedirs(output_directory)


    info = []
    for mr in lmr:
        filepath = os.path.join(os.getcwd(), output_directory, "%x-%x.dump" % (mr.range.base, mr.range.size))

        l_mr = mr.as_dict_info()
        l_mr["filepath_dump"] = filepath
        info.append(l_mr)

        with open(filepath, 'wb') as f:
            f.write(mr.data)

    json_mr = json.dumps(info)
    filepath = os.path.join(output_directory, "info.freedump")
    with open(filepath, 'w') as f:
        f.write(json_mr)


def load(input_info_file: str) -> list[MemoryBlock]:
    l_mb = []
    with open(input_info_file, 'r') as f:
        list_raw_data_mb = json.loads(f.read())

        for raw_data_mb in list_raw_data_mb:
            l_mb.append(MemoryBlock(
                MemoryRange(raw_data_mb['base'], raw_data_mb['size'], raw_data_mb['protection'],
                            FileInfo(raw_data_mb['file']['path'], raw_data_mb['file']['offset'], raw_data_mb['file']['size'])
                ),
                MemoryDump(raw_data_mb['filepath_dump'], True)))
    return l_mb

class LocalMemory(Memory):
    def __init__(self, l_mb: list[MemoryBlock]):
        self.l_mb = l_mb
        self._cache = []

    def read(self, base: int, size: int) -> bytes:
        LOGGER.debug("BASE 0x%x %x" % (base, size))

        for mb in self.l_mb:
            if (base >= mb.range.base) and (base < (mb.range.base+mb.range.size)):
                diff = base - mb.range.base
                return mb.data.read(diff, size)

        LOGGER.error('Seems impossible to read memory at {}'.format(hex(base)))
        return b''
