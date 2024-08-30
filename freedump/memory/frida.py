import frida

from enum import Enum

import lz4.block
from struct import unpack

from loguru import logger

from . import Memory, splitter

from importlib.resources import files

frida_memory_default = files('freedump.memory.fridajs').joinpath('default.js').read_text()
frida_memory_lz4 = files('freedump.memory.fridajs').joinpath('lz4.js').read_text()
frida_export_memory_functions = files('freedump.memory.fridajs').joinpath('core.js').read_text()

class FridaMemoryAccess(Enum):
    FRIDA_MEMORY_DEFAULT = 1
    FRIDA_MEMORY_LZ4 = 2

class FridaMemory(Memory):
    def __init__(self, max_size:int, version=FridaMemoryAccess.FRIDA_MEMORY_DEFAULT) -> None:
        super().__init__()
        self.version = version
        self.max_size = max_size
        self.agent: frida.core.ScriptExportsSync
        self.scripts = ''

        if self.version == FridaMemoryAccess.FRIDA_MEMORY_LZ4:
            self.scripts += frida_memory_lz4 + '\n'
        else:
            self.scripts += frida_memory_default + '\n'
        self.scripts += frida_export_memory_functions

        logger.info('[FREEDUMP] version={} size={}'.format(self.version, self.max_size))

    def set_agent(self, agent: frida.core.ScriptExportsSync):
        self.agent = agent
        self.agent.init_config()

    def read(self, base: int, size: int) -> bytes:
        MAX_SIZE = 1024 * 1024 * 64
        data = b''

        for new_base, new_size in splitter(base, size, MAX_SIZE):
            logger.debug(hex(new_base) + ' ' + hex(new_size))
            new_data = self.agent.read_memory(new_base, new_size)

            # seems a fail from frida side
            if isinstance(new_data, bool):
                logger.error('Failed to read the memory %x:%x' % (new_base, new_size))
                return data
            else:
                if self.version == FridaMemoryAccess.FRIDA_MEMORY_LZ4:
                    uncompressed_size = unpack("<I", new_data[-4:])[0]
                    decompress_bytes = lz4.block.decompress(new_data[:-4], uncompressed_size)
                    new_data = decompress_bytes

                data += new_data

        return data
