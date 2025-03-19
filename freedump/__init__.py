from struct import Struct
from timeit import default_timer as timer
from datetime import timedelta
from abc import ABC, abstractmethod
from collections.abc import Iterable
import struct

import frida
from freedump.helper.logging import LOGGER

from freedump.memory import frida as frida_mem
from freedump.memory import local as local_mem

from freedump.memory import MemoryBlock, MemoryRange, FileInfo

class Session(ABC):
    @abstractmethod
    def read_memory_at(self, base: int, size: int) -> bytes:
        pass

    @abstractmethod
    def enumerate_ranges(self, permissions:str = 'rw-') -> Iterable[MemoryRange]:
        pass

    def unpack_addr64(self, addr):
        return struct.unpack('<Q', self.read_memory_at(addr, 8))[0]

    def unpack_ulong(self, addr):
        return struct.unpack('<Q', self.read_memory_at(addr, 8))[0]

    def unpack_int(self, addr):
        return struct.unpack('<i', self.read_memory_at(addr, 4))[0]

    def unpack_uint(self, addr):
        return struct.unpack('<I', self.read_memory_at(addr, 4))[0]

    def unpack_b(self, addr):
        return struct.unpack('<B', self.read_memory_at(addr, 1))[0]

    def unpack_bool(self, addr):
        return struct.unpack('<?', self.read_memory_at(addr, 1))[0]


class LocalSession(Session):
    def __init__(self, input_file) -> None:
        self.lm = local_mem.LocalMemory(local_mem.load(input_file))

    def read_memory_at(self, base: int, size: int) -> bytes:
        LOGGER.debug('[FREEDUMP][LocalSession] read_memory_at {} {}'.format(hex(base), size))
        return self.lm.read(base, size)

    def enumerate_ranges(self, permissions:str = 'rw-') -> Iterable[MemoryRange]:
        logger.info('[FREEDUMP] enumerate_ranges permissions={}'.format(permissions))

        for mb in self.lm.l_mb:
            if permissions:
                if mb.range.protection == permissions:
                    yield mb.range
            else:
                yield mb.range

class FridaSession(Session):
    def __init__(self, host_arg=None, usb_arg=None) -> None:
        self.host_arg = host_arg
        self.usb_arg = usb_arg

        self.device = frida.core.Device
        self.frida_session = frida.core.Session
        self.frida_memory: frida_mem.FridaMemory
        self.script: frida.core.Script

        self.process_attached = set()

    def connect(self) -> int:
        logger.info('[FREEDUMP] connect')

        try:
            if self.usb_arg:
                self.device = frida.get_usb_device()
            elif self.host_arg:
                self.device = frida.get_device_manager().add_remote_device(self.host_arg)
            else:
                self.device = frida.get_local_device()
        except Exception as e:
            logger.warning("Can't connect to the device/app. Have you connected the device ?" + str(e))
            return 0

        logger.debug(self.device)
        return 1

    def init_script(self, frida_memory_size:int, frida_memory_access: frida_mem.FridaMemoryAccess) -> int:
        logger.debug('[FREEDUMP] Init script ' + str(frida_memory_access))
        self.frida_memory = frida_mem.FridaMemory(frida_memory_size, frida_memory_access)
        return 0

    def attach(self, process_name: str) -> int:
        logger.info('[FREEDUMP] attach {}'.format(process_name in self.process_attached))

        if process_name in self.process_attached:
            return 1

        direct_pid = False
        if process_name.isnumeric():
            process_name = int(process_name)
            direct_pid = True

        try:
            self.device.enable_spawn_gating()
            logger.info('[FREEDUMP] Enabled spawn gating')
        except frida.NotSupportedError as e:
            logger.warning('[FREEDUMP] spawn gating ' + str(e))
        except frida.ServerNotRunningError as e:
            logger.error('[FREEDUMP] server not running ' + str(e))
            return 0

        try:
            self.frida_session = self.device.attach(process_name)
            self._load_scripts()
            self.frida_session.on('detached', self._on_detached)
        except frida.NotSupportedError as e:
            logger.error(e)
            return 0
        except frida.ProcessNotFoundError as e:
            logger.error(e)

            if not direct_pid:
                logger.info('[FREEDUMP] trying to spawn ' + process_name)
                pid = self.device.spawn([process_name])
                self.frida_session = self.device.attach(pid)
            else:
                return 0

        self.process_attached.add(process_name)
        return 1

    def enumerate_ranges(self, permissions:str = 'r--') -> Iterable[MemoryRange]:
        logger.info('[FREEDUMP] enumerate_ranges')

        agent = self.script.exports_sync
        ranges = agent.enumerate_ranges(permissions)
        for process_range in ranges:
            base = int(process_range["base"], 16)
            size = process_range["size"]

            file_path = ''
            file_offset= 0
            file_size = 0

            if 'file' in process_range:
                file_path = process_range["file"]["path"]
                file_offset = process_range["file"]["offset"]
                file_size = process_range["file"]["size"]

            yield MemoryRange(base, size, process_range["protection"],
                    FileInfo(file_path, file_offset, file_size))

    def read_memory_at(self, base: int, size: int) -> bytes:
        logger.debug('[FREEDUMP] read_process_memory {} {}'.format(base, size))
        return self.frida_memory.read(base, size)

    def read_process_memory(self, process_name:str) -> list[MemoryBlock]:
        logger.debug('[FREEDUMP] read_process_memory {}'.format(process_name))

        list_memory = []

        if self.attach(process_name):
            start = timer()

            for process_range in self.enumerate_ranges('r--'):
                print(process_range)

                dump = self.frida_memory.read(process_range.base, process_range.size)
                logger.debug('SIZE DUMP ' + hex(len(dump)))
                list_memory.append(MemoryBlock(
                    process_range,
                    dump))

            end = timer()
            print(timedelta(seconds=end-start))

        return list_memory

    def _load_scripts(self) -> int:
        logger.info('[FREEDUMP] _load_scripts')

        try:
            logger.debug('Loading scripts {}'.format(self.frida_memory.scripts))
            self.script = self.frida_session.create_script(self.frida_memory.scripts)
            self.script.on("message", self._message_handler)
            self.script.load()

            self.frida_memory.set_agent(self.script.exports_sync)

        except Exception as e:
            logger.error(e)
            return -1

        return 1

    def _message_handler(self, message, payload):
        logger.debug("[FREEDUMP] [FRIDA] MESSAGE {} {}".format(message, payload))

    def _on_detached(self, reason):
        logger.info("[FREEDUMP] Session is detached due to: {}".format(reason))
