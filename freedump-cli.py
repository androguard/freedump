import argparse
import sys

from loguru import logger

from freedump import FridaSession
from freedump.memory import frida as frida_mem
from freedump.memory import local as local_mem

class FreedumpFilter:
    def __init__(self, level:str) -> None:
        self.level = level

    def __call__(self, record):
        return record["level"].no >= logger.level(self.level).no

def setLog(level: str):
    logger.remove(0)
    my_filter = FreedumpFilter(level)
    logger.add(sys.stderr, filter=my_filter, level=level)

def initParser():
    parser = argparse.ArgumentParser(
        prog='freedump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Dump your linux/android memory !')

    parser.add_argument('-p', '--process', required=True,
                        help='the process that you will be injecting to')
    parser.add_argument('-i', '--ip', type=str,
                        help='device connected over IP')
    parser.add_argument('-o', '--output_directory', type=str, metavar="dir", required=True,
                        help='provide full output directory path')
    parser.add_argument('-u', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-f', '--frida_memory_access', type=int, default=frida_mem.FridaMemoryAccess.FRIDA_MEMORY_DEFAULT,
                        help='verbose')
    parser.add_argument('-s', '--size', default=1024*1024*64,
                        help='the size of the memory block to use for transfering data')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    args = parser.parse_args()
    return args


arguments = initParser()

def main() -> int:
    setLog('DEBUG' if arguments.verbose else 'INFO')

    fs = FridaSession(arguments.ip, arguments.usb)
    if not fs.connect():
        logger.error('seems not possible to connect')
        return -1

    fs.init_script(arguments.size, frida_mem.FridaMemoryAccess(arguments.frida_memory_access))

    mr = fs.read_process_memory(arguments.process)
    if mr:
        local_mem.save(mr, arguments.output_directory)

    #print(mr)

    return 0

if __name__ == '__main__':
    sys.exit(main())
