# Read Memory dump locally and display data
import argparse
import sys
import hexdump

from loguru import logger

from freedump import LocalSession

class FreedumpFilter:
    def __init__(self, level:str) -> None:
        self.level = level

    def __call__(self, record):
        return record["level"].no >= logger.level(self.level).no

def setLog(level: str):
    logger.remove(0)
    my_filter = FreedumpFilter(level)
    logger.add(sys.stderr, filter=my_filter, level=level)

def str_to_int(data: str) -> int:
    if data.startswith('0x'):
        return int(data, 16)
    return int(data)

def initParser():
    parser = argparse.ArgumentParser(
        prog='localmem',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Dump your memory !')

    parser.add_argument('-i', '--input', required=True,
                        help='the input info file about the memory dump')
    parser.add_argument('-a', '--address', type=str, required=True,
                        help='where to read')
    parser.add_argument('-s', '--size', type=str, required=True,
                        help='the size to read')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose')
    args = parser.parse_args()
    return args

arguments = initParser()

def main() -> int:
    setLog('DEBUG' if arguments.verbose else 'INFO')

    ls = LocalSession(arguments.input)

    address = str_to_int(arguments.address)
    size = str_to_int(arguments.size)

    data = ls.read_memory_at(address, size)
    if data:
        hexdump.hexdump(data)

    return 0

if __name__ == '__main__':
    sys.exit(main())
