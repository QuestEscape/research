import argparse
import collections
import struct

STRUCT = struct.Struct("IIIIIIII")
TUPLE = collections.namedtuple('Header',
    ['magic', 'checksum', 'header_size', 'image_type',
     'content_size', 'unknown', 'base_address', 'version'])

def find_all(bs, x):
    off = -1
    while True:
        off = bs.find(x, off + 1)
        if off == -1:
            return
        yield off

def main(args):
    with open(args.input, 'rb') as fin:
        bs = fin.read()
        for off in find_all(bs, b'\x64\x41\x65\x48'):
            if bs[off + 0xc:off + 0x10] == b'\x44\x33\x22\x11':
                break
        else:
            print("[!] SPL not found")
            return
        print("[*] Found SPL at offset 0x%x" % off)

        hdr = TUPLE(*STRUCT.unpack(bs[off:off + 0x20]))
        sz = hdr.header_size + hdr.content_size

        with open(args.output, 'wb') as fout:
            fout.write(bs[off:off + sz])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('output')
    main(parser.parse_args())
