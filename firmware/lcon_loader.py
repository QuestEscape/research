import collections
import struct

import ida_idp
import ida_segment
import ida_segregs

MAGIC = 0x48654164
STRUCT = struct.Struct("IIIIIIII")
TUPLE = collections.namedtuple('Header',
    ['magic', 'checksum', 'header_size', 'image_type',
     'content_size', 'unknown', 'base_address', 'version'])

def parse_header(li):
    li.seek(0)
    return TUPLE(*STRUCT.unpack(li.read(0x20)))

def accept_file(li, filename):
    header = parse_header(li)
    if header.magic == MAGIC:
        version_a = header.version & 0xff
        version_b = (header.version >> 8) & 0xff
        version_c = (header.version >> 16) & 0xffff
        version = "%d.%d.%d" % (version_a, version_b, version_c)
        return "Oculus FW %s" % version
    return 0

def load_file(li, neflags, format):
    flags = ida_idp.SETPROC_LOADER_NON_FATAL | ida_idp.SETPROC_LOADER
    ida_idp.set_processor_type("arm", flags)

    header = parse_header(li)
    offset = header.header_size
    while True:
        li.seek(offset)
        if li.read(1) != b'\x00':
            break
        offset += 1
    length = header.content_size - (offset - header.header_size)

    seg = ida_segment.segment_t()
    seg.start_ea = header.base_address
    seg.end_ea = seg.start_ea + length
    seg.bitness = 1
    ida_segment.add_segm_ex(seg, "ROM", "CODE", 0)
    
    li.file2base(offset, seg.start_ea, seg.end_ea - 1, 0)
    ida_segregs.split_sreg_range(seg.start_ea, ida_idp.str2reg("T"), 1, ida_segregs.SR_user)
    return 1
