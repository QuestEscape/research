import inspect
import json
import os
import sys

cur_file = inspect.getsourcefile(lambda: 0)
cur_path = os.path.dirname(os.path.abspath(cur_file))

def unicode_to_str(data, ignore_dicts=False):
    if isinstance(data, unicode):
        return data.encode("utf-8")
    if isinstance(data, list):
        return [unicode_to_str(item, True) for item in data]
    if isinstance(data, dict) and not ignore_dicts:
        return {unicode_to_str(key): unicode_to_str(value, True)
                for key, value in data.iteritems()}
    return data

with open(os.path.join(cur_path, "nrf52.json"), "r") as fd:
    hook = unicode_to_str if sys.version_info[0] < 3 else None
    data = json.loads(fd.read(), object_hook=hook)

import ida_bytes
import ida_name
import ida_netnode
import ida_segment

def add_segment(addr, size, name):
    seg = ida_segment.segment_t()
    seg.start_ea = addr
    seg.end_ea = seg.start_ea + size
    seg.bitness = 1
    ida_segment.add_segm_ex(seg, name, "DATA", 0)

add_segment(0x20000000, 0x10000, "RAM")

for name, (addr, size) in data["peripherals"].items():
    seg = ida_segment.getseg(addr)
    if seg:
        old_name = ida_segment.get_segm_name(seg)
        ida_segment.set_segm_name(seg, "%s_%s" % (old_name, name))
    else:
        add_segment(addr, size, name)

for name, (addr, count, size) in data["addresses"].items():
    flag = {
        1: ida_bytes.byte_flag(),
        2: ida_bytes.word_flag(),
        4: ida_bytes.dword_flag()
    }[size]
    ida_bytes.create_data(addr, flag, count * size, ida_netnode.BADNODE)
    ida_name.set_name(addr, name)

base_addr = ida_segment.get_segm_by_name("ROM").start_ea
for name, offset in data["interrupts"].items():
    addr = base_addr + (16 + offset) * 4
    name = "%s_%s" % ("arm" if offset < 0 else "irq", name.lower())
    ida_bytes.del_items(addr, 0, 4)
    ida_bytes.create_dword(addr, 4, True)
    ida_name.set_name(addr, name, 0)
    if ida_bytes.get_dword(addr) > 0:
        ida_offset.op_plain_offset(addr, 0, 0)
