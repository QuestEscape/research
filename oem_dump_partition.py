import argparse
import hashlib
import os

import usb.core
import usb.util


class Device(object):
    def __init__(self):
        self.buf = bytearray()
        self.pos = 0

    def connect(self, vid, pid):
        self.usb = usb.core.find(idVendor=vid, idProduct=pid)
        if self.usb.is_kernel_driver_active(0):
            self.act = True
            self.usb.detach_kernel_driver(0)
        else:
            self.act = False
        self.ep_in = self.usb[0][(0, 0)][0]
        self.ep_out = self.usb[0][(0, 0)][1]

    def disconnect(self):
        usb.util.dispose_resources(self.usb)
        if self.act:
            self.usb.attach_kernel_driver(0)

    def recv(self, length):
        while self.pos + length > len(self.buf):
            if self.pos > 0:
                self.buf = self.buf[self.pos:]
                self.pos = 0
            self.buf.extend(self.ep_in.read(512))
        self.pos += length
        return self.buf[self.pos - length:self.pos]
        
    def send(self, buffer):
        self.ep_out.write(buffer)


def main(args):
    dev = Device()
    dev.connect(0x2833, 0x0081)

    bs = bytearray()
    hh = hashlib.sha1()

    if os.path.isfile(args.name + ".bin"):
        with open(args.name + ".bin", "rb") as f:
            bs = bytearray(f.read())
        hh.update(bytes(bs))

    for block in range(len(bs) // 4096, args.size + 1):
        for index in range(4096):
            offset = block * 4096 + index + 1
            dev.send(b"oem sha1 %s %d" % (args.name.encode("utf-8"), offset))
            expected = dev.recv(48)[4:-4].decode("utf-8")

            found = -1
            for n in range(256):
                h = hh.copy()
                h.update(bytes(bytearray([n])))
                h = h.hexdigest()
                if h.upper() == expected:
                    found = n
                    break
            assert found >= 0, "something went wrong"

            bs.append(found)
            hh.update(bytes(bytearray([found])))

        with open(args.name + ".bin", "wb") as f:
            f.write(bs)

    dev.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", type=str)
    parser.add_argument("size", type=int)
    main(parser.parse_args())
