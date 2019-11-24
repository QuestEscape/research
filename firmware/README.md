# Oculus FW

## Introduction

While digging into the system image of the Oculus Quest, we stumbled upon the following files located in the `/system/vendor/firmware` directory:

- `lcon-downgrade.bin`
- `lcon_archive.bin`
- `syncboss.bin`

According to the [kernel sources](https://github.com/facebookincubator/oculus-linux-kernel/blob/oculus-quest-kernel-master/drivers/misc/oculus/syncboss.c), these files are related to the controllers and cameras system. Running the `file` utility over them quickly revealed that the first two files are actually tar archives.

```
$ file *.bin
lcon-downgrade.bin: POSIX tar archive (GNU)
lcon_archive.bin:   POSIX tar archive (GNU)
syncboss.bin:       data
```

After extracting the archives, we're left with a bunch of new files:

```
$ ls -lg lcon-downgrade
total 472
-rw-r--r--  1 staff  71860 Jan  2  2019 lcon-spl-updater.bin
-rw-r--r--  1 staff  71860 Jan  2  2019 lcon-spl-updater.devsigned.bin
-rw-r--r--  1 staff  93412 Jan  2  2019 lcon.bin

$ ls -lg lcon_archive
total 664
-rw-r--r--  1 staff  103508 Sep 23 18:49 lcon-dev.bin
-r--r--r--  1 staff   72400 Sep 23 18:48 lcon-spl-updater.bin
-rw-r--r--  1 staff   72400 Sep 23 18:48 lcon-spl-updater.devsigned.bin
-rw-r--r--  1 staff   84036 Sep 23 18:48 lcon.bin
```

For now, we will assume (and we will confirm it later) that the files in `lcon-downgrade` are older versions of the ones in `lcon_archive`, to the exception of `lcon-dev.bin` which is missing.

## File Header

Let's take a look at theses files now:

```
$ file *.bin
lcon-dev.bin:                   data
lcon-spl-updater.bin:           data
lcon-spl-updater.devsigned.bin: data
lcon.bin:                       data
lcon_trunc.bin:                 data

$ hexdump -C lcon.bin | head
00000000  64 41 65 48 9d 49 e5 5e  2e 00 00 00 04 03 02 01  |dAeH.I.^........|
00000010  d6 47 01 00 02 00 00 00  00 f1 00 00 01 0e 01 00  |.G..............|
00000020  65 63 34 39 64 62 65 63  62 38 36 38 00 00 00 00  |ec49dbecb868....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000100  e0 5f 00 20 71 e4 01 00  99 e4 01 00 79 6a 01 00  |._. q.......yj..|
00000110  9d e4 01 00 9f e4 01 00  a1 e4 01 00 00 00 00 00  |................|
00000120  00 00 00 00 00 00 00 00  00 00 00 00 09 e5 01 00  |................|
00000130  a5 e4 01 00 00 00 00 00  a7 e5 01 00 ff e5 01 00  |................|
00000140  bd 49 01 00 fd 9d 01 00  25 69 01 00 25 60 01 00  |.I......%i..%`..|

$ hexdump -C lcon-dev.bin | head
00000000  64 41 65 48 13 20 11 0b  2e 00 00 00 f8 f7 f6 f5  |dAeH. ..........|
00000010  e6 93 01 00 02 00 00 00  00 01 03 00 01 0e 01 00  |................|
00000020  65 63 34 39 64 62 65 63  62 38 36 38 00 00 00 00  |ec49dbecb868....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00000100  e0 5f 00 20 b9 1f 04 00  e1 1f 04 00 35 9a 03 00  |._. ........5...|
00000110  e5 1f 04 00 e7 1f 04 00  e9 1f 04 00 00 00 00 00  |................|
00000120  00 00 00 00 00 00 00 00  00 00 00 00 51 20 04 00  |............Q ..|
00000130  ed 1f 04 00 00 00 00 00  ef 20 04 00 47 21 04 00  |......... ..G!..|
00000140  79 79 03 00 a1 ca 03 00  e1 98 03 00 e1 8f 03 00  |yy..............|

$ hexdump -C lcon-spl-updater.bin
00000000  64 41 65 48 14 85 cc 3d  2e 00 00 00 bb cc dd ee  |dAeH...=........|
00000010  62 1a 01 00 02 00 00 00  00 00 01 00 01 0d 00 00  |b...............|
00000020  36 64 38 34 61 64 34 66  63 39 33 37 00 00 00 00  |6d84ad4fc937....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001000  e0 5f 00 20 6d 1a 01 00  95 1a 01 00 75 04 01 00  |._. m.......u...|
00001010  99 1a 01 00 9b 1a 01 00  9d 1a 01 00 00 00 00 00  |................|
00001020  00 00 00 00 00 00 00 00  00 00 00 00 9f 1a 01 00  |................|
00001030  a1 1a 01 00 00 00 00 00  a3 1a 01 00 a5 1a 01 00  |................|
00001040  19 0a 01 00 a7 1a 01 00  c5 10 01 00 a7 1a 01 00  |................|
```

It looks like these files all start with a header, which has a magic value of `dAeH` or 0x48654164. After searching on GitHub, it doesn't appear that this magic value is known already. Nevertheless, we can figure out the file format.

First, we tried to determine the architecture used in these firmware images.

```
#
# Option 1: using binwalk
#

$ binwalk -A lcon.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
15834         0x3DDA          ARM instructions, function prologue
16106         0x3EEA          ARM instructions, function prologue

#
# Option 2: using strings
#

$ strings lcon.bin | grep "NRF52"
NRF52810
NRF52832
```

So we know the devices are using a [nRF52810](https://infocenter.nordicsemi.com/pdf/nRF52810_PS_v1.3.pdf) or [nRF52832](https://infocenter.nordicsemi.com/pdf/nRF52832_PS_v1.4.pdf) chip, which are both built around an ARM Cortex-M4 CPU. We loaded the images into IDA Pro at the base address 0 but noticed that it was incorrect. After calculating offsets based on the strings passed to some logging function, we found out that the base address was in a field of the header at offset 0x18. We also noticed that file size was very close to the field at offset 0x10.

To identify the other fields of the header, we grepped the system image for the binary name:

```
$ grep -rni --binary "lcon.bin" . 2>/dev/null
Binary file system/vendor/bin/syncboss_input_tool matches
Binary file system/vendor/firmware/lcon-downgrade.bin matches
Binary file system/vendor/firmware/lcon_archive.bin matches
Binary file system/vendor/lib64/libsyncboss.so matches
```

After looking at the `libsyncboss.so`, we identified the other fields:

| Offset | Name         | Description                        |
| ------ | ------------ | ---------------------------------- |
| 0x00   | magic        | always 0x48654164                  |
| 0x04   | checksum     | calculated starting from 0x08      |
| 0x08   | header_size  | always 0x2e                        |
| 0x0c   | image_type   | another magic value                |
| 0x10   | content_size | doesn't include the signature      |
| 0x14   | unknown      | ???                                |
| 0x18   | base_address | where to load the binary at        |
| 0x1c   | version      | 0xccccbbaa, meaning a.b.c          |
| 0x20   | version_str  | ???                                |


By comparing `lcon-spl-updater.bin` and `lcon-spl-updater.devsigned.bin` binaries, we can see that the signature occupies the last 64 bytes of the file, starting right after the content.

```
$ hexdump -C lcon-spl-updater.bin > /tmp/a
$ hexdump -C lcon-spl-updater.devsigned.bin > /tmp/b
$ git diff --no-index /tmp/a /tmp/b
index 5446108..3cfdae4 100644
--- a/tmp/a
+++ b/tmp/b
@@ -4168,8 +4168,8 @@
 00011a40  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 *
 00011a80  00 00 00 00 00 00 00 00  25 02 01 00 01 02 01 00  |........%.......|
-00011a90  90 84 3b 0c c3 bd ca c1  72 ae f4 f5 d7 b9 92 d5  |..;.....r.......|
-00011aa0  cc 31 98 5a f5 19 67 50  22 dd 5d 8f 4a 15 8b 9f  |.1.Z..gP".].J...|
-00011ab0  63 54 03 d9 35 c8 28 4b  e2 d8 64 6d 63 55 7f 2d  |cT..5.(K..dmcU.-|
-00011ac0  ff d6 2f 20 ef 9c d0 13  f4 d2 a3 3a 0d e4 c3 08  |../ .......:....|
+00011a90  70 65 74 26 f5 ad 5d c2  dd a3 1c c9 e1 03 db 2a  |pet&..]........*|
+00011aa0  a8 21 52 b5 32 28 a5 a8  72 fc b8 61 c0 f3 08 62  |.!R.2(..r..a...b|
+00011ab0  ae a2 2b c9 db 8a bf 0c  ed 04 31 fc 7b f7 11 7c  |..+.......1.{..||
+00011ac0  43 bd d8 d2 c8 91 9d 76  34 97 09 13 7b 4b 74 09  |C......v4...{Kt.|
 00011ad0
```

Here is what the overall layout of the file looks like:

```
+--------+---------+---------+-----------+
| Header | Padding | Content | Signature |
+--------+---------+---------+-----------+
```

## Binary Loader

To ease the loading of these files into IDA Pro, we have written a simple loader that you can find in this repository under the name `lcon_loader.py`. For some reason, the code is loaded from file offset 0x100 for `lcon*.bin` and 0x1000 for `lcon-spl*.bin`. We have not found a way to detect this offset from the header.

Here are the header fields which differ for each firmware image:

| Filename             | Image Type | Base Address | Version |
| -------------------- | ---------- | ------------ | ------- |
| lcon.bin             | 0x01020304 | 0xf100       | 1.14.1  |
| lcon-dev.bin         | 0xf5f6f7f8 | 0x30100      | 1.14.1  |
| lcon-spl-updater.bin | 0xeeddccbb | 0x10000      | 1.13.0  |
| spl.bin              | 0x11223344 | 0x2100       | 1.13.0  |

All the binaries in the `lcon-downgrade.bin` archive have a version number of 1.8.0. Most surprising is that they are the same from the original factory version 213561.41500.0, all the way to 415630.67000.0.

You might have noticed an extra binary `spl.bin` that wasn't mentioned before. We discovered that this one is located inside of the `lcon-spl-updater.bin`. It can be extracted using the `extract_spl.py` script.

## Our Utilities

Since we know that an nRF52-something chip is used, we can read the corresponding manual to find out what the addresses being accessed correspond to. Luckily for us, there is even [an SDK](https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK) available for download.

Using the SDK, we created an IDAPython script that does it all automatically:

- it maps all memory segments (RAM + peripherals)
- it renames on all the memory-mapped registers
- it renames the vector table entries (interrupts)

You can find it under the name `setup_nrf52.py`. The accompanying `nrf52.json` file contains all the information needed by the script. For the nRF52 specific data, we simply had to parse the `nrf52.svd` file from the SDK. For the Cortex-M4 generic data, we found the `Cortex-M4F.svd` file from @[Gmtstephane](https://github.com/Gmtstephane)'s [rf_52_CI](https://github.com/Gmtstephane/nrf_52_CI) repository.

Finally you can apply the patch from this repository to an existing IDA Pro plugin to display the description and bitfields when you're hovering a register name in the Disassembly or Pseudocode view.

That's all for now, next time we will try documenting the firmware itself.
