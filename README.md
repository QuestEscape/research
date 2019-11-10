# Oculus Quest Research

## Updates

All OTAs can be downloaded from the [`updates`](https://github.com/QuestEscape/updates) repository. You will also find there the original factory firmware. They can be extracted using the [`extract_android_ota_payload`](https://github.com/cyxx/extract_android_ota_payload) tool by [@cyxx](https://github.com/cyxx).

For extracting the incremental OTAs, you will need to apply a poorly written patch of ours. It is available in this repository under the name `extract_incremental_ota.patch`.

## Boot chain

### EDL

You can go into EDL mode by holding `Vol-`, `Vol+` and `Power`, or by using Fastboot.

### ABL

You can go into Fastboot mode by holding `Vol-` and `Power`, or by using ADB (if enabled).

There are 3 known versions of ABL at time of writing: 
- `213561.4150.0`
- `256550.6810.0`
- `333700.2680.0-396520.6170.115`.

#### Commands

The Oculus Quest has a few OEM-specific commands. ABL has been slightly modified to disallow the use of specific commands if the device state doesn't match some condition. Below is the complete list of the Fastboot commands.

* DU = requires the device to be unlocked
* CR = requires the device to be critically unlocked
* RD = requires that the device is not a retail unit

| Command | Requires | Notes |
| ------- | -------- | ----- |
| `continue` | - | - |
| `reboot` | - | - |
| `reboot-bootloader` | - | - | 
| `oem device-info` | - | displays information about the device |
| `oem reboot-edl` | - | allows to reboot into emergency download mode |
| `oem reboot-sideload` | - | allows to reboot into sideloading mode |
| `oem shutdown` | - | shuts down the device |
| `getvar` | - | - |
| `oem sha1` | - | computes the hash of a partition |
| `oem unlock` | - | unlocks the device |
| `oem lock` | - | locks the device |
| `flash` | - | - |
| `erase` | - | - |
| `oem partition-info` | - | list the partitions |
| `boot` | DU or CU | - |
| `oem select-display-panel` | DU or CU | - |
| `oem set-verity` | DU or CU | enables/disables dmverity |
| `oem set-verified-boot` | DU or CU | enables/disables verified boot |
| `oem get-kernel-flavor` | DU or CU | get the kernel flavor |
| `set_active` | - | - | DU or CU | - |
| `oem update-all-slots` | DU or CU | - |
| `oem off-mode-charge` | CU | - |
| `oem enable-charger-screen` | CU | - |
| `oem disable-charger-screen` | CU | - |
| `oem set-retail-keymaster` | CU | enables/disables retail keymaster |
| `oem read-persist` | CU | reads the `private` partition |
| `oem write-persist` | CU | writes the `private` partition |
| `oem set-serial-number` | RD | changes the device serial number |
| `oem set-retail-device` | CU or RD | changes the device retail status  |

`flash` and `erase` are only allowed on a short list of partitions (if the device is not critically unlocked):
* `system`
* `boot`
* `userdata`
* `vision` (added in `256550.6810.0`)

The `oem set-retail-keymaster` command was added in `333700.2680.0`.

##### Oversight

There was an oversight in the `oem sha1` command in versions `213561.4150.0` and `256550.6810.0`. This command takes two arguments: the partition name and a size. The second argument specifies how much data will be read and hashed. By specifying incremental sizes and brute-forcing the last byte each time, it is possible to dump a whole partition.

Version `333700.2680.0` and later have a minimal size of 512 bytes, which prevents you from dumping a partition if you don't know what it begins with. 

We have implemented this process in the `oem_dump_partition.py` script (which makes use of the [PyUSB](https://github.com/pyusb/pyusb) library). In practice, dumping the n-th byte of a partition takes 3 times n seconds (most of the time is spent by the device). This greatly limits the partitions that can be dumped that way.

#### Partitions

Here is the list of partitions obtained using the `oem partition-info`:

| Name | Lun | Start | End | Size |
| ---- | --- | ----- | --- | ---- |
| `ssd` | 0 | 6 | 7 | 1 |
| `persist` | 0 | 8 | 8199 | 8191 |
| `misc` | 0 | 8200 | 8455 | 255 |
| `keystore` | 0 | 8456 | 8583 | 127 |
| `frp` | 0 | 8584 | 8711 | 127 |
| `system_a` | 0 | 8712 | 664071 | 655359 |
| `system_b` | 0 | 664072 | 1319431 | 655359 |
| `private` | 0 | 1319432 | 1335815 | 16383 |
| `vision` | 0 | 1335816 | 1466887 | 131071 |
| `userdata` | 0 | 1466888 | 15161338 | 13694450 |
| `xbl_a` | 1 | 6 | 1018 | 1012 |
| `xbl_b` | 2 | 6 | 1018 | 1012 |
| `cdt` | 3 | 6 | 6 | 0 |
| `ddr` | 3 | 7 | 262 | 255 |
| `rpm_a` | 4 | 6 | 133 | 127 |
| `tz_a` | 4 | 134 | 645 | 511 |
| `hyp_a` | 4 | 646 | 773 | 127 |
| `pmic_a` | 4 | 774 | 901 | 127 |
| `modem_a` | 4 | 902 | 29061 | 28159 |
| `bluetooth_a` | 4 | 29062 | 29317 | 255 |
| `ovrtz_a` | 4 | 29318 | 33413 | 4095 |
| `abl_a` | 4 | 33414 | 33669 | 255 |
| `keymaster_a` | 4 | 33670 | 33797 | 127 |
| `boot_a` | 4 | 33798 | 50181 | 16383 |
| `cmnlib_a` | 4 | 50182 | 50309 | 127 |
| `cmnlib64_a` | 4 | 50310 | 50437 | 127 |
| `devcfg_a` | 4 | 50438 | 50469 | 31 |
| `rpm_b` | 4 | 50470 | 50597 | 127 |
| `tz_b` | 4 | 50598 | 51109 | 511 |
| `hyp_b` | 4 | 51110 | 51237 | 127 |
| `pmic_b` | 4 | 51238 | 51365 | 127 |
| `modem_b` | 4 | 51366 | 79525 | 28159 |
| `bluetooth_b` | 4 | 79526 | 79781 | 255 |
| `ovrtz_b` | 4 | 79782 | 83877 | 4095 |
| `abl_b` | 4 | 83878 | 84133 | 255 |
| `keymaster_b` | 4 | 84134 | 84261 | 127 |
| `boot_b` | 4 | 84262 | 100645 | 16383 |
| `cmnlib_b` | 4 | 100646 | 100773 | 127 |
| `cmnlib64_b` | 4 | 100774 | 100901 | 127 |
| `devcfg_b` | 4 | 100902 | 100933 | 31 |
| `sec` | 4 | 100934 | 100937 | 3 |
| `devinfo` | 4 | 100938 | 100938 | 0 |
| `dip` | 4 | 100939 | 101194 | 255 |
| `apdp` | 4 | 101195 | 101258 | 63 |
| `msadp` | 4 | 101259 | 101322 | 63 |
| `dpo` | 4 | 101323 | 101323 | 0 |
| `splash` | 4 | 101324 | 109679 | 8355 |
| `limits` | 4 | 109680 | 109680 | 0 |
| `toolsfv` | 4 | 109681 | 109936 | 255 |
| `logfs` | 4 | 109937 | 111984 | 2047 |
| `sti` | 4 | 111985 | 112496 | 511 |
| `logdump` | 4 | 112497 | 128880 | 16383 |
| `storsec` | 4 | 128881 | 128912 | 31 |
| `modemst1` | 5 | 6 | 517 | 511 |
| `modemst2` | 5 | 518 | 1029 | 511 |
| `fsg` | 5 | 1030 | 1541 | 511 |
| `fsc` | 5 | 1542 | 1542 | 0 |

Offsets and sizes are in blocks of 4096 bytes each.

### Unlocking

Unlocking the device (in a legitimate way) is done by flashing the `unlock_token` partition. The data being flashed is made of two parts: a "bootloader script" and its signature (which strangely precedes it).

The "bootloader signature" has the following format:
```
01 <unlock_serial_len>:4 <unlock_serial>:unlock_serial_len
```

The `unlock_serial` field must of course match the device's.

The signature is verified using RSA-PSS-SHA-256 and the following public key:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm+zQa4coLC8LhrK4mYpO
EyCDeTDhhgFp34sCHHklNRh9yZLEjv21XWN6VMTdg4oVAjNNPEvRsGD/AmeTDYh/
g3sMHwWa7H5Plv77np+g9+ogIP/MMCr8OcBNmlmF4sg8RppIkqgqkA/ZJKQDZtEp
JHVeaYCx+llsbYVRXU2NpbQ0t40tuKyaDdze9tP8D1JppLzSaijTpcKmvDkPKerz
MT12Z0zV2Rvg8EdMOr+h/nQb36cMWhPewxyJoAKgcMhoWJiBiEpWO1hfAXt9//C7
bODv7Ygo5CLCM5A49ZP+lHsgBv0Mf4GTCJGLwJ1wBFoy3Dtlxe0/Jlu2RlgUAI1q
TwIDAQAB
-----END PUBLIC KEY-----
```

## Companion System

The companion is the Oculus application that you install on your Android or iOS smartphone. It communicates with the headset using Bluetooth Low Energy (BLE). It acts as a client, so there exists a server on the Quest (`CompanionServer.apk`).

### System Applications

The system applications are located in `/system/app` and `/system/priv-app` folders. They are only available in their "odexed" form, meaning that the `.apk` file only contains the resources, and that the byte-code is in the `.odex` file.

We have used [smali](https://github.com/JesusFreke/smali) by [@JesusFreke](https://github.com/JesusFreke) to convert the `.odex` file to `.smali` files, and then [dex2jar](https://github.com/pxb1988/dex2jar) by [@pxb1988](https://github.com/pxb1988) to convert the `.smali` files to `.class` files (and regroup them into a single `.jar`).
```
java -jar baksmali-2.3.jar deodex CompanionServer.odex -b boot.oat
java -jar smali-2.3.jar assemble out/ -o CompanionServer.dex
d2j-dex2jar.sh CompanionServer.dex -o CompanionServer.jar
```

Finally, the `.jar` file can be opened into [bytecode-viewer](https://github.com/Konloch/bytecode-viewer) by [@Konloch](https://github.com/), which includes 6 decompilers. We have found Procyon to work the best on this particular application, but having the ability to have multiple decompilers side-to-side, as well as the raw byte-code, makes reverse engineering a lot easier.

### Bluetooh Low Energy

#### GATT Server

To communicate with the client, as well as the controllers, the server exposes a GATT service called `Companion` (UUID: `0000FEB8-0000-1000-8000-00805F9B34FB`). This service exposes two GATT characteristics: `ccs` (UUID: `7a442881-509c-47fa-ac02-b06a37d9eb76`) and `status` (UUID: `7a442666-509c-47fa-ac02-b06a37d9eb76`). Each of the them has a  GATT descriptor called `Configuration` (UUID: `00002902-0000-1000-8000-00805f9b34fb`).

A custom protocol is used between the client and the server. It uses the `ccs` characteristic: writing the value sends data, reading the value receives data. The protocol is composed of a transport layer, a presentation layer, and an application layer (that uses Protobuf).

#### Transport Layer

The transport layer goal is pretty simple: it makes data fit within the limited MTU by:

- spliting data into chunks of size `mtu - 2`
- prefixed these chunks with an 2-byte header
    - that contains a big endian sequence number
    - whose high bit is set when it is the final chunk

#### Authentication Layer

The authentication layer protects the communications. On each new connection, the server generates a key pair that will be used to secure the channel. The client does the same. The two public keys are then exchanged during the `Hello` phase, and used to derive a secret key. It is this secret key that is used to encrypt/decrypt the later messages.

The cryptography-related functions are located inside the `libauthentication.so` native library, which wraps the well-known crypto library [`libsodium`](https://github.com/jedisct1/libsodium). The standard functions are used, which facilitates writing a client.

#### Application Layer

The application layer defines a protocol that makes use of Protobuf serialized data. The packets from the client to the server are message of type `Request`, and the ones from the server to the client of type `Response`.

The body of these messages can itself be Protobuf serialized data. For example, during the `Hello` phase, the client will send a `HelloRequest` message and the server will reply with a `HelloResponse` message that itself contains another message.


#### Messages

Here is the list of methods implemented in version `256550.6810.0`:
```
ADB_MODE_SET, ADB_MODE_STATUS, APP_LAUNCH, AUTHENTICATE, AUTOSLEEP_TIME_SET,
AUTOSLEEP_TIME_STATUS, AUTOWAKE_SET, AUTOWAKE_STATUS, CONTROLLER_PAIR,
CONTROLLER_SCAN, CONTROLLER_SCAN_AND_PAIR, CONTROLLER_SET_HANDEDNESS,
CONTROLLER_STATUS, CONTROLLER_UNPAIR, CONTROLLER_VERIFY_CONNECTABLE,
CRASH_REPORTS_ENABLED_SET, CRASH_REPORTS_ENABLED_STATUS, DEV_MODE_SET,
DEV_MODE_STATUS, HEALTH_AND_SAFETY_WARNING_SET, HELLO, HMD_CAPABILITIES,
HMD_STATUS, HMD_VERSION, LINE_FREQUENCY_SET, LINE_FREQUENCY_STATUS, LOCALE_SET,
MANAGED_MODE_SET, MANAGED_MODE_STATUS, MIRROR_REQUEST, MTP_MODE_SET,
MTP_MODE_STATUS, NAME_SET, NUX_COMPLETED, OCULUS_INSERT_LINKED_ACCOUNT,
OCULUS_LOGIN_DEPRECATED, OCULUS_LOGOUT, OCULUS_SET_ACCESS_TOKEN,
OCULUS_SET_USER_SECRET, OTA_ENABLED_SET, OTA_ENABLED_STATUS, PING, PIN_LOCK,
PIN_RESET, PIN_SET, PIN_STATUS, PIN_UNLOCK, PIN_VERIFY, SYSTEM_UNLOCK,
TEXT_SEND, TIME_SET, UNKNOWN, VERIFY_MULTIPLE_CONTROLLERS_CONNECTABLE,
WIFI_CONNECT, WIFI_DISABLE, WIFI_ENABLE, WIFI_FORGET, WIFI_RECONNECT,
WIFI_SCAN, WIFI_STATUS, WIPE_DATA
```

#### Implementation

We have written a bare-bones client implementation in Python that uses the [Core Bluetooth](https://developer.apple.com/documentation/corebluetooth) framework of macOS via the [`PyObjC`](https://bitbucket.org/ronaldoussoren/pyobjc/) bridge. You can find the client in this repository under the name `ble_companion_client.py`.

## Kernel

The kernel used by Oculus Quest was vulnerable to CVE-2018-9568 up to version `256550.6810.0` ([this commit](https://github.com/facebookincubator/oculus-linux-kernel/commit/589280fc40ddbcc2287024c8b672568a0fdd68e7#diff-56c7c22bc6dcdc2c4ff303ab61738ff2R1526) fixes the vulnerability). An exploit for it should be available in the [`exploit`](https://github.com/QuestEscape/exploit) repository.

## Miscellaneous

The internal server used to generate unlock codes is located at [https://our.internmc.facebook.com/intern/oculus/oem_unlock](https://our.internmc.facebook.com/intern/oculus/oem_unlock).
