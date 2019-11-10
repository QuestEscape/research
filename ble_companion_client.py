import struct
import sys
import threading

from Foundation import *
from PyObjCTools import AppHelper

from protobuf3.message import Message
from protobuf3.fields import UInt32Field, EnumField, BytesField, BoolField
from enum import Enum

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random

from IPython.terminal.embed import InteractiveShellEmbed

class Method(Enum):
    ADB_MODE_SET = 6005
    ADB_MODE_STATUS = 6006
    APP_LAUNCH = 7001
    AUTHENTICATE = 2
    AUTOSLEEP_TIME_SET = 6013
    AUTOSLEEP_TIME_STATUS = 6014
    AUTOWAKE_SET = 6011
    AUTOWAKE_STATUS = 6012
    CONTROLLER_PAIR = 3002
    CONTROLLER_SCAN = 3001
    CONTROLLER_SCAN_AND_PAIR = 3006
    CONTROLLER_SET_HANDEDNESS = 3005
    CONTROLLER_STATUS = 3003
    CONTROLLER_UNPAIR = 3004
    CONTROLLER_VERIFY_CONNECTABLE = 3007
    CRASH_REPORTS_ENABLED_SET = 6009
    CRASH_REPORTS_ENABLED_STATUS = 6010
    DEV_MODE_SET = 6001
    DEV_MODE_STATUS = 6002
    HEALTH_AND_SAFETY_WARNING_SET = 9101
    HELLO = 1
    HMD_CAPABILITIES = 8003
    HMD_STATUS = 8001
    HMD_VERSION = 8002
    LINE_FREQUENCY_SET = 6016
    LINE_FREQUENCY_STATUS = 6017
    LOCALE_SET = 9001
    MANAGED_MODE_SET = 11001
    MANAGED_MODE_STATUS = 11002
    MIRROR_REQUEST = 10001
    MTP_MODE_SET = 6003
    MTP_MODE_STATUS = 6004
    NAME_SET = 6015
    NUX_COMPLETED = 9201
    OCULUS_INSERT_LINKED_ACCOUNT = 2101
    OCULUS_LOGIN_DEPRECATED = 2001
    OCULUS_LOGOUT = 2002
    OCULUS_SET_ACCESS_TOKEN = 2004
    OCULUS_SET_USER_SECRET = 2003
    OTA_ENABLED_SET = 6007
    OTA_ENABLED_STATUS = 6008
    PING = 0
    PIN_LOCK = 4003
    PIN_RESET = 4006
    PIN_SET = 4001
    PIN_STATUS = 4002
    PIN_UNLOCK = 4004
    PIN_VERIFY = 4005
    SYSTEM_UNLOCK = 9301
    TEXT_SEND = 12001
    TIME_SET = 9002
    UNKNOWN = 99999
    VERIFY_MULTIPLE_CONTROLLERS_CONNECTABLE = 3008
    WIFI_CONNECT = 1002
    WIFI_DISABLE = 1006
    WIFI_ENABLE = 1005
    WIFI_FORGET = 1004
    WIFI_RECONNECT = 1007
    WIFI_SCAN = 1001
    WIFI_STATUS = 1003
    WIPE_DATA = 5001

class Request(Message):
    version = UInt32Field(field_number=1)
    method = EnumField(field_number=2, enum_cls=Method)
    seq = UInt32Field(field_number=3)
    body = BytesField(field_number=4)

class ResponseCode(Enum):
    SUCCESS = 0
    FAIL = 1
    FAIL_RETRY = 2

class Response(Message):
    seq = UInt32Field(field_number=1)
    code = EnumField(field_number=2, enum_cls=ResponseCode)
    body = BytesField(field_number=3)

class ErrorCode(Enum):
    ALREADY_IN_PROGRESS = 7
    APP_LAUNCH_ERROR = 501
    APP_NOT_INSTALLED = 502
    AUTHENTICATION_FAILURE = 5
    BAD_ACCESS_TOKEN = 13
    BAD_ARGUEMENT = 4
    BAD_LOCK_PIN = 401
    BAD_PERIPHERAL_ADDRESS = 31
    BAD_PERIPHERAL_DEVICE = 30
    BAD_REQUEST = 1
    BATTERY_TOO_LOW = 3
    CONTROLLER_BLOCKED_BY_UPDATE = 604
    CONTROLLER_INTERNAL_ERROR = 603
    CONTROLLER_PAIR_FAILED = 601
    CONTROLLER_PAIR_REQUIRED = 602
    DEVICE_BLE_ERROR = 15
    DEVICE_WIFI_ERROR = 14
    PIN_LOCK_NOT_SET = 402
    TIMED_OUT = 6
    TOO_MANY_PIN_TRIES = 403
    UNKNOWN_ERROR = 0
    UNSUPPORTED_METHOD = 2
    USER_PIN_REQUIRED = 8
    WIFI_AUTH_TIMEOUT = 17
    WIFI_INVALID_AUTH = 12
    WIFI_IP_CONFIG_FAIL = 18
    WIFI_NO_INTERNET = 16
    WIFI_NO_NETWORK = 11

class ErrorDetails(Message):
    code = EnumField(field_number=1, enum_cls=ErrorCode)
    debugDetails = BytesField(field_number=2)
    localizedUserFacingDescription = BytesField(field_number=3)

class HelloRequest(Message):
    clientPublicKey = BytesField(field_number=1)
    clientChallenge = BytesField(field_number=2)
    knownCertFingerprint = BytesField(field_number=3)

class HelloSignedData(Message):
    serverPublicKey = BytesField(field_number=1)
    authenticationChallenge = BytesField(field_number=2)
    deviceNeedsToBeUnlocked = BoolField(field_number=3)

class HelloResponse(Message):
    signedData = BytesField(field_number=1)
    signature = BytesField(field_number=2)
    serverCertificate = BytesField(field_number=3)

class AppLaunchRequest(Message):
    appId = BytesField(field_number=1)
    packageName = BytesField(field_number=2)

class DevModeRequest(Message):
    mode = UInt32Field(field_number=1)

class DevModeResponse(Message):
    status = UInt32Field(field_number=1)

class OtaEnabledRequest(Message):
    enable = BoolField(field_number=1)

class OtaEnabledResponse(Message):
    enabled = BoolField(field_number=1)

class State(Enum):
    STATE_INIT = 0
    EXCHANGE_HELLO = 1
    CHALLENGE_RESPONSE = 2
    WAIT_FOR_COMMAND = 3

class BleModule(object):
    COMPANION_DEVICE_UUID = '7A1FAD2E-AA0E-4840-8E48-AF278FA86911'
    COMPANION_CCS_UUID = '7A442881-509C-47FA-AC02-B06A37D9EB76'
    COMPANION_STATUS_UUID = '7A442666-509C-47FA-AC02-B06A37D9EB76'

    def centralManagerDidUpdateState_(self, manager):
        self.manager = manager
        manager.scanForPeripheralsWithServices_options_(None, None)

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(self, manager, peripheral, data, rssi):
        if BleModule.COMPANION_DEVICE_UUID in repr(peripheral.UUID):
            self.peripheral = peripheral
            manager.connectPeripheral_options_(peripheral, None)
            manager.stopScan()

    def centralManager_didConnectPeripheral_(self, manager, peripheral):
        peripheral.setDelegate_(self)
        peripheral.discoverServices_([])

    def peripheral_didDiscoverServices_(self, peripheral, services):
        service = peripheral.services()[0]
        peripheral.discoverCharacteristics_forService_([], service)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        for characteristic in service.characteristics():
            if BleModule.COMPANION_CCS_UUID in repr(characteristic.UUID):
                self.ccs = characteristic
                self.recv_message(b"")
            if BleModule.COMPANION_STATUS_UUID in repr(characteristic.UUID):
                self.status = characteristic

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, characteristic, error):
        value = characteristic.value()
        if value not in [b'\xff', b'----']:
            self.recv_transport(value)
        peripheral.readValueForCharacteristic_(characteristic)

    def peripheral_didWriteValueForCharacteristic_error_(self, peripheral, characteristic, error):
        peripheral.readValueForCharacteristic_(characteristic)

    def send_ble_module(self, data):
        # print(">", data)
        value = NSData.dataWithBytes_length_(data, len(data))
        self.peripheral.writeValue_forCharacteristic_type_(value, self.ccs, 0)

class CompanionClient(BleModule):
    def __init__(self):
        super(CompanionClient, self).__init__()

        self.mtu = 20
        self.value = bytearray()
        self.prev_seq = -1

        self.secure = False
        self.pub_key = None
        self.priv_key = PrivateKey.generate()
        self.box = None

        self.seq = 0
        self.state = State.STATE_INIT
        self.handler = self.handle_not_implemented

    def recv_transport(self, data):
        # print("<", data)
        seq = struct.unpack('>H', data[:2])[0]
        self.value.extend(data[2:])
        assert seq & 0x7fff == self.prev_seq + 1

        resp = None
        if seq & 0x8000:
            resp = bytes(self.value)
            self.recv_authentication(resp)
            self.value.clear()
            self.prev_seq = -1
        else:
            self.prev_seq = seq

    def send_transport(self, data):
        chunks = []
        seq = 0
        for off in range(0, len(data), self.mtu - 2):
            size = min(self.mtu - 2, len(data) - off)
            header = struct.pack('>H', seq)
            chunks.append(header + data[off:off + size])
            seq += 1

        last = bytearray(chunks[-1])
        last[0] |= last[0] | 0x80
        chunks[-1] = bytes(last)

        for chunk in chunks:
            self.send_ble_module(chunk)

    def recv_authentication(self, data):
        if self.secure:
            data = self.box.decrypt(data)
        self.recv_message(data)

    def send_authentication(self, data):
        if self.secure:
            data = self.box.encrypt(data)
        self.send_transport(data)

    def recv_message(self, data):
        resp = Response()
        resp.parse_from_bytes(data)

        if self.state == State.STATE_INIT:
            self.send_hello_request()
            self.state = State.EXCHANGE_HELLO

        elif self.state == State.EXCHANGE_HELLO:
            self.recv_hello_response(resp.body)
            self.state = State.WAIT_FOR_COMMAND

        elif self.state == State.WAIT_FOR_COMMAND:
            if self.handler:
                self.handler(resp.code, resp.body)

    def send_message(self, method, body=None, handler=None):
        if handler:
            self.handler = handler
        else:
            self.handler = self.handle_not_implemented

        req = Request()
        req.version = 0
        req.method = method
        req.seq = self.seq
        self.seq += 1
        if body:
            req.body = body.encode_to_bytes()
        self.send_authentication(req.encode_to_bytes())

    def send_hello_request(self):
        hello = HelloRequest()
        hello.clientPublicKey = self.priv_key.public_key.encode()
        hello.clientChallenge = b"\x00"
        self.send_message(Method.HELLO, hello)

    def recv_hello_response(self, body):
        hello = HelloResponse()
        hello.parse_from_bytes(body)

        signed_data = HelloSignedData()
        signed_data.parse_from_bytes(hello.signedData)

        self.secure = True
        self.pub_key = PublicKey(signed_data.serverPublicKey)
        self.box = Box(self.priv_key, self.pub_key)

        # please forgive me for writing this monstrosity
        shell = InteractiveShellEmbed()
        threading.Thread(target=shell, kwargs={"local_ns": {"client": self}}).start()

    def handle_not_implemented(self, code, body):
        if code == ResponseCode.SUCCESS:
            print(code)
            print(body)
        else:
            details = ErrorDetails()
            details.parse_from_bytes(body)
            print(details.code)
            if details.debugDetails:
                print(details.debugDetails.decode('utf-8'))
            if details.localizedUserFacingDescription:
                print(details.localizedUserFacingDescription.decode('utf-8'))

    def ping(self):
        def handler(code, body):
            print("Pong!")
        self.send_message(Method.PING, handler=handler)

    def launch_app(self, appId, packageName):
        def handler(code, body):
            print("Success")
        req = AppLaunchRequest()
        req.appId = appId
        req.packageName = packageName
        self.send_message(Method.APP_LAUNCH, req, handler=handler)

    def dev_mode_status(self):
        def handler(code, body):
            resp = DevModeResponse()
            resp.parse_from_bytes(body)
            print("Status: %d" % resp.status)
        self.send_message(Method.DEV_MODE_STATUS, handler=handler)

    def dev_mode_set(self, mode):
        def handler(code, body):
            print("Success")
        req = DevModeRequest()
        req.mode = mode
        self.send_message(Method.DEV_MODE_SET, req, handler=handler)

    def ota_enabled_status(self):
        def handler(code, body):
            resp = OtaEnabledResponse()
            resp.parse_from_bytes(body)
            print("Enabled: %s" % resp.enabled)
        self.send_message(Method.OTA_ENABLED_STATUS, handler=handler)

    def ota_enabled_set(self, enable):
        def handler(code, body):
            print("Success")
        req = OtaEnabledRequest()
        req.enable = enable
        self.send_message(Method.OTA_ENABLED_SET, req, handler=handler)

if __name__ == '__main__':
    try:
        central_manager = CBCentralManager.alloc()
        central_manager.initWithDelegate_queue_options_(CompanionClient(), None, None)
        AppHelper.runConsoleEventLoop()
    except KeyboardInterrupt:
        sys.exit()
