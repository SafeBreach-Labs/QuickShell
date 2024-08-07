import logging
from threading import Lock, Thread, Event
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from dataclasses import dataclass
from enum import Enum
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
import binascii

import asyncio

class PcpType(Enum):
    P2P_STAR = 1
    P2P_CLUSTER = 2
    P2P_POINT_TO_POINT = 3

class WebRtcState(Enum):
    CONNECTABLE = 1
    UNCONNECTABLE = 2

class DeviceType(Enum):
    UNKNOWN = 0
    PHONE = 1
    TABLET = 2
    LAPTOP = 3

@dataclass
class EndpointInfo:
    name: str
    device_type: DeviceType
    raw_bytes: bytes

@dataclass
class QuickShareBleDevice:
    endpoint_id: str
    endpoint_info: EndpointInfo
    bt_addr: str

@dataclass
class QuickShareWifiLanDevice:
    name: str
    ip: str
    port: int
        

kVersionAndPcpLength = 1;
kVersionBitmask = 0x0E0;
kPcpBitmask = 0x01F;
kServiceIdHashLength = 3;
kEndpointIdLength = 4;
kEndpointInfoSizeLength = 1;
kBluetoothMacAddressLength = 6
kUwbAddressSizeLength = 1;
kExtraFieldLength = 1;
kEndpointInfoLengthBitmask = 0x0FF;
kWebRtcConnectableFlagBitmask = 0x01;

kMaxEndpointInfoLength = 131;
kMaxFastEndpointInfoLength = 17;

kMinAdvertisementLength = kVersionAndPcpLength + kServiceIdHashLength + kEndpointIdLength + kEndpointInfoSizeLength + kBluetoothMacAddressLength;
# The difference between normal and fast advertisements is that the fast one
# omits the SERVICE_ID_HASH and Bluetooth MAC address. This is done to save
# space.
kMinFastAdvertisementLength = kMinAdvertisementLength - kServiceIdHashLength - kBluetoothMacAddressLength;

ENDPOINT_INFO_VERSION_BITMASK = 0b11100000
ENDPOINT_INFO_VISIBILITY_BITMASK = 0b00010000
ENDPOINT_INFO_DEVICE_TYPE_BITMASK = 0b00001110

def create_endpoint_info_from_bytes(endpoint_info_bytes: bytes) -> EndpointInfo:
    bit_field = endpoint_info_bytes[0]
    version = (bit_field & ENDPOINT_INFO_VERSION_BITMASK) >> 5
    visibility = (bit_field & ENDPOINT_INFO_VISIBILITY_BITMASK) >> 4
    device_type_num = (bit_field & ENDPOINT_INFO_DEVICE_TYPE_BITMASK) >> 1

    expected_name_len = endpoint_info_bytes[17]
    name = endpoint_info_bytes[18:18+expected_name_len]

    if len(name) != expected_name_len:
        return None
    
    return EndpointInfo(name, DeviceType(device_type_num), endpoint_info_bytes)

def ip_bytes_to_ip_str(ip_bytes):
    ip_num_list = []
    for ip_byte in ip_bytes:
        ip_num_list.append(str(ip_byte))
    
    return ".".join(ip_num_list)


class QuickShareBleScanner:

    CONTINUOUS_SCAN_DURATION = 2 # Seconds

    def __init__(self) -> None:
        self.__bt_addr_to_quick_share_device = {}
        self.__bt_addr_to_quick_share_device_mutex = Lock()
        self.__bleak_scanner = None
        self.__should_stop_event = Event()
        self.__scan_thread = None

    async def async_start_background_scanning(self):

        def __ble_advertisement_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            for service_data in advertisement_data.service_data.values():
                quick_share_ble_device = self.convert_adv_service_data_to_device(service_data)
                if quick_share_ble_device != None:
                    with self.__bt_addr_to_quick_share_device_mutex:
                        self.__bt_addr_to_quick_share_device[quick_share_ble_device.bt_addr] = quick_share_ble_device

        self.__should_stop_event.clear()
        self.__bleak_scanner = BleakScanner(detection_callback=__ble_advertisement_callback)
        await self.__bleak_scanner.start()
        self.__bleak_scanner._backend.watcher.allow_extended_advertisements = True
        await asyncio.sleep(self.CONTINUOUS_SCAN_DURATION)
        await self.__bleak_scanner.stop()

    def __start_background_scanning_thread(self):
        while True:
            asyncio.run(self.async_start_background_scanning())
            if self.__should_stop_event.is_set():
                break

    def start_background_scanning(self):
        if self.__scan_thread != None and self.__scan_thread.is_alive():
            logging.error("Cannot start scanner when it's already running")
            return
       
        with self.__bt_addr_to_quick_share_device_mutex:
            self.__bt_addr_to_quick_share_device.clear()
       
        self.__scan_thread = Thread(target=self.__start_background_scanning_thread)
        self.__scan_thread.start()

    def stop(self):
        if self.__scan_thread == None or not self.__scan_thread.is_alive():
            logging.error("Cannot stop scanner when it's not running")
            return
        
        self.__should_stop_event.set()
        self.__scan_thread.join()

    def get_findings(self):
        with self.__bt_addr_to_quick_share_device_mutex:
            return list(self.__bt_addr_to_quick_share_device.values()) # "list()" also copies the found devices so the caller's actions on the devices won't collide with an ongoing scan
        
    def __del__(self):
        if self.__scan_thread != None and self.__scan_thread.is_alive():
            self.stop()

    @staticmethod
    def convert_adv_service_data_to_device(service_data: bytes, is_fast_adv: bool = False) -> QuickShareBleDevice:
        service_data = service_data[8:]
        min_advertisement_length = kMinFastAdvertisementLength if is_fast_adv else kMinAdvertisementLength
        if len(service_data) < min_advertisement_length:
            # Service data is less than minimum length
            return None
        
        service_data_byte_index = 0
        version_and_pcp_byte = service_data[service_data_byte_index]
        service_data_byte_index += 1
        version = (version_and_pcp_byte & kVersionBitmask) >> 5
        pcp = version_and_pcp_byte & kPcpBitmask
        if pcp not in [e.value for e in PcpType]:
            # pcp type is unknown
            return None
        
        if not is_fast_adv:
            service_id_hash = service_data[service_data_byte_index:service_data_byte_index + kServiceIdHashLength]
            service_data_byte_index += kServiceIdHashLength
        
        endpoint_id = service_data[service_data_byte_index:service_data_byte_index + kEndpointIdLength]
        service_data_byte_index += kEndpointIdLength

        expected_endpoint_info_len = service_data[service_data_byte_index]
        service_data_byte_index += 1

        endpoint_info = service_data[service_data_byte_index:service_data_byte_index + expected_endpoint_info_len]
        service_data_byte_index += expected_endpoint_info_len
    
        endpoint_info_len = len(endpoint_info)
        max_endpoint_info_length = kMaxFastEndpointInfoLength if is_fast_adv else kMaxEndpointInfoLength
        if endpoint_info_len != expected_endpoint_info_len or endpoint_info_len > max_endpoint_info_length:
            # endpoint info length is wrong
            return None
        
        if not is_fast_adv:
            bt_mac_address_bytes = service_data[service_data_byte_index:service_data_byte_index + kBluetoothMacAddressLength]
            service_data_byte_index += kBluetoothMacAddressLength

            bt_mac_address_hex_list = []
            for mac_byte in bt_mac_address_bytes:
                bt_mac_address_hex_list.append(binascii.hexlify(mac_byte.to_bytes(1,"little")).decode())
            bt_mac_address = ":".join(bt_mac_address_hex_list)
        
        if len(service_data) > service_data_byte_index:
            expected_uwb_address_length = service_data[service_data_byte_index]
            service_data_byte_index += 1
            uwb_address = service_data[service_data_byte_index:service_data_byte_index + expected_uwb_address_length]
            service_data_byte_index += expected_uwb_address_length
            if len(uwb_address) != expected_uwb_address_length:
                # Got unexpected len for UWB address
                return None
        
            if not is_fast_adv and service_data_byte_index < len(service_data):
                extra_field = service_data[service_data_byte_index]
                service_data_byte_index += 1
                web_rtc_state = WebRtcState.CONNECTABLE.value if (extra_field & kWebRtcConnectableFlagBitmask) == 1 else WebRtcState.UNCONNECTABLE.value

        return QuickShareBleDevice(endpoint_id, create_endpoint_info_from_bytes(endpoint_info), bt_mac_address)


class QuickShareWifiLanScanner:

    QUICK_SHARE_MDNS_SERVICE_TYPE = "_FC9F5ED42C8A._tcp.local."

    class MyListener(ServiceListener):
        def __init__(self, ip_addr_to_wifi_lan_device: dict[str, QuickShareWifiLanDevice], ip_addr_to_wifi_lan_device_mutex) -> None:
            super().__init__()
            self.__mdns_names_to_wifi_lan_devices = ip_addr_to_wifi_lan_device
            self.__ip_addr_to_wifi_lan_device_mutex = ip_addr_to_wifi_lan_device_mutex

        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            ip_addr = ip_bytes_to_ip_str(info.addresses[0])
            with self.__ip_addr_to_wifi_lan_device_mutex:
                self.__mdns_names_to_wifi_lan_devices[name] = QuickShareWifiLanDevice(name, ip_addr, info.port)

        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name)
            ip_addr = ip_bytes_to_ip_str(info.addresses[0])
            with self.__ip_addr_to_wifi_lan_device_mutex:
                self.__mdns_names_to_wifi_lan_devices[name] = QuickShareWifiLanDevice(name, ip_addr, info.port)

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            with self.__ip_addr_to_wifi_lan_device_mutex:
                self.__mdns_names_to_wifi_lan_devices.pop(name)

    def __init__(self) -> None:
        self.__ip_addr_to_wifi_lan_device_mutex = Lock()
        self.__mdns_names_to_wifi_lan_devices = {}
        self.__zeroconf = None
    
    def start_background_scanning(self):
        if self.__zeroconf != None:
            logging.error("Cannot start scanner when it's already running")
            return
        self.__mdns_names_to_wifi_lan_devices.clear()
        zeroconf = Zeroconf()
        listener = self.MyListener(self.__mdns_names_to_wifi_lan_devices, self.__ip_addr_to_wifi_lan_device_mutex)
        browser = ServiceBrowser(zeroconf, self.QUICK_SHARE_MDNS_SERVICE_TYPE, listener)

    def stop(self):
        if self.__zeroconf == None:
            logging.error(f"{self.__class__.__name__} was not start yet, so it cannot be stopped")
            return
        self.__zeroconf.close()
        self.__zeroconf = None

    def get_findings(self) -> list[QuickShareWifiLanDevice]:
        with self.__ip_addr_to_wifi_lan_device_mutex:
            return list(self.__mdns_names_to_wifi_lan_devices.values()) # "list()" also copies the found devices so the caller's actions on the devices won't collide with an ongoing scan
        
    def __del__(self):
        if self.__zeroconf != None:
            self.stop()



