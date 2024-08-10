import pydivert
import threading
from abc import ABC, abstractmethod

class SnifferPacket(pydivert.Packet):
    pass

class IMitmSniffer(ABC):
    
    @abstractmethod
    def open(self):
        pass
    
    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def recv(self, sec_timeout: int) -> SnifferPacket:
        pass
    
    @abstractmethod
    def send(self, packet: SnifferPacket):
        pass
        
        
class PyDivertMitmSniffer(IMitmSniffer):

    def __init__(self, windivert_filter: str) -> None:
        self.__pydivert_capture = pydivert.WinDivert(filter = windivert_filter, layer = pydivert.Layer.NETWORK_FORWARD)
        self.__pydivert_capture._filter
        self.__is_open = False
        self.__pydivert_recv_packet = None
        self.__recv_thread = None
        
    def open(self):
        self.__pydivert_capture.open()
        self.__is_open = True

    def close(self):
        if self.__recv_thread != None and self.__recv_thread.is_alive():
            self.__recv_thread._stop()
            
        self.__pydivert_capture.close()
        self.__is_open = False

    def recv(self, sec_timeout: int = None) -> SnifferPacket:
        if self.__recv_thread != None and self.__recv_thread.is_alive():
            self.__recv_thread.join(sec_timeout)
            if self.__recv_thread.is_alive():
                raise TimeoutError(f"{self.__class__.__name__} timed out while receiving a packet")
            return self.__pydivert_recv_packet
            
        if sec_timeout == None:
            return self.__pydivert_capture.recv()

        self.__recv_thread = threading.Thread(target=self.__pydivert_recv)
        self.__recv_thread.start()
        self.__recv_thread.join(sec_timeout) # Wait for the thread to finish
        if self.__recv_thread.is_alive():
            raise TimeoutError(f"{self.__class__.__name__} timed out while receiving a packet")
        
        return self.__pydivert_recv_packet
    
    def send(self, packet: SnifferPacket):
        self.__pydivert_capture.send(packet)

    def __del__(self):
        if self.__is_open:
            self.close()
    
    def __pydivert_recv(self):
        self.__pydivert_recv_packet = self.__pydivert_capture.recv()


g_mitm_sniffer = None


def init_pydivert_mitm_sniffer(windivert_filter: str):
    global g_mitm_sniffer
    g_mitm_sniffer = PyDivertMitmSniffer(windivert_filter)

def get_mitm_sniffer() -> IMitmSniffer:
    return g_mitm_sniffer