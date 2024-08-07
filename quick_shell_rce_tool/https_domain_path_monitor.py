import time
import logging
from typing import Dict
from scapy.all import IP
from scapy.layers.all import load_layer
from scapy.layers.tls.all import TLS

from domain_path import DomainPath
from mitm_sniffer import get_mitm_sniffer, IMitmSniffer

TLS_PACKET_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1
TLS_EXTENTION_TYPE_SERVER_NAME = 0

load_layer("tls")
def is_packet_tls_client_hello_for_domain(packet, domain):
    scapy_packet = IP((bytes(packet.raw)))
    try:
        # Check for TLS CLIENT HELLO packet with matching server name
        if scapy_packet[TLS].type == TLS_PACKET_TYPE_HANDSHAKE and scapy_packet[TLS].msg[0].msgtype == TLS_HANDSHAKE_TYPE_CLIENT_HELLO: # and packet.tls.handshake_extensions_server_name == "vscode.download.prss.microsoft.com":
            for ext in scapy_packet[TLS].msg[0].ext:
                if ext.type == TLS_EXTENTION_TYPE_SERVER_NAME:
                    logging.info(f"Victim accessed this domain: {ext.servernames[0].servername.decode()}")
                    if ext.servernames[0].servername.decode() == domain:
                        return True
    except (AttributeError, IndexError) as e:
        # Handle cases where TLS fields might be missing
        pass

    return False


class HttpsDomainPathMonitor:

    def __init__(self, mitm_sniffer: IMitmSniffer, domain_paths_to_monitor: list[DomainPath]) -> None:
        self.__mitm_sniffer = mitm_sniffer
        self.__domain_paths_to_monitor = domain_paths_to_monitor

    def monitor_until_hit(self) -> DomainPath:
        self.__mitm_sniffer = get_mitm_sniffer()

        # DomainPaths to number of hits in them
        domain_paths_to_hit_count: Dict[DomainPath, int] = {domain_path: 0 for domain_path in self.__domain_paths_to_monitor}
        domain_paths_to_last_hit_time: Dict[DomainPath, int] = {}
        domain_paths_to_ips : Dict[DomainPath: list[str]] = {}

        while True:
            packet = self.__mitm_sniffer.recv()
            sec_recv_time = time.time()  # Final result is in milliseconds
            self.__mitm_sniffer.send(packet)

            for domain_path, hit_count in domain_paths_to_hit_count.items():
                if not is_packet_tls_client_hello_for_domain(packet, domain_path.domain_order[hit_count].domain_str):
                    continue

                sec_last_hit_time = domain_paths_to_last_hit_time.get(domain_path, 0)
                
                if sec_last_hit_time != 0 and sec_recv_time - sec_last_hit_time > domain_path.sec_delay_between_domains:
                    domain_paths_to_last_hit_time[domain_path] = 0
                    domain_paths_to_hit_count[domain_path] = 0
                    domain_paths_to_ips[domain_path] = []
                    continue
            
                domain_paths_to_last_hit_time[domain_path] = sec_recv_time
                domain_paths_to_hit_count[domain_path] += 1
                
                
                if domain_paths_to_ips.get(domain_path):
                    domain_paths_to_ips[domain_path].append(packet.dst_addr)
                else:
                    domain_paths_to_ips[domain_path] = [packet.dst_addr]
        
                if domain_paths_to_hit_count[domain_path] == len(domain_path.domain_order):
                    # We have a full hit for all the domains in the domain path
                    return domain_path, domain_paths_to_ips[domain_path]
