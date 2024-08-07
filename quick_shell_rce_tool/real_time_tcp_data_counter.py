import logging
import time
from mitm_sniffer import IMitmSniffer

class RealTimeTcpDataCounter:

    DATA_SKIP_SIZE = 1024 * 5 # Bytes

    def __init__(self, mitm_sniffer: IMitmSniffer, sender_ip: str, receiver_ip: str) -> None:
        self.__mitm_sniffer = mitm_sniffer
        self.__sender_ip = sender_ip
        self.__receiver_ip = receiver_ip

    def count_data_until_timeout(self, sec_timeout = 3.0, keep_ahead_payload_packets_count = 1, should_print_progress = True):
        total_length = 0
        payload_set = set()
        limit = 0
        
        last_relevant_packet_recv_time = 0
        sender_packet_queue = []

        while True:
            try:
                packet = self.__mitm_sniffer.recv(sec_timeout)
            except TimeoutError:
                logging.info(f"mitm sniffer timed out waiting to recv packet from mitm sniffer")
                break

            recv_time = time.time()

            # "packet.tcp == None" is a bug in pydivert we don't understand, this is how we fix it
            # Also, ignore all packets sent from the receiver, just send them
            if packet.src_addr != self.__sender_ip or packet.dst_addr != self.__receiver_ip or packet.tcp == None:
                self.__mitm_sniffer.send(packet)    
                continue

            if last_relevant_packet_recv_time != 0 and recv_time >= last_relevant_packet_recv_time + sec_timeout:
                # The sender has not sent for "sec_timeout" seconds
                logging.info(f"{self.__class__.__name__} timed out waiting to recv packet from mitm sniffer")
                break

            last_relevant_packet_recv_time = recv_time

            # Count TCP packet sizes into the total_length only if the payload was not sent already
            if len(packet.tcp.payload) > 0 and packet.tcp.payload not in payload_set:
                total_length += len(packet.tcp.payload)
                payload_set.add(packet.tcp.payload)
            else:
                is_retransmit_payload_in_sender_queue = False
                for queue_packet in sender_packet_queue:
                    if packet.tcp.payload == queue_packet.tcp.payload:
                        is_retransmit_payload_in_sender_queue = True
                
                if not is_retransmit_payload_in_sender_queue:
                    self.__mitm_sniffer.send(packet)

                continue


            if total_length < self.DATA_SKIP_SIZE:
                self.__mitm_sniffer.send(packet)
                continue
            else:
                sender_packet_queue.append(packet)

            if len(sender_packet_queue) <= keep_ahead_payload_packets_count:
                # Positioning us "keep_ahead_payload_packets_count" steps ahead of the sender
                continue

            if should_print_progress and total_length // (1024 * 1024) > limit:
                limit += 1
                if total_length > 1024**2:
                    print(f"\r{total_length // (1024**2)} MB", end="")
                elif total_length > 1024:
                    print(f"\r{total_length // (1024**2)} KB", end="")
                elif total_length > 0:
                    print(f"\r{total_length} B", end="")

            first_packet_in_queue = sender_packet_queue.pop(0)
            self.__mitm_sniffer.send(first_packet_in_queue)  # re-inject the packet into the network stack

        if should_print_progress:
            print()

        return total_length, sender_packet_queue


    