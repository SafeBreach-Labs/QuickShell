import argparse
import os
import yaml

from tools.python_tool_helpers.offline_frames_utils import decode_offline_frame_protobuf_bytes


def parse_args():
    parser = argparse.ArgumentParser(description="Parse Quick Share's (OfflineFrame) packets into textual readable YAML structures")

    parser.add_argument("packet_flow_file", help="A path to a file with containing all packets in |length|packet|length|packet| format")
    parser.add_argument("out_dir", help="A path to a directory where the output file/s will be created")

    return parser.parse_args()


def main():
    args = parse_args()
    packets_file_path = os.path.abspath(args.packets_file)
    output_dir = os.path.abspath(args.out_dir)

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    with open(packets_file_path, "rb") as f:
        packets_buffer = f.read()

    packet_count = 0
    while 0 != len(packets_buffer):
        packet_length_bytes = packets_buffer[:4]
        packet_length = int.from_bytes(packet_length_bytes, "little")
        packets_buffer = packets_buffer[4:]
        current_packet_bytes = packets_buffer[:packet_length]
        packets_buffer = packets_buffer[packet_length:]

        offline_frame_dict = decode_offline_frame_protobuf_bytes(current_packet_bytes)
        parsed_file_path = os.path.join(output_dir, f"packet_{packet_count}.yaml")
        
        with open(parsed_file_path, "w") as f:
            yaml.dump(offline_frame_dict, f)

        packet_count += 1


if __name__ == "__main__":
    main()