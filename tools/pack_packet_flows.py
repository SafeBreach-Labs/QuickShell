import argparse
import os
import yaml

from python_tool_helpers.offline_frames_utils import offline_frame_dict_to_offline_frame


def parse_args():
    parser = argparse.ArgumentParser(description="Packs (serializes) Quick Share's (OfflineFrame) packets' pretty YAML files into their protobuf serialized byte form")

    parser.add_argument("packets_dir", help="A path to a directory containing all YAML packets")
    parser.add_argument("out_file", help="A path to the packets file to be created")

    return parser.parse_args()


def main():
    args = parse_args()
    packets_dir_path = os.path.abspath(args.packets_dir)
    output_file_path = os.path.abspath(args.out_file)
    offline_frame_list = []

    dir_files = os.listdir(packets_dir_path)
    dir_files.sort(key=lambda filename: int(filename.replace("packet_", "").replace(".yaml", "")))
    for filename in dir_files:
        packet_file_path = os.path.join(packets_dir_path, filename)
        if os.path.isfile(packet_file_path) and packet_file_path.endswith(".yaml"):
            with open(packet_file_path, "r") as f:
                current_offline_frame = offline_frame_dict_to_offline_frame(yaml.safe_load(f))
            offline_frame_list.append(current_offline_frame)

    with open(output_file_path, "wb") as f:
        for offline_frame in offline_frame_list:
            offline_frame_bytes = offline_frame.SerializeToString()
            f.write(len(offline_frame_bytes).to_bytes(4, "little"))
            f.write(offline_frame_bytes)


if __name__ == "__main__":
    main()