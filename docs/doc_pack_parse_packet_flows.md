# pack_packet_flows & parse_packet_flows

Tools for packing and parsing our custom binary format for representing sequences of packets (OfflineFrames). The format is simple:

`[DWORD Length][Serialized Offline Frame][DWORD Length][Serialized Offline Frame]...`

* [DWORD Length] - Four bytes that represent the size of a packet in little endian
* [Serialized Offline Frame] - A serialized protobuf packet (OfflineFrame)

Three of the tools that we developed in this repo use these custom format:
* [**quick_fuzz**](/docs/doc_quick_fuzz.md) - Receives files in this format as corpus (fuzzing input files)
* [**send_packets**](/docs/doc_send_packets.md) - Receives files in this format as an input, and sends the contained packets
* [**quick_sniff**](/docs/doc_quick_sniff.md) - Outputs files in this format that hold the sequence of packets that each device that participated a sniffed session sent


## Build
Run:
```cmd
bazel build //tools:pack_packet_flows
bazel build //tools:parse_packet_flows
```
The executables will be created in `./bazel-bin/tools`

## Usage
pack_packet_flows:

```cmd
usage: pack_packet_flows.py [-h] parsed_packet_flow_dir out_packet_flow_file

Packs (serializes) Quick Share's (OfflineFrame) packets' pretty YAML files into their     
protobuf serialized byte form

positional arguments:
  parsed_packet_flow_dir
                        A path to a directory containing all packets in YAML (as
                        parse_packet_flows parses outputs)
  out_packet_flow_file  A path to the packets file to be create
```

parse_packet_flows:

```cmd
usage: parse_packet_flows.py [-h] packet_flow_file out_dir

Parse Quick Share's (OfflineFrame) packets into textual readable YAML structures

positional arguments:
  packet_flow_file  A path to a file with containing all packets in
                    |length|packet|length|packet| format
  out_dir           A path to a directory where the output file/s will be created
```

### Advanced Parameters
quick_sniff works by hooking the most basic Read & Write functions that are used by Quick Share to send and receive packets using any communication method. They don't have symbols inside the compiled binary, and so we must set their addresses (offsets) statically per the version of the Quick Share app. We set the addresses to the addresses of these functions in the vulnerable version of Quick Share that is present in this repository. If you want to sniff packets on a different version, you'll have to modify the addresses. Quick explanations for how to find these functions in a disassembler are written in comments in `quick_sniff.cc`. The names of these functions in Quick Share's source code are:
* BaseEndpointChannel::Read
* BaseEndpointChannel::Write