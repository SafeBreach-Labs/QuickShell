# quick_sniff

A sniffer that captures Quick Share's protocol packets, prints them textually. In addition, for each device in the session, it creates a binary file in our custom format that holds all the sent packets in the order they were sent.

## Build
Run:
```cmd
bazel build //tools:quick_sniff
```
The DLL will be created in `./bazel-bin/tools`

## Usage
quick_sniff is really a DLL that is injected into the Quick Share for Windows app. Therefore, once the DLL is compiled, you need to either inject the DLL into a running Quick Share app or alternatively modify the specific `nearby_sharing_dart.dll` of the Quick Share app to be dependent on `quick_sniff.dll` (using a tool like CFF Explorer for example). Inside the vulnerable version of the Quick Share app that we uploaded to this repo, you'll find a file called `nearby_sharing_dart_quick_sniff.dll` in addition to `nearby_sharing_dart.dll`. The `nearby_sharing_dart_quick_sniff.dll` file is a modified version of `nearby_sharing_dart.dll` that is dependent on `quick_sniff.dll`. Therefore, once you compiled `quick_sniff.dll` you can do these two simple actions in order to execute quick_sniff:
1. Copy `quick_sniff.dll` into the root folder of the vulnerable Quick Share app
2. Rename `nearby_sharing_dart_quick_sniff.dll` to `nearby_sharing_dart.dll` 
3. Run the vulnerable version of the app (`nearby_share.exe`)

### Parameters
Since quick_sniff is a DLL and not a command line tool, we created two constant variables at the top of the `quick_sniff.cc` file that is compiled into `quick_sniff.dll`. These are their names and purpose:
* `LOG_FILE_PATH`: A path to a log file to create. The sent and received packets will be logged into this log file.
* `PACKET_FLOW_DIR_PATH`: A path to a directory to save files in our custom format that contain sequences of sent packets. For each session between two Quick Share devices, two files will be created. Each of them contains the sequence of packets that were sent by one of the participated devices. The format is very simple - 4 bytes of length in little endian, followed by a serialized packet (the packets that Quick Share uses are called OfflineFrame, and they are defined by Protobuf. So, a serialized packet means a Protobuf serialized OfflineFrame). To better understand the custom format, read the docs about [**pack_packet_flows & parse_packet_flows**](/docs/doc_pack_parse_packet_flows.md)

### Advanced Parameters
quick_sniff works by hooking the most basic Read & Write functions that are used by Quick Share to send and receive packets using any communication method. They don't have symbols inside the compiled binary, and so we must set their addresses (offsets) statically per the version of the Quick Share app. We set the addresses to the addresses of these functions in the vulnerable version of Quick Share that is present in this repository. If you want to sniff packets on a different version, you'll have to modify the addresses. Quick explanations for how to find these functions in a disassembler are written in comments in `quick_sniff.cc`. The names of these functions in Quick Share's source code are:
* BaseEndpointChannel::Read
* BaseEndpointChannel::Write