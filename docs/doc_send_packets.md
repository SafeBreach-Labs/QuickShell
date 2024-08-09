# send_packets
Sends Quick Share's protocol packets. As input, it receives a binary file in our custom format with packets to send (the same format that the quick_sniff tool outputs).

## Build
Run:
```cmd
bazel build //tools:send_packets
```
The executable will be created in `./bazel-bin/tools`

## Usage
```cmd
send_packets.exe <medium> <target_address> <packet_flow_file>
```

### Parameters
* `medium`: Determines over which communication method the file will be sent. Can be either `bt` or `wifi_lan`
* `target_address`: Sets the target address to send the file to.
  * In case the chosen `medium` is `bt`: the `target_address` parameter is a bluetooth mac address (bytes separated by ":")
  * In case the chosen `medium` is `wifi_lan`: the `target_address` parameter is an IP address and a port separated by space.
* `packet_flow_file`: Path to a file that contains serialized offline frames. The format is [DWORD little endian length][serialized offline frame] (exactly the same as the quick_sniff tool outputs). IMPORTANT - keep in mind that the send_packets tool expects a sequence of packets that is "by the book", meaning that it expects that this file will contain packets of these types and in this sequence:
  * Connection Request
  * Connection Response
  * Paired Key Encryption
  * Paired Key Result
  * Introduction
  * File
  * File Done

If you want to send your own custom sequence of packets that is different from the normal one, you can just change `send_packets.cc` to your own preference.