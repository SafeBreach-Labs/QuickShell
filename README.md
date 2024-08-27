# QuickShell

<div align="center">
<img src="./images/quick_shell_logo.png" width="50%"/>
</div align="center">

## Overview

This project showcases the vulnerability research that we conducted on Quick Share, which we presented at DEF CON 32 (2024). Our work reveals critical vulnerabilities and includes tools we’ve developed, including a Remote Code Execution (RCE) attack chain tool.

* [DEF CON Talk link](https://defcon.org/html/defcon-32/dc-32-speakers.html#54485)

* [Technical Blog Post link](https://www.safebreach.com/blog/rce-attack-chain-on-quick-share)


## Repository Contents

This repository includes the tools we developed during our research:

1. [**quick_shell**](./docs/doc_quick_shell.md): Implements the entire RCE chain, overwriting an installer executable downloaded by a victim Windows device with Quick Share.
2. [**quick_sniff**](./docs/doc_quick_sniff.md): A sniffer that captures Quick Share's protocol packets, prints them textually. In addition, for each device in the session, it creates a binary file in our custom format that holds all the sent packets in the order they were sent.
3. [**send_packets**](./docs/doc_send_packets.md): Sends Quick Share's protocol packets. As input, it receives a binary file in our custom format with packets to send (the same format that the quick_sniff tool outputs).
4. [**send_file_with_bypass**](./docs/doc_send_file_with_bypass.md): Exploits the vulnerabilities we reported for Quick Share for Android & Windows that allow sending a file without authorization or acceptance by the receiver, no matter what's the current discovery mode ("Your Devices", "Contacts", or "Everyone")
5. [**force_wifi_connection**](./docs/doc_force_wifi_connection.md): Forces a device with Quick Share to connect to a given WiFi network. If performed against a Windows device with the vulnerable Quick Share version, then it also crashes its Quick Share app, creating a Wi-Fi connection to the given Wi-Fi network that lasts forever.
6. [**quick_fuzz**](./docs/doc_quick_fuzz.md): A fuzzer for Quick Share for Windows. Each fuzzing iteration sends a sequence of offline frames, simulating an entire transfer session.

### Supporting Tools

1. [**pack_packet_flows & parse_packet_flows**](./docs/doc_pack_parse_packet_flows.md)

## Building Tools

This repository uses Bazel for building. In order to build the tools you'll need to install Bazel - [Install Bazel on Windows](https://bazel.build/install/windows)

## Authors - Or Yair & Shmuel Cohen

|          | Or Yair                                         | Shmuel Cohen                                                  |
|----------|-------------------------------------------------|---------------------------------------------------------------|
| LinkedIn | [Or Yair](https://www.linkedin.com/in/or-yair/) | [Shmuel Cohen](https://www.linkedin.com/in/the-shmuel-cohen/) |
| Twitter  | [@oryair1999](https://twitter.com/oryair1999)   | [@\_BinWalker\_](https://twitter.com/_BinWalker_)             |

## Further Contributions

If you have any questions or need further assistance, feel free to reach out. We look forward to your contributions and collaboration in improving this set of tools.