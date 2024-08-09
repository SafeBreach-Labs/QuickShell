# QuickShell
<div align="center">
<img src="./images/quick_shell_logo.png" width="50%"/>
</div align="center">

## Overview
This project showcases the vulnerability research that we conducted on Quick Share, which we presented at DEF CON 32 (2024). Our work reveals critical vulnerabilities and includes tools we’ve developed, including a Remote Code Execution (RCE) attack chain tool.


## Repository Contents

This repository includes the tools we developed during our research:

1. **quick_shell**: Implements the entire RCE chain, overwriting an installer executable downloaded by a victim Windows device with Quick Share.
2. [**quick_sniff**](./docs/doc_quick_sniff.md): A sniffer that captures Quick Share's protocol packets, prints them textually. In addition, for each device in the session, it creates a binary file in our custom format that holds all the sent packets in the order they were sent.
3. [**send_packets**](./docs/doc_send_packets.md): Sends Quick Share's protocol packets. As input, it receives a binary file in our custom format with packets to send (the same format that the quick_sniff tool outputs).
4. [**send_file_with_bypass**](./docs/doc_send_file_with_bypass.md): Exploits the vulnerabilities we reported for Quick Share for Android & Windows that allow sending a file without authorization or acceptance by the receiver, no matter what's the current discovery mode ("Your Devices", "Contacts", or "Everyone")
5. [**force_wifi_connection**](./docs/doc_force_wifi_connection.md): Forces a device with Quick Share to connect to a given WiFi network. If performed against a Windows device with the vulnerable Quick Share version, then it also crashes its Quick Share app, creating a Wi-Fi connection to the given Wi-Fi network that lasts forever.
6. **quick_fuzz**: A fuzzer for Quick Share for Windows. Each fuzzing iteration sends a sequence of offline frames, simulating an entire transfer session.


## Further Contributions
If you have any questions or need further assistance, feel free to reach out. We look forward to your contributions and collaboration in improving this set of tools.