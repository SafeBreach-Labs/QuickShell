# force_wifi_connection

Forces a target Quick Share device to connect to a specified WiFi network.
To make the WiFi connection last indefinitely, a packet that crashes Quick Share for Windows is sent once the WiFi connection is established.
Note: The easiest configuration for using this tool would be running it on a Windows computer with Windows' hotspot feature turned on and used as the the target WiFi network

## Build
Run:
```cmd
bazel build //tools:force_wifi_connection
```
The executable will be created in `./bazel-bin/tools`

## Usage
```cmd
force_wifi_connection.exe <target_bt_mac> <ap_ssid> <ap_password> <ap_freq> <ip>
```

### Parameters
* `target_bt_mac`: The bluetooth MAC address of the target Quick Share device 
* `ap_ssid`: The SSID of the WiFi network to connect to 
* `ap_password`: The password of the WiFi network to connect to 
* `ap_freq`: The frequency in MHz of the WiFi AP to connect to. Advice: use a WiFi analyzer app on your phone to find the frequency 
* `ip`: The IP to which the target Quick Share device needs to connect after the connection to the WiFi network was established.
This program assumes that the IP address belongs to the same computer on which this program runs. Thus, in order for the flow of the program to continue successfully after the WiFi connection was established, the computer on which this program runs must be in the target WiFi network.