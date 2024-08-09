# send_file_with_bypass
Sends a file to a Quick Share device while bypassing authorization and acceptance of the file by the victim user.
## Usage
```cmd
send_file_with_bypass.exe <medium> <target_address> <path_of_file_to_send> <name_to_send_in_base64>
```

### Parameters
* `medium`: Determines over which communication method the file will be sent. Can be either `bt` or `wifi_lan`
* `target_address`: Sets the target address to send the file to.
  * In case the chosen `medium` is `bt`: the `target_address` parameter is a bluetooth mac address (bytes separated by ":")
  * In case the chosen `medium` is `wifi_lan`: the `target_address` parameter is an IP address and a port separated by space.
* `path_of_file_to_send`: A path on the local computer that points to a file with the content to send. IMPORTANT - A file is sent in chunks. We have not yet added support for chunks, and so the maximum size for a file to be sent is the maximum chunk size which is 1047552 Bytes (one byte less than 1MB).
* `name_to_send_in_base64`: The that should be set for the content of the file that is sent, encoded in base64 (so you can provide names with unprintable characters)