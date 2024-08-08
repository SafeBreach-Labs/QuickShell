py_library(
    name = "quick_shell_py_deps",
    srcs = glob(["*.py"], exclude = ["quick_shell.py"]),
    deps = [
        "@pypi//pydivert:pkg",
        "@pypi//zeroconf:pkg",
        "@pypi//bleak:pkg",
        "@pypi//scapy:pkg",
        "@pypi//pyyaml:pkg",
        "@pypi//parse:pkg",
    ]
)

py_binary(
    name = "quick_shell",
    srcs = ["quick_shell.py"],
    deps = [
        ":quick_shell_py_deps",
        "//tools:force_wifi_connection",
        "//tools:send_file_with_bypass",
    ]
)
