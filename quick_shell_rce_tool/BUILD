py_library(
    name = "quick_shell_py_deps",
    srcs = glob(["*.py"]),

)

py_binary(
    name = "quick_shell",
    srcs = glob(["*.py"]),
    deps = [
        "//quick_share:quick_share_py_proto",
        "//tools:force_wifi_connection",
        "//tools:send_file_with_bypass",
    ]
)
