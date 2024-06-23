

cc_library(
    name = "tools_library",
    srcs = ["offline_frames_storage.cc", "utils.cc"],
    hdrs = glob(["include/*.hh", "include/*.h"]),
    deps = [
        "//logger:logger",
        "//quick_share:quick_share",
    ],
)

cc_binary(
    name = "send_packets",
    srcs = ["send_packets.cc"],
    deps = [
        ":tools_library",
        "//logger:logger",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)

cc_binary(
    name = "send_file_with_bypass",
    srcs = ["send_file_with_bypass.cc"],
    deps = [
        ":tools_library",
        "//logger:logger",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)


cc_binary(
    name = "force_wifi_connection",
    srcs = ["force_wifi_connection.cc"],
    deps = [
        ":tools_library",
        "//logger:logger",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)

cc_binary(
    name = "quick_shell_communication_tools",
    srcs = [],
    linkstatic = True,
    linkshared = 1,
    copts = ["/DCOMPILING_DLL"],
    deps = [
        ":force_wifi_connection",
        ":send_file_with_bypass",
        ":send_packets",
    ],
)