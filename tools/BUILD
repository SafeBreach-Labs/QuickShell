

cc_library(
    name = "tools_library",
    srcs = ["offline_frames_storage.cc", "utils.cc"],
    hdrs = glob(["include/*.hh", "include/*.h"]),
    deps = [
        "//common:common",
        "//quick_share:quick_share_cc_proto",
    ],
)

cc_binary(
    name = "send_packets",
    srcs = ["send_packets.cc"],
    deps = [
        ":tools_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)

cc_binary(
    name = "send_file_with_bypass",
    srcs = ["send_file_with_bypass.cc"],
    deps = [
        ":tools_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)


cc_binary(
    name = "send_file_with_bypass_after_fix",
    srcs = ["send_file_with_bypass_after_fix.cc"],
    deps = [
        ":tools_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)


cc_binary(
    name = "force_wifi_connection",
    srcs = ["force_wifi_connection.cc"],
    deps = [
        ":tools_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)

cc_binary(
    name = "quick_sniff",
    srcs = ["quick_sniff.cc", "lib/include/MinHook.h"],
    linkstatic = True,
    linkshared = 1,
    copts = ["/DCOMPILING_DLL"],
    deps = [
        ":tools_library",
        "//common:common",
        "@nlohmann_json//:json",
    ],
)