cc_library(
    name = "tool_helpers_library",
    srcs = ["tool_helpers/offline_frames_storage.cc", "tool_helpers/utils.cc"],
    hdrs = glob(["tool_helpers/include/*.hh", "tool_helpers/include/*.h"]),
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//common:common",
        "//quick_share:quick_share_cc_proto",
    ],
)

cc_binary(
    name = "send_packets",
    srcs = ["send_packets.cc"],
    deps = [
        ":tool_helpers_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
)

cc_binary(
    name = "send_file_with_bypass",
    srcs = ["send_file_with_bypass.cc"],
    deps = [
        ":tool_helpers_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
    visibility = [
        "//visibility:public",
    ],
)


cc_binary(
    name = "force_wifi_connection",
    srcs = ["force_wifi_connection.cc"],
    deps = [
        ":tool_helpers_library",
        "//common:common",
        "//quick_share:quick_share",
        "@argparse//:argparse",
    ],
    visibility = [
        "//visibility:public",
    ],
)

cc_binary(
    name = "quick_sniff",
    srcs = ["quick_sniff.cc", "lib/include/MinHook.h"],
    linkstatic = True,
    linkshared = 1,
    copts = ["/DCOMPILING_DLL"],
    deps = [
        ":tool_helpers_library",
        "//common:common",
        "@nlohmann_json//:json",
        "@com_google_protobuf//:protobuf"
    ],
)

py_library(
    name = "python_tool_helpers_library",
    srcs = glob(["python_tool_helpers/*.py"])
)

py_binary(
    name = "parse_packet_flows",
    srcs = ["parse_packet_flows.py"],
    deps = [
        ":python_tool_helpers_library",
        "//quick_share:quick_share_py_proto",
        "@pypi//pyyaml:pkg",
    ]
)

py_binary(
    name = "pack_packet_flows",
    srcs = ["pack_packet_flows.py"],
    deps = [
        ":python_tool_helpers_library",
        "//quick_share:quick_share_py_proto",
        "@pypi//pyyaml:pkg",
    ]
)