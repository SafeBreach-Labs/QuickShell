proto_library(
    name = "quick_share_proto",
    srcs = [
        "proto/offline_wire_formats.proto",
        "proto/wire_format.proto"
    ],
    visibility = [
        "//visibility:private",
    ],
)

cc_proto_library(
    name = "quick_share_cc_proto",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":quick_share_proto",
    ],
)

load("@com_google_protobuf//:protobuf.bzl", "py_proto_library")

py_proto_library(
    name = "quick_share_py_proto",
    srcs = [
        "proto/offline_wire_formats.proto",
        "proto/wire_format.proto"
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "quick_share",
    srcs = ["quick_share_medium.cc", "quick_share_connection.cc"],
    hdrs = glob(["include/*.hh", "include/*.h"]),
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":quick_share_cc_proto",
        "//common:common",
        "@com_google_ukey2//:ukey2"
    ]
)