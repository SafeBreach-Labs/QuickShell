proto_library(
    name = "quick_share_proto",
    srcs = [
        "proto/offline_wire_formats.proto",
        "proto/wire_format.proto"
    ],
    visibility = [
        "//visibility:private",  # Only private by automation, not intent. Owner may accept CLs adding visibility. See go/scheuklappen#explicit-private.
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

cc_library(
    name = "quick_share",
    srcs = ["quick_share_medium.cc", "quick_share_connection.cc"],
    hdrs = glob(["include/*.hh", "include/*.h"]),
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":quick_share_cc_proto",
        "//logger:logger",
        "@com_google_ukey2//:ukey2"
    ]
)