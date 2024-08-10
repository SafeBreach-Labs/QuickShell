cc_library(
    name = "logger",
    srcs = ["logger.cc"],
    hdrs = glob(["include/*.hh"]),
    visibility = [
        "//visibility:public"
    ]
)

cc_library(
    name = "exceptions",
    hdrs = glob(["include/*.hh"]),
    visibility = [
        "//visibility:public"
    ]
)

cc_library(
    name = "common",
    deps = [
        ":logger",
        ":exceptions"
    ],
    visibility = [
        "//visibility:public"
    ]
)