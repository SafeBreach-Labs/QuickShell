cc_binary(
    name = "quick_share_fuzzing_patches",
    srcs = ["quick_share_fuzzing_patches.cc"],
    linkstatic = True,
    linkshared = 1,
    copts = ["/DCOMPILING_DLL"],
)

proto_library(
    name = "fuzzer_proto",
    srcs = [
        "proto/offline_wire_formats_for_mutator.proto"
    ],
    visibility = [
        "//visibility:private",
    ],
)

cc_proto_library(
    name = "fuzzer_cc_proto",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":fuzzer_proto",
    ],
)

cc_binary(
    name = "fuzzing_harness",
    srcs = [
        "harness_main.cc",
        "harness_mutations.cc",
        "harness_offline_frames_validator.cc",
        "test_case.cc",
        "include/test_case.hh",
        "include/harness_offline_frames_validator.hh",
    ],
    deps = [
        "//tools:tool_helpers_library",
        "//quick_share:quick_share",
        ":fuzzer_cc_proto",
        "@libprotobuf-mutator",
    ],
    linkstatic = True,
    linkshared = 1,
    copts = ["/DCOMPILING_DLL"],
)