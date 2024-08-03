load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_foreign_cc",
    strip_prefix = "rules_foreign_cc-0.6.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.6.0.tar.gz",
)
load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

_ALL_CONTENT = """\
filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
"""

http_archive(
    name = "rules_pkg",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/0.9.1/rules_pkg-0.9.1.tar.gz",
    ],
    sha256 = "8f9ee2dc10c1ae514ee599a8b42ed99fa262b757058f65ad3c384289ff70c4b8",
)
load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
rules_pkg_dependencies()


http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-27.1",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v27.1.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()

http_archive(
    name = "boringssl",
    sha256 = "5d299325d1db8b2f2db3d927c7bc1f9fcbd05a3f9b5c8239fa527c09bf97f995",
    strip_prefix = "boringssl-0acfcff4be10514aacb98eb8ab27bb60136d131b",
    urls = ["https://github.com/google/boringssl/archive/0acfcff4be10514aacb98eb8ab27bb60136d131b.tar.gz"],
)

http_archive(
    name = "com_google_ukey2",
    strip_prefix = "ukey2-master",
    urls = ["https://github.com/google/ukey2/archive/master.zip"],
)

http_archive(
    name = "argparse",
    sha256 = "674e724c2702f0bfef1619161815257a407e1babce30d908327729fba6ce4124",
    strip_prefix = "argparse-3.0",
    url = "https://github.com/p-ranav/argparse/archive/refs/tags/v3.0.zip",
    # For some reason bazel fails to find argparse's BUILD file in its root folder no matter what
    build_file_content = """
cc_library(
    name = "argparse",
    hdrs = ["include/argparse/argparse.hpp"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)"""

)

http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-20240116.2",
    urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20240116.2.tar.gz"],
)

http_archive(
    name = "nlohmann_json",
    strip_prefix = "json-3.11.3",
    urls = ["https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz"]
)