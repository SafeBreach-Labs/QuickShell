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
    name = "rules_python",  # 2023-01-10T22:00:51Z
    sha256 = "5de54486a60ad8948dabe49605bb1c08053e04001a431ab3e96745b4d97a4419",
    strip_prefix = "rules_python-70cce26432187a60b4e950118791385e6fb3c26f",
    urls = ["https://github.com/bazelbuild/rules_python/archive/70cce26432187a60b4e950118791385e6fb3c26f.zip"],
)

http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.17.0",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.17.0.tar.gz"],
)

http_archive(
    name = "com_google_protobuf_cc",
    strip_prefix = "protobuf-3.17.0",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.17.0.tar.gz"],
)

http_archive(
    name = "boringssl",
    sha256 = "5d299325d1db8b2f2db3d927c7bc1f9fcbd05a3f9b5c8239fa527c09bf97f995",  # Last updated 2022-10-19
    strip_prefix = "boringssl-0acfcff4be10514aacb98eb8ab27bb60136d131b",
    urls = ["https://github.com/google/boringssl/archive/0acfcff4be10514aacb98eb8ab27bb60136d131b.tar.gz"],
)

http_archive(
    name = "com_google_ukey2",
    strip_prefix = "ukey2-master",
    urls = ["https://github.com/google/ukey2/archive/master.zip"],
)
