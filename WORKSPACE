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

# Load rules_python
http_archive(
    name = "rules_python",
    strip_prefix = "rules_python-0.15.0",
    urls = [
        "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.15.0.tar.gz",
    ],
)


load("@rules_python//python:repositories.bzl", "py_repositories", "python_register_toolchains")

py_repositories()

python_register_toolchains(
    name = "python_3_9",
    python_version = "3.9.13",
)

load("@rules_python//python:pip.bzl", "pip_parse")

pip_parse(
    # (Optional) You can set an environment in the pip process to control its
    # behavior. Note that pip is run in "isolated" mode so no PIP_<VAR>_<NAME>
    # style env vars are read, but env vars that control requests and urllib3
    # can be passed
    # environment = {"HTTPS_PROXY": "http://my.proxy.fun/"},
    name = "pypi",

    python_interpreter_target = "@python_3_9_host//:python",

    requirements_lock = "//quick_shell_rce_tool:requirements.lock",
)

load("@pypi//:requirements.bzl", "install_deps")

# Initialize repositories for all packages in requirements_lock.txt.
install_deps()

