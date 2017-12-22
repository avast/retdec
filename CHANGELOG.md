# Changelog

# dev

* Enhancement: Decrease the default timeout when downloading the support package during installation ([#6](https://github.com/avast-tl/retdec/pull/6)).
* Enhancement: Any shell can be used to install the decompiler, not just Bash.
* Enhancement: Added unofficial support for macOS build ([#7](https://github.com/avast-tl/retdec/issues/7))
* Fix: Build of `googletest` with VS 2017 ([#55](https://github.com/avast-tl/retdec/issues/55))
* Fix: Build of `retdec-config` when two different compilers are employed ([#52](https://github.com/avast-tl/retdec/issues/52)).
* Fix: Build of the `llvm` submodule with VS 2017 when DIA SDK is installed ([#61](https://github.com/avast-tl/retdec/issues/61)).
* Fix: Ordering of compiler detections ([#39](https://github.com/avast-tl/retdec/issues/39)).
* Fix: Remove duplicate `lib` prefix when installing [libdwarf](https://github.com/avast-tl/libdwarf) libraries ([#31](https://github.com/avast-tl/retdec/issues/31)).
* Fix: When installing the decompiler, do not remove the entire `share` directory ([#12](https://github.com/avast-tl/retdec/issues/12)).
* Fix: Improve OS type detection when installing the decompiler.
* Fix: Remove useless OS type detection when running decompilations ([#10](https://github.com/avast-tl/retdec/issues/10)).

# v3.0 (2017-12-13)

Initial public release.
