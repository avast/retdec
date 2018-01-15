# Changelog

# dev

* Enhancement: Prefix all the installed binaries and scripts with `retdec-`. Rename some tools to make names more uniform.
* Enhancement: Get rid of all git submodules. Move sources of all RetDec related repositories to this main repository. Get 3rd party dependencies using CMake external projects.
* Enhancement: Added community support for building and running RetDec inside Docker ([#60](https://github.com/avast-tl/retdec/pull/60)).
* Enhancement: Decrease the default timeout when downloading the support package during installation ([#6](https://github.com/avast-tl/retdec/pull/6)).
* Enhancement: Any shell can be used to install the decompiler, not just Bash.
* Enhancement: Added unofficial support for macOS build ([#7](https://github.com/avast-tl/retdec/issues/7)).
* Enhancement: Allow 32b versions of `bin2llvmir` and `llvmir2hll` on Windows access more memory ([#7](https://github.com/avast-tl/retdec/issues/73)).
* Fix: RetDec works even if it is installed to a directory which have whitespaces in its path.
* Fix: Reduced the length of build paths to external projects ([#61](https://github.com/avast-tl/retdec/issues/61)).
* Fix: Build of `googletest` with VS 2017 ([#55](https://github.com/avast-tl/retdec/issues/55)).
* Fix: Build of `retdec-config` when two different compilers are employed ([#52](https://github.com/avast-tl/retdec/issues/52)).
* Fix: Build of the `llvm` submodule with VS 2017 when DIA SDK is installed ([#61](https://github.com/avast-tl/retdec/issues/61)).
* Fix: Ordering of compiler detections ([#39](https://github.com/avast-tl/retdec/issues/39)).
* Fix: Remove duplicate `lib` prefix when installing [libdwarf](https://github.com/avast-tl/libdwarf) libraries ([#31](https://github.com/avast-tl/retdec/issues/31)).
* Fix: When installing the decompiler, do not remove the entire `share` directory ([#12](https://github.com/avast-tl/retdec/issues/12)).
* Fix: Improve OS type detection when installing the decompiler.
* Fix: Remove useless OS type detection when running decompilations ([#10](https://github.com/avast-tl/retdec/issues/10)).

# v3.0 (2017-12-13)

Initial public release.
