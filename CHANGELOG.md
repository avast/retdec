# Changelog

# dev

* Enhancement: References to ticket numbers from our internal issue tracking systems were replaced by short descriptions in `retdec-regression-tests` repository ([commit](https://github.com/avast-tl/retdec-regression-tests/commit/bcbab21ad57d084136ce5ffc8a1d6325c2cf792b)).
* Enhancement: Added a missing license for the `retdec-support` repository ([retdec-support #1](https://github.com/avast-tl/retdec-support/issues/1)).
* Enhancement: Better detection of tools: new signatures and heuristics. YARA signatures are compiled now.
* Enhancement: Added Travis and Appveyor continuous integration builds ([#2](https://github.com/avast-tl/retdec/issues/2)).
* Enhancement: Build with `-std=c++14` instead of `-std=gnu++14` with GCC on Linux ([#76](https://github.com/avast-tl/retdec/issues/76)).
* Enhancement: Speeded up build by skipping compilation of unnecessary dependencies (e.g. unused LLVM libraries, tools, and examples).
* Enhancement: OpenSSL is now automatically built only if it is not found in your system.
* Enhancement: Added support for a system-wide installation ([#94](https://github.com/avast-tl/retdec/issues/94)).
* Enhancement: Prefixed all the installed binaries and scripts with `retdec-` ([#70](https://github.com/avast-tl/retdec/issues/70)). Also, some tools were renamed to make their names more uniform.
* Enhancement: Got rid of all git submodules ([#92](https://github.com/avast-tl/retdec/issues/92), [#93](https://github.com/avast-tl/retdec/issues/93)). Moved sources of all RetDec-related repositories to this main repository. Third-party dependencies are downloaded and built via CMake's external projects. This allows us to have e.g. only a single copy of LLVM ([#14](https://github.com/avast-tl/retdec/issues/14)) and not require a recursive clone ([#48](https://github.com/avast-tl/retdec/issues/48), [#68](https://github.com/avast-tl/retdec/issues/68), [#72](https://github.com/avast-tl/retdec/issues/72)).
* Enhancement: Set a proper `rpath` during installation on Linux and macOS ([#77](https://github.com/avast-tl/retdec/issues/77), [#100](https://github.com/avast-tl/retdec/issues/100)). This allows us to move the installation directory after the installation into another location.
* Enhancement: Added community support for building and running RetDec inside Docker ([#60](https://github.com/avast-tl/retdec/pull/60)).
* Enhancement: Decrease the default timeout when downloading the support package during installation ([#6](https://github.com/avast-tl/retdec/pull/6)).
* Enhancement: Any shell can be used to install the decompiler, not just Bash.
* Enhancement: Added unofficial support for macOS build ([#7](https://github.com/avast-tl/retdec/issues/7)).
* Enhancement: Allow 32b versions of `bin2llvmir` and `llvmir2hll` on Windows access more memory ([#7](https://github.com/avast-tl/retdec/issues/73)).
* Fix: Only a single copy of LLVM (and all other components) is kept ([#14](https://github.com/avast-tl/retdec/issues/14)).
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
* Fix: Filesystem path in utils now returns correct information when it is appended with another path.

# v3.0 (2017-12-13)

Initial public release.
