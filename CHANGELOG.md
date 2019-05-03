# Changelog

# dev

* New Feature: Added presentation of section and overlay entropy in `retdec-fileinfo` ([#502](https://github.com/avast/retdec/issues/502), [#507](https://github.com/avast/retdec/pull/507)).
* New Feature: Added presentation of version info from PE file in `retdec-fileinfo` ([#408](https://github.com/avast/retdec/issues/408), [#519](https://github.com/avast/retdec/pull/519)).
* New Feature: Added presentation of thread-local storage directory from PE file in `retdec-fileinfo` ([#417](https://github.com/avast/retdec/issues/417), [#523](https://github.com/avast/retdec/pull/523)).
* Enhancement: Added macOS and Linux (Ubuntu, Debian, Fedora) release builds ([#526](https://github.com/avast/retdec/issues/526)).
* Enhancement: Added support for using a local repository clone for RetDec external dependencies ([#279](https://github.com/avast/retdec/issues/279)).
* Enhancement: Parallelized compilation of YARA rules during installation ([#540](https://github.com/avast/retdec/issues/540)).
* Enhancement: Updated LLVM to version 8.0.0 ([#110](https://github.com/avast/retdec/issues/110)).
* Enhancement: Updated YARA to version 3.9 ([#527](https://github.com/avast/retdec/pull/527)).

# v3.3 (2019-03-18)

* New Feature: Added basic support of 64-bit x86 architecture ([#9](https://github.com/avast/retdec/issues/9), [#513](https://github.com/avast/retdec/pull/513)).
* New Feature: Added presentation of imported types and TypeRef hashes for .NET binaries ([#363](https://github.com/avast/retdec/issues/363), [#364](https://github.com/avast/retdec/issues/364), [#428](https://github.com/avast/retdec/issues/428)).
* New Feature: Added presentation of metadata from binaries written in Visual Basic and detection of P-code ([#138](https://github.com/avast/retdec/issues/138), [#440](https://github.com/avast/retdec/pull/440)).
* New Feature: Added computation and presentation of icon hashes for exact and also similarity matching in PE files ([#339](https://github.com/avast/retdec/issues/339)).
* Enhancement: Distribute YARA rules in a text form in the RetDec support package ([retdec-support #3](https://github.com/avast/retdec-support/issues/3)).
* Enhancement: Updated YARA to version 3.8.1 ([#218](https://github.com/avast/retdec/issues/218)).
* Enhancement: Made `--generate-log` option of `retdec-decompiler.py` work on macOS ([#383](https://github.com/avast/retdec/issues/383), [#450](https://github.com/avast/retdec/pull/450)).
* Enhancement: Replaced recursion with iterative implementation in x87 FPU analysis in `retdec-bin2llvmir` ([#450](https://github.com/avast/retdec/pull/450)).
* Enhancement: The `new` LLVM IR to BIR converter is now the default (and only) back-end's converter. In most cases, this improves code structure and significantly speeds up decompilations ([#211](https://github.com/avast/retdec/issues/211), [#508](https://github.com/avast/retdec/issues/508), [#509](https://github.com/avast/retdec/pull/509)).
* Enhancement: The `fileformat` library, and all its object file modules, accept both `std::istream` and `(data, size)` pair, in addition to the original input file path.
* Enhancement: Reduced the needed stack space in `retdec-llvmir2hll` ([#492](https://github.com/avast/retdec/pull/492), [#495](https://github.com/avast/retdec/pull/495)).
* Enhancement: Added support for build and run on FreeBSD and potentially on other BSD OSes ([#476](https://github.com/avast/retdec/pull/476)).
* Enhancement: It is possible to use local PeLib directory instead of remote revision via CMake variable `PELIB_LOCAL_DIR`. This is convenient when modifying both PeLib and RetDec at the same time.
* Enhancement: Improved detection of needed libraries and imported/external functions in ELF binaries ([#457](https://github.com/avast/retdec/issues/457)).
* Enhancement: Added semantics for more MIPS instructions.
* Enhancement: Capstone2LlvmIr library refactoring ([#115](https://github.com/avast/retdec/issues/115)).
* Enhancement: Removed the build and runtime dependency on ncurses/libtinfo ([#409](https://github.com/avast/retdec/pull/409)).
* Enhancement: Add a check into our scripts that they are run from an installation directory and not from the `scripts` directory ([#418](https://github.com/avast/retdec/issues/418)).
* Enhancement: Improved corruption checks in `retdec-fileinfo` to recognize cut PE files which are still loadable ([#463](https://github.com/avast/retdec/issues/463)).
* Enhancement: Redesign output files naming scheme ([#132](https://github.com/avast/retdec/issues/132)).
* Fix: Fixed false COFF file format detections ([#421](https://github.com/avast/retdec/issues/421), [#431](https://github.com/avast/retdec/issues/431)).
* Fix: Fixed LLVM IR syntax error: `Global variable initializer type does not match global variable type` ([#436](https://github.com/avast/retdec/issues/436)).
* Fix: Fixed translation of x86 `sbb` instruction ([#401](https://github.com/avast/retdec/issues/401)).
* Fix: Fixed `fileinfo` crash during `Asn1Sequence` initialization when parsing PE certificates ([#256](https://github.com/avast/retdec/issues/256)).
* Fix: Fixed `fileinfo` crash during reconstruction of .NET types ([#458](https://github.com/avast/retdec/issues/458), [#511](https://github.com/avast/retdec/pull/511)).
* Fix: Fixed generation of MIPS branch instructions ([#88](https://github.com/avast/retdec/issues/88)).
* Fix: Fixed generation of empty if blocks in C output ([#83](https://github.com/avast/retdec/issues/83)).
* Fix: Fixed decompilation of simple x86 system calls ([#24](https://github.com/avast/retdec/issues/24)).
* Fix: Fixed potential infinite looping in llvmir2hll's copy propagation pass ([#479](https://github.com/avast/retdec/issues/479)).
* Fix: Fixed `FilesystemPath::isFile()` ([#490](https://github.com/avast/retdec/issues/490), [#491](https://github.com/avast/retdec/pull/491)).
* Fix: Fixed `retdec-signature-from-library-creator.py` when there is a lot of input files by adding an option to `retdec-bin2pat` to have the objects list passed through a text file instead of via program arguments ([#472](https://github.com/avast/retdec/issues/472), [#484](https://github.com/avast/retdec/pull/484)).
* Fix: Stricter rules for PE section names ([#451](https://github.com/avast/retdec/issues/451)).
* Fix: Fixed incorrect return code of `bin2pat` that caused `signature-from-library-creator.py` to silently fail on error ([#473](https://github.com/avast/retdec/issues/473), [#474](https://github.com/avast/retdec/pull/474)).
* Fix: Fixed installation when Python is in a path containing spaces ([#441](https://github.com/avast/retdec/issues/441)).
* Fix: Fixed handling of pointers with segment overrides, including loads/stores from/to zero (null) pointers ([#41](https://github.com/avast/retdec/issues/41), [#169](https://github.com/avast/retdec/issues/169), [#347](https://github.com/avast/retdec/issues/347), [#376](https://github.com/avast/retdec/issues/376), [#391](https://github.com/avast/retdec/pull/391)).
* Fix: Fixed translation of x86 FPU instructions to LLVM IR ([#293](https://github.com/avast/retdec/issues/293)).

# v3.2 (2018-08-16)

* New Feature: Converted shell scripts to Python scripts so that Windows users no longer have to install MSYS2 in order to run RetDec ([#338](https://github.com/avast/retdec/pull/338), [#147](https://github.com/avast/retdec/issues/147)).
* New Feature: Added generation of export-table hashes into `retdec-fileinfo` ([#121](https://github.com/avast/retdec/issues/121), [#321](https://github.com/avast/retdec/pull/321)).
* New Feature: Automatically generate and publicly host an up-to-date Doxygen documentation ([#20](https://github.com/avast/retdec/issues/20)).
* Enhancement: Suppress superfluous ranlib warnings about static libraries having no symbols on macOS ([#271](https://github.com/avast/retdec/issues/271), [#349](https://github.com/avast/retdec/pull/349)).
* Fix: Fixed assertions in statically linked code recognition ([#333](https://github.com/avast/retdec/issues/333)).
* Fix: Fixed aborts due to assertions during decoding of some MIPS binaries ([#335](https://github.com/avast/retdec/issues/335)).
* Fix: Fixed a memory leak when parsing Mach-O files ([#331](https://github.com/avast/retdec/pull/331)).

# v3.1 (2018-06-07)

* New Feature: `retdec-fileinfo` is now able to detect when a PE file is corrupted and cannot be loaded ([#281](https://github.com/avast/retdec/pull/281)).
* New Feature: Added a new tool: `retdec-getsig`. It can be used for creating signatures of packers, compilers, and other tools.
* New Feature: The number of bytes read from the input file's entry point by `retdec-fileinfo` is now configurable with the `--ep-bytes` option.
* Enhancement: Complete rewrite of binary to LLVM IR decoding phase ([#116](https://github.com/avast/retdec/issues/116)).
* Enhancement: Added reference checks to statically linked code detection ([#113](https://github.com/avast/retdec/issues/113)).
* Enhancement: Speeded up RetDec rebuild and installation by disabling forced reconfiguration of LLVM ([#294](https://github.com/avast/retdec/pull/294)).
* Enhancement: Added new OS/ABI and tool detections for ELF files ([#244](https://github.com/avast/retdec/issues/244)).
* Enhancement: Improved support for analysis of ELF [core files](http://www.gabriel.urdhr.fr/2015/05/29/core-file/) by `retdec-fileinfo` ([#142](https://github.com/avast/retdec/issues/142)).
* Enhancement: Added support for limiting overall memory when running decompilations and tools ([#270](https://github.com/avast/retdec/issues/270), [#290](https://github.com/avast/retdec/issues/290)). By default, decompilations are now run with limited memory (half of system RAM) to prevent "black screens" (mostly on Windows). Use `--no-memory-limit` to override.
* Enhancement: On macOS, you no longer need to have GNU coreutils in `PATH` to build and install RetDec. GNU coreutils are still needed to run RetDec, though.
* Enhancement: Import-table hashes generated by `retdec-fileinfo` are now compatible with import-table hashes from YARA/pefile ([#246](https://github.com/avast/retdec/issues/246)).
* Enhancement: Tool `retdec-macho-extractor` can now extract objects from non-archive Mach-O universal binaries ([#125](https://github.com/avast/retdec/issues/125)).
* Enhancement: References to ticket numbers from our internal issue tracking system were replaced by short descriptions in the `retdec-regression-tests` repository ([retdec-regression-tests #1](https://github.com/avast/retdec-regression-tests/issues/1)).
* Enhancement: Added a missing license for the `retdec-support` repository ([retdec-support #1](https://github.com/avast/retdec-support/issues/1)).
* Enhancement: Better detection of tools: new signatures and heuristics. YARA signatures are compiled now.
* Enhancement: Added Travis and AppVeyor continuous integration builds ([#2](https://github.com/avast/retdec/issues/2)).
* Enhancement: Build with `-std=c++14` instead of `-std=gnu++14` with GCC on Linux ([#76](https://github.com/avast/retdec/issues/76)).
* Enhancement: Speeded up build by skipping compilation of unnecessary dependencies (e.g. unused LLVM libraries, tools, and examples).
* Enhancement: OpenSSL is now automatically built only if it is not found in your system.
* Enhancement: Added support for a system-wide installation ([#94](https://github.com/avast/retdec/issues/94)).
* Enhancement: Prefixed all the installed binaries and scripts with `retdec-` ([#70](https://github.com/avast/retdec/issues/70)). Also, some tools were renamed to make their names more uniform.
* Enhancement: Got rid of all git submodules ([#92](https://github.com/avast/retdec/issues/92), [#93](https://github.com/avast/retdec/issues/93)). Moved sources of all RetDec-related repositories to this main repository. Third-party dependencies are downloaded and built via CMake's external projects. This allows us to have e.g. only a single copy of LLVM ([#14](https://github.com/avast/retdec/issues/14)) and not require a recursive clone ([#48](https://github.com/avast/retdec/issues/48), [#68](https://github.com/avast/retdec/issues/68), [#72](https://github.com/avast/retdec/issues/72)).
* Enhancement: Set a proper `rpath` during installation on Linux and macOS ([#77](https://github.com/avast/retdec/issues/77), [#100](https://github.com/avast/retdec/issues/100)). This allows us to move the installation directory after the installation into another location.
* Enhancement: Added community support for building and running RetDec inside Docker ([#60](https://github.com/avast/retdec/pull/60)).
* Enhancement: Decrease the default timeout when downloading the support package during installation ([#6](https://github.com/avast/retdec/pull/6)).
* Enhancement: Any shell can be used to install the decompiler, not just Bash.
* Enhancement: Added unofficial support for macOS build ([#7](https://github.com/avast/retdec/issues/7)).
* Enhancement: Allow 32b versions of `bin2llvmir` and `llvmir2hll` on Windows access more memory ([#7](https://github.com/avast/retdec/issues/73)).
* Enhancement: Added a method in `loader::Image` to obtain segment content as a raw data pointer.
* Enhancement: `retdec-fileinfo` now prints raw bytes of Rich Header in the JSON format ([#288](https://github.com/avast/retdec/issues/288)).
* Enhancement: Delayed imports in PE files are now distinguished from non-delayed imports in the output from `retdec-fileinfo` by a boolean flag ([#287](https://github.com/avast/retdec/issues/288)).
* Fix: Add a missing `.c` extension to files generated by `retdec-archive-decompiler.sh` ([#261](https://github.com/avast/retdec/issues/261).
* Fix: Fixed build of yaracpp on 32b Unix-like operating systems ([#299](https://github.com/avast/retdec/issues/299)).
* Fix: Fixed parsing of PE files having corrupted import tables ([#101](https://github.com/avast/retdec/issues/101)).
* Fix: Fixed parsing of delayed imports by ordinals in PE files ([#282](https://github.com/avast/retdec/issues/282)).
* Fix: Fixed ordering of detected tools (e.g. compilers and packers) on systems whose `std::sort()` is not stable ([#262](https://github.com/avast/retdec/issues/262)).
* Fix: When running RetDec on macOS, `gtimeout` is now used instead of `timeout` ([#260](https://github.com/avast/retdec/issues/260)). This fixes the following runtime error when running `retdec-archive-decompiler.sh`: `The `timeout` command is required but it is not available`.
* Fix: When running RetDec on macOS, `greadlink` is now used instead of `readlink`. This fixes runtime errors of the form `readlink: illegal option -- e`.
* Fix: `retdec-decompiler.sh` on macOS no longer requires the GNU version of `sed` ([#257](https://github.com/avast/retdec/issues/257)).
* Fix: `#!/usr/bin/env bash` is now used instead of `#!/bin/bash` to run our scripts ([#258](https://github.com/avast/retdec/issues/258)).
* Fix: Fixed `retdec-fileinfo` crashes when verifying digital signature of PE files ([#87](https://github.com/avast/retdec/issues/87)).
* Fix: Fixed infinite loop in COFF word length detection for rare cases ([#242](https://github.com/avast/retdec/issues/242)).
* Fix: Fixed several ELF bugs causing crashes ([#239](https://github.com/avast/retdec/issues/239), [#240](https://github.com/avast/retdec/issues/240), [#241](https://github.com/avast/retdec/issues/241), [#248](https://github.com/avast/retdec/issues/248)).
* Fix: Fixed unit-tests discovery in `retdec-tests-runner.sh` on macOS ([#238](https://github.com/avast/retdec/issues/238)).
* Fix: Non-printable characters in ELF .dynamic section output are now replaced with hexadecimal codes ([#82](https://github.com/avast/retdec/issues/82)).
* Fix: Fix for several segmentation faults in ELF parsing module ([#89](https://github.com/avast/retdec/issues/89)).
* Fix: Added a workaround for a GCC 5 compilation bug ([#231](https://github.com/avast/retdec/issues/231)).
* Fix: Fix LLVM (and therefore RetDec) build on systems with architecture other than x86 ([llvm #3](https://github.com/avast/llvm/issues/3)).
* Fix: Valid Mach-O x64 relocations are no longer ignored.
* Fix: Only a single copy of LLVM (and all other components) is kept ([#14](https://github.com/avast/retdec/issues/14)).
* Fix: RetDec works even if it is installed to a directory which have whitespaces in its path.
* Fix: Reduced the length of build paths to external projects ([#61](https://github.com/avast/retdec/issues/61)).
* Fix: Build of `googletest` with VS 2017 ([#55](https://github.com/avast/retdec/issues/55)).
* Fix: Build of `retdec-config` when two different compilers are employed ([#52](https://github.com/avast/retdec/issues/52)).
* Fix: Build of the `llvm` submodule with VS 2017 when DIA SDK is installed ([#61](https://github.com/avast/retdec/issues/61)).
* Fix: Ordering of compiler detections ([#39](https://github.com/avast/retdec/issues/39)).
* Fix: Remove duplicate `lib` prefix when installing [libdwarf](https://github.com/avast/libdwarf) libraries ([#31](https://github.com/avast/retdec/issues/31)).
* Fix: When installing the decompiler, do not remove the entire `share` directory ([#12](https://github.com/avast/retdec/issues/12)).
* Fix: Improve OS type detection when installing the decompiler.
* Fix: Remove useless OS type detection when running decompilations ([#10](https://github.com/avast/retdec/issues/10)).
* Fix: Filesystem path in utils now returns correct information when it is appended with another path.
* Fix: Plain output of `fileinfo` now escapes non-printable characters in subject/issuer name/organization of PE certificates ([#253](https://github.com/avast/retdec/issues/253)).
* Fix: Invalid dates are no longer shown in the output of `fileinfo` ([#251](https://github.com/avast/retdec/issues/251)).
* Fix: Fixed crash of `fileinfo` when accessing slightly corrupted security directory ([#255](https://github.com/avast/retdec/issues/255), [#250](https://github.com/avast/retdec/issues/250)).
* Fix: Delayed imports are now ignored when calculating import-table hashes for PE files ([#287](https://github.com/avast/retdec/issues/287)).
* Fix: Import-table hashes for Mach-O binaries are now always generated even if commands for library loading are not ordered ([#285](https://github.com/avast/retdec/issues/287)).
* Fix: OpenSSL can now be built on ARM architectures (Linux and Windows) and other non-recognized architectures (Linux only) ([#299](https://github.com/avast/retdec/issues/299)).
* Fix: Decompilation in raw mode (`--mode raw`) no longer removes the original input file when cleanup option is used (`--cleanup`) ([#309](https://github.com/avast/retdec/issues/309)).
* Fix: Retdec can now be cross-compiled ([yaracpp #2](https://github.com/avast/yaracpp/pull/2)).

# v3.0 (2017-12-13)

Initial public release.
