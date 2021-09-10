# Changelog

# dev

* New feature: Generate ELF (import) symbol-related hashes, including VirusTotal compatible `telfhash` ([#286](https://github.com/avast/retdec/issues/286), [#936](https://github.com/avast/retdec/pull/936)).
* New Feature: `retdec-fileinfo` can be configured via JSON file. See `--fileinfo-config` option for more details.
* New Feature: RetDec is now also a library ([#779](https://github.com/avast/retdec/pull/779). Related changes are the removal of `retdec-decompiler.py` (it is now a binary, e.g. `retdec-decompiler.exe` on Windows), `retdec-bin2llvmir`, `retdec-llvmir2hll`, and some other supportive functionality.
* Enhancement: Improve PE's .NET parsing - make it more aligned with parsing in YARA ([#997](https://github.com/avast/retdec/pull/997), [regression tests #106](https://github.com/avast/retdec-regression-tests/pull/106)).
* Enhancement: Add `signatureVerified` flag to PE's digital signature entries ([#994](https://github.com/avast/retdec/pull/994), [regression tests #102](https://github.com/avast/retdec-regression-tests/pull/102)).
* Enhancement: Add YARA signature for InnoSetup 6.1.0 ([#989](https://github.com/avast/retdec/pull/989)).
* Enhancement: Provide one-line-style values for digital signature's subjects and issuers ([#956](https://github.com/avast/retdec/issues/956), [#976](https://github.com/avast/retdec/pull/976), [regression tests #92](https://github.com/avast/retdec-regression-tests/pull/92)).
* Enhancement: Compute hashes of decrypted PE rich headers ([#621](https://github.com/avast/retdec/issues/621), [#945](https://github.com/avast/retdec/pull/945)).
* Enhancement: Unified logging on stdout/stderr. Added option `--silent`. Printed text is colored only when output is a terminal ([#791](https://github.com/avast/retdec/issues/791).
* Enhancement: Support all the CMake build types (i.e. `Debug`, `Release`, `RelWithDebInfo` and `MinSizeRel`) on all systems ([#774](https://github.com/avast/retdec/issues/774)).
* Enhancement: YARA updated to version 4.0.1 ([#758](https://github.com/avast/retdec/issues/758)), fixed Mach-O parsing issue ([#283](https://github.com/avast/retdec/issues/283)).
* Enhancement: Improved detection of many packers/installers/compilers in `retdec-fileinfo`, including Armadillo ([#733](https://github.com/avast/retdec/pull/733)), VMProtect ([#734](https://github.com/avast/retdec/pull/734), [#778](https://github.com/avast/retdec/pull/778)), Petite ([#735](https://github.com/avast/retdec/pull/735)), Enigma ([#741](https://github.com/avast/retdec/pull/741)), ASPack ([#743](https://github.com/avast/retdec/pull/743)), Eziriz ([#746](https://github.com/avast/retdec/pull/746)), PyInstaller ([#748](https://github.com/avast/retdec/pull/748)), Astrum InstallWizard ([#753](https://github.com/avast/retdec/pull/753)), AutoHotKey ([#756](https://github.com/avast/retdec/pull/756)), AutoIt ([#757](https://github.com/avast/retdec/pull/757)), BAT to PE-EXE script compilers ([#761](https://github.com/avast/retdec/pull/761)), Bero ([#764](https://github.com/avast/retdec/pull/764)), CExe ([#781](https://github.com/avast/retdec/pull/781)), MoleBox ([#815](https://github.com/avast/retdec/pull/815)), Blizzard Protector ([#845](https://github.com/avast/retdec/pull/845)), CreateInstall installer ([#852](https://github.com/avast/retdec/pull/852)), FlyStudio installer ([#853](https://github.com/avast/retdec/pull/853)), Gentee installer ([#855](https://github.com/avast/retdec/pull/855)), Ghost installer and InnoSetup ([#857](https://github.com/avast/retdec/pull/857), [#899](https://github.com/avast/retdec/pull/899)), InstallCreator ([#804](https://github.com/avast/retdec/pull/858)), Quick Batch installer ([#864](https://github.com/avast/retdec/pull/864)), Wise installer ([#865](https://github.com/avast/retdec/pull/865)), Viseman installer ([#868](https://github.com/avast/retdec/pull/868)), Setup Factory ([#869](https://github.com/avast/retdec/pull/869)), Xenocode Application Launcher [#870](https://github.com/avast/retdec/pull/870), SmartInstall Maker ([#871](https://github.com/avast/retdec/pull/871)), and other improvements ([#804](https://github.com/avast/retdec/pull/804), [#831](https://github.com/avast/retdec/pull/831)).
* Enhancement: Enable .NET module in RetDec's YARA ([#747](https://github.com/avast/retdec/issues/747)).
* Enhancement: Require OpenSSL as a prerequisite. It is no longer built by RetDec ([#807](https://github.com/avast/retdec/pull/807)).
* Enhancement: Replace RetDec's `FilesystemPath` implementation with C++ Filesystem library ([#806](https://github.com/avast/retdec/pull/806)).
* Enhancement: Added support for Ninja CMake generator ([#8](https://github.com/avast/retdec/issues/8), [#830](https://github.com/avast/retdec/issues/8)).
* Enhancement: Removed copyrights from RetDec's outputs ([#843](https://github.com/avast/retdec/pull/843)).
* Enhancement: Add `--version` program option to all executable RetDec apps and add this info to `retdec-fileinfo`'s verbose output as well ([#926](https://github.com/avast/retdec/pull/926)).
* Enhancement: Added support for new ELF UPX unpacking stubs (versions 3.93 - 3.96) ([#929](https://github.com/avast/retdec/pull/929)).
* Enhancement: Improved YARA rules for detection of the SHA-512 algorithm ([#935](https://github.com/avast/retdec/pull/935)).
* Enhancement: Improved PE Authenticode parsing ([#902](https://github.com/avast/retdec/pull/902), [#380](https://github.com/avast/retdec/issues/380)).
* Fix: Stricter validation of PE signatures - they need to be outside of the image to be considered valid ([#972](https://github.com/avast/retdec/issues/972), [#986](https://github.com/avast/retdec/pull/986), [regression tests #108](https://github.com/avast/retdec-regression-tests/pull/108)).
* Fix: Do not provide entry point offset in case it doesn't exist ([#962](https://github.com/avast/retdec/issues/962), [#975](https://github.com/avast/retdec/pull/975), [regression tests #101](https://github.com/avast/retdec-regression-tests/pull/101)).
* Fix: Fix PE resource parsing issues ([#963](https://github.com/avast/retdec/issues/963), [#982](https://github.com/avast/retdec/pull/982), [regression tests #105](https://github.com/avast/retdec-regression-tests/pull/105)).
* Fix: Fix PE imports parsing issues ([#1003](https://github.com/avast/retdec/pull/1003), [regression tests #107](https://github.com/avast/retdec-regression-tests/pull/107)).
* Fix: Accept PDB info only if `IMAGE_DEBUG_TYPE_CODEVIEW` flag is set ([#1004](https://github.com/avast/retdec/pull/1004)).
* Fix: Prevent PE delayed import parser to load garbage data ([#981](https://github.com/avast/retdec/pull/981)).
* Fix: Don't detect .NET structures that do not belong to the binary itself, but to the embedded binary ([#967](https://github.com/avast/retdec/issues/967), [#970](https://github.com/avast/retdec/pull/970), [regression tests #90](https://github.com/avast/retdec-regression-tests/pull/90)).
* Fix: Fixed handling of escaped characters in PE section names ([#958](https://github.com/avast/retdec/issues/958), [#979](https://github.com/avast/retdec/pull/979), [regression tests #94](https://github.com/avast/retdec-regression-tests/pull/94)).
* Fix: Fixed .NET's TypeLib ID parsing - add _Parent relationship_ check ([#966](https://github.com/avast/retdec/issues/966), [#983](https://github.com/avast/retdec/pull/983), [regression tests #96](https://github.com/avast/retdec-regression-tests/pull/96)).
* Fix: Make error handling for PE resource directory in sync with YARA - i.e. behave as YARA does ([#988](https://github.com/avast/retdec/pull/988), [regression tests #98](https://github.com/avast/retdec-regression-tests/pull/98)).
* Fix: Fixed memory leak in `Fileformat` library ([#951](https://github.com/avast/retdec/issues/951), [#984](https://github.com/avast/retdec/pull/984)).
* Fix: Raise max length limit applied to PE symbol names ([#957](https://github.com/avast/retdec/issues/957), [#978](https://github.com/avast/retdec/pull/978), [regression tests #93](https://github.com/avast/retdec-regression-tests/pull/93)).
* Fix: Fixed parsing of junk data from PE resource table's `type` entry ([#959](https://github.com/avast/retdec/issues/959), [#974](https://github.com/avast/retdec/pull/974)).
* Fix: Fixed PE rich header analysis algorithm ([#973](https://github.com/avast/retdec/pull/973), [#960](https://github.com/avast/retdec/issues/960), [#965](https://github.com/avast/retdec/issues/965), [regression tests #91](https://github.com/avast/retdec-regression-tests/pull/91)).
* Fix: Arithmetic shift is no longer converted to signed division as these operations provide different output with negative numbers. ([#724](https://github.com/avast/retdec/issues/724)).
* Fix: Fixed infinite looping during the copy-propagation optimization in `llvmir2hll` ([#876](https://github.com/avast/retdec/pull/876)).
* Fix: Fixed analyzed calling convention on MIPS architecture. Register F0 is used for floating point function return ([#656](https://github.com/avast/retdec/issues/656)).
* Fix: Fixed filtration to better handle functions with no arguments and therefore to reduce noise in output ([#155](https://github.com/avast/retdec/issues/155)).
* Fix: Fixed build on some systems by adding missing includes of `<limits>` into `retdec-fileinfo` ([#745](https://github.com/avast/retdec/pull/745)).
* Fix: Fixed two type errors in `scripts/retdec-archive-decompiler.py` ([#759](https://github.com/avast/retdec/pull/759)).
* Fix: Fixed runtime and memory use of `retdec-fileinfo` on PE samples having corrupted relocations ([#872](https://github.com/avast/retdec/issues/872), [#873](https://github.com/avast/retdec/pull/873)).
* Fix: Fixed a corruption check for PE samples with invalid import thunks ([#897](https://github.com/avast/retdec/pull/897), [#917](https://github.com/avast/retdec/pull/917)).
* Fix: Fixed recognition of very corrupted PE samples ([#921](https://github.com/avast/retdec/issues/921)).
* Fix: Fixed parsing of corrupted resources in `retdec-fileinfo` ([#907](https://github.com/avast/retdec/pull/907), [#911](https://github.com/avast/retdec/issues/911)).
* Fix: MPRESS unpacker will now correctly copy resources, exports and other non-packed sections correctly.
* Fix: `retdec-fileinfo.py` is now usable even when decompiler is not installed.

# v4.0 (2020-04-07)

* New Feature: Added support for decompilation of 64-bit ARM binaries ([#268](https://github.com/avast/retdec/issues/268), [#533](https://github.com/avast/retdec/pull/533), [#550](https://github.com/avast/retdec/pull/550)).
* New Feature: Added presentation of section and overlay entropy in `retdec-fileinfo` ([#502](https://github.com/avast/retdec/issues/502), [#507](https://github.com/avast/retdec/pull/507)).
* New Feature: Added presentation of version info from PE file in `retdec-fileinfo` ([#408](https://github.com/avast/retdec/issues/408), [#519](https://github.com/avast/retdec/pull/519)).
* New Feature: Added presentation of thread-local storage directory from PE file in `retdec-fileinfo` ([#417](https://github.com/avast/retdec/issues/417), [#523](https://github.com/avast/retdec/pull/523)).
* New Feature: Added presentation of missing dependencies of PE files in `retdec-fileinfo` ([#585](https://github.com/avast/retdec/pull/585)).
* New Feature: Added presentation of anomalies of PE files in `retdec-fileinfo` ([#415](https://github.com/avast/retdec/issues/415), [#570](https://github.com/avast/retdec/pull/570)).
* New Feature: Added heuristic detection of StarForce, SecuROM, SafeDisc, MPRMMGVA, ActiveMark, Petite, and RLPack ([#600](https://github.com/avast/retdec/pull/600), [#607](https://github.com/avast/retdec/pull/607), [#615](https://github.com/avast/retdec/pull/615)).
* New Feature: Added control flow related information to RetDec config ([#646](https://github.com/avast/retdec/issues/646)).
* New Feature: Added option to generate the decompilation results as JSON ([JSON output file format](https://github.com/avast/retdec/wiki/Decompiler-outputs#json-output-file-format)). This output contains additional meta-information and can be conveniently consumed by 3rd-party tools.
* New Feature: Added a new library called `retdec` that lets you decompile the input into both LLVM IR module and structured (i.e. functions and basic blocks) Capstone disassembly. See the `retdectool` demo application.
* Enhancement: Improved handling of ELF object files and ELF thunks (implemented in PR [#577](https://github.com/avast/retdec/pull/577), solved issues [#184](https://github.com/avast/retdec/issues/184), [#480](https://github.com/avast/retdec/issues/480), and partially solved [#201](https://github.com/avast/retdec/issues/201)).
* Enhancement: Demangler rewritten ([#95](https://github.com/avast/retdec/issues/95)).
* Enhancement: Added macOS and Linux (Ubuntu, Debian, Fedora) release builds ([#526](https://github.com/avast/retdec/issues/526)).
* Enhancement: Added support for using a local repository clone for RetDec external dependencies ([#279](https://github.com/avast/retdec/issues/279)).
* Enhancement: Parallelized compilation of YARA rules during installation ([#540](https://github.com/avast/retdec/issues/540)).
* Enhancement: Updated LLVM to version 8.0.0 ([#110](https://github.com/avast/retdec/issues/110)).
* Enhancement: Updated YARA to version 3.9 ([#527](https://github.com/avast/retdec/pull/527)).
* Enhancement: Updated OpenSSL to version 1.1.1c ([#601](https://github.com/avast/retdec/pull/601)). This fixes build of OpenSSL on macOS Mojave ([#439](https://github.com/avast/retdec/issues/439)).
* Enhancement: Added support for relocations that pair multiple `R_MIPS_LO16` against a single `R_MIPS_HI16` ([#627](https://github.com/avast/retdec/issues/627), [#628](https://github.com/avast/retdec/pull/628)).
* Enhancement: Added handling of all x86 FPU instructions in assembly to LLVM IR translation ([#394](https://github.com/avast/retdec/issues/394), [#643](https://github.com/avast/retdec/pull/643)).
* Enhancement: All registers are localized - i.e. transformed from global variables to local variables ([#652](https://github.com/avast/retdec/issues/652)). This significantly (20% on average) speeds up the decompilation process and greatly reduces noise in output.
* Enhancement: Added CMake options to build and install only specific targets ([#510](https://github.com/avast/retdec/issues/510)).
* Enhancement: Switched from C++14 to C++17 ([#650](https://github.com/avast/retdec/issues/650)).
* Enhancement: Replaced uses of `mpark::variant` from `deps/variant` with standard C++17 `std::variant`. Removed the `variant` dependency.
* Enhancement: Updated Yaramod to version v3.0.0 ([#680](https://github.com/avast/retdec/pull/680)). RetDec no longer requires Flex and Bison. This fixes [#103](https://github.com/avast/retdec/issues/103).
* Enhancement: Take out most of the types from `config` library and place them to a separate `common` library that could be used across an entire RetDec source base ([#686](https://github.com/avast/retdec/issues/686)).
* Enhancement: `retdec-fileinfo` is now able to produce human-readable representation of a product name and VS version from Rich header ([#691](https://github.com/avast/retdec/pull/691)).
* Enhancement: Added a new corruption check into `retdec-fileinfo` that detects cut or zeroed digital signature ([#719](https://github.com/avast/retdec/pull/719)).
* Enhancement: Reduced RetDec's external dependencies:
   * The sources of the following 3rd-party projects were moved from their own repositories directly to the main RetDec repository (to `/deps/`): ELFIO, RapidJSON, TinyXML2.
   * The sources of the following Avast projects were moved from their own repositories directly to the main RetDec repository (to `/src/`): Yaracpp, PeLib.
   * The following 3rd-party dependencies use upstream project repositories, not modified Avast forks as before: Capstone, Yara.
   * The following dependencies are no longer needed: JsonCpp, Libdwarf, Libelf.
* Enhancement: Implemented proper RetDec installation ([#648](https://github.com/avast/retdec/issues/648)). It is now possible to easily use RetDec components in other CMake projects.
* Enhancement: Some optimizations in critical RetDec components ([#731](https://github.com/avast/retdec/pull/731)). It is however still often very slow on big inputs.
* Fix: Increased the limit for the number of entries in import directory when deciding whether a PE file is corrupted or not ([avast/pelib#13](https://github.com/avast/pelib/pull/13)).
* Fix: Fixed build on BSD systems ([#598](https://github.com/avast/retdec/pull/598)).
* Fix: Resources which are located in the different section than resource tree are now properly parsed ([#596](https://github.com/avast/retdec/pull/596)).
* Fix: Version information which contained strings shorter than reported are now properly parsed ([#596](https://github.com/avast/retdec/pull/596)).
* Fix: Fixed crashes of `retdec-fileinfo` when analyzing ELF samples containing invalid ranges ([#521](https://github.com/avast/retdec/issues/521)).
* Fix: Fixed crashes of `retdec-unpacker` when trying to unpack corrupted ELF samples having incorrect size of additional data ([#582](https://github.com/avast/retdec/issues/582)).
* Fix: Fixed several Mach-O parsing crashes ([#581](https://github.com/avast/retdec/issues/581), [#561](https://github.com/avast/retdec/issues/561), [#568](https://github.com/avast/retdec/issues/568)).
* Fix: Fixed import table hashes computation - hashes are no longer produced from empty strings ([#460](https://github.com/avast/retdec/issues/460)).
* Fix: Fixed build on Microsoft Windows via MSYS2 ([#606](https://github.com/avast/retdec/pulls/606)).
* Fix: Fixed build on macOS Mojave by updating OpenSSL and using `xcrun` ([#439](https://github.com/avast/retdec/issues/439)).
* Fix: Fixed computation of the _"RVA of the import name is invalid"_ loader error ([avast/pelib#11](https://github.com/avast/pelib/pull/11)).
* Fix: Fixed computation of the _"Import directory is cut"_ loader error ([avast/pelib#17](https://github.com/avast/pelib/pull/17)).
* Fix: Export ordinals are now correctly calculated as relative to the base ([#612](https://github.com/avast/retdec/issues/612), [avast/pelib#10](https://github.com/avast/pelib/pull/10)).
* Fix: Fixed crash in the decoding phase ([#637](https://github.com/avast/retdec/issues/637), [#641](https://github.com/avast/retdec/pull/641)).
* Fix: Fixed global variable naming issue ([#636](https://github.com/avast/retdec/issues/636), [#645](https://github.com/avast/retdec/pull/645)).
* Fix: Fixed binary to LLVM IR translation of some MIPS instructions ([#633](https://github.com/avast/retdec/issues/633)), and made the translation process less error prone altogether ([#672](https://github.com/avast/retdec/pull/672)).
* Fix: Fixed incorrect translation of PHI nodes in `llvmir2hll` ([#658](https://github.com/avast/retdec/issues/658)).
* Fix: Fixed the build of LLVM when having OCaml installed in your system ([#701](https://github.com/avast/retdec/issues/701)).

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
