# RetDec

[![Travis CI build status](https://travis-ci.org/avast-tl/retdec.svg?branch=master)](https://travis-ci.org/avast-tl/retdec)
[![AppVeyor build status](https://ci.appveyor.com/api/projects/status/github/avast-tl/retdec?branch=master&svg=true)](https://ci.appveyor.com/project/avast-tl/retdec?branch=master)

[RetDec](https://retdec.com/) is a retargetable machine-code decompiler based on [LLVM](https://llvm.org/).

The decompiler is not limited to any particular target architecture, operating system, or executable file format:
* Supported file formats: ELF, PE, Mach-O, COFF, AR (archive), Intel HEX, and raw machine code.
* Supported architectures (32b only): Intel x86, ARM, MIPS, PIC32, and PowerPC.

Features:
* Static analysis of executable files with detailed information.
* Compiler and packer detection.
* Loading and instruction decoding.
* Signature-based removal of statically linked library code.
* Extraction and utilization of debugging information (DWARF, PDB).
* Reconstruction of instruction idioms.
* Detection and reconstruction of C++ class hierarchies (RTTI, vtables).
* Demangling of symbols from C++ binaries (GCC, MSVC, Borland).
* Reconstruction of functions, types, and high-level constructs.
* Integrated disassembler.
* Output in two high-level languages: C and a Python-like language.
* Generation of call graphs, control-flow graphs, and various statistics.

For more information, check out our
* [Wiki](https://github.com/avast-tl/retdec/wiki) (in progress)
* [Botconf 2017 talk](https://retdec.com/web/files/publications/retdec-slides-botconf-2017.pdf)
* [Publications](https://retdec.com/publications/)

## Installation and Use

Currently, we support only Windows (7 or later), Linux, and unofficially macOS.

**Warning: Decompilations of larger binaries (1 MB or more) may require a lot of RAM. When running decompilations, we advise you to limit the maximal virtual memory for processes before decompiling to prevent potential swapping and unresponsiveness. On Linux, you can run e.g. `ulimit -Sv 9863168` in your shell to limit the maximal virtual memory to 8 GB.**

### Windows

1. Either download and unpack a pre-built package from the following list, or build and install the decompiler by yourself (the process is described below):

    * [32b Windows](https://github.com/avast-tl/retdec/releases/download/v3.0/retdec-v3.0-windows-32b.zip) (v3.0)
    * [64b Windows](https://github.com/avast-tl/retdec/releases/download/v3.0/retdec-v3.0-windows-64b.zip) (v3.0)

2. Install [Microsoft Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145).

3. Install [MSYS2](http://www.msys2.org/) and other needed applications by following RetDec's [Windows environment setup guide](https://github.com/avast-tl/retdec/wiki/Windows-Environment).

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, run

    ```sh
    bash $RETDEC_INSTALL_DIR/bin/retdec-decompiler.sh test.exe
    ```

   For more information, run `retdec-decompiler.sh` with `--help`.

### Linux

1. There are currently no pre-built packages for Linux. You will have to build and install the decompiler by yourself. The process is described below.

2. After you have built the decompiler, you will need to install the following packages via your distribution's package manager:

    * [Bash](https://www.gnu.org/software/bash/) (version >= 4)
    * [UPX](https://upx.github.io/)
    * [bc](https://www.gnu.org/software/bc/)
    * [Graphviz](http://www.graphviz.org/)

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, run

    ```sh
    $RETDEC_INSTALL_DIR/bin/retdec-decompiler.sh test.exe
    ```

   For more information, run `retdec-decompiler.sh` with `--help`.

### macOS

**Warning: macOS build was added based on community feedback and is not directly supported by the RetDec team. We do not guarantee you that these instructions will work for you. If you encounter any problem with your build, submit an issue so the macOS community can help you out.**

1. There are currently no pre-built packages for macOS. You will have to build and install the decompiler by yourself. The process is described below.

2. After you have built the decompiler, you will need to install the following packages:

    * [Bash](https://www.gnu.org/software/bash/) (version >= 4)
    * [UPX](https://upx.github.io/)
    * [Graphviz](http://www.graphviz.org/)
    * [GNU getopt](https://www.gnu.org/software/libc/manual/html_node/Getopt.html) -- should be first in `PATH`

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, run

    ```
    # /usr/local/bin/bash if installed via Homebrew
    /path/to/gnu/bash $RETDEC_INSTALL_DIR/bin/retdec-decompiler.sh test.exe
    ```

   For more information, run `retdec-decompiler.sh` with `--help`.

## Build and Installation

This section describes a local build and installation of RetDec. Instructions for Docker are given in the next section.

### Requirements

#### Linux

* A C++ compiler and standard C++ library supporting C++14 (e.g. GCC >= 4.9)
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [Perl](https://www.perl.org/)
* [Python](https://www.python.org/) (version >= 3.4)
* [Bison](https://www.gnu.org/software/bison/) (version >= 3.0)
* [Flex](https://www.gnu.org/software/flex/) (version >= 2.6)
* [autotools](https://en.wikipedia.org/wiki/GNU_Build_System) ([autoconf](https://www.gnu.org/software/autoconf/autoconf.html), [automake](https://www.gnu.org/software/automake/), and [libtool](https://www.gnu.org/software/libtool/))
* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
* [m4](https://www.gnu.org/software/m4/m4.html)
* [coreutils](https://www.gnu.org/software/coreutils)
* [wget](https://www.gnu.org/software/wget/)
* [ncurses](http://invisible-island.net/ncurses/) (for `libtinfo`)
* [zlib](http://zlib.net/)
* Optional: [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and [Graphviz](http://www.graphviz.org/) for generating API documentation

On Debian-based distributions (e.g. Ubuntu), the required packages can be installed with `apt-get`:

```sh
sudo apt-get install build-essential cmake git perl python3 bash bison flex autoconf automake libtool pkg-config m4 coreutils zlib1g-dev libtinfo-dev wget bc upx doxygen graphviz
```

On RPM-based distributions (e.g. Fedora), the required packages can be installed with `dnf`:

```sh
sudo dnf install gcc gcc-c++ cmake make git perl python3 bash bison flex autoconf automake libtool pkg-config m4 coreutils zlib-devel ncurses-devel wget bc upx doxygen graphviz
```

On Arch Linux, the required packages can be installed with `pacman`:

```sh
sudo pacman -S base-devel cmake git perl python3 bash bison flex autoconf automake libtool pkg-config m4 coreutils zlib ncurses wget bc upx doxygen graphviz
```

#### Windows

* Microsoft Visual C++ (version >= Visual Studio 2015 Update 2)
* [Git](https://git-scm.com/)
* [MSYS2](http://www.msys2.org/) and some other applications. Follow RetDec's [Windows environment setup guide](https://github.com/avast-tl/retdec/wiki/Windows-Environment) to get everything you need on Windows.
* [Active Perl](https://www.activestate.com/activeperl). It needs to be the first Perl in `PATH`, or it has to be provided to CMake using `CMAKE_PROGRAM_PATH` variable, e.g. `-DCMAKE_PROGRAM_PATH=/c/perl/bin`.
* [Python](https://www.python.org/) (version >= 3.4)

#### macOS

Packages should be preferably installed via [Homebrew](https://brew.sh).

* Full Xcode installation (Command Line Tools are untested)
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [Perl](https://www.perl.org/)
* [Python](https://www.python.org/) (version >= 3.4)
* [Bison](https://www.gnu.org/software/bison/) (version >= 3.0)
* [Flex](https://www.gnu.org/software/flex/) (version >= 2.6)
* [autotools](https://en.wikipedia.org/wiki/GNU_Build_System) ([autoconf](https://www.gnu.org/software/autoconf/autoconf.html), [automake](https://www.gnu.org/software/automake/), and [libtool](https://www.gnu.org/software/libtool/))
* [coreutils](https://www.gnu.org/software/coreutils) (ensure that you have `$(brew --prefix coreutils)/libexec/gnubin` in your `PATH`)
* [wget](https://www.gnu.org/software/wget/)
* Optional: [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and [Graphviz](http://www.graphviz.org/) for generating API documentation

### Process

Note: Although RetDec now supports a system-wide installation ([#94](https://github.com/avast-tl/retdec/issues/94)), unless you use your distribution's package manager to install it, we recommend installing RetDec locally into a designated directory. The reason for this is that uninstallation will be easier as you will only need to remove a single directory. To perform a local installation, run `cmake` with the `-DCMAKE_INSTALL_PREFIX=<path>` parameter, where `<path>` is directory into which RetDec will be installed (e.g. `$HOME/projects/retdec-install` on Linux and macOS, and `C:\projects\retdec-install` on Windows).

* Clone the repository:
  * `git clone https://github.com/avast-tl/retdec`
* Linux:
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of CPU cores to use for parallel build)
  * `make install`
* Windows:
  * Open a command prompt (e.g. `C:\msys64\msys2_shell.cmd` from [MSYS2](https://github.com/avast-tl/retdec/wiki/Windows-Environment))
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path> -G<generator>`
  * `cmake --build . --config Release -- -m`
  * `cmake --build . --config Release --target install`
  * Alternatively, you can open `retdec.sln` generated by `cmake` in Visual Studio IDE.
* macOS:
  * `cd retdec`
  * `mkdir build && cd build`
  * ```sh
    # Apple ships old Flex & Bison, so Homebrew versions should be used.
    export CMAKE_INCLUDE_PATH="/usr/local/opt/flex/include"
    export CMAKE_LIBRARY_PATH="/usr/local/opt/flex/lib;/usr/local/opt/bison/lib"
    export PATH="/usr/local/opt/flex/bin:/usr/local/opt/bison/bin:$PATH"
    ```
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of CPU cores to use for parallel build)
  * `make install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`.
* (Windows only) `-G<generator>` is `-G"Visual Studio 14 2015"` for 32-bit build using Visual Studio 2015, or `-G"Visual Studio 14 2015 Win64"` for 64-bit build using Visual Studio 2015. Later versions of Visual Studio may be used.

You can pass the following additional parameters to `cmake`:
* `-DRETDEC_DOC=ON` to build with API documentation (requires Doxygen and Graphviz, disabled by default).
* `-DRETDEC_TESTS=ON` to build with tests (disabled by default).
* `-DRETDEC_DEV_TOOLS=ON` to build with development tools (disabled by default).
* `-DCMAKE_BUILD_TYPE=Debug` to build with debugging information, which is useful during development. By default, the project is built in the `Release` mode. This has no effect on Windows, but the same thing can be achieved by running `cmake --build .` with the `--config Debug` parameter.
* `-DCMAKE_PROGRAM_PATH=<path>` to use Perl at `<path>` (probably useful only on Windows).

## Build in Docker

Docker support is maintained by community. If something does not work for you or if you have suggestions for improvements, open an issue or PR.

### Build Image

Building in Docker does not require installation of required libraries locally. This is a good option for trying out RetDec without setting up the whole build toolchain.

To build the RetDec docker image, run
```
docker build -t retdec .
```

This builds the container from the master branch of this repository.

To build the container using the local copy of the repository, use the development Dockerfile, `Dockerfile.dev`:
```
docker build -t retdec:dev . -f Dockerfile.dev
```

### Run Container

To decompile a binary, create a container to upload the binary to:
```
docker create --name retdec_init retdec
```

Upload the binary (note the destination directory should be a directory with read/write permissions, such as `/home/retdec/`):
```
docker cp <file> retdec_init:/destination/path/of/binary
```

Commit the copied files into the container image:
```
docker commit retdec_init retdec:initialized
```

Run the decompiler:
```
docker run --name retdec retdec:initialized retdec-decompiler.sh /destination/path/of/binary
```

Copy output back to host:
```
docker cp retdec:/destination/path/of/binary.c /path/to/save/file
```

## Repository Overview

This repository contains the following libraries:
* `ar-extractor` - library for extracting object files from archives (based on LLVM).
* `bin2llvmir` - library of LLVM passes for translating binaries into LLVM IR modules.
* `capstone2llvmir` - binary instructions to LLVM IR translation library.
* `config` - library for representing and managing RetDec configuration databases.
* `cpdetect` - library for compiler and packer detection in binaries.
* `crypto` - collection of cryptographic functions.
* `ctypes` - C++ library for representing C function data types.
* `debugformat` - library for uniform representation of DWARF and PDB debugging information.
* `demangler` - demangling library capable to handle names generated by the GCC/Clang, Microsoft Visual C++, and Borland C++ compilers.
* `dwarfparser` - library for high-level representation of DWARF debugging information.
* `fileformat` - library for parsing and uniform representation of various object file formats. Currently supporting the following formats: COFF, ELF, Intel HEX, Mach-O, PE, raw data.
* `llvm-support` - set of LLVM related utility functions.
* `llvmir-emul` - LLVM IR emulation library used for unit testing.
* `llvmir2hll` - library for translating LLVM IR modules to high-level source codes (C, Python-like language).
* `loader` - library for uniform representation of binaries loaded to memory. Supports the same formats as fileformat.
* `macho-extractor` - library for extracting regular Mach-O binaries from fat Mach-O binaries (based on LLVM).
* `patterngen` - binary pattern extractor library.
* `pdbparser` - Microsoft PDB files parser library.
* `stacofin` - static code finder library.
* `unpacker` - collection of unpacking functions.
* `utils` - general C++ utility library.

This repository contains the following tools:
* `ar-extractortool` - frontend for the ar-extractor library (installed as `retdec-ar-extractor`).
* `bin2llvmirtool` - frontend for the `bin2llvmir` library (installed as `retdec-bin2llvmir`).
* `bin2pat` - tool for generating patterns from binaries (installed as `retdec-bin2pat`).
* `capstone2llvmirtool` - frontend for the `capstone2llvmir` library (installed as `retdec-capstone2llvmir`).
* `configtool` - frontend for the `config` library (installed as `retdec-config`).
* `ctypesparser` - C++ library for parsing C function data types from JSON files into `ctypes` representation (installed as `retdec-ctypesparser`).
* `demangler_grammar_gen` -- tool for generating new grammars for the `demangler` library (installed as `retdec-demangler-grammar-gen`).
* `demanglertool` -- frontend for the `demangler` library (installed as `retdec-demangler`).
* `fileinfo` - binary analysis tool. Supports the same formats as `fileformat` (installed as `retdec-fileinfo`).
* `idr2pat` - tool for extracting patterns from IDR knowledge bases (installed as `retdec-idr2pat`).
* `llvmir2hlltool` - frontend for the `llvmir2hll` library (installed as `retdec-llvmir2hll`).
* `macho-extractortool` - frontend for the `macho-extractor` library (installed as `retdec-macho-extractor`).
* `pat2yara` - tool for processing patterns to YARA signatures (installed as `retdec-pat2yara`).
* `stacofintool` - frontend for the `stacofin` library (installed as `retdec-stacofin`).
* `unpackertool` - plugin-based unpacker (installed as `retdec-unpacker`).

This repository contains the following scripts:
* `retdec-decompiler.sh` - the main decompilation script binding it all together. This is the tool to use for full binary-to-C decompilations.
* Support scripts used by `retdec-decompiler.sh`:
  * `retdec-color-c.py` - decorates output C sources with IDA color tags - syntax highlighting for IDA.
  * `retdec-config.sh` - decompiler's configuration file.
  * `retdec-archive-decompiler.sh` - decompiles objects in the given AR archive.
  * `retdec-fileinfo.sh` - a Fileinfo tool wrapper.
  * `retdec-signature-from-library-creator.sh` - extracts function signatures from the given library.
  * `retdec-unpacker.sh` - tries to unpack the given executable file by using any of the supported unpackers.
  * `retdec-utils.sh` - a collection of bash utilities.
* `retdec-tests-runner.sh` - run all tests in the unit test directory.
* `type_extractor`

## Related Repositories

* [retdec-idaplugin](https://github.com/avast-tl/retdec-idaplugin) -- embeds RetDec into IDA (Interactive Disassembler) and makes its use much easier.
* [retdec-regression-tests-framework](https://github.com/avast-tl/retdec-regression-tests-framework) -- provides means to run and create regression tests for RetDec and related tools. This is a must if you plan to contribute to the RetDec project.
* [retdec-python](https://github.com/s3rvac/retdec-python) -- Python library and tools providing easy access to our online decompilation service through its [REST API](https://retdec.com/api/).
* [vim-syntax-retdecdsm](https://github.com/s3rvac/vim-syntax-retdecdsm) -- Vim syntax-highlighting file for the output from the RetDec's disassembler (`.dsm` files).

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the [`LICENSE`](https://github.com/avast-tl/retdec/blob/master/LICENSE) file for more details.

RetDec uses third-party libraries or other resources listed, along with their licenses, in the [`LICENSE-THIRD-PARTY`](https://github.com/avast-tl/retdec/blob/master/LICENSE-THIRD-PARTY) file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast-tl/retdec/wiki/Contribution-Guidelines).

## Acknowledgements

This software was supported by the research funding TACR (Technology Agency of the Czech Republic), ALFA Programme No. TA01010667.
