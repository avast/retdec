# RetDec

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

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, go into `$RETDEC_INSTALL_DIR/bin` and run:

    ```sh
    bash decompile.sh test.exe
    ```

   For more information, run `bash decompile.sh --help`.

### Linux

1. There are currently no pre-built packages for Linux. You will have to build and install the decompiler by yourself. The process is described below.

2. After you have built the decompiler, you will need to install the following packages via your distribution's package manager:

    * [Bash](https://www.gnu.org/software/bash/)
    * [UPX](https://upx.github.io/)
    * [bc](https://www.gnu.org/software/bc/)
    * [Graphviz](http://www.graphviz.org/)

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, go into `$RETDEC_INSTALL_DIR/bin` and run:

    ```sh
    ./decompile.sh test.exe
    ```

   For more information, run `./decompile.sh --help`.

### macOS

**Warning: macOS build was added based on community feedback and is not directly supported by the RetDec team. We do not guarantee you that these instructions will work for you. If you encounter any problem with your build, submit an issue so the macOS community can help you out.**

1. There are currently no pre-built packages for macOS. You will have to build and install the decompiler by yourself. The process is described below.

2. After you have built the decompiler, you will need to install the following packages:

    * [Bash](https://www.gnu.org/software/bash/)
    * [UPX](https://upx.github.io/)
    * [Graphviz](http://www.graphviz.org/)
    * GNU getopt -- should be first in `PATH`

3. Now, you are all set to run the decompiler. To decompile a binary file named `test.exe`, go into `$RETDEC_INSTALLED_DIR/bin` and run:

    ```
    # /usr/local/bin/bash if installed via Homebrew
    /path/to/gnu/bash ./decompile.sh test.exe
    ```

   For more information, run `./decompile.sh --help`.

## Build and Installation

This section describes a manual build and installation of RetDec.

### Requirements

#### Linux

* A C++ compiler and standard C++ library supporting C++14 (e.g. GCC >= 4.9)
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [Perl](https://www.perl.org/)
* [Python](https://www.python.org/) (version >= 3.4)
* [Bash](https://www.gnu.org/software/bash/)
* [Bison](https://www.gnu.org/software/bison/) (version >= 3.0)
* [Flex](https://www.gnu.org/software/flex/)
* [coreutils](https://www.gnu.org/software/coreutils)
* [wget](https://www.gnu.org/software/wget/)
* [libtool](https://www.gnu.org/software/libtool/)
* [ncurses](http://invisible-island.net/ncurses/) (for `libtinfo`)
* [zlib](http://zlib.net/)
* Optional: [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and [Graphviz](http://www.graphviz.org/) for generating API documentation

On Debian-based distributions (e.g. Ubuntu), the required packages can be installed with `apt-get`:

```sh
sudo apt-get install build-essential cmake git perl python3 bash coreutils wget bc doxygen graphviz upx flex bison zlib1g-dev libtinfo-dev autoconf automake pkg-config m4 libtool
```

On RPM-based distributions (e.g. Fedora), the required packages can be installed with `dnf`:

```sh
sudo dnf install git cmake make gcc gcc-c++ perl python3 bash zlib-devel flex bison m4 coreutils autoconf automake libtool ncurses-devel wget bc doxygen graphviz upx pkg-config
```

#### Windows

* Microsoft Visual C++ (version >= Visual Studio 2015 Update 2)
* [Git](https://git-scm.com/)
* [MSYS2](http://www.msys2.org/) and some other applications. Follow RetDec's [Windows environment setup guide](https://github.com/avast-tl/retdec/wiki/Windows-Environment) to get everything you need on Windows.
* [Active Perl](https://www.activestate.com/activeperl). It needs to be the first Perl in `PATH`, or it has to be provided to CMake using `CMAKE_PROGRAM_PATH` variable, e.g. `-DCMAKE_PROGRAM_PATH=/c/perl/bin`.
* [Python](https://www.python.org/) (version >= 3.4)

#### macOS

  * Full Xcode installation (Command Line Tools are untested)
  * CMake (version >= 3.6)
  * Newer versions of Bison and Flex, preferably installed via [Homebrew](https://brew.sh)
  * [wget](https://www.gnu.org/software/wget/)
  * [Python](https://www.python.org/) (version >= 3.4, macOS has 2.7)

### Process

**Warning: Currently, RetDec has to be installed into a clean, dedicated directory. Do NOT install it into `/usr`, `/usr/local`, etc. because our build system is not yet ready for system-wide installations. So, when running `cmake`, always set `-DCMAKE_INSTALL_PREFIX=<path>` to a directory that will be used just by RetDec. For more details, see [#12](https://github.com/avast-tl/retdec/issues/12).**

* Recursively clone the repository (it contains submodules):
  * `git clone --recursive https://github.com/avast-tl/retdec`
* Linux:
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make && make install`
* Windows:
  * Open MSBuild command prompt, or any terminal that is configured to run the `msbuild` command.
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path> -G<generator>`
  * `msbuild /m /p:Configuration=Release retdec.sln`
  * `msbuild /m /p:Configuration=Release INSTALL.vcxproj`
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
  * `make && make install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`.
* (Windows only) `-G<generator>` is `-G"Visual Studio 14 2015"` for 32-bit build using Visual Studio 2015, or `-G"Visual Studio 14 2015 Win64"` for 64-bit build using Visual Studio 2015. Later versions of Visual Studio may be used.

You can pass the following additional parameters to `cmake`:
* `-DRETDEC_DOC=ON` to build with API documentation (requires Doxygen and Graphviz, disabled by default).
* `-DRETDEC_TESTS=ON` to build with tests, including all the tests in dependency submodules (disabled by default).
* `-DCMAKE_BUILD_TYPE=Debug` to build with debugging information, which is useful during development. By default, the project is built in the `Release` mode. This has no effect on Windows, but the same thing can be achieved by running `msbuild` with the `/p:Configuration=Debug` parameter.
* `-DCMAKE_PROGRAM_PATH=<path>` to use Perl at `<path>` (probably useful only on Windows).

## Repository Overview

This repository contains the following libraries:
* `bin2llvmir` -- library of LLVM passes for translating binaries into LLVM IR modules.
* `debugformat` -- library for uniform representation of DWARF and PDB debugging information.
* `dwarfparser` -- library for high-level representation of DWARF debugging information.
* `llvm-support` -- set of LLVM related utility functions.
* `llvmir2hll` -- library for translating LLVM IR modules to high-level source codes (C, Python-like language).

This repository contains the following tools:
* `bin2llvmirtool` -- frontend for the `bin2llvmir` library.
* `llvm2hlltool` -- frontend for the `llvmir2hll` library.

This repository contains the following scripts:
* `decompile.sh` -- the main decompilation script binding it all together. This is the tool to use for full binary-to-C decompilations.
* Support scripts used by `decompile.sh`:
  * `color-c.py` -- decorates output C sources with IDA color tags -- syntax highlighting for IDA.
  * `config.sh` -- decompiler's configuration file.
  * `decompile-archive.sh` -- decompiles objects in the given AR archive.
  * `fileinfo.sh` -- a Fileinfo tool wrapper.
  * `signature-from-library.sh` -- extracts function signatures from the given library.
  * `unpack.sh` -- tries to unpack the given executable file by using any of the supported unpackers.
* Other utility scripts:
  * `decompile-all.sh` -- decompiles all executables in the given directory and subdirectories.
  * `run-unit-test.sh` -- run all tests in the unit test directory.
  * `utils.sh` -- a collection of bash utilities.

## Related Repositories

* [retdec-idaplugin](https://github.com/avast-tl/retdec-idaplugin) -- embeds RetDec into IDA (Interactive Disassembler) and makes its use much easier.
* [retdec-regression-tests-framework](https://github.com/avast-tl/retdec-regression-tests-framework) -- provides means to run and create regression tests for RetDec and related tools. This is a must if you plan to contribute to the RetDec project.
* [retdec-python](https://github.com/s3rvac/retdec-python) -- Python library and tools providing easy access to our online decompilation service through its [REST API](https://retdec.com/api/).
* [vim-syntax-retdecdsm](https://github.com/s3rvac/vim-syntax-retdecdsm) -- Vim syntax-highlighting file for the output from the RetDec's disassembler (`.dsm` files).

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the `LICENSE` file for more details.

RetDec uses third-party libraries or other resources listed, along with their licenses, in the `LICENSE-THIRD-PARTY` file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast-tl/retdec/wiki/Contribution-Guidelines).

## Acknowledgements

This software was supported by the research funding TACR (Technology Agency of the Czech Republic), ALFA Programme No. TA01010667.
