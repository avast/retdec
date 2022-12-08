> **Warning**
>
> The RetDec project is currently in a **limited maintenance mode** due to a lack of resources:
> * Pull Requests are welcomed. They are reviewed with priority, if possible without delays.
> * Issues are reacted on with delays up to one quarter. Issues are not actively solved unless they relate to a basic project maintenance.
> * The basic project maintenance continues.
> * Only a very limited development is carried on.

# RetDec

[![Travis CI build status](https://travis-ci.org/avast/retdec.svg?branch=master)](https://travis-ci.org/avast/retdec)
[![TeamCity build status](https://retdec-tc.avast.com/app/rest/builds/aggregated/strob:(buildType:(project:(id:Retdec)))/statusIcon)](https://retdec-tc.avast.com/project.html?projectId=Retdec&guest=1)
[![RetDec CI](https://github.com/avast/retdec/actions/workflows/retdec-ci.yml/badge.svg)](https://github.com/avast/retdec/actions/workflows/retdec-ci.yml)

[RetDec](https://retdec.com/) is a retargetable machine-code decompiler based on [LLVM](https://llvm.org/).

The decompiler is not limited to any particular target architecture, operating system, or executable file format:
* Supported file formats: ELF, PE, Mach-O, COFF, AR (archive), Intel HEX, and raw machine code
* Supported architectures:
    * 32-bit: Intel x86, ARM, MIPS, PIC32, and PowerPC
    * 64-bit: x86-64, ARM64 (AArch64)

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
* [Wiki](https://github.com/avast/retdec/wiki) (in progress)
* Botconf 2017 talk: [slides](https://retdec.com/static/publications/retdec-slides-botconf-2017.pdf), [video](https://www.youtube.com/watch?v=HHFvtt5b6yY)
* REcon Montreal 2018 talk: [slides](https://retdec.com/static/publications/retdec-slides-recon-2018.pdf)
* [Publications](https://retdec.com/publications/)

## Installation

There are two ways of obtaining and installing RetDec:
1. Download and unpack a pre-built [stable](https://github.com/avast/retdec/releases) or [bleeding-edge](https://github.com/avast/retdec#automated-teamcity-builds) package and follow instructions in the _Use_ section of its `retdec/share/retdec/README.md` file after unpacking.
2. Build RetDec by yourself from sources by following the [Build and Installation](#build-and-installation) section. After installation, follow instructions below.

We currently support Windows (7 or later), Linux, macOS, and (experimentally) FreeBSD. An installed version of RetDec requires approximately 5 to 6 GB of free disk space.

## Use

Please, ensure that you reading instructions corresponding to the used RetDec version. If unsure, refer to the `retdec/share/retdec/README.md` file in the installation.

### Windows

1. After [installing RetDec](#installation), install [Microsoft Visual C++ Redistributable for Visual Studio 2017](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).

2. Install the following programs:

    * [UPX](https://upx.github.io/) (Optional: if you want to use UPX unpacker in the preprocessing stage)
    * [Graphviz](https://graphviz.gitlab.io/_pages/Download/windows/graphviz-2.38.msi) (Optional: if you want to generate call or control flow graphs)

3. To decompile a binary file named `test.exe`, run

    ```
    $RETDEC_INSTALL_DIR\bin\retdec-decompiler.exe test.exe
    ```

   For more information, run `retdec-decompiler.exe` with `--help`.

### Linux

1. After [installing RetDec](#installation), install the following packages via your distribution's package manager:

    * [UPX](https://upx.github.io/) (Optional: if you want to use UPX unpacker in the preprocessing stage)
    * [Graphviz](http://www.graphviz.org/) (Optional: if you want to generate call or control flow graphs)

2. To decompile a binary file named `test.exe`, run

    ```
    $RETDEC_INSTALL_DIR/bin/retdec-decompiler test.exe
    ```

   For more information, run `retdec-decompiler` with `--help`.

### macOS

1. After [installing RetDec](#installation), install the following packages:

    * [UPX](https://upx.github.io/) (Optional: if you want to use UPX unpacker in the preprocessing stage)
    * [Graphviz](http://www.graphviz.org/) (Optional: if you want to generate call or control flow graphs)

2. To decompile a binary file named `test.exe`, run

    ```
    $RETDEC_INSTALL_DIR/bin/retdec-decompiler test.exe
    ```

   For more information, run `retdec-decompiler` with `--help`.

### FreeBSD (Experimental)

1. There are currently no pre-built "ports" packages for FreeBSD. You will have to build and install the decompiler by yourself. The process is described below.

2. To decompile a binary file named `test.exe`, run

    ```
    $RETDEC_INSTALL_DIR/bin/retdec-decompiler test.exe
    ```

   For more information, run `retdec-decompiler` with `--help`.

### Use of RetDec libraries

You can easily use various RetDec libraries in your projects - if they are build with CMake. RetDec installation contains all the necessary headers, libraries, and CMake scripts.

If you installed RetDec into a standard installation location of your system (e.g. `/usr`, `/usr/local`), all you need to do in order to use its components is:

```cmake
find_package(retdec 5.0 REQUIRED
   COMPONENTS
      <component>
      [...]
)
target_link_libraries(your-project
   PUBLIC
      retdec::<component>
      [...]
)
```

If you did not install RetDec somewhere where it can be automatically discovered, you need to help CMake find it before `find_package()` is used. There are generally two ways to do it (pick & use only one):

1. Add the RetDec installation directory to [`CMAKE_PREFIX_PATH`](https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html):
    ```cmake
    list(APPEND CMAKE_PREFIX_PATH ${RETDEC_INSTALL_DIR})
    ```

2. Set the path to installed RetDec CMake scripts to `retdec_DIR`:
    ```cmake
    set(retdec_DIR ${RETDEC_INSTALL_DIR}/share/retdec/cmake)
    ```

See the [Repository Overview](https://github.com/avast/retdec/wiki/Repository-Overview) wiki page for the list of available RetDec components, or the [retdec-build-system-tests](https://github.com/avast/retdec-build-system-tests) for demos on how to use them.

## Build and Installation

This section describes a local build and installation of RetDec. Instructions for Docker are given in the next section.

### Requirements

#### Linux

* A C++ compiler and standard C++ library supporting C++17 (e.g. GCC >= 7)
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [OpenSSL](https://www.openssl.org/) (version >= 1.1.1)
* [Python](https://www.python.org/) (version >= 3.4)
* [autotools](https://en.wikipedia.org/wiki/GNU_Build_System) ([autoconf](https://www.gnu.org/software/autoconf/autoconf.html), [automake](https://www.gnu.org/software/automake/), and [libtool](https://www.gnu.org/software/libtool/))
* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
* [m4](https://www.gnu.org/software/m4/m4.html)
* [zlib](http://zlib.net/)
* Optional: [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and [Graphviz](http://www.graphviz.org/) for generating API documentation

On Debian-based distributions (e.g. Ubuntu), the required packages can be installed with `apt-get`:

```sh
sudo apt-get install build-essential cmake git openssl libssl-dev python3 autoconf automake libtool pkg-config m4 zlib1g-dev upx doxygen graphviz
```

On RPM-based distributions (e.g. Fedora), the required packages can be installed with `dnf`:

```sh
sudo dnf install gcc gcc-c++ cmake make git openssl openssl-devel python3 autoconf automake libtool pkg-config m4 zlib-devel upx doxygen graphviz
```

On Arch Linux, the required packages can be installed with `pacman`:

```sh
sudo pacman --needed -S base-devel cmake git openssl python3 autoconf automake libtool pkg-config m4 zlib upx doxygen graphviz
```

#### Windows

* Microsoft Visual C++ (version >= Visual Studio 2017 version 15.7)
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [OpenSSL](https://www.openssl.org/) (version >= 1.1.1)
* [Python](https://www.python.org/) (version >= 3.4)
* Optional: [Doxygen](http://ftp.stack.nl/pub/users/dimitri/doxygen-1.8.13-setup.exe) and [Graphviz](https://graphviz.gitlab.io/_pages/Download/windows/graphviz-2.38.msi) for generating API documentation

#### macOS

Packages should be preferably installed via [Homebrew](https://brew.sh).

* macOS >= 10.15
* Full Xcode installation ([including command-line tools](https://github.com/frida/frida/issues/338#issuecomment-426777849), see [#425](https://github.com/avast/retdec/issues/425) and [#433](https://github.com/avast/retdec/issues/433))
* [CMake](https://cmake.org/) (version >= 3.6)
* [Git](https://git-scm.com/)
* [OpenSSL](https://www.openssl.org/) (version >= 1.1.1)
* [Python](https://www.python.org/) (version >= 3.4)
* [autotools](https://en.wikipedia.org/wiki/GNU_Build_System) ([autoconf](https://www.gnu.org/software/autoconf/autoconf.html), [automake](https://www.gnu.org/software/automake/), and [libtool](https://www.gnu.org/software/libtool/))
* Optional: [Doxygen](http://www.stack.nl/~dimitri/doxygen/) and [Graphviz](http://www.graphviz.org/) for generating API documentation

#### FreeBSD (Experimental)

Packages should be installed via FreeBSDs pre-compiled package repository using the `pkg` command or built from scratch using the `ports` database method.

* Full "pkg" tool instructions: [handbook pkg method](https://www.freebsd.org/doc/handbook/pkgng-intro.html)
  * `pkg install cmake python37 git autotools`
OR
* Full "ports" instructions: [handbook ports method](https://www.freebsd.org/doc/handbook/ports-using.html)
  * `portsnap fetch`
  * `portsnap extract`
* For example, `cmake` would be
  * `whereis cmake`
  * `cd /usr/ports/devel/cmake`
  * `make install clean`

### Process

Note: Although RetDec now supports a system-wide installation ([#94](https://github.com/avast/retdec/issues/94)), unless you use your distribution's package manager to install it, we recommend installing RetDec locally into a designated directory. The reason for this is that uninstallation will be easier as you will only need to remove a single directory. To perform a local installation, run `cmake` with the `-DCMAKE_INSTALL_PREFIX=<path>` parameter, where `<path>` is directory into which RetDec will be installed (e.g. `$HOME/projects/retdec-install` on Linux and macOS, and `C:\projects\retdec-install` on Windows).

* Clone the repository:
  * `git clone https://github.com/avast/retdec`
* Linux:
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of processes to use for parallel build, typically number of cores + 1 gives fastest compilation time)
  * `make install`
* Windows:
  * Open a command prompt (e.g. `cmd.exe`)
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path> -G<generator>`
  * `cmake --build . --config Release -- -m`
  * `cmake --build . --config Release --target install`
  * Alternatively, you can open `retdec.sln` generated by `cmake` in Visual Studio IDE
* macOS:
  * `cd retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of processes to use for parallel build, typically number of cores + 1 gives fastest compilation time)
  * `make install`
* FreeBSD:
  * `sudo pkg install git cmake`
  * `git clone https://github.com/avast/retdec`
  * `cd retdec`
  * `mkdir build && cd build`
  * ```sh
    # FreeBSD (and other BSDs) do need cmake, python3, git, autotools. OpenSSL is pre-installed in the OS but check its version.
    # Later versions may be available for each of the packages.
    # See what is installed:
    sudo pkg info cmake python37 autotools
    # Install/upgrade them:
    sudo pkg install cmake python37 autotools
    ```
  * `cmake .. -DCMAKE_INSTALL_PREFIX=<path>`
  * `make -jN` (`N` is the number of processes to use for parallel build, typically number of cores + 1 gives fastest compilation time)
  * `make install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`. Quote the path if you are using backslashes on Windows (e.g. `-DCMAKE_INSTALL_PREFIX="C:\retdec"`).
* (Windows only) `-G<generator>` is `-G"Visual Studio 15 2017"` for 32-bit build using Visual Studio 2017, or `-G"Visual Studio 15 2017 Win64"` for 64-bit build using Visual Studio 2017. Later versions of Visual Studio may be used.

You can pass the following additional parameters to `cmake`:
* `-DRETDEC_DOC=ON` to build with API documentation (requires Doxygen and Graphviz, disabled by default).
* `-DRETDEC_TESTS=ON` to build with tests (disabled by default).
* `-DRETDEC_DEV_TOOLS=ON` to build with development tools (disabled by default).
* `-DRETDEC_COMPILE_YARA=OFF` to disable YARA rules compilation at installation step (enabled by default).
* `-DCMAKE_BUILD_TYPE=Debug` to build with debugging information, which is useful during development. By default, the project is built in the `Release` mode. This has no effect on Windows, but the same thing can be achieved by running `cmake --build .` with the `--config Debug` parameter.
* `-D<dep>_LOCAL_DIR=<path>` where `<dep>` is from `{CAPSTONE, GOOGLETEST, KEYSTONE, LLVM, YARA, YARAMOD}` (e.g. `-DCAPSTONE_LOCAL_DIR=<path>`), to use the local repository clone at `<path>` for RetDec dependency instead of downloading a fresh copy at build time. Multiple such options may be used at the same time.
* `-DRETDEC_ENABLE_<component>=ON` to build only the specified component(s) (multiple such options can be used at once), and its (theirs) dependencies. By default, all the components are built. If at least one component is enabled via this mechanism, all the other components that were not explicitly enabled (and are not needed as dependencies of enabled components) are not built. See [cmake/options.cmake](https://github.com/avast/retdec/blob/master/cmake/options.cmake) for all the available component options.
  * `-DRETDEC_ENABLE_ALL=ON` can be used to (re-)enable all the components.
  * Alternatively, `-DRETDEC_ENABLE=<comma-separated component list>` can be used instead of `-DRETDEC_ENABLE_<component>=ON` (e.g. `-DRETDEC_ENABLE=fileformat,loader,ctypesparser` is equivalent to `-DRETDEC_ENABLE_FILEFORMAT=ON -DRETDEC_ENABLE_LOADER=ON -DRETDEC_ENABLE_CTYPESPARSER=ON`).

## Build in Docker

Docker support is maintained by community. If something does not work for you or if you have suggestions for improvements, open an issue or PR.

### Build Image

Building in Docker does not require installation of the required libraries locally. This is a good option for trying out RetDec without setting up the whole build toolchain.

To build the RetDec Docker image, run
```
docker build -t retdec - < Dockerfile
```

This builds the image from the master branch of this repository.

To build the image using the local copy of the repository, use the development Dockerfile, `Dockerfile.dev`:
```
docker build -t retdec:dev . -f Dockerfile.dev
```

### Run Container

If your `uid` is not 1000, make sure that the directory containing your input binary files is accessible for RetDec:
```
chmod 0777 /path/to/local/directory
```
Now, you can run the decompiler inside a container:
```
docker run --rm -v /path/to/local/directory:/destination retdec retdec-decompiler /destination/binary
```
Note: Do not modify the `/destination` part is. You only need to change `/path/to/local/directory`. Output files will then be generated to `/path/to/local/directory`.

## Nightly Builds

We generate up-to-date RetDec packages from the latest commit in the `master` branch in two ways:
* Using our TeamCity servers
* Using Github Actions.

The builds are mostly meant to be used by RetDec developers, contributors, and other people experimenting with the product (e.g. testing if an issue present in the official release still exists in the current `master`).

You can use these as you wish, but keep in mind that there are no guarantees they will work on your system (especially the Linux version), and that regressions are a possibility. To get a stable RetDec version, either download the latest official pre-built package or build the latest RetDec version tag.

**TeamCity**

* [Windows Server 2016, version 10.0](https://retdec-tc.avast.com/repository/download/Retdec_WinBuild/.lastSuccessful/package/retdec-master-windows-64b.7z?guest=1)
* [Ubuntu Bionic Linux, version 18.04](https://retdec-tc.avast.com/repository/download/RetDec_LinuxBuild/.lastSuccessful/package/retdec-master-linux-64b.tar.xz?guest=1)
* [Mac OS X, version 10.14.6](https://retdec-tc.avast.com/repository/download/Retdec_MacBuild/.lastSuccessful/package/retdec-master-macos-64b.tar.xz?guest=1)

**Github Actions**

You can find builds for macOS, Linux and Windows in the [latest RetDec CI workflow run](https://github.com/avast/retdec/actions/workflows/retdec-ci.yml).

## Project Documentation

See the [project documentation](https://retdec-tc.avast.com/repository/download/Retdec_DoxygenBuild/.lastSuccessful/build/doc/doxygen/html/index.html?guest=1) for an up to date Doxygen-generated software reference corresponding to the latest commit in the `master` branch.

## Related Repositories

* [retdec-idaplugin](https://github.com/avast/retdec-idaplugin) -- Embeds RetDec into IDA (Interactive Disassembler) and makes its use much easier.
* [retdec-r2plugin](https://github.com/avast/retdec-r2plugin) -- Embeds RetDec into Radare2 and makes its use much easier.
* [retdec-regression-tests-framework](https://github.com/avast/retdec-regression-tests-framework) -- A framework for writing and running regression tests for RetDec and related tools. This is a must if you plan to contribute to the RetDec project.
* [retdec-regression-tests](https://github.com/avast/retdec-regression-tests) -- A suite of regression tests for RetDec and related tools.
* [retdec-build-system-tests](https://github.com/avast/retdec-build-system-tests) -- A suite of tests for RetDec's build system. This can also serve as a collection of demos on how to use RetDec libraries.
* [vim-syntax-retdecdsm](https://github.com/s3rvac/vim-syntax-retdecdsm) -- Vim syntax-highlighting file for the output from the RetDec's disassembler (`.dsm` files).

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the [`LICENSE`](https://github.com/avast/retdec/blob/master/LICENSE) file for more details.

RetDec incorporates a modified PeLib library. New modules added by Avast Software are licensed under the MIT license. The original sources are licensed under the following license:
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com), licensed under the zlib/libpng License. See the [`LICENSE-PELIB`](https://github.com/avast/retdec/blob/master/LICENSE-PELIB) file for more details.

RetDec uses third-party libraries or other resources listed, along with their licenses, in the [`LICENSE-THIRD-PARTY`](https://github.com/avast/retdec/blob/master/LICENSE-THIRD-PARTY) file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast/retdec/wiki/Contribution-Guidelines).

## Acknowledgements

This software was supported by the research funding TACR (Technology Agency of the Czech Republic), ALFA Programme No. TA01010667.
