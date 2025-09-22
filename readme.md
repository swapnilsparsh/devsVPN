# privateLINE Connect Desktop (Windows/Linux)

**privateLINE Connect Desktop** is the official [privateLINE](https://privateline.io) VPN client for Windows, Linux platforms.
privateLINE Connect Desktop releases are distributed on the official site [privateline.io](https://privateline.io/downloads).

- [privateLINE Connect Desktop (Windows/Linux)](#privateline-connect-desktop-windowslinux)
	- [About this Repo](#about-this-repo)
	- [Installation](#installation)
		- [Requirements](#requirements)
			- [Windows](#windows)
			- [Linux](#linux)
		- [Compilation](#compilation)
			- [Windows](#windows-1)
			- [Linux](#linux-1)
		- [Development \& Testing Tips \& Tricks](#development--testing-tips--tricks)
	- [Versioning](#versioning)
	- [Security Policy](#security-policy)
	- [License](#license)
	- [Authors](#authors)
	- [Acknowledgements](#acknowledgements)

<a name="about-repo"></a>

## About this Repo

This is the GitHub repo of the [privateLINE Connect Desktop](https://privateline.io/downloads) app.

The project is divided into three parts:

* **daemon**: Core module of the privateLINE software built mostly using the Go language. It runs with privileged rights as a system service/daemon.
* **UI**: Graphical User Interface built using Electron.
* **CLI**: Command Line Interface.

<a name="installation"></a>

## Installation

These instructions enable you to get the project up and running on your local machine for development and testing purposes.

<a name="requirements"></a>

### Requirements

<a name="requirements_windows"></a>

#### Windows

[Go 1.23+](https://golang.org/); Git; [npm](https://www.npmjs.com/get-npm); [Node.js (20)](https://nodejs.org/); [nsis3](https://nsis.sourceforge.io/Download); Build Tools for Visual Studio 2019 ('Windows 10 SDK 10.0.19041.0', 'Windows 11 SDK 10.0.22000.0', 'MSVC v142 C++ x64 build tools', 'C++ ATL for latest v142 build tools'); gcc compiler (e.g. [TDM GCC](https://jmeubank.github.io/tdm-gcc/download/)).  

Target Windows platforms are: Windows 10, Windows 11. To make sure that your build works on win10 - you must install the exact SDK versions as part of Build Tools for Visual Studio installation, not the latest SDKs.

<a name="requirements_linux"></a>

#### Linux

[Go 1.23+](https://golang.org/); Git; [npm](https://www.npmjs.com/get-npm); [Node.js (20)](https://nodejs.org/); gcc; make; [FPM](https://fpm.readthedocs.io/en/latest/installation.html); curl; rpm; libiw-dev.

To compile  [liboqs](https://github.com/open-quantum-safe/liboqs), additional packages are required:
`sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind`

Target Linux platforms are the ones with GLIBC 2.31 or higher. Currently supported platforms:
- Ubuntu 20.04 LTS or higher
- Debian 11 or higher

In order to create release builds, you need to set up your development environment in Linux with GLIBC 2.31 - either Debian 11 (recommended), or Ubuntu 20.04 LTS.

<a name="compilation"></a>

### Compilation

<a name="compilation_windows"></a>

#### Windows

Instructions to build installer of privateLINE Client *(daemon + CLI + UI)*:
Use Developer Command Prompt for Visual Studio (required for building native sub-projects).

```bash
git clone https://github.com/swapnilsparsh/devsVPN.git
cd devsVPN/ui/References/Windows
build.bat
```
- Use `desktop-app/ui/References/Windows/build.bat` to create a release build (maximum package compression, slow compilation).
- Use `desktop-app/ui/References/Windows/build-debug.bat` to create a build for testing (no package compression, fast compilation).

Compiled binaries can be found at `ui/References/Windows/bin`

<a name="compilation_linux"></a>

#### Linux

Linux build can produce two package flavors:

* **privateline-connect-console**: Console-only release, which includes daemon+CLI.
* **privateline-connect-full**: Console and Xorg release, includes daemon+CLI+UI.

Since both package flavors include the daemon, you can install either privateline-connect-console package, or privateline-connect-full, but not both at the same time.

```bash
# get sources
git clone https://github.com/swapnilsparsh/devsVPN.git

# Run build.sh without arguments to get all build options:
cd devsVPN
./cli/References/Linux/build.sh

ERROR: you must include '--console' or '--full' argument

Usage: ./build.sh < --console | --full > < --deb | --rpm > < --test | --release > [-v,--version VER]
	--console               Build a console-only package containing daemon+CLI
	--full                  Build a full package containing daemon+CLI+UI
	--deb                   Build a DEB package
	--rpm                   Build an RPM package
	--test                  Build a package for testing - no package compression, fast compilation
	--release               Build a release package - max package compression, slow compilation
	-v, --version           Specify version

Examples:

	To create a testing build of a console-only package in DEB format:
		yes | ./build.sh --console --deb --test

	To create a release build of a full package in RPM format:
		./build.sh --full --rpm --release
```

If you try to create a Linux build on machine with GLIBC version higher than 2.31, build will complain. To bypass the confirmation prompts and create a local testing build, you can pipe `yes` to `build.sh`:
``` bash
yes | ./build.sh ...
```

Compiled DEB/RPM packages can be found at `cli/References/Linux/_out_bin`

<a name="tips-and-tricks"></a>

### [Development & Testing Tips & Tricks](docs/dev-tips-and-tricks.md)

<a name="versioning"></a>

## Versioning

Current version is set in `ui/package.json` for all build types on all platforms.

<a name="security"></a>

## Security Policy

If you want to report a security problem, please read our [Security Policy](/.github/SECURITY.md).

<a name="license"></a>

## License

This project is licensed under the GPLv3 - see the [License](/LICENSE.md) file for details.

<a name="Authors"></a>

## Authors

See the [Authors](/AUTHORS) file for the list of contributors who participated in this project.

<a name="acknowledgements"></a>

## Acknowledgements

See the [Acknowledgements](/ACKNOWLEDGEMENTS.md) file for the list of third party libraries used in this project.
