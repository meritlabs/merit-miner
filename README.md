# merit-miner

This is a multi-threaded CPU miner for Merit.
It can be used for pool mining or solo mining with local Merit daemon.

The softtware is based on original miner for Litecoin and Bitcoin, fork of Jeff Garzik's reference cpuminer.

License: GPLv2.  See [LICENSE](LICENSE.md) for details.

### Dependencies
```
libboost    https://www.boost.org/
libcurl     http://curl.haxx.se/libcurl/
jansson     http://www.digip.org/jansson/ # (jansson is included in-tree)
```

### Basic *nix build instructions

```
sudo apt-get install build-essential libtool automake autotools-dev libcurl4-openssl-dev libboost-dev
./autogen.sh	# only needed if building from git repo
./nomacro.pl	# in case the assembler doesn't support macros
./configure
make
```

### Basic Windows build instructions, using MinGW

Install MinGW and the MSYS Developer Tool Kit (http://www.mingw.org/)
- Make sure you have mstcpip.h in MinGW\include

If using MinGW-w64, install pthreads-w64

Install libcurl devel (http://curl.haxx.se/download.html)
- Make sure you have libcurl.m4 in MinGW\share\aclocal
- Make sure you have curl-config in MinGW\bin
In the MSYS shell, run:
```
./autogen.sh	# only needed if building from git repo
LIBCURL="-lcurldll" ./configure
make
```

### Windows build instructions using WSL

With Windows 10, Microsoft has released a new feature named the [Windows
Subsystem for Linux (WSL)](https://msdn.microsoft.com/commandline/wsl/about). This
feature allows you to run a bash shell directly on Windows in an Ubuntu-based
environment. Within this environment you can cross compile for Windows without
the need for a separate Linux VM or server.

This feature is not supported in versions of Windows prior to Windows 10 or on
Windows Server SKUs. In addition, it is available [only for 64-bit versions of
Windows](https://msdn.microsoft.com/en-us/commandline/wsl/install_guide).

For Windows 10 systems with the Fall Creators Update applied (version >= 16215.0) use the Windows Store
to install Ubuntu. Search for "Linux" in the Windows Store and install the free "Ubuntu" application.
Full instructions are available on the above link.

To get the bash shell, you must first activate the feature in Windows.

1. Turn on Developer Mode
  * Open Settings -> Update and Security -> For developers
  * Select the Developer Mode radio button
  * Restart if necessary
2. Enable the Windows Subsystem for Linux feature
  * From Start, search for "Turn Windows features on or off" (type 'turn')
  * Scroll down and Select Windows Subsystem for Linux (beta)
  * Click OK
  * Restart if necessary
3. Install a Linux Distribution
  * Open the Microsoft Store (Win + type 'store') 
  * Search for Ubuntu (Orange icon) or whichever you prefer (This doc will assume Ubuntu)
  * Install the app
4. Complete Installation
  * Open a cmd prompt (Win key + type 'cmd')
  * In the command prompt window type "bash"
  * Accept the license
  * Create a new UNIX user account (this is a separate account from your Windows account)
5. Test it
  * Run `sudo apt update`

Next actions are performed in WSL Bash application (cmd window -> `bash`) and assumes that Ubuntu provider is used.

1. Install required libraries:
    ```
    sudo apt install libcurl4-openssl-dev
    sudo apt install libboost-all-dev
    sudo apt install build-essential libtool autotools-dev automake pkg-config
    ```
2. Execute configuration and build commands inside your Merit folder:
    ```
    ./autogen.sh	# (optional) Run first only needed if you're building from a cloned git repo
    ./nomacro.pl	# (optional) in case the assembler doesn't support macros
    ./configure  # (required) This will prepare the build on your machine to be compiled
    make         # (required) This will "make" the build and create the desired minerd.exe Bash application
    ```
3. Run minerd using Bash application as described in [Usage instructions](#usage-instructions)

### Usage instructions

Run `./minerd --help` to see options.

Connecting through a proxy:  Use the --proxy option.
To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host.
Protocols socks4a and socks5h, allowing remote name resolving, are also
available since libcurl 7.18.0.
If no protocol is specified, the proxy is assumed to be a HTTP proxy.
When the --proxy option is not used, the program honors the http_proxy
and all_proxy environment variables.

### Exmaple usage

#### Run as a solo miner pointed to meritd instance

`./minerd -o http://127.0.0.1:2335 -O merit:localpwd -t 2 -C 2 --coinbase-addr=your_merit_address_or_alias`

#### Run with pool supporting stratum protocol

`./minerd -o stratum+tcp://pool.merit.me:3333 -u your_merit_address_or_alias -t 2 -C 2`

* The value after `-u` can simply be your public Merit Address or your Merit Alias (without the @ symbol). No ' ' or " " are needed.
* The `-t 2 -C 2` flags set the threads for your processor. -t 6 would use six threads. You can remove `-t 2 -C 2` entirely to have it automatically use every available thread.
* Press (Ctrl + C) a few times inside the command window to stop minerd.exe. Pressing the Up key will allow you to run previous commands or edit them.
