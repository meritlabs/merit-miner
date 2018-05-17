# merit-miner

This is a multi-threaded CPU miner for Merit.
It can be used for pool mining or solo mining with local Merit daemon.
The softtware is based on original miner for Litecoin and Bitcoin, fork of Jeff Garzik's reference cpuminer.

License: GPLv2.  See [COPYING](COPYING) for details.

### Dependencies
```
libcurl		http://curl.haxx.se/libcurl/
jansson		http://www.digip.org/jansson/ # (jansson is included in-tree)
```

### Basic *nix build instructions

```
./autogen.sh	# only needed if building from git repo
./nomacro.pl	# in case the assembler doesn't support macros
./configure CFLAGS="-O3" --disable-assembly --enable-march # Make sure -O3 is an O and not a zero!
make
```

### Notes for AIX users
- To build a 64-bit binary, export OBJECT_MODE=64
- GNU-style long options are not supported, but are accessible via configuration file

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
LIBCURL="-lcurldll" ./configure CFLAGS="-O3"
make
```

### Issues
- asm code is not supported and miner should be built with `--disable-assembly` flag

### Usage instructions

Run `minerd --help` to see options.

Connecting through a proxy:  Use the --proxy option.
To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host.
Protocols socks4a and socks5h, allowing remote name resolving, are also
available since libcurl 7.18.0.
If no protocol is specified, the proxy is assumed to be a HTTP proxy.
When the --proxy option is not used, the program honors the http_proxy
and all_proxy environment variables.

Also many issues and FAQs are covered in the forum thread
dedicated to this program, https://bitcointalk.org/index.php?topic=55038.0

### Exmaple usage

#### Run as a solo miner pointed to meritd instance

`./minerd -o http://127.0.0.1:2335 -D -O merit:local321 -t 2 --coinbase-addr=mPffSnc9UZ8kpZV1cRrY7MF3SWgxja7Eh6`

#### Run with pool supporting stratum protocol

`./minerd -o stratum+tcp://127.0.0.1:3333 -u tony -D -t 1`
