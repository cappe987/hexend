<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>
-->

# Hexend - Send raw hex frames
For when you want to manually craft frames, or to copy the hexdump from
Tcpdump/Wireshark and repeat or modify the frame afterwards.

```
hexend <iface> [HEXFILE] [OPTIONS]
```
HEXFILE can be either a name from the included hex frames (prioritized) or a
filepath. If left blank it will read from stdin. Any non-hex characters in
input are ignored.

# Installation
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

# Examples
Send a frame by filepath to `eth0`.
```
hexend eth0 my_frames/frame.hex
```

Send the built-in frame `bcast`, repeat 10 times and suppress output
```
hexend eth0 bcast -c 10 -q
```

Pipe file contents to input, repeat 5 times with 0.1 second interval
```
cat my_frames/frame.hex | hexend eth0 -c 5 -i 0.1
```

Pipe raw string to input, repeat 1000 times with no interval
```
echo ffffffffffffaaaaaaaaaaaa0000 | hexend eth0 -c 1000 -i 0
```
