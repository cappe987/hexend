<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>
-->

# Hexend - Send raw hex frames
> /hɛksɛnd/ (pronunciation)

For when you want to manually craft frames, or to copy the hexdump from
Tcpdump/Wireshark and repeat or modify the frame afterwards.

```
hexend <iface> [FILE] [OPTIONS]
```
File may only contain hexadecimal characters and whitespace.

# Installation
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

# Examples
Send a frame from file to `eth0`
```
hexend eth0 my_frames/frame.hex
```

Send a frame from file, repeat 10 times and suppress output
```
hexend eth0 my_frames/frame.hex -c 10 -q
```

Pipe file contents to input, repeat 5 times with 0.1 second interval
```
cat my_frames/frame.hex | hexend eth0 -c 5 -i 0.1
```

Pipe raw string to input, repeat 1000 times with no interval
```
echo ffffffffffffaaaaaaaaaaaa0000 | hexend eth0 -c 1000 -i 0
```
