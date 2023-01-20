<!---
SPDX-License-Identifier: MIT
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
Send a frame from file to `eth0`. Repeats until stopped.
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

# Test
The test script depends on `tshark` and requires you to have access to running
it. If you have Wireshark and is part of the "wireshark" group it should work.
To run the full test suite do
```
make test
```

To select an individual test you can do
```
make test t=zero_interval
```

# Hexend shell script
After creating this project I found a way to do this with shell scripts, which is what I initially would have wanted. But the performance of the shell script (found in `script/hexend`) is much worse if you want to send a lot of packets. On the upside, it doesn't require escalated privileges. The script is very basic right now and depends on `xxd` and `socat`. It is used the same, either by piping to `stdin`, or by providing a filename. It currently does not support any of the argument flags.
