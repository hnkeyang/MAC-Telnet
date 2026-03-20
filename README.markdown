MAC-Telnet / MAC SSH for OpenWrt
==============================

This is a fork of [MAC-Telnet](https://github.com/aouyar/MAC-Telnet) from
[aouyar](https://github.com/aouyar) (_Ali Onur Uyar_) which is an SSH-enabled
version of the original MAC-Telnet implementation from
[haakonnessjoen](https://github.com/haakonnessjoen) (_Håkon Nessjøen_).

The fork reworks the mactelnet codebase to built upon uloop, usock and
other facilities provided by the standard OpenWrt libraries.

# server
mactelnetd -c /usr/bin/login

# client
mactelnet -N 4e:74:e6:02:4d:03

Licensing
---------

See the _LICENSE_ file that acompanies the code for full licensing information.
