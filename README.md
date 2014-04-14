heartbleed-test
=================

A simple tool written in Ruby wich allow testing a remote server for OpenSSL CVE-2014-0160 vulnerability.

## Disclaimer

**I will not be taken responsible for the damage that could be done using this tool. It was written to check private servers for a precise vulnerability and measure potential user-related data leakages under high traffic. It is shared as a tool for internal security auditing.**

## Dependencies

Requires :

- Ruby
- Bundler

In order to install these prerequisites, first download and install ruby for your plateform.
Then install Bundler, with the command ```gem install bundler ``` and retrieve project dependencies by running ```bundle install``` in the project root directory.


## Usage

The command line synopsis is ```ruby src/run.rb <host> [<port>]```

If the remote host does not appear to be vulnerable, the ouptut will look like this :

<pre>
Host server:443 seems safe
</pre>

If the remote host is vulnerable, the ouput will display about 16 Kib of data stolen from memory and shown as an hexadecimal dump. 

Note : 16 Kib is the maximum size for one Heartbeat message without using *max_fragment_length* extension, see [RFC 6520](https://tools.ietf.org/html/rfc6520).

<pre>
Host server:443 is vulnerable! Heartbeat response payload :
00000000  d4 03 03 53 4a 84 a9 00 01 02 03 04 05 06 07 08  |...SJ...........|
00000010  09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18  |................|
00000020  19 1a 1b 00 01 a6 00 00 00 01 00 02 00 03 00 04  |................|
00000030  00 05 00 06 00 07 00 08 00 09 00 0a 00 0b 00 0c  |................|
00000040  00 0d 00 0e 00 0f 00 10 00 11 00 12 00 13 00 14  |................|
00000050  00 15 00 16 00 17 00 18 00 19 00 1a 00 1b 00 1c  |................|
00000060  00 1d 00 1e 00 1f 00 20 00 21 00 22 00 23 00 24  |....... .!.".#.$|
00000070  00 25 00 26 00 27 00 28 00 29 00 2a 00 2b 00 2c  |.%.&.'.(.).*.+.,|
00000080  00 2d 00 2e 00 2f 00 30 00 31 00 32 00 33 00 34  |.-.../.0.1.2.3.4|
....
</pre>


## Improvement

This tool may be improved in future versions with things like :
- Command line argument checking
- Support for more complex cases
- Better timeout management


