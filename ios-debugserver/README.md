LLDB debugserver for iOS
========================

This makefile will extract the `debugserver` binary for iOS from
the Apple Developer Disk Image and process it to make it usable
for remote debugging on jailbroken devices.

For more information see http://iphonedevwiki.net/index.php/Debugserver

Usage
-----

List all available iOS targets:

	$ make ls
	4.2		5.1		7.0		8.1
	4.3		6.0		7.1		8.2
	5.0		6.1		8.0		8.3


Build debugserver from specific iOS version:

	$ make debugserver IOS=8.1
	hdiutil detach /Volumes/DeveloperDiskImage || true
	hdiutil: detach failed - No such file or directory
	hdiutil attach /Applications/Xcode.app/.../8.1*/DeveloperDiskImage.dmg
	Checksumming whole disk (Apple_HFS : 0)…
	...................................................................
		  whole disk (Apple_HFS : 0): verified   CRC32 $1718D76D
	verified   CRC32 $03C50CCF
	/dev/disk3       /Volumes/DeveloperDiskImage
	cp /Volumes/DeveloperDiskImage/usr/bin/debugserver .
	codesign -s - --entitlements entitlements.plist -f debugserver
	debugserver: replacing existing signature
	lipo -extract armv7 debugserver -o debugserver-8.1-armv7
	lipo -extract arm64 debugserver -o debugserver-8.1-arm64
	rm debugserver
	hdiutil detach /Volumes/DeveloperDiskImage
	"disk3" unmounted.
	"disk3" ejected.

Installation
------------

At this point you'll get two binaries named as `debugserver-8.1-armv7` and `debugserver-8.1-arm64`.

	$ scp debugserver-8.1-arm64 root@192.168.1.35:.

Meanwhile in the iDevice:

	# ./debugserver-8.1-armv7 *:1234 -a Calculator

In the host run the following lines:

	$ lldb
	(lldb) platform select remote-ios
	(lldb) process connect connect://192.168.1.35:1234

Final notes
-----------

Note that the LLDB disassembler misses a *LOT* of instructions, so I would recommend using `radare2`, `r2pipe` or `lldb-capstone-arm`:

https://github.com/upbit/lldb-capstone-arm

Enjoy
