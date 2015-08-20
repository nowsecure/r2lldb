OSXDBGS=/Applications/Xcode.app/Contents//SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver
SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport
DISKIMG=/Volumes/DeveloperDiskImage

all:
	@echo
	@echo "make ls                    # list all available versions"
	@echo "make debugserver IOS=8.1   # build debugserver for iOS 8.1"
	@echo

ios ls:
	@cd $(SDKROOT) ; ls

check:
	@if [ -z "$(IOS)" ]; then echo "IOS=xxx required" ; false ; fi

debugserver: check
	hdiutil detach $(DISKIMG) || true
	hdiutil attach $(SDKROOT)/$(IOS)*/DeveloperDiskImage.dmg
	cp $(DISKIMG)/usr/bin/debugserver .
	codesign -s - --entitlements entitlements.plist -f debugserver
	lipo -extract armv7 debugserver -o debugserver-$(IOS)-armv7
	lipo -extract arm64 debugserver -o debugserver-$(IOS)-arm64
	rm debugserver
	hdiutil detach $(DISKIMG)
	$(MAKE) debugserver-x86_64

debugserver-x86_64:
	cp -f $(OSXDBGS) debugserver-x86_64
