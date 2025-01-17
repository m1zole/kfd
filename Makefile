BUNDLE := com.m1zole.kfd

.PHONY: all clean

all: clean
	xcodebuild clean build CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO PRODUCT_BUNDLE_IDENTIFIER="$(BUNDLE)" -sdk iphoneos -scheme kfd -configuration Debug -derivedDataPath build
	ln -sf build/Build/Products/Debug-iphoneos Payload
	rm -rf Payload/kfd.app/Frameworks
	zip -r9 kfd.ipa Payload/kfd.app

clean:
	rm -rf build Payload kfd.ipa
