BUNDLE := com.m1zole.kfd

.PHONY: all clean

all: clean
	#$(MAKE) -C amfidebilitate clean all
	#cd Taurine/resources && tar -xf basebinaries.tar
	#rm -f Taurine/resources/{amfidebilitate,basebinaries.tar}
	#cp {amfidebilitate}/bin/* Taurine/resources
	#cd Taurine/resources && tar -cf basebinaries.tar amfidebilitate jailbreakd jbexec pspawn_payload-stg2.dylib pspawn_payload.dylib
	#rm -f Taurine/resources/{amfidebilitate,jailbreakd,jbexec,*.dylib}
	xcodebuild clean build CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO PRODUCT_BUNDLE_IDENTIFIER="$(BUNDLE)" -sdk iphoneos -scheme kfd -configuration Debug -derivedDataPath build
	ln -sf build/Build/Products/Debug-iphoneos Payload
	rm -rf Payload/kfd.app/Frameworks
	ldid -Sfastpath.entitlements build/Build/Products/Debug-iphoneos/kfd.app/kfd
	ldid -s build/Build/Products/Debug-iphoneos/kfd.app
	zip -r9 kfd.ipa Payload/kfd.app

clean:
	rm -rf build Payload kfd.ipa
