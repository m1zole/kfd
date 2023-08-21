TARGET = jailbreakd

CC = clang++

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I./src/_shared -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -miphoneos-version-min=15.0 -fobjc-arc -Wno-nullability-completeness-on-arrays -O3
LDFLAGS = -lbsm 

sign: $(TARGET)
	@ldid -Sentitlements.plist $<
	cp jailbreakd ../../binaries
	cp daemon.plist ../../binaries/kr.h4ck.jailbreakd.plist
	rm ../../binaries/binaries.tc
	trustcache create ../../binaries/binaries.tc ../../binaries
	find ../.. -type f -name '.*' -delete

# $(TARGET): $(wildcard src/*.m src/*.S src/machoparse/*.c)
# 	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(TARGET): $(wildcard src/server.m)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
