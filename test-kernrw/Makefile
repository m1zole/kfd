TARGET  = test-kernrw
OUTDIR ?= bin

CODESIGN = /usr/local/bin/ldid -SEnt.plist
CXX       = xcrun -sdk iphoneos clang++ -arch arm64 -std=c++11

CFLAGS  = -Wall -Iinclude -I.

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG
else
    CFLAGS += -O2 -fvisibility=hidden
    CFLAGS += -DVERSION_COMMIT_COUNT='"The people who are crazy enough to think they can change the world are the ones who do"'
    CFLAGS += -DVERSION_COMMIT_SHA='"I Used To Be An Adventurer Like You, Then I Took An Arrow In The Knee."'
endif

CFLAGS += -DCUSTOM_LOGGING="\"serial_log.h\""
CXXFLAGS += -DCUSTOM_LOGGING="\"serial_log.h\""

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): main.mm KernelRW.cpp libgeneral_exception.cpp | $(OUTDIR)
	$(CXX) -o $@ $^ $(CFLAGS) -framework IOKit -framework Foundation -framework UIKit
	strip $@
	$(CODESIGN) $@
	cp bin/test-kernrw ../binaries
	rm ../binaries/binaries.tc
	trustcache create ../binaries/binaries.tc ../binaries
	find .. -type f -name '.*' -delete

clean:
	rm -f $(OUTDIR)/$(TARGET) $(OUTDIR)/$(TARGET).gz
