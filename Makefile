TARGET = ProjectSword
CC = clang

# CI flag — set CI=1 on GitHub Actions runners
ifneq ($(CI),1)
# Local macOS: get SDK path dynamically
SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ISYSROOT := -isysroot $(SDK_PATH)
else
# CI runner: Xcode is installed at standard path
SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ISYSROOT := -isysroot $(SDK_PATH)
endif

CFLAGS = -framework Foundation \
         -framework CoreServices \
         -framework IOSurface \
         -framework IOKit \
         -framework Security \
         -I./src \
         $(ISYSROOT) \
         -arch arm64 \
         -arch arm64e \
         -Wno-availability \
         -miphoneos-version-min=18.0 \
         -fobjc-arc

OBJECTS = src/main.o src/physrw.o src/util.o src/gadgets.o src/asm.o src/jailbreak.o src/shell.o

all: $(TARGET)

sign: $(TARGET)
	ldid -Sentitlements.plist $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

src/main.o: src/main.m src/offsets.h src/physrw.h src/util.h src/gadgets.h src/jailbreak.h src/shell.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/physrw.o: src/physrw.c src/physrw.h src/offsets.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/util.o: src/util.c src/util.h src/offsets.h src/physrw.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/gadgets.o: src/gadgets.c src/gadgets.h src/offsets.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/asm.o: src/asm.S
	$(CC) $(CFLAGS) -c -o $@ $<

src/jailbreak.o: src/jailbreak.c src/jailbreak.h src/offsets.h src/util.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/shell.o: src/shell.c src/shell.h src/offsets.h src/util.h src/jailbreak.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) src/*.o
	rm -rf Payload
	rm -f ProjectSword.ipa

ipa: $(TARGET)
	mkdir -p Payload/ProjectSword.app
	cp $(TARGET) Payload/ProjectSword.app/
	cp Info.plist Payload/ProjectSword.app/
	cp entitlements.plist Payload/ProjectSword.app/
	if [ -f bootstrap.tar ]; then cp bootstrap.tar Payload/ProjectSword.app/; echo "[+] bootstrap.tar bundled in IPA"; fi
ifneq ($(SIGN),0)
	ldid -Sentitlements.plist Payload/ProjectSword.app/$(TARGET) 2>/dev/null || echo "[-] ldid not available, IPA will need manual signing"
endif
	cd Payload && zip -r ../ProjectSword.ipa ProjectSword.app/
	rm -rf Payload
	@echo "[+] IPA: ProjectSword.ipa"

.PHONY: all clean sign ipa
