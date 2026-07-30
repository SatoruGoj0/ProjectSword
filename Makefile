TARGET = ProjectSword
CC = clang

# CI flag — set CI=1 on GitHub Actions runners (both branches do same thing now)
SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ISYSROOT := -isysroot $(SDK_PATH)

# Lite mode — strip private entitlements for regular developer signing
#   make LITE=1 ipa   → uses entitlements.lite.plist (installs but won't exploit)
#   make ipa          → uses entitlements.plist (needs TrollStore)
ENTITLEMENTS_FILE = $(if $(LITE),entitlements.lite.plist,entitlements.plist)

CFLAGS = -framework Foundation \
         -framework UIKit \
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

OBJECTS = src/main.o src/AppDelegate.o src/physrw.o src/util.o src/gadgets.o src/asm.o src/jailbreak.o src/shell.o

all: $(TARGET)

sign: $(TARGET)
	ldid -S$(ENTITLEMENTS_FILE) $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

src/AppDelegate.o: src/AppDelegate.m src/AppDelegate.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/main.o: src/main.m src/offsets.h src/physrw.h src/util.h src/gadgets.h src/jailbreak.h src/shell.h src/AppDelegate.h
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
	cp $(ENTITLEMENTS_FILE) Payload/ProjectSword.app/
	if [ -f bootstrap.tar ]; then cp bootstrap.tar Payload/ProjectSword.app/; echo "[+] bootstrap.tar bundled in IPA"; fi
ifneq ($(SIGN),0)
	ldid -S$(ENTITLEMENTS_FILE) Payload/ProjectSword.app/$(TARGET)
	@echo "[+] Signed with ldid using $(ENTITLEMENTS_FILE)"
endif
ifneq ($(wildcard embedded.mobileprovision),)
	cp embedded.mobileprovision Payload/ProjectSword.app/
	@echo "[+] Provisioning profile bundled"
endif
	zip -r ProjectSword.ipa Payload/
	rm -rf Payload
	@echo "[+] IPA: ProjectSword.ipa"
	@echo "[+] Entitlements: $(ENTITLEMENTS_FILE)"

.PHONY: all clean sign ipa
