TARGET = ProjectSword
CC = clang

SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ISYSROOT := -isysroot $(SDK_PATH)

# Lite mode strips private entitlements — works with any developer cert
# Full mode needs TrollStore (platform-application + private entitlements)
ENTITLEMENTS_FILE = $(if $(LITE),entitlements.lite.plist,entitlements.plist)

# Always link Foundation, UIKit, Security — needed regardless of mode
LINK_FRAMEWORKS = -framework Foundation -framework UIKit -framework Security -framework CoreServices

# Always link IOSurface/IOKit — lite build tries IOSurface and falls back
# to pure Mach VM if the entitlement is unavailable at runtime
LINK_FRAMEWORKS += -framework IOSurface -framework IOKit -framework CoreGraphics -framework ImageIO

CFLAGS = $(LINK_FRAMEWORKS) \
         -I./src \
         $(ISYSROOT) \
         -arch arm64 \
         -arch arm64e \
         -Wno-availability \
         -miphoneos-version-min=18.0 \
         -fobjc-arc

# Only the files we actually need
OBJECTS = src/main.o src/AppDelegate.o src/shell.o src/phase6.o

all: $(TARGET)

sign: $(TARGET)
	ldid -S$(ENTITLEMENTS_FILE) $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

src/AppDelegate.o: src/AppDelegate.m src/AppDelegate.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/main.o: src/main.m src/offsets.h src/shell.h src/AppDelegate.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/phase6.o: src/phase6.m src/phase6.h src/offsets.h
	$(CC) $(CFLAGS) -c -o $@ $<

src/shell.o: src/shell.c src/shell.h src/offsets.h src/jailbreak.h
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
	if [ -f version.txt ]; then cp version.txt Payload/ProjectSword.app/; fi
	if [ -f bootstrap.tar ]; then cp bootstrap.tar Payload/ProjectSword.app/; fi
	if [ -f TrustCache ]; then cp TrustCache Payload/ProjectSword.app/; fi
	if [ -f sileo.deb ]; then cp sileo.deb Payload/ProjectSword.app/; fi
	if [ -f sileo.tar ]; then cp sileo.tar Payload/ProjectSword.app/; fi
ifneq ($(SIGN),0)
	ldid -S$(ENTITLEMENTS_FILE) Payload/ProjectSword.app/$(TARGET)
	@echo "[+] Signed with ldid using $(ENTITLEMENTS_FILE)"
endif
ifneq ($(wildcard embedded.mobileprovision),)
	cp embedded.mobileprovision Payload/ProjectSword.app/
endif
	zip -r ProjectSword.ipa Payload/
	rm -rf Payload
	@echo "[+] IPA: ProjectSword.ipa"
	@echo "[+] Entitlements: $(ENTITLEMENTS_FILE)"

.PHONY: all clean sign ipa
