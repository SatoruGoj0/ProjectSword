# ProjectSword — iOS 18.2.1 Jailbreak (iPhone 12 / A14)

An iOS 18.2.1 (build 22C161) jailbreak for iPhone 12 (iPhone13,2, A14) using a 5-phase exploit chain:

| Phase | Technique | Target |
|-------|-----------|--------|
| 1 | **DarkSword** ICMP6 socket UAF | Kernel R/W (kread64/kwrite64) |
| 2 | **Gadget scanner** | Runtime kernel gadget resolution |
| 3 | **IOBufferMemoryDescriptor + IODMACommand** | Physical R/W primitive |
| 4 | **PPL bypass** via physical R/W | Platformize (TF_PLATFORM) |
| 5 | **Sandbox escape** via posix_spawn persona 99 | uid 0, no sandbox → bootstrap + Sileo |

## Architecture

```
ProjectSword/
├── src/
│   ├── main.m          # DarkSword exploit + orchestrator + kernel R/W primitives
│   ├── physrw.c/h      # Physical R/W via DMA (ported from Fugu18)
│   ├── util.c/h        # PPL bypass, platformize, proc finder
│   ├── gadgets.c/h     # Runtime kernel gadget scanner
│   ├── asm.S           # PAC bypass thread handler + PPL assembly
│   ├── jailbreak.c/h   # Sandbox escape, tcload, bootstrap, Sileo install
│   ├── shell.c/h       # TCP command shell (iDownload-like, port 1337)
│   └── offsets.h       # Verified struct offsets for xnu-11215.62.3
├── .github/workflows/  # CI/CD pipeline (GitHub Actions)
├── scripts/            # Bootstrap downloader, env setup
├── Makefile            # Build system
├── Info.plist          # Bundle configuration
└── entitlements.plist  # Required IOKit/security entitlements
```

## Requirements

- **macOS 14+** with **Xcode 15.4+** (iOS 18.0 SDK)
- **Homebrew** (for ldid)
- A jailbroken iDevice or sideloading tool (AltStore, Sideloadly, TrollStore)
- Developer-signed embedded.mobileprovision for on-device deployment

## Build

### Locally

```bash
git clone https://github.com/ibrahimatmorphis/ProjectSword.git
cd ProjectSword

# Install deps
brew install ldid

# Download Procursus bootstrap (optional, for full bootstrap install)
./scripts/download-bootstrap.sh

# Build IPA
cd ios18-research/ProjectSword
make ipa
```

The IPA will be at `ios18-research/ProjectSword/ProjectSword.ipa`.

### Via CI (GitHub Actions)

Push to any branch — the workflow builds automatically. Download the IPA from the **Actions** tab → workflow run → **Artifacts**.

To trigger a release build with auto-published IPA:
```bash
gh workflow run build.yml -f release=true
```

## Usage

1. Install the IPA via AltStore / Sideloadly / TrollStore
2. Launch ProjectSword
3. The exploit runs automatically through all 5 phases
4. After completion, an **iDownload-like shell** starts on **127.0.0.1:1337**

Connect to the shell:
```bash
nc 127.0.0.1 1337
```

### Shell Commands

| Command | Description |
|---------|-------------|
| `r64 <addr>` | Read 8 bytes from kernel address |
| `r32 <addr>` | Read 4 bytes from kernel address |
| `w64 <addr> <val>` | Write 8 bytes to kernel address |
| `w32 <addr> <val>` | Write 4 bytes to kernel address |
| `tcload <path>` | Load a trust cache file |
| `mount` | Remount /private/preboot as r/w |
| `bootstrap` | Install Procursus bootstrap |
| `sileo` | Register Sileo package manager |
| `platformize` | Make current process a platform binary |
| `help` | Show available commands |
| `exit` | Exit shell |

## Supported Devices

| Device | SoC | Notes |
|--------|-----|-------|
| iPhone 12 | A14 (T8101) | **Primary target** — verified offsets |

**SPTM not applicable**: A14 uses PPL (not SPTM), making this architecture uniquely viable.

## Credits

- **Fugu18**: oobPCI, breakCFI, physrw, bootstrap/Sileo flow
- **DarkSword**: ICMP6 socket UAF kernel exploit
- **Procursus Team**: Bootstrap infrastructure
- **iOS 18.2.1 kernel**: xnu-11215.62.3/RELEASE_ARM64_T8101

## License

MIT
