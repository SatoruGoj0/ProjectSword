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
├── src/                   # Exploit chain + post-exploitation
│   ├── main.m             # DarkSword ICMP6 UAF + kernel R/W primitives
│   ├── physrw.c/h         # Physical R/W via IODMACommand (Fugu18 port)
│   ├── util.c/h           # PPL bypass, platformize, proc/task finder
│   ├── gadgets.c/h        # Runtime kernel gadget scanner
│   ├── asm.S              # PAC bypass thread handler + PPL assembly
│   ├── jailbreak.c/h      # Sandbox escape, tcload, bootstrap, Sileo
│   ├── shell.c/h          # TCP command shell (port 1337)
│   └── offsets.h          # Verified struct offsets for xnu-11215.62.3
├── .github/workflows/     # CI/CD: GitHub Actions macOS runner
├── scripts/               # Bootstrap download helper
├── bootstrap.tar          # Procursus bootstrap (Git LFS; committed by user)
├── Makefile               # Build system
├── Info.plist
└── entitlements.plist     # IOKit + security entitlements
```

## Requirements

- **macOS 14+** with **Xcode 15.4+** (iOS 18.0 SDK)
- **Homebrew** (for ldid)
- Sideloading tool (AltStore, Sideloadly, TrollStore) for IPA install
- Developer-signed embedded.mobileprovision for on-device deployment

## Build

### 1. Get the bootstrap (optional, for full bootstrap install)

```bash
git clone https://github.com/ibrahimatmorphis/ProjectSword.git
cd ProjectSword

# Option A — download via script
./scripts/get-bootstrap.sh

# Option B — download manually from:
#   https://github.com/ProcursusTeam/Procursus/releases
#   (get bootstrap-iphoneos-arm64e-rootless.tar.xz, extract to bootstrap.tar)

# Commit with Git LFS
git lfs track ios18-research/ProjectSword/bootstrap.tar
git add ios18-research/ProjectSword/bootstrap.tar .gitattributes
git commit -m "Add Procursus bootstrap"
git push
```

### 2. Build IPA

```bash
# Local build
cd ios18-research/ProjectSword
make ipa

# Output: ios18-research/ProjectSword/ProjectSword.ipa
```

### Via CI (GitHub Actions)

Push `bootstrap.tar` to the repo (with Git LFS), then push any branch — the workflow builds automatically. Download the IPA from **Actions** tab → workflow run → **Artifacts**.

Trigger a release build:
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
