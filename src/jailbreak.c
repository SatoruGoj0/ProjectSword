#include "jailbreak.h"
#include "offsets.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <spawn.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <mach-o/dyld.h>

extern uint64_t kread64(uint64_t addr);
extern void kwrite64(uint64_t addr, uint64_t val);
extern uint32_t kread32(uint64_t addr);
extern void kwrite32(uint64_t addr, uint32_t val);
extern uint64_t kread_ptr(uint64_t addr);
extern bool kread_buf(uint64_t addr, void *buf, size_t len);
extern void kwrite_buf(uint64_t addr, const void *buf, size_t len);
extern bool platformize_proc(void);

// Forward declarations
static int mkdir_p(const char *path, mode_t mode);

// Posix spawn persona attributes (private API)
typedef int (*posix_spawnattr_set_persona_np_t)(posix_spawnattr_t *, int, uint32_t);
typedef int (*posix_spawnattr_set_persona_uid_np_t)(posix_spawnattr_t *, uid_t);
typedef int (*posix_spawnattr_set_persona_gid_np_t)(posix_spawnattr_t *, gid_t);

static posix_spawnattr_set_persona_np_t _pspn = NULL;
static posix_spawnattr_set_persona_uid_np_t _pspu = NULL;
static posix_spawnattr_set_persona_gid_np_t _pspg = NULL;

static bool resolve_persona_symbols(void) {
    _pspn = (posix_spawnattr_set_persona_np_t)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_np");
    _pspu = (posix_spawnattr_set_persona_uid_np_t)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_uid_np");
    _pspg = (posix_spawnattr_set_persona_gid_np_t)dlsym(RTLD_DEFAULT, "posix_spawnattr_set_persona_gid_np");
    return _pspn && _pspu && _pspg;
}

bool escape_sandbox(void) {
    // On iOS 18, sandbox escape requires platformization first.
    // After TF_PLATFORM is set, we can use posix_spawnattr_set_persona_np
    // to spawn processes as uid 0 outside the sandbox.
    
    if (!platformize_proc()) {
        printf("[-] platformize failed\n");
        return false;
    }
    
    if (!resolve_persona_symbols()) {
        printf("[-] cannot resolve persona symbols\n");
        return false;
    }
    
    printf("[+] Sandbox escape ready (platform + persona APIs available)\n");
    return true;
}

pid_t spawn_as_root(const char *path, const char *args[], const char *envp[]) {
    if (!_pspn) resolve_persona_symbols();
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    
    // Persona 99 = root, no sandbox
    _pspn(&attr, 99, 1);
    _pspu(&attr, 0);
    _pspg(&attr, 0);
    
    // Use posix_spawnp so PATH is searched
    pid_t pid;
    int ret = posix_spawnp(&pid, path, NULL, &attr, (char *const *)args, (char *const *)envp);
    posix_spawnattr_destroy(&attr);
    
    if (ret != 0) {
        printf("[-] spawn_as_root(%s): %s\n", path, strerror(ret));
        return -1;
    }
    return pid;
}

int spawn_and_wait(const char *path, const char *args[]) {
    pid_t pid = spawn_as_root(path, args, NULL);
    if (pid <= 0) return -1;
    
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool remount_private_preboot(void) {
    // /private/preboot is mounted as a firmware volume, read-only
    // We need to remount it r/w using mount() syscall with MNT_UPDATE
    
    int ret = mount("apfs", "/private/preboot", MNT_UPDATE, NULL);
    if (ret != 0) {
        printf("[-] mount -u /private/preboot failed: %s\n", strerror(errno));
        // Try as root via spawn
        const char *args[] = {"mount", "-u", "/private/preboot", NULL};
        ret = spawn_and_wait("/sbin/mount", args);
        if (ret != 0) {
            printf("[-] mount via spawn failed: %d\n", ret);
            return false;
        }
    }
    
    printf("[+] /private/preboot remounted r/w\n");
    return true;
}

// Trust cache loading via kernel R/W
// The KC_CONVERT_AMFI_CDHASH syscall or direct kernel tcload

// On iOS 15+, the trust cache is managed by the kernel's amfi.kext
// We can add entries directly via kernel R/W:
// 1. Find the trust cache head in kernel memory
// 2. Allocate new entry in kernel zone
// 3. Link it into the chain

static bool kalloc_filled(uint64_t *out, size_t size, const void *data) {
    // Use OOL_ports or OSObject allocation via IOSurface
    // For simplicity, use mach_vm_allocate in kernel zone
    // Actually use OOL message allocation for kalloc
    // This is a placeholder - full implementation requires zone allocation
    
    // We can allocate kernel memory via mach message OOL descriptors
    // OOL descriptors with size < 0x1000 go to kalloc zone
    
    kern_return_t ret;
    
    // Use host special port 4 (kernel task) for mach_vm_allocate
    // But we need the kernel_task port first
    // Alternative: use kalloc via OSObject::operator new() instance
    // through IOSurface subclasses
    
    // For now, we allocate kernel memory by exploiting OOL_ports
    // Each OOL_ports message allocates kalloc.(size) zones
    
    // Simplified: use small OOL messages to allocate in kalloc.4096
    // then write our TC data via kread/kwrite
    
    uint64_t kaddr = 0;
    
    // Use IOSurface buffer allocation in kernel
    // IOSurface buffers use kalloc
    
    // Strategy: allocate a kalloc.4096 via IOSurface
    // IOSurfaceCreate with allocationSize=4096 gives us an array
    // We can then leak the kernel address via IOSurface methods
    
    // For now, return 0 (caller handles)
    (void)data;
    (void)size;
    
    return false;
}

bool load_trust_cache_from_data(void *data, size_t len) {
    // Approach: Find the amfi trust cache entries list
    // The trust cache entries are stored as a linked list in amfi.kext
    // We add our entry by modifying the list
    
    // Step 1: Find amfi trust cache structures in kernel
    // Use known symbol patterns to find tc_entries
    
    // Step 2: Allocate kernel memory for new TC entry
    // Each TC entry is trust_cache_t + cdhash entries
    
    // Step 3: Write entry data and link into list
    
    // Full implementation requires:
    // - Kernel zone allocation mechanism
    // - amfi symbol scanning
    
    // For physical R/W based approach, we could instead:
    // 1. Write TC data to physical page
    // 2. Map it into amfi's address space via pmap
    
    printf("[*] Trust cache load from data: %zu bytes\n", len);
    (void)data;
    
    // For now, return false (requires full zone allocator)
    return false;
}

bool load_trust_cache(const char *tc_path) {
    printf("[*] Loading trust cache: %s\n", tc_path);
    
    int fd = open(tc_path, O_RDONLY);
    if (fd < 0) {
        printf("[-] Cannot open trust cache: %s\n", tc_path);
        return false;
    }
    
    struct stat st;
    fstat(fd, &st);
    
    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (data == MAP_FAILED) {
        printf("[-] mmap failed: %s\n", strerror(errno));
        return false;
    }
    
    bool ret = load_trust_cache_from_data(data, st.st_size);
    munmap(data, st.st_size);
    return ret;
}

static const char *jb_path = "/private/preboot/jb";
static const char *jb_var = "/var/jb";

bool install_bootstrap(void) {
    printf("[*] Installing bootstrap to %s\n", jb_path);
    
    // 1. Create JB directory
    struct stat st;
    if (stat(jb_path, &st) != 0) {
        if (mkdir_p(jb_path, 0755) != 0) {
            printf("[-] mkdir %s failed: %s\n", jb_path, strerror(errno));
            return false;
        }
    }
    
    // 2. Extract bootstrap.tar
    // The bootstrap.tar is embedded in the app bundle
    // Get path to our executable
    char self_path[4096] = {};
    uint32_t size = sizeof(self_path);
    if (_NSGetExecutablePath(self_path, &size) != 0) return false;
    
    // Derive app bundle path
    char *slash = strrchr(self_path, '/');
    if (!slash) return false;
    *slash = 0;
    
    char tar_path[4096] = {};
    snprintf(tar_path, sizeof(tar_path), "%s/bootstrap.tar", self_path);
    
    if (stat(tar_path, &st) != 0) {
        printf("[-] bootstrap.tar not found at %s\n", tar_path);
        return false;
    }
    
    // Extract using tar (spawned as root)
    const char *argv[] = {
        "tar",
        "--preserve-permissions",
        "-xkf",
        tar_path,
        "-C",
        jb_path,
        NULL
    };
    
    int ret = spawn_and_wait("/usr/bin/tar", argv);
    if (ret != 0) {
        printf("[-] tar extraction failed: %d\n", ret);
        return false;
    }
    
    printf("[+] Bootstrap extracted to %s\n", jb_path);
    
    // 3. Create /var/jb symlink
    setup_symlinks();
    
    // 4. Load trust caches from bootstrap
    char tc_path[4096] = {};
    snprintf(tc_path, sizeof(tc_path), "%s/TrustCache", jb_path);
    if (stat(tc_path, &st) == 0) {
        load_trust_cache(tc_path);
    }
    
    return true;
}

bool setup_symlinks(void) {
    unlink(jb_var);
    if (symlink(jb_path, jb_var) != 0) {
        printf("[-] symlink %s -> %s failed: %s\n", jb_var, jb_path, strerror(errno));
        return false;
    }
    printf("[+] %s -> %s\n", jb_var, jb_path);
    return true;
}

bool install_sileo(void) {
    printf("[*] Installing Sileo\n");
    
    char sileo_path[4096] = {};
    char uicache_path[4096] = {};
    
    // Sileo.app comes from bootstrap
    snprintf(sileo_path, sizeof(sileo_path), "%s/Applications/Sileo.app", jb_path);
    
    struct stat st;
    if (stat(sileo_path, &st) != 0) {
        printf("[-] Sileo.app not found at %s\n", sileo_path);
        return false;
    }
    
    snprintf(uicache_path, sizeof(uicache_path), "%s/usr/bin/uicache", jb_path);
    
    const char *args[] = {
        "uicache",
        "-p",
        sileo_path,
        NULL
    };
    
    int ret;
    if (stat(uicache_path, &st) == 0) {
        ret = spawn_and_wait(uicache_path, args);
    } else {
        // Use system uicache
        ret = spawn_and_wait("/usr/bin/uicache", args);
    }
    
    if (ret != 0) {
        printf("[-] uicache failed: %d\n", ret);
        return false;
    }
    
    printf("[+] Sileo installed and registered with uicache\n");
    return true;
}

// Helper: mkdir -p
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[4096] = {};
    strncpy(tmp, path, sizeof(tmp) - 1);
    
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    return mkdir(tmp, mode);
}
