#ifndef JAILBREAK_H
#define JAILBREAK_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach/mach.h>

// Sandbox escape
bool escape_sandbox(void);

// Spawn a process as uid 0 (requires platformization)
pid_t spawn_as_root(const char *path, const char *args[], const char *envp[]);
int spawn_and_wait(const char *path, const char *args[]);

// Remount /private/preboot as read-write
bool remount_private_preboot(void);

// Trust cache loading
typedef struct {
    uint32_t version;
    uint32_t count;
    uint8_t  entries[];
} __attribute__((packed)) trust_cache_t;

bool load_trust_cache(const char *tc_path);
bool load_trust_cache_from_data(void *data, size_t len);

// Bootstrap installation
bool install_bootstrap(void);
bool setup_symlinks(void);
bool install_sileo(void);

// Shell (iDownload-like)
void start_shell(uint16_t port);

#endif
