#ifndef JAILBREAK_H
#define JAILBREAK_H

#include <stdint.h>
#include <stdbool.h>

// Sandbox escape via MAC label manipulation
bool escape_sandbox(void);

// Bootstrap installation
bool install_bootstrap(void);
bool install_sileo(void);

// Trust cache (placeholder - needs TC injection implementation)
bool load_trust_cache(const char *path);

// Remount /private/preboot
bool remount_private_preboot(void);

#endif
