#include "shell.h"
#include "offsets.h"
#include "util.h"
#include "jailbreak.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

extern uint64_t kread64(uint64_t addr);
extern void kwrite64(uint64_t addr, uint64_t val);
extern void kwrite32(uint64_t addr, uint32_t val);
extern uint64_t kread_ptr(uint64_t addr);
extern uint32_t kread32(uint64_t addr);

static int parse_hex(const char *s, uint64_t *out) {
    *out = strtoull(s, NULL, 16);
    return 0;
}

static void handle_command(int fd, const char *cmd_line) {
    char cmd[256] = {};
    strncpy(cmd, cmd_line, sizeof(cmd) - 1);
    
    // Tokenize
    char *argv[32] = {};
    int argc = 0;
    char *tok = strtok(cmd, " \t\n\r");
    while (tok && argc < 32) {
        argv[argc++] = tok;
        tok = strtok(NULL, " \t\n\r");
    }
    
    if (argc == 0) return;
    
    char reply[4096] = {};
    
    if (strcmp(argv[0], "help") == 0) {
        snprintf(reply, sizeof(reply),
            "Available commands:\n"
            "  r64 <addr>              Read 8 bytes from kernel address\n"
            "  r32 <addr>              Read 4 bytes from kernel address\n"
            "  w64 <addr> <val>        Write 8 bytes to kernel address\n"
            "  w32 <addr> <val>        Write 4 bytes to kernel address\n"
            "  kcall <func> <a1..a8>   Call kernel function (if PAC bypass available)\n"
            "  tcload <path>           Load a TrustCache file\n"
            "  mount                   Remount /private/preboot as r/w\n"
            "  bootstrap               Install Procursus bootstrap\n"
            "  sileo                   Install Sileo package manager\n"
            "  platformize             Make this process a platform binary\n"
            "  exit                    Exit shell\n"
        );
    }
    else if (strcmp(argv[0], "r64") == 0 && argc >= 2) {
        uint64_t addr; parse_hex(argv[1], &addr);
        uint64_t val = kread64(addr);
        snprintf(reply, sizeof(reply), "0x%llx: 0x%016llx\n", addr, val);
    }
    else if (strcmp(argv[0], "r32") == 0 && argc >= 2) {
        uint64_t addr; parse_hex(argv[1], &addr);
        uint32_t val = kread32(addr);
        snprintf(reply, sizeof(reply), "0x%llx: 0x%08x\n", addr, val);
    }
    else if (strcmp(argv[0], "w64") == 0 && argc >= 3) {
        uint64_t addr, val;
        parse_hex(argv[1], &addr); parse_hex(argv[2], &val);
        kwrite64(addr, val);
        snprintf(reply, sizeof(reply), "0x%llx <- 0x%016llx\n", addr, val);
    }
    else if (strcmp(argv[0], "w32") == 0 && argc >= 3) {
        uint64_t addr, val;
        parse_hex(argv[1], &addr); parse_hex(argv[2], &val);
        kwrite32(addr, (uint32_t)val);
        snprintf(reply, sizeof(reply), "0x%llx <- 0x%08x\n", addr, (uint32_t)val);
    }
    else if (strcmp(argv[0], "tcload") == 0 && argc >= 2) {
        bool ok = load_trust_cache(argv[1]);
        snprintf(reply, sizeof(reply), "tcload: %s\n", ok ? "OK" : "FAILED");
    }
    else if (strcmp(argv[0], "mount") == 0) {
        bool ok = remount_private_preboot();
        snprintf(reply, sizeof(reply), "remount: %s\n", ok ? "OK" : "FAILED");
    }
    else if (strcmp(argv[0], "bootstrap") == 0) {
        bool ok = install_bootstrap();
        snprintf(reply, sizeof(reply), "bootstrap: %s\n", ok ? "OK" : "FAILED");
    }
    else if (strcmp(argv[0], "sileo") == 0) {
        bool ok = install_sileo();
        snprintf(reply, sizeof(reply), "sileo: %s\n", ok ? "OK" : "FAILED");
    }
    else if (strcmp(argv[0], "platformize") == 0) {
        bool ok = platformize_proc();
        snprintf(reply, sizeof(reply), "platformize: %s\n", ok ? "OK" : "FAILED");
    }
    else {
        snprintf(reply, sizeof(reply), "Unknown command: %s\n", argv[0]);
    }
    
    write(fd, reply, strlen(reply));
}

static void *shell_thread(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    char buf[4096] = {};
    
    const char *banner =
        "ProjectSword iDownload Shell\n"
        "Type 'help' for available commands\n\n";
    write(client_fd, banner, strlen(banner));
    
    while (1) {
        write(client_fd, "PS> ", 4);
        int n = (int)read(client_fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        handle_command(client_fd, buf);
    }
    close(client_fd);
    return NULL;
}

void start_shell(uint16_t port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return; }
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { INADDR_LOOPBACK }
    };
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(server_fd); return;
    }
    
    listen(server_fd, 5);
    printf("[*] Shell listening on 127.0.0.1:%d\n", port);
    
    while (1) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) continue;
        pthread_t th;
        pthread_create(&th, NULL, shell_thread, (void*)(intptr_t)client);
        pthread_detach(th);
    }
}
