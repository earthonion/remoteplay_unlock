#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "io.h"
#include "patches.h"
#include "self.h"

#define REMOTEPLAY_PATH "/system/vsh/app/NPXS40102/eboot.bin"
#define EXPORT_DIR "/mnt/usb0/rp_prohibit"
#define OFFSETS_JSON EXPORT_DIR "/rp_prohibit_offsets.json"

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static void notify(const char *fmt, ...) {
    notify_request_t req;
    va_list ap;

    memset(&req, 0, sizeof(req));
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static pid_t find_pid(const char *name) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t size;
    uint8_t *buf;
    pid_t result = -1;

    if(sysctl(mib, 4, NULL, &size, NULL, 0)) {
        return -1;
    }
    if(!(buf=malloc(size))) {
        return -1;
    }
    if(sysctl(mib, 4, buf, &size, NULL, 0)) {
        free(buf);
        return -1;
    }

    for(uint8_t *ptr=buf; ptr<buf+size;) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;

        ptr += ki->ki_structsize;
        if(!strcmp(ki->ki_comm, name)) {
            result = ki->ki_pid;
            break;
        }
    }

    free(buf);
    return result;
}

static int do_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    return (int)__syscall(SYS_ptrace, request, pid, addr, data);
}

static int ptrace_attach(pid_t pid) {
    if(do_ptrace(PT_ATTACH, pid, 0, 0)) {
        return -1;
    }
    if(waitpid(pid, 0, 0) < 0) {
        do_ptrace(PT_DETACH, pid, 0, 0);
        return -1;
    }
    return 0;
}

static int ptrace_write(pid_t pid, intptr_t addr, const void *buf, size_t size) {
    struct ptrace_io_desc iod = {
        .piod_op = PIOD_WRITE_D,
        .piod_offs = (void *)addr,
        .piod_addr = (void *)buf,
        .piod_len = size,
    };

    return do_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static int write_bytes(pid_t pid, intptr_t addr, const uint8_t *bytes, size_t size) {
    intptr_t page = addr & ~(intptr_t)(PAGE_SIZE - 1);
    uint8_t verify[4];
    int prot = kernel_get_vmem_protection(pid, page, PAGE_SIZE);
    int err;
    int saved_errno;

    if(prot < 0) {
        puts("kernel_get_vmem_protection failed");
        return -1;
    }
    if(kernel_set_vmem_protection(pid, page, PAGE_SIZE,
                                  prot | PROT_READ | PROT_WRITE | PROT_EXEC)) {
        puts("kernel_set_vmem_protection(RWX) failed");
        return -1;
    }

    errno = 0;
    err = ptrace_write(pid, addr, bytes, size);
    saved_errno = errno;
    if(kernel_set_vmem_protection(pid, page, PAGE_SIZE, prot)) {
        puts("kernel_set_vmem_protection(restore) failed");
        return -1;
    }
    if(err) {
        printf("ptrace PT_IO write failed: errno=%d (%s)\n",
               saved_errno, strerror(saved_errno));
        return -1;
    }
    if(mdbg_copyout(pid, addr, verify, size)) {
        puts("Patch verification read failed");
        return -1;
    }
    if(memcmp(verify, bytes, size)) {
        puts("Patch verification mismatch");
        return -1;
    }

    return 0;
}

static int apply_patches(pid_t pid, intptr_t base) {
#ifdef RESTORE_PATCHES
    const int restoring = 1;
#else
    const int restoring = 0;
#endif
    size_t applied[PATCH_COUNT];
    size_t applied_count = 0;
    int already_patched = 1;
    int failed = 0;

    for(size_t i=0; i<PATCH_COUNT; i++) {
        const patch_t *patch = &patches[i];
        const uint8_t *expected = restoring ? patch->replacement : patch->original;
        const uint8_t *desired = restoring ? patch->original : patch->replacement;
        uint8_t current[4];

        if(mdbg_copyout(pid, base+patch->offset, current, patch->size)) {
            printf("%s: read failed at offset 0x%x\n", patch->name, patch->offset);
            return -1;
        }
        if(!memcmp(current, expected, patch->size)) {
            already_patched = 0;
        } else if(memcmp(current, desired, patch->size)) {
            printf("%s: signature mismatch at offset 0x%x; unsupported build\n",
                   patch->name, patch->offset);
            return -1;
        }
    }

    if(already_patched) {
        puts(restoring ? "Original instructions are already restored" :
                         "RP-Prohibit patches are already applied");
        return 0;
    }
    if(ptrace_attach(pid)) {
        printf("ptrace attach failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    for(size_t i=0; i<PATCH_COUNT; i++) {
        const patch_t *patch = &patches[i];
        const uint8_t *expected = restoring ? patch->replacement : patch->original;
        const uint8_t *desired = restoring ? patch->original : patch->replacement;
        uint8_t current[4];

        if(mdbg_copyout(pid, base+patch->offset, current, patch->size) ||
           memcmp(current, expected, patch->size)) {
            continue;
        }
        if(write_bytes(pid, base+patch->offset, desired, patch->size)) {
            printf("%s: write failed; rolling back\n", patch->name);
            while(applied_count) {
                size_t index = applied[--applied_count];
                const patch_t *rollback = &patches[index];
                const uint8_t *rollback_bytes = restoring ?
                    rollback->replacement : rollback->original;

                if(write_bytes(pid, base+rollback->offset,
                               rollback_bytes, rollback->size)) {
                    printf("%s: rollback failed\n", rollback->name);
                }
            }
            failed = -1;
            break;
        }

        applied[applied_count++] = i;
        printf("%s: %s at offset 0x%x\n", patch->name,
               restoring ? "restored" : "patched", patch->offset);
    }

    if(do_ptrace(PT_DETACH, pid, 0, 0)) {
        printf("ptrace detach failed: errno=%d (%s)\n", errno, strerror(errno));
        failed = -1;
    }
    return failed;
}

#ifdef TESTING_BRANCH
static int export_eboot(uint32_t firmware, char *name, size_t name_size) {
    char destination[256];
    struct stat st;
    int input = -1;
    int output = -1;
    int err = -1;

    if(mkdir(EXPORT_DIR, 0755) && errno != EEXIST) {
        printf("mkdir %s failed: %s\n", EXPORT_DIR, strerror(errno));
        return -1;
    }
    if((input=open(REMOTEPLAY_PATH, O_RDONLY, 0)) < 0) {
        printf("open %s failed: %s\n", REMOTEPLAY_PATH, strerror(errno));
        return -1;
    }
    if(fstat(input, &st)) {
        printf("fstat %s failed: %s\n", REMOTEPLAY_PATH, strerror(errno));
        close(input);
        return -1;
    }

    snprintf(name, name_size, "eboot_%04x.bin", firmware);
    snprintf(destination, sizeof(destination), "%s/%s", EXPORT_DIR, name);
    if((output=open(destination, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
        printf("open %s failed: %s\n", destination, strerror(errno));
        close(input);
        return -1;
    }

    int self = self_is_valid(REMOTEPLAY_PATH);
    if(self > 0) {
        err = self_extract_elf(input, output);
    } else if(!self) {
        err = io_pcopy(input, output, 0, 0, st.st_size);
    }

    close(input);
    if(close(output) && !err) {
        err = -1;
    }
    if(err && errno == EBADMSG) {
        printf("SELF digest mismatch; keeping decrypted eboot %s\n", destination);
        err = 0;
    }
    if(err) {
        printf("Could not export eboot to %s: self=%d errno=%d (%s)\n",
               destination, self, errno, strerror(errno));
        unlink(destination);
        return -1;
    }

    printf("Decrypted eboot exported to %s\n", destination);
    return 0;
}

static int export_eboot_syscore(uint32_t firmware, char *name, size_t name_size) {
    pid_t pid = getpid();
    uint64_t authid = kernel_get_ucred_authid(pid);
    int result;

    if(kernel_set_ucred_authid(pid, 0x4800000000000007l)) {
        puts("Could not set SceSysCore authid for eboot export");
        return -1;
    }
    result = export_eboot(firmware, name, name_size);
    if(kernel_set_ucred_authid(pid, authid)) {
        puts("Could not restore authid after eboot export");
        return -1;
    }
    return result;
}

static int write_offsets_json(uint32_t firmware, int patched, const char *eboot_name) {
    FILE *file = fopen(OFFSETS_JSON, "w");

    if(!file) {
        printf("open %s failed: %s\n", OFFSETS_JSON, strerror(errno));
        return -1;
    }

    fprintf(file, "{\n");
    fprintf(file, "  \"firmware\": \"0x%04x\",\n", firmware);
    fprintf(file, "  \"firmware_version\": \"%x.%02x\",\n",
            firmware >> 8, firmware & 0xff);
    fprintf(file, "  \"scan_complete\": %s,\n",
            scanned_offsets_complete() ? "true" : "false");
    fprintf(file, "  \"patch_applied\": %s,\n", patched ? "true" : "false");
    if(eboot_name) {
        fprintf(file, "  \"eboot\": \"%s\",\n", eboot_name);
    } else {
        fprintf(file, "  \"eboot\": null,\n");
    }
    fprintf(file, "  \"offsets\": {\n");
    for(size_t i=0; i<PATCH_COUNT; i++) {
        fprintf(file, "    \"%s\": ", patches[i].id);
        if(patches[i].matches == 1) {
            fprintf(file, "\"0x%x\"", patches[i].offset);
        } else {
            fprintf(file, "null");
        }
        fprintf(file, "%s\n", i+1 == PATCH_COUNT ? "" : ",");
    }
    fprintf(file, "  },\n");
    fprintf(file, "  \"match_counts\": {\n");
    for(size_t i=0; i<PATCH_COUNT; i++) {
        fprintf(file, "    \"%s\": %u%s\n", patches[i].id,
                patches[i].matches, i+1 == PATCH_COUNT ? "" : ",");
    }
    fprintf(file, "  }\n");
    fprintf(file, "}\n");

    if(fclose(file)) {
        printf("write %s failed: %s\n", OFFSETS_JSON, strerror(errno));
        return -1;
    }
    printf("Offsets written to %s\n", OFFSETS_JSON);
    return 0;
}
#endif

static int patch_remoteplay(void) {
    uint32_t raw_firmware = kernel_get_fw_version();
    uint32_t firmware = raw_firmware >> 16;
    const firmware_profile_t *profile;
    pid_t pid = find_pid("SceRemotePlay");
    intptr_t base;
    int unknown;
#ifdef TESTING_BRANCH
    int result;
    char eboot_name[64];
    int eboot_exported = 0;
#endif

    printf("Firmware: 0x%08x (%x.%02x)\n", raw_firmware,
           firmware >> 8, firmware & 0xff);
    if(pid < 0) {
        puts("SceRemotePlay is not running");
        return -1;
    }
    if(!(base=kernel_dynlib_mapbase_addr(pid, 0))) {
        puts("Could not resolve SceRemotePlay map base");
        return -1;
    }
    printf("SceRemotePlay: pid=%d base=0x%lx\n", pid, base);

    profile = find_firmware_profile(firmware);
#ifdef TESTING_BRANCH
    profile = NULL;
    puts("Testing branch: ignoring hardcoded profiles");
#endif
    unknown = !profile;
    if(!unknown) {
        printf("Using firmware profile 0x%04x\n", profile->firmware);
        for(size_t i=0; i<PATCH_COUNT; i++) {
            patches[i].offset = profile->offsets[i];
            patches[i].matches = 1;
        }
        return apply_patches(pid, base);
    }

#ifndef TESTING_BRANCH
    printf("No hardcoded profile for firmware 0x%04x\n", firmware);
    return -1;
#else
    printf("Pattern scanning firmware 0x%04x\n", firmware);
    result = scan_offsets(pid, base);
    if(!export_eboot_syscore(firmware, eboot_name, sizeof(eboot_name))) {
        eboot_exported = 1;
    }
    if(result || !scanned_offsets_complete()) {
        puts("Could not resolve every patch offset");
        result = -1;
    } else {
        puts("Offset scan complete; no instructions modified");
        result = 0;
    }
    if(write_offsets_json(firmware, 0, eboot_exported ? eboot_name : NULL)) {
        result = -1;
    }
    return result;
#endif
}

static int run_with_privileges(void) {
    uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t caps[16];
    uint64_t authid;
    pid_t mypid = getpid();
    int failed;

    if(!(authid=kernel_get_ucred_authid(mypid))) {
        puts("kernel_get_ucred_authid failed");
        return -1;
    }
    if(kernel_get_ucred_caps(mypid, caps)) {
        puts("kernel_get_ucred_caps failed");
        return -1;
    }
    if(kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
        puts("kernel_set_ucred_authid failed");
        return -1;
    }
    if(kernel_set_ucred_caps(mypid, privcaps)) {
        puts("kernel_set_ucred_caps failed");
        if(kernel_set_ucred_authid(mypid, authid)) {
            puts("Failed to restore authid");
        }
        return -1;
    }

    failed = patch_remoteplay();

    if(kernel_set_ucred_authid(mypid, authid)) {
        puts("Failed to restore authid");
        failed = -1;
    }
    if(kernel_set_ucred_caps(mypid, caps)) {
        puts("Failed to restore capabilities");
        failed = -1;
    }

    return failed;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef TESTING_BRANCH
    puts("Remote Play offset scanner (testing)");
#else
    puts("Remote Play prohibition bypass (runtime patch)");
#endif

    if(run_with_privileges()) {
        puts("Remote Play payload failed; check the log");
        notify("Remote Play payload failed; check the log");
        return 1;
    }

#ifdef TESTING_BRANCH
    puts("Offset scan and export completed");
    notify("Remote Play offsets exported");
#else
    puts("RP-Prohibit is now forced to zero");
    notify("Remote Play prohibition patch applied");
#endif
    return 0;
}
