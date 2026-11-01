#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "patches.h"

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
    uint8_t verify[6];
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
    size_t applied[PATCH_COUNT];
    size_t applied_count = 0;
    int already_patched = 1;
    int failed = 0;

    for(size_t i=0; i<PATCH_COUNT; i++) {
        const patch_t *patch = &patches[i];
        uint8_t current[6];

        if(mdbg_copyout(pid, base+patch->offset, current, patch->size)) {
            printf("%s: read failed at offset 0x%x\n", patch->name, patch->offset);
            return -1;
        }
        if(!memcmp(current, patch->original, patch->size)) {
            already_patched = 0;
        } else if(memcmp(current, patch->replacement, patch->size)) {
            printf("%s: signature mismatch at offset 0x%x; unsupported build\n",
                   patch->name, patch->offset);
            return -1;
        }
    }

    if(already_patched) {
        puts("RP-Prohibit patches are already applied");
        return 0;
    }
    if(ptrace_attach(pid)) {
        printf("ptrace attach failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    for(size_t i=0; i<PATCH_COUNT; i++) {
        const patch_t *patch = &patches[i];
        uint8_t current[6];

        if(mdbg_copyout(pid, base+patch->offset, current, patch->size) ||
           memcmp(current, patch->original, patch->size)) {
            continue;
        }
        if(write_bytes(pid, base+patch->offset, patch->replacement, patch->size)) {
            printf("%s: write failed; rolling back\n", patch->name);
            while(applied_count) {
                size_t index = applied[--applied_count];
                const patch_t *rollback = &patches[index];

                if(write_bytes(pid, base+rollback->offset,
                               rollback->original, rollback->size)) {
                    printf("%s: rollback failed\n", rollback->name);
                }
            }
            failed = -1;
            break;
        }

        applied[applied_count++] = i;
        printf("%s: patched at offset 0x%x\n", patch->name, patch->offset);
    }

    if(do_ptrace(PT_DETACH, pid, 0, 0)) {
        printf("ptrace detach failed: errno=%d (%s)\n", errno, strerror(errno));
        failed = -1;
    }
    return failed;
}

static int patch_remoteplay(void) {
    uint32_t raw_firmware = kernel_get_fw_version();
    uint32_t firmware = raw_firmware >> 16;
    const firmware_profile_t *profile = find_firmware_profile(firmware);
    pid_t pid = find_pid("SceRemotePlay");
    intptr_t base;

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

    if(!profile) {
        printf("No hardcoded profile for firmware 0x%04x\n", firmware);
        return -1;
    }

    printf("Using firmware profile 0x%04x\n", profile->firmware);
    for(size_t i=0; i<PATCH_COUNT; i++) {
        patches[i].offset = profile->offsets[i];
        patches[i].matches = 1;
        if(profile->overrides && profile->overrides[i].size) {
            patches[i].size = profile->overrides[i].size;
            memcpy(patches[i].original, profile->overrides[i].original,
                   patches[i].size);
            memcpy(patches[i].replacement, profile->overrides[i].replacement,
                   patches[i].size);
        }
    }
    return apply_patches(pid, base);
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
    puts("Remote Play prohibition bypass (runtime patch)");

    if(run_with_privileges()) {
        puts("Failed to patch SceRemotePlay");
        notify("Remote Play unlock failed; check the payload log");
        return 1;
    }

    puts("RP-Prohibit is now forced to zero");
    notify("Remote Play prohibition patch applied");
    return 0;
}
