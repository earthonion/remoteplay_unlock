#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/mdbg.h>

#include "patches.h"

#define SCAN_LIMIT 0x600000
#define SCAN_CHUNK 0x40000
#define SCAN_PATTERN_MAX 43
#define SCAN_OVERLAP (SCAN_PATTERN_MAX - 1)

typedef struct {
    size_t pattern_size;
    size_t patch_offset;
    uint8_t pattern[SCAN_PATTERN_MAX];
    uint8_t mask[SCAN_PATTERN_MAX];
} scan_rule_t;

patch_t patches[PATCH_COUNT] = {
    {
        "rp_prohibit_primary",
        "RP-Prohibit primary",
        0,
        3,
        {0x8b, 0x4b, 0x08},
        {0x31, 0xc9, 0x90},
        0,
    },
    {
        "rp_prohibit_alternate",
        "RP-Prohibit alternate",
        0,
        4,
        {0x41, 0x0f, 0x95, 0xc0},
        {0x45, 0x31, 0xc0, 0x90},
        0,
    },
    {
        "rp_prohibit_fallback",
        "RP-Prohibit fallback",
        0,
        4,
        {0x41, 0x0f, 0x95, 0xc0},
        {0x45, 0x31, 0xc0, 0x90},
        0,
    },
    {
        "dynamic_prohibition_notification",
        "Dynamic prohibition notification",
        0,
        4,
        {0x45, 0x0f, 0xb6, 0xf7},
        {0x45, 0x31, 0xf6, 0x90},
        0,
    },
    {
        "protection_state_computation",
        "Protection-state computation",
        0,
        4,
        {0x55, 0x48, 0x89, 0xe5},
        {0x31, 0xc0, 0xc3, 0x90},
        0,
    },
};

static const firmware_profile_t firmware_profiles[] = {
    {
        0x1360,
        {0x600fe, 0x6013d, 0x602c8, 0x1bc75, 0x1b4f0},
    },
    {
        0x1200,
        {0x3962e, 0x3966d, 0x397f8, 0x1ba25, 0x1b2b0},
    },
};

static const scan_rule_t scan_rules[PATCH_COUNT] = {
    {
        38,
        25,
        {
            0x8b, 0x83, 0xc4, 0x01, 0x10, 0x00, 0x83, 0xf8,
            0x08, 0x0f, 0x87, 0xcd, 0x01, 0x00, 0x00, 0xb9,
            0xc4, 0x01, 0x00, 0x00, 0x0f, 0xa3, 0xc1, 0x73,
            0x2a, 0x8b, 0x4b, 0x08, 0x31, 0xd2, 0x84, 0xc9,
            0x0f, 0x95, 0xc2, 0x83, 0xf8, 0x08,
        },
        {
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1,
        },
    },
    {
        25,
        21,
        {
            0xb9, 0x38, 0x00, 0x00, 0x00, 0x0f, 0xa3, 0xc1,
            0x0f, 0x83, 0x8b, 0x01, 0x00, 0x00, 0x45, 0x31,
            0xc0, 0x80, 0x7b, 0x08, 0x00, 0x41, 0x0f, 0x95,
            0xc0,
        },
        {
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1,
        },
    },
    {
        43,
        7,
        {
            0x45, 0x31, 0xc0, 0x80, 0x7b, 0x08, 0x00, 0x41,
            0x0f, 0x95, 0xc0, 0x48, 0x83, 0xec, 0x08, 0x4c,
            0x8d, 0x15, 0xf7, 0x47, 0x4a, 0x00, 0x4c, 0x8d,
            0x1d, 0xb3, 0xe7, 0x4a, 0x00, 0x48, 0x8d, 0x15,
            0x2e, 0x23, 0x4c, 0x00, 0x48, 0x8d, 0x0d, 0x78,
            0x79, 0x4a, 0x00,
        },
        {
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1,
            0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0,
        },
    },
    {
        40,
        7,
        {
            0x44, 0x88, 0xb3, 0x10, 0x01, 0x00, 0x00, 0x45,
            0x0f, 0xb6, 0xf7, 0x48, 0x8d, 0x7b, 0x40, 0x44,
            0x89, 0xf6, 0xe8, 0xfb, 0x62, 0x2f, 0x00, 0x48,
            0x8b, 0x7b, 0x18, 0x48, 0x85, 0xff, 0x74, 0x0a,
            0x44, 0x89, 0xf6, 0xe8, 0x6a, 0x0a, 0xff, 0xff,
        },
        {
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0,
            1, 1, 1, 1, 0, 0, 0, 0,
        },
    },
    {
        41,
        0,
        {
            0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
            0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
            0x28, 0x48, 0x83, 0x7f, 0x30, 0x00, 0x48, 0x89,
            0xcb, 0x49, 0x89, 0xd7, 0x49, 0x89, 0xfc, 0x4c,
            0x8d, 0x6f, 0x30, 0x48, 0x89, 0x75, 0xc8, 0x74,
            0x22,
        },
        {
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 0,
        },
    },
};

const firmware_profile_t *find_firmware_profile(uint32_t firmware) {
    size_t count = sizeof(firmware_profiles) / sizeof(firmware_profiles[0]);

    for(size_t i=0; i<count; i++) {
        if(firmware_profiles[i].firmware == firmware) {
            return &firmware_profiles[i];
        }
    }
    return NULL;
}

static int pattern_matches(const uint8_t *data, const scan_rule_t *rule) {
    for(size_t i=0; i<rule->pattern_size; i++) {
        if(rule->mask[i] && data[i] != rule->pattern[i]) {
            return 0;
        }
    }
    return 1;
}

int scan_offsets(pid_t pid, intptr_t base) {
    uint8_t *buf = malloc(SCAN_CHUNK + SCAN_OVERLAP);
    int result = 0;

    if(!buf) {
        return -1;
    }
    for(size_t i=0; i<PATCH_COUNT; i++) {
        patches[i].matches = 0;
        patches[i].offset = 0;
    }

    for(size_t pos=0; pos<SCAN_LIMIT; pos+=SCAN_CHUNK) {
        size_t start = pos ? pos-SCAN_OVERLAP : 0;
        size_t end = pos+SCAN_CHUNK;
        size_t size;

        if(end > SCAN_LIMIT) {
            end = SCAN_LIMIT;
        }
        size = end-start;
        if(mdbg_copyout(pid, base+start, buf, size)) {
            printf("Pattern scan stopped at offset 0x%zx\n", start);
            if(!pos) {
                result = -1;
            }
            break;
        }

        for(size_t i=0; i<size; i++) {
            size_t absolute = start+i;
            if(absolute < pos) {
                continue;
            }
            for(size_t j=0; j<PATCH_COUNT; j++) {
                const scan_rule_t *rule = &scan_rules[j];

                if(i+rule->pattern_size > size ||
                   buf[i] != rule->pattern[0]) {
                    continue;
                }
                if(pattern_matches(buf+i, rule)) {
                    if(!patches[j].matches) {
                        patches[j].offset = absolute+rule->patch_offset;
                    }
                    patches[j].matches++;
                }
            }
        }
    }

    free(buf);
    for(size_t i=0; i<PATCH_COUNT; i++) {
        if(patches[i].matches == 1) {
            printf("%s: offset 0x%x (unique match)\n",
                   patches[i].name, patches[i].offset);
        } else {
            printf("%s: %u matches\n", patches[i].name, patches[i].matches);
        }
    }
    return result;
}

int scanned_offsets_complete(void) {
    for(size_t i=0; i<PATCH_COUNT; i++) {
        if(patches[i].matches != 1) {
            return 0;
        }
    }
    return 1;
}
