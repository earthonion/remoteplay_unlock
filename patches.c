#include "patches.h"

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
