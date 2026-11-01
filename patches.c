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

static const patch_override_t firmware_1001_overrides[PATCH_COUNT] = {
    {
        5,
        {0x44, 0x0f, 0xb6, 0x53, 0x08},
        {0x45, 0x31, 0xd2, 0x90, 0x90},
    },
    {
        5,
        {0x44, 0x0f, 0xb6, 0x53, 0x08},
        {0x45, 0x31, 0xd2, 0x90, 0x90},
    },
    {
        5,
        {0x44, 0x0f, 0xb6, 0x53, 0x08},
        {0x45, 0x31, 0xd2, 0x90, 0x90},
    },
    {
        4,
        {0x45, 0x0f, 0xb6, 0xf7},
        {0x45, 0x31, 0xf6, 0x90},
    },
    {0},
};

static const patch_override_t firmware_0320_overrides[PATCH_COUNT] = {
    {
        6,
        {0x45, 0x0f, 0xb6, 0x54, 0x24, 0x08},
        {0x45, 0x31, 0xd2, 0x90, 0x90, 0x90},
    },
    {
        6,
        {0x45, 0x0f, 0xb6, 0x5c, 0x24, 0x08},
        {0x45, 0x31, 0xdb, 0x90, 0x90, 0x90},
    },
    {
        6,
        {0x45, 0x0f, 0xb6, 0x74, 0x24, 0x08},
        {0x45, 0x31, 0xf6, 0x90, 0x90, 0x90},
    },
    {
        4,
        {0x41, 0x0f, 0xb6, 0xf5},
        {0x31, 0xf6, 0x90, 0x90},
    },
    {
        4,
        {0x55, 0x48, 0x89, 0xe5},
        {0x31, 0xc0, 0xc3, 0x90},
    },
};

static const patch_t firmware_1001_supplemental[] = {
    {
        "protection_audio_initial",
        "10.01 protection audio initial",
        0x19105,
        3,
        {0x40, 0x88, 0x30},
        {0xc6, 0x00, 0x00},
        0,
    },
    {
        "protection_video_initial",
        "10.01 protection video initial",
        0x19108,
        4,
        {0x45, 0x88, 0x75, 0x00},
        {0x41, 0xc6, 0x00, 0x00},
        0,
    },
    {
        "protection_audio_forced_1",
        "10.01 protection audio forced 1",
        0x1914b,
        3,
        {0xc6, 0x00, 0x01},
        {0xc6, 0x00, 0x00},
        0,
    },
    {
        "protection_video_forced_1",
        "10.01 protection video forced 1",
        0x1914e,
        5,
        {0x41, 0xc6, 0x45, 0x00, 0x01},
        {0x41, 0xc6, 0x45, 0x00, 0x00},
        0,
    },
    {
        "protection_audio_forced_2",
        "10.01 protection audio forced 2",
        0x1918a,
        3,
        {0xc6, 0x00, 0x01},
        {0xc6, 0x00, 0x00},
        0,
    },
    {
        "protection_video_forced_2",
        "10.01 protection video forced 2",
        0x1918d,
        5,
        {0x41, 0xc6, 0x45, 0x00, 0x01},
        {0x41, 0xc6, 0x45, 0x00, 0x00},
        0,
    },
    {
        "protection_audio_forced_3",
        "10.01 protection audio forced 3",
        0x191f6,
        3,
        {0xc6, 0x00, 0x01},
        {0xc6, 0x00, 0x00},
        0,
    },
    {
        "protection_video_forced_3",
        "10.01 protection video forced 3",
        0x191f9,
        5,
        {0x41, 0xc6, 0x45, 0x00, 0x01},
        {0x41, 0xc6, 0x45, 0x00, 0x00},
        0,
    },
};

static const firmware_profile_t firmware_profiles[] = {
    {
        0x1360,
        {0x600fe, 0x6013d, 0x602c8, 0x1bc75, 0x1b4f0},
        NULL,
        NULL,
        0,
    },
    {
        0x1200,
        {0x3962e, 0x3966d, 0x397f8, 0x1ba25, 0x1b2b0},
        NULL,
        NULL,
        0,
    },
    {
        0x1001,
        {0x309b8, 0x30a93, 0x30b74, 0x196de, 0x18fe0},
        firmware_1001_overrides,
        firmware_1001_supplemental,
        sizeof(firmware_1001_supplemental) / sizeof(firmware_1001_supplemental[0]),
    },
    {
        0x0320,
        {0x1badc6, 0x1bad0b, 0x1babc8, 0x1271b, 0x11af0},
        firmware_0320_overrides,
        NULL,
        0,
    },
    {
        0x1270,
        {0x3a03e, 0x3a07d, 0x3a208, 0x1ba25, 0x1b2b0},
        NULL,
        NULL,
        0,
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
