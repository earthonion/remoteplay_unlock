#pragma once

#include <stddef.h>
#include <stdint.h>

#define PATCH_COUNT 5

enum patch_index {
    PATCH_RP_PRIMARY,
    PATCH_RP_ALTERNATE,
    PATCH_RP_FALLBACK,
    PATCH_DYNAMIC_NOTIFICATION,
    PATCH_PROTECTION_COMPUTATION,
};

typedef struct {
    const char *id;
    const char *name;
    uint32_t offset;
    size_t size;
    uint8_t original[6];
    uint8_t replacement[6];
    unsigned int matches;
} patch_t;

typedef struct {
    size_t size;
    uint8_t original[6];
    uint8_t replacement[6];
} patch_override_t;

typedef struct {
    uint32_t firmware;
    uint32_t offsets[PATCH_COUNT];
    const patch_override_t *overrides;
    const patch_t *supplemental;
    size_t supplemental_count;
} firmware_profile_t;

extern patch_t patches[PATCH_COUNT];

const firmware_profile_t *find_firmware_profile(uint32_t firmware);
