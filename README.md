# Remote Play Unlock

PS5 payload that bypasses Remote Play prohibition by patching `SceRemotePlay` (`NPXS40102/eboot.bin`) in memory. It covers the initial `RP-Prohibit` response, dynamic prohibition notifications, and audio/video protection-state computation.

The registry setting `/REMOTEPLAY/ignore_prohibition` is not present on retail 13.60, so this payload uses runtime instruction patches instead.

## Branches

- `main`: the simple payload. It uses hardcoded offsets for supported firmware versions and refuses unknown firmware.
- `testing`: the offset-discovery payload. It always pattern scans, exports a decrypted eboot and a JSON report, and never modifies Remote Play instructions.

Built ELFs are ignored by Git. The `main` branch has a GitHub Actions workflow that builds and publishes `remoteplay_unlock.elf` to the rolling `latest` prerelease on every push.

## Supported firmware

| Firmware | Firmware ID |
| --- | --- |
| 10.01 | `0x1001` |
| 12.00 | `0x1200` |
| 13.60 | `0x1360` |

The firmware ID is `kernel_get_fw_version() >> 16`.

## Building

Install the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk) and set `PS5_PAYLOAD_SDK`:

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
git checkout main
make clean all
```

This produces `remoteplay_unlock.elf`.

For the testing payload:

```sh
git checkout testing
make clean all
```

This produces `remoteplay_unlock_offsets.elf`.

## Running

Start your payload listener, then deploy with the SDK:

```sh
make test PS5_HOST=<ps5-ip>
```

Or send the ELF to the listener directly:

```sh
nc -q 0 <ps5-ip> 9021 < remoteplay_unlock.elf
```

On `main`, a successful run reports that each patch was applied or that the patches were already applied. The changes are in memory, so run the payload again if `SceRemotePlay` restarts or the console reboots. It does not need to be rerun for each app.

The original instruction bytes are checked before every write. A signature mismatch aborts the payload instead of patching an unrecognized build.

## Adding offsets for a new firmware

Use the `testing` branch to discover offsets, then add them to a firmware profile on `main`.

### 1. Run the scanner

```sh
git checkout testing
make clean all
make test PS5_HOST=<ps5-ip>
```

The testing payload ignores hardcoded profiles and scans the running `SceRemotePlay` process. It does not attach to or modify the process.

It writes these files to USB:

```text
/mnt/usb0/rp_prohibit/rp_prohibit_offsets.json
/mnt/usb0/rp_prohibit/eboot_<firmware-id>.bin
```

For example, 13.60 produces `eboot_1360.bin`.

If the console is running an FTP server, the files can be retrieved with:

```sh
curl ftp://<ps5-ip>:2121/mnt/usb0/rp_prohibit/rp_prohibit_offsets.json -o rp_prohibit_offsets.json
curl ftp://<ps5-ip>:2121/mnt/usb0/rp_prohibit/eboot_1360.bin -o eboot_1360.bin
```

### 2. Validate the scan results

Check `rp_prohibit_offsets.json` before adding a profile:

- `"scan_complete"` must be `true`.
- Every entry in `match_counts` must be `1`.
- Every entry in `offsets` must have a non-null value.
- `"patch_applied"` is always `false` because the testing payload is non-destructive.

Example offset keys, in profile order:

1. `rp_prohibit_primary`
2. `rp_prohibit_alternate`
3. `rp_prohibit_fallback`
4. `dynamic_prohibition_notification`
5. `protection_state_computation`

If a signature has zero or multiple matches, do not add its reported offset to `main`. Inspect the exported eboot and update the masked signatures in `scan_rules` in `patches.c` on the `testing` branch. Wildcard bytes in the masks allow branch and call displacements to vary; keep the surrounding instruction bytes specific enough to avoid false matches.

### 3. Add a firmware profile

Switch to `main` and edit `firmware_profiles` in `patches.c`:

```sh
git checkout main
```

Add one entry using the firmware ID and the five offsets in the order shown above:

```c
static const firmware_profile_t firmware_profiles[] = {
    {
        0x1360,
        {0x600fe, 0x6013d, 0x602c8, 0x1bc75, 0x1b4f0},
        NULL,
    },
    {
        0x1400,
        {0xPRIMARY, 0xALTERNATE, 0xFALLBACK, 0xDYNAMIC, 0xPROTECTION},
        NULL,
    },
};
```

Replace the example `0x1400` ID and placeholder offsets with values from the JSON report. Keep the patch order unchanged. The third field is an optional `patch_override_t` array. Use it when a firmware needs different original/replacement bytes or instruction lengths, and use `{0}` for patches that should keep the defaults. For example, 10.01 uses a five-byte `movzx r10d` override for the first three patches; 12.00 and 13.60 use `NULL` because no overrides are needed.

### 4. Verify and publish

Build and deploy the new profile:

```sh
make clean all
make test PS5_HOST=<ps5-ip>
```

Confirm that all five patches pass their original-byte checks, then test Remote Play with an app that previously triggered the prohibition. Test switching into that app without resending the payload.

After verification:

```sh
git add patches.c
git commit -m "Add Remote Play offsets for firmware X.XX"
git push origin main
```

The `main` workflow will build the hardcoded ELF and publish it to the `latest` prerelease. Scanner or signature improvements should be committed and pushed on `testing` instead; pushes to `testing` do not create a hardcoded-payload release.
