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
| 3.20 | `0x0320` |
| 10.01 | `0x1001` |
| 12.00 | `0x1200` |
| 12.70 | `0x1270` |
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

## Porting

See [PORTING.md](PORTING.md) for the complete firmware-porting guide, including scanner usage, manual offset discovery, instruction-safety checks, scanner signatures, and the PR validation checklist.

---

> **Note:** This project was made entirely by AI (Kimi K3.1 pro).
