# Porting Remote Play Unlock to another firmware

This guide is intended to let another developer or AI model find, validate, and submit correct firmware offsets without guessing.

## Understand the two branches

- `main` builds `remoteplay_unlock.elf`. It patches a running `SceRemotePlay` process only when the detected firmware has a hardcoded profile. Unknown firmware is rejected.
- `testing` builds `remoteplay_unlock_offsets.elf`. It always pattern scans and exports data, but never modifies Remote Play instructions. Use it to discover offsets and obtain a decrypted eboot.

The patched executable is:

```text
/system/vsh/app/NPXS40102/eboot.bin
```

The payload resolves its base with `kernel_dynlib_mapbase_addr(pid, 0)` and adds each profile offset to that base.

## Offset rules

- Profile offsets are virtual addresses relative to the eboot image base, not runtime absolute addresses.
- Do not use the address of an instruction in one firmware as the offset in another without verifying the code.
- If you need a file offset, calculate it from the ELF program headers. Many current dumps use `file offset = virtual offset + 0x4000`, but that is not a valid assumption for every binary.
- Preserve exact instruction lengths. Use NOPs only to pad a replacement to the original length.
- Check register width, REX prefixes, SIB bytes, stack effects, and flags. A correct-looking offset from a disassembler is not enough by itself.

## Fast path: run the scanner

Build and deploy the testing payload:

```sh
git checkout testing
make clean all
make test PS5_HOST=<ps5-ip>
```

The scanner ignores hardcoded profiles and reads the running process. It writes:

```text
/mnt/usb0/rp_prohibit/rp_prohibit_offsets.json
/mnt/usb0/rp_prohibit/eboot_<firmware-id>.bin
```

For example, firmware 12.00 produces `eboot_1200.bin`.

With an FTP server running on the console, retrieve the results with:

```sh
curl ftp://<ps5-ip>:2121/mnt/usb0/rp_prohibit/rp_prohibit_offsets.json -o rp_prohibit_offsets.json
curl ftp://<ps5-ip>:2121/mnt/usb0/rp_prohibit/eboot_1200.bin -o eboot_1200.bin
```

Before using the offsets, require all of these conditions:

- `"scan_complete"` is `true`.
- Every entry in `match_counts` is `1`.
- Every entry in `offsets` is non-null.
- `"patch_applied"` is `false`.

A scanner match is only a candidate. Disassemble each matched instruction and its callers before adding it to `main`.

If a signature has zero or multiple matches, do not submit its offset. Inspect the exported eboot and improve the signature first.

## The five required patch sites

Keep this exact order in every firmware profile:

| Index | JSON key | Purpose |
| --- | --- | --- |
| 0 | `rp_prohibit_primary` | First `RP-Prohibit` response-generation path |
| 1 | `rp_prohibit_alternate` | Second response-generation path |
| 2 | `rp_prohibit_fallback` | Fallback response-generation path |
| 3 | `dynamic_prohibition_notification` | In-session prohibition notification |
| 4 | `protection_state_computation` | Audio/video protection-state computation |

### 0–2. Find the `RP-Prohibit` response values

Search the eboot for the string `RP-Prohibit: ` and follow its code references. The three formatting paths load a prohibition value and pass it to the response builder. Patch each value to zero without changing control flow incorrectly.

Do not patch the string or blindly replace the first `movzx` found nearby. Identify the actual value consumed by the formatter.

A useful patch is often a value-sized push or move:

```text
push r10  ->  push 0
41 52     ->  6a 00
```

Other valid examples include:

```text
mov ecx, dword ptr [rbx + 8]  ->  xor ecx, ecx ; nop
8b 4b 08                      ->  31 c9 90

setne r8b                     ->  xor r8d, r8d ; nop
41 0f 95 c0                   ->  45 31 c0 90
```

Always inspect instructions after the replacement. `xor`, `test`, and `cmp` change flags. If a following conditional branch relies on the previous flags, patch a flag-neutral argument instead.

**Why 10.01 is special:** replacing `movzx r10d, byte ptr [rbx + 8]` with `xor r10d, r10d` clears CF and breaks the following string-length branch. Use the `push r10` sites instead:

```c
{0x30a58, 0x30b45, 0x30bd7, 0x196de, 0x18fe0}
```

At 3.20, each `movzx` is immediately followed by `sub rsp, 8`, which overwrites the flags before another branch, so the CF issue does not apply. Do not assume that proves other aspects of 3.20 are correct; validate them independently.

### 3. Find the dynamic notification

Follow app-focus or prohibition-state changes until a boolean is passed to a notification call. Zero the boolean immediately before the call, preserving the surrounding logic and instruction length.

Typical examples:

```text
movzx r14d, r15b  ->  xor r14d, r14d ; nop
45 0f b6 f7       ->  45 31 f6 90

movzx esi, r13b   ->  xor esi, esi ; nop ; nop
41 0f b6 f5       ->  31 f6 90 90
```

The register and instruction encoding vary by firmware. Do not use a replacement for a different register merely because the offset looks similar.

### 4. Find the protection-state computation

Useful landmarks include:

- `SceRpResProhibitSectionMtx`
- `SceRpProhibitionSection`
- app-info fields such as `protectAudio`, `protectVideo`, and `prohibitType`
- code that reads the current app record and writes two protection booleans

The default entry replacement is:

```text
55 48 89 e5  ->  31 c0 c3 90
```

This replaces the function prologue with `xor eax, eax ; ret ; nop`. Before using it:

1. Find all callers.
2. Confirm that their output flags are initialized to zero before the call.
3. Check whether later code depends on state updates performed by the original function.
4. Test an app that previously produced a black screen, not just the initial connection.

If a whole-function stub is not safe for a particular build, patch the output writes instead. Do not hide state corruption by forcing a return and hoping the rest of the process does not depend on it.

## Add a hardcoded profile

Switch to `main` and edit `firmware_profiles` in `patches.c`:

```sh
git checkout main
```

Each entry contains a firmware ID, five offsets, and an optional override array. The firmware ID is `kernel_get_fw_version() >> 16`; for example, 12.00 is `0x1200`.

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

Replace the example ID and placeholders with validated values. Do not change the patch order.

Use `NULL` when the default original/replacement bytes work. When a build needs different bytes or lengths, provide a `patch_override_t` array with one entry per patch and `{0}` for patches that retain the defaults.

For example, 10.01 currently uses two-byte `push 0` replacements for the first three patches:

```c
static const patch_override_t firmware_1001_overrides[PATCH_COUNT] = {
    {2, {0x41, 0x52}, {0x6a, 0x00}},
    {2, {0x41, 0x52}, {0x6a, 0x00}},
    {2, {0x41, 0x52}, {0x6a, 0x00}},
    {0},
    {0},
};
```

Remember that base-register choices affect encoding. For example, 3.20 uses `r12`, which requires a SIB byte, so its header instructions and replacements are six bytes long. A five-byte replacement would leave an extra opcode behind and is invalid.

## Improve scanner signatures when needed

On `testing`, edit `scan_rules` and `scan_rule_patch_indices` in `patches.c`.

Each rule contains:

- `pattern_size`: number of bytes in the signature.
- `patch_offset`: instruction offset within that signature.
- `pattern`: instruction bytes.
- `mask`: `1` for exact bytes and `0` for wildcard bytes.

Use wildcards for branch destinations, call targets, and RIP-relative displacements that can change between builds. Keep opcodes, register operands, and structure offsets specific enough to avoid false matches.

Multiple rules may point to the same patch index. The scanner de-duplicates matches by resolved patch offset. A patch is resolved only when exactly one distinct offset is found.

The current pattern buffer is sized for signatures up to `SCAN_PATTERN_MAX` bytes. Increase it deliberately if a longer signature is necessary, including the overlap logic.

Validate every new rule against the target eboot and, when practical, against other firmware dumps to check for accidental matches.

## Validate before opening a PR

Run through this checklist:

- [ ] The firmware ID comes from the target console or its scanner JSON.
- [ ] All five offsets point to the intended instructions.
- [ ] Every original byte sequence matches the binary exactly.
- [ ] Every replacement has the same length as its original instruction.
- [ ] Control flow, flags, stack behavior, and register usage were reviewed.
- [ ] Scanner rules, if changed, produce one unique offset per patch.
- [ ] `make clean all` succeeds with the PS5 Payload SDK.
- [ ] The payload applies or recognizes all patches on the target console.
- [ ] Remote Play connects, and a previously prohibited app displays without needing a rerun for each app.
- [ ] The README supported-firmware table is updated.
- [ ] No built ELFs or other generated binaries are committed.

Build and deploy with:

```sh
make clean all
make test PS5_HOST=<ps5-ip>
```

A successful payload run is not sufficient by itself; verify the actual Remote Play scenario on the target firmware. If hardware is unavailable, say explicitly in the PR that the profile was validated only against the eboot.

## Submit the PR

Commit the profile and any required documentation changes on `main`:

```sh
git add patches.c README.md
git commit -m "Add Remote Play offsets for firmware X.XX"
git push origin main
```

Scanner or signature improvements belong on `testing` instead. Pushes to `main` publish the hardcoded payload to the `latest` prerelease; pushes to `testing` publish the scanner to `latest-testing`.

In the PR description, include:

1. Firmware version and eboot hash if available.
2. All five offsets and original/replacement bytes.
3. Why each patch is safe, especially flags and callers.
4. Scanner results or disassembly evidence.
5. Whether testing was performed on hardware or only against the binary.

Do not include speculative offsets just to silence scanner errors. A smaller verified profile is safer than a complete but unvalidated one.

---

> **Note:** This project was made entirely by AI (Kimi K3.1 pro).
