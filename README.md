# Luac0re

Luac0re is a [mast1c0re](https://cturt.github.io/mast1c0re.html) variation that uses Lua scripting for easier exploit development.

## Overview

- The original [mast1c0re for Okage](https://github.com/McCaulay/mast1c0re) uses PS2 code execution only, which requires the [PS2SDK](https://github.com/ps2dev/ps2sdk) to compile the code.
- Luac0re uses minimal PS2 shellcode to escape ps2emu, then leverages the Lua 5.3 interpreter already embedded in the main executable (originally intended for ps2emu configuration) to simplify code writing and execution.
- Starting from version 2.0, a JIT compiler exploit has been added, enabling arbitrary native userland code execution on the latest PS4/PS5 firmwares without requiring a kernel exploit.
- Additionally, non AF_UNIX domain socket creation restriction introduced in PS5 firmware 8.00 can now be bypassed using the JIT exploit.

## Requirements

- PS4 or PS5 console
- Disc or digital version of *Star Wars Racer Revenge* USA (CUSA03474) or EU (CUSA03492) region
- Poopsploit payload requires 12.00 or lower firmware PS5

## Usage

1. Download the latest [release](https://github.com/Gezine/Luac0re/releases) ZIP file and extract it
2. The included savedata has been modified to allow a larger savedata image, as the original was too small to fit all the required files.
3. As a result, existing savedata image cannot be used — resigning the included savedata is mandatory.
4. For resigning the savedata, refer to the remote_lua_loader [SETUP guide](https://github.com/shahrilnet/remote_lua_loader/blob/main/SETUP.md)
5. Start the game and go to "OPTIONS -> HALL OF FAME"
6. Enjoy

## Porting Research — Fahrenheit / Indigo Prophecy

### Goal
Investigate whether Fahrenheit / Indigo Prophecy (PS4 Limited Run #331, `UP1642-CUSA04798` US / `EP1628-CUSA05760` EU) can serve as an alternative entry point for Luac0re, replacing Star Wars Racer Revenge.

> Gezine's assessment: *"Fahrenheit is probably exploitable but with a lot of pain."*

### Why Fahrenheit?
- Available as a PS4 disc release (Limited Run #331) — physical disc removes PSN dependency for savedata import
- Runs in the same ps2emu as SWRR — the Lua 5.3 interpreter hijack and all post-escape payloads would be reusable as-is
- Only the PS2-side entry shellcode would need to be ported

### Save File Structure (VMC)

| Offset | Content |
|--------|---------|
| `0x27970` | `PROFILENAME.idx` — VMC directory entry, do not modify |
| `0x28c00` | `PROFILENAME.dat` — VMC directory entry, do not modify |
| `0x291c5` | Profile name + `BONUSES` data — serialized format |
| `0x29973` | Profile name + `KEY_CONFIG_USER_INFOS` |

Profile name is stored as **uppercase ASCII**, prefixed by a 4-byte little-endian length field (`05 00 00 00` for a 5-char name). This is a structured serialized format, not a raw strcpy target.

### Key Functions (Ghidra / PCSX2 — `SLES_535.39`)

| Address | Role |
|---------|------|
| `003bd964` | Custom strcmp |
| `001e5d68` | strcmp wrapper |
| `00269b00` | Profile lookup by name |
| `0026c9d0` | Structure navigation |
| `00293308` | List insertion |
| `0026e2f0` | **Save validation** — generates "SaveGame %s Corrupted" |
| `003b4f08` | Hash validation via C++ vtable dispatch |
| `00201aa0` | **Hash algorithm** — CRC32-like (init `0xFFFFFFFF`, finalize with NOT, custom lookup table) |

### Runtime RAM Addresses (profile name)

With PCSX2 debugger, profile name found at:
`004B8F12`, `004BB760`, `004BB7A0`, `0077F3E8`, `0077F760`, `0077F808`, `0077F810`

### Current Blocker

Every modified savedata is rejected as corrupted before the profile name is even parsed. The game computes a custom hash over the save data via a C++ vtable call (`FUN_003b4f08` → virtual method at vtable offset `+0x24`), and compares it against a stored value at offset `+0x14` in the save structure.

The hash algorithm (`FUN_00201aa0`) uses a CRC32-like pattern but with a **non-standard lookup table** (`FUN_00201a70`). Standard CRC32 bruteforce found no match.

### Next Steps
- Dump the vtable at runtime in PCSX2 to identify the exact hash function
- Reverse `FUN_00201a70` in Ghidra to reconstruct the custom lookup table
- Once the hash can be recalculated, resume overflow testing on the profile name field

### Tools Used
- PCSX2 Qt with debug mode
- Ghidra 12.0.4 + ghidra-emotionengine-reloaded plugin (R5900/PS2 support)
- Python for VMC binary analysis

## Credits

- **[CTurt](https://github.com/CTurt)** - [mast1c0re](https://cturt.github.io/mast1c0re.html) writeup
- **[McCaulay](https://github.com/McCaulay)** - [mast1c0re](https://mccaulay.co.uk/mast1c0re-part-2-arbitrary-ps2-code-execution/) writeup and [Okage](https://github.com/McCaulay/mast1c0re) reference implementation
- **[ChampionLeake](https://github.com/ChampionLeake)** - PS2 *Star Wars Racer Revenge* exploit writeup on [psdevwiki](https://www.psdevwiki.com/ps2/Vulnerabilities)
- **[shahrilnet](https://github.com/shahrilnet) & [null_ptr](https://github.com/n0llptr)** - Code references from [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- **[Dr.Yenyen](https://github.com/DrYenyen)** - Testing and validation
- **[TheFlow](https://github.com/theofficialflow)** - Original netcontrol kernel exploit
- **[egycnq](https://github.com/egycnq)** - Porting netcontrol kernel exploit to Luac0re

## Disclaimer

This tool is provided as-is for research and development purposes only.  
Use at your own risk.  
The developers are not responsible for any damage, data loss, or other consequences resulting from the use of this software.
