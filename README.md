Porting Luac0re to Fahrenheit / Indigo Prophecy — Research Notes
Goal
Investigate whether Fahrenheit / Indigo Prophecy (PS4 Limited Run #331, UP1642-CUSA04798 US / EP1628-CUSA05760 EU) can serve as an alternative entry point for Luac0re, replacing Star Wars Racer Revenge.
Gezine's assessment: "Fahrenheit is probably exploitable but with a lot of pain."
Why Fahrenheit?

Available as a PS4 disc release (Limited Run #331) — physical disc removes PSN dependency for savedata import
Runs in the same ps2emu as SWRR — the Lua 5.3 interpreter hijack and all post-escape payloads would be reusable as-is
Only the PS2-side entry shellcode would need to be ported

Save File Structure (VMC)
The savedata (mcd001.ps2) contains two files in the VMC directory:
OffsetContent0x27970PROFILENAME.idx — VMC directory entry, do not modify0x28c00PROFILENAME.dat — VMC directory entry, do not modify0x291c5Profile name + BONUSES data — serialized format0x29973Profile name + KEY_CONFIG_USER_INFOS
Profile name is stored as uppercase ASCII, prefixed by a 4-byte little-endian length field (05 00 00 00 for a 5-char name). This is a structured serialized format, not a raw strcpy target.
Key Functions (Ghidra / PCSX2 — SLES_535.39)
AddressRole003bd964Custom strcmp001e5d68strcmp wrapper00269b00Profile lookup by name0026c9d0Structure navigation00293308List insertion0026e2f0Save validation — generates "SaveGame %s Corrupted"003b4f08Hash validation via C++ vtable dispatch00201aa0Hash algorithm — CRC32-like (init 0xFFFFFFFF, finalize with NOT, custom lookup table)
Runtime RAM addresses (profile name)
With PCSX2 debugger, profile name found at:
004B8F12, 004BB760, 004BB7A0, 0077F3E8, 0077F760, 0077F808, 0077F810
Current Blocker
Every modified savedata is rejected as corrupted before the profile name is even parsed. The game computes a custom hash over the save data via a C++ vtable call (FUN_003b4f08 → virtual method at vtable offset +0x24), and compares it against a stored value at offset +0x14 in the save structure.
The hash algorithm (FUN_00201aa0) uses a CRC32-like pattern but with a non-standard lookup table (FUN_00201a70). Standard CRC32 bruteforce found no match.
Next Steps

Dump the vtable at runtime in PCSX2 to identify the exact hash function
Reverse FUN_00201a70 in Ghidra to reconstruct the custom lookup table
Once the hash can be recalculated, resume overflow testing on the profile name field

Tools Used

PCSX2 Qt with debug mode
Ghidra 12.0.4 + ghidra-emotionengine-reloaded plugin (R5900/PS2 support)
Python for VMC binary analysis
