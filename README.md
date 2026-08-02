# FindXrefs — recover "no cross-references" in IDA Pro

An IDA Pro plugin for when **"Jump to xref" (X) shows no references** to a
string (or any address) on a large binary — even though references clearly
exist. It scans the whole database for references IDA hasn't materialized yet
and forces them to appear.

> Keywords: IDA no xrefs to string · IDA missing cross-references ·
> IDA string has no xref · force / find xref in IDA.

## Demo

![FindXrefs demo](demo.gif)

## The problem

On very large binaries IDA is still auto-analyzing when you land on an item — a
string, function, global, or any referenceable address. The code that
references it is still **undefined bytes**, so IDA has not created the
cross-reference yet. Pressing **X** reports "no xrefs" — not because none exist,
but because that code was never decoded.

## What it does

Place the cursor on the string (or any target address) and run the plugin. It
scans the entire database for references to that address using your chosen 
engine and **materializes** each match so the xref shows up:

1. **Default Mode (Heuristic Disassembly)**
   - **RIP-relative (x86-64):** detects `lea/mov reg, [rip + disp32]` where
     `target == disp_addr + 4 + disp32`.
   - **Absolute:** literal pointers to the address (data tables, `mov reg, imm`,
     `push offset`, ...).
2. **Raw Relative 32-bit Mode:** Brute-forces a sliding window scan across all
   memory evaluating `target == current_ea + 4 + rel32` for non-standard or 
   heavily obfuscated relative offsets.

For each match landing on undefined bytes it calls `create_insn` (code) or
creates a data offset. Once the byte becomes code/offset, IDA generates the
xref automatically and it appears under **X**.

## Installation

Copy `find_xrefs.py` into IDA's plugins directory:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- or: `<IDA install>\plugins\`

Restart IDA.

## Usage

1. Put the cursor on the string / address with the missing xrefs.
2. Press **Ctrl-Shift-X** (or `Edit > Plugins > Find Xrefs`).
3. Select your preferred scanning engine (**Default** or **Raw Relative 32-bit**).
4. Choose whether to scan code segments only (faster) or the whole database.
5. Review the found references in the list (double-click to jump).
6. Confirm to materialize them — then press **X** on the string to see the xrefs.

## Requirements

- IDA Pro with IDAPython (x86-64 for RIP-relative scanning; 32-bit uses the
  absolute/relative scan).
- **numpy is optional.** If present, both RIP-relative and Raw Relative 32-bit scans use a vectorized engine (~5× faster on the byte sweep). If not, it automatically falls back to regex and standard loop engines that need nothing beyond the standard library. The plugin prints which engine is active on load.

## Notes

- Large segments are scanned in overlapping chunks with a cancellable progress
  box.
- If **Default Mode** finds 0 candidates, the plugin automatically offers a 
  fallback prompt to scan using the **Raw Relative 32-bit** engine.

## License

Released under the MIT License. See [LICENSE](LICENSE).
