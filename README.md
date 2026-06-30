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

On very large binaries IDA is still auto-analyzing when you open a string. The
code that references the string is still **undefined bytes**, so IDA has not
created the cross-reference yet. Pressing **X** reports "no xrefs" — not because
none exist, but because that code was never decoded.

## What it does

Place the cursor on the string (or any target address) and run the plugin. It
scans the entire database for references to that address and **materializes**
each match so the xref shows up:

1. **RIP-relative (x86-64)** — detects `lea/mov reg, [rip + disp32]` where
   `target == disp_addr + 4 + disp32`.
2. **Absolute** — literal pointers to the address (data tables, `mov reg, imm`,
   `push offset`, ...).

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
3. Choose whether to scan code segments only (faster) or the whole database.
4. Review the found references in the list (double-click to jump).
5. Confirm to materialize them — then press **X** on the string to see the xrefs.

## Requirements

- IDA Pro with IDAPython (x86-64 for RIP-relative scanning; 32-bit uses the
  absolute scan).
- **numpy is optional.** If present, the RIP scan uses a vectorized engine
  (~5× faster on the byte sweep). If not, it automatically falls back to a
  regex-based engine that needs nothing beyond the standard library. The plugin
  prints which engine is active on load.

## Notes

- The plugin does not call `auto_wait()`, so it won't block waiting for IDA's
  full autoanalysis; `create_insn` registers the xref immediately.
- Large segments are scanned in overlapping chunks with a cancellable progress
  box.

## License

MIT (add a `LICENSE` file).
