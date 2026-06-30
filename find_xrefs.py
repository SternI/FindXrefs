r"""
find_xrefs.py - IDA Pro plugin

On very large binaries IDA is still auto-analyzing when you open a string, so
"Jump to xref" (X) reports no references: not because they don't exist, but
because the code that references the string is still undefined bytes.

Place the cursor on the string (or any target address) and run the plugin
(Ctrl-Shift-X). It scans the whole database for references to that address:

  1. RIP-relative (x86-64): detects `lea/mov reg, [rip + disp32]` where
     target == disp_addr + 4 + disp32.
  2. Absolute: literal pointers to the address (data tables, mov reg,imm,
     push offset, ...).

Each match that lands on undefined bytes is materialized (create_insn or a data
offset). Once the byte becomes code/offset, IDA generates the xref and it shows
up under X.

Install: copy this file into IDA's plugins dir
(%APPDATA%\Hex-Rays\IDA Pro\plugins\ or <IDA>\plugins\), restart IDA.
Default hotkey: Ctrl-Shift-X. Also under Edit > Plugins > Find Xrefs.
"""

import re
import struct

try:
    # numpy is optional (not shipped with IDA). A partial/corrupt install can
    # import yet fail later, so force a real op to confirm it works.
    import numpy as np
    np.frombuffer(b"\x00\x00\x00\x00", dtype=np.uint8)
    _HAVE_NUMPY = True
    _NUMPY_ERR = ""
except Exception as _e:
    _HAVE_NUMPY = False
    _NUMPY_ERR = repr(_e)

import ida_idaapi
import ida_kernwin
import ida_bytes
import ida_segment
import ida_ua
import ida_xref
import ida_nalt
import ida_offset
import ida_ida
import idautils
import ida_idp

PLUGIN_NAME = "Find Xrefs"
PLUGIN_HOTKEY = "Ctrl-Shift-X"

# Max bytes to look back when locating an instruction start (prefixes + REX +
# opcode fit easily in 8 bytes).
MAX_INSN_BACKTRACK = 8

# Chunk size for splitting large segments: lets us refresh progress and honor
# cancellation. Chunks overlap 4 bytes so no disp32 is lost on a boundary.
SCAN_CHUNK = 32 * 1024 * 1024

# ModR/M bytes of a RIP-relative operand: mod=00, rm=101 -> (b & 0xC7) == 0x05.
# Only 8 possible values (the reg field varies). The stdlib regex engine (C)
# locates these far faster than a Python loop.
_RIP_MODRM_RE = re.compile(
    b"[" + b"".join(b"\\x%02x" % v for v in range(256) if (v & 0xC7) == 0x05) + b"]"
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _ptr_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _is_x86():
    return ida_idp.ph_get_id() == ida_idp.PLFM_386


def _iter_segments(code_only):
    """Yield (start_ea, end_ea) of the segments to scan."""
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        if code_only and seg.type != ida_segment.SEG_CODE:
            continue
        if not ida_bytes.is_loaded(seg.start_ea):
            continue
        yield seg.start_ea, seg.end_ea


def _read_segment(start, end):
    size = end - start
    if size <= 0:
        return b""
    data = ida_bytes.get_bytes(start, size)
    return data if data else b""


def _find_insn_start(end_ea, target):
    """
    Given an instruction end and the target, step back to find the real
    instruction start by decoding. Returns (start_ea, size) or (None, 0).
    """
    insn = ida_ua.insn_t()
    for back in range(1, MAX_INSN_BACKTRACK + 1):
        start = end_ea - back
        if start < 0:
            break
        length = ida_ua.decode_insn(insn, start)
        if length <= 0:
            continue
        if start + length != end_ea:
            continue
        if _insn_refs_target(insn, target):
            return start, length
    return None, 0


def _insn_refs_target(insn, target):
    """True if any operand of the decoded instruction points at target."""
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        if op.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far, ida_ua.o_imm):
            if op.addr == target or op.value == target:
                return True
        if op.type == ida_ua.o_displ:
            if op.addr == target:
                return True
    return False


# --------------------------------------------------------------------------- #
# Scan engines
# --------------------------------------------------------------------------- #
def scan_rip_relative(target, segments, found):
    """Scan for x86-64 RIP-relative references to target."""
    if _ptr_size() != 8 or not _is_x86():
        return

    engine_name, engine_fn = _rip_engine()
    ida_kernwin.msg("[Find Xrefs] RIP scan engine: %s\n" % engine_name)

    for seg_start, seg_end in segments:
        if ida_kernwin.user_cancelled():
            return
        size = seg_end - seg_start
        off = 0
        while off < size:
            if ida_kernwin.user_cancelled():
                return
            chunk_len = min(SCAN_CHUNK, size - off)
            base = seg_start + off
            data = ida_bytes.get_bytes(base, chunk_len)
            if data:
                ida_kernwin.replace_wait_box(
                    "Find Xrefs: scanning RIP %#x (%d%%)"
                    % (base, (off * 100) // max(size, 1)))
                for modrm_ea in engine_fn(data, base, target):
                    _confirm_rip_match(modrm_ea, target, found)
            if chunk_len <= 4:
                break
            off += chunk_len - 4  # 4-byte overlap


def _rip_engine():
    """Pick the RIP scan engine. numpy if usable, else regex."""
    if _HAVE_NUMPY:
        return "numpy (vectorized)", _rip_raw_numpy
    return "regex (install numpy for faster speed)", _rip_raw_regex


def _confirm_rip_match(modrm_ea, target, found):
    start, sz = _find_insn_start(modrm_ea + 5, target)
    if start is None:
        # Couldn't confirm as an instruction; record the raw modrm anyway.
        start, sz = modrm_ea, 0
    _add_result(found, start, sz, "rip-relative", target)


def _rip_raw_numpy(data, base, target):
    """
    Vectorized RIP-relative scan. Returns candidate modrm addresses (unconfirmed).

    Condition  base + i + 5 + disp32 == target  is rewritten as
    disp32 + i == target - base - 5 = K, keeping arithmetic in int64 and
    avoiding 64-bit address overflow.
    """
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size < 5:
        return []
    modrm = arr[:-4]
    cand = np.nonzero((modrm & 0xC7) == 0x05)[0]
    if cand.size == 0:
        return []
    disp = (arr[cand + 1].astype(np.uint32)
            | (arr[cand + 2].astype(np.uint32) << 8)
            | (arr[cand + 3].astype(np.uint32) << 16)
            | (arr[cand + 4].astype(np.uint32) << 24)).astype(np.int32)
    K = target - base - 5
    hit = (disp.astype(np.int64) + cand.astype(np.int64)) == K
    return [base + int(i) for i in cand[hit].tolist()]


def _rip_raw_regex(data, base, target):
    """
    numpy-free engine. The C regex engine locates candidate ModR/M bytes, so the
    Python loop only walks the few hits. Returns candidate modrm addresses.
    Same condition: disp32 + i == target - base - 5 = K.
    """
    K = target - base - 5
    limit = len(data) - 4
    out = []
    for m in _RIP_MODRM_RE.finditer(data):
        i = m.start()
        if i >= limit:
            continue
        disp = struct.unpack_from("<i", data, i + 1)[0]
        if disp + i == K:
            out.append(base + i)
    return out


def scan_absolute(target, segments, found):
    """Scan for absolute references: target appears verbatim as a little-endian
    pointer/immediate."""
    psize = _ptr_size()
    needle = target.to_bytes(psize, "little")

    for seg_start, seg_end in segments:
        if ida_kernwin.user_cancelled():
            return
        data = _read_segment(seg_start, seg_end)
        pos = data.find(needle)
        while pos != -1:
            hit_ea = seg_start + pos
            start, size = _find_insn_start(hit_ea + psize, target)
            if start is not None:
                _add_result(found, start, size, "absolute-code", target)
            else:
                _add_result(found, hit_ea, psize, "absolute-data", target)
            pos = data.find(needle, pos + 1)


# --------------------------------------------------------------------------- #
# Results and materialization
# --------------------------------------------------------------------------- #
def _add_result(found, ea, size, kind, target):
    if ea in found:
        return
    found[ea] = {
        "ea": ea,
        "size": size,
        "kind": kind,
        "target": target,
        "defined": not ida_bytes.is_unknown(ida_bytes.get_flags(ea)),
    }


def materialize(result):
    """Force IDA to define the reference so it shows up in xrefs. Returns True
    if something was created."""
    ea = result["ea"]
    kind = result["kind"]

    if kind in ("rip-relative", "absolute-code"):
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE,
                                max(result["size"], 1))
        return ida_ua.create_insn(ea) > 0

    if kind == "absolute-data":
        psize = _ptr_size()
        if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
            if psize == 8:
                ida_bytes.create_qword(ea, 8, True)
            else:
                ida_bytes.create_dword(ea, 4, True)
        reftype = ida_nalt.REF_OFF64 if psize == 8 else ida_nalt.REF_OFF32
        ida_offset.op_offset(ea, 0, reftype, result["target"])
        return True

    return False


def has_xref(target):
    for _ in idautils.XrefsTo(target):
        return True
    return False


# --------------------------------------------------------------------------- #
# UI: results list
# --------------------------------------------------------------------------- #
class XrefResultChooser(ida_kernwin.Choose):
    def __init__(self, target, results):
        title = "Find Xrefs - references to %#x" % target
        cols = [
            ["Address", 18],
            ["Type", 16],
            ["State", 12],
            ["Preview", 50],
        ]
        super().__init__(title, cols, flags=ida_kernwin.Choose.CH_MODAL)
        self.results = results

    def OnGetSize(self):
        return len(self.results)

    def OnGetLine(self, n):
        r = self.results[n]
        state = "defined" if r["defined"] else "undefined"
        return ["%#x" % r["ea"], r["kind"], state, _preview(r["ea"])]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.results[n]["ea"])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


def _preview(ea):
    txt = ida_bytes.get_bytes(ea, 8) or b""
    return " ".join("%02X" % b for b in txt)


# --------------------------------------------------------------------------- #
# Main logic
# --------------------------------------------------------------------------- #
def run_find_xrefs():
    target = ida_kernwin.get_screen_ea()
    if target == ida_idaapi.BADADDR:
        ida_kernwin.warning("No address under the cursor.")
        return

    head = ida_bytes.get_item_head(target)
    if head != ida_idaapi.BADADDR:
        target = head

    scan_code_only = ida_kernwin.ask_yn(
        1, "Scan code segments ONLY?\n"
           "(No = scan the whole database, slower)")
    if scan_code_only == -1:
        return

    segments = list(_iter_segments(code_only=bool(scan_code_only)))
    if not segments:
        ida_kernwin.warning("No loaded segments to scan.")
        return

    found = {}
    ida_kernwin.show_wait_box("Find Xrefs: scanning memory...")
    try:
        scan_rip_relative(target, segments, found)
        if not ida_kernwin.user_cancelled():
            scan_absolute(target, segments, found)
    finally:
        ida_kernwin.hide_wait_box()

    if ida_kernwin.user_cancelled():
        ida_kernwin.msg("[Find Xrefs] Cancelled by user.\n")
        return

    results = sorted(found.values(), key=lambda r: r["ea"])
    if not results:
        ida_kernwin.info("No references found to %#x." % target)
        return

    undefined = [r for r in results if not r["defined"]]
    ida_kernwin.msg(
        "[Find Xrefs] %d reference(s) to %#x (%d undefined).\n"
        % (len(results), target, len(undefined)))

    XrefResultChooser(target, results).Show(True)

    if ida_kernwin.ask_yn(
            1,
            "Materialize %d reference(s) so they show up in xrefs?\n"
            "Undefined regions will be turned into code/offset."
            % len(results)) != 1:
        return

    created = 0
    total = len(results)
    ida_kernwin.show_wait_box("Find Xrefs: creating references...")
    try:
        for idx, r in enumerate(results):
            if ida_kernwin.user_cancelled():
                break
            ida_kernwin.replace_wait_box(
                "Find Xrefs: creating references %d/%d" % (idx + 1, total))
            if materialize(r):
                created += 1
        # No ida_auto.auto_wait() here: on a half-analyzed large binary it would
        # block until ALL autoanalysis finishes (looks like a hang). Not needed:
        # create_insn/op_offset register the xref immediately.
    finally:
        ida_kernwin.hide_wait_box()

    ida_kernwin.refresh_idaview_anyway()

    ida_kernwin.msg(
        "[Find Xrefs] %d reference(s) materialized. Press X on the string.\n"
        % created)

    if has_xref(target):
        ida_kernwin.info(
            "Done: %d reference(s) created.\n"
            "They now appear in the xrefs of %#x." % (created, target))
    else:
        ida_kernwin.info(
            "Processed %d candidate(s) but IDA produced no xrefs "
            "(the region may already be defined another way)." % created)


# --------------------------------------------------------------------------- #
# IDA integration
# --------------------------------------------------------------------------- #
class FindXrefsPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Find and materialize hidden xrefs to the current address"
    help = __doc__
    wanted_name = PLUGIN_NAME
    # wanted_hotkey both binds the shortcut and shows it as the hint next to the
    # entry in Edit > Plugins. Being the only registration, there is no
    # "Conflicting shortcut".
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        ida_kernwin.msg("[Find Xrefs] loaded. Hotkey: %s\n" % PLUGIN_HOTKEY)
        if _HAVE_NUMPY:
            ida_kernwin.msg("[Find Xrefs] numpy OK: vectorized engine active.\n")
        else:
            ida_kernwin.msg(
                "[Find Xrefs] numpy unavailable (%s).\n"
                "[Find Xrefs] Using regex engine (fast, no numpy). To enable "
                "numpy: pip install --force-reinstall numpy in IDA's Python.\n"
                % (_NUMPY_ERR or "not installed"))
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        run_find_xrefs()


def PLUGIN_ENTRY():
    return FindXrefsPlugin()
