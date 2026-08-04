"""Applies a benzened_trace artifact to the open IDA database.

Run with File > Script file, or `ida -S"apply_trace.py <artifact.json>" <image>`.

Each module is keyed by build id. Applying is refused rather than warned about
when the open image cannot be selected unambiguously, because every offset is
meaningless against a different build.
"""

import json
import sys

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import idaapi
import idautils
import idc


def image_build_id():
    """Reads .note.gnu.build-id out of the loaded image.

    Scans rather than walks the note payload, because these libraries lead with
    zero padding and a zero header has no length to advance by.
    """
    for seg_start in idautils.Segments():
        name = idc.get_segm_name(seg_start)
        if "note" not in name:
            continue
        end = idc.get_segm_end(seg_start)
        at = seg_start
        while at + 12 <= end:
            if ida_bytes.get_dword(at + 8) == 3:
                namesz = ida_bytes.get_dword(at)
                descsz = ida_bytes.get_dword(at + 4)
                if namesz == 4 and 8 <= descsz <= 64:
                    if ida_bytes.get_bytes(at + 12, 4) == b"GNU\0":
                        desc = ida_bytes.get_bytes(at + 16, descsz)
                        return desc.hex()
            at += 4
    return None


def offset_to_ea(offset):
    """Artifact offsets are file offsets, which IDA can map back to an address."""
    ea = idaapi.get_fileregion_ea(offset)
    return None if ea == idaapi.BADADDR else ea


def apply_functions(entries):
    """Creates a function at each recovered entry point.

    A packed library exports almost nothing, so most of these are addresses IDA
    left as raw bytes. Existing functions are left alone.
    """
    made = 0
    for offset in entries:
        ea = offset_to_ea(offset)
        if ea is None or ida_funcs.get_func(ea):
            continue
        if ida_funcs.add_func(ea):
            made += 1
    return made


def apply_sites(sites):
    """Comments each probed site with what was observed and who called it."""
    marked = 0
    for site in sites:
        ea = offset_to_ea(site["offset"])
        if ea is None:
            continue
        lines = ["benzened_trace: {} hits".format(site["hits"])]
        for edge in sorted(site["callers"], key=lambda e: -e["count"]):
            lines.append(
                "  from {}@{:#x} x{}".format(edge["module"], edge["vaddr"], edge["count"])
            )
        idc.set_cmt(ea, "\n".join(lines), 0)
        # A probed site is worth finding again, so it also becomes a named location.
        idc.set_name(ea, "probe_{}".format(site["label"].replace("0x", "")), idc.SN_CHECK)
        marked += 1
    return marked


def select_module(artifact, actual):
    """Selects the one artifact module that belongs to the open image."""
    modules = artifact.get("modules", [])
    if actual:
        matches = [module for module in modules if module.get("build_id") == actual]
        if len(matches) == 1:
            return matches[0]
        ida_kernwin.warning(
            "Refusing to apply.\nNo unique artifact module matches build {}".format(actual)
        )
        return None
    ida_kernwin.warning(
        "Refusing to apply.\nThe image has no build id and the artifact has {} modules".format(
            len(modules)
        )
    )
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else ida_kernwin.ask_file(0, "*.json", "artifact")
    if not path:
        return

    with open(path) as handle:
        artifact = json.load(handle)

    actual = image_build_id()
    module = select_module(artifact, actual)
    if module is None:
        return

    made = apply_functions(module.get("functions", []))
    marked = apply_sites(module.get("sites", []))
    print(
        "apply_trace: {} functions created, {} sites annotated, from {}".format(
            made, marked, path
        )
    )


if __name__ == "__main__":
    main()
