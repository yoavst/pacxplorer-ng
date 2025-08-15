__all__ = ["analyze"]

from collections.abc import Iterator

import idaapi
import idautils

from ..definitions import VtablePacEntry


def analyze() -> list[VtablePacEntry]:
    """Analyze vtables in the database and return a list of VtablePacEntry objects."""

    """
    In case of multiple inheritance, the vtable contains more concatenated vtables in a special way.
    We need to parse the concatenated vtables of the base classes as well as the main one.

    vtable layout with multiple inheritance can look like this:
    <offset to this>
    <rtti>
    vmethod 1
    ...
    vmethod n

    <offset to this> --> this is the vtable of one of the base classes
    <rtti>  --> same rtti as before
    vmethod n+1
    ...
    vmethod m

    <offset of this> --> another base class
    < etc >
    """
    entries: list[VtablePacEntry] = []
    for ea in iterate_vtables():
        vtable_address = ea
        first_rtti_ptr = idaapi.get_qword(ea + 8)
        # first section of the vtable - main vtable.
        # mostly, this is the only part there is.
        # If there are concatenated vtables due to multiple inheritance, iterate over them.
        while True:
            ea += 16  # skip 'this offset' and rtti in vtable
            # offset in the current vtable
            offset = 0
            # now iterate over virtual methods
            while True:
                orig_qword = idaapi.get_original_qword(ea + offset)
                patched_qword = idaapi.get_qword(ea + offset)

                # end of the vtable is detected by encountering not a tagged pointer
                # this is okay even if there are several conjoined vtables back-to-back,
                # due to the first non-ptr element in the vtable
                if orig_qword == patched_qword or orig_qword is None:
                    break

                # this is expected to always succeed
                pac = get_pac(orig_qword)
                if pac is not None:
                    method_addr = idaapi.get_qword(ea + offset)
                    entries.append(VtablePacEntry(method_addr, vtable_address, ea + offset, offset, pac))

                offset += 8

            # if we haven't parsed anything in the inner loop, no need to process this whole vtable anymore
            if offset == 0:
                break
            # in the context of the concatenated vtables loop, skip past the vtable we have just finished
            ea += offset
            # we know there is a concatenated vtable only by encountering the same rtti ptr as the main one.
            # normal case: not concatenated vtable, so break after one iteration
            if first_rtti_ptr == 0 or idaapi.get_qword(ea + 8) != first_rtti_ptr:
                break

    return entries


# Based on https://github.com/Synacktiv-contrib/kernelcache-laundering/blob/master/ios12_kernel_cache_helper.py
def get_pac(decorated_addr: int):
    """Return MOVK pac code from decorated pointer"""
    if decorated_addr & 0x4000000000000000 != 0:
        return None
    if decorated_addr & 0x8000000000000000 == 0:
        return None
    return (decorated_addr >> 32) & 0xFFFF


def iterate_vtables() -> Iterator[int]:
    """Iterate over all vtables in the database, yielding class name and vtable ea."""
    for ea, name in idautils.Names():
        if not name.startswith("__ZTV") and not name.startswith("_ZTV"):
            continue

        demangled = idaapi.demangle_name(name, idaapi.inf_get_short_demnames())
        if not demangled or not demangled.startswith("`vtable for'"):
            continue

        yield ea
