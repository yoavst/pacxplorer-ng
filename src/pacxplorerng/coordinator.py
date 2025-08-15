import ida_hexrays
import idaapi
import idautils
import idc
from ida_hexrays import cfuncptr_t

from pacxplorerng.explorer import Explorer
from pacxplorerng.gui.choose import FuncXrefChooser, MovkXrefChooser


class Coordinator:
    def __init__(self, explorer: Explorer):
        self.explorer = explorer

    def jump_pac_xrefs(self, ctx):
        ea = self._get_ea_for_jump(ctx)
        if self._has_movk_xrefs(ea):
            chooser = MovkXrefChooser(ea, self.explorer.movk_to_functions(ea))
        elif (func_ea := self._has_vtable_xrefs(ea)) is not None:
            chooser = FuncXrefChooser(func_ea, self.explorer.function_to_movks(func_ea))
        else:
            return

        chosen = chooser.show()
        if chosen is None:
            return
        idaapi.jumpto(int(chosen[0], 16))

    def can_jump_pac_xrefs(self, ctx) -> bool:
        """Check if we can jump to PAC xrefs based on the current context."""
        if not self.explorer.analysis_done:
            return False

        ea = self._get_ea_for_jump(ctx)
        return self._has_movk_xrefs(ea) or self._has_vtable_xrefs(ea) is not None

    @staticmethod
    def _get_ea_for_jump(ctx) -> int:
        """Get the EA the user expects us to search for xrefs to/from."""
        if idaapi.get_widget_type(ctx.widget) == idaapi.BWN_PSEUDOCODE:
            return _get_movk_ea_from_current_decompile(ctx.widget) or idc.here()
        else:
            return idc.here()

    def _has_movk_xrefs(self, ea: int) -> bool:
        return bool(self.explorer.movk_to_functions(ea))

    def _has_vtable_xrefs(self, ea: int) -> int | None:
        if self.explorer.is_pac_function(ea):
            return ea

        # Convert vtable entry address to function address
        refs = list(idautils.DataRefsFrom(idc.get_item_head(ea)))
        if len(refs) != 1:
            return None
        else:
            func_addr = refs[0]
            return func_addr if self.explorer.is_pac_function(func_addr) else None


# region IDA utilities
def _get_movk_ea_from_current_decompile(widget) -> int | None:  # noqa: C901
    vu = ida_hexrays.get_widget_vdui(widget)
    if vu is None:
        return None

    if not vu.get_current_item(ida_hexrays.USE_KEYBOARD):
        return None

    cfunc = vu.cfunc
    if cfunc is None:
        return None

    if vu.item.citype in [ida_hexrays.VDI_FUNC, ida_hexrays.VDI_LVAR]:
        return cfunc.entry_ea

    if not vu.get_current_item(ida_hexrays.USE_KEYBOARD) or not vu.item.is_citem():
        return None

    citem = vu.item.e
    if citem is None or cfunc is None:
        return None

    cfunc_body = cfunc.body
    has_seen_call = False
    while citem is not None:
        citem = citem.cexpr if citem.is_expr() else citem.cinsn
        if citem.op == ida_hexrays.cot_call:
            has_seen_call = True

        if has_seen_call:
            call_ea = _find_call_ea_from_ea(cfunc, citem.ea)
            if call_ea is not None:
                movk_ea = _get_previous_movk(call_ea)
                if movk_ea is not None:
                    return movk_ea
                break
        citem = cfunc_body.find_parent_of(citem)
    return None


def _find_call_ea_from_ea(cfunc: cfuncptr_t, item_ea: int) -> int | None:
    ea_map = cfunc.get_eamap()
    insn = idautils.DecodeInstruction(item_ea)
    while insn is not None and insn.get_canon_mnem() not in ("BLR", "BR"):
        next_ea = idc.next_head(item_ea)
        # we are not in the same statement anymore
        if next_ea not in ea_map or item_ea not in ea_map or ea_map[item_ea] != ea_map[next_ea]:
            return None
        item_ea = next_ea
        insn = idautils.DecodeInstruction(item_ea)
    if insn is None:
        return None
    return item_ea


def _get_previous_movk(call_ea: int) -> int | None:
    """Given a call, search previous instructions to find a movk call"""
    insn = idautils.DecodeInstruction(call_ea)
    if not insn:
        return None

    if insn.get_canon_mnem() not in ("BLR", "BR"):
        return None

    # Get the register for PAC code
    movk_reg = insn[1].reg
    # BLR with just one register is unauthenticated, so there will be no PAC xref
    if movk_reg == 0:
        return None

    for _ in range(10):
        insn, _ = idautils.DecodePrecedingInstruction(insn.ea)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == "MOVK" and insn[0].reg == movk_reg:
            return insn.ea
    return None


# endregion
