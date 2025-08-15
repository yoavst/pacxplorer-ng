__all__ = ["PLUGIN_ENTRY", "PacxplorerNGPlugin"]

import json
from contextlib import suppress

import ida_idaapi
import idaapi
from ida_idaapi import plugin_t
from ida_kernwin import UI_Hooks
from netnode import Netnode

from .coordinator import Coordinator
from .explorer import AnalysisNotDoneError, Explorer
from .gui.actions import AnalyzeMenu, JumpXrefMenu, MenuBase

NETNODE_IO = "$ pacxplorer_io"
NETNODE_RESULT_INPUT = "input"
NETNODE_RESULT_OUTPUT = "output"
ARG_PAC_CANDIDATES_FROM_MOVK = 5
ARG_PAC_XREFS_TO_ADDRESS = 6


class PacxplorerNGPlugin(plugin_t, UI_Hooks):
    flags = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
    comment = "find xrefs for vtable methods using PAC codes"
    help = ""
    wanted_name = "PacXplorer-NG"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.explorer: Explorer = Explorer()
        self.coordinator: Coordinator = Coordinator(self.explorer)
        self.actions: list[MenuBase] = []
        self.jump_xref_action: MenuBase | None = None
        self.input_output_netnode: Netnode | None = None

    def init(self):
        typename = idaapi.get_file_type_name().lower()
        if "arm64e" not in typename:
            print(f"[{self.wanted_name}] IDB deemed unsuitable (not an ARM64e binary). Skipping...")
            return idaapi.PLUGIN_SKIP

        self.input_output_netnode = Netnode(NETNODE_IO)

        self.hook()
        print(f"[{self.wanted_name}] IDB deemed suitable. Initializing...")

        return idaapi.PLUGIN_KEEP

    def term(self):
        print(f"[{self.wanted_name}] Terminating...")
        self.unhook()
        for action in self.actions:
            action.unregister()

    def ready_to_run(self):
        # Load analysis results if they are already cached
        with suppress(AnalysisNotDoneError):
            self.explorer.analyze(only_cached=True)

        self.jump_xref_action = JumpXrefMenu(self)
        self.actions = [AnalyzeMenu(self)]
        for action in self.actions:
            action.attach_to_menu()

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        """UI_Hooks function - Attaches the Find Xref action to the disassembly/pseudocode right click menu."""
        if not self.explorer.analysis_done or self.jump_xref_action is None:
            return

        widget_type = idaapi.get_widget_type(widget)
        if widget_type == idaapi.BWN_DISASM or widget_type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup_handle, "-", None, idaapi.SETMENU_FIRST)
            idaapi.attach_action_to_popup(widget, popup_handle, self.jump_xref_action.name, None, idaapi.SETMENU_FIRST)

    def run(self, arg=0):
        """plugin_t run() implementation"""
        if arg in [ARG_PAC_CANDIDATES_FROM_MOVK, ARG_PAC_XREFS_TO_ADDRESS]:
            input_ea = self.input_output_netnode.get(NETNODE_RESULT_INPUT)
            self.input_output_netnode.kill()
            if input_ea is None:
                print(f"[{self.wanted_name}] call {arg:d}: did not receive argument for")
                return
            elif not self.explorer.analysis_done:
                print(f"[{self.wanted_name}] call {arg:d}: Analysis was not done")
                return

            if arg == ARG_PAC_CANDIDATES_FROM_MOVK:
                candidates = self.explorer.movk_to_functions(input_ea)
                result_serialized = json.dumps([candidate._asdict() for candidate in candidates])
                self.input_output_netnode[NETNODE_RESULT_OUTPUT] = result_serialized
            else:
                movks = self.explorer.function_to_movks(input_ea)
                result_serialized = json.dumps(movks)
                self.input_output_netnode[NETNODE_RESULT_OUTPUT] = result_serialized


# noinspection PyPep8Naming
def PLUGIN_ENTRY() -> plugin_t:
    return PacxplorerNGPlugin()
