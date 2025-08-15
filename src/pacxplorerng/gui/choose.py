__all__ = ["FuncXrefChooser", "MovkXrefChooser"]

from typing import Generic, NamedTuple, TypeVar

import idaapi
import idc
from ida_kernwin import Choose, action_handler_t

from pacxplorerng.definitions import VtablePacEntry

T = TypeVar("T", bound=tuple)


class SimpleChoose(Choose, Generic[T]):
    # Fix Choose.UI_Hooks_Trampoline to work with modal dialogs
    # noinspection PyPep8Naming
    class UI_Hooks_Trampoline(Choose.UI_Hooks_Trampoline):
        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if hasattr(chooser, "OnPopup") and callable(chooser.OnPopup):
                chooser.OnPopup(form, popup_handle)

    # noinspection PyPep8Naming
    class chooser_handler_t(action_handler_t):
        def __init__(self, handler):
            super().__init__()
            self.handler = handler

        def activate(self, ctx):
            self.handler()
            return 1

        def update(self, ctx):
            return (
                idaapi.AST_ENABLE_FOR_WIDGET
                if idaapi.is_chooser_widget(ctx.widget_type)
                else idaapi.AST_DISABLE_FOR_WIDGET
            )

    def __init__(self, title: str, items: list[T], columns: list):
        super().__init__(title, columns, flags=Choose.CH_RESTORE)

        self.items: list[T] = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def show(self):
        selected = self.Show(modal=True)
        if selected < 0:
            return None
        return self.items[selected]


class MovkXrefItem(NamedTuple):
    address: str
    method: str
    clazz: str


class MovkXrefChooser(SimpleChoose[MovkXrefItem]):
    unique_functions = True

    def __init__(self, ea: int, entries: list[VtablePacEntry]):
        super().__init__(
            f"PAC xrefs from 0x{ea:016X}",
            MovkXrefChooser._create_items(entries),
            [
                ["Address", 20 | Choose.CHCOL_HEX],
                ["Method", 40 | Choose.CHCOL_PLAIN],
                ["Class", 30 | Choose.CHCOL_PLAIN],
            ],
        )

        self.all_items: list[MovkXrefItem] = self.items
        self.apply_unique()

    def OnPopup(self, form, popup_handle):
        idaapi.attach_action_to_popup(form, popup_handle, "-", None, idaapi.SETMENU_FIRST)

        desc = idaapi.action_desc_t(
            "pacxplorer-ng:choose:unique",
            "PAC: toggle unique function names",
            self.chooser_handler_t(self.toggle_unique),
        )
        idaapi.attach_dynamic_action_to_popup(form, popup_handle, desc, None, idaapi.SETMENU_FIRST)

    def OnRefresh(self, n):
        return Choose.ALL_CHANGED, 0

    def apply_unique(self):
        """Apply the unique function names setting."""
        if MovkXrefChooser.unique_functions:
            unique_dict: dict[tuple[str, str], str] = {}
            for address, method, clazz in self.all_items:
                if clazz != unique_dict.setdefault((address, method), clazz):
                    unique_dict[(address, method)] = "<multiple classes>"
            self.items = sorted(
                (MovkXrefItem(address, method, clazz) for (address, method), clazz in unique_dict.items()),
                key=lambda item: item.address,
            )

        else:
            self.items = self.all_items

    def toggle_unique(self):
        MovkXrefChooser.unique_functions = not MovkXrefChooser.unique_functions
        self.apply_unique()
        self.Refresh()

    @staticmethod
    def _create_items(entries: list[VtablePacEntry]) -> list[MovkXrefItem]:
        items = []
        for entry in entries:
            print(hex(entry.vtable_addr), _demangle(entry.vtable_addr))
            items.append(
                MovkXrefItem(
                    address=f"0x{entry.method_addr:016X}",
                    method=_demangle(entry.method_addr),
                    clazz=_demangle(entry.vtable_addr),
                )
            )
        return items


class FuncXrefItem(NamedTuple):
    address: str
    address_textual: str


class FuncXrefChooser(SimpleChoose[FuncXrefItem]):
    def __init__(self, func_ea: int, eas: list[int]):
        super().__init__(
            f"PAC xrefs to: 0x{func_ea:016X}",
            self._create_items(eas),
            [
                ["Address (hex)", 15 | Choose.CHCOL_HEX],
                ["Address", 30 | Choose.CHCOL_PLAIN],
            ],
        )

    @staticmethod
    def _create_items(eas: list[int]) -> list[FuncXrefItem]:
        return [
            FuncXrefItem(
                address=f"0x{ea:016X}",
                address_textual=idc.get_func_off_str(ea),
            )
            for ea in eas
        ]


def _demangle(ea: int) -> str:
    name = idc.get_name(ea, idc.GN_LONG)
    demangled = (idaapi.demangle_name(str(name), idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)) or "").replace(
        "`vtable for'", ""
    )
    return demangled or name
