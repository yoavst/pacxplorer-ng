import typing

import idaapi
from idaapi import AST_ENABLE_ALWAYS, action_desc_t, action_handler_t, register_action, unregister_action

if typing.TYPE_CHECKING:
    from ..ida_plugin import PacxplorerNGPlugin


class MenuBase(action_handler_t):
    label: str = None
    shortcut: str = None
    tooltip: str = None
    icon: int = -1

    def __init__(self, plugin: "PacxplorerNGPlugin"):
        super().__init__()
        self.plugin: PacxplorerNGPlugin = plugin
        self.name = self.plugin.wanted_name + ":" + self.__class__.__name__
        self.register()

    def register(self):
        return register_action(
            action_desc_t(
                self.name,  # Name. Acts as an ID. Must be unique.
                self.label,  # Label. That's what users see.
                self,  # Handler. Called when activated, and for updating
                self.shortcut,  # shortcut,
                self.tooltip,  # tooltip
                self.icon,  # icon
            )
        )

    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        unregister_action(self.name)

    def attach_to_menu(self) -> bool:
        """Attach the action to the menu."""
        return idaapi.attach_action_to_menu(self.path(), self.name, idaapi.SETMENU_APP)

    def activate(self, ctx) -> int:
        # dummy method
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS

    def path(self):
        return "Edit/Plugins/" + self.plugin.wanted_name + "/" + self.label

    def get_name(self):
        return self.name


class AnalyzeMenu(MenuBase):
    label = "Analyze IDB..."
    tooltip = "Analyze the current IDB for PAC codes and vtables"

    def activate(self, ctx):
        self.plugin.explorer.analyze()
        return 1


class JumpXrefMenu(MenuBase):
    label = "Jump to PAC XREFs..."
    shortcut = "Meta-X"
    icon = 151

    def activate(self, ctx):
        self.plugin.coordinator.jump_pac_xrefs(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE if self.plugin.coordinator.can_jump_pac_xrefs(ctx) else idaapi.AST_DISABLE
