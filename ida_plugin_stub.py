"""
This is a stub file to be dropped in IDA plugins directory (usually ~/.idapro/plugins)
You should install pacxplorer-ng package globally in your python installation (When developing, use an editable install...)
Make sure that this is the python version that IDA is using (otherwise you can switch with idapyswitch...)
Then copy:
- ida_plugin_stub.py to ~/idapro/plugins/pacxplorer-ng/ida_plugin_stub.py
- ida-plugin.json to ~/idapro/plugins/pacxplorer-ng/ida_plugin.json
"""

# noinspection PyUnresolvedReferences
__all__ = ["PLUGIN_ENTRY", "PacxplorerNGPlugin"]
try:
    from pacxplorerng.ida_plugin import PLUGIN_ENTRY, PacxplorerNGPlugin
except ImportError:
    print("[Error] Could not load Pacxplorer-NG plugin. pacxplorer-ng Python package doesn't seem to be installed.")
