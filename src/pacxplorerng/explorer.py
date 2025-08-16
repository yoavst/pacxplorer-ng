import time

import idaapi
import idc

from .analyzers.movk import analyze_all as movk_analyze
from .analyzers.vtable import analyze as vtable_analyze
from .definitions import PLUGIN_NAME, ExplorerProtocol, PacTuple, VtablePacEntry
from .storage.netnodes import PickleNetNode

NETNODE_NAME = "$ pacxplorerng-ng"
ANALYSIS_DONE_KEY = "analysis_done"
VTABLE_ENTRIES_KEY = "vtable_entries"
MOVK_ENTRIES_KEY = "movk_entries"


class AnalysisNotDoneError(Exception):
    def __init__(self):
        super().__init__("Analysis not done yet. Please run the analysis first.")


class Explorer(ExplorerProtocol):
    _INSTANCE: "Explorer" = None

    def __init__(self):
        self._cache = PickleNetNode(NETNODE_NAME)
        self._analysis_done = False

        self._funcs_by_code: dict[PacTuple, list[VtablePacEntry]] = {}
        """Mapping of PAC codes to their possible corresponding function entries. Helps in solving call site => function candidates."""
        self._code_by_func: dict[int, PacTuple] = {}
        """Mapping of function addresses to their PAC codes. Helps in solving function function => candidates call sites."""
        self._codes_by_movk: dict[int, PacTuple] = {}
        """Mapping of MOVK instruction addresses to their PAC codes. Helps in solving call site => function candidates."""
        self._movks_by_code: dict[PacTuple, list[int]] = {}
        """Mapping of PAC codes to their possible MOVK instruction addresses. Helps in solving function => candidates call sites."""

    @staticmethod
    def get_instance() -> "Explorer":
        """Get the singleton instance of the Explorer."""
        if Explorer._INSTANCE is None:
            Explorer._INSTANCE = Explorer()
        return Explorer._INSTANCE

    def analyze(self, only_cached: bool = False) -> None:
        analysis_done = self._cache.get(ANALYSIS_DONE_KEY, False)
        if only_cached:
            if not analysis_done:
                raise AnalysisNotDoneError()
            print(f"[{PLUGIN_NAME}] this IDB had been previously analyzed, loading from cache")
        elif analysis_done:
            answer = idc.ask_yn(idaapi.ASKBTN_NO, "HIDECANCEL\nRe-analyze the IDB?")
            if answer != idaapi.ASKBTN_YES:
                return
            self._cache.kill()
            self._analysis_done = False

        idaapi.show_wait_box(f"HIDECANCEL\n{PLUGIN_NAME} analyzing...")
        try:
            self._perform_analyze()
            self._analysis_done = True
            self._cache[ANALYSIS_DONE_KEY] = True

        finally:
            idaapi.hide_wait_box()
            if not self._analysis_done:
                self._cache.kill()

    def _perform_analyze(self):
        print(f"[{PLUGIN_NAME}] Performing analysis for virtual table entries...")
        before = time.time_ns()
        vtable_entries = self._cache.get_or(VTABLE_ENTRIES_KEY, vtable_analyze)
        if len(vtable_entries) == 0:
            idaapi.warning(
                f"{PLUGIN_NAME}\nUnable to find vtables and pac codes.\n"
                "If this is a KernelCache:\n"
                "make sure ida_kernelcache is run on this idb"
            )
        else:
            time_took_ms = int((time.time_ns() - before) / 1_000_000)
            print(f"[{PLUGIN_NAME}] Found {len(vtable_entries)} vtable entries. Took: {time_took_ms}ms")
        funcs_by_code: dict[PacTuple, list[VtablePacEntry]] = {}
        code_by_func: dict[int, PacTuple] = {}

        for entry in vtable_entries:
            pac_tuple = PacTuple(entry.offset, entry.pac)
            funcs_by_code.setdefault(pac_tuple, []).append(entry)
            code_by_func[entry.method_addr] = pac_tuple

        self._funcs_by_code = funcs_by_code
        self._code_by_func = code_by_func

        print(f"[{PLUGIN_NAME}] Performing analysis for MOVK entries...")
        before = time.time_ns()
        movk_entries = self._cache.get_or(MOVK_ENTRIES_KEY, movk_analyze)
        if len(movk_entries) == 0:
            idaapi.warning(f"{PLUGIN_NAME}\nUnable to find movk pac codes.\nThis is weird...")
        else:
            time_took_ms = int((time.time_ns() - before) / 1_000_000)
            print(f"[{PLUGIN_NAME}] Found {len(movk_entries)} MOVK entries. Took : {time_took_ms}ms")

        codes_by_movk: dict[int, PacTuple] = {}
        movks_by_code: dict[PacTuple, list[int]] = {}
        for movk in movk_entries:
            codes_by_movk[movk.movk_addr] = movk.pac_tuple
            movks_by_code.setdefault(movk.pac_tuple, []).append(movk.movk_addr)
        self._codes_by_movk = codes_by_movk
        self._movks_by_code = movks_by_code

        print(f"[{PLUGIN_NAME}] Analysis completed.")

    def movk_to_functions(self, movk_ea: int) -> list[VtablePacEntry]:
        if not self._analysis_done:
            raise AnalysisNotDoneError()

        pac_tuple = self._codes_by_movk.get(movk_ea)
        if pac_tuple is None:
            return []
        return self._funcs_by_code.get(pac_tuple, [])

    def function_to_movks(self, func_ea: int) -> list[int]:
        if not self._analysis_done:
            raise AnalysisNotDoneError()

        pac_tuple = self._code_by_func.get(func_ea)
        if pac_tuple is None:
            return []
        return self._movks_by_code.get(pac_tuple, [])

    def is_pac_function(self, func_ea: int) -> bool:
        return func_ea in self._code_by_func

    @property
    def analysis_done(self) -> bool:
        """Check if the analysis has been done."""
        return self._analysis_done
