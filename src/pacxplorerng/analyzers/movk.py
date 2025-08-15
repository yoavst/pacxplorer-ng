__all__ = ["analyze_all", "analyze_func"]

from typing import Union, cast

import capstone.arm64
import ida_bytes
import idaapi
import idautils
import idc
from capstone.aarch64_const import AARCH64_OP_IMM, AARCH64_OP_REG, AARCH64_SFT_LSL
from ida_funcs import func_t

from ..definitions import MovkCodeTuple, PacTuple

GOOD_MOVK_COMMENT = "This MOVK has PAC xrefs"
BAD_STATIC_VTBL_MOVK_COMMENT = "This MOVK has **NO** PAC xrefs (static vtable)"
BAD_ERROR_MOVK_COMMENT = "This MOVK has **NO** PAC xrefs (analysis error, please report!)"
BAD_INDIRECT_REG_VAL = "Could not find register value for indirect op (analysis error, please report!)"

MAX_INSNS_BACK_FOR_CONST_REGISTER = 20

md = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
md.detail = True


class FuncMovKAnalyzer:
    def __init__(self, func_start_ea: int):
        self._func: func_t = idaapi.get_func(func_start_ea)

        if self._func is None:
            raise ValueError("Function not found at the specified address.")

        func_bytes = ida_bytes.get_bytes(self._func.start_ea, self._func.end_ea - self._func.start_ea)
        self._func_insns: dict[int, capstone.CsInsn] = {
            i.address: i for i in md.disasm(func_bytes, self._func.start_ea)
        }

    def analyze(self) -> list[MovkCodeTuple]:
        movks: list[MovkCodeTuple] = []
        for addr, insn in self._func_insns.items():
            if insn.mnemonic != "movk":
                continue
            pac_tuple = self._analyze_movk(insn)
            if pac_tuple is not None:
                movks.append(MovkCodeTuple(pac_tuple, addr))
        return movks

    def _analyze_movk(self, movk_insn: capstone.CsInsn) -> PacTuple | None:  # noqa: C901
        # Given movk instruction of the form: MOVK X17, #0xCDA1,LSL#48
        movk_op1, movk_op2 = cast(list[capstone.aarch64.AArch64Op], movk_insn.operands)

        # Verify that: the first operand is a register, the second operand has a shift of 48 bits
        if movk_op1.type != AARCH64_OP_REG or movk_op2.shift.type != AARCH64_SFT_LSL or movk_op2.shift.value != 48:
            return None

        # Extract the pac value, and the context register.
        ctx_reg = movk_op1.reg
        movk_code = movk_op2.imm

        # Search for the previous instruction that sets the context register to extract the vtable offset.
        current_instruction = movk_insn.address
        visited_addresses: set[int] = set()
        offset = 0
        while True:
            # Get previous instruction, if there is no previous instruction or already visited this, return None
            current_instruction = self._get_previous_instruction(current_instruction)
            if current_instruction is None or current_instruction in visited_addresses:
                return None
            visited_addresses.add(current_instruction)

            insn = self._func_insns[current_instruction]
            mnem = insn.mnemonic
            # print(
            #     f"current_instruction: {current_instruction:x}, {insn} ; state: {offset=:X} {movk_code=:X}, ctx_reg={insn.reg_name(ctx_reg)}"
            # )

            # Every instruction we care about has at least one operand. Continue going up.
            if len(insn.operands) == 0:
                continue
            op1 = insn.operands[0]

            # We authenticated the ctx register, so it is probably a vtable. We can stop here
            if (mnem == "autdza" or mnem == "autda") and op1.type == AARCH64_OP_REG and op1.reg == ctx_reg:
                self._add_comment(movk_insn.address, GOOD_MOVK_COMMENT)
                return PacTuple(offset, movk_code)

            regs_read, regs_write = insn.regs_access()

            if ctx_reg in regs_write:
                if not regs_read:
                    # If it modifies insn the context register using a constant value, it is likely a static vtable.
                    # We don't support static vtables yet...
                    self._add_comment(movk_insn.address, BAD_STATIC_VTBL_MOVK_COMMENT)
                    return None
                elif mnem == "mov":
                    # It is a MOV instruction with a register. So we need to follow the new register instead
                    # MOVK ctx_reg, other_reg
                    ctx_reg = insn.operands[1].reg
                    # print(f"Following new register: {insn.reg_name(ctx_reg)}")
                elif mnem == "add":
                    # It is an ADD instruction with a register. So we need to follow the new register instead, and update the base offset.
                    # According to ARM documents, only op3 can be an immediate value.
                    ctx_reg = insn.operands[1].reg
                    op3 = insn.operands[2]

                    if op3.type == AARCH64_OP_IMM:
                        # We can just add the immediate value to the offset.
                        offset += op3.imm
                    elif op3.type == AARCH64_OP_REG:
                        # We need to find the constant value assigned to this register.
                        op3_reg_val = self._find_const_assignment_to_register(insn, op3.reg)
                        if op3_reg_val is None:
                            return None
                        offset += op3_reg_val
                    else:
                        # Should not be possible AFAIK
                        return None
                elif mnem == "ldr" and insn.writeback and insn.operands[1].mem.base == ctx_reg:
                    # It is an LDR instruction with writeback, which means it is loading the entry from vtable
                    # LDR X9, [X8,#0x18]!     ; X8 = vtbl + offset
                    # We want to extract the offset here.
                    offset += insn.operands[1].mem.disp
                else:
                    # Pacxplorer original code has it. Not really sure what reaches here.
                    # TODO check it
                    return None

    def _find_const_assignment_to_register(self, insn: capstone.CsInsn, reg: int) -> int | None:
        """Find the instruction that assigns a constant value to the specified register."""
        for _ in range(MAX_INSNS_BACK_FOR_CONST_REGISTER):
            previous_insn_addr = self._get_previous_instruction(insn.address)
            if previous_insn_addr is None:
                break
            insn = self._func_insns.get(previous_insn_addr)
            if insn.mnemonic != "mov":
                continue
            op1 = insn.operands[0]
            if op1.type == AARCH64_OP_REG and op1.reg == reg:
                # Found the instruction that assigns a constant value to the register
                return insn.operands[1].imm

        self._add_comment(insn.address, BAD_INDIRECT_REG_VAL)
        return None

    def _get_previous_instruction(self, current_address: int) -> int | None:
        """Get the previous instruction before the current address."""
        return next(
            (x for x in idautils.CodeRefsTo(current_address, True) if x in self._func_insns and x != current_address),
            None,
        )

    @staticmethod
    def _add_comment(addr: int, comment: str):
        """Add a comment to the specified address in the function."""
        current_comment = idc.get_cmt(addr, True)
        new_comment = FuncMovKAnalyzer._edit_comment(current_comment, comment)
        idc.set_cmt(addr, new_comment, True)

    @staticmethod
    def _edit_comment(current_comment: Union[str, None], new_comment: str):
        if current_comment is None:
            current_comment = ""
        if new_comment not in current_comment:
            current_comment = current_comment.rstrip()
            if current_comment:
                current_comment += "\n"
            current_comment += new_comment
        return current_comment


def analyze_func(func_ea: int) -> list[MovkCodeTuple]:
    """
    Analyze the function at the specified address for MOVK instructions and PAC information.
    """
    analyzer = FuncMovKAnalyzer(func_ea)
    return analyzer.analyze()


def analyze_all() -> list[MovkCodeTuple]:
    """Analyze all functions in the IDA database for MOVK instructions and PAC information."""
    movk_codes = []
    for func in idautils.Functions():
        analyzer = FuncMovKAnalyzer(func)
        movk_codes.extend(analyzer.analyze())

    return movk_codes
