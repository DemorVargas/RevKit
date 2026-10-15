"""Instruction decoding."""

from __future__ import annotations

import unittest

from revkit.emulator.decoder import Decoder
from revkit.emulator.errors import DecodeError
from revkit.emulator.memory import Memory


def decode_one(code: bytes, *, bits: int = 64, base: int = 0x1000):
    mem = Memory(page_bits=12)
    mem.write(base, code)
    return Decoder(mem, bits).decode(base)


def decode_all(code: bytes, *, bits: int = 64, base: int = 0x1000):
    mem = Memory(page_bits=12)
    mem.write(base, code)
    dec = Decoder(mem, bits)
    out = []
    addr = base
    while addr < base + len(code):
        ins = dec.decode(addr)
        out.append(ins)
        addr = ins.next_rip
    return out


class MovTests(unittest.TestCase):
    def test_mov_reg_imm32(self):
        ins = decode_one(bytes.fromhex("b834120000"))
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].reg, 0)
        self.assertEqual(ins.operands[1], 0x1234)

    def test_mov_reg_imm64_with_rex_w(self):
        ins = decode_one(bytes.fromhex("48b83412000000000000"))
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].size, 64)
        self.assertEqual(ins.operands[1], 0x1234)

    def test_mov_reg_reg(self):
        ins = decode_one(bytes.fromhex("4889d8"))  # mov rax, rbx
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].reg, 0)
        self.assertEqual(ins.operands[1].reg, 3)

    def test_mov_rm_reg(self):
        ins = decode_one(bytes.fromhex("8945fc"))  # mov [rbp-4], eax
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].kind, "mem")
        self.assertEqual(ins.operands[0].base, 5)  # rbp
        self.assertEqual(ins.operands[0].disp, -4)

    def test_mov_8_bit_reg(self):
        ins = decode_one(bytes.fromhex("8a00"))  # mov al, [rax]
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].size, 8)
        self.assertEqual(ins.operands[1].size, 8)


class LeaTests(unittest.TestCase):
    def test_lea_rip_relative(self):
        ins = decode_one(bytes.fromhex("488d3511000000"))  # lea rsi, [rip+0x11]
        self.assertEqual(ins.mnemonic, "lea")
        self.assertEqual(ins.operands[0].reg, 6)
        self.assertTrue(ins.operands[1].rip_rel)
        self.assertEqual(ins.operands[1].disp, 0x11)

    def test_lea_with_base_and_index(self):
        ins = decode_one(bytes.fromhex("488d040f"))  # lea rax, [rdi + rcx*1]
        self.assertEqual(ins.mnemonic, "lea")
        op = ins.operands[1]
        self.assertEqual(op.base, 7)  # rdi
        self.assertEqual(op.index, 1)  # rcx
        self.assertEqual(op.scale, 1)

    def test_lea_with_scaled_index(self):
        ins = decode_one(bytes.fromhex("488d04c8"))  # lea rax, [rax + rcx*8]
        self.assertEqual(ins.operands[1].index, 1)
        self.assertEqual(ins.operands[1].scale, 8)


class StackTests(unittest.TestCase):
    def test_push_reg(self):
        ins = decode_one(bytes.fromhex("50"))
        self.assertEqual(ins.mnemonic, "push")
        self.assertEqual(ins.operands[0].reg, 0)

    def test_push_r8_via_rex_b(self):
        ins = decode_one(bytes.fromhex("4150"))
        self.assertEqual(ins.mnemonic, "push")
        self.assertEqual(ins.operands[0].reg, 8)

    def test_push_imm8(self):
        ins = decode_one(bytes.fromhex("6a01"))
        self.assertEqual(ins.mnemonic, "push")
        self.assertEqual(ins.operands[0], 1)

    def test_push_imm32(self):
        ins = decode_one(bytes.fromhex("6800000100"))
        self.assertEqual(ins.mnemonic, "push")
        self.assertEqual(ins.operands[0], 0x10000)

    def test_pop_reg(self):
        ins = decode_one(bytes.fromhex("58"))
        self.assertEqual(ins.mnemonic, "pop")
        self.assertEqual(ins.operands[0].reg, 0)

    def test_ret(self):
        ins = decode_one(bytes.fromhex("c3"))
        self.assertEqual(ins.mnemonic, "ret")

    def test_ret_imm16(self):
        ins = decode_one(bytes.fromhex("c20800"))
        self.assertEqual(ins.mnemonic, "ret")
        self.assertEqual(ins.operands[0], 8)


class ControlFlowTests(unittest.TestCase):
    def test_jmp_rel8(self):
        ins = decode_one(bytes.fromhex("eb05"))
        self.assertEqual(ins.mnemonic, "jmp")
        self.assertEqual(ins.operands[0], 0x1000 + 2 + 5)

    def test_jmp_rel32(self):
        ins = decode_one(bytes.fromhex("e900000100"))
        self.assertEqual(ins.mnemonic, "jmp")
        self.assertEqual(ins.operands[0], 0x1000 + 5 + 0x10000)

    def test_call_rel32(self):
        ins = decode_one(bytes.fromhex("e800000000"))
        self.assertEqual(ins.mnemonic, "call")
        self.assertEqual(ins.operands[0], 0x1000 + 5)

    def test_je_rel8(self):
        ins = decode_one(bytes.fromhex("7405"))
        self.assertEqual(ins.mnemonic, "je")
        self.assertEqual(ins.operands[0], 0x1000 + 2 + 5)

    def test_jnz_rel8(self):
        self.assertEqual(decode_one(bytes.fromhex("7505")).mnemonic, "jne")

    def test_ja_rel32(self):
        ins = decode_one(bytes.fromhex("0f8700000100"))
        self.assertEqual(ins.mnemonic, "ja")

    def test_short_jump_negative(self):
        ins = decode_one(bytes.fromhex("75f6"))
        self.assertEqual(ins.operands[0], 0x1000 + 2 - 10)


class SyscallTests(unittest.TestCase):
    def test_syscall(self):
        ins = decode_one(bytes.fromhex("0f05"))
        self.assertEqual(ins.mnemonic, "syscall")
        self.assertEqual(ins.next_rip, 0x1002)

    def test_ud2(self):
        self.assertEqual(decode_one(bytes.fromhex("0f0b")).mnemonic, "ud2")


class GroupOpcodeTests(unittest.TestCase):
    def test_inc_rm(self):
        ins = decode_one(bytes.fromhex("ffc0"))  # inc eax
        self.assertEqual(ins.mnemonic, "inc")
        self.assertEqual(ins.operands[0].reg, 0)

    def test_dec_rm(self):
        ins = decode_one(bytes.fromhex("48ffc9"))  # dec rcx
        self.assertEqual(ins.mnemonic, "dec")
        self.assertEqual(ins.operands[0].reg, 1)

    def test_call_rm(self):
        ins = decode_one(bytes.fromhex("ffd0"))  # call rax
        self.assertEqual(ins.mnemonic, "call")
        self.assertEqual(ins.operands[0].reg, 0)

    def test_jmp_rm(self):
        ins = decode_one(bytes.fromhex("ffe0"))  # jmp rax
        self.assertEqual(ins.mnemonic, "jmp")

    def test_push_rm_via_group(self):
        ins = decode_one(bytes.fromhex("ff30"))  # push [rax]
        self.assertEqual(ins.mnemonic, "push")

    def test_invalid_ff_group_raises(self):
        with self.assertRaises(DecodeError):
            decode_one(bytes.fromhex("ff38"))  # ff /7 is not valid

    def test_inc_rm8(self):
        ins = decode_one(bytes.fromhex("fec0"))  # inc al
        self.assertEqual(ins.mnemonic, "inc")
        self.assertEqual(ins.operands[0].size, 8)

    def test_test_rm_imm(self):
        ins = decode_one(bytes.fromhex("f7c001000000"))  # test eax, 1
        self.assertEqual(ins.mnemonic, "test")
        self.assertEqual(ins.operands[1], 1)

    def test_not_rm(self):
        ins = decode_one(bytes.fromhex("f7d0"))  # not eax
        self.assertEqual(ins.mnemonic, "not")

    def test_neg_rm(self):
        self.assertEqual(decode_one(bytes.fromhex("f7d8")).mnemonic, "neg")

    def test_mul_rm(self):
        self.assertEqual(decode_one(bytes.fromhex("f7e0")).mnemonic, "mul")

    def test_imul_rm(self):
        self.assertEqual(decode_one(bytes.fromhex("f7e8")).mnemonic, "imul")

    def test_div_rm(self):
        self.assertEqual(decode_one(bytes.fromhex("f7f0")).mnemonic, "div")

    def test_idiv_rm(self):
        self.assertEqual(decode_one(bytes.fromhex("f7f8")).mnemonic, "idiv")

    def test_shifts_by_reg_field(self):
        self.assertEqual(decode_one(bytes.fromhex("d1e0")).mnemonic, "shl")  # shl eax, 1
        self.assertEqual(decode_one(bytes.fromhex("d1e8")).mnemonic, "shr")
        self.assertEqual(decode_one(bytes.fromhex("d1f8")).mnemonic, "sar")
        self.assertEqual(decode_one(bytes.fromhex("d3e0")).mnemonic, "shl")  # by cl

    def test_shift_with_imm_count(self):
        ins = decode_one(bytes.fromhex("c1e003"))  # shl eax, 3
        self.assertEqual(ins.mnemonic, "shl")
        self.assertEqual(ins.operands[1], 3)


class TwoByteTests(unittest.TestCase):
    def test_movzx(self):
        ins = decode_one(bytes.fromhex("0fb6c0"))  # movzx eax, al
        self.assertEqual(ins.mnemonic, "movzx")
        self.assertEqual(ins.operands[1].size, 8)

    def test_movzx_word(self):
        self.assertEqual(decode_one(bytes.fromhex("0fb7c0")).mnemonic, "movzx")

    def test_movsx(self):
        self.assertEqual(decode_one(bytes.fromhex("0fbec0")).mnemonic, "movsx")

    def test_cmove(self):
        self.assertEqual(decode_one(bytes.fromhex("0f44c2")).mnemonic, "cmove")

    def test_sete(self):
        ins = decode_one(bytes.fromhex("0f94c0"))  # sete al
        self.assertEqual(ins.mnemonic, "sete")
        self.assertEqual(ins.operands[0].size, 8)

    def test_bswap(self):
        self.assertEqual(decode_one(bytes.fromhex("0fc8")).mnemonic, "bswap")

    def test_multibyte_nop(self):
        self.assertEqual(decode_one(bytes.fromhex("0f1f00")).mnemonic, "nop")

    def test_imul_reg_reg(self):
        self.assertEqual(decode_one(bytes.fromhex("0fafc3")).mnemonic, "imul")

    def test_rdtsc(self):
        self.assertEqual(decode_one(bytes.fromhex("0f31")).mnemonic, "rdtsc")


class MiscTests(unittest.TestCase):
    def test_xor_reg_reg(self):
        ins = decode_one(bytes.fromhex("4831ff"))  # xor rdi, rdi
        self.assertEqual(ins.mnemonic, "xor")
        self.assertEqual(ins.operands[0].reg, 7)
        self.assertEqual(ins.operands[1].reg, 7)

    def test_nop(self):
        self.assertEqual(decode_one(bytes.fromhex("90")).mnemonic, "nop")

    def test_int3(self):
        self.assertEqual(decode_one(bytes.fromhex("cc")).mnemonic, "int3")

    def test_movsxd(self):
        ins = decode_one(bytes.fromhex("63c0"))  # movsxd rax, eax
        self.assertEqual(ins.mnemonic, "movsxd")

    def test_operand_size_prefix_makes_it_16_bit(self):
        ins = decode_one(bytes.fromhex("66b83400"))  # mov ax, 0x34
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[0].size, 16)

    def test_immediate_mov_8_bit(self):
        ins = decode_one(bytes.fromhex("b032"))  # mov al, 0x32
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[1], 0x32)

    def test_modrm_mod3_is_register_direct(self):
        ins = decode_one(bytes.fromhex("89c3"))  # mov ebx, eax
        self.assertEqual(ins.operands[0].kind, "reg")
        self.assertEqual(ins.operands[1].kind, "reg")

    def test_full_routine_decodes(self):
        code = bytes.fromhex(
            "48c7c001000000" "48c7c701000000" "48c7c600200000"
            "48c7c20d000000" "0f05" "48c7c03c000000" "4831ff" "0f05"
        )
        ins = decode_all(code)
        self.assertEqual(len(ins), 8)
        self.assertEqual(ins[4].mnemonic, "syscall")
        self.assertEqual(ins[7].mnemonic, "syscall")


class RejectionTests(unittest.TestCase):
    def test_unknown_opcode_raises(self):
        with self.assertRaises(DecodeError):
            decode_one(bytes.fromhex("06"))  # push es, invalid in long mode

    def test_garbage_raises(self):
        # Memory is sparse and zero-filled, so a zero byte decodes fine. A byte
        # that is genuinely not an instruction must still raise.
        with self.assertRaises(DecodeError):
            decode_one(bytes.fromhex("06"))


class WidthTests(unittest.TestCase):
    def test_32_bit_mode_decodes(self):
        ins = decode_one(bytes.fromhex("b834120000"), bits=32)
        self.assertEqual(ins.mnemonic, "mov")
        self.assertEqual(ins.operands[1], 0x1234)

    def test_32_bit_rip_relative_is_absolute(self):
        ins = decode_one(bytes.fromhex("8b0510000000"), bits=32)  # mov eax, [0x10]
        self.assertEqual(ins.mnemonic, "mov")
        self.assertFalse(ins.operands[1].rip_rel)
        self.assertEqual(ins.operands[1].disp, 0x10)


if __name__ == "__main__":
    unittest.main()
