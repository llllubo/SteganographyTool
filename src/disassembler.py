import sys
import subprocess
import re

from iced_x86 import *
from analyzer import Analyzer
from my_instruction import MyInstruction
from misc import get_numof_useable_b_from_nop


class Disassembler:

    
    @staticmethod
    def __parse_file_bitness(lines: str, fpath: str) -> int:
        # To get to know, what versions of instructions are allowed.
        # File bitness parsing.
        re_fformat = re.compile(
            r'file format\s+(?P<farch>[peilf]{2,3}[0-9]{0,2})-(?P<type>.*)'
            )
        fformat = re_fformat.search(lines)
        
        # Can not get file format of executable.
        if fformat is None:
            print(
                f"ERROR! Format of given executable was not recognized: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)
            
        # Get to know what type of executable was given.
        if fformat.group("farch") == "pei" or fformat.group("farch") == "pe":
            if fformat.group("type") == "i386":
                return 32
            else:
                return 64
        else:
            return int(fformat.group("farch")[-2:])
    
    
    @staticmethod
    def __parse_code_sections(lines: str, fpath: str) -> list:
        # Parse executable sections info (name, size, VMA, file offset).
        re_code_sections = re.compile(
            r'(?P<section>\.\S+)\s+(?P<size>[0-9a-fA-F]+)\s+(?P<vma>[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(?P<foffset>[0-9a-fA-F]+).*[\r\n]+.*CODE'
            )
        code_sections = re_code_sections.findall(lines)
        
        if code_sections is None:
            print(
                f"ERROR! Can not detect executable part of given file: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)

        return code_sections
    
    
    @staticmethod
    def __get_binary_info(fpath: str) -> tuple:
        # vraciam bitness a pre CODE sekcie: name, size, RIP (VMA), file offset
        # Often formats: pe[i]-x86-64 | pe[i]-i386 | elf64-.* | elf32-.*
        
        # Parse header info and sections info of executable.
        try:
            b_lines = subprocess.check_output(
                    ["objdump", "-h", fpath],
                    stderr=subprocess.STDOUT
                    )
        except subprocess.CalledProcessError:
            print(
                f"ERROR! Can not access given executable: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)
        
        lines = b_lines.decode("UTF-8")
        bitness = Disassembler.__parse_file_bitness(lines, fpath)
        code_sections = Disassembler.__parse_code_sections(lines, fpath)
        
        return (bitness, code_sections)
    
    
    # @staticmethod
    # def __set_formatter() -> object:
    #     formatter = Formatter(FormatterSyntax.INTEL)
    #     formatter.digit_separator = "'"
    #     formatter.hex_digit_group_size = 4
    #     formatter.hex_prefix = "0x"
    #     formatter.hex_suffix = ""
    #     formatter.uppercase_hex = False
    #     formatter.first_operand_char_index = 8
    #     formatter.space_after_operand_separator = True
    #     formatter.space_between_memory_add_operators = True
    #     formatter.show_zero_displacements = True
    #     formatter.displacement_leading_zeros = True
    #     formatter.always_show_scale = True
    #     formatter.leading_zeros = True
    #     formatter.signed_immediate_operands = True
        
    #     return formatter
    
    
    @staticmethod
    def __not_acc_reg(instr: Instruction) -> bool:
        # Only AH register from all accumaltor registers is allowed,
        # because following accumulator registers has shorter code
        # missing ModR/M byte, where magic happens. This function is
        # designed for TEST instruction of 'test-non-acc-reg' eq. class.
        if instr.op0_kind == OpKind.REGISTER and \
           instr.op0_register != Register.AL and \
           instr.op0_register != Register.AX and \
           instr.op0_register != Register.EAX and \
           instr.op0_register != Register.RAX:
            return True
        return False
    
    
    @staticmethod
    def __can_swap(instr: Instruction, operand: int) -> bool:
        ##### can swap index and base registers.

        # def create_enum_dict(module):
        #     return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}
        # reg_to_str = create_enum_dict(Register)
        
        if instr.op_kind(operand) == OpKind.MEMORY and \
            instr.memory_base != 0 and \
            instr.memory_index != 0 and \
            instr.memory_base != instr.memory_index and \
            instr.memory_index_scale == 1:
            # print("..")
            # print(f"{reg_to_str[instr.memory_base]} - {instr.memory_base}")
            # print(f"{reg_to_str[instr.memory_index]} - {instr.memory_index}")
            # print(f"{instr.memory_index_scale}")
            # print("..")
            return True
        
        return False

    
    @staticmethod
    def disassemble(exef: str, method: str, analyzer: Analyzer) -> tuple:
        
        code_bitness, code_sections = Disassembler.__get_binary_info(exef)
        
        try:
            fd = open(exef, "rb")
        except IOError:
            print(f"ERROR! Can not access given executable: {exef}", file=sys.stderr)
            sys.exit(101)
        
        #######
        selected_instrs = []
        nop90_indicator = None
        cap = 0 ## BITS
        #######
        
        # Array of disassembled instructions from every code section.
        all_instrs = []
        
        # formatter = Disassembler.__set_formatter()
        
        # Index of instruction within all instructions.
        i = 0
        for sec in code_sections:
            
            sec_size = int(sec[1], 16)
            sec_rip = int(sec[2], 16)
            sec_foffset = int(sec[3], 16)
            
            # Reading code section from executable.
            fd.seek(sec_foffset)
            b_code = fd.read(sec_size)
            
            # Create the decoder and initialize RIP
            decoder = Decoder(code_bitness, b_code, ip=sec_rip)
            
            # Loop through instructions within one section.
            for instr in decoder:
                # Calculate file offset of current instruction.
                instr_foffset = (instr.ip - sec_rip) + sec_foffset
                
                ########
                my_instr = MyInstruction(instr, instr_foffset, i)
                ########
                
                # Collect every disassembled instruction.
                all_instrs.append(my_instr)
                
                ########
                op_code = my_instr.instruction.op_code()
                
                # print(op_code.instruction_string)

                if method == "nops" or \
                   method == "nops-embedding" or \
                   method == "ext-sub-nops":
                    
                    # 1 byte NOPs 0x90 - two in a row.
                    if op_code.is_nop and instr.len == 1:
                        if nop90_indicator is not None:
                            # Select two 1 byte NOPs in a row.
                            selected_instrs.append(all_instrs[(my_instr.ioffset-1)])
                            selected_instrs.append(my_instr)
                            # Reset indicator.
                            nop90_indicator = None
                            cap += 1    # Coding 1.
                        else:
                            nop90_indicator = my_instr
                    else:
                        nop90_indicator = None
                        
                    # Multi-byte NOP.
                    if op_code.is_nop:
                        
                        if instr.len == 2:
                            # 2 bytes NOP 0x6690
                            selected_instrs.append(my_instr)
                            
                            cap += 2    # Coding 01.

                        elif instr.len == 3:
                            # 3 bytes NOP 0x0f1f00.
                            selected_instrs.append(my_instr)
                            
                            cap += 2
                        
                        elif instr.len > 3:
                            # More than 3 bytes long NOP.
                            selected_instrs.append(my_instr)
                            
                            cap += get_numof_useable_b_from_nop(
                                my_instr.instruction,
                                code_bitness
                                )
                            
                    # 2 bytes FNOP 0xd9d0 is not included in 'is_nop',
                    # therefore it must be detected separately.
                    elif instr.len == 2 and \
                        op_code.op_code_string == "D9 D0":
                    
                        selected_instrs.append(my_instr)
                        cap += 2    # Coding 00.
                            
                if method == "ext-sub" or \
                   method == "extended-substitution" or \
                   method == "ext-sub-nops":
                    
                    # TEST non-acc-(except AH)-r, imm
                    # TEST /0 /1
                    if re.match(
                            r'TEST [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and Disassembler.__not_acc_reg(instr):
                        selected_instrs.append(my_instr)
                        cap += 1
                        
                    ##### pozor v 'm' mozu byt len 32-bit a 64-bit registry
                    ##### TOTO BUDE MAT VACSIU PRIORITU SPOMEDZI EQ CLASSES
                    ##### ^^ tento swap je prakticky nedetegovatelny..?
                    ##### cize je lepsie ho pouzit.. a nekradne ani instrukcie
                    ##### z inych tried, po porovnani na awk a Adobe32
                    # OPCODE m, r/imm
                    # OPCODE r, m
                    # BASE-INDEX swap while SCALE is 1.
                    # This class has higher priority over class 'shl-sal'
                    # and, in mode 'ext-sub-nops', also over classes
                    # 'add-neg' and 'sub-neg'.
                    elif (      # OPCODE Memory, Register.
                        re.match(
                            r'.* r/m[0-9]{1,2}, r[0-9]{1,2}',
                            op_code.instruction_string
                        ) and Disassembler.__can_swap(instr, 0)
                    ) or \
                    (        # OPCODE Memory, Immediate.
                        re.match(
                            r'.* r/m[0-9]{1,2}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and Disassembler.__can_swap(instr, 0)
                    ) or \
                    (        # OPCODE Register, Memory.
                        re.match(
                            r'.* r[0-9]{1,2}, r/m[0-9]{1,2}',
                            op_code.instruction_string
                        ) and Disassembler.__can_swap(instr, 1)
                    ):
                        selected_instrs.append(my_instr)
                        cap += 1
                        
                    # SHL/SAL /4 /6
                    # First operand is always in form r/m and second can
                    # be only 1 as value (this has specific OPCODE), CL
                    # register or any immediate value.
                    elif re.match(
                            r'(?:SHL|SAL) r/m[0-9]{1,2}, (?:1|CL|imm[0-9]{1,2})',
                            op_code.instruction_string
                        ):
                        # This overlap with class 'swap-base-index', but
                        # we do not need to check it because of 'if-elif'
                        # statements.
                        # This class has lower priority than class
                        # 'swap-base-index'.
                        selected_instrs.append(my_instr)
                        cap += 1
                        
                    elif code_bitness == 32:
                        # OPCODE = ADD|SUB|ADC|SBB|AND|OR|XOR|CMP
                        # OPCODE m8, imm8
                        # OPCODE non-al-r8, imm8
                        # AL register appears individually in mnemonics, so
                        # do not have to be checked in r/m8.
                        if re.match(
                                r'(:?ADD|SUB|ADC|SBB|AND|OR|XOR|CMP) r/m8, imm8',
                                op_code.instruction_string
                        ):
                            # This has affect, in 32-bit mode, on classes
                            # 'add-neg' and 'sub-neg'. 
                            # This has lower priority than class 'swap-base-
                            # index', but higher than classes 'add-neg' and
                            # 'sub-neg'.
                            selected_instrs.append(my_instr)
                            cap += 1
                            
                    
                if method == "sub" or \
                   method == "instruction-substitution" or \
                   method == "ext-sub-nops":
                    ## POZOR KED JE IMM, MOZE BYT PRVY OP. LEN REGISTER,
                    ## NEMUSI BYT R/M
                    ############ VYMENA OPERANDOV ak menim strany r, r/m
                
                    ###### ZJEDNODUSIT PRE UCELY LEN NAJDENIA
                
                    ############ AND A OR MOZU MAT PODMIENKY AJ AKO TEST

                    ## FIRST CLASS - 'tao'.
                    # TEST r/m, r (TEST r, r\m does not exist).
                    if re.match(
                            r'TEST r/m[0-9]{1,2}, r[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.op0_kind == OpKind.REGISTER and \
                            instr.op0_register == instr.op1_register:
                        selected_instrs.append(my_instr)
                        cap += 2    # Coding 00
                    
                    elif re.match(
                            r'AND r/m[0-9]{1,2}, r[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.op0_kind == OpKind.REGISTER and \
                            instr.op0_register == instr.op1_register:
                        selected_instrs.append(my_instr)
                        cap += 1    # Coding 1
                        
                    elif re.match(
                            r'OR r/m[0-9]{1,2}, r[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.op0_kind == OpKind.REGISTER and \
                            instr.op0_register == instr.op1_register:
                        selected_instrs.append(my_instr)
                        cap += 2    # Coding 01
                        
                    ## SUB-XOR CLASS
                    elif re.match(
                            r'(?:SUB|XOR) (?:r/m|r)[0-9]{1,2}, (?:r|r/m)[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.op0_kind == OpKind.REGISTER and \
                            instr.op1_kind == OpKind.REGISTER and \
                            instr.op0_register == instr.op1_register:
                        selected_instrs.append(my_instr)
                        cap += 2
                        ############# CHECK AF flag
                        print(f"0b{instr.rflags_read:b} .... 0b{instr.rflags_modified:b}")
                    
                    ## ALL CLASSES WITH r/m, r & r, r/m INSTR. VERSIONS.
                    # r/m, r versions of MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB.
                    # AND and OR are in the previous 'if' as well, because
                    # their priority belonging is to the class where TEST,
                    # AND and OR are together.
                    elif re.match(
        r'(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r/m[0-9]{1,2}, r[0-9]{1,2}',
                            op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER:
                        # Do not to be check, as previous 'if' statement
                        # can not cause duplicates.
                        selected_instrs.append(my_instr)
                        cap += 1
                        
                    elif re.match(
        r'(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r[0-9]{1,2}, r/m[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.op1_kind == OpKind.REGISTER:
                        # Do not to be check, as previous 'if' statement
                        # can not cause duplicates.
                        selected_instrs.append(my_instr)
                        cap += 1
                        
                    ## CLASSES ADD & SUB WITH THEIR NEGATED IMMEDIATES.
                    # ADD r/m, imm
                    elif re.match(
                            r'ADD [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.immediate(1) >= 0:
                        # Must check because of mode 'ext-sub-nops' where
                        # class 'swap-base-index' (2nd part of 'if'
                        # statement) can take same instruction earlier, but
                        # also in 32-bit mode this can cause classes
                        # '.*-32bit'.
                        if selected_instrs and \
                        id(selected_instrs[-1]) != id(my_instr):
                            ############ CHECK OF, CF, AF flags
                            # print(f"0b{instr.rflags_read:b} .... 0b{instr.rflags_modified:b}")
                            selected_instrs.append(my_instr)
                            ########## nulu nemozem negovat, zachovam ju
                            
                            cap += 1
                        
                    # SUB r/m, -imm .. NEGATED
                    elif re.match(
                            r'SUB [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.immediate(1) < 0:
                        # Must check because of mode 'ext-sub-nops' where
                        # class 'swap-base-index' (2nd part of 'if'
                        # statement) can take same instruction earlier, but
                        # also in 32-bit mode this can cause classes
                        # '.*-32bit'.
                        if selected_instrs and \
                        id(selected_instrs[-1]) != id(my_instr):
                            ############ CHECK OF, CF, AF flags
                            # print(f"0b{instr.rflags_read:b} .... 0b{instr.rflags_modified:b}")
                            selected_instrs.append(my_instr)
                            cap += 1
                        
                    # SUB r/m, imm
                    elif re.match(
                            r'SUB [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.immediate(1) >= 0:
                        # Must check because of mode 'ext-sub-nops' where
                        # class 'swap-base-index' (2nd part of 'if'
                        # statement) can take same instruction earlier, but
                        # also in 32-bit mode this can cause classes
                        # '.*-32bit'.
                        if selected_instrs and \
                        id(selected_instrs[-1]) != id(my_instr):
                            ############ CHECK OF, CF, AF flags
                            # print(f"0b{instr.rflags_read:b} .... 0b{instr.rflags_modified:b}")
                            selected_instrs.append(my_instr)
                        ########## nulu nemozem negovat, zachovam ju
                        
                            cap += 1
                        
                    # ADD r/m, -imm .. NEGATED
                    elif re.match(
                            r'ADD [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                            op_code.instruction_string
                        ) and instr.immediate(1) < 0:
                        # Must check because of mode 'ext-sub-nops' where
                        # class 'swap-base-index' (2nd part of 'if'
                        # statement) can take same instruction earlier, but
                        # also in 32-bit mode this can cause classes
                        # '.*-32bit'.
                        if selected_instrs and \
                        id(selected_instrs[-1]) != id(my_instr):
                            ############ CHECK OF, CF, AF flags
                            # print(f"0b{instr.rflags_read:b} .... 0b{instr.rflags_modified:b}")
                            selected_instrs.append(my_instr)
                            cap += 1
                
                ##### KONTROLNY VYPIS
                # disasm = formatter.format(all_instrs[i].instruction)
                # instr_offset = all_instrs[i].instruction.ip - sec_rip
                # instr_code = b_code[instr_offset:(instr_offset + all_instrs[i].instruction.len)].hex().lower()
                # print(f"{all_instrs[i].ioffset}..{all_instrs[i].instruction.ip:016X} {instr_code:30} {disasm}")
                
                # Global counter of all decoded instructions.
                i += 1

        fd.close()
        analyzer.set_total_instrs = i
        analyzer.set_useable_instrs = len(selected_instrs)
        analyzer.set_capacity = cap
        
        return all_instrs, selected_instrs, code_bitness
    
    
    ##### instr.rflags_read
    ##### instr.rflags_modified
    ##### instr.flow_control
    
    # if instr.rflags_modified != RflagsBits.NONE:
    #     rflags_bits_to_string(instr.rflags_modified)
    
    # def rflags_bits_to_string(rf: int) -> str:
    #     def append(sb: str, s: str) -> str:
    #         if len(sb) != 0:
    #             sb += ", "
    #         return sb + s

    #     sb = ""
    #     if (rf & RflagsBits.OF) != 0:
    #         sb = append(sb, "OF")
    #     if (rf & RflagsBits.SF) != 0:
    #         sb = append(sb, "SF")
    #     if (rf & RflagsBits.ZF) != 0:
    #         sb = append(sb, "ZF")
    #     if (rf & RflagsBits.AF) != 0:
    #         sb = append(sb, "AF")
    #     if (rf & RflagsBits.CF) != 0:
    #         sb = append(sb, "CF")
    #     if (rf & RflagsBits.PF) != 0:
    #         sb = append(sb, "PF")
    #     if (rf & RflagsBits.DF) != 0:
    #         sb = append(sb, "DF")
    #     if (rf & RflagsBits.IF) != 0:
    #         sb = append(sb, "IF")
    #     if (rf & RflagsBits.AC) != 0:
    #         sb = append(sb, "AC")
    #     if (rf & RflagsBits.UIF) != 0:
    #         sb = append(sb, "UIF")
    #     if len(sb) == 0:
    #         return "<empty>"
    #     return sb
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
        # set_op1_kind(new_val)
    
        # info_factory = InstructionInfoFactory()
        
        # assert instr1.code == Code.XCHG_RM8_R8
        # assert instr1.mnemonic == Mnemonic.XCHG
        # assert instr1.len == 4
        
        # assert instr2.code == Code.ADD_RM32_IMM8
        # assert instr2.mnemonic == Mnemonic.ADD
        # assert instr2.len == 5
        
        # assert instr3.code == Code.EVEX_VMOVDQU64_ZMM_K1Z_ZMMM512
        # assert instr3.mnemonic == Mnemonic.VMOVDQU64
        # assert instr3.len == 6
        
        # # `instr.mnemonic` also returns a `Mnemonic` enum
        # print(f"mnemonic: {formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)}")
        # print(f"operands: {formatter.format_all_operands(instr)}")
        # # `instr.op0_kind`/etc return operand kind, see also `instr.op0_register`, etc to get reg/mem info
        # print(f"op #0   : {formatter.format_operand(instr, 0)}")
        # print(f"op #1   : {formatter.format_operand(instr, 1)}")
        # print(f"reg RCX : {formatter.format_register(Register.RCX)}")
        
        # nop = Instruction.create(Code.NOPQ)
        # xor = Instruction.create_reg_i32(Code.XOR_RM64_IMM8, Register.R14, -1)
        # rep_stosd = Instruction.create_rep_stosd(64)
        # add = Instruction.create_mem_i32(Code.ADD_RM64_IMM8, MemoryOperand(Register.RCX, Register.RDX, 8, 0x1234_5678), 2)
        # print(f"{nop}")
        # print(f"{xor:x}")
        # print(f"{rep_stosd}")
        # print(f"{add}")
        # print(f"{Instruction.create_declare_byte_1(0x90)}")
        # print(f"{xor.memory_displ_size}")
        # print(f"{xor.memory_displacement}")
        # print(f"{xor.memory_index_scale}")
        # print(f"0x{xor.immediate(1):x}")
        
        # print(f"{instr.code} interny kod instrukcie")
        # print(f"{instr.op_code()} mnemonic instrukcie aj s ops")
        # print(f"{instr.code_size} velkost kodu instrukcie (bytes)")
        # print(f"{instr.mnemonic} interny kod mnemonicu")
        # print(f"{instr.memory_base} interny kod")
        # print(f"{instr.memory_index} interny kod")
        
        # print(f"{instr.op_count}")
        # print(f"{instr.op_kind(0) == OpKind.MEMORY}")
        # print(f"{instr.memory_base == Register.RAX}")
        # print(f"{instr.memory_index == Register.NONE}")
        # print(f"{instr.op_kind(1) == OpKind.REGISTER}")
        # print(f"{instr.op_register(1) == Register.EBX}")