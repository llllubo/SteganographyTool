import re
import math

from iced_x86 import *
from my_instruction import MyInstruction
from analyzer import Analyzer
from misc import count_useable_bytes_from_nop
from eq_classes_processor import EqClassesProcessor


class Selector:
    
    ############################## n pojde prec a vypocita sa
    @staticmethod
    def __compute_average_capacity(eq_class: str, n: int) -> int:
        # If within one Equivalent Class is number of members not equal
        # to Power of 2, then only average capacity can be computed as
        # real capacity depend on exact occurence of particular members
        # from class.
        return math.ceil(math.log2(n)-1) + ( n - pow(2, math.ceil(math.log2(n) - 1)) ) / ( pow(2, math.ceil(math.log2(n) - 1)) )
    
    
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
    def __liveness_flags_detection(all_instrs: list,
                                   my_instr: MyInstruction,
                                   rflags_to_check: int,
                                   force: bool) -> bool:
        ## MUSIM IST PODLA EXECUTION FLOW - PORIESIT SKOKY
        # ^^ prechadzam kym nepride end of function alebo kym nepride instrukcia ktora modifikuje tento znak skor ako pride instrukcia, ktora ho cita.
        # LIVENESS DETECTION OF MODIFIED FLAGS BY REPLACEMENT INSTRUCTION.
        
        if rflags_to_check == RflagsBits.NONE:
            return True
        
        # got_op_code = my_instr.instruction.op_code()
        # print("\n\n\n\n\n\n")
        # print(f"{got_op_code.instruction_string:16} | 0b{rflags_to_check:>8b}")
        
        all_rflags = (RflagsBits.OF, RflagsBits.SF, RflagsBits.ZF,
                      RflagsBits.AF, RflagsBits.CF, RflagsBits.PF,
                      RflagsBits.DF, RflagsBits.IF, RflagsBits.AC,
                      RflagsBits.UIF)
        
        # Transformation of given flags all in one integer to the list
        # of proper flags values.
        check_rflags = [rflag
                        for rflag in all_rflags
                            if (rflag & rflags_to_check) != 0]
        
        # List for marking whether the flag has already been checked
        # (modified by another instruction).
        safe_rflags = [False] * len(check_rflags)

        # orig_my_instr = my_instr

        # In 'my_instr' is always present next instruction from
        # previous one.
        my_instr = all_instrs[my_instr.ioffset + 1]
        
        while True:
            
            rflags_read = my_instr.instruction.rflags_read
            rflags_modified = my_instr.instruction.rflags_modified
            op = my_instr.instruction.op_code()
            # print(f"next: {my_instr.ioffset} - {op.instruction_string}, modified: {rflags_modified:b}, read: {rflags_read:b}",)

            for idx, rflag in enumerate(check_rflags):
                # print(f"rflag: {rflag:b}")
                # Liveness detection of checked flags.
                if (rflag & rflags_read) != 0:
                    # Instruction tests checked flag.
                    return False
                if (rflag & rflags_modified) != 0:
                    # Instruction modifies checked flag.
                    safe_rflags[idx] = True
                    # print(f"CHECKED rflag: {idx}, {rflag:b}")
                    # End immediately when all flags are safe.
                    if False not in safe_rflags:
                        # print(f".. all flags are safe -- OK")
                        return True
            
            # Only because of clearer conditions.
            instr = my_instr.instruction
            
            if instr.flow_control == FlowControl.NEXT:
                # Execution flow follow next instruction.
                my_instr = all_instrs[my_instr.ioffset + 1]
            
            elif instr.flow_control == FlowControl.RETURN:
                # The end of a function.
                break
            
            # CALL|JMP near/far
            # ONLY if user specify by argument (very time-consuming).
            elif force and \
                (
                    instr.flow_control == FlowControl.CALL or \
                    instr.flow_control == FlowControl.UNCONDITIONAL_BRANCH
                ):
                   
                if instr.op_count == 1:
                    if instr.op0_kind == OpKind.NEAR_BRANCH16 or \
                        instr.op0_kind == OpKind.NEAR_BRANCH32 or \
                        instr.op0_kind == OpKind.NEAR_BRANCH64:

                        get_target = instr.near_branch_target
                    
                    elif instr.op0_kind == OpKind.FAR_BRANCH16 or \
                        instr.op0_kind == OpKind.FAR_BRANCH32:
                        
                        get_target = instr.far_branch_selector
                        
                    else:
                        # print("UNSUPPORTED CALL OR UNCOND. BRANCH...")
                        return False
                
                else:
                    # print("UNSUPPORTED CALL OR UNCOND. BRANCH")
                    return False
                    
                # print(f"TUTUUUTUTUTUTUTT: 0x{get_target:x}")
                found_instr = [my_instr 
                                for my_instr in all_instrs 
                                    if my_instr.instruction.ip == get_target]
                
                if found_instr:
                    # print(f"najdene? {found_instr[0].ioffset} - {found_instr[0].foffset:x}")
                    my_instr = found_instr[0]
                else:
                    # print("nenajdene")
                    return False
            
            else:   
                # print("NOT SUPPORTED JUMP")
                return False
        
        # print(f".. OK -- end of function: ", end="")
        # for j in check_rflags:
        #     print(f"{j:b}, ", end="")
        # print()

        return True
    
    
    @staticmethod
    def __check_regs_dependency(bitness: int,
                                reg0: Register_,
                                reg1: Register_) -> bool:
        
        info0 = RegisterInfo(reg0)
        info1 = RegisterInfo(reg1)
        if bitness == 32:
            full_reg0 = info0.full_register32
            full_reg1 = info1.full_register32
        else:
            full_reg0 = info0.full_register
            full_reg1 = info1.full_register
            
        if full_reg0 == full_reg1:
            return True
        
        return False
    
    
    @classmethod
    def __mem_op_use_reg(cls,
                         bitness: int,
                         instr: Instruction,
                         reg: Register_) -> bool:
        
        if instr.memory_base != Register.NONE and \
            cls.__check_regs_dependency(bitness, instr.memory_base, reg):
            return True
        if instr.memory_index != Register.NONE and \
            cls.__check_regs_dependency(bitness, instr.memory_index, reg):
            return True
        
        return False

    
    # ak do registra zapisujem, nesmiem uz z neho citat !!! ak sa nachadza v MEMORY, je to citanie !!! citat z neho mozem len v tej istej instruckii (mov rax, rax alebo mov rax,[rax]).
    # ak zapisujem do MEM, z tohto miesta uz nesmiem citat ani tam zapisat.
    @classmethod
    def __check_independency(cls,
                             prev_mov: Instruction,
                             curr_mov: Instruction,
                             bitness: int) -> bool:
        
        # Can not be exactly two same MOV instructions.
        if prev_mov.eq_all_bits(curr_mov):
            return False
        # In case when they are not equal in bits, because of they
        # differ only in Direction Bit as MOV can -- in that case they
        # actually are equal and can not be ordered lexicographically.
        elif f"{prev_mov:ixr}" == f"{curr_mov:ixr}":
            # print(f"{prev_mov:ixr} | {curr_mov:ixr}")
            # op1 = prev_mov.op_code()
            # op2 = curr_mov.op_code()
            # print(f"{op1.instruction_string} | {op2.instruction_string}\n")
            return False
        
        # If some mov write to the REG, this REG can not be used anymore
        # (except within same instruction).
        if prev_mov.op0_kind == OpKind.REGISTER:
            
            if curr_mov.op0_kind == OpKind.REGISTER and \
                cls.__check_regs_dependency(bitness, curr_mov.op0_register, prev_mov.op0_register):
                return False
            if curr_mov.op1_kind == OpKind.REGISTER and \
                cls.__check_regs_dependency(bitness, curr_mov.op1_register, prev_mov.op0_register):
                return False
            if (
                    curr_mov.op0_kind == OpKind.MEMORY or \
                    curr_mov.op1_kind == OpKind.MEMORY
                ) and \
                cls.__mem_op_use_reg(bitness, curr_mov, prev_mov.op0_register):
                return False
        
        if curr_mov.op0_kind == OpKind.REGISTER:
            
            if prev_mov.op1_kind == OpKind.REGISTER and \
                cls.__check_regs_dependency(bitness, prev_mov.op1_register, curr_mov.op0_register):
                    return False
            if (
                    prev_mov.op0_kind == OpKind.MEMORY or \
                    prev_mov.op1_kind == OpKind.MEMORY
                ) and \
                cls.__mem_op_use_reg(bitness, prev_mov, curr_mov.op0_register):
                return False
            
        # Same MEMORY locations on the 'cross'.
        if prev_mov.op0_kind == OpKind.MEMORY:
            if prev_mov.op0_kind == curr_mov.op1_kind and \
                cls.__check_regs_dependency(bitness, prev_mov.memory_base, curr_mov.memory_base) and \
                cls.__check_regs_dependency(bitness, prev_mov.memory_index, curr_mov.memory_index) and \
                prev_mov.memory_index_scale == curr_mov.memory_index_scale and \
                prev_mov.memory_displacement == curr_mov.memory_displacement:
                return False
        
        # Same MEMORY locations on the 'cross'.
        if prev_mov.op1_kind == OpKind.MEMORY:
            if prev_mov.op1_kind == curr_mov.op0_kind and \
                cls.__check_regs_dependency(bitness, prev_mov.memory_base, curr_mov.memory_base) and \
                cls.__check_regs_dependency(bitness, prev_mov.memory_index, curr_mov.memory_index) and \
                prev_mov.memory_index_scale == curr_mov.memory_index_scale and \
                prev_mov.memory_displacement == curr_mov.memory_displacement:
                return False
            
        return True
    
    
    @classmethod
    def select(cls,
               all_my_instrs: list,
               method: str,
               force: bool,
               analyzer: Analyzer) -> list:
        
        selected_my_instrs = []
        nop90_indicator = 0
        fnop_indicator = False
        nop6690_indicator = False
        mov_indicator = False
        avg_cap = 0.0       # In BITS
        min_cap = 0         # In BITS
        max_cap = 0         # In BITS
        
        for my_instr in all_my_instrs:
            
            instr = my_instr.instruction
            op_code = my_instr.instruction.op_code()


            if method == "mov" or \
                method == "ext-sub-nops-mov":
                
                # Two MOVs in a row.
                if instr.mnemonic == Mnemonic.MOV:
                    if mov_indicator:
                        # Got two MOVs in a row.
                        # Need to check their independency.
                        prev_mov = all_my_instrs[my_instr.ioffset - 1]
                        
                        if cls.__check_independency(prev_mov.instruction,
                                                    instr,
                                                    analyzer.bitness):
                            prev_mov.set_eq_class = "mov-scheduling"
                            selected_my_instrs.append(prev_mov)
                            my_instr.set_eq_class = "mov-scheduling"
                            selected_my_instrs.append(my_instr)
                            
                            # Reset indicator only if MOV instructions
                            # are independent and can be used, otherwise
                            # if next instruction will be MOV,
                            # dependency check will be performed again.
                            mov_indicator = False
                            avg_cap += 1.0
                            min_cap += 1
                            max_cap += 1
                            
                            # print(f".... {prev_mov.ioffset}: {prev_mov.instruction} \t\t {my_instr.ioffset}: {my_instr.instruction}")
                    else:
                        # Set indicator.
                        mov_indicator = True
                else:
                    # Reset indicator.
                    mov_indicator = False


            if method == "nops" or \
                method == "ext-sub-nops-mov":
                
                # 1 byte NOPs 0x90.
                if op_code.is_nop and instr.len == 1:
                    
                    if nop90_indicator > 0:
                        # 2nd or 3rd NOP 0x90 detected.
                        
                        if nop90_indicator == 1:
                            # 2nd NOP 0x90 detected.
                            nop90_indicator = 2
                            
                            prev_nop = all_my_instrs[my_instr.ioffset - 1]
                            prev_nop.set_eq_class = "2B-NOP"
                            selected_my_instrs.append(prev_nop)
                            
                            my_instr.set_eq_class = "2B-NOP"
                            selected_my_instrs.append(my_instr)
                        
                            avg_cap += cls.__compute_average_capacity("", 3)
                            min_cap += 1
                            max_cap += 2
                        
                        elif nop90_indicator == 2:
                            # 3rd NOP 0x90 detected.
                            
                            # Reset indicator.
                            nop90_indicator = 0
                            
                            selected_my_instrs[-2].set_eq_class = "3B-NOP"
                            selected_my_instrs[-1].set_eq_class = "3B-NOP"
                            my_instr.set_eq_class = "3B-NOP"
                            selected_my_instrs.append(my_instr)
                            
                            # Computation must also be returned.
                            avg_cap -= cls.__compute_average_capacity("", 3)
                            min_cap -= 1
                            max_cap -= 2
                            # Fixed computation.
                            avg_cap += cls.__compute_average_capacity("", 6)
                            min_cap += 2
                            max_cap += 3
                        
                    else:
                        # 1st NOP 0x90 detected.
                        nop90_indicator = 1
                        
                        if nop6690_indicator:
                            # Detected sequence: 0x6690; 0x90.
                            
                            # Reset indicators.
                            nop90_indicator = 0
                            nop6690_indicator = False

                            selected_my_instrs[-1].set_eq_class = "3B-NOP"
                            my_instr.set_eq_class = "3B-NOP"
                            selected_my_instrs.append(my_instr)
                            
                            avg_cap += cls.__compute_average_capacity("", 6)
                            min_cap += 2
                            max_cap += 3
                        
                        elif fnop_indicator:
                            # Detected sequence: 0xd9d0; 0x90.
                            
                            # Reset indicators.
                            nop90_indicator = 0
                            fnop_indicator = False
                            
                            selected_my_instrs[-1].set_eq_class = "3B-NOP"
                            my_instr.set_eq_class = "3B-NOP"
                            selected_my_instrs.append(my_instr)
                            
                            avg_cap += cls.__compute_average_capacity("", 6)
                            min_cap += 2
                            max_cap += 3
                    
                # Multi-byte NOP.
                if op_code.is_nop:
                    
                    if instr.len == 2:
                        # 2 bytes NOP 0x6690 detected.
                        nop6690_indicator = True
                        
                        if nop90_indicator == 1:
                            # Detected sequence: 0x90; 0x6690
                            
                            nop6690_indicator = False
                            
                            prev_nop = all_my_instrs[my_instr.ioffset - 1]
                            prev_nop.set_eq_class = "3B-NOP"
                            selected_my_instrs.append(prev_nop)
                            my_instr.set_eq_class = "3B-NOP"
                            selected_my_instrs.append(my_instr)
                            
                            avg_cap += cls.__compute_average_capacity("", 6)
                            min_cap += 2
                            max_cap += 3
                            
                        else:                            
                            # Only one NOP 0x6690 detected.
                            my_instr.set_eq_class = "2B-NOP"
                            selected_my_instrs.append(my_instr)
                            
                            avg_cap += cls.__compute_average_capacity("", 3)
                            min_cap += 1
                            max_cap += 2
                            
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        fnop_indicator = False

                    elif instr.len == 3:
                        # 3 bytes NOP 0x0f1f00.
                        
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        nop6690_indicator = False
                        fnop_indicator = False
                        
                        my_instr.set_eq_class = "3B-NOP"
                        selected_my_instrs.append(my_instr)
                        
                        avg_cap += cls.__compute_average_capacity("", 6)
                        min_cap += 2
                        max_cap += 3
                    
                    elif instr.len > 3:
                        # More than 3 bytes long NOP.
                        
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        nop6690_indicator = False
                        fnop_indicator = False
                        
                        my_instr.set_eq_class = ">3B-NOP"
                        selected_my_instrs.append(my_instr)
                        
                        cap = count_useable_bytes_from_nop(
                            instr,
                            analyzer.bitness
                            )
                        avg_cap += float(cap)
                        min_cap += cap
                        max_cap += cap
                        
                    # Can not reset indicators here all at once, because
                    # this case also cover situation when 0x90 occurs.
                        
                # 2 bytes long FNOP 0xd9d0 is not included in 'is_nop',
                # therefore it must be detected separately.
                elif instr.len == 2 and \
                    op_code.op_code_string == "D9 D0":
                
                    fnop_indicator = True
                    
                    if nop90_indicator == 1:
                        # Detected sequence: 0x90; 0xd9d0
                        
                        fnop_indicator = False
                        
                        prev_nop = all_my_instrs[my_instr.ioffset - 1]
                        prev_nop.set_eq_class = "3B-NOP"
                        selected_my_instrs.append(prev_nop)
                        my_instr.set_eq_class = "3B-NOP"
                        selected_my_instrs.append(my_instr)
                        
                        avg_cap += cls.__compute_average_capacity("", 6)
                        min_cap += 2
                        max_cap += 3
                        
                    else:                            
                        # Only one FNOP detected.                        
                        my_instr.set_eq_class = "2B-NOP"
                        selected_my_instrs.append(my_instr)
                        
                        avg_cap += cls.__compute_average_capacity("", 3)
                        min_cap += 1
                        max_cap += 2
                        
                    # Reset indicators for a case they are set.
                    nop90_indicator = 0
                    nop6690_indicator = False
                        
                else:
                    # Reset indicators when non-NOP instruction occurs.
                    nop90_indicator = 0
                    nop6690_indicator = False
                    fnop_indicator = False
                        
                        
            if method == "ext-sub" or \
                method == "ext-sub-nops-mov":
                
                # TEST non-acc-(except AH)-r, imm
                # TEST /0 /1
                if re.match(
                        r'TEST [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}',
                        op_code.instruction_string
                    ) and cls.__not_acc_reg(instr):
                    
                    # my_instr.set_eq_class = \
                    #     EqClassesProcessor.all_eq_classes['TEST non-accumulator-register']
                    my_instr.set_eq_class = "TEST-non-acc-reg"
                    selected_my_instrs.append(my_instr)
                    avg_cap += 1.0
                    min_cap += 1
                    max_cap += 1
                    
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
                elif (   # OPCODE Memory, Register.
                    re.match(
                        r'.* r/m[0-9]{1,2}, r[0-9]{1,2}',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 0)
                ) or \
                (        # OPCODE Memory, Immediate.
                    re.match(
                        r'.* r/m[0-9]{1,2}, imm[0-9]{1,2}',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 0)
                ) or \
                (        # OPCODE Register, Memory.
                    re.match(
                        r'.* r[0-9]{1,2}, r/m[0-9]{1,2}',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 1)
                ):
                    
                    # my_instr.set_eq_class = \
                    #     EqClassesProcessor.all_eq_classes['Swap base-index']
                    my_instr.set_eq_class = "swap-base-index-regs"
                    selected_my_instrs.append(my_instr)
                    avg_cap += 1.0
                    min_cap += 1
                    max_cap += 1
                    
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
                    
                    # my_instr.set_eq_class = \
                    #     EqClassesProcessor.all_eq_classes['SHL/SAL']
                    my_instr.set_eq_class = "shl-sal"
                    selected_my_instrs.append(my_instr)
                    avg_cap += 1.0
                    min_cap += 1
                    max_cap += 1
                    
                elif analyzer.bitness == 32:
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
                        
                        # my_instr.set_eq_class = \
                        # EqClassesProcessor.all_eq_classes[]
                        my_instr.set_eq_class = "two-opcodes-32bit"
                        selected_my_instrs.append(my_instr)
                        avg_cap += 1.0
                        min_cap += 1
                        max_cap += 1
                        
                
            if method == "sub" or \
                method == "ext-sub" or \
                method == "ext-sub-nops-mov":
                ## POZOR KED JE IMM, MOZE BYT PRVY OP. LEN REGISTER,
                ## NEMUSI BYT R/M
                ############ VYMENA OPERANDOV ak menim strany r, r/m

                ## CLASS 'tao'.
                # TEST r/m, r (TEST r, r\m does not exist).
                if re.match(
                        r'(?:TEST|OR) r/m[0-9]{1,2}, r[0-9]{1,2}',
                        op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER and \
                        instr.op0_register == instr.op1_register:
                            
                    my_instr.set_eq_class = "test-and-or"
                    selected_my_instrs.append(my_instr)
                    avg_cap += cls.__compute_average_capacity("", 3)
                    min_cap += 1
                    max_cap += 2
                
                elif re.match(
                        r'AND r/m[0-9]{1,2}, r[0-9]{1,2}',
                        op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER and \
                        instr.op0_register == instr.op1_register:
                            
                    my_instr.set_eq_class = "test-and-or"
                    selected_my_instrs.append(my_instr)
                    avg_cap += cls.__compute_average_capacity("", 3)
                    min_cap += 1
                    max_cap += 2
                    
                ## SUB-XOR CLASS
                elif re.match(
                        r'(?:SUB|XOR) (?:r/m|r)[0-9]{1,2}, (?:r|r/m)[0-9]{1,2}',
                        op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER and \
                        instr.op1_kind == OpKind.REGISTER and \
                        instr.op0_register == instr.op1_register:
                    
                    # Must check AF flag as it's sometimes set
                    # differently by instructions SUB and XOR.
                    if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.AF,
                            force
                            ):

                        my_instr.set_eq_class = "sub-xor"
                        selected_my_instrs.append(my_instr)
                        avg_cap += 2.0
                        min_cap += 2
                        max_cap += 2
   
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
                    my_instr.set_eq_class = "two-opcodes-r/m-r"
                    selected_my_instrs.append(my_instr)
                    avg_cap += 1.0
                    min_cap += 1
                    max_cap += 1
                    
                elif re.match(
    r'(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r[0-9]{1,2}, r/m[0-9]{1,2}',
                        op_code.instruction_string
                    ) and instr.op1_kind == OpKind.REGISTER:
                    # Do not to be check, as previous 'if' statement
                    # can not cause duplicates.
                    my_instr.set_eq_class = "two-opcodes-r-r/m"
                    selected_my_instrs.append(my_instr)
                    avg_cap += 1.0
                    min_cap += 1
                    max_cap += 1
                    
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
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force
                            ):

                            my_instr.set_eq_class = "add-neg"
                            selected_my_instrs.append(my_instr)
                            ########## nulu nemozem negovat, zachovam ju
                            avg_cap += 1.0
                            min_cap += 1
                            max_cap += 1
                    
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
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force
                            ):

                            my_instr.set_eq_class = "add-neg"
                            selected_my_instrs.append(my_instr)
                            avg_cap += 1.0
                            min_cap += 1
                            max_cap += 1
                    
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
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force
                            ):

                            my_instr.set_eq_class = "sub-neg"
                            selected_my_instrs.append(my_instr)
                            ########## nulu nemozem negovat, zachovam ju
                            avg_cap += 1.0
                            min_cap += 1
                            max_cap += 1
                    
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
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force
                            ):
                            
                            my_instr.set_eq_class = "sub-neg"
                            selected_my_instrs.append(my_instr)
                            avg_cap += 1.0
                            min_cap += 1
                            max_cap += 1
            
        analyzer.set_total_instrs = len(all_my_instrs)
        analyzer.set_useable_instrs = len(selected_my_instrs)
        analyzer.set_avg_capacity = avg_cap
        analyzer.set_min_capacity = min_cap
        analyzer.set_max_capacity = max_cap

        return selected_my_instrs