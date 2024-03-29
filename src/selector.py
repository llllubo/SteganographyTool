"""
`Selector` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""

import re
import sys

from iced_x86 import *
from my_instruction import MyInstruction
from analyzer import Analyzer
from common import count_useable_bits_from_nop
from eq_classes_processor import EqClassesProcessor


class Selector:
    """
    `Selector` is responsible for selecting potential instructions usable
    for embedding/extraction. This selection is made according to the
    used equivalent classes criteria.
    """
    
    
    @staticmethod
    def __not_acc_reg(instr: Instruction) -> bool:
        """
        Only AH register from all accumaltor registers is allowed,
        because following accumulator registers has shorter code
        missing ModR/M byte, where magic happens. This function is
        designed for TEST instruction of 'test-non-acc-reg' eq. class.
        """
        if instr.op0_kind == OpKind.REGISTER and \
           instr.op0_register != Register.AL and \
           instr.op0_register != Register.AX and \
           instr.op0_register != Register.EAX and \
           instr.op0_register != Register.RAX:
            return True
        
        return False
    
    
    @staticmethod
    def __non_ebp_esp_reg(reg: Register_) -> bool:
        """
        Decide if given register is one of (E)BP or (E)SP registers.
        """
        if reg == Register.RSP or \
            reg == Register.RBP or \
            reg == Register.ESP or \
            reg == Register.EBP or \
            reg == Register.SP or \
            reg == Register.BP or \
            reg == Register.SPL or \
            reg == Register.BPL:
            return False
        
        return True
    
    
    @classmethod
    def __can_swap(cls, instr: Instruction, operand: int) -> bool:
        """
        Decide if base ans index memory registers can be swapped.
        """
        if instr.op_kind(operand) == OpKind.MEMORY and \
            instr.memory_base != Register.NONE and \
            instr.memory_index != Register.NONE and \
            instr.memory_base != instr.memory_index and \
            cls.__non_ebp_esp_reg(instr.memory_base) and \
            cls.__non_ebp_esp_reg(instr.memory_index) and \
            instr.memory_index_scale == 1:
            
            return True
        
        return False
    
    
    @staticmethod
    def __is_stack_reg(instr: Instruction) -> bool:
        """
        Check occurence of stack register within given instruction.
        """
        if instr.op0_kind == OpKind.REGISTER and \
            (
                instr.op0_register == Register.RSP or \
                instr.op0_register == Register.ESP or \
                instr.op0_register == Register.SP or \
                instr.op0_register == Register.SPL
            ):
            return True
        return False
    
    
    @staticmethod
    def __liveness_flags_detection(all_instrs: list,
                                   my_instr: MyInstruction,
                                   rflags_to_check: int,
                                   force_flag: bool) -> bool:
        """
        Liveness detection of modified flags by replacement instruction.
        Check given flags if they are live until any instruction which
        modifies it come. Execution flow is respected while checking.
        Flag is live if instruction which reads it come earlier than
        instruction which modofies it. Basic checking is done until
        any jump is present. If 'force' flag was given by user,
        unconditional jumps are traced and this can achieve bigger
        capacity. The end of any function stops checking with positive
        result.
        """
        if rflags_to_check == RflagsBits.NONE:
            return True
        
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

        # In 'my_instr' is always present next instruction from
        # previous one.
        my_instr = all_instrs[my_instr.ioffset + 1]
        
        while True:
            
            rflags_read = my_instr.instruction.rflags_read
            rflags_modified = my_instr.instruction.rflags_modified

            for idx, rflag in enumerate(check_rflags):
                # Liveness detection of checked flags.
                
                if (rflag & rflags_read) != 0:
                    # Instruction tests checked flag.
                    return False
                
                if (rflag & rflags_modified) != 0:
                    # Instruction modifies checked flag.
                    safe_rflags[idx] = True
                    
                    # End immediately when all flags are safe.
                    if False not in safe_rflags:
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
            elif force_flag and \
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
                        return False
                
                else:
                    return False
                    
                found_instr = [my_instr 
                                for my_instr in all_instrs 
                                    if my_instr.instruction.ip == get_target]
                
                if found_instr:
                    my_instr = found_instr[0]
                else:
                    return False
            
            else:   
                return False

        return True
    
    
    @staticmethod
    def __check_regs_dependency(bitness: int,
                                reg0: Register_,
                                reg1: Register_) -> bool:
        """
        Check if given registers are influenced by each other (e.g. EAX
        & RAX).
        """
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
        """
        Decide if memory operand of given instruction uses register `reg`.
        """
        if instr.memory_base != Register.NONE and \
            cls.__check_regs_dependency(bitness, instr.memory_base, reg):
            return True
        if instr.memory_index != Register.NONE and \
            cls.__check_regs_dependency(bitness, instr.memory_index, reg):
            return True
        
        return False

    
    # ak do registra zapisujem, nesmiem uz z neho citat !!! ak sa nachadza v MEMORY, je to citanie !!! citat z neho mozem len v tej istej instruckii .
    # ak zapisujem do MEM, z tohto miesta uz nesmiem citat ani tam zapisat.
    @classmethod
    def __check_independency(cls,
                             prev_mov: Instruction,
                             curr_mov: Instruction,
                             bitness: int) -> bool:
        """
        Two registers are dependent on each other if their order is
        irreplaceable.
        
        If write to any register is performed, it can not be used
        anymore (bith sides). If register occurs on left side as
        memory operand, it's reading from it and can be used next time
        (MOV rax, rax; MOV rax, [rax]).
        
        From specific register or memory location can be read more
        times. If it's writing to any memory location, this location
        can not be used anymore.
        """
        
        # Can not be exactly two same MOV instructions.
        if prev_mov.eq_all_bits(curr_mov):
            return False
        # In case when they are not equal in bits, because of they
        # differ only in Direction Bit as MOV can -- in that case they
        # actually are equal and can not be ordered lexicographically.
        elif f"{prev_mov:ix}" == f"{curr_mov:ix}":
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
    
    
    @staticmethod
    def __set_eq_class(instr: MyInstruction, eq_class_name: str) -> None:
        """
        Assign desired equivalent class object to the `MyInstruction`
        object according to given eq. class name.
        """
        for obj_eq_class in EqClassesProcessor.all_eq_classes:
            if obj_eq_class.class_name == eq_class_name:
                instr.set_eq_class = obj_eq_class
    
    
    @classmethod
    def select(cls,
               all_my_instrs: list,
               method: str,
               force_flag: bool,
               fexe: str,
               analyzer: Analyzer) -> list:
        """
        Select instructions according to the used equivalent classes.
        """
        selected_my_instrs = []
        nop90_indicator = 0
        nop6690_indicator = False
        fnop_indicator = False
        mov_indicator = False
        avg_cap = 0.0       # In BITS
        min_cap = 0         # In BITS
        max_cap = 0         # In BITS
        
        # File is opened because of more than 3 bytes long NOP class and
        # is closed at the end of Selector.
        try:
            fd = open(fexe, "rb")
        except IOError:
            print(f"ERROR! Can not open cover-file for analysis: ", file=sys.stderr)
            sys.exit(102)
        
        for my_instr in all_my_instrs:
            
            instr = my_instr.instruction
            op_code = my_instr.instruction.op_code()

            ## NOT IMPLEMENTED YET.
            if method == "mov":
                
                # Two MOVs in a row.
                if instr.mnemonic == Mnemonic.MOV:
                    if mov_indicator:
                        # Got two MOVs in a row.
                        # Need to check their independency.
                        prev_mov = all_my_instrs[my_instr.ioffset - 1]
                        
                        if cls.__check_independency(prev_mov.instruction,
                                                    instr,
                                                    analyzer.bitness):
                            
                            if prev_mov.eq_class is not None and \
                                (
                                    prev_mov.eq_class.class_name == "MOV" or \
                                    prev_mov.eq_class.class_name == \
                                        "Swap base-index registers 32-bit"
                                ):
                                # Previous MOV has already got eq_class
                                # and also was selected.
                                prev_mov.set_mov_scheduling_flag = True
                                
                            else:
                                # Previous MOV has not any eq_class and
                                # was not selected yet.
                                cls.__set_eq_class(prev_mov, "MOV Scheduling")
                                selected_my_instrs.append(prev_mov)
                            
                            # Current MOV will be checked similarly in
                            # MOV equivalent class.
                            cls.__set_eq_class(my_instr, "MOV Scheduling")
                            selected_my_instrs.append(my_instr)
                            
                            # Reset indicator only if MOV instructions
                            # are independent and can be used, otherwise
                            # if next instruction will be MOV,
                            # dependency check will be performed again.
                            mov_indicator = False
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                            
                    else:
                        # Set indicator.
                        mov_indicator = True
                else:
                    # Reset indicator.
                    mov_indicator = False


            if method == "nops" or \
                method == "ext-sub-nops":
                
                # 1 byte NOPs 0x90.
                if op_code.is_nop and instr.len == 1:
                    
                    if nop90_indicator > 0:
                        # 2nd or 3rd NOP 0x90 detected.
                        
                        if nop90_indicator == 1:
                            # 2nd NOP 0x90 detected.
                            nop90_indicator = 2
                            
                            prev_nop = all_my_instrs[my_instr.ioffset - 1]
                            cls.__set_eq_class(prev_nop, "2 Bytes Long NOP")
                            selected_my_instrs.append(prev_nop)
                            
                            cls.__set_eq_class(my_instr, "2 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                        
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                        
                        elif nop90_indicator == 2:
                            # 3rd NOP 0x90 detected.
                            
                            # Reset indicator.
                            nop90_indicator = 0
                            
                            # Computation must also be returned.
                            avg_cap -= selected_my_instrs[-1].eq_class.avg_cap
                            min_cap -= selected_my_instrs[-1].eq_class.min_cap
                            max_cap -= selected_my_instrs[-1].eq_class.max_cap
                            
                            cls.__set_eq_class(
                                selected_my_instrs[-2], "3 Bytes Long NOP")
                            cls.__set_eq_class(
                                selected_my_instrs[-1], "3 Bytes Long NOP")
                            cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                            
                            # Fix computation.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                        
                    else:
                        # 1st NOP 0x90 detected.
                        nop90_indicator = 1
                        
                        if nop6690_indicator:
                            # Detected sequence: 0x6690; 0x90.
                            
                            # Reset indicators.
                            nop90_indicator = 0
                            nop6690_indicator = False

                            # Computation must also be returned.
                            avg_cap -= selected_my_instrs[-1].eq_class.avg_cap
                            min_cap -= selected_my_instrs[-1].eq_class.min_cap
                            max_cap -= selected_my_instrs[-1].eq_class.max_cap
                            
                            cls.__set_eq_class(
                                selected_my_instrs[-1], "3 Bytes Long NOP")
                            cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                            
                            # Fix computation.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                        
                        elif fnop_indicator:
                            # Detected sequence: 0xd9d0; 0x90.
                            
                            # Reset indicators.
                            nop90_indicator = 0
                            fnop_indicator = False
                            
                            # Computation must also be returned.
                            avg_cap -= selected_my_instrs[-1].eq_class.avg_cap
                            min_cap -= selected_my_instrs[-1].eq_class.min_cap
                            max_cap -= selected_my_instrs[-1].eq_class.max_cap
                            
                            cls.__set_eq_class(
                                selected_my_instrs[-1], "3 Bytes Long NOP")
                            cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                            
                            # Fix computation.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                    
                # Multi-byte NOP.
                if op_code.is_nop:
                    
                    if instr.len == 2:
                        # 2 bytes NOP 0x6690 detected.
                        nop6690_indicator = True
                        
                        if nop90_indicator == 1:
                            # Detected sequence: 0x90; 0x6690
                            
                            nop6690_indicator = False
                            
                            prev_nop = all_my_instrs[my_instr.ioffset - 1]
                            cls.__set_eq_class(prev_nop, "3 Bytes Long NOP")
                            selected_my_instrs.append(prev_nop)
                            cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                            
                        else:                            
                            # Only one NOP 0x6690 detected.
                            cls.__set_eq_class(my_instr, "2 Bytes Long NOP")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                            
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        fnop_indicator = False

                    elif instr.len == 3:
                        # 3 bytes NOP 0x0f1f00.
                        
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        nop6690_indicator = False
                        fnop_indicator = False
                        
                        cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        avg_cap += my_instr.eq_class.avg_cap
                        min_cap += my_instr.eq_class.min_cap
                        max_cap += my_instr.eq_class.max_cap
                    
                    elif instr.len > 3:
                        # More than 3 bytes long NOP.
                        
                        # Reset indicators for a case they are set.
                        nop90_indicator = 0
                        nop6690_indicator = False
                        fnop_indicator = False
                        
                        cls.__set_eq_class(my_instr, ">3 Bytes Long NOP")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        fd.seek(my_instr.foffset)
                        cap = count_useable_bits_from_nop(instr,
                                                          fd.read(len(instr)))
                        avg_cap += float(cap)
                        min_cap += cap
                        max_cap += cap
                        
                    # Can not reset indicators all at once here, because
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
                        cls.__set_eq_class(prev_nop, "3 Bytes Long NOP")
                        selected_my_instrs.append(prev_nop)
                        
                        cls.__set_eq_class(my_instr, "3 Bytes Long NOP")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        avg_cap += my_instr.eq_class.avg_cap
                        min_cap += my_instr.eq_class.min_cap
                        max_cap += my_instr.eq_class.max_cap
                        
                    else:                            
                        # Only one FNOP detected.                        
                        cls.__set_eq_class(my_instr, "2 Bytes Long NOP")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        avg_cap += my_instr.eq_class.avg_cap
                        min_cap += my_instr.eq_class.min_cap
                        max_cap += my_instr.eq_class.max_cap
                        
                    # Reset indicators for a case they are set.
                    nop90_indicator = 0
                    nop6690_indicator = False
                        
                else:
                    # Reset indicators when non-NOP instruction occurs.
                    nop90_indicator = 0
                    nop6690_indicator = False
                    fnop_indicator = False
                        
                        
            if method == "ext-sub" or \
                method == "ext-sub-nops":
                
                # TEST non-acc-(except AH)-reg, imm
                # TEST /0 /1
                if re.match(
                        r'^TEST [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and cls.__not_acc_reg(instr):
                    
                    cls.__set_eq_class(my_instr, "TEST non-accumulator register")
                    selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap

                # OPCODE m, r/imm; OPCODE r, m
                # BASE-INDEX swap while SCALE is 1. It can not be used
                # if any EBP/ESP-like registers are used as they swap
                # memory segments related to their position (base-index)
                # and also it can be used only for 32-bit executables.
                # This class has higher priority over class 'SHL/SAL'
                # and, in mode 'ext-sub-nops', also over classes
                # 'ADD negated' and 'SUB negated'. It's set like that,
                # because of good stealthiness of this redundancy.
                elif analyzer.bitness == 32 and \
                ( (   # OPCODE Memory, Register.
                    re.match(
                        r'^.* r/m[0-9]{1,2}, r[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 0)
                ) or \
                (        # OPCODE Memory, Immediate.
                    re.match(
                        r'^.* r/m[0-9]{1,2}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 0)
                ) or \
                (        # OPCODE Register, Memory.
                    re.match(
                        r'^.* r[0-9]{1,2}, r/m[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and cls.__can_swap(instr, 1)
                ) ):
                    
                    mnemo = op_code.instruction_string[:3]
                        
                    # Same MOV instruction can be scheduled and also to
                    # belong to this class.
                    if mnemo == "MOV" and \
                        my_instr.eq_class is not None and \
                        my_instr.eq_class.class_name == "MOV Scheduling":
                        # MOV has already been detected for ordering.
                        cls.__set_eq_class(my_instr,
                                           "Swap base-index registers 32-bit")
                        my_instr.set_mov_scheduling_flag = True
                        
                    else:
                        cls.__set_eq_class(my_instr,
                                           "Swap base-index registers 32-bit")
                        selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                # SHL/SAL /4 /6
                # First operand is always in form r/m and second can
                # be only 1 as value (this has specific OPCODE), CL
                # register or any immediate value.
                elif re.match(
                        r'^(?:SHL|SAL) r/m[0-9]{1,2}, (?:1|CL|imm[0-9]{1,2})$',
                        op_code.instruction_string
                    ):
                    # This overlap with class 'swap-base-index', but
                    # we do not need to check it because of 'if-elif'
                    # statements.
                    # This class has lower priority than class
                    # 'swap-base-index'.
                    
                    cls.__set_eq_class(my_instr, "SHL/SAL")
                    selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                elif analyzer.bitness == 32:
                    # OPCODE = ADD|SUB|ADC|SBB|AND|OR|XOR|CMP
                    # OPCODE m8, imm8
                    # OPCODE non-al-r8, imm8
                    # AL register appears individually in mnemonics, so
                    # do not have to be checked in r/m8.
                    if re.match(
                            r'^(?:ADD|SUB|ADC|SBB|AND|OR|XOR|CMP) r/m8, imm8$',
                            op_code.instruction_string
                    ):
                        # This has affect, in 32-bit mode, on classes
                        # 'ADD negated' and 'SUB negated'. 
                        # This has lower priority than class 'Swap base-
                        # index registers', but higher than classes
                        # 'ADD negated' and 'SUB negated'.
                        
                        mnemo = op_code.instruction_string[:3]
                        if mnemo == "OR ":
                            mnemo = "OR"
                        
                        cls.__set_eq_class(my_instr, mnemo + " 32-bit")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        avg_cap += my_instr.eq_class.avg_cap
                        min_cap += my_instr.eq_class.min_cap
                        max_cap += my_instr.eq_class.max_cap
                        
                
            if method == "sub" or \
                method == "ext-sub" or \
                method == "ext-sub-nops":
                ## WARNING: When there is 'imm' in instruction string
                ## and the first operand is any register, this register
                ## can be directly specified - therefore there is
                ## special regular expression sometimes.

                # TEST/AND/OR.
                # TEST r, r\m does not exist.
                if re.match(
                        r'^TEST r/m[0-9]{1,2}, r[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER and \
                        instr.op0_register == instr.op1_register:
                    
                    cls.__set_eq_class(my_instr, "TEST/AND/OR")
                    selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                elif re.match(
                        r'^(?:AND|OR) (?:r|r/m)[0-9]{1,2}, (?:r/m|r)[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.op0_kind == OpKind.REGISTER and \
                        instr.op1_kind == OpKind.REGISTER and \
                        instr.op0_register == instr.op1_register:
                    
                    cls.__set_eq_class(my_instr, "TEST/AND/OR")
                    selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                # SUB/XOR.
                elif re.match(
                        r'^(?:SUB|XOR) (?:r/m|r)[0-9]{1,2}, (?:r|r/m)[0-9]{1,2}$',
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
                            force_flag
                            ):

                        cls.__set_eq_class(my_instr, "SUB/XOR")
                        selected_my_instrs.append(my_instr)
                        
                        # Compute capacities.
                        avg_cap += my_instr.eq_class.avg_cap
                        min_cap += my_instr.eq_class.min_cap
                        max_cap += my_instr.eq_class.max_cap
   
                ## ALL CLASSES WITH r/m, r & r, r/m INSTR. VERSIONS.
                # r/m, r versions of MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB.
                # AND and OR are in the previous 'if' as well, because
                # their priority is to belong to the class TEST/AND/OR.
                elif re.match(
    r'^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r/m[0-9]{1,2}, r[0-9]{1,2}$',
                        op_code.instruction_string
                ) and instr.op0_kind == OpKind.REGISTER:
                    
                    mnemo = op_code.instruction_string[:3]
                        
                    # Same MOV instruction can be scheduled and also to
                    # belong to this class.
                    if mnemo == "MOV" and \
                        my_instr.eq_class is not None and \
                        my_instr.eq_class.class_name == "MOV Scheduling":
                        # MOV has already been detected for ordering.
                        cls.__set_eq_class(my_instr, mnemo)
                        my_instr.set_mov_scheduling_flag = True
                        
                    else:
                        if mnemo == "OR ":
                            mnemo = "OR"
                        
                        cls.__set_eq_class(my_instr, mnemo)
                        selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                elif re.match(
    r'^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r[0-9]{1,2}, r/m[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.op1_kind == OpKind.REGISTER:
                    
                    mnemo = op_code.instruction_string[:3]
                    
                    # Same MOV instruction can be scheduled and also to
                    # belong to this class.
                    if mnemo == "MOV" and \
                        my_instr.eq_class is not None and \
                        my_instr.eq_class.class_name == "MOV Scheduling":
                        # MOV is already detected for ordering.
                        cls.__set_eq_class(my_instr, mnemo)
                        my_instr.set_mov_scheduling_flag = True
                        
                    else:
                        if mnemo == "OR ":
                            mnemo = "OR"
                        
                        cls.__set_eq_class(my_instr, mnemo)
                        selected_my_instrs.append(my_instr)
                    
                    # Compute capacities.
                    avg_cap += my_instr.eq_class.avg_cap
                    min_cap += my_instr.eq_class.min_cap
                    max_cap += my_instr.eq_class.max_cap
                    
                # CLASSES ADD & SUB WITH THEIR NEGATED IMMEDIATES.
                # ADD r/m, imm
                elif re.match(
                        r'^ADD [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.immediate(1) >= 0 and \
                        not cls.__is_stack_reg(instr):
                    # Must check because of mode 'ext-sub-nops' where
                    # class 'swap-base-index' (2nd part of 'if'
                    # statement) can take same instruction earlier, but
                    # also in 32-bit mode this can cause classes
                    # '.* 32-bit'.
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force_flag
                            ):
                            
                            cls.__set_eq_class(my_instr, "ADD negated")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                    
                # SUB r/m, -imm .. NEGATED
                elif re.match(
                        r'^SUB [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.immediate(1) < 0 and \
                        not cls.__is_stack_reg(instr):
                    # Must check because of mode 'ext-sub-nops' where
                    # class 'swap-base-index' (2nd part of 'if'
                    # statement) can take same instruction earlier, but
                    # also in 32-bit mode this can cause classes
                    # '.* 32-bit'.
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force_flag
                            ):

                            cls.__set_eq_class(my_instr, "ADD negated")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                    
                # SUB r/m, imm
                elif re.match(
                        r'^SUB [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.immediate(1) >= 0 and \
                        not cls.__is_stack_reg(instr):
                    # Must check because of mode 'ext-sub-nops' where
                    # class 'swap-base-index' (2nd part of 'if'
                    # statement) can take same instruction earlier, but
                    # also in 32-bit mode this can cause classes
                    # '.* 32-bit'.
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force_flag
                            ):

                            cls.__set_eq_class(my_instr, "SUB negated")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
                    
                # ADD r/m, -imm .. NEGATED
                elif re.match(
                        r'^ADD [a-zA-Z0-9/]{1,6}, imm[0-9]{1,2}$',
                        op_code.instruction_string
                    ) and instr.immediate(1) < 0 and \
                        not cls.__is_stack_reg(instr):
                    # Must check because of mode 'ext-sub-nops' where
                    # class 'swap-base-index' (2nd part of 'if'
                    # statement) can take same instruction earlier, but
                    # also in 32-bit mode this can cause classes
                    # '.* 32-bit'.
                    if selected_my_instrs and \
                        id(selected_my_instrs[-1]) != id(my_instr):
                        
                        # Must check OF, CF, AF flags as they are 
                        # sometimes set differently by ADD and SUB.
                        if cls.__liveness_flags_detection(
                            all_my_instrs,
                            my_instr,
                            RflagsBits.OF | RflagsBits.CF | RflagsBits.AF,
                            force_flag
                            ):
                            
                            cls.__set_eq_class(my_instr, "SUB negated")
                            selected_my_instrs.append(my_instr)
                            
                            # Compute capacities.
                            avg_cap += my_instr.eq_class.avg_cap
                            min_cap += my_instr.eq_class.min_cap
                            max_cap += my_instr.eq_class.max_cap
        
        
        fd.close()
        # Fullfil analyzer attributes.
        analyzer.set_total_instrs = len(all_my_instrs)
        analyzer.set_useable_instrs = len(selected_my_instrs)
        analyzer.set_avg_capacity = avg_cap
        analyzer.set_min_capacity = min_cap
        analyzer.set_max_capacity = max_cap

        return selected_my_instrs