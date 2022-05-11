"""
`Embedder` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""


import os
import re
import sys
import math
import lzma
from cryptography.fernet import Fernet

from iced_x86 import *
from bitarray import *
from analyzer import Analyzer
from eq_classes_processor import EqClassesProcessor
import common
from my_instruction import MyInstruction


class Embedder:
    """
    `Embedder` is responsible for preprocessing secret message and
    embedding it.
    """
    
    __b_passwd = None
    """
    Storage of given password in bytes.
    """
    
    
    @staticmethod
    def get_secret_data(secret_message: str) -> tuple:
        """
        Parse given secret message. If file path was given, content of
        it is going to be converted to bytes and embedded, and file
        extension is parsed and converted as well. If only string was
        given it's coverted to bytes as well, and file extension txt
        will be embedded.
        """
        
        if os.path.isfile(secret_message):
            # The whole file is going to be embedded.
            b_fext = common.get_file_extension(secret_message)
            
            try:
                fd = open(secret_message, "rb")
            except IOError:
                print("ERROR! Can not access file of embedding data: {args.secret_message}", file=sys.stderr)
                sys.exit(104)
            
            b_secret_data = fd.read()
            fd.close()
        else:
            # Embedded will be just string.
            b_secret_data = secret_message.encode()
            # If no file was given, txt extension will be used (8 bytes).
            b_fext = b'txt'
            b_fext += bytes(common.SIZE_OF_FEXT - len(b_fext))
        
        return (b_secret_data, b_fext)
    
    
    @staticmethod
    def compress(content: bytes) -> bytes:
        """
        Compress given bytes with LZMA algorithm.
        """
        
        lzc = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=0)
        
        try:
            b_comp1 = lzc.compress(content)
        except lzma.LZMAError:
            print("ERROR! While preprocessing secret message an error occured.", file=sys.stderr)
            sys.exit(104)
        
        b_comp2 = lzc.flush()
        
        return (b_comp1 + b_comp2)
    
    
    @classmethod
    def encrypt_data(cls, data: bytes) -> bytes:
        """
        Encrypt given data in bytes with given password.
        """
        
        b_key, cls.__b_passwd = common.gen_key_from_passwd()
        cipher = Fernet(b_key)
        b_encrypted = cipher.encrypt(data)
        
        return b_encrypted
    
    
    @classmethod
    def xor_data_len(cls, encrypted: bytes) -> bytes:
        """
        Function returns XORed length of embedding data.
        """

        # Must be in bytes, because password is in the bytes as well.
        b_encrypted_len = \
           len(encrypted).to_bytes(common.SIZE_OF_DATA_LEN, byteorder="little")
        
        # Prepare password length ONLY for XOR operation.
        if len(cls.__b_passwd) <= common.SIZE_OF_DATA_LEN:
            b_passwd = cls.__b_passwd
            b_passwd += bytes(common.SIZE_OF_DATA_LEN - len(cls.__b_passwd))
        else:
            b_passwd = cls.__b_passwd[:common.SIZE_OF_DATA_LEN]

        # Data length bytes are going to be XORed with password of same
        # size. If given password is longer, it's truncated. This is
        # security reason as if whole password bytes were XORed with null
        # padding of data length bytes, password characters would map to
        # the XORed data length and could be readable. Reversed cycle is
        # used to avoid problem when null byte is in the middle of data.
        null_padding = 0
        
        for b in reversed(b_encrypted_len):
            if b != 0:
                break
            null_padding += 1
        
        i = common.SIZE_OF_DATA_LEN - null_padding
        
        b_xored_len = \
            bytes([a ^ b for a, b in zip(b_encrypted_len, b_passwd[:i])])
        
        # Add null bytes after XOR.
        b_xored_len += bytes(common.SIZE_OF_DATA_LEN - len(b_xored_len))
        
        return b_xored_len
    
    
    @classmethod
    def xor_fext(cls, fext: bytes) -> bytes:
        """
        XOR given file extension in bytes with password and return it.
        """   

        # XOR only if there is any file extension.
        if fext != bytes(common.SIZE_OF_FEXT):
            # Prepare password length ONLY for XOR operation.
            if len(cls.__b_passwd) <= common.SIZE_OF_FEXT:
                b_passwd = cls.__b_passwd
                b_passwd += bytes(common.SIZE_OF_FEXT - len(cls.__b_passwd))
            else:
                b_passwd = cls.__b_passwd[:common.SIZE_OF_FEXT]
            
            # File extension bytes are going to be XORed with password
            # of same size. If given password is longer, it's truncated.
            # This is security reason as if whole password bytes were
            # XORed with null padding of data length bytes, password
            # characters would map to the XORed data length and could be
            # readable. Reversed cycle is used to avoid problem when
            # null byte is in the middle of data.
            null_padding = 0
            
            for b in reversed(fext):
                if b != 0:
                    break
                null_padding += 1
            
            i = common.SIZE_OF_FEXT - null_padding
            
            b_xored_fext = bytes([a ^ b for a, b in zip(fext, b_passwd[:i])])
            
            # Add null bytes after XOR.
            b_xored_fext += bytes(common.SIZE_OF_FEXT - len(b_xored_fext))
            
            return b_xored_fext
        
        return fext
    
    
    @staticmethod
    def check_cap(mess_len: int, analyzer: Analyzer) -> None:
        """
        Check if message with given length after preprocessing can be
        embedded and exit the program if not.
        """

        if mess_len > (analyzer.min_capacity / 8):
            print(f"ERROR! Capacity of cover-file is not sufficient and data can not be embedded!", file=sys.stderr)
            sys.exit(104)
                
                
    @staticmethod
    def __find_encoded_idx(eq_class: EqClassesProcessor,
                           bits_mess: bitarray) -> int:
        """
        Map first bits (of reasonable lenght) from message bits to the
        encoding index of particular equivalent class member index.
        """
        
        mem_len = len(eq_class.members)
        is_power_of_2 = (bin(mem_len).count("1") == 1)

        if not is_power_of_2:
            # If variable length encoding was used, 1st try is to take
            # maximum number of bits that can be embedded by current
            # equivalent class.
            max_bits = math.ceil(math.log2(mem_len) - 1) + 1
        else:
            # Fixed length encoding was used, therefore only max. number
            # of bits will be tested.
            max_bits = int(math.log2(mem_len))
        
        # Correctness of message length if last bits are going to be
        # embedded - zeros padding.
        added_nulls = None
        if max_bits > len(bits_mess):
            added_nulls = bitarray(max_bits - len(bits_mess))
            added_nulls.setall(0)
            bits_mess.extend(added_nulls)
        
        # 1st try to find appropriate encoding with max. allowed length
        # and also the only one try if fixed length encoding was used.
        for idx, encoded_idx in enumerate(eq_class.encoded_idxs):
            if encoded_idx == bits_mess[:max_bits]:
                return idx

        # 2nd try to find appropriate encoding with min. allowed length.
        # This has to always find useable encoding, if 1st try was
        # unsuccessful, in case of variable length encoding.
        if not is_power_of_2:
            min_bits = max_bits - 1
            
            # Pop zero padding if was added.
            if added_nulls is not None:
                bits_mess.pop()
            
            for idx, encoded_idx in enumerate(eq_class.encoded_idxs):
                if encoded_idx == bits_mess[:min_bits]:
                    return idx
            
            
    @staticmethod
    def __get_rex_idx(instr_fromf: bytes, opcode_idx: int) -> int:
        """
        REX prefix, if present, is placed immediately before opcode,
        return its index within whole instruction bytes.
        """
        
        if opcode_idx != 0:
            # Try to find out if REX prefix is present.
            i = opcode_idx - 1
            rex = bitarray()
            while True:
                # Check if there is any more byte opcode prefix (LEGACY).
                if instr_fromf[i:i+1] == b"\x0f" or \
                    instr_fromf[i:i+1] == b"\x38" or \
                    instr_fromf[i:i+1] == b"\x3a":

                    if i == 0:
                        # There is no REX, only more bytes long opcode.
                        return -1
                    # Go and check next byte.
                    i -= 1
                else:
                    # Here must be REX prefix, if not REX is not present.
                    rex.frombytes(instr_fromf[i:i+1])
                    if rex[:4] == bitarray('0100'):
                        # Found REX prefix.
                        return i
                    else:
                        # There is no REX prefix.
                        return -1
        else:
            # There is no REX prefix.
            return -1
    
    
    @staticmethod
    def __can_schedule_mov(instr_mov0: MyInstruction,
                       instr_mov1: MyInstruction) -> bool:
        """
        Decide if MOVs will be used for embedding - same check will be
        done by extractor.
        """
        
        mov0 = f"{instr_mov0.instruction}"
        mov1 = f"{instr_mov1.instruction}"
        if common.lexicographic_mov_sort(mov0) == \
            common.lexicographic_mov_sort(mov1):
            # It is signing tak they can not be scheduled. It happens
            # extremely rare.
            return False

        return True        
    
    
    @classmethod
    def __should_swap_mov(cls,
                          instr_mov0: MyInstruction,
                          instr_mov1: MyInstruction,
                          idx: int) -> bool:
        """
        Decide if MOV pair should be swapped according to the next
        embedding bit of information.
        """
        
        # Get instruction string.
        mov0 = f"{instr_mov0.instruction}"
        mov1 = f"{instr_mov1.instruction}"
        
        # There is possibility that both will have set only scheduling
        # flag and then could not be decided what ordering would be
        # used. Therefore must be accessed to the array of all
        # equivalent classes and read out configured ordering from file.
        for eq_class in EqClassesProcessor.all_eq_classes:
            if eq_class.class_name == "MOV Scheduling":
                ordering = eq_class.members[idx]
        
        if ordering == "Ascending" and \
            common.lexicographic_mov_sort(mov0) > common.lexicographic_mov_sort(mov1):
            return True
        
        elif ordering == "Descending" and \
            common.lexicographic_mov_sort(mov0) < common.lexicographic_mov_sort(mov1):
            return True
        
        return False
        
        
    @classmethod
    def __should_swap_base_index(cls, instr: MyInstruction, idx: int) -> bool:
        """
        Find out if base and index memory registers should be swapped
        according to desired order determined by next encoding bit of
        message.
        """

        if instr.eq_class.members[idx] == "Ascending" and \
            instr.instruction.memory_base > instr.instruction.memory_index:
            return True
        
        elif instr.eq_class.members[idx] == "Descending" and \
            instr.instruction.memory_base < instr.instruction.memory_index:
            return True
        
        return False


    @staticmethod
    def __swap_base_index(rex_idx: int,
                          opcode_idx: int,
                          bits_instr: bitarray) -> bool:
        """
        Last parameter of function is going to be changed and then
        will be used outside function.
        """
        
        # First, swap REX prefix bits if available.
        if rex_idx != -1:
            # There was REX prefix detected.
            rex_b_bit_offset = rex_idx * 8 + 7
            rex_b_bit = bits_instr[rex_b_bit_offset]
            rex_x_bit_offset = rex_idx * 8 + 6
            rex_x_bit = bits_instr[rex_x_bit_offset]
            bits_instr[rex_b_bit_offset] = rex_x_bit
            bits_instr[rex_x_bit_offset] = rex_b_bit
        
        # Second, swap SIB.base and SIB.index registers.
        sib_sign_offset = (opcode_idx + 1) * 8 + 5
        if bits_instr[sib_sign_offset:sib_sign_offset + 3] == \
            bitarray('100'):
            # Just to make sure, that SIB byte is present.
            sib_offset = (opcode_idx + 2) * 8
            base_offset = sib_offset + 5
            index_offset = sib_offset + 2
            bits_base = bits_instr[base_offset:base_offset + 3]
            bits_index = bits_instr[index_offset:index_offset + 3]
            bits_instr[base_offset:base_offset + 3] = bits_index
            bits_instr[index_offset:index_offset + 3] = bits_base
        else:
            # Something goes wrong and SIB byte sign is not
            # ok - instruction is not used for embedding.
            return False

        return True
    
    
    @staticmethod
    def __swap_rm_r_operands(rex_idx: int,
                             opcode_idx: int,
                             bits_instr: bitarray) -> None:
        """
        Last parameter of function is going to be changed and then
        will be used outside function.
        """
        
        # First, swap REX prefix bits if available.
        if rex_idx != -1:
            # There was REX prefix detected.
            rex_b_bit_offset = rex_idx * 8 + 7
            rex_b_bit = bits_instr[rex_b_bit_offset]
            rex_r_bit_offset = rex_idx * 8 + 5
            rex_r_bit = bits_instr[rex_r_bit_offset]
            bits_instr[rex_b_bit_offset] = rex_r_bit
            bits_instr[rex_r_bit_offset] = rex_b_bit
        
        # Locate Reg/Opcode field inside ModR/M byte.
        reg_field_offset = (opcode_idx + 1) * 8 + 2
        reg_bits = bits_instr[reg_field_offset:(reg_field_offset + 3)]
        # Locate rm field inside ModR/M byte.
        rm_field_offset = (opcode_idx + 1) * 8 + 5
        rm_bits = bits_instr[rm_field_offset:(rm_field_offset + 3)]
        
        # Rewrite required Reg/Opcode field bits inside instruction.
        bits_instr[reg_field_offset:(reg_field_offset + 3)] = rm_bits
        # Rewrite required rm field bits inside instruction.
        bits_instr[rm_field_offset:(rm_field_offset + 3)] = reg_bits
    
    
    @staticmethod
    def __create_opcode(instr: MyInstruction, idx: int) -> bytes:
        """
        Create desired OPCODE for instructions of equivalent classes
        'TEST/AND/OR' and 'SUB/XOR'.
        """
        
        if OpCodeInfo(instr.instruction.code).operand_size == 0:
            # Correctness of OPCODE if 1 byte operand.
            new_opcode = int(instr.eq_class.members[idx][2:], 16)
            new_opcode -= 1
            b_new_opcode = new_opcode.to_bytes(OpCodeInfo(instr.instruction.code).op_code_len, byteorder="little")
            
        else:
            # Without any correctness, only get OPCODE from
            # class member.
            b_new_opcode = bytes.fromhex(instr.eq_class.members[idx][2:])
            
        return b_new_opcode


    @staticmethod
    def __make_ADD_SUB_opcode(instr: Instruction,
                                opcode_idx: int,
                                bits_to_embed: bitarray,
                                bits_instr: bitarray) -> None:
        """
        Embed ADD or SUB OPCODE according to the next encoding bits.
        There is special case of AL register operand when OPCODES of
        ADD and SUB differ and they must be changed. Also, in this
        case there is no ModR/M byte, so Reg/Opcode can not be
        modified. Otherwise, OPCODES stay same and Reg/Opcode field of
        ModR/M byte is changed only.
        Last parameter of function is going to be changed and then
        will be used outside function.
        """
        
        if instr.op0_kind == OpKind.REGISTER and \
            instr.op0_register == Register.AL:
            # Register AL has special OPCODE without ModR/M.
            
            new_opcode = bitarray()
            if bits_to_embed == bitarray('000'):
                # ADD is going to be embedded.
                new_opcode.frombytes(bytes.fromhex("04"))
            else:
                # SUB is going to be embedded.
                new_opcode.frombytes(bytes.fromhex("2c"))
            
            opcode_offset = opcode_idx * 8
            opcode_len = OpCodeInfo(instr.code).op_code_len * 8
            bits_instr[opcode_offset:(opcode_offset + opcode_len)] = new_opcode
        else:
            # Locate Reg/Opcode field inside ModR/M byte.
            reg_field_offset = (opcode_idx + 1) * 8 + 2
            # Rewrite required bits inside instruction.
            bits_instr[reg_field_offset:(reg_field_offset + 3)] = bits_to_embed
    
    
    @staticmethod
    def __twos_complement(instr: Instruction, op_size: int) -> bytes:
        """
        Make two's complement of immediate operand.
        """
    
        # print(f"instr.immediate(1):x -- {instr.immediate(1):x}")
    
        # bits_imm = bitarray()
        # bits_imm.frombytes(instr.immediate(1).to_bytes(op_size,
        #                                                byteorder="little",
        #                                                signed=True))
        # print(f"{bits_imm}")
        # # bits_imm = ~bits_imm
        # # print(f"{bits_imm}")
        # # bits_imm += 1
        # # print(f"{bits_imm}")
        
        # # sys.exit()
        # print(f"{imm:x}")
        
        bits_number = int("{0:08b}".format(instr.immediate(1)))
        flipped_bits_number = ~ bits_number
        flipped_bits_number = flipped_bits_number + 1
        str_twos_complement = str(flipped_bits_number)
            
        return int(str_twos_complement, 2).to_bytes(
            op_size,
            byteorder="little",
            signed=True)
        
        # imm = instr.immediate(1)
        # bits_size = op_size * 8
        # if imm < 0:
        #     imm = (1 << bits_size) + imm
        # else:
        #     if (imm & (1 << (bits_size - 1))) != 0:
        #         # If sign bit is set.
        #         # compute negative value.
        #         imm = imm - (1 << bits_size)
        # print(f"{imm:x}")
        # return imm
            
            
    @staticmethod
    def __get_imm_idx(instr_fromf: bytes, imm: int, op_size: int) -> int:
        """
        Get index position of immediate operand inside instruction.
        """
        
        b_imm = imm.to_bytes(op_size, byteorder="little", signed=True)
        
        # print(f"b_imm: {b_imm.hex()}")
        
        return instr_fromf.find(b_imm)

    
    @classmethod
    def embed(cls,
              fexe: str,
              mess: bytes,
              potential_my_instrs: list,
              verbose: bool) -> None:
        """
        Embed given secret message.
        """

        # Skip flag defines how many next instructions should be
        # skipped as they were already used by first instruction
        # from their group (3 and 2 Bytes Long NOP classes).
        skip = 0
        
        # Determines if MOVs were already scheduled. It's False at the
        # beginning, but first MOV set it to True after they are
        # scheduled.
        movs_scheduled = False
        
        bits_mess = bitarray(endian="little")
        bits_mess.frombytes(mess)
        
        try:
            fd = open(fexe, "r+b")
        except IOError:
            print(f"ERROR! Can not open cover file for embedding: {fexe}",
                  file=sys.stderr)
            sys.exit(104)
        
        for instr_idx, my_instr in enumerate(potential_my_instrs):
            
            if skip:
                # Skip current NOP instruction.
                skip -= 1
                continue
            
            # For speed performance.
            eq_class = my_instr.eq_class
            instr = my_instr.instruction
            
            # Instructions that don't have encoding LEGACY are skipped.
            # Legacy encoding for opcodes of instructions is mainly used
            # in each PE and ELF (32- and 64-bit) executables and others
            # encodings are very rare.
            if eq_class is not None and \
                instr.encoding == EncodingKind.LEGACY:
                
                # Encoding is lexicographic order of used instructions
                # strings and it's determined by configuration file.
                if (eq_class.class_name == "MOV Scheduling" or \
                    my_instr.mov_scheduling_flag) and not movs_scheduled:

                    ## Second MOV is current, both can be scheduled now.

                    # Set flag with first MOV - This is only tag for
                    # knowledge that first MOV was tried to be scheduled.
                    movs_scheduled = True

                    if cls.__can_schedule_mov(my_instr,
                                              potential_my_instrs[instr_idx+1]):
                    
                        next_mov = potential_my_instrs[instr_idx + 1]
                        
                        # Find out desired order for MOVs according to
                        # the encoding.
                        idx = cls.__find_encoded_idx(eq_class, bits_mess)

                        # Decide if both MOVs should be swapped according to
                        # the next secret message bits or if they are in the
                        # right order.
                        if cls.__should_swap_mov(my_instr, next_mov, idx):
                            # MOVs are going to be swapped.
                            
                            # Read instruction bytes of 1st MOV.
                            fd.seek(my_instr.foffset)
                            b_mov0_fromf = fd.read(len(instr))
                            
                            # Read instruction bytes of 2nd MOV.
                            fd.seek(next_mov.foffset)
                            b_mov1_fromf = fd.read(len(next_mov.instruction))
                            
                            # Swap them.
                            fd.seek(my_instr.foffset)
                            fd.write(b_mov1_fromf)
                            
                            fd.seek(my_instr.foffset + len(next_mov.instruction))
                            fd.write(b_mov0_fromf)
                            
                        # Delete already embedded order bit from list.
                        del bits_mess[:len(eq_class.encoded_idxs[idx])]
                else:
                    # Unset flag with second MOV.
                    movs_scheduled = False
                
                
                if re.match(r"^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB)$",
                          eq_class.class_name):
                    # Form of instruction changes (r/m, r <=> r, r/m),
                    # therefore, also, operands must be changed. If REX
                    # prefix is present, proper bits of prefix are
                    # exchanged, as well.
                    # MOV instruction form this class can also be
                    # scheduled.

                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Find Direction bit to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    new_dir_bit = eq_class.members[idx]
                    
                    dir_bit_offset = (opcode_idx * 8) + 6
                    # decide if Direction bit is going to be swapped.
                    if bits_instr[dir_bit_offset:dir_bit_offset + 1] != \
                        new_dir_bit:
                    
                        # Direction bit is going to be changed.
                        rex_idx = cls.__get_rex_idx(b_instr_fromf, opcode_idx)
                        
                        # Exchange Reg/Opcode and rm field of ModR/M byte.
                        cls.__swap_rm_r_operands(rex_idx,
                                                opcode_idx,
                                                bits_instr)
                        
                        # Rewrite Direction bit inside opcode of instruction.
                        bits_instr[dir_bit_offset:dir_bit_offset + 1] = \
                            new_dir_bit
                        
                        # Embed to the executable.
                        fd.seek(my_instr.foffset)
                        fd.write(bits_instr)
                    
                    # Always 1, because embedded was only Direction bit.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                
                
                # Encoding is lexicographic order of used registers name
                # and it's determined by configuration file.
                if eq_class.class_name == "Swap base-index registers 32-bit":
                    # Instruction form changes (SIB.base <=> SIB.index),
                    # therefore, also, operands must be changed. If REX
                    # prefix is present, proper bits of prefix are
                    # exchanged, as well.
                    # MOV instruction form this class can also be
                    # scheduled.

                    # Find out desired order for base-index according to
                    # the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    
                    # Decide if base and index registers should be
                    # swapped according to the next secret message bits
                    # or if they are in the right order.
                    if cls.__should_swap_base_index(my_instr, idx):

                        # Read instruction bytes from file to be able to
                        # modify it.
                        fd.seek(my_instr.foffset)
                        b_instr_fromf = fd.read(len(instr))
                       
                        # Convert read instruction from bytes to bits.
                        bits_instr = bitarray()
                        bits_instr.frombytes(b_instr_fromf)
                        
                        # Get and find an opcode of instruction.
                        instr_opcode = OpCodeInfo(instr.code).op_code
                        
                        opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                           instr_opcode)
                        
                        rex_idx = cls.__get_rex_idx(b_instr_fromf, opcode_idx)
                        
                        # Swap registers. If swap is not successful,
                        # nothing is embeddded and instr. is skipped.
                        if cls.__swap_base_index(rex_idx, opcode_idx, bits_instr):                        
                            # Embed to the executable.
                            fd.seek(my_instr.foffset)
                            fd.write(bits_instr)
                            
                            # Delete already embedded bit from list.
                            del bits_mess[:len(eq_class.encoded_idxs[idx])]

                    else:
                        # Delete already embedded bit from list.
                        del bits_mess[:len(eq_class.encoded_idxs[idx])]
                        
                
                # Classes can be together as their usage is based on
                # exactly same principle.
                elif eq_class.class_name == "2 Bytes Long NOP" or \
                    eq_class.class_name == "3 Bytes Long NOP":

                    # Set skip flag for next instructions skipping.
                    skip = common.set_skip_flag(my_instr,
                                                potential_my_instrs[instr_idx + 1])

                    # Find bits to embed according to the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)

                    # Embed to the executable.
                    fd.seek(my_instr.foffset)
                    fd.write(bytes.fromhex(eq_class.members[idx][2:]))
                    
                    # Delete already embedded bits from list.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]

                
                # Class does not encodes class members, as it does not
                # have any. In this case, bits from message are simply
                # embedded to the last useable instruction bytes.
                elif eq_class.class_name == ">3 Bytes Long NOP":

                    # Get number of bits available for embedding.
                    fd.seek(my_instr.foffset)
                    bits_cnt = \
                        common.count_useable_bits_from_nop(instr,
                                                           fd.read(len(instr)))
                    # Take bits needed to embed.
                    bits_to_embed = bits_mess[:bits_cnt]

                    # There is 100% chance that it will be multiple of 8.
                    b_cnt = bits_cnt // 8
                    
                    # Embed to the executable.
                    pos = my_instr.foffset + (len(instr) - b_cnt)
                    fd.seek(pos)
                    fd.write(bits_to_embed)

                    # Delete already embedded bits from list.
                    del bits_mess[:len(bits_to_embed)]

                
                # These two classes can be merged as they modify only
                # Reg/Opcode field inside ModR/M byte.
                elif eq_class.class_name == "SHL/SAL" or \
                    eq_class.class_name == "TEST non-accumulator register":

                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Find bits to embed according to the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    bits_to_embed = eq_class.members[idx]

                    # Locate Reg/Opcode field inside ModR/M byte.
                    reg_field_offset = (opcode_idx + 1) * 8 + 2
                    # Rewrite required bits inside instruction.
                    bits_instr[reg_field_offset:(reg_field_offset + 3)] = \
                        bits_to_embed

                    # Embed to the executable.
                    fd.seek(my_instr.foffset)
                    fd.write(bits_instr)

                    # Delete already embedded bits from list.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                
                
                elif re.match(r"^(?:ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) 32-bit$",
                          eq_class.class_name):

                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)

                    # Find Direction bit to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    dir_bit = eq_class.members[idx]
                    
                    # Rewrite Direction bit inside opcode of instruction.
                    dir_bit_offset = (opcode_idx * 8) + 6
                    bits_instr[dir_bit_offset:dir_bit_offset + 1] = dir_bit

                    # Embed to the executable.
                    fd.seek(my_instr.foffset)
                    fd.write(bits_instr)
                    
                    # Always 1, because embedded was only Direction bit.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                
                
                elif eq_class.class_name == "SUB/XOR" or \
                    eq_class.class_name == "TEST/AND/OR":

                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Find Reg/Opcode bits to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    
                    # Creates desired opcode according to encoding bits.
                    b_new_opcode = cls.__create_opcode(my_instr, idx)
                    
                    # Embed to the executable.
                    fd.seek(my_instr.foffset + opcode_idx)
                    fd.write(b_new_opcode)

                    # Delete already embedded bits from list.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]

                
                elif eq_class.class_name == "ADD negated" or \
                    eq_class.class_name == "SUB negated":
                    continue
                    print()
                    ## nulu nemozem negovat, zachovam ju
                    # NEGACIA imm je dvojkovy doplnek
                    # ^^ 0x42 => -0x42 == (extended sign)FFF..BE
                    
                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Find Reg/Opcode bits to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    bits_to_embed = eq_class.members[idx]
                    
                    operand_size = OpCodeInfo(instr.code).operand_size
                    print(f"class: {eq_class.class_name}\ninstr: {instr}\nb_instr_fromf: {b_instr_fromf.hex()}\noperand_size: {operand_size}\nbits_to_embed: {bits_to_embed}\ninstr_opcode: {instr_opcode:x}, {opcode_idx}\nbits_instr: {bits_instr}")
                    
                    # Embed ADD or SUB according to next encoding bits.
                    # There is special case for 1 byte long AL register
                    # operand which is also handled.
                    cls.__make_ADD_SUB_opcode(instr,
                                              opcode_idx,
                                              bits_to_embed,
                                              bits_instr)
                
                    # Make two's Complement of immediate (always last
                    # bytes) if required - if ADD was changed to SUB and
                    # vice versa. Also zero immediate can not be negated
                    # as it has only one representation in two's
                    # complement code.
                    if instr.immediate(1) != 0 and \
                        ( (
                            instr.mnemonic == Mnemonic.ADD and \
                            bits_to_embed == bitarray('101')
                        ) or (
                            instr.mnemonic == Mnemonic.SUB and \
                            bits_to_embed == bitarray('000')
                        ) ):
                        # It's ADD changing to SUB => swap sign.
                        # or..
                        # It's SUB changing to ADD => swap sign.
                        
                        # Get operand size in bytes.
                        op_size = OpCodeInfo(instr.code).operand_size // 8
                        if op_size == 0:
                            # For 1 byte long operands function returns 0.
                            op_size = 1
                        elif op_size == 8:
                            # For all ADD/SUB instructions are always
                            # 64 bits long immediates truncated to 32.
                            # It can be done as Stack instructions are
                            # not supported in this program (they do not
                            # truncate 64 bits to 32).
                            op_size = 4
                        print(f"{my_instr.foffset:x}, {op_size}")
                        # Make 2's complement to negate immediate.
                        b_imm_compl = cls.__twos_complement(instr, op_size)
                        # Get position in instruction bytes where
                        # immediate begins.
                        imm_idx = cls.__get_imm_idx(b_instr_fromf,
                                                    instr.immediate(1),
                                                    op_size)
                        
                        print(f"imm_idx: {imm_idx}")
                        # Substitute immediate operand for his 2's comp.
                        bits_imm = bitarray()
                        bits_imm.frombytes(b_imm_compl)
                        # Truncate long sign extension.
                        imm_len = len(bits_instr[imm_idx * 8:])
                        bits_instr[imm_idx * 8:] = bits_imm[:imm_len]
                        
                        print(f"{instr.immediate(1):x}, {b_imm_compl}")
                                                
                    print(f"{bits_instr.tobytes().hex()}, {my_instr.foffset:x}")

                    # Embed to the executable.
                    fd.seek(my_instr.foffset)
                    fd.write(bits_instr)

                    # Delete already embedded bits from list.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                    # sys.exit()
    
                
            else:
                print(f"CAN NOT BE USED - NOT LEGACY INSTRUCTION.", file=sys.stderr)
                
            if not len(bits_mess):
                # All bits were embedded (whole message).
                if verbose:
                    print(f"All data was successfully embedded.")
                break
            
        fd.close()