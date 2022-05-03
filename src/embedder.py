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
    __b_passwd = None
    
    @staticmethod
    def get_secret_data(secret_message: str) -> tuple:
        # parameter znaci zadany secret mess, vracia sa v bajtoch obsah suboru
        # a file extension.. alebo len string v bajtoch ak nebol zadany subor
        if os.path.isfile(secret_message):
            # The whole file is going to be embedded.
            b_fext = common.get_file_extension(secret_message)
            
            try:
                fd = open(secret_message, "rb")
            except IOError:
                print("ERROR! Can not access file of embedding data: {args.secret_message}", file=sys.stderr)
                sys.exit(101)
            
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
        
        lzc = lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=0)
        
        try:
            b_comp1 = lzc.compress(content)
        except lzma.LZMAError:
            print("ERROR! While preprocessing secret message an error occured.", file=sys.stderr)
            sys.exit(101)
        
        b_comp2 = lzc.flush()
        
        return (b_comp1 + b_comp2)
    
    
    @classmethod
    def encrypt_data(cls, data: bytes) -> bytes:
        b_key, cls.__b_passwd = common.gen_key_from_passwd()
        cipher = Fernet(b_key)
        b_encrypted = cipher.encrypt(data)
        
        return b_encrypted
    
    
    @classmethod
    def xor_data_len(cls, encrypted: bytes) -> bytes:
        # vracia 32B XORovanu dlzku spravy
        # Must be in bytes, because password is in the bytes as well.
        b_encrypted_len = len(encrypted).to_bytes(common.SIZE_OF_DATA_LEN, byteorder="little")
        
        print(f"[32B == {len(b_encrypted_len)} -- little] b_encrypted_len: {b_encrypted_len} -> {int.from_bytes(b_encrypted_len, byteorder='little')}")
        
        # Prepare password length ONLY for XOR operation.
        if len(cls.__b_passwd) <= common.SIZE_OF_DATA_LEN:
            b_passwd = cls.__b_passwd
            b_passwd += bytes(common.SIZE_OF_DATA_LEN - len(cls.__b_passwd))
        else:
            b_passwd = cls.__b_passwd[:common.SIZE_OF_DATA_LEN]

        # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
        # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
        null_padding = 0
        
        for b in reversed(b_encrypted_len):
            if b != 0:
                break
            null_padding += 1
        
        i = common.SIZE_OF_DATA_LEN - null_padding
        
        b_xored_len = bytes([a ^ b for a, b in zip(b_encrypted_len, b_passwd[:i])])
        print(f"...{b_xored_len}")
        
        # Add null bytes after XOR.
        b_xored_len += bytes(common.SIZE_OF_DATA_LEN - len(b_xored_len))
        
        print(f"[32B == {len(b_xored_len):,} -- little] b_xored_len: {b_xored_len}")
        
        return b_xored_len
    
    
    @classmethod
    def xor_fext(cls, fext: bytes) -> bytes:
        # vraciam vyXORovany fext ktory ma 8 bajtov.     

        # xoruje sa len ak je nejaka extension, inak by sa heslo vyxorovalo do extension (xoroval by som heslo s nulami == heslo).
        if fext != bytes(common.SIZE_OF_FEXT):
            # Prepare password length ONLY for XOR operation.
            if len(cls.__b_passwd) <= common.SIZE_OF_FEXT:
                b_passwd = cls.__b_passwd
                b_passwd += bytes(common.SIZE_OF_FEXT - len(cls.__b_passwd))
            else:
                b_passwd = cls.__b_passwd[:common.SIZE_OF_FEXT]
            
            # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
            # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
            
            null_padding = 0
            
            for b in reversed(fext):
                if b != 0:
                    break
                null_padding += 1
            
            i = common.SIZE_OF_FEXT - null_padding
            
            b_xored_fext = bytes([a ^ b for a, b in zip(fext, b_passwd[:i])])
            print(f"...{b_xored_fext}")
            
            # Add null bytes after XOR.
            b_xored_fext += bytes(common.SIZE_OF_FEXT - len(b_xored_fext))
            
            print(f"[8B == {len(b_xored_fext):,} -- little] b_xored_fext: {b_xored_fext}")
            
            return b_xored_fext
        
        print(f"[8B == {len(fext):,} -- little] b_xored_fext: {fext}")
        
        return fext
    
    
    @staticmethod
    def check_cap(mess_len: int, analyzer: Analyzer) -> None:
        
        cap_indicator = ""
        if mess_len > (analyzer.min_capacity / 8) and \
            mess_len < (analyzer.max_capacity / 8):
            cap_indicator = "probably"
        elif mess_len > (analyzer.max_capacity / 8):
            cap_indicator = "definitely"
            
        # If needed to ask user.
        if cap_indicator:
            
            if cap_indicator == "probably":
                answer = input("Capacity of the cover file is probably not sufficient (the embedding data can be truncated).\nDo you want to continue anyway? [y/n] ").lower().strip()
            elif cap_indicator == "definitely":
                answer = input("Capacity of the cover file is definitely not sufficient (the embedding data will be truncated).\nDo you want to continue anyway? [y/n] ").lower().strip()

            if answer != "yes" and \
                answer != "ye" and \
                answer != "y":
                print("Steganography was not applied!")
                sys.exit(0)
                
                
    @staticmethod
    def __find_encoded_idx(eq_class: EqClassesProcessor,
                           bits_mess: bitarray) -> int:
        
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
        # embedded -- zeros padding.
        added_nulls = None
        if max_bits > len(bits_mess):
            added_nulls = bitarray(max_bits - len(bits_mess))
            added_nulls.setall(0)
            bits_mess.extend(added_nulls)
        
        # print(f"{mem_len} | {is_power_of_2} | {max_bits} | {added_nulls} | {len(bits_mess)}")
        
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
                    
        ####################################### PREC
        print("TOTO POJDE PREC -- KONTROLA NECHCENEJ CHYBY")
        sys.exit(101)
            
            
    @staticmethod
    def __get_rex_idx(instr_fromf: bytes, opcode_idx: int) -> int:
        # REX prefix, if present, is placed immediately before opcode.
        
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
        
    
    @classmethod
    def __should_swap_mov(cls,
                          instr_mov0: MyInstruction,
                          instr_mov1: MyInstruction,
                          idx: int) -> bool:
        # Find out if base and index memory registers should be swapped
        # according to desired order determined by next encoding bit of
        # message.
        
        mov0 = f"{instr_mov0.instruction}"
        mov1 = f"{instr_mov1.instruction}"
        if common.lexicographic_mov_sort(mov0) == \
            common.lexicographic_mov_sort(mov1):
            # Setting first MOV to None is signing tak they can not be
            # scheduled. It happens extremely rare.
            print(".................SAME")
            instr_mov0 = None
            return False
        
        # There is possibility that both will have set only scheduling
        # flag and then could not be decided what ordering would be
        # used. Therefore must be accessed to the array of all
        # equivalent classes and read out configured ordering from file.
        ordering = "Ascending"
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
        # Find out if base and index memory registers should be swapped
        # according to desired order determined by next encoding bit of
        # message.
        
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
        # Last parameter of function is going to be changed and then
        # will be used outside function.
        
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
            print(f"CHYBAAAAAAAAAAAAAAAAAAAAAAAAA")############### PREC
            return False

        return True
    
    
    @staticmethod
    def __swap_rm_r_operands(rex_idx: int,
                             opcode_idx: int,
                             bits_instr: bitarray) -> None:
        # Last parameter of function is going to be changed and then
        # will be used outside function.
        
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
        # Create desired OPCODE for instructions of equivalent classes
        # 'TEST/AND/OR' and 'SUB/XOR'.
        if OpCodeInfo(instr.instruction.code).operand_size == 0:
            # Correctness of OPCODE if 1 byte operand.
            new_opcode = int(instr.eq_class.members[idx][2:], 16)
            new_opcode -= 1
            b_new_opcode = \
                new_opcode.to_bytes(OpCodeInfo(instr.instruction.code).op_code_len, byteorder="little")
            
            # print(f"tuu: {b_new_opcode.hex()}")
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
        # Embed ADD or SUB OPCODE according to the next encoding bits.
        # There is special case of AL register operand when OPCODES of
        # ADD and SUB differ and they must be changed. Also, in this
        # case there is no ModR/M byte, so Reg/Opcode can not be
        # modified. Otherwise, OPCODES stay same and Reg/Opcode field of
        # ModR/M byte is changed only.
        # Last parameter of function is going to be changed and then
        # will be used outside function.
        
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
    
        print(f"instr.immediate(1):x -- {instr.immediate(1):x}")
    
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
        # Get index position of immediate operand inside instruction.
        b_imm = imm.to_bytes(op_size, byteorder="little", signed=True)
        print(f"b_imm: {b_imm.hex()}")
        return instr_fromf.find(b_imm)

    
    @classmethod
    def embed(cls,
              fexe: str,
              mess: bytes,
              potential_my_instrs: list,
              bitness: int) -> None:

        ### moze byt MOV1 a MOV2 (ked je MOV schedule) ako:
        ## eq_classes schedule, schedule
        ## flag, eq_class schedule
        ## flag, flag
        
        # Skip flag defines how many next instructions should be
        # skipped as they were already used by first instruction
        # from their group (3 and 2 Bytes Long NOP classes).
        skip = 0
        # Skip flag determines first occurence of scheduling MOV if True.
        skip_mov = False
        
        bits_mess = bitarray(endian="little")
        bits_mess.frombytes(mess)
        print(f"{bits_mess}")
        print(f"")
        
        try:
            fd = open(fexe, "r+b")
        except IOError:
            print(f"ERROR! Can not open cover file for embedding: {fexe}",
                  file=sys.stderr)
            sys.exit(101)
        
        for instr_idx, my_instr in enumerate(potential_my_instrs):
            # print()
            
            if skip:
                # Skip current NOP instruction.
                skip -= 1
                # print("SKIPPING")
                continue
            
            # For speed performance.
            eq_class = my_instr.eq_class
            instr = my_instr.instruction
            
            
            # if instr.encoding != EncodingKind.LEGACY:
            #     print("POOOOOOOOOOOZOOOOOOOOOOOOOOOOR")
            # if OpCodeInfo(instr.code).op_code_len != 1:
            #     print("POOOOOOOOOOOZOOOOOOOOOOOOOOOOR !!!!!!!!!!")
            # continue
            
            
            # Instructions that don't have encoding LEGACY are skipped.
            # Legacy encoding for opcodes of instructions is mainly used
            # in each PE and ELF (32- and 64-bit) executables and others
            # encodings are very rare.
            if eq_class is not None and \
                instr.encoding == EncodingKind.LEGACY:
                
                # op_code = instr.op_code()
                # fd.seek(my_instr.foffset)
                # print(f"{eq_class.class_name} | {my_instr.instruction} | {op_code.instruction_string} | {my_instr.foffset:x} | {fd.read(len(my_instr.instruction)).hex()}")
                
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
                    
                    # print(f"{b_instr_fromf.hex()}, {my_instr.foffset}")
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    # instr_opcode_len = OpCodeInfo(instr.code).op_code_len
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    # print()
                    # print(f"{b_instr_fromf.hex()}, {instr_opcode:x}, {opcode_idx}")
                    # Find Direction bit to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    new_dir_bit = eq_class.members[idx]
                    # print(f"{new_dir_bit}")
                    # print(f"{new_dir_bit}, {opcode_idx}, {instr_opcode:x}, {idx}")
                    
                    dir_bit_offset = (opcode_idx * 8) + 6
                    # decide if Direction bit is going to be swapped.
                    if bits_instr[dir_bit_offset:dir_bit_offset + 1] != \
                        new_dir_bit:
                    
                        # Direction bit is going to be changed.
                        rex_idx = cls.__get_rex_idx(b_instr_fromf, opcode_idx)
                        # print(f"rex: {rex_idx}")
                        # Exchange Reg/Opcode and rm field of ModR/M byte.
                        cls.__swap_rm_r_operands(rex_idx,
                                                opcode_idx,
                                                bits_instr)
                        
                        # Rewrite Direction bit inside opcode of instruction.
                        bits_instr[dir_bit_offset:dir_bit_offset + 1] = \
                            new_dir_bit
                        # print(f"{bits_instr}")
                        # Embed to the executable.
                        fd.seek(my_instr.foffset)
                        fd.write(bits_instr)
                    
                    # Always 1, because embedded was only Direction bit.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                    
                    # fd.seek(my_instr.foffset)
                    # print(f"{my_instr.instruction}, {fd.read(len(instr)).hex()}, {my_instr.foffset:x}")
                    # # sys.exit()
                    # # if my_instr.foffset == 0x23e1b:
                    # #     sys.exit()
                
                # Class does not encodes class members, as it does not
                # have any. Encoding is lexicographic order of used
                # registers name.
                if eq_class.class_name == "Swap base-index registers":
                    # Instruction form changes (SIB.base <=> SIB.index),
                    # therefore, also, operands must be changed. If REX
                    # prefix is present, proper bits of prefix are
                    # exchanged, as well.
                    # MOV instruction form this class can also be
                    # scheduled.
                    continue
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
                        
                        # print()
                        # print(f"{instr}")
                        # print(f"{b_instr_fromf}, {my_instr.foffset:x}")
                        # print(f"{b_instr_fromf.hex()}")
                        
                        # Get and find an opcode of instruction.
                        instr_opcode = OpCodeInfo(instr.code).op_code
                        # instr_opcode_len = OpCodeInfo(instr.code).op_code_len
                        opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                           instr_opcode)
                        
                        rex_idx = cls.__get_rex_idx(b_instr_fromf, opcode_idx)
                        # print(f"REX: {rex_idx}")
                        # print(f"{bits_instr}")
                        
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
                    
                    # fd.seek(my_instr.foffset)
                    # print(f"{fd.read(len(instr)).hex()}")
                    # sys.exit()
                    
                # Class does not encodes class members, as it does not
                # have any. Encoding is lexicographic order of used
                # instructions strings.
                if eq_class.class_name == "MOV Scheduling" or \
                    my_instr.mov_scheduling_flag:
                    
                    # Skip is set if first MOV scheduling instruction
                    # occurs.
                    if not skip_mov:
                        skip_mov = True
                    else:
                        skip_mov = False

                    ############# LEN VYPIS
                    # if my_instr.mov_scheduling_flag:
                    #     print(f"f: {instr}, {eq_class.class_name}")
                    # else:
                    #     print(f"{instr}, {eq_class.class_name}")
                    # print(f"{my_instr.foffset:x}, {len(instr)}")
                    
                    # mov0 = f"{my_instr.instruction}"
                    # mov1 = f"{potential_my_instrs[instr_idx + 1].instruction}"
                    # if common.lexicographic_mov_sort(mov0) == \
                    #     common.lexicographic_mov_sort(mov1) and \
                    #         skip_mov:
                    #     print(".................SAME")
                    
                    # if not skip_mov:
                    #     # Second scheduled MOV is current.
                    #     print()
                    #############

                    # First MOV is skipped for now.
                    if skip_mov:
                        continue

                    ## Second MOV is current, both can be scheduled now.
                    
                    # Find out desired order for MOVs according to
                    # the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)

                    # Decide if both MOVs should be swapped according to
                    # the next secret message bits or if they are in the
                    # right order.
                    if cls.__should_swap_mov(potential_my_instrs[instr_idx -1],
                                             my_instr,
                                             idx):
                        ## MOVs are going to be swapped.
                        # Read instruction bytes of 1st MOV.
                        fd.seek(potential_my_instrs[instr_idx -1].foffset)
                        b_mov0_fromf = \
                            fd.read(len(potential_my_instrs[instr_idx -1].instruction))
                        # Read instruction bytes of 2nd MOV.
                        fd.seek(my_instr.foffset)
                        b_mov1_fromf = fd.read(len(instr))
                        
                        # Swap them.
                        fd.seek(potential_my_instrs[instr_idx - 1].foffset)
                        fd.write(b_mov1_fromf)
                        fd.seek(potential_my_instrs[instr_idx - 1].foffset + len(b_mov1_fromf))
                        fd.write(b_mov0_fromf)
                    
                    if potential_my_instrs[instr_idx - 1] is None:
                        # They could not be scheduled, extremely rare
                        # situation happend.
                        print(f"CHYYYYYYYYYYYYYYYYYYYYYYYYYYBAA")
                        continue
                        
                    # Delete already embedded order bit from list.
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
                    bits_cnt = common.count_useable_bits_from_nop(instr, bitness)
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
                    # SUB mam nastaveny na klasicky OPCODE 0x29, ale pri
                    # operandoch al,al atd (reg8 -- pozor aj r12b atd) je OPCODE 0x29-0x1==0x28
                    # Podobne s XOR.. klasicke 0x31, reg8 0x31-0x1==0x30
                    # TEST mam nastaveny na klasicky OPCODE 0x85, ale pri
                    # operandoch al,al atd (reg8 -- pozor aj r12b atd) je OPCODE 0x85-0x1==0x84
                    # Podobne s AND.. klasicke 0x21, reg8 0x21-0x1==0x20
                    # Podobne s OR.. klasicke 0x09, reg8 0x09-0x1==0x08
                    
                    # Read instruction bytes from file to be able to
                    # modify it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    # print(f"{b_instr_fromf.hex()}")
                    # print(f"{instr}")
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Find Reg/Opcode bits to embed according to the
                    # encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    # print(f"{eq_class.encoded_idxs[idx]}")
                    # print(f"{OpCodeInfo(instr.code).operand_size}")
                    
                    # Creates desired opcode according to encoding bits.
                    b_new_opcode = cls.__create_opcode(my_instr, idx)
                    
                    # Embed to the executable.
                    fd.seek(my_instr.foffset + opcode_idx)
                    fd.write(b_new_opcode)

                    # Delete already embedded bits from list.
                    del bits_mess[:len(eq_class.encoded_idxs[idx])]
                    
                    # fd.seek(my_instr.foffset)
                    # print(f"{fd.read(len(instr)).hex()}")
                    # sys.exit()
                
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
                print()
                print()
                print()
                print(f"CAN NOT BE USED -- NOT LEGACY")
                print()
                print()
                print()
                
            ###################################### OK ???
            # print(f"{bits_mess}")
            # print()
            if not len(bits_mess):
                # All bits were embedded (whole message).
                print(f"KONEC")
                break
            
        fd.close()
        
        
        
        
        # print(f"op_code: {OpCodeInfo(my_instr.instruction.code).op_code:x}")
                # print(f"op_code_len {OpCodeInfo(my_instr.instruction.code).op_code_len}")
                # print()
                # print(f"mandatory_prefix {OpCodeInfo(my_instr.instruction.code).mandatory_prefix:x}")
                # print()
                # print(f"is_group {OpCodeInfo(my_instr.instruction.code).is_group}")
                # print(f"group_index {OpCodeInfo(my_instr.instruction.code).group_index}")                    
                # print(f"is_rm_group {OpCodeInfo(my_instr.instruction.code).is_rm_group}")
                # print(f"rm_group_index {OpCodeInfo(my_instr.instruction.code).rm_group_index}")
                # print()
                # print(f"is_available_in_mode(bitness) {OpCodeInfo(my_instr.instruction.code).is_available_in_mode(bitness)}")
                # print(f"compatibility_mode {OpCodeInfo(my_instr.instruction.code).compatibility_mode}")
                # print(f"long_mode {OpCodeInfo(my_instr.instruction.code).long_mode}")
                # print()
                # print(f"mode64 {OpCodeInfo(my_instr.instruction.code).mode64}")
                # print(f"mode32 {OpCodeInfo(my_instr.instruction.code).mode32}")
                # print(f"mode16 {OpCodeInfo(my_instr.instruction.code).mode16}")
                # print(f"is_instruction {OpCodeInfo(my_instr.instruction.code).is_instruction}")
                # print()
                # print(f"code_size {my_instr.instruction.code_size}")
                # print(f"is_invalid {my_instr.instruction.is_invalid}")
                # if my_instr.instruction.op1_kind == OpKind.IMMEDIATE64:
                #     print(f"immediate {my_instr.instruction.immediate(1)}")
                # print(f"op_code() {my_instr.instruction.op_code()}") # -- vracia OpCodeInfo
        
        
        
    # eq_all_bits(&self, other: &Self)
     
    # set_op1_kind(new_val)

    # info_factory = InstructionInfoFactory()
    
    # assert instr1.code == Code.XCHG_RM8_R8
    # assert instr1.mnemonic == Mnemonic.XCHG
    # assert instr1.len == 4
    
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