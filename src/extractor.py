"""
`Extractor` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""

import os
import re
import sys
import lzma

from iced_x86 import *
from bitarray import bitarray
from cryptography.fernet import (Fernet, InvalidToken)
import common
from eq_classes_processor import EqClassesProcessor
from my_instruction import MyInstruction


class Extractor:
    """
    `Extractor` is responsible for extracting data from given
    stego-executable.
    """
    
    __b_key = None
    """
    Storage of generated key (from password) in bytes.
    """
    
    __b_passwd = None
    """
    Storage of given password in bytes.
    """
    
    @staticmethod
    def __opcode_correction(instr: MyInstruction, opcode: int) -> str:
        """
        Correction of read OPCODE to the desired format acceptable for
        decode. There is one special case where OPCODE has to be
        modified, additionally. It's when 1 byte register operand is
        used.
        
        This correction is applied for classes 'SUB/XOR' and
        'TEST/AND/OR'.
        """
        if OpCodeInfo(instr.instruction.code).operand_size == 0:
            # Correction of 1 byte operand OPCODE.
            # Endianness does not matter as OPCODE is always 1 byte long.
            opcode += 1
            return f"{opcode:#04x}"
        else:
            return f"{opcode:#04x}"
        
        
    @staticmethod
    def __get_order_type(instr: MyInstruction, next_mov: MyInstruction) -> str:
        """
        Determine occuring order. It's designed for classes
        'MOV Scheduling' and 'Swap base-index registers 32-bit' as
        only these use scheduling.
        
        Only in case of class 'MOV Scheduling' is 2nd parameter given,
        otherwise it's set to None. This parameter is 1st occured MOV.
        """
        
        if next_mov is not None:
            if instr.eq_class.class_name == "MOV Scheduling" or \
                next_mov.eq_class.class_name == "MOV Scheduling" or \
                instr.mov_scheduling_flag or next_mov.mov_scheduling_flag:
                mov0 = f"{instr.instruction}"
                mov1 = f"{next_mov.instruction}"
                
                if common.lexicographic_mov_sort(mov0) < \
                    common.lexicographic_mov_sort(mov1):
                    return "Ascending"
                else:
                    return "Descending"
            
        elif instr.eq_class.class_name == "Swap base-index registers 32-bit":
            if instr.instruction.memory_base < instr.instruction.memory_index:
                return "Ascending"
            else:
                return "Descending"
    
    
    @staticmethod
    def __decode_mov(order: str) -> bitarray:
        """
        Decode given order. For 'MOV Scheduling' can occur situation
        when both MOVs will have set only `mov_scheduling_flag`.
        Therefore can not be used classic `__decode()` function and
        this special one was created.
        """
        for eq_class in EqClassesProcessor.all_eq_classes:
            if eq_class.class_name == "MOV Scheduling":
                for idx, mem in enumerate(eq_class.members):
                    if order == mem:
                        return eq_class.encoded_idxs[idx]
    
    
    @staticmethod
    def __decode(eq_class: EqClassesProcessor, extracted_mem) -> bitarray:
        """
        Decode extracted bits to message bits. This is determined by
        encoding defined in configuration file.
        
        `extracted_mem` can be of more data types. It depends on
        equivalent class.
        """
        for idx, mem in enumerate(eq_class.members):
            if extracted_mem == mem:
                return eq_class.encoded_idxs[idx]
    
    
    @classmethod
    def extract(cls,
                fexe: str,
                potential_my_instrs: list,
                verbose: bool,
                passwd: str) -> bitarray:
        """
        Extract secret message.
        
        passwd parameter contains password string if was given by option
        value, otherwise it's None.
        """
        try:
            fd = open(fexe, "rb")
        except IOError:
            print(f"ERROR! Can not open stego-file for extracting: {fexe}",
                  file=sys.stderr)
            sys.exit(105)
        
        # Prepared bitarray to store extracted bits here. At the end it
        # will be returned by this function.
        bits_mess = bitarray(endian="little")
        # Extract limit defines how many bits are going to be extracted.
        # This limit changes during the extraction as first it's set to
        # amount of bits which defines length of further data. After
        # this limit is reached, second is set that determines length of
        # real data. If limit will be reached, fulfilled bitarray is
        # returned. If the end of potential instructions will come first
        # it's known that it can not be extracted all data, because of
        # insufficient capacity of executable. In that case all
        # collected bits are returned and flag is set.
        extract_limit = common.SIZE_OF_DATA_LEN * 8
        # This flag determines phase of extraction.
        # Two possible values:
        #   * False -> extracting is first bytes storing data length.
        #   * True  -> extracting are real data (payload).
        data_extraction_flag = False
        # Skip flag defines how many next instructions should be
        # skipped as they were already used by first instruction
        # from their group (3 and 2 Bytes Long NOP classes).
        skip = 0        
        
        # Determines if MOVs were already scheduled. It's False at the
        # beginning, but first MOV set it to True after they are
        # scheduled.
        movs_scheduled = False
            
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
                if eq_class.class_name == "MOV Scheduling" or \
                    my_instr.mov_scheduling_flag and not movs_scheduled:

                    ## Second MOV is current, scheduling can be decoded.

                    # Set flag with first MOV - This is only tag for
                    # knowledge that first MOV was tried to be scheduled.
                    movs_scheduled = True

                    # Get type of order in which are both MOVs present.
                    order = cls.__get_order_type(my_instr,
                                                 potential_my_instrs[instr_idx +1])
                    # Decode found out order. Here can occur situation
                    # when both MOVs will have set only
                    # 'mov_scheduling_flag'. Therefore can not be used
                    # '__decode()' function here and special one was
                    # created.
                    extracted_bits = cls.__decode_mov(order)
                    
                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)
                else:
                    # Unset flag with second MOV.
                    movs_scheduled = False
                    
                
                if re.match(r"^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB)$",
                          eq_class.class_name) or \
                    re.match(r"^(?:ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) 32-bit$",
                          eq_class.class_name):
                    # Secret bit is stored at the place of Direction bit
                    # inside OPCODE.
                    # MOV instruction from this class can also be
                    # scheduled - NOT IMPLEMENTED.
                    
                    # Read instruction bytes from file to be able to
                    # analyze it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))
                    
                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    dir_bit_offset = (opcode_idx * 8) + 6
                    # Decode read Direction bit.
                    extracted_bits = cls.__decode(eq_class,
                                bits_instr[dir_bit_offset:dir_bit_offset + 1])
                    
                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)


                # Encoding is lexicographic order of used registers name
                # and it's determined by configuration file.
                if eq_class.class_name == "Swap base-index registers 32-bit":
                    # Instruction form changes (SIB.base <=> SIB.index),
                    # therefore, also, operands must be changed. If REX
                    # prefix is present, proper bits of prefix are
                    # exchanged, as well.
                    # MOV instruction from this class can also be
                    # scheduled - NOT IMPLEMENTED.

                    # Get type of order in which are memory registers
                    # present.
                    order = cls.__get_order_type(my_instr, None)
                    
                    # Decode read Direction bit.
                    extracted_bits = cls.__decode(eq_class, order)

                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)
                
                
                # Classes can be together as their usage is based on
                # exactly same principle.
                elif eq_class.class_name == "2 Bytes Long NOP" or \
                    eq_class.class_name == "3 Bytes Long NOP":

                    # Set skip flag for next instructions skipping.
                    skip = common.set_skip_flag(my_instr,
                                                potential_my_instrs[instr_idx + 1])
                    # Read instruction bytes from file to be able to
                    # analyze it.
                    fd.seek(my_instr.foffset)
                    if eq_class.class_name == "2 Bytes Long NOP":
                        b_instr_fromf = fd.read(2)
                    elif eq_class.class_name == "3 Bytes Long NOP":
                        b_instr_fromf = fd.read(3)
                    
                    # Convert bytes to hex string.
                    hex_instr = "0x" + b_instr_fromf.hex()
                    
                    # Decode read instruction.
                    extracted_bits = bitarray(endian="little")
                    extracted_bits = cls.__decode(eq_class, hex_instr)
                    
                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)


                # Class does not encodes class members, as it does not
                # have any. In this case, bits from message are simply
                # embedded to the last useable instruction bytes.
                elif eq_class.class_name == ">3 Bytes Long NOP":

                    # Get number of last instruction bits which contain
                    # message bits.
                    fd.seek(my_instr.foffset)
                    bits_cnt = \
                        common.count_useable_bits_from_nop(instr,
                                                           fd.read(len(instr)))
                    # There is 100% chance that it will be multiple of 8.
                    b_cnt = bits_cnt // 8
                    
                    # Extract from executable.
                    pos = my_instr.foffset + (len(instr) - b_cnt)
                    fd.seek(pos)
                    b_extracted = fd.read(b_cnt)
                    
                    # Convert extracted bytes to bits.
                    extracted_bits = bitarray(endian="little")
                    extracted_bits.frombytes(b_extracted)

                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)
                    
                
                # These two classes can be merged as they modify only
                # Reg/Opcode field inside ModR/M byte.
                elif eq_class.class_name == "SHL/SAL" or \
                    eq_class.class_name == "TEST non-accumulator register":
                    # Secret bit is defined by Reg/Opcode bits of ModR/M
                    # byte inside instruction.

                    # Read instruction bytes from file to be able to
                    # analyze it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))

                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)

                    # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code
                    opcode_idx = common.get_opcode_idx(b_instr_fromf,
                                                       instr_opcode)
                    
                    # Locate Reg/Opcode field inside ModR/M byte.
                    reg_field_offset = (opcode_idx + 1) * 8 + 2
                    
                    # Decode read Direction bit.
                    extracted_bits = cls.__decode(eq_class,
                            bits_instr[reg_field_offset:reg_field_offset + 3])

                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)
                
                
                elif eq_class.class_name == "SUB/XOR" or \
                    eq_class.class_name == "TEST/AND/OR":

                    # Read instruction bytes from file to be able to
                    # analyze it.
                    fd.seek(my_instr.foffset)
                    b_instr_fromf = fd.read(len(instr))

                    # Convert read instruction from bytes to bits.
                    bits_instr = bitarray()
                    bits_instr.frombytes(b_instr_fromf)
                    
                     # Get and find an opcode of instruction.
                    instr_opcode = OpCodeInfo(instr.code).op_code

                    # Correctness of read OPCODE.
                    opcode = cls.__opcode_correction(my_instr, instr_opcode)

                    # Decode read Direction bit.
                    extracted_bits = cls.__decode(eq_class, opcode)

                    # Collect decoded bits and create message.
                    bits_mess.extend(extracted_bits)

                
            else:
                print(f"CAN NOT BE USED - NOT LEGACY INSTRUCTION.", file=sys.stderr)
            
            
            if len(bits_mess) >= extract_limit:
                
                if not data_extraction_flag:
                    # If bits defined data length are available, their
                    # length is decoded and set as new extract limit.
                    b_xored_len = bits_mess[:extract_limit].tobytes()
                    
                    # UnXOR extracted length of data with password.
                    data_len = cls.__unxor_data_len(b_xored_len, passwd)
                    
                    # Remove bits specifying data length from array.
                    del bits_mess[:extract_limit]
                    
                    # Set new extraction limit (file extension + raw
                    # data).
                    extract_limit = data_len * 8 + common.SIZE_OF_FEXT * 8
                    
                    # Set next extracting phase.
                    data_extraction_flag = True
                else:
                    # Full requested message was extracted.
                    if verbose:
                        print("All required data was extracted.")
                    break
    
        fd.close()
    
        # Check if all expected data were extracted.
        if len(bits_mess) < extract_limit:
            # Not all requested data could be extracted.
            # This should not happen and if do, it will throw error
            # when Fernet checks integrity of data,
            pass
        
        # Correctness of extracted data. Bits extracted in addition,
        # was extracted with last required bits and must be truncated.
        del bits_mess[extract_limit:]
        
        return bits_mess
        
    
    @classmethod
    def __unxor_data_len(cls, xored_len: bytes, passwd: str) -> int:
        """
        Function returns XORed data length as integer and also it
        requires password from user.
        
        passwd parameter contains password string if was given by option
        value, otherwise it's None.
        """
        cls.__b_key, cls.__b_passwd = common.gen_key_from_passwd(passwd)
        
        # Prepare password length ONLY for XOR operation.
        if len(cls.__b_passwd) <= common.SIZE_OF_DATA_LEN:
            b_passwd = cls.__b_passwd
            b_passwd += bytes(common.SIZE_OF_DATA_LEN - len(cls.__b_passwd))
        else:
            b_passwd = cls.__b_passwd[:common.SIZE_OF_DATA_LEN]

        # Data length bytes are going to be unXORed with password
        # of same size. If given password is longer, it's truncated.
        # This is security reason as if whole password bytes were
        # XORed with null padding of data length bytes, password
        # characters would map to the XORed data length and could be
        # readable. Reversed cycle is used to avoid problem when
        # null byte is in the middle of data.
        null_padding = 0
        
        for b in reversed(xored_len):
            if b != 0:
                break
            null_padding += 1
        
        i = common.SIZE_OF_DATA_LEN - null_padding
        
        b_unxored_len = bytes([a ^ b for a, b in zip(xored_len, b_passwd[:i])])
        
        # Add null bytes after XOR.
        b_unxored_len += bytes(common.SIZE_OF_DATA_LEN - len(b_unxored_len))
        
        return int.from_bytes(b_unxored_len, byteorder="little")
    
    
    @classmethod
    def unxor_fext(cls, xored_fext: bytes) -> bytes:
        """
        Function returns unXORed file extension in bytes of proposed
        length.
        """
        
        # Check if there is any file extension, if not, return given
        # bytes.
        if xored_fext != bytes(common.SIZE_OF_FEXT):
            
            # Prepare password length ONLY for XOR operation.
            if len(cls.__b_passwd) <= common.SIZE_OF_FEXT:
                b_passwd = cls.__b_passwd
                b_passwd += bytes(common.SIZE_OF_FEXT - len(cls.__b_passwd))
            else:
                b_passwd = cls.__b_passwd[:common.SIZE_OF_FEXT]
            
            # File extension bytes are going to be unXORed with password
            # of same size. If given password is longer, it's truncated.
            # This is security reason as if whole password bytes were
            # XORed with null padding of data length bytes, password
            # characters would map to the XORed data length and could be
            # readable. Reversed cycle is used to avoid problem when
            # null byte is in the middle of data.
            null_padding = 0
            
            for b in reversed(xored_fext):
                if b != 0:
                    break
                null_padding += 1
            
            i = common.SIZE_OF_FEXT - null_padding
            
            b_unxored_fext = bytes([a ^ b for a, b in zip(xored_fext, b_passwd[:i])])
            
            # Add null bytes after XOR.
            b_unxored_fext += bytes(common.SIZE_OF_FEXT - len(b_unxored_fext))

            return b_unxored_fext
        
        return xored_fext
    
    
    @classmethod
    def decrypt_data(cls, data: bytes) -> bytes:
        """
        Decrypt given data in bytes.
        """
        cipher = Fernet(cls.__b_key)
        try:
            b_decrypted = cipher.decrypt(data)
        except InvalidToken:
            print("ERROR! Wrong password for extracting data.", file=sys.stderr)
            sys.exit(105)

        return b_decrypted
    
    
    @staticmethod
    def decompress(content: bytes) -> bytes:
        """
        Decompress given data.
        """
        lzd = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        
        try:
            b_decomp = lzd.decompress(content)
        except lzma.LZMAError:
            print("ERROR! While preprocessing extracted data an error occured.", file=sys.stderr)
            sys.exit(105)
        
        return b_decomp
    
    
    @staticmethod
    def __create_fname(fext: str) -> str:
        """
        Create file name for exctrated content with desired extension.
        """
        i = 1 
        while True:
            if os.path.exists(f"./extracted/output{i}{fext}"):
                i += 1
                continue
            break
        
        return "output" + str(i) + fext
    
    
    @classmethod
    def make_output(cls, data: bytes, fext: bytes) -> None:
        """
        Ensure that output directory will be present.
        """
        try:
            os.mkdir("./extracted")
        except FileExistsError:
            # Existing directory will be used.
            pass
        except OSError:
            print("ERROR! Creation of output directory failed.", file=sys.stderr)
            sys.exit(105)
        
        # Get rid of null bytes in file extension, if present.
        ext = ""
        for b in fext:
            if b != 0:
                ext += chr(b)
        
        # Add dot before extension, if present.
        if ext != "":
            ext = "." + ext
            
        fname = cls.__create_fname(ext)
        
        # Write extracted content to the file.
        try:
            fd = open(f"./extracted/{fname}", "wb")
        except IOError:
            print(f"ERROR! Can not access an output file: {fname}", file=sys.stderr)
            sys.exit(105)
        else:
            fd.write(data)
            fd.close()