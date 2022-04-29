from asyncore import read
import os
import sys
import math
import lzma
from cryptography.fernet import Fernet

from iced_x86 import *
from bitarray import *
from analyzer import Analyzer
from eq_classes_processor import EqClassesProcessor
import misc


class Embedder:
    __b_passwd = None
    
    @staticmethod
    def get_secret_data(secret_message: str) -> tuple:
        # parameter znaci zadany secret mess, vracia sa v bajtoch obsah suboru
        # a file extension.. alebo len string v bajtoch ak nebol zadany subor
        if os.path.isfile(secret_message):
            # The whole file is going to be embedded.
            b_fext = misc.get_file_extension(secret_message)
            
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
            b_fext += bytes(misc.SIZE_OF_FEXT - len(b_fext))
        
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
        b_key, cls.__b_passwd = misc.gen_key_from_passwd()
        cipher = Fernet(b_key)
        b_encrypted = cipher.encrypt(data)
        
        return b_encrypted
    
    
    @classmethod
    def xor_data_len(cls, encrypted: bytes) -> bytes:
        # vracia 32B XORovanu dlzku spravy
        # Must be in bytes, because password is in the bytes as well.
        b_encrypted_len = len(encrypted).to_bytes(misc.SIZE_OF_DATA_LEN, byteorder="little")
        
        print(f"[32B == {len(b_encrypted_len)} -- little] b_encrypted_len: {b_encrypted_len} -> {int.from_bytes(b_encrypted_len, byteorder='little')}")
        
        # Prepare password length ONLY for XOR operation.
        if len(cls.__b_passwd) <= misc.SIZE_OF_DATA_LEN:
            b_passwd = cls.__b_passwd
            b_passwd += bytes(misc.SIZE_OF_DATA_LEN - len(cls.__b_passwd))
        else:
            b_passwd = cls.__b_passwd[:misc.SIZE_OF_DATA_LEN]

        # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
        # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
        null_padding = 0
        
        for b in reversed(b_encrypted_len):
            if b != 0:
                break
            null_padding += 1
        
        i = misc.SIZE_OF_DATA_LEN - null_padding
        
        b_xored_len = bytes([a ^ b for a, b in zip(b_encrypted_len, b_passwd[:i])])
        print(f"...{b_xored_len}")
        
        # Add null bytes after XOR.
        b_xored_len += bytes(misc.SIZE_OF_DATA_LEN - len(b_xored_len))
        
        print(f"[32B == {len(b_xored_len):,} -- little] b_xored_len: {b_xored_len}")
        
        return b_xored_len
    
    
    @classmethod
    def xor_fext(cls, fext: bytes) -> bytes:
        # vraciam vyXORovany fext ktory ma 8 bajtov.     

        # xoruje sa len ak je nejaka extension, inak by sa heslo vyxorovalo do extension (xoroval by som heslo s nulami == heslo).
        if fext != bytes(misc.SIZE_OF_FEXT):
            # Prepare password length ONLY for XOR operation.
            if len(cls.__b_passwd) <= misc.SIZE_OF_FEXT:
                b_passwd = cls.__b_passwd
                b_passwd += bytes(misc.SIZE_OF_FEXT - len(cls.__b_passwd))
            else:
                b_passwd = cls.__b_passwd[:misc.SIZE_OF_FEXT]
            
            # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
            # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
            
            null_padding = 0
            
            for b in reversed(fext):
                if b != 0:
                    break
                null_padding += 1
            
            i = misc.SIZE_OF_FEXT - null_padding
            
            b_xored_fext = bytes([a ^ b for a, b in zip(fext, b_passwd[:i])])
            print(f"...{b_xored_fext}")
            
            # Add null bytes after XOR.
            b_xored_fext += bytes(misc.SIZE_OF_FEXT - len(b_xored_fext))
            
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
        # 1st try is to take maximum number of bits that
        # can be embedded by current equivalent class.
        max_bits = math.floor(math.log2(mem_len)) + 1
        
        res = None
        # 1st try to find appropriate encoding with max. allowed length.
        for idx, encoded_idx in enumerate(eq_class.encoded_idxs):
            if encoded_idx == \
                bits_mess[:max_bits]:
                
                res = idx
        
        # 2nd try to find appropriate encoding with min. allowed length.
        # This has to always find useable encoding, if 1st try was
        # unsuccessful.
        if res is None:
            min_bits = max_bits - 1
            
            for idx, encoded_idx in enumerate(eq_class.encoded_idxs):
                if encoded_idx == \
                    bits_mess[:min_bits]:
                    
                    res = idx
                    
        ####################################### PREC
        if res is None:
            print("TOTO POJDE PREC -- KONTROLA NECHCENEJ CHYBY")
                    
        return res


    @staticmethod
    def __parse_shl_member(idx: int) -> None:
        pass
        print(f"{idx}")

    
    @classmethod
    def embed(cls,
              fexe: str,
              mess: bytes,
              potential_my_instrs: list,
              bitness: int) -> None:
        ######## SKONTROLOVAT NAVIAC PRI MOV AJ FLAG, CI BOLO POUZITE AJ SCHEDULING..
        ### moze byt MOV1 a MOV2 (ked je MOV schedule) ako:
        ## eq_classes schedule, schedule
        ## flag, eq_class schedule
        ## flag, flag
        
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
        
        for my_instr in potential_my_instrs:
            
            # For speed performance.
            eq_class = my_instr.eq_class
            
            # Instructions that don't have encoding LEGACY are skipped.
            # Legacy encoding for opcodes of instructions is mainly used
            # in each PE and ELF (32- and 64-bit) executables.
            if eq_class is not None and \
                my_instr.instruction.encoding == EncodingKind.LEGACY:
                
                op_code = my_instr.instruction.op_code()
                
                
                fd.seek(my_instr.foffset)
                print(f"{eq_class.class_name} | {my_instr.instruction} | {op_code.instruction_string} | {my_instr.foffset:x} | {fd.read(my_instr.instruction.len).hex()}")

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
                # print()
                # print()
                # print()
                # print()
                
                
                
                

                # Class does not encodes class members, as it does not
                # have any. Encoding is lexicographic order of used
                # instructions strings.
                if eq_class.class_name == "MOV Scheduling" or \
                    my_instr.mov_scheduling_flag:
                    pass
                
                # Classes can be together as their usage is based on
                # exactly same principle.
                elif eq_class.class_name == "2 Bytes Long NOP" or \
                    eq_class.class_name == "3 Bytes Long NOP":

                    # Find bits to embed according to the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    
                    # Embed to the executable.
                    fd.seek(my_instr.foffset)
                    fd.write(bytes.fromhex(eq_class.members[idx][2:]))
                    
                    embedded_bits = eq_class.encoded_idxs[idx]
                    
                    # Delete already embedded bits from list.
                    del bits_mess[:len(embedded_bits)]
                
                # Class does not encodes class members, as it does not
                # have any. In this case, bits from message are simply
                # embedded to the last useable instruction bytes.
                elif eq_class.class_name == ">3 Bytes Long NOP":

                    # Get number of bits available for embedding.
                    bits_cnt = misc.count_useable_bytes_from_nop(my_instr.instruction, bitness)
                    # Take bits needed to embed.
                    bits_to_embed = bits_mess[:bits_cnt]

                    # There is 100% chance that it will be multiple of 8.
                    b_cnt = bits_cnt // 8
                    
                    # Embed to the executable.
                    pos = my_instr.foffset + (len(my_instr.instruction)-b_cnt)
                    fd.seek(pos)
                    fd.write(bits_to_embed)
                    
                    # Delete already embedded bits from list.
                    del bits_mess[:bits_cnt]
                
                elif eq_class.class_name == "TEST non-accumulator register":
                    
                    # Find bits to embed according to the encoding.
                    idx = cls.__find_encoded_idx(eq_class, bits_mess)
                    
                    # fd.seek(my_instr.foffset)
                    # b_instr_fromf = fd.read(my_instr.instruction.len)
                    # print(f"{b_instr_fromf}")
                    
                    # print(f"is_group {OpCodeInfo(my_instr.instruction.code).is_group}")
                    # print(f"group_index {OpCodeInfo(my_instr.instruction.code).group_index}")                    
                    # print(f"is_rm_group {OpCodeInfo(my_instr.instruction.code).is_rm_group}")
                    # print(f"rm_group_index {OpCodeInfo(my_instr.instruction.code).rm_group_index}")
                    # sys.exit()
                    
                    # embedded_bits = eq_class.encoded_idxs[idx]
                    
                
                # Class does not encodes class members, as it does not
                # have any. Encoding is lexicographic order of used
                # registers name.
                elif eq_class.class_name == "Swap base-index registers":
                    ####### kedze budem vymienat base a index registre,
                    ## check ci ide o 64 bitove registre a ak ano, treba
                    ## swapnut aj bity v REX prefixe (LEN V LONG MODE),
                    # ktore doplnuju kod registrov..
                    pass
                    # my_instr.instruction.set_memory_base()
                    # my_instr.instruction.set_memory_index()
                
                elif eq_class.class_name == "SHL/SAL":
                    pass                    
                    
                    #
                
                elif eq_class.class_name == "ADD 32-bit":
                    pass
                
                elif eq_class.class_name == "SUB 32-bit":
                    pass
                
                elif eq_class.class_name == "CMP 32-bit":
                    pass
                
                elif eq_class.class_name == "AND 32-bit":
                    pass
                
                elif eq_class.class_name == "OR 32-bit":
                    pass
                
                elif eq_class.class_name == "XOR 32-bit":
                    pass
                
                elif eq_class.class_name == "ADC 32-bit":
                    pass
                
                elif eq_class.class_name == "SBB 32-bit":
                    pass
                
                elif eq_class.class_name == "TEST/AND/OR":
                    pass
                
                elif eq_class.class_name == "SUB/XOR":
                    pass
                
                elif eq_class.class_name == "MOV":
                    ### POZOR MOV sklbit so scheduling..
                    ############ VYMENA OPERANDOV ak menim strany r, r/m
                    ####### kedze budem vymienat registre r a rm,
                    ## check ci ide o 64 bitove registre a ak ano, treba
                    ## swapnut aj bity v REX prefixe (LEN V LONG MODE),
                    # ktore doplnuju kod registrov..
                    ##### ^^ TOTO PLATI PRE VSETKY 'mnemo' CLASSY
                    pass
                
                elif eq_class.class_name == "ADD":
                    pass
                
                elif eq_class.class_name == "SUB":
                    pass
                
                elif eq_class.class_name == "AND":
                    pass
                
                elif eq_class.class_name == "OR":
                    pass
                
                elif eq_class.class_name == "XOR":
                    pass
                
                elif eq_class.class_name == "CMP":
                    pass
                
                elif eq_class.class_name == "ADC":
                    pass
                
                elif eq_class.class_name == "SBB":
                    pass
                
                elif eq_class.class_name == "ADD negated":
                    ########## nulu nemozem negovat, zachovam ju
                    pass
                
                elif eq_class.class_name == "SUB negated":
                    ########## nulu nemozem negovat, zachovam ju
                    pass
                
            else:
                print()
                print()
                print()
                print(f"CAN NOT BE USED -- NOT LEGACY")
                print()
                print()
                print()
                
            ###################################### OK ???
            if bits_mess is None:
                # All bits were embedded (whole message).
                print(f"{bits_mess}, KONEC")
                break
            
        fd.close()
        
        
        
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