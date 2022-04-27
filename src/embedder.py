import os
import sys
import lzma
from cryptography.fernet import Fernet

from analyzer import Analyzer
from my_instruction import MyInstruction
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
    def embed(mess: bytes, potential_my_instrs: MyInstruction) -> None:
        ######## SKONTROLOVAT NAVIAC PRI MOV AJ FLAG, CI BOLO POUZITE AJ SCHEDULING..
        ### moze byt MOV1 a MOV2 (ked je MOV schedule) ako:
        ## eq_classes schedule, schedule
        ## flag, eq_class schedule
        ## flag, flag
        
        for my_instr in potential_my_instrs:
            
            for eq_class in EqClassesProcessor.all_eq_classes:
                
                if my_instr.eq_class == eq_class:
                    print(f"{my_instr.eq_class} == {eq_class}")
                
                print(f"{eq_class}")