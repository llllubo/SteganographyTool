import os
import sys
import lzma
from cryptography.fernet import Fernet
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
    
    
    @staticmethod
    def encrypt_data(data: bytes) -> bytes:
        b_key, Embedder.__b_passwd = misc.gen_key_from_passwd()
        cipher = Fernet(b_key)
        b_encrypted = cipher.encrypt(data)
        
        return b_encrypted
    
    
    @staticmethod
    def xor_data_len(encrypted: bytes) -> bytes:
        # vracia 32B XORovanu dlzku spravy
        # Must be in bytes, because password is in the bytes as well.
        b_encrypted_len = len(encrypted).to_bytes(misc.SIZE_OF_DATA_LEN, byteorder="little")
        
        print(f"[32B == {len(b_encrypted_len)} -- little] b_encrypted_len: {b_encrypted_len} -> {int.from_bytes(b_encrypted_len, byteorder='little')}")
        
        # Prepare password length ONLY for XOR operation.
        if len(Embedder.__b_passwd) <= misc.SIZE_OF_DATA_LEN:
            b_passwd = Embedder.__b_passwd
            b_passwd += bytes(misc.SIZE_OF_DATA_LEN - len(Embedder.__b_passwd))
        else:
            b_passwd = Embedder.__b_passwd[:misc.SIZE_OF_DATA_LEN]

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
    
    
    @staticmethod
    def xor_fext(fext: bytes) -> bytes:
        # vraciam vyXORovany fext ktory ma 8 bajtov.     

        # xoruje sa len ak je nejaka extension, inak by sa heslo vyxorovalo do extension (xoroval by som heslo s nulami == heslo).
        if fext != bytes(misc.SIZE_OF_FEXT):
            # Prepare password length ONLY for XOR operation.
            if len(Embedder.__b_passwd) <= misc.SIZE_OF_FEXT:
                b_passwd = Embedder.__b_passwd
                b_passwd += bytes(misc.SIZE_OF_FEXT - len(Embedder.__b_passwd))
            else:
                b_passwd = Embedder.__b_passwd[:misc.SIZE_OF_FEXT]
            
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