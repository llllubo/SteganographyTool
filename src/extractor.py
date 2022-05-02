import os
import sys
import lzma
from bitarray import bitarray
from cryptography.fernet import (Fernet, InvalidToken)
import misc


class Extractor:
    __b_key = None
    __b_passwd = None
    
    
    @classmethod
    def extract(cls, fexe: str, n: int, bits_mess: bitarray) -> None:
        # n - Number of bits to extract.
        
        try:
            fd = open(fexe, "rb")
        except IOError:
            print(f"ERROR! Can not open stego-file for extracting: {fexe}",
                  file=sys.stderr)
            sys.exit(101)
            
        
    
    
    @classmethod
    def unxor_data_len(cls, xored_len: bytes) -> int:
        # vraciam vyxorovanu dlzku dat ako cislo
        # uz vytvara kluc a pyta heslo
        cls.__b_key, cls.__b_passwd = misc.gen_key_from_passwd()
        
        # Prepare password length ONLY for XOR operation.
        if len(cls.__b_passwd) <= misc.SIZE_OF_DATA_LEN:
            b_passwd = cls.__b_passwd
            b_passwd += bytes(misc.SIZE_OF_DATA_LEN - len(cls.__b_passwd))
        else:
            b_passwd = cls.__b_passwd[:misc.SIZE_OF_DATA_LEN]

        # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
        # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
        null_padding = 0
        
        for b in reversed(xored_len):
            if b != 0:
                break
            null_padding += 1
        
        i = misc.SIZE_OF_DATA_LEN - null_padding
        
        b_unxored_len = bytes([a ^ b for a, b in zip(xored_len, b_passwd[:i])])
        print(f"...{b_unxored_len}")
        
        # Add null bytes after XOR.
        b_unxored_len += bytes(misc.SIZE_OF_DATA_LEN - len(b_unxored_len))
        
        print(f"[32B == {len(b_unxored_len):,} -- little] b_unxored_len: {b_unxored_len}")

        return int.from_bytes(b_unxored_len, byteorder="little")
    
    
    @classmethod
    def unxor_fext(cls, xored_fext: bytes) -> bytes:
        # vraciam unXORovany fext ktory ma 8 bajtov
        
        # xoruje sa len ak je nejaka extension, inak by sa heslo vyxorovalo do extension (xoroval by som heslo s nulami == heslo).
        if xored_fext != bytes(misc.SIZE_OF_FEXT):
            
            # Prepare password length ONLY for XOR operation.
            if len(cls.__b_passwd) <= misc.SIZE_OF_FEXT:
                b_passwd = cls.__b_passwd
                b_passwd += bytes(misc.SIZE_OF_FEXT - len(cls.__b_passwd))
            else:
                b_passwd = cls.__b_passwd[:misc.SIZE_OF_FEXT]
            
            # vezmem heslo len take dlhe ako je data_len, vyXORujem a predlzim o nuly vysledok.
            # zistujem aky dlhy je padding null bytes, odzadu aby nedoslo k chybe ak by bol null byte v strede niecoho..
            null_padding = 0
            
            for b in reversed(xored_fext):
                if b != 0:
                    break
                null_padding += 1
            
            i = misc.SIZE_OF_FEXT - null_padding
            
            b_unxored_fext = bytes([a ^ b for a, b in zip(xored_fext, b_passwd[:i])])
            print(f"...{b_unxored_fext}")
            
            # Add null bytes after XOR.
            b_unxored_fext += bytes(misc.SIZE_OF_FEXT - len(b_unxored_fext))
            
            print(f"[8B == {len(b_unxored_fext):,} -- little] b_unxored_fext: {b_unxored_fext}")
            
            return b_unxored_fext
        
        print(f"[8B == {len(xored_fext):,} -- little] b_unxored_fext: {xored_fext}")
        
        return xored_fext
    
    
    @classmethod
    def decrypt_data(cls, data: bytes) -> bytes:
        # vracia desifrovane data
        cipher = Fernet(cls.__b_key)
        
        try:
            b_decrypted = cipher.decrypt(data)
        except InvalidToken:
            print("ERROR! Wrong password for extracting data.", file=sys.stderr)
            sys.exit(101)
        
        print(f"b_decrypted data len: {len(b_decrypted):,}")
        
        return b_decrypted
    
    
    @staticmethod
    def decompress(content: bytes) -> bytes:
        
        lzd = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        
        try:
            b_decomp = lzd.decompress(content)
        except lzma.LZMAError:
            print("ERROR! While preprocessing extracted data an error occured.", file=sys.stderr)
            sys.exit(101)
        
        print(f"b_decomp data len: {len(b_decomp):,}")
        
        return b_decomp
    
    
    @staticmethod
    def __create_fname(fext: str) -> str:
        # Create file name for exctrated content with desired extension.
        i = 1 
        while True:
            if os.path.exists(f"./extracted/output{i}{fext}"):
                i += 1
                continue
            break
        
        return "output" + str(i) + fext
    
    
    @classmethod
    def make_output(cls, data: bytes, fext: bytes) -> None:
        # Ensure that output directory will be present.
        try:
            os.mkdir("./extracted")
        except FileExistsError:
            # Existing directory will be used.
            pass
        except OSError:
            print("ERROR! Creation of output directory failed.", file=sys.stderr)
            sys.exit(101)
        
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
            sys.exit(101)
        else:
            fd.write(data)
            fd.close()