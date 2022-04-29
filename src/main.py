#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Steganography for Executables

Author:  Ľuboš Bever
Date:    11.05.2022
Version: 1.0
Project: Bachelor's thesis, BUT FIT Brno
""" 
 

import sys
import time
from iced_x86 import *

from args_parser import ArgsParser
from disassembler import Disassembler
from embedder import Embedder
from extractor import Extractor
from analyzer import Analyzer
from selector import Selector
from eq_classes_processor import EqClassesProcessor


__author__ = "Ľuboš Bever"
__copyright__ = "Copyright 2022, Ľuboš Bever"
__credits__ = ["Ľuboš Bever", "Josef Strnadel"]
__license__ = "GNU GPLv3"
# __date__ = 
__version__ = "1.0"
__maintainer__ = "Ľuboš Bever"
__email__ = "213409@vutbr.cz" # or __contact__
__status__ = "Prototype" # "Prototype", "Development", or "Production"


class Main:


    @staticmethod
    def run() -> None:
       
        args = ArgsParser.parse()
        # print(f"\nargs:\n{args}\n")
        
        # Only modes 'embed' and 'analyze' require cover file,
        # others require stego-file.
        if args.mode == "e" or \
           args.mode == "embed" or \
           args.mode == "a" or \
           args.mode == "analyze":
            inputf = args.cover_file
        else:
            inputf = args.stego_file            
        
        # Disassemble all instructions from executable.
        # Needed to keep all of them because of flags checking.
        # It also finds useable instructions according to method and 
        # compute embedding capacity.
        all_my_instrs, bitness = Disassembler.disassemble(inputf)
        
        # Prepare instances of equivalent classes.
        EqClassesProcessor.prepare_eq_classes(args.method, args.config_file)
        # print(EqClassesProcessor.all_eq_classes)
        # print()
        # return
        
        
        ############### ZAPIS v pripade do NOPov multibytes
        # # nulls = 5
        # hex_string = "0x90900f1f0090906690669090d9d06690d9d090d9d00f1f002e660f1f840000000000906690909090900f1f009090d9d09090"
        # mess = bytes.fromhex(hex_string[2:])
        # # Must compute offset for multi-byte NOPs like that.
        # # offset = potential_instrs[1].foffset + potential_instrs[1].instruction.len - nulls

        # try:
        #     fd = open("aa", "r+b")
        # except IOError:
        #     print("ERROR! ", file=sys.stderr)
        # else:
        #     # fd.seek(offset)
        #     fd.seek(0x1044)
        #     fd.write(mess)
        #     fd.close()
        ################
        
        
        # Prepare empty Analyzer to be filled by Selector.
        analyzer = Analyzer(bitness, 0, 0, 0.0, 0, 0)
        potential_my_instrs = \
            Selector.select(all_my_instrs, args.method, args.force, analyzer)

        # for a, b in itertools.combinations(potential_my_instrs, 2):
        #     if id(a) == id(b):
        #         print(f"kurva..a.. {a.ioffset}, {a.eq_class}, {a.mov_scheduling_flag}")
        #         print(f"kurva..b.. {b.ioffset}, {b.eq_class}, {b.mov_scheduling_flag}")
        
        # return
    
        # ###### KONTROLNY VYPIS
        # for my_instr in potential_my_instrs:

        #     ##### ENCODING - vracia zlu dlzku dlhych NOPov s prefixami
        #     encoder = Encoder(bitness)
        #     try:
        #         ############ NEPOUZIVAT TUTO DLZKU !!!!!!!!!!!!!!
        #         encoder.encode(my_instr.instruction, my_instr.instruction.ip)
        #     except ValueError:
        #         buffer = ""
        #         # print("ERROR encode")
        #         # sys.exit(1000)
        #     else:
        #         buffer = encoder.take_buffer()
        #         hexcode = " ".join(re.findall(r'(?:[0-9a-fA-F]{2}|[0-9a-fA-F])', buffer.hex()))

        #     got_op_code = my_instr.instruction.op_code()

        #     print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {got_op_code.instruction_string:<16}     {got_op_code.op_code_string:<15} {my_instr.instruction.len:2} |  {hexcode:15} | {my_instr.eq_class}")
        #     print(f"{my_instr.instruction}")
        #     print()
        #     if my_instr.instruction.encoding != EncodingKind.LEGACY:
        #         print()
        #         print()
        #         print()
        #         print()
        #         print("nieee")
        #         print()
        #         print()
        #         print()
        #         print()

        # # print(f"\nNONE: {0x0:08b}\n  OF: {0x1:08b}\n  SF: {0x2:08b}\n  ZF: {0x4:08b}\n  AF: {0x8:08b}\n  CF: {0x10:08b}\n  PF: {0x20:08b}")
        
        # print(f"{OpCodeInfo(Code.FNOP).op_code:x}, {Code.}")
        # return

        ##### TESTOVANIE
        # opat sa disassembluje vstupny subor a printnu sa instrukcie..
        # chcem zmenu len tam kde som ju spravil.. diff
        
        if args.mode != "a" and args.mode != "analyze":
            # Encode indexes of each class members. They will be used
            # while embedding/extracting/resetting.
            EqClassesProcessor.encode_members_indexes()
        
        ######### POZOR NA ENDIANNESS, NEVIEM CI SOM DOBRE TVORIL BYTES..
        if args.mode == "e" or args.mode == "embed":
            
            ####### EMBEDDING
            # zatial sa vlozia bity na kazde miesto
            # ak bude cas, z tohto listu referencii sa vyselektuju len niektore,
            # ale tak aby som bol schopny vratit rovnake vysledky pri extrakcii
            
            # Get secret data and file extension in bytes.
            b_secret_data, b_fext = Embedder.get_secret_data(args.secret_message)
            
            print()
            print(f"len(b_secret_data): {len(b_secret_data):,}")
            print(f"b_fext: {len(b_fext):,} -> {b_fext}")
            
            # Lossless compression of secret data.
            b_comp = Embedder.compress(b_secret_data)
            print(f"len(b_comp): {len(b_comp):,}")
            
            # Encrypt compressed secret data.
            b_encrypted = Embedder.encrypt_data(b_comp)
            # Compute length of encrypted data and XOR the length with
            # password. The length is 32 bytes long and do not count
            # with itself neither with 8 bytes long file extension
            # (it's only raw data).
            b_xored_len = Embedder.xor_data_len(b_encrypted)
            # XOR file extension with password. The extension is always
            # 8 bytes long.
            b_xored_fext = Embedder.xor_fext(b_fext)
            
            # Get all parts of data into the one.
            b_message = b_xored_len + b_xored_fext + b_encrypted
            
            print(f"MIN CAPACITY: {analyzer.min_capacity / 8} bytes")
            print(f"MAX CAPACITY: {analyzer.max_capacity / 8} bytes")
            print(f"len(b_message): {len(b_message)} bytes")
            print(f"b_message: {b_message}")

            # Check if cover file has sufficient capacity and inform.
            # Function can exit program if required by user.
            Embedder.check_cap(len(b_message), analyzer)

            # vklada sa sprava -- prechod skrz ekviv. triedy atd. podla metody
            Embedder.embed(inputf,
                           b_message,
                           potential_my_instrs,
                           analyzer.bitness)
            
            print("---------------------------------------------------")
            
            ############extrakcia
            
            # extract xorovanu dlzku dat -- 32B
            
            # UnXOR extracted length of data with password.
            data_len = Extractor.unxor_data_len(b_xored_len)
            print(f"extracted (encrypted) data len: {data_len:,}")
            
            # extract fext -- 8B
            
            # UnXOR extracted file extension with password.
            b_unxored_fext = Extractor.unxor_fext(b_xored_fext)
            
            # extract zvysne data -- pouzitie metody
            
            # Decrypt extracted data.
            b_decrypted = Extractor.decrypt_data(b_encrypted)
            
            # Decompress decrypted data and get secret message.
            b_decomp = Extractor.decompress(b_decrypted)
            
            ##### len kontrola
            if b_secret_data == b_decomp:
                print("OK kompresia")
            else:
                print("NEOK kompresia")
            ##### len kontrola
            if b_fext == b_unxored_fext:
                print("OK fext")
            else:
                print("NEOK fext")
            
            Extractor.make_output(b_decomp, b_unxored_fext)
            
        elif args.mode == "x" or args.mode == "extract":
            
            ##### extrakcia
            # prechod skrz list referencii na instrukcie na extrakciu
            # mam dlzku a podla nej iterujem a extrahujem
            pass
        
        elif args.mode == "r" or args.mode == "reset":
            
            # prechod cez list referencii na instrukcie
            # vkladat budem asi len nuly -- najcastejsie sa vyskytujuce tvary z kazdej classy, vynulujem space v NOPs.
            pass
        
        # Only analysis is printed.
        else:
            analyzer.print_analysis(args.method, inputf)
        
    
if __name__ == "__main__":
    
    start = time.time()
    
    try:
        Main.run()
    except KeyboardInterrupt:
        sys.exit(0)
    
    print("\n--- %s seconds ---" % (time.time() - start))