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
from bitarray import bitarray
from iced_x86 import *

from args_parser import ArgsParser
from disassembler import Disassembler
from embedder import Embedder
from extractor import Extractor
from analyzer import Analyzer
from selector import Selector
from eq_classes_processor import EqClassesProcessor
from common import *


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
            
        
        # hex_string = "0x0f1f009090909066909090"
        # mess = bytes.fromhex(hex_string[2:])
        # try:
        #     # fd = open("exace-testing/AcroRd32.exe", "r+b")
        #     fd = open("aa", "r+b")
        # except IOError:
        #     print("ERROR! ", file=sys.stderr)
        # else:
        #     # fd.seek(offset)
        #     fd.seek(0x10a1)
        #     fd.write(mess)
        #     fd.close()
        # return
        
        # Disassemble all instructions from executable.
        # Needed to keep all of them because of flags checking.
        # It also finds useable instructions according to method and 
        # compute embedding capacity.
        all_my_instrs, bitness = Disassembler.disassemble(inputf)
        
        # Prepare instances of equivalent classes.
        EqClassesProcessor.prepare_eq_classes(args.method, args.config_file)
        
        # Prepare empty Analyzer to be filled by Selector.
        analyzer = Analyzer(bitness, 0, 0, 0.0, 0, 0)
        potential_my_instrs = \
            Selector.select(all_my_instrs, args.method, args.force, analyzer)
            
        # for a, b in itertools.combinations(potential_my_instrs, 2):
        #     if id(a) == id(b):
        #         print(f"kurva..a.. {a.ioffset}, {a.eq_class}, {a.mov_scheduling_flag}")
        #         print(f"kurva..b.. {b.ioffset}, {b.eq_class}, {b.mov_scheduling_flag}")
    
        # ###### KONTROLNY VYPIS
        # tmp = 0
        # for my_instr in potential_my_instrs:

        #     got_op_code = my_instr.instruction.op_code()
        #     tmp += len(my_instr.instruction)
        #     # print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {got_op_code.instruction_string:<16}     {my_instr.instruction.len:2}", end=" | ")
        #     print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {my_instr.instruction.len:2}", end=" | ")
        #     # print(f"{my_instr.eq_class.class_name} | {my_instr.instruction}")
        #     print(f"{my_instr.eq_class.class_name}")
        #     print()
        #     if my_instr.instruction.encoding != EncodingKind.LEGACY:
        #         print()
        #         print()
        #         print("nieee")
        #         print()
        #         print()
        # print(f"len: {tmp}")
        # return

        ##### TESTOVANIE
        # opat sa disassembluje vstupny subor a printnu sa instrukcie..
        # chcem zmenu len tam kde som ju spravil.. diff
        
        # If there was not Analyze mode given, all necessary operations
        # over equivalent classes are done.
        if args.mode != "a" and args.mode != "analyze":
            # Encode indexes of each class members. They will be used
            # while embedding/extracting/resetting.
            EqClassesProcessor.encode_members_indexes()
            # Parse equivalent class members if needed (this is not
            # applied for example on NOP classes).
            EqClassesProcessor.parse_members()
        #     print(EqClassesProcessor.all_eq_classes)
        # return
        ######### POZOR NA ENDIANNESS, NEVIEM CI SOM DOBRE TVORIL BYTES..
        
        if args.mode == "e" or args.mode == "embed":
            
            # Get secret data and file extension in bytes.
            b_secret_data, b_fext = Embedder.get_secret_data(args.secret_message)
            
            print()
            print(f"len(b_secret_data): {len(b_secret_data):,}")
            print(f"b_fext: {len(b_fext):,} -> {b_fext}")
            
            # # Lossless compression of secret data.
            # b_comp = Embedder.compress(b_secret_data)
            # print(f"len(b_comp): {len(b_comp):,}")
            
            # # Encrypt compressed secret data.
            # b_encrypted = Embedder.encrypt_data(b_comp)
            # # Compute length of encrypted data and XOR the length with
            # # password. The length is 32 bytes long and do not count
            # # with itself neither with 8 bytes long file extension
            # # (it's only raw data).
            # b_xored_len = Embedder.xor_data_len(b_encrypted)
            # # XOR file extension with password. The extension is always
            # # 8 bytes long.
            # b_xored_fext = Embedder.xor_fext(b_fext)
            
            # # Get all parts of data into the one.
            # b_message = b_xored_len + b_xored_fext + b_encrypted
            
            b_message = len(b_secret_data).to_bytes(SIZE_OF_DATA_LEN, byteorder="little") + b_fext + b_secret_data
            # print(f"{b_message}")
            
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
            
            # ############extrakcia
            
            # # extract xorovanu dlzku dat -- 32B
            
            # # UnXOR extracted length of data with password.
            # data_len = Extractor.unxor_data_len(b_xored_len)
            # print(f"extracted (encrypted) data len: {data_len:,}")
            
            # # extract fext -- 8B
            
            # # UnXOR extracted file extension with password.
            # b_unxored_fext = Extractor.unxor_fext(b_xored_fext)
            
            # # extract zvysne data -- pouzitie metody
            
            # # Decrypt extracted data.
            # b_decrypted = Extractor.decrypt_data(b_encrypted)
            
            # # Decompress decrypted data and get secret message.
            # b_decomp = Extractor.decompress(b_decrypted)
            
            # ##### len kontrola
            # if b_secret_data == b_decomp:
            #     print("OK kompresia")
            # else:
            #     print("NEOK kompresia")
            # ##### len kontrola
            # if b_fext == b_unxored_fext:
            #     print("OK fext")
            # else:
            #     print("NEOK fext")
            
            # Extractor.make_output(b_decomp, b_unxored_fext)
            
        elif args.mode == "x" or args.mode == "extract":
            
            ##### extrakcia
            # prechod skrz list referencii na instrukcie na extrakciu
            # mam dlzku a podla nej iterujem a extrahujem
            
            # Extract all data.
            bits_extracted = Extractor.extract(inputf,
                                               potential_my_instrs,
                                               bitness)
            
            print(f"main - extracted_len: {len(bits_extracted) / 8}")
            print(f"{bits_extracted.tobytes()}")
            b_fext = bits_extracted[:SIZE_OF_FEXT * 8].tobytes()
            print(f"{b_fext}")
            b_data = bits_extracted[SIZE_OF_FEXT * 8:].tobytes()
            Extractor.make_output(b_data, b_fext)
            
            # # Locate and prepare file extension bits.
            # b_xored_fext = bits_extracted[:SIZE_OF_FEXT * 8].tobytes()
            # # File extension bits can be deleted to get pure data bits.
            # del bits_extracted[:SIZE_OF_FEXT * 8]
            # print(f"{b_xored_fext}")
            # # UnXOR extracted file extension with password.
            # b_unxored_fext = Extractor.unxor_fext(b_xored_fext)
            # print(f"{b_unxored_fext}")
            
            # # Decrypt extracted data.
            # b_encrypted = bits_extracted.tobytes()
            # b_decrypted = Extractor.decrypt_data(b_encrypted)
            # print(f"{b_decrypted}")
            # # Decompress decrypted data and get secret message.
            # b_decomp = Extractor.decompress(b_decrypted)
            # print(f"{b_decomp}")
            # Extractor.make_output(b_decomp, b_unxored_fext)
        
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