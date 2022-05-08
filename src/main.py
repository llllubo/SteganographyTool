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
        
        # Run timer for case when verbose mode will be used.
        start = time.time()
        
        args = ArgsParser.parse()
        
        # print(f"\nargs:\n{args}\n")
        
        # Modes 'embed' and 'analyze' require cover file, others require
        # stego-file.
        if args.mode == "e" or \
           args.mode == "embed" or \
           args.mode == "a" or \
           args.mode == "analyze":
            inputf = args.cover_file
        else:
            inputf = args.stego_file
        
        if args.verbose:
            print("Disassembling given executable...")
            sys.stdout.flush()
        
        # Disassemble all instructions from executable and instantiate
        # class MyInstruction for every decoded one.
        all_my_instrs, bitness = Disassembler.disassemble(inputf)
        
        if args.verbose:
            print("Parsing configuration file...")
            sys.stdout.flush()
        
        # Prepare instances of equivalent classes.
        EqClassesProcessor.prepare_eq_classes(args.method, args.config_file)
        
        if args.verbose:
            print("Analyzing given executable...")
            sys.stdout.flush()
        
        # Prepare empty Analyzer to be filled.
        analyzer = Analyzer(bitness, 0, 0, 0.0, 0, 0)
        potential_my_instrs = Selector.select(all_my_instrs,
                                              args.method,
                                              args.force,
                                              inputf,
                                              analyzer)
            
        # for a, b in itertools.combinations(potential_my_instrs, 2):
        #     if id(a) == id(b):
        #         print(f"kurva..a.. {a.ioffset}, {a.eq_class}, {a.mov_scheduling_flag}")
        #         print(f"kurva..b.. {b.ioffset}, {b.eq_class}, {b.mov_scheduling_flag}")
        # return
        ###### KONTROLNY VYPIS
        # tmp = 0
        # for my_instr in potential_my_instrs:

        #     got_op_code = my_instr.instruction.op_code()
        #     tmp += len(my_instr.instruction)
        #     # print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {got_op_code.instruction_string:<16}     {my_instr.instruction.len:2}", end=" | ")
        #     print(f"{my_instr.instruction}")
        #     # print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {my_instr.instruction.len:2}   {got_op_code.instruction_string:<16}", end=" | ")
        #     # print(f"{my_instr.eq_class.class_name} | {my_instr.instruction}")
        #     # print(f"{my_instr.eq_class.class_name}")
        #     # print()
        #     if my_instr.instruction.encoding != EncodingKind.LEGACY:
        #         print()
        #         print()
        #         print("nieee")
        #         print()
        #         print()
        # print(f"len: {tmp}")
        # return
        
        # If there was not Analyze mode given, all necessary operations
        # over equivalent classes are done.
        if args.mode != "a" and args.mode != "analyze":
            
            if args.verbose:
                if args.mode == "x" or args.mode == "extract":
                    word = "extraction"
                else:
                    word = "embedding"
                print(f"Preparing for {word}...")
                sys.stdout.flush()
            
            # Encode indexes of each class members. They will be used
            # while embedding/extracting.
            EqClassesProcessor.encode_members_indexes()
            
            # Parse equivalent class members if needed (this is not
            # applied for example on NOP classes).
            EqClassesProcessor.parse_members()
        
        if args.mode == "e" or args.mode == "embed":
            
            if args.verbose:
                print("Preprocessing given data...")
                sys.stdout.flush()
            
            # Get secret data and file extension in bytes.
            b_secret_data, b_fext = Embedder.get_secret_data(args.secret_message)
            
            # print()
            # print(f"len(b_secret_data): {len(b_secret_data):,}")
            # print(f"b_fext: {len(b_fext):,} -> {b_fext}")
            
            # Lossless compression of secret data.
            b_comp = Embedder.compress(b_secret_data)
            
            # print(f"len(b_comp): {len(b_comp):,}")
            
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
            
            # b_message = len(b_secret_data).to_bytes(SIZE_OF_DATA_LEN, byteorder="little") + b_fext + b_secret_data
            
            # print(f"MIN CAPACITY: {analyzer.min_capacity / 8} bytes")
            # print(f"MAX CAPACITY: {analyzer.max_capacity / 8} bytes")
            # print(f"len(b_message): {len(b_message)} bytes")
            # print(f"b_message: {b_message}")

            # Check if cover file has sufficient capacity and if not,
            # inform and exit the program.
            Embedder.check_cap(len(b_message), analyzer)

            if args.verbose:
                print("Embedding...")
                sys.stdout.flush()

            # Embedding desired data according selected method.
            Embedder.embed(inputf,
                           b_message,
                           potential_my_instrs,
                           args.verbose)
            
        elif args.mode == "x" or args.mode == "extract":
            
            if args.verbose:
                print("Extracting...")
                sys.stdout.flush()
            
            # Extract all data.
            bits_extracted = Extractor.extract(inputf,
                                               potential_my_instrs,
                                               args.verbose)
            
            # print(f"main - extracted_len: {len(bits_extracted) / 8}")
            # print(f"{bits_extracted.tobytes()}")
            # b_fext = bits_extracted[:SIZE_OF_FEXT * 8].tobytes()
            # print(f"{b_fext}")
            # b_data = bits_extracted[SIZE_OF_FEXT * 8:].tobytes()
            # Extractor.make_output(b_data, b_fext)
            
            if args.verbose:
                print("Postprocessing of extracted data...")
                sys.stdout.flush()
            
            # Locate and prepare file extension bits.
            b_xored_fext = bits_extracted[:SIZE_OF_FEXT * 8].tobytes()
            
            # File extension bits can be deleted to get pure data bits.
            del bits_extracted[:SIZE_OF_FEXT * 8]
            
            # print(f"{b_xored_fext}")
            
            # UnXOR extracted file extension with password.
            b_unxored_fext = Extractor.unxor_fext(b_xored_fext)
            
            # print(f"{b_unxored_fext}")
            
            # Decrypt extracted data.
            b_encrypted = bits_extracted.tobytes()
            b_decrypted = Extractor.decrypt_data(b_encrypted)
            
            # print(f"{b_decrypted}")
            
            # Decompress decrypted data and get secret message.
            b_decomp = Extractor.decompress(b_decrypted)
            
            # print(f"{b_decomp}")
            
            if args.verbose:
                print("Generating output...")
                sys.stdout.flush()
            
            Extractor.make_output(b_decomp, b_unxored_fext)
        
        # Only analysis is printed.
        else:
            analyzer.print_analysis(args.method, inputf)
        
        
        if args.verbose:
            # Print time.
            print("--- %s seconds ---" % (time.time() - start))
    
if __name__ == "__main__":
    
    try:
        Main.run()
    except KeyboardInterrupt:
        sys.exit(0)