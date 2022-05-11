#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
**Steganography for Executables**

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
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
__credits__ = ["Ľuboš Bever"]
__license__ = "GNU GPLv3"
__version__ = "1.0"
__maintainer__ = "Ľuboš Bever"
__email__ = "beverlubos@gmail.com"
__status__ = "Prototype"


class Main:
    """
    Class contains only `run` method to run the whole program.
    """

    @staticmethod
    def run() -> None:
        """
        Run program.
        """
        
        # Run timer for case when verbose mode will be printed.
        time_start = time.time()
        
        # Parse command-line arguments.
        args = ArgsParser.parse()
        
        # If analyze mode, do not verbose.
        if args.mode == "a" or args.mode == "analyze":
            args.verbose = False
        
        # Modes 'embed' and 'analyze' require cover file, others require
        # stego-file.
        if args.mode == "e" or \
           args.mode == "embed" or \
           args.mode == "a" or \
           args.mode == "analyze":
            inputf = args.cover_file
        else:
            inputf = args.stego_file
        
        # Prepare empty Analyzer to be filled.
        analyzer = Analyzer()
        
        if args.verbose:
            print("Disassembling given executable...")
            sys.stdout.flush()
        
        # Disassemble all instructions from executable and instantiate
        # class MyInstruction for every decoded one.
        all_my_instrs = Disassembler.disassemble(inputf, analyzer)
        
        if args.verbose:
            print("Parsing configuration file...")
            sys.stdout.flush()
        
        # Prepare instances of equivalent classes.
        EqClassesProcessor.prepare_eq_classes(args.method, args.config_file)
        
        if args.verbose:
            print("Analyzing given executable...")
            sys.stdout.flush()
        
        # Select potential instructions.
        potential_my_instrs = Selector.select(all_my_instrs,
                                              args.method,
                                              args.force,
                                              inputf,
                                              analyzer)
        
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

            # Lossless compression of secret data.
            b_comp = Embedder.compress(b_secret_data)
            
            # Encrypt compressed secret data.
            b_encrypted = Embedder.encrypt_data(b_comp, args.passwd)
            
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
                                               args.verbose,
                                               args.passwd)
            
            if args.verbose:
                print("Postprocessing of extracted data...")
                sys.stdout.flush()
            
            # Locate and prepare file extension bits.
            b_xored_fext = bits_extracted[:SIZE_OF_FEXT * 8].tobytes()
            
            # File extension bits can be deleted to get pure data bits.
            del bits_extracted[:SIZE_OF_FEXT * 8]
            
            # UnXOR extracted file extension with password.
            b_unxored_fext = Extractor.unxor_fext(b_xored_fext)
            
            # Decrypt extracted data.
            b_encrypted = bits_extracted.tobytes()
            b_decrypted = Extractor.decrypt_data(b_encrypted)
            
            # Decompress decrypted data and get secret message.
            b_decomp = Extractor.decompress(b_decrypted)

            if args.verbose:
                print("Generating output...")
                sys.stdout.flush()
            
            Extractor.make_output(b_decomp, b_unxored_fext)
        
        # Only analysis is printed.
        else:
            analyzer.print_analysis(args.method, inputf)
        
        
        if args.verbose:
            # Print time.
            print("--- %s seconds ---" % (time.time() - time_start))
    
    
if __name__ == "__main__":
    
    try:
        Main.run()
    except KeyboardInterrupt:
        sys.exit(0)