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
import re
from traceback import print_tb
from iced_x86 import *

from args_parser import ArgsParser
from disassembler import Disassembler
from embedder import Embedder
from extractor import Extractor
from analyzer import Analyzer


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
        # print(f"args:\n{args}\n")
        
        # Only modes 'embed' and 'analyze' require cover file,
        # others require stego-file.
        if args.mode == "e" or \
           args.mode == "embed" or \
           args.mode == "a" or \
           args.mode == "analyze":
            inputf = args.cover_file
        else:
            inputf = args.stego_file            
        
        # Prepare empty Analyzer (only method is set now) to be filled
        # by Disassembler.
        analyzer = Analyzer(0, 0, 0)
        
        # Disassemble all instructions from executable.
        # Needed to keep all of them because of flags checking.
        # It also finds useable instructions according to method and 
        # compute embedding capacity.
        all_instrs, potential_instrs, bitness = \
            Disassembler.disassemble(inputf, args.method, analyzer)

        ######KONTROLNY VYPIS
        for my_instr in potential_instrs:
            
            ####### len skusam, lebo dlhe NOPy s prefixmi su zle encodovane
            # try:
            #     fd = open(inputf, "rb")
            # except IOError:
            #     print("ERROR ....")
            #     sys.exit(1000)
            # fd.seek(my_instr.foffset)
            # b_instr = fd.read(my_instr.instruction.len)
            # fd.close()
            # print(f"{b_instr.hex():20}", end="\t")
            
            ##### ENCODING - vracia zlu dlzku dlhych NOPov s prefixami
            encoder = Encoder(bitness)
            try:
                ############ NEPOUZIVAT TUTO DLZKU !!!!!!!!!!!!!!
                encoder.encode(my_instr.instruction, my_instr.instruction.ip)
            except ValueError:
                buffer = ""
                # print("ERROR encodee")
                # sys.exit(1000)
            else:
                buffer = encoder.take_buffer()
                hexcode = " ".join(re.findall(r'(?:[0-9a-fA-F]{2}|[0-9a-fA-F])', buffer.hex()))
            
            # if b_instr.hex() == buffer.hex():
            #     print("ok")
            # else:
            #     print("neok")
            # print()
            # continue

            got_op_code = my_instr.instruction.op_code()
            
            print(f"{my_instr.ioffset:8}   {my_instr.foffset:6x}    {got_op_code.instruction_string:<16}     {got_op_code.op_code_string:<15} {my_instr.instruction.len:2} |  {hexcode:15}")
        
        ##### TESTOVANIE
        # opat sa disassembluje vstupny subor a printnu sa instrukcie..
        # chcem zmenu len tam kde som ju spravil.. diff
    
    
        ################
        # nulls = 5
        # hex_string = "0x9876543210"
        # mess = bytes.fromhex(hex_string[2:])
        # # Must compute offset for multi-byte NOPs like that.
        # offset = potential_instrs[1].foffset + potential_instrs[1].instruction.len - nulls

        # try:
        #     fd = open("aa", "r+b")
        # except IOError:
        #     print("ERROR! ", file=sys.stderr)
        # else:
        #     fd.seek(offset)
        #     # fd.seek(0x1b9b7d)
        #     fd.write(mess)
        #     fd.close()
        ################
    
    
        ############ VYTVORIT EQ CLASSES PODLA METODY
        print(f"\nNONE: {0x0:08b}\n  OF: {0x1:08b}\n  SF: {0x2:08b}\n  ZF: {0x4:08b}\n  AF: {0x8:08b}\n  CF: {0x10:08b}\n  PF: {0x20:08b}")
        return
        
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
            
            print(f"CAPACITY: {analyzer.capacity}")
            print(f"len(b_message): {len(b_message)}")
            print(f"b_message: {b_message}")
            
            #### UROBI SA KONTROLA KAPACITY A VYPISE AK NESTACI
            if (analyzer.capacity / 8) < len(b_message):
                
                print(f"KAPACITA JE V PIZDUCH")###############
                
                answer = input("Capacity of the cover file is not sufficient (the embedding data will be truncated).\nDo you want to continue anyway? [y/n] ").lower().strip()

                if answer != "yes" and \
                    answer != "ye" and \
                    answer != "y":
                    print("Steganography is not applied!")
                    sys.exit(0)
            else:        
                print(f"KAPACITA JE OK")

            # vklada sa sprava -- prechod skrz ekviv. triedy atd. podla metody
            
            print()
            
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
    
    
    
        ### Z ICED POVODNE SPRACOVANIE
        # code_bitness, code_sections = Disassembler.get_binary_info(inputf)
        
        # ### ulozit vsetky instrukcie do listu -- parsovat vystup objdump
        # # nejako oddelit funkcie od seba, aj sekcie
        # # musim ich mat kvoli neskorsej kontrole na priznaky
        # disassm_sections = []
        # for sec in code_sections:
            
        #     # CODE_RIP = 0x0000_0001_4000_1000
        #     # start_foffset = 0x400 + (CODE_RIP - 0x0001_4000_1000)
        #     code_size = int(sec[1], 16)
        #     code_rip = int(sec[2], 16)
        #     start_foffset = int(sec[3], 16)
        #     # print(f"{sec[0]}, {code_size:,}, {code_rip:,}, {start_foffset:,}")
        #     print(f"{sec[0]}, 0x{code_size:x}, 0x{code_rip:x}, 0x{start_foffset:x}")

        #     try:
        #         fd = open(inputf, "rb")
        #     except IOError:
        #         print(f"ERROR! Can not access given executable: {inputf}", file=sys.stderr)
        #         sys.exit(101)
            
        #     fd.seek(start_foffset)
        #     code = fd.read(code_size)
        #     fd.close()

        #     # Create the decoder and initialize RIP
        #     decoder = iced.Decoder(code_bitness, code, ip=code_rip)
        #     disassm_sections.append(decoder)

        #     formatter = iced.Formatter(iced.FormatterSyntax.INTEL)
        #     formatter.digit_separator = "'"
        #     formatter.first_operand_char_index = 8
        #     formatter.hex_prefix = "0x"
        #     formatter.hex_suffix = ""
        #     formatter.hex_digit_group_size = 4
        #     formatter.uppercase_hex = False # cisla v operandoch
        #     formatter.space_after_operand_separator = True
        #     formatter.show_zero_displacements = True
        #     formatter.leading_zeros = True

        #     for instr in decoder:
        #         disasm = formatter.format(instr)
        #         #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
        #         #   op0_str = formatter.format_operand(instr, 0)
        #         #   operands_str = formatter.format_all_operands(instr)
                
        #         instr_offset = instr.ip - code_rip
        #         bytes_str = code[instr_offset:(instr_offset + instr.len)].hex().lower()
        #         print(f"{instr.ip:016X} {bytes_str:30} {disasm}")
        #     print()