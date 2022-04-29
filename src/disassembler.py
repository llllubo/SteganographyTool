import sys
import subprocess
import re

from iced_x86 import *
from my_instruction import MyInstruction


class Disassembler:

    
    @staticmethod
    def __parse_file_bitness(lines: str, fpath: str) -> int:
        # To get to know, what versions of instructions are allowed.
        # File bitness parsing.
        re_fformat = re.compile(
            r'file format\s+(?P<farch>[peilf]{2,3}[0-9]{0,2})-(?P<type>.*)'
            )
        fformat = re_fformat.search(lines)
        
        # Can not get file format of executable.
        if fformat is None:
            print(
                f"ERROR! Format of given executable was not recognized: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)
            
        # Get to know what type of executable was given.
        if fformat.group("farch") == "pei" or fformat.group("farch") == "pe":
            if fformat.group("type") == "i386":
                return 32
            else:
                return 64
        else:
            return int(fformat.group("farch")[-2:])
    
    
    @staticmethod
    def __parse_code_sections(lines: str, fpath: str) -> list:
        # Parse executable sections info (name, size, VMA, file offset).
        re_code_sections = re.compile(
            r'(?P<section>\.\S+)\s+(?P<size>[0-9a-fA-F]+)\s+(?P<vma>[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(?P<foffset>[0-9a-fA-F]+).*[\r\n]+.*CODE'
            )
        code_sections = re_code_sections.findall(lines)
        
        if code_sections is None:
            print(
                f"ERROR! Can not detect executable part of given file: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)

        return code_sections
    
    
    @classmethod
    def __get_binary_info(cls, fpath: str) -> tuple:
        # vraciam bitness a pre CODE sekcie: name, size, RIP (VMA), file offset
        # Often formats: pe[i]-x86-64 | pe[i]-i386 | elf64-.* | elf32-.*
        
        # Parse header info and sections info of executable.
        try:
            b_lines = subprocess.check_output(
                    ["objdump", "-h", fpath],
                    stderr=subprocess.STDOUT
                    )
        except subprocess.CalledProcessError:
            print(
                f"ERROR! Can not access given executable: {fpath}",
                file=sys.stderr
                )
            sys.exit(101)
        
        lines = b_lines.decode("UTF-8")
        bitness = cls.__parse_file_bitness(lines, fpath)
        code_sections = cls.__parse_code_sections(lines, fpath)
        
        return (bitness, code_sections)
    
    
    @staticmethod
    def __set_formatter() -> object:
        formatter = Formatter(FormatterSyntax.INTEL)
        formatter.digit_separator = "'"
        formatter.hex_digit_group_size = 4
        formatter.hex_prefix = "0x"
        formatter.hex_suffix = ""
        formatter.uppercase_hex = False
        formatter.first_operand_char_index = 8
        formatter.space_after_operand_separator = True
        formatter.space_between_memory_add_operators = True
        formatter.show_zero_displacements = True
        # formatter.displacement_leading_zeros = True
        formatter.always_show_scale = True
        # formatter.leading_zeros = True
        formatter.signed_immediate_operands = True
        
        return formatter

    
    @classmethod
    def disassemble(cls, exef: str) -> tuple:
        
        code_bitness, code_sections = cls.__get_binary_info(exef)
        
        try:
            fd = open(exef, "rb")
        except IOError:
            print(f"ERROR! Can not access given executable: {exef}", file=sys.stderr)
            sys.exit(101)
        
        # Array of all disassembled 'my instructions' classes from every
        # code section.
        all_my_instrs = []
        
        formatter = cls.__set_formatter()
        
        # Index of all decoded instructions.
        i = 0
        for sec in code_sections:
            
            sec_size = int(sec[1], 16)
            sec_rip = int(sec[2], 16)
            sec_foffset = int(sec[3], 16)
            
            # Reading code section from executable.
            fd.seek(sec_foffset)
            b_code = fd.read(sec_size)
            
            # Create the decoder and initialize RIP
            decoder = Decoder(code_bitness, b_code, ip=sec_rip)
            
            # Loop through instructions within one section.            
            for instr in decoder:
                # Calculate file offset of current instruction.
                instr_foffset = (instr.ip - sec_rip) + sec_foffset

                # Name of equivalent class is filled in by selector.
                all_my_instrs.append(
                    MyInstruction(instr, instr_foffset, i, None)
                    )
                
                ######################## KONTROLNY VYPIS
                # got_op_code = instr.op_code()
                # disasm = formatter.format(instr)
                # print(f"{i:8}   {instr_foffset:6x}    {got_op_code.instruction_string:<16}     {disasm:<36}")
                ######################## KONIEC KONTROLNY VYPIS
                
                i += 1
            print()
                
        # Close read executable.
        fd.close()

        return all_my_instrs, code_bitness