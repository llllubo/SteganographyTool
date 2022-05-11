"""
`common` module defines all functions used by methods of multiple modules.

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""


import sys
import re
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from iced_x86 import (Instruction, OpCodeInfo)
from my_instruction import MyInstruction


SIZE_OF_DATA_LEN = 32
"""
Number of bytes specifying data length inside embedded/extracted data.
"""

SIZE_OF_FEXT = 8
"""
Number of bytes specifying file extension inside embedded/extracted data.
"""


def lexicographic_mov_sort(mov_string: str):
    """
    Lexicographic sorter is designed for MOV scheduling. It has 1
    imperfection and that is unability to sort two different but
    lexicographiclly same instrucion strings.
    `E.g. MOV [rax], rbx; MOV [rbx], rax.`
    
    Example above is allowed by selector, but this function
    determines they are same. This scheduling will be skipped if
    occurs.
    
    Also, this imprefection has influence on embedding capacity.
    As practically was tested, this case is extremely rare,
    therefore average capacity is not changed and remains set to 1.
    """
    
    return sorted(sorted(mov_string), key=str.upper)


def set_skip_flag(instr: MyInstruction, next_instr: MyInstruction) -> int:
    """
    This function is always performed only for first instruction
    of NOPs sequence. There is one special situation, when for
    3 Bytes Long NOP equivalent class, it's not possible to
    determine if 1 or 2 next instructions should be skipped
    (because of `0x909090` sequence).
    
    This is common procedure for `Embedder` and `Extractor`.
    """

    if instr.eq_class.class_name == "2 Bytes Long NOP":
        if len(instr.instruction) == 2:
            skip = 0
        elif len(instr.instruction) == 1:
            skip = 1
    elif instr.eq_class.class_name == "3 Bytes Long NOP":
        if len(instr.instruction) == 3:
            skip = 0
        elif len(instr.instruction) == 2:
            skip = 1
        elif len(instr.instruction) == 1:
            # Number of NOPs that are going to be skipped is
            # significantly influenced by next instruction. If next
            # is again NOP 0x90, 2 skips must be done, otherwise 1.
            if len(next_instr.instruction) == 1:
                # Sequence of three 1 byte long NOPs (0x909090).
                skip = 2
            else:
                # Sequence of 1 byte 0x90 and any 2 bytes long NOP.
                skip = 1
        
    return skip


def get_opcode_idx(instr: bytes, opcode: int) -> int:
    """
    Return index of opcode within instruction bytes.
    """
    
    for idx, b in enumerate(instr):
        if b == opcode:
            return idx


def count_useable_bits_from_nop(instr: Instruction,
                                instr_fromf: bytes) -> int:
    """
    This counter is running only for NOP instructions with length more
    than 3 bytes.
    """
    
    # Get OPCODE index.
    opcode = OpCodeInfo(instr.code).op_code
    opcode_idx = get_opcode_idx(instr_fromf, opcode)
    
    return (len(instr) - (opcode_idx + 1) - 1) * 8


def get_file_extension(f: str) -> bytes:
    """
    Extract file extension from file path and return it as `SIZE_OF_FEXT` bytes long without dot.
    """
    
    # Create regex for file extension match and get it.
    re_fpath = re.compile(r'\.(?P<fext>(tar\.)?\w+)$')
    fpath = re_fpath.search(f)
        
    # Get parsed file extension, if present.
    if fpath is not None:
        
        b_fext = fpath.group("fext").encode()
        # If file extension si longer than 8 bytes, truncate it.
        # ONLY FOR SUPPORTABILITY REASONS.
        if len(b_fext) > SIZE_OF_FEXT:
            b_fext = b_fext[:SIZE_OF_FEXT]
        else:
            b_fext += bytes(SIZE_OF_FEXT - len(b_fext))
        
        return b_fext
    
    return bytes(SIZE_OF_FEXT)


def gen_key_from_passwd(passwd: str) -> tuple:
    """
    Ask for user password and generate symmetric key derived from it if
    no suppressing option was given (-p/--passwd).
    """
    if passwd is None:
        # Makes stdin again useable, if secret message was given from stdin.
        sys.stdin = open('/dev/tty')
        try:
            passwd = input("Please, enter the password: ")
        except EOFError:
            print("\nERROR! Required password was not given.", file=sys.stderr)
            sys.exit(109)

    b_passwd = passwd.encode()
    
    # Was generated from os.urandom(16) python function.
    b_salt = b'\x8d\x8fk\xe9,\x8e\x12\xe5\x0f\x92\xb7]-\x8f\x16T'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=b_salt,
        iterations=390000,
        backend=default_backend
    )
    b_key = base64.urlsafe_b64encode(kdf.derive(b_passwd))
    
    return b_key, b_passwd