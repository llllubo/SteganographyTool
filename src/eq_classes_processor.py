import json
import sys
import re
import math

from bitarray import *


class EqClassesProcessor:
    # List keeps all instantiated equivalent classes.
    all_eq_classes = []
    
    
    def __init__(self,
                 method_name: str,
                 class_name: str,
                 desc: str,
                 members: list,
                 encoded_idxs: list,    # List of BITS.
                 avg_cap: float,
                 min_cap: int,
                 max_cap: int) -> None:
        self.__method_name = method_name
        self.__class_name = class_name
        self.__desc = desc
        self.__members = members
        self.__encoded_idxs = encoded_idxs
        self.__avg_cap = avg_cap
        self.__min_cap = min_cap
        self.__max_cap = max_cap
        EqClassesProcessor.all_eq_classes.append(self)
    
    
    @property
    def method_name(self) -> str:
        return self.__method_name
        
    
    @property
    def class_name(self) -> str:
        return self.__class_name
        
        
    @property
    def desc(self) -> str:
        return self.__desc
        
        
    @property
    def members(self) -> list:
        return self.__members
    
    
    @property
    def encoded_idxs(self) -> list:
        return self.__encoded_idxs
    
    
    @encoded_idxs.setter
    def set_encoded_idxs(self, idxs: list) -> None:
        self.__encoded_idxs = idxs
    
    
    @property
    def avg_cap(self) -> float:
        return self.__avg_cap
    
        
    @property
    def min_cap(self) -> int:
        return self.__min_cap
        
        
    @property
    def max_cap(self) -> int:
        return self.__max_cap
    
    
    def __repr__(self) -> str:
        return f"\nEqClass('{self.method_name[:10]}...', '{self.class_name}', '{self.desc[:10]}...', {self.members}, {self.encoded_idxs}, {self.avg_cap}, {self.min_cap}, {self.max_cap})"
    
    
    @staticmethod
    def __compute_avg_cap(members: list) -> float:
        # If within one Equivalent Class is number of members not equal
        # to Power of 2, then only average capacity can be computed as
        # real capacity depend on exact occurence of particular members
        # from class.
        n = len(members)
        return math.ceil(math.log2(n) - 1) + \
            (n - pow(2, math.ceil(math.log2(n) - 1))) / \
                pow(2, math.ceil(math.log2(n) - 1))
    
    
    @classmethod
    def prepare_eq_classes(cls, method: str, fconfig: str) -> None:
        
        try:
            fd = open(fconfig, "r")
        except IOError:
            print(f"ERROR! Can not load configuration file: {fconfig}", file=sys.stderr)
            sys.exit(101)
        
        obj_json = json.load(fd)
        fd.close()
        
        # Change form of string method.
        if method == "mov":
            method = "Scheduling"
        elif method == "nops":
            method = "NOP Instructions Using"
        elif method == "sub":
            method = "Basic Instruction Substitution"
        elif method == "ext-sub":
            method = "Extended Instruction Substitution"
        
        for method_name in obj_json:
            
            obj_eq_classes = obj_json[method_name]
            # Load only equivalent classes appropriate for given method,
            # also when 'ext-sub' method is given, classes for 'sub'
            # method are loaded as well.
            if method_name == method or \
                (
                    method == "Extended Instruction Substitution" and \
                    method_name == "Basic Instruction Substitution"
                ) or method == "ext-sub-nops-mov":
                
                for eq_class_name in obj_eq_classes:
                    
                    obj_eq_class = obj_eq_classes[eq_class_name]
                    
                    # Compute capacities for some equivalent classes.
                    if eq_class_name == ">3 Bytes Long NOP":
                        # This must be computed for every instruction
                        # separately, therefore 0.0 for now.
                        cap = 0.0
                    
                    else:
                        cap = cls.__compute_avg_cap(obj_eq_class['Members'])
                    
                    cls(
                        method_name=method_name,
                        class_name=eq_class_name,
                        desc=obj_eq_class['Description'],
                        members=obj_eq_class['Members'],
                        encoded_idxs=[],
                        avg_cap=cap,
                        min_cap=math.floor(cap),
                        max_cap=math.ceil(cap),
                    )
                    
    @classmethod
    def encode_members_indexes(cls) -> None:
        # It is used if not analyze mode was given, therefore it's
        # called after eq_classes objects creation, additionally.
        for eq_class in cls.all_eq_classes:
            
            mem_len = len(eq_class.members)
            if mem_len:
                # Equivalent class has some members.
                base_bits_len = math.floor(math.log2(mem_len))
                
                for idx, _ in enumerate(eq_class.members):
                    idx = idx % pow(2, base_bits_len)
                    eq_class.encoded_idxs.append(
                        bitarray(f"{idx:0{base_bits_len}b}", endian="little"))
                    
                # Correctness of bit values - adding 'group bits' at
                # the end of bitarrays.
                for idx, encoded_idx in enumerate(eq_class.encoded_idxs):

                    if (mem_len - 1) < (idx + pow(2, base_bits_len)):
                        break
                    else:
                        encoded_idx.append(0)
                        eq_class.encoded_idxs[idx + pow(2, base_bits_len)].append(1)
                        
                        
    @classmethod
    def parse_members(cls) -> None:
        # Parse certain members to bitarrays required to embed or to
        # extract. Then Embedder and Extractor will just pick this bits.
        for eq_class in cls.all_eq_classes:
            
            if eq_class.class_name == "MOV Scheduling" or \
                eq_class.class_name == "Swap base-index registers 32-bit":
                
                for mem in eq_class.members:
                    if not re.match(r'^(?:Ascending|Descending)$',mem.strip()):
                        print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}",
                            file=sys.stderr)
                        sys.exit(102) 
            
            elif eq_class.class_name == "TEST non-accumulator register" or \
                eq_class.class_name == "SHL/SAL":
                # Must be 3 bits long as they will modify Reg/Opcode
                # field inside ModR/M byte of instruction.
                try:
                    eq_class.members[:] = [bitarray(f"{int(mem.strip()[-1]):03b}")
                                            for mem in eq_class.members]
                except ValueError:
                    print(f"ERROR! While parsing equivalent class members an error occured.",
                          file=sys.stderr)
                    sys.exit(102)
                    
            elif re.match(r"^(?:ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) 32-bit$",
                          eq_class.class_name):
                # Set Direction bit as bitarray with length equal to 1.
                for idx, mem in enumerate(eq_class.members):
                    if re.match(
                        r'^Direction Bit: [0-1]{1}$',
                        mem.strip()):
                        
                        eq_class.members[idx] = \
                            bitarray(f"{int(mem.strip()[-1]):b}")
                    
                    else:
                        print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}",
                          file=sys.stderr)
                        sys.exit(102)  
                    
            elif eq_class.class_name == "TEST/AND/OR":
                
                re_test = re.compile(r'^TEST r/m, r$')
                re_dir0 = re.compile(r'^(?P<mnemo>AND|OR) r/m, r$')
                re_dir1 = re.compile(r'^(?P<mnemo>AND|OR) r, r/m$')
            
                for idx, mem in enumerate(eq_class.members):
                    
                    dir0 = re_dir0.match(mem.strip())
                    if dir0 is not None:
                        # It is r/m, r form.
                        mnemo = dir0.group("mnemo")
                        if mnemo == "AND":
                            # It is AND r/m, r.
                            eq_class.members[idx] = "0x21"
                        elif mnemo == "OR":
                            # It is OR r/m, r.
                            eq_class.members[idx] = "0x09"
                    else:
                        dir1 = re_dir1.match(mem.strip())
                        if dir1 is not None:
                            # It is r, r/m form.
                            mnemo = dir1.group("mnemo")
                            if mnemo == "AND":
                                # It is AND r, r/m.
                                eq_class.members[idx] = "0x23"
                            elif mnemo == "OR":
                                # It is OR r, r/m.
                                eq_class.members[idx] = "0x0b"
                        else:
                            test = re_test.match(mem.strip())
                            if test is not None:
                                # It is TEST r/m, r.
                                eq_class.members[idx] = "0x85"
                            else:
                                # Wrong class member inside config file.
                                print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}", file=sys.stderr)
                                sys.exit(102)
            
            elif eq_class.class_name == "SUB/XOR":

                re_dir0 = re.compile(r'^(?P<mnemo>SUB|XOR) r/m, r$')
                re_dir1 = re.compile(r'^(?P<mnemo>SUB|XOR) r, r/m$')
            
                for idx, mem in enumerate(eq_class.members):
                    
                    dir0 = re_dir0.match(mem.strip())
                    if dir0 is not None:
                        # It is r/m, r form.
                        mnemo = dir0.group("mnemo")
                        if mnemo == "XOR":
                            # It is XOR r/m, r.
                            eq_class.members[idx] = "0x31"
                        elif mnemo == "SUB":
                            # It is SUB r/m, r.
                            eq_class.members[idx] = "0x29"
                    else:
                        dir1 = re_dir1.match(mem.strip())
                        if dir1 is not None:
                            # It is r, r/m form.
                            mnemo = dir1.group("mnemo")
                            if mnemo == "XOR":
                                # It is XOR r, r/m.
                                eq_class.members[idx] = "0x33"
                            elif mnemo == "SUB":
                                # It is SUB r, r/m.
                                eq_class.members[idx] = "0x2b"
                        else:
                            # Wrong class member inside config file.
                            print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}", file=sys.stderr)
                            sys.exit(102)
                        
            
            elif re.match(r"^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB)$",
                          eq_class.class_name):
                # Set Direction bit as bitarray with length equal to 1.
                for idx, mem in enumerate(eq_class.members):
                    if re.match(
                        r'^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r/m, r$',
                        mem.strip()):
                        
                        eq_class.members[idx] = bitarray('0')
                    
                    elif re.match(
                        r'^(?:MOV|ADD|SUB|AND|OR|XOR|CMP|ADC|SBB) r, r/m$',
                        mem.strip()):
                        
                        eq_class.members[idx] = bitarray('1')
                    
                    else:
                        print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}",
                          file=sys.stderr)
                        sys.exit(102)              
                    
            elif eq_class.class_name == "ADD negated":
                # ADD and SUB instructions have both same opcodes, but
                # they differ in Reg/Opcode field inside ModR/M byte.
                for idx, mem in enumerate(eq_class.members):
                    
                    if re.match(r'^ADD r/m, imm$', mem.strip()):
                        # Reg/Opcode field of ADD.
                        eq_class.members[idx] = bitarray('000')
                        
                    elif re.match(r'^SUB r/m, -imm$', mem.strip()):
                        # Reg/Opcode field of SUB.
                        eq_class.members[idx] = bitarray('101')
                   
                    else:
                        # Wrong format of class member.
                        print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}",
                          file=sys.stderr)
                        sys.exit(102)
            
            elif eq_class.class_name == "SUB negated":
                # ADD and SUB instructions have both same opcodes, but
                # they differ in Reg/Opcode field inside ModR/M byte.
                for idx, mem in enumerate(eq_class.members):
                    
                    if re.match(r'^SUB r/m, imm$', mem.strip()):
                        # Reg/Opcode field of SUB.
                        eq_class.members[idx] = bitarray('101')
                    
                    elif re.match(r'^ADD r/m, -imm$', mem.strip()):
                        # Reg/Opcode field of ADD.
                        eq_class.members[idx] = bitarray('000')
                    
                    else:
                        # Wrong format of class member.
                        print(f"ERROR! While parsing equivalent class members from file an error occured: {eq_class.class_name}",
                          file=sys.stderr)
                        sys.exit(102)