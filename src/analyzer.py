"""
`Analyzer` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""

import os


class Analyzer:
    """
    Analyzer class is responsible for printing analysis if `analyze` mode was given.
    """
    
    def __init__(self,
                 bitness: int = 0,
                 total_instrs: int = 0,
                 total_code_bytes: int = 0,
                 useable_instrs: int = 0,
                 avg_cap: float = 0.0,
                 min_cap: int = 0,
                 max_cap: int = 0) -> None:
        """
        Create an instance of the `Analyzer`.
        """
        self.__bitness = bitness
        self.__total_instrs = total_instrs
        self.__total_code_bytes = total_code_bytes
        self.__useable_instrs = useable_instrs
        self.__avg_capacity = avg_cap   # In BITS
        self.__min_capacity = min_cap   # In BITS
        self.__max_capacity = max_cap   # In BITS

    
    @property
    def bitness(self) -> int:
        """
        `bitness` of analyzing executable (cover program or stego-program). Defaults to 0.
        """
        return self.__bitness
    
    
    @bitness.setter
    def set_bitness(self, bitness: int) -> None:
        self.__bitness = bitness
    
        
    @property
    def total_instrs(self) -> int:
        """
        Number of all decoded instructions inside analyzing executable. Defaults to 0.
        """
        return self.__total_instrs
    
    
    @total_instrs.setter
    def set_total_instrs(self, total: int) -> None:
        self.__total_instrs = total
        
        
    @property
    def total_code_bytes(self) -> int:
        """
        Total amount of bytes within all code sections of analyzing executable. Defaults to 0.
        """
        return self.__total_code_bytes
    
    
    @total_code_bytes.setter
    def set_total_code_bytes(self, b: int) -> None:
        self.__total_code_bytes = b
        

    @property
    def useable_instrs(self) -> int:
        """
        Amount of usable instructions from analyzing executable. These instructions are going to be used in `embed`/`extract` mode. Defaults to 0.
        """
        return self.__useable_instrs
    
    
    @useable_instrs.setter
    def set_useable_instrs(self, useable: int) -> None:
        self.__useable_instrs = useable
        
        
    @property
    def avg_capacity(self) -> float:
        """
        Average capacity of analyzing executable (variable encoding). Defaults to 0.0.
        """
        return self.__avg_capacity
    
    
    @avg_capacity.setter
    def set_avg_capacity(self, avg_cap: float) -> None:
        self.__avg_capacity = avg_cap
        
        
    @property
    def min_capacity(self) -> int:
        """
        Minimum available capacity of analyzing executable. Defaults to 0.
        """
        return self.__min_capacity
    
    
    @min_capacity.setter
    def set_min_capacity(self, min_cap: int) -> None:
        self.__min_capacity = min_cap
        
        
    @property
    def max_capacity(self) -> int:
        """
        Maximum available capacity of analyzing executable. Defaults to 0.
        """
        return self.__max_capacity
    
    
    @max_capacity.setter
    def set_max_capacity(self, max_cap: int) -> None:
        self.__max_capacity = max_cap
        
        
    def print_analysis(self, method: str, fpath: str) -> None:
        """
        Print computed analysis of given executable.
        """
        
        print(f"STEGANOGRAPHIC ANALYSIS:\n")
        
        if method == "sub":
            method = "Basic Substitution"
            
        elif method == "ext-sub":
            method = "Extended Substitution"
            
        elif method == "nops":
            method = "NOP Instructions Using"
            
        elif method == "mov":
            method = "MOV Scheduling"
            
        elif method == "ext-sub-nops":
            method = "Combination of Extended Substitution with NOPs Embedding"
        
        exe_size = os.path.getsize(fpath)
        
        print(f"Executable {self.bitness}-bit:\t{fpath}")
        print(f"Steganography method:\t{method}")
        print()
        print(f"Total size of executable:\t{exe_size:12,} Bytes")
        print(f"Total size of instructions:\t{self.set_total_code_bytes:12,} Bytes")
        print()
        print(f"All decoded instructions:\t\t\t{self.total_instrs:8,}")
        print(f"Potentially usable instructions:\t\t{self.useable_instrs:8,}")
        print(f"Information capacity of given executable:")
        print()
        print(f"\tAverage: \t{(self.avg_capacity / 8):12,.3f} Bytes", end="")
        
        # For average capacity.
        b = int(self.avg_capacity // 8)
        bits = int(self.avg_capacity % 8)
        if b > 0 and bits > 0:
            print(f" ({b:,} Bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print(f"\tMinimum: \t{(self.min_capacity / 8):12,.3f} Bytes", end="")
        
        # For minimum capacity.
        b = self.min_capacity // 8
        bits = self.min_capacity % 8
        
        if b > 0 and bits > 0:
            print(f" ({b:,} Bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print(f"\tMaximum: \t{(self.max_capacity / 8):12,.3f} Bytes", end="")
        
        # For maximum capacity.
        b = int(self.max_capacity // 8)
        bits = int(self.max_capacity % 8)

        if b > 0 and bits > 0:
            print(f" ({b:,} Bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print()
        print(f"Summary:")
        print(f"\t{(self.set_total_code_bytes / exe_size):6.2%}\tinstruction percentage")
        print(f"\t{(self.useable_instrs / self.total_instrs):6.2%}\tof useable instructions")
        print(f"\t{(self.max_capacity / (exe_size * 8)):.5f}\tencoding rate")