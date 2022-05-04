class Analyzer:
    
    def __init__(self,
                 bitness: int,
                 total_instrs: int,
                 useable_instrs: int,
                 avg_cap: float,
                 min_cap: int,
                 max_cap: int) -> None:
        self.__bitness = bitness
        self.__total_instrs = total_instrs
        self.__useable_instrs = useable_instrs
        self.__avg_capacity = avg_cap   # In BITS
        self.__min_capacity = min_cap   # In BITS
        self.__max_capacity = max_cap   # In BITS
        
    
    @property
    def bitness(self) -> int:
        return self.__bitness
    
        
    @property
    def total_instrs(self) -> int:
        return self.__total_instrs
    
    
    @total_instrs.setter
    def set_total_instrs(self, total: int) -> None:
        self.__total_instrs = total
        

    @property
    def useable_instrs(self) -> int:
        return self.__useable_instrs
    
    
    @useable_instrs.setter
    def set_useable_instrs(self, useable: int) -> None:
        self.__useable_instrs = useable
        
        
    @property
    def avg_capacity(self) -> float:
        return self.__avg_capacity
    
    
    @avg_capacity.setter
    def set_avg_capacity(self, avg_cap: float) -> None:
        self.__avg_capacity = avg_cap
        
        
    @property
    def min_capacity(self) -> int:
        return self.__min_capacity
    
    
    @min_capacity.setter
    def set_min_capacity(self, min_cap: int) -> None:
        self.__min_capacity = min_cap
        
        
    @property
    def max_capacity(self) -> int:
        return self.__max_capacity
    
    
    @max_capacity.setter
    def set_max_capacity(self, max_cap: int) -> None:
        self.__max_capacity = max_cap
        
        
    def print_analysis(self, method: str, fpath: str) -> None:
        print(f"STEGANOGRAPHIC ANALYSIS:\n")
        
        if method == "sub":
            method = "Basic Substitution"
            
        elif method == "ext-sub":
            method = "Extended Substitution"
            
        elif method == "nops":
            method = "NOP Instructions Using"
            
        elif method == "mov":
            method = "MOV Scheduling"
            
        elif method == "ext-sub-nops-mov":
            method = "Combination of Extended Substitution with NOPs & MOV Scheduling"
        
        print(f"Executable {self.bitness}-bit:\t{fpath}")
        print(f"Steganography method:\t{method}")
        print()
        print(f"All decoded instructions:\t\t\t{self.total_instrs:,}")
        print(f"Potentially useable instructions:\t\t{self.useable_instrs:,}")
        print(f"Information capacity of given executable:")
        print()
        print(f"\tAverage: \t{(self.avg_capacity / 8):12,.3f} Bytes", end="")
        
        # For average capacity.
        b = int(self.avg_capacity // 8)
        bits = int(self.avg_capacity % 8)
        if b > 0 and bits > 0:
            print(f" ({b:,} bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print(f"\tMinimum: \t{(self.min_capacity / 8):12,.3f} Bytes", end="")
        
        # For minimum capacity.
        b = self.min_capacity // 8
        bits = self.min_capacity % 8
        
        if b > 0 and bits > 0:
            print(f" ({b:,} bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print(f"\tMaximum: \t{(self.max_capacity / 8):12,.3f} Bytes", end="")
        
        # For maximum capacity.
        b = int(self.max_capacity // 8)
        bits = int(self.max_capacity % 8)

        if b > 0 and bits > 0:
            print(f" ({b:,} bytes and {bits:,} bits)")
        elif b == 0 and bits > 0:
            print(f" ({bits:,} bits)")
        else:
            print()
        
        print()
        print(f"Summary:")
        print(f"\t{(self.useable_instrs / self.total_instrs):.2%} of useable instructions")