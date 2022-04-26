


class Analyzer:
    
    def __init__(self,
                 bitness: int,
                 total_instrs: int,
                 useable_instrs: int,
                 cap: int) -> None:
        self.__bitness = bitness
        self.__total_instrs = total_instrs
        self.__useable_instrs = useable_instrs
        self.__capacity = cap   ## BITS
        
    
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
    def capacity(self) -> int:
        return self.__capacity
    
    
    @capacity.setter
    def set_capacity(self, cap: int) -> None:
        self.__capacity = cap
        
        
    def print_analysis(self, method: str, fpath: str) -> None:
        print(f"STEGANOGRAPHIC ANALYSIS:\n")
        
        if method == "sub" or \
           method == "instruction-substitution":
            method = "Basic substitution"
            
        elif method == "ext-sub" or \
             method == "extended-substitution":
            method = "Extended substitution"
            
        elif method == "nops" or \
             method == "nops-embedding":
            method = "NOP instructions embedding/extracting"
            
        elif method == "ext-sub-nops":
            method = "Combination of extended substitution with NOPs"
        
        print(f"Executable {self.bitness}-bit:\t{fpath}")
        print(f"Steganography method:\t{method}")
        print()
        print(f"All decoded instructions:\t\t\t{self.total_instrs:,}")
        print(f"Potentially useable instructions:\t\t{self.useable_instrs:,}")
        print(f"Information capacity of given executable:\t{(self.capacity / 8):,} Bytes ({(self.capacity // 8):,} bytes and {(self.capacity % 8)} bits)")
        print(f"\nSummary:")
        print(f"\t{(self.useable_instrs/self.total_instrs):.2%} of useable instructions")