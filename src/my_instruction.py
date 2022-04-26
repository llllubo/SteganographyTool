from iced_x86 import Instruction


class MyInstruction:
    
    
    def __init__(self,
                 instr: Instruction,
                 foffset: int,
                 ioffset: int,
                 eq_class: str) -> None:
        self.__instr = instr
        self.__foffset = foffset
        self.__ioffset = ioffset
        self.__eq_class = eq_class
        
        
    @property
    def instruction(self) -> Instruction:
        return self.__instr
    
    
    @instruction.setter
    def set_instruction(self, instr: Instruction) -> None:
        self.__instr = instr
        
        
    @property
    def foffset(self) -> int:
        return self.__foffset
    
    
    @foffset.setter
    def set_foffset(self, foffset: int) -> None:
        self.__foffset = foffset
        
        
    @property
    def ioffset(self) -> int:
        return self.__ioffset
    
    
    @ioffset.setter
    def set_ioffset(self, ioffset: int) -> None:
        self.__ioffset = ioffset
        
        
    @property
    def eq_class(self) -> str:
        return self.__eq_class
    
    
    @eq_class.setter
    def set_eq_class(self, eq_class: str) -> None:
        self.__eq_class = eq_class